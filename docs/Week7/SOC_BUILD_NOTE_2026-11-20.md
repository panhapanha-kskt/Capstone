# One-command operation — build note (Phase 3), 2026-11-20

What was built from the approved design (`SOC_AUTOMATION_RESEARCH_2026-11-20.md`, section C, with the
user's decisions of 2026-11-20). Nothing here trains, promotes or touches `models/` by itself: the learner
only runs the existing Part B scripts, and promotion stays manual unless `--auto-promote` / `auto_promote: true`.

## Files

| File | New / edited | What it does |
|---|---|---|
| `scripts/soc.sh` | new | `up [--auto-promote] [svc]`, `down [svc]`, `restart [svc]`, `status`, `logs [svc] [-f]`. Bash front-end; starts one supervisor per service with `setsid -f`. |
| `scripts/soc_supervisor.py` | new | One supervisor per service (`detector` = push listener + `dashboard/server.py`, `learner` = `scripts/learner.py`). flock on `runs/soc/<svc>.supervisor.lock`, children in their own process groups, TERM → wait → KILL of the whole group, exponential backoff 2 s → 300 s (reset after 120 s healthy), health checks (`/api/health`, `/healthz`, learner heartbeat), size-rotated logs in `logs/soc/`, state in `runs/soc/state/`. Also the `status` / `env` / `wait-healthy` / `strays` / `kill-groups` helpers for soc.sh. |
| `scripts/learner.py` | new | The trigger loop (research C5): (b) captures > (c) verdicts > (a) drift, cooldown, max runs/day, locks, `nice -n 10` (+ `ionice -c3` if it works), decisions as JSON lines with `"source":"learner"` in `runs/promotion_log.jsonl`, models/ hash guard, promote retry. Runs only `ALLOWED_SCRIPTS`. |
| `src/dns_detect/soc/__init__.py`, `config.py`, `triggers.py` | new | Config loading (defaults + `config/soc.yaml` / `SOC_CONFIG`, Python resolution) and the pure trigger functions. Stdlib + PyYAML only. |
| `config/soc.yaml` | new | All settings with safe, commented defaults (`auto_promote: false`, 24 h cooldown, 2 runs/day, 1 auto-promotion/week). |
| `scripts/part_b.py` | **edited** | Probe-then-promote gap closed: holds an EXCLUSIVE non-blocking flock on `runs/.pipeline.lock` (and refuses if `pipeline_lock.active_readers()` is non-empty) through promote → smoke test → rollback. Same exit codes and log decisions as before. |
| `scripts/run_candidate_seeds.sh` | **edited** | `FEEDBACK=<file>` → every seed's `train_models.sh` gets `--feedback <file>`. Unset/empty → the same command as before. |
| `README.md` | **edited** | New section "One-command operation". |
| `.gitignore` | **edited** | `runs/soc/` and `logs/soc/`. |
| `tests/test_learner_triggers.py`, `tests/test_soc_supervisor.py`, `tests/test_soc_cli.py`, `tests/test_part_b_exclusive_lock.py`, `tests/test_run_candidate_seeds_feedback.py` | new | Stub-only tests (nothing trained, the real gate is never run). |
| `docs/Week7/SOC_BUILD_NOTE_2026-11-20.md` | new | This note. |

Not edited: `scripts/run_all.sh`, `scripts/run_pipeline.sh`, `dashboard/server.py`, `scripts/compare_models.py`,
`config/success_criteria.yaml`, `scripts/promote_model.sh`, `scripts/rollback_model.sh`, `scripts/smoke_models.py`,
`scripts/train_new_data.sh`, `scripts/export_feedback_labels.py`, anything in `models/`, `data/`, `outputs/`.

## How it runs (from WSL Kali)

```bash
cd /mnt/c/Programming-CTF/Capstone
bash scripts/soc.sh up            # detector + learner in the background; prints status
bash scripts/soc.sh status        # services, last trigger, last gate result, live model, ready-to-promote
bash scripts/soc.sh logs learner -f
bash scripts/soc.sh down          # clean stop, then checks for stray processes (exit 1 if any)
```

State: `runs/soc/` (supervisor locks/PIDs, `state/<child>.json`, `learner_state.json`, `learner.lock`,
`learner.heartbeat`). Logs: `logs/soc/` (`listener.log`, `dashboard.log`, `learner.log`,
`supervisor-<svc>.log`, `train_<RUN>.log`). Only new files are written there.

### Learner details worth knowing
- **First start** seeds `runs/soc/learner_state.json`: captures already in `models/training_provenance.json`
  are marked trained, verdicts up to the newest existing `verdict_at` are not counted, and the monitoring report
  already on disk does not count towards drift.
- **Data missing (exit 4):** before running the real scripts the learner checks that every file in
  `models/training_provenance.json` (and the live split for (c)) exists. Today the 7 Tu2023 files are only on the
  Kali VM, so a trigger ends with `run_finished … decision: data_missing, exit: 4`, a cooldown, and the inputs are
  **not** marked trained (they fire again after the cooldown once the files are copied). This check exists because
  `train_new_data.sh` exits 1 (not 4) when live files are missing.
- **Outcome mapping** (exit code of the training command = part_b's): 0 promoted · 10 ready (status prints the
  promote command) · 1 gate FAIL (only if part_b logged `gate: FAIL` for this run; otherwise "error") ·
  2 rolled back · 3 + part_b decision "not promoted: run_pipeline.sh is running" (or "another Part B run") with
  auto-promote → promote retry every 120 s, max 15, then "ready_to_promote_manually" · 4 data missing · other → error.
  Inputs are marked trained only when the training completed (part_b logged a line for the run).
- **Drift** needs 3 *distinct* reports (sha256) in a row with `retrain_recommended: true`, fires once, re-arms
  after a `false` report, and with `require_new_data: true` (default) only fires if there is ≥1 new capture or
  settled verdict; otherwise it logs `skipped: drift_without_new_data` once and disarms.
- `AUTO_PROMOTE`, `FEEDBACK`, `FILES`, `RUN_NAME`, `SEEDS`, `SPLIT` are never inherited from the shell; the learner
  sets them itself. `soc.sh up` removes `SOC_AUTO_PROMOTE` from the environment unless `--auto-promote` is given.

## Phase 4 (verification)
See `SOC_LIVE_CHECK_2026-11-20.md`: test suite, live check per acceptance criterion on a scratch copy,
and the independent review's findings — one CRITICAL (the captures run's EDA step rewrote
`models/training_provenance.json`), fixed and verified — with the follow-up fixes.

## Shadow check (added after the Phase 4 research question, 2026-11-20)
`scripts/shadow_check.py` + `scripts/part_b.py --shadow` (+ `SHADOW=1` pass-through in `run_candidate_seeds.sh` /
`train_new_data.sh`; the learner sets it when `shadow.enabled` is true, the default). After the gate PASSes and
before `promote_model.sh`, the chosen seed scores `data/processed/week3_features_all.json` (the traffic the detector
last processed) with the normal ML bridge into a temp folder, and its `ml_combined_label` is compared row by row
with the live model's `week3_features_with_ml.json`. Thresholds in `config/soc.yaml` `shadow:`. Exit 5 = FAIL,
`models/` unchanged; exit 4 = no live traffic yet → reported, promote decided on the gate alone. Verified on the
real live traffic in the VM: live model vs itself → agreement 1.0 PASS; yesterday's rejected retrain candidate
→ 6,566 vs 8,098 flags, agreement 0.81 → FAIL. Tests: `tests/test_shadow_check.py` (10).
Known limit: it is a one-shot comparison on the latest traffic snapshot, not a multi-day canary with live
traffic split between models; the dashboard still runs one model at a time.

## Left out / known gaps
- **Training console is not blocked by the learner.** The learner refuses to start while a `train_models.sh` it did
  not start is running, but the console inside `dashboard/server.py` can still start a run while the learner trains
  (both write `data/processed/merged_*`). Blocking it would need a `dashboard/server.py` change (out of scope).
- **Task 6 drift baseline not done.** `monitoring_report.json` recommends a retrain on attack-only `data/raw`;
  trigger (a) is therefore narrowed (3 distinct reports, edge-triggered, new data required).
- **Drift with only 1–49 new verdicts** trains through `run_candidate_seeds.sh` with `FEEDBACK`, but
  `train_models.sh --feedback` refuses fewer than `feedback.min_verdicts` (50) usable rows, so such a run ends as
  an error + cooldown. Safe, but it does not train. Revisit with Task 6.
- **No shadow/canary scoring** (would need detector changes); `smoke_models.py` is the offline stand-in.
- `ionice -c3` is best-effort and probably a no-op on `/mnt/c` under WSL; `nice -n 10` is what criterion 1 relies on.
- After a detector crash its heartbeat in `runs/.pipeline.readers/` blocks promotes for up to 20 min (covered by
  the 30-min retry window; nothing under `runs/` is deleted by soc).
- `part_b.py` now pauses detection runs (they wait on the shared lock) for the duration of promote + smoke test.
- WSL may stop the distro when no terminal is open (`instanceIdleTimeout`, not verified for background-only
  processes). If it does, set `instanceIdleTimeout=-1` under `[wsl2]` in `%UserProfile%\.wslconfig` or keep a
  terminal open. Boot-time auto-start is out of scope (needs root).
- Live check (Phase 4) was not part of this build; it runs on a scratch copy of the repo.
- `models/PROMOTED.json` vs the live files: the 10 JSON model files were rewritten with CRLF line endings after
  the 2026-11-19 promote (same content; the .pkl files match exactly). `soc.sh status` reports this as
  "sha256 verified; some JSON files differ only in CRLF/LF line endings" instead of a mismatch. Nothing was changed
  in `models/`.

## Roll back everything

1. Stop it: `bash scripts/soc.sh down`.
2. Restore the edited files from the backups made before editing (timestamp in the folder name):
   ```bash
   B=runs/soc/backups/20261120_120720     # made by this build before editing
   cp "$B/scripts/part_b.py" scripts/part_b.py
   cp "$B/scripts/run_candidate_seeds.sh" scripts/run_candidate_seeds.sh
   cp "$B/README.md" README.md
   cp "$B/.gitignore" .gitignore
   ```
   or, once committed, `git revert <the soc commits>` (or `git checkout <commit-before-soc> -- scripts/part_b.py
   scripts/run_candidate_seeds.sh README.md .gitignore`).
3. Remove the new files:
   ```bash
   rm -f scripts/soc.sh scripts/soc_supervisor.py scripts/learner.py config/soc.yaml \
         tests/test_learner_triggers.py tests/test_soc_supervisor.py tests/test_soc_cli.py \
         tests/test_part_b_exclusive_lock.py tests/test_run_candidate_seeds_feedback.py \
         docs/Week7/SOC_BUILD_NOTE_2026-11-20.md
   rm -rf src/dns_detect/soc
   ```
4. Optional: `rm -rf runs/soc logs/soc` (soc's own state and logs; learner lines stay in `runs/promotion_log.jsonl`,
   marked `"source":"learner"`).
