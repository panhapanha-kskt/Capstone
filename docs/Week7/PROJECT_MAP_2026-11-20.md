# Project map for one-command operation (Phase 1) — 2026-11-20

Scope: what exists today for the fixed design (Detector · Learner · Bridge · `scripts/soc.sh`).
Read-only phase: no code was changed. Everything below was read from the repo on branch
`safety-fixes` (which still has **uncommitted** work: the C1/C2/H1 safety fixes, the lab scripts and
`train_new_data.sh`). Statements marked *(not verified)* could not be checked from my workspace.

---

## a. Flows today

### a1. Detector path (Part 1)

```
Technitium DNS (Docker: infra/technitium-elk/docker-compose.yml, started by hand or run_all.sh --with-infra)
  │  PushLogger DNS App (infra/technitium-apps/PushLogger, installed by scripts/setup_pushlogger.sh)
  │  HTTP POST /push  (token = TECHNITIUM_PUSH_TOKEN or TECHNITIUM_API_KEY from .env)
  ▼
scripts/technitium_push_listener.py  (ThreadingHTTPServer, :8787, /healthz)
  │  Handler appends one Technitium-format line per query
  ▼
data/raw/<date>.log
  │  dashboard/server.py  watch_loop(): log_signature(data/raw/*.log) every --interval 3 s,
  │  waits --debounce 5 s of quiet, then run_pipeline(zscore, custom_cmd)
  │     (server-side, since safety-fixes H1: holds PIPELINE_LOCK.detection_running(runs/) for the whole run,
  │      heartbeat file runs/.pipeline.readers/<host>-<pid>-<id>, refreshed by beat() before each step)
  ▼  sync_logs()  (only if --watch is not data/raw)
  ▼  pipeline_steps():   — the same commands as scripts/run_pipeline.sh, re-run over ALL of data/raw each time
  1. python -m dns_detect.features.extractor                 → data/processed/week3_features_all.json
  2. python -m dns_detect.fusion.bridge --week3 … --output …  → data/processed/week3_features_with_ml.json
        loads models/ (Path A RF/GBT, Path B dns_trafficformer_iforest.pkl, fusion_lr.pkl)
  3. python -m dns_detect.detection.engine --input … --output … --zscore 2.0 --csv
        rules 1–6 + Z-score (caps now ranked + overflow alert, C1) → data/processed/week4_unified_alerts.json(.csv)
  4. python -m dns_detect.monitoring.monitor --live … --alerts … --output …   (non-fatal)
        PSI vs training feature_snapshot, alert rate, score saturation → data/processed/monitoring_report.json
        { retrain_recommended: bool, reasons: [...] }
  ▼  load_alerts(force=True) → record_history() → EXPORTS.trigger()
dashboard pages (/soc /alerts /triage /health, /api/health) ;  analyst verdicts →
  dashboard/data/alert_management.json  records[fp].{verdict, verdict_by, verdict_at}
  (SOC_DASHBOARD_DATA_DIR overrides the folder)
```

Command-line equivalent of one detection run: `scripts/run_pipeline.sh` (same 4 steps; holds `flock -s 8`
on `runs/.pipeline.lock` for its whole run). `scripts/run_all.sh` = train-if-missing → `run_pipeline.sh` →
read `retrain_recommended` (step 17).

Notes that matter for soc.sh:
- The dashboard process also hosts the **training console** (`start_training_api()`, uvicorn thread,
  `/training`), which can start `train_models.sh` runs and (since C2) promote through `part_b.py`.
- `server.py` has no SIGTERM handler: `pipeline_steps` children started by `subprocess.run` survive a
  plain kill of the parent → soc.sh must stop the whole process group.
- The listener is started today with `nohup … & disown` by `setup_pushlogger.sh`, log `scripts/.push_listener.log`.

### a2. Part B path (Learner, today run by hand)

```
scripts/train_new_data.sh <dir>        (new, uncommitted; Week 7 Task 2)
  1. sha256sum -c <dir>/SHA256SUMS --ignore-missing      (written by scripts/lab_capture.sh on the Kali VM)
  2. files = models/training_provenance.json source_files + <dir>/*.json  → <dir>/files_<RUN>.txt
     (exit 1 if any live-model file is missing; today 7 Tu2023 files exist only on the Kali VM)
  3. per-file rows/labels + record-type rule check → <dir>/check_<RUN>.json   (--check-only stops here)
  4. scripts/train_models.sh --eda-only …                → data/processed/eda_data_report.*
  5. seed 1: DNS_DETECT_MODELS_DIR=runs/<RUN>_s42 train_models.sh --new-split …
  ▼
scripts/run_candidate_seeds.sh   (RUN_NAME, SEEDS="42 43 44", SPLIT, FILES, AUTO_PROMOTE)
  for each seed: DNS_DETECT_MODELS_DIR=runs/<RUN>_s<seed> train_models.sh --seed s --n-days 20
                 --path-b-model iforest --force-retrain --split-manifest runs/<RUN>_split.json --files …
  (exit 4 if training files or split missing; seeds with evaluation_metrics.json are skipped)
  ▼
scripts/part_b.py --name <RUN> --seeds "…" [--auto-promote]      (also --run DIR, safety-fixes)
  - flock EX|NB runs/.promote.lock          → exit 3 if another promote is running
  - gate: scripts/compare_models.py --runs … --out runs/<RUN>_gate.json
          criteria config/success_criteria.yaml (min_seeds 3, same split, recall ≥ 0.95, FPR budget,
          not worse than models/ on the same test rows, beats every rule baseline every seed)
          → FAIL: log, exit 1 (models/ untouched)
  - pick_seed(): seed whose false alarms are closest to the median
  - no --auto-promote: log "ready, waiting for approval", print the promote command, exit 10
  - pipeline_running(runs/) (flock probe on runs/.pipeline.lock + live heartbeats) → exit 3
  - scripts/promote_model.sh <run> before_<RUN>
        required-file check + dns_detect.models.schema check (nothing changed on failure)
        mv models/* → models/archive/before_<RUN>_<ts>/  ; copy listed files ; models/PROMOTED.json (sha256)
  - scripts/smoke_models.py --models models --reference <run> [--data <run>/merged_features_labeled.json]
        fails → scripts/rollback_model.sh (newest models/archive/*, replaced set → archive/rolledback_<ts>) exit 2
  - success → exit 0
  every decision → one JSON line in runs/promotion_log.jsonl {time, git_commit, name, runs, gate, promoted, decision, …}
```

Other ways into training today: `run_all.sh --retrain|--auto-retrain [--auto-promote]` (→ run_candidate_seeds.sh
with the live model's files/split), the training console (`dashboard/training-gui`, runs in the dashboard process),
`train_models.sh` with `DNS_DETECT_MODELS_DIR` unset (**writes models/ directly** — the only remaining direct path,
by design for first-time setup).

Analyst verdicts → training (Task 12): `scripts/export_feedback_labels.py --url http://127.0.0.1:9000`
→ `data/feedback/verdict_labels.json` (+ meta) → `train_models.sh --feedback FILE` (min 50 / max 5000 from
`settings.yaml: feedback`). **Not wired** into `run_candidate_seeds.sh` or `train_new_data.sh`.

### a3. Lock, promotion log, archive / rollback today

| Mechanism | File | Who takes it | Who checks it |
|---|---|---|---|
| Detection reader lock (POSIX) | `runs/.pipeline.lock` `flock -s` | `run_pipeline.sh`; dashboard via `pipeline_lock.py` on Linux | `part_b.py` → refuses promote (exit 3) |
| Detection heartbeat (any OS) | `runs/.pipeline.readers/*` (stale after 20 min) | dashboard `run_pipeline()` | `part_b.py` |
| One promote at a time | `runs/.promote.lock` `flock -x` | `part_b.py` | `part_b.py` |
| Audit log | `runs/promotion_log.jsonl` | `part_b.py` | humans (last entry 2026-11-19: gate FAIL, kept models) |
| Archive | `models/archive/<label>_<ts>/` | `promote_model.sh` (moves old set) | `rollback_model.sh` |
| Rollback | `models/archive/rolledback_<ts>/` keeps the replaced set | `rollback_model.sh` | — |
| Training concurrency | **none** — `train_models.sh` writes shared `data/processed/merged_features_*.json`, `eda_*`, `merge_report.json`, `labeling_report.json` even when the model goes to a run folder | — | — |

---

## b. Exists / partial / missing

### Design table

| Row | Status | Evidence / gap |
|---|---|---|
| Detector: PushLogger → listener | ✅ exists | `technitium_push_listener.py`, `setup_pushlogger.sh`; not supervised (nohup) |
| Detector: extract → score → rules → dashboard, real time | ✅ exists | `server.py` watch loop; ⚠ re-processes all of `data/raw` each run (latency grows with log size) |
| Detector: background + restart | ❌ missing | foreground process, no restart, no PID file |
| Learner: train_new_data.sh → 3 seeds → gate → smoke → promote/rollback | ⚠ partial | scripts exist (train_new_data.sh **uncommitted**); no loop, no triggers, no `nice` |
| Bridge: models/ + gate | ✅ exists | `compare_models.py` + `success_criteria.yaml`; `promote_model.sh` the only scripted writer |
| Bridge: lock, promote waits for detection | ✅ exists (uncommitted) | safety-fixes H1; part_b exits 3 instead of **waiting** — no retry |
| One command `soc.sh up/down/restart/status/logs` | ❌ missing | — |
| Trigger (a) drift | ⚠ partial | `monitoring_report.json.retrain_recommended`; **today it is `true`** (PSI query_length 8.03, saturated scores) on attack-only `data/raw` → would fire at once; Task 6 (proper drift baseline) not done |
| Trigger (b) new Kali captures | ⚠ partial | `data/processed/week7/*.json` + `SHA256SUMS` + `CAPTURES.log` by `lab_capture.sh`; no watcher; folder empty on Windows today |
| Trigger (c) ≥ 50 new verdicts | ⚠ partial | verdicts in `dashboard/data/alert_management.json` (1 today); export script exists; no counter, no `--feedback` pass-through in Part B |
| Cooldown / one run at a time (training) | ❌ missing | only promote is serialised |
| Promote only with `--auto-promote` / `auto_promote: true` | ✅ flag exists | `part_b.py --auto-promote`; no `config/soc.yaml` |

### Acceptance criteria

| # | Criterion | Status | Gap |
|---|---|---|---|
| 1 | Detection keeps its latency during training; training separate and `nice` | ⚠ partial | separate processes already; no `nice`/`ionice`; no latency measurement exists; both share CPU and `data/processed/` (disjoint files) |
| 2 | Failures don't spread; each restarts itself with backoff | ❌ missing | gate FAIL already leaves models/ alone; no supervisor |
| 3 | Only (a)/(b)/(c) start training; cooldown; one at a time | ❌ missing | today no automatic training at all (watch loop never trains — good) |
| 4 | models/ only via promote_model.sh after PASS, only with auto-promote, never under the lock; smoke-fail rollback; log every decision | ✅ mostly exists | part_b.py does all of it; learner must log its own trigger/skip decisions too; train_models.sh without `DNS_DETECT_MODELS_DIR` still writes models/ — the learner must never call it that way |

---

## c. Commands run by hand today (what soc.sh must reproduce)

All from WSL/Kali: `cd /mnt/c/Programming-CTF/Capstone && source ~/Capstone/.venv/bin/activate`
(venv path from `docs/Week6/ML_IMPROVEMENT_IMPLEMENTATION_2026-11-19.md`; *(not verified)* — the repo's
`.venv/` is a **Windows** venv (Python 3.13, `Scripts/`), unusable from WSL).

| Piece | Command today |
|---|---|
| Technitium + ELK | `cd infra/technitium-elk && docker compose up -d` (or `run_all.sh --with-infra`) |
| PushLogger install/config (once per key) | `./scripts/setup_pushlogger.sh --api-key <token> [--push-host 172.20.0.1]` |
| Push listener | `python3 scripts/technitium_push_listener.py --port 8787` (setup script: `nohup … > scripts/.push_listener.log &`) |
| Detector + dashboard | `python3 dashboard/server.py --port 9000` (add `--host 0.0.0.0` + non-default `ADMIN_TOKEN` to reach it from Windows) |
| Detection once (CLI) | `./scripts/run_pipeline.sh` or `./scripts/run_all.sh --skip-train` |
| Export verdicts | `python3 scripts/export_feedback_labels.py --url http://127.0.0.1:9000` |
| Retrain on the live data | `./scripts/run_all.sh --retrain [--auto-promote]` |
| Train new captures | `bash scripts/train_new_data.sh data/processed/week7 [--check-only]` |
| Promote by hand | `bash scripts/promote_model.sh runs/<RUN>_s<seed> before_<RUN>` (part_b prints it) |
| Roll back | `bash scripts/rollback_model.sh [models/archive/X]` |

---

## d. Assumptions (I will proceed on these unless you say otherwise)

1. **Branching:** the safety-fixes work is committed/merged first; soc work goes on a new branch `soc-automation` from it (soc relies on `pipeline_lock.py`).
2. **Detector service = 2 supervised children**: push listener + `dashboard/server.py` (watch loop). Docker/Technitium is **not** managed by soc.sh (`status` only reports whether `:5380` answers).
3. **State and logs:** `runs/soc/` (state.json, PID files, learner lock — new files only, nothing existing rewritten) and `logs/soc/` (detector.log, listener.log, learner.log, rotated by size).
4. **data/processed/** generated files (merged_*, eda_*, week3_*, week7/files_*, check_*) keep being written by the existing scripts as today; soc.sh itself writes nothing in `data/`. `data/raw`, `data/external`, `Dataset/` stay read-only.
5. **"Refuses to start while the lock is held"** = the learner won't start a run while another training/promote holds `runs/.promote.lock` or the learner's own lock. It does **not** wait for the detection lock to start *training* (detection holds it every few seconds); only *promote* waits for it, with retries.
6. Training at `nice -n 10` and `ionice -c3` where available.
7. Mocked training only in tests; Phase 4 live check runs the dashboard with `--demo` and a stub `TRAIN_CMD` so nothing real is trained or promoted.

## Questions for you

1. **Drift trigger (a)** fires today (`retrain_recommended: true` from attack-only `data/raw`), and retraining on the same files cannot fix drift. OK to define (a) as: *monitor recommends retrain on N consecutive detection runs (default 3) AND cooldown passed*, still subject to the run producing a candidate only through the gate? Or should (a) wait for Task 6's proper drift baseline?
2. **What does each trigger train on?** Proposal: (a) live model files (`run_candidate_seeds.sh` defaults); (b) `train_new_data.sh data/processed/week7` (live files + new captures); (c) live files + exported verdicts — which needs a small pass-through (`FEEDBACK=…` → `train_models.sh --feedback`) in `run_candidate_seeds.sh`. Allowed?
3. **WSL venv path**: is it `~/Capstone/.venv`? And is `systemd` enabled in your WSL Kali (`/etc/wsl.conf` `[boot] systemd=true`)? It decides whether `systemd --user` is even an option.
4. **Promote refused because detection is running (exit 3):** retry gate+promote every poll until it gets a quiet moment (max N tries), or just log and leave it as "ready to promote" for you?
5. The 7 Tu2023 training files exist only on the Kali VM, so any trigger on Windows/WSL ends with exit 4 (data missing) until you copy them. Learner then logs it and enters cooldown — acceptable?
6. Should the training console (inside the dashboard) be blocked from training while the learner trains? Both write the same `data/processed/merged_*` files.
