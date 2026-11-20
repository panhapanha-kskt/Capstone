# One-command operation — Phase 4 verification (2026-11-20)

Where: a **scratch copy** of the repo (scripts, src, config, dashboard, models, data/raw, 32 MB) in the
assistant's Linux VM, Python 3.10. The real repo, `models/`, `data/` and git were not touched by the live
check. Stand-ins: training = `fake_train.sh` (burns both CPUs at `nice 10`, makes 3 empty seed folders, then
runs the **real** `scripts/part_b.py`), gate = a stub that passes or fails on request (`PART_B_GATE`),
`TECHNITIUM_PUSH_TOKEN=probe-token`. The detector (push listener + `dashboard/server.py`) and the full
extract → bridge → rules → monitor pipeline were **real** (one detection run ≈ 8–9 s on 8,152 records).
One scratch-only change: `fusion_lr.pkl` was re-pickled for the VM's older scikit-learn (1.7.2 vs 1.9.1).

## Test suite (real repo, VM)
`496 passed, 2 skipped, 1 failed` — the failure is the pre-existing `tests/test_labeling.py::
test_parent_domain_psl_private_suffixes` (needs internet). New: 5 soc test files (72 tests) +
`tests/test_soc_review_fixes.py` (5) + 1 test in `tests/test_safety_fixes.py`. No stray processes after the runs.

## Acceptance criteria (recorded output, abridged)

**1. Different speeds** — push one DNS line → new alerts, measured from the POST to the end of the
pipeline run that includes it (3 s poll + 5 s debounce + run):
```
idle learner:        probe 1: push -> new alerts in 17.1 s (pipeline run 7.7 s)
during training:     probe 1: push -> new alerts in 17.2 s (pipeline run 8.6 s)
(2 CPUs burning)     probe 2: push -> new alerts in 18.2 s (pipeline run 8.9 s)
training process:    NI=10  bash fake_train.sh --trigger captures --run soc_captures_20261120_122031
```
Median during training 17.7 s ≤ 1.5 × 17.1 s baseline. Training ran in its own process group under the
learner supervisor, never under the detector.

**2. Failures don't spread**
```
kill -9 learner mid-run → training group gone; detector probe: 15.2 s (unchanged)
  learner    running  pid 150  RESTARTS 1  LAST EXIT -9   (listener/dashboard: 0 restarts)
  log: run_aborted "learner stopped mid-run; inputs not marked trained, cooldown set"
       skipped  reason=cooldown   (the same capture, next poll)
kill -9 dashboard → dashboard running pid 234 RESTARTS 1 LAST EXIT -9; listener 0; learner 0 restarts
gate FAIL (verdicts run) → run_finished gate_fail "gate FAIL; models/ unchanged"; next probe fine
```
Backoff 2 s → 300 s (demo: 2 → 60 s), reset after a healthy period; each child restarts alone.

**3. Different triggers**
```
2 probes (new log lines) → run_started lines: 0
capture file + SHA256SUMS  → run_started trigger=captures (15 s later; settle 5 s + poll 10 s)
50 verdicts added AFTER start → run_started trigger=verdicts; export wrote data/feedback/verdict_labels.json
50 verdicts present BEFORE first start → not counted (state seeded: "verdicts counted after …")
drift: report 1 → 0 runs, report 2 → 0 runs, report 3 (distinct) → run_started trigger=drift
runs/soc/learner.lock held + new capture → skipped reason=locked (no cooldown)
2nd trigger inside the cooldown → skipped reason=cooldown (logged once)
```

**4. Safety** — `models/` hashed before `up` and after `down` in every session: **identical every time**,
`models/archive` stayed empty.
```
gate PASS, no flag      → exit 10  "ready, waiting for approval"; status: ready to promote: soc_captures_… (command printed)
up --auto-promote, detection running → part_b "not promoted: run_pipeline.sh is running"; learner promote_busy,
                                        retried every 20 s (demo), then "ready_to_promote_manually"
up --auto-promote, detection idle    → promote_model.sh: "…_s43/dns_tunnel_rf.pkl is missing — nothing was changed";
                                        part_b "promote failed, models/ unchanged" (stub seeds have no model files)
every decision → one JSON line in runs/promotion_log.jsonl ("source":"learner"; part_b lines unchanged)
```
`down` exit 0 and `pgrep` found no stray process after every session; a second `up` started nothing.

## Independent review (agent that did not see the code) — findings and fixes
| # | Finding | Fix |
|---|---|---|
| CRITICAL | `train_new_data.sh` step 4 ran `train_models.sh --eda-only` **without** `DNS_DETECT_MODELS_DIR`; the merge rewrites `models/training_provenance.json` → every captures run would write `models/` outside `promote_model.sh`. Reproduced on the scratch copy (provenance hash changed). | EDA step now runs with `DNS_DETECT_MODELS_DIR=runs/<RUN>_eda` (backup in `runs/soc/backups/20261120_122954/`). Verified: provenance unchanged. Test greps every reachable `train_models.sh` call. |
| HIGH | `soc.sh down` → `kill-groups` SIGKILLed any pgid recorded in `runs/soc/state/*.json` without checking it is still ours (PID reuse after a WSL restart). | Kills only a group whose member still runs our command marker. Test with an unrelated group. |
| HIGH | Stub/test env (`SOC_TRAIN_CMD`, `PART_B_GATE`, `PART_B_PROMOTE`, `DNS_DETECT_MODELS_DIR`, …) leaked from the operator's shell into the real services → stub gate = promotion without the real gate. | `soc.sh up` drops them (prints which) unless `SOC_ALLOW_STUBS=1`. |
| MEDIUM | Drift arm consumed by `data_missing`/locked (no run) | Disarmed only when a run really starts. |
| MEDIUM | Every poll re-hashed every capture on `/mnt/c` | Skip files already trained on the listed checksum; (size, mtime) hash cache. |
| MEDIUM | Hash guard watched only the configured `models_dir` | Guards the configured dir **and** `<repo>/models`. |
| MEDIUM | Stale detection heartbeat after a dashboard killed mid-run blocked promotes up to 20 min (seen in the live check) | `pipeline_lock.active_readers()` drops a marker whose pid is dead on this host (backup of `pipeline_lock.py` in the same backups folder). |
| LOW | state file that is JSON but not an object crashed the learner | handled as corrupt → re-seeded |

Left as known gaps (see SOC_BUILD_NOTE): `check_allowed()` only protects against a literal forbidden
script path (a wrapper via `SOC_TRAIN_CMD` can bypass it — now only possible with `SOC_ALLOW_STUBS=1`);
verdicts younger than the settle window are exported but not counted (count inflated by at most one
window); `status` does not show whether auto-promote is armed; a promote run by hand with
`promote_model.sh` is only caught by the hash guard; training console not blocked by the learner;
Task 6 drift baseline; WSL idle shutdown untested.

## Shadow check (added afterwards)
Real bridge on the real live traffic (8,152 rows), VM: live model as candidate → flags 8098 vs 8098, agreement
1.0000 → PASS. Rejected retrain candidate `runs/retrain_20261120_010558_s42` → flags 6566 vs 8098, agreement
0.8121 → **FAIL** (would have been held back even on a gate PASS). `models/` untouched in both runs.
Full suite after the change: 506 passed, 2 skipped, 1 failed (the known offline test).

## What stays manual
Collecting attack data in the Kali lab (`lab_capture.sh`), analyst verdicts in the dashboard, approving a
promotion (`bash scripts/promote_model.sh <run>` as printed, or `soc.sh up --auto-promote`).

## Rolling back everything from this phase
```powershell
git switch main; git branch -D soc-automation            # before merging: drops all soc commits
```
After merging: `git revert` the soc commits, or restore the edited files from
`runs/soc/backups/20261120_120720/` and `runs/soc/backups/20261120_122954/` and delete the new files listed
in SOC_BUILD_NOTE. Then `bash scripts/soc.sh down` if anything is running.
