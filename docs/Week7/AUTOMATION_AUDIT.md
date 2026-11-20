# Automation audit: training + real-time detection

**DNS Traffic Anomaly Detection · audited 2026-11-20 on `main` (after Tasks 9, 10, 12)**

**Answer in one line:** the *pieces* follow best practice (separate training and detection, a gate before
promotion, run records, rollback), but the *system* is not yet automated end to end. Starting it takes
3 commands in 3 terminals, nothing restarts a crashed process, one promotion path skips the gate, and
real-time detection silently stops raising new alerts once a day's log has more than 200 ML hits.

Evidence labels: **Observed** = read in the code (file:line) or seen in a run on 2026-11-20.

---

## 1. What exists today

| Part | Piece | Started by | Runs in background? | Restarts on crash / boot? |
|---|---|---|---|---|
| Capture | Technitium DNS (Docker) | `docker compose up -d` | ✅ | ✅ `restart: always` (docker-compose.yml:11) |
| Capture | PushLogger app + `technitium_push_listener.py` | `scripts/setup_pushlogger.sh` | ✅ `nohup … &` (setup_pushlogger.sh:136) | ❌ |
| Detect | `dashboard/server.py` watch loop: every 3 s, re-runs extract → bridge → rules → monitor | `python3 dashboard/server.py` | ❌ foreground | ❌ |
| Detect | `run_pipeline.sh` / `run_all.sh --skip-train` (one-shot) | by hand | — | — |
| Learn | `train_models.sh` (12 steps) | by hand / console | — | — |
| Learn | `run_all.sh --retrain`, `train_new_data.sh` → seeds → gate → `part_b.py` | by hand | — | — |
| Learn | Training console (`/training`) → `train_models.sh` into its own run folder | browser | ✅ (dashboard thread) | ❌ |
| Learn | Retrain trigger (`monitor.py` → `retrain_recommended`) | — | — | — |

---

## 2. Scorecard against best practice

| Practice (source) | Status | Note |
|---|---|---|
| Training and serving are separate pipelines (Google MLOps [1]) | ✅ | Part 1 detect / Part 2 learn |
| Model validated before deployment (MLOps [1]; ML Test Score [2]) | ⚠️ | Part B gate ✅, **training console promote skips it** (C2) |
| Rollback to a known-good model ([2]) | ✅ | `rollback_model.sh`, archive in `models/archive/` |
| Reproducible runs: commit, packages, data hashes, seed ([2]) | ✅ | `run_record.json` |
| Schema check between model and code (training–serving skew [3]) | ✅ | bridge + `run_pipeline.sh` + promote |
| Continuous training triggered by new data / drift ([1]) | ❌ | trigger only in one-shot `run_all --auto-retrain`; not in real-time mode (H2) |
| Long-running services supervised, restart on failure, one start/stop command (12-factor "disposability" [4]) | ❌ | 3 manual starts, no supervisor (H3) |
| Real-time detection processes only new events | ❌ | whole day re-processed on every change (H4) |
| No silent loss of alerts | ❌ | per-run caps drop newest alerts (C1) |
| Monitoring that does not false-trigger | ⚠️ | drift fired on an attack-only log (M1) |
| Tests run automatically on every push (CI) | ❌ | no `.github/workflows` (M3) |
| Data retention / log rotation | ❌ | `data/raw`, `logs/`, `runs/` (1.8 GB) only grow (M2) |

---

## 3. Findings, most severe first

### C1 · Real-time detection stops alerting on new traffic (Critical)
- **Observed:** `src/dns_detect/detection/engine.py` stops each rule at a fixed count: 100 (line 638), 50 (684),
  200 (742, ML label), 200 (807, ML score). Rows are visited in file order, oldest first, with no sort.
- `dashboard/server.py:1093` re-runs the whole pipeline over every `data/raw/*.log` on each change.
- **Effect:** once a day's log already holds 200 ML-flagged queries, any later attack that day produces **no
  ML alert**. Seen in the 2026-11-20 run: 8,098 ML-flagged rows → "Alerts generated: 200".
- **Fix:** process only new rows (H4), and when a cap is still wanted, keep the **newest / highest-score** rows
  and report how many were left out (aggregate them into one "N more" alert) instead of dropping silently.

### C2 · Two ways to change `models/`, one skips every safety check (Critical)
- **Observed:** training console promote → `dashboard/training-gui/core/registry.py:101` `promote()` →
  `_deploy()` (line 88): copies the run folder over the whole production folder and moves the old one to
  `gui_data/backups/`. It only shows metric warnings, which `force` overrides; **no gate, no seeds, no schema
  check, no smoke test, no lock, no `PROMOTED.json`**. Because it moves the *whole* `models/` folder away,
  `models/archive/` (used by `rollback_model.sh`) goes with it.
- **Fix:** one door. The console's Promote calls `scripts/part_b.py` (or `promote_model.sh` + smoke test) for
  Capstone runs; its own `_deploy` stays only for demo mode.

### H1 · A promote can swap models in the middle of a detection run (High)
- **Observed:** `part_b.py:57` waits while `runs/.pipeline.lock` is held, but only `run_pipeline.sh:123` takes
  that lock. The dashboard's own pipeline (`server.py:1093`, the real-time path) does not.
- **Fix:** take the same shared lock in `server.py run_pipeline()`.

### H2 · The retrain trigger never fires in real-time mode (High)
- **Observed:** `monitor.py` sets `retrain_recommended`; `server.py` only displays it (lines 941, 1299).
  Acting on it exists only in one-shot `run_all.sh --auto-retrain` (run_all.sh:320).
- **Fix:** a small background "learner" that watches three triggers (drift flag, new files in an inbox folder,
  ≥ 50 verdicts) and runs Part B — at most one run at a time, with a cool-down, never while detection runs.

### H3 · No single start/stop, no supervision (High)
- **Observed:** 3 separate starts (Technitium, listener via `nohup`, dashboard in the foreground). A crashed
  listener or dashboard stays down; nothing starts at boot; logs go to different places.
- **Fix:** one command, `scripts/soc.sh up | down | status | logs`, that starts every service in the
  background with pid files, health checks and restart-on-crash (or systemd user units / docker compose).

### H4 · Every update re-processes the whole day (High, grows over time)
- **Observed:** extractor reads every `*.log` (extractor.py:476, 732); bridge reloads models each run.
- **Effect:** cost per update grows with the day's traffic; a B1-style multi-day capture makes each update slower.
- **Fix:** incremental detection: remember the byte offset per log file, process only new lines, carry the last
  5 minutes as context for the window features (same rule as `aggregates.py`), append new alerts.

### M1 · Drift monitor false-triggers on attack-heavy traffic (Medium)
- **Observed (2026-11-20):** a 3-minute attack-only log → `query_length` PSI 8.03 → "RETRAIN RECOMMENDED".
- **Fix:** measure drift on rows the model scores as normal, and require a minimum volume (Week 7 Task 6).

### M2 · Nothing is cleaned up (Medium)
`data/raw/` (1.2 MB now, grows daily), `logs/`, `runs/` (1.8 GB) only grow. **Fix:** retention settings
(e.g. keep 30 days of raw logs, last N candidate runs, compress old logs).

### M3 · No CI (Medium)
About 370 tests exist but run only by hand. **Fix:** a GitHub Actions workflow running `pytest` on every push
and pull request, so a merge can't break the pipeline unnoticed.

### M4 · Pipeline outputs tracked in git (Low)
`data/processed/week3_*`, `week4_*`, `*_report.json` show as modified after every run. **Fix:** untrack + ignore.

### L1 · Default admin token (Low, localhost only)
`server.py:3324` refuses non-localhost with the default token, which is correct. Keep it that way.

---

## 4. Target design: one command, both parts in the background

```
scripts/soc.sh up                         # start everything, in the background
scripts/soc.sh status | logs | down       # see / follow / stop

┌─ PART 1 · DETECT (always on) ─────────────────────────────────────────────┐
│ Technitium ──push──▶ listener ──▶ data/raw/*.log                          │
│                                     │ new lines only (offset + 5-min tail) │
│                                     ▼                                      │
│              detector: features → Path A/B → fusion → rules → alerts      │
│              (holds runs/.pipeline.lock while it scores)                   │
│                                     ▼                                      │
│              SOC dashboard (/triage /alerts /soc /health)  ── verdicts ──┐ │
│              monitor: drift on normal-looking traffic ── flag ─────────┐ │ │
└──────────────────────────────────────────────────────────────────────── │─│─┘
┌─ PART 2 · LEARN (event-driven, never blocks detection) ───────────────── │─│─┐
│ learner watches:  drift flag ◀───────────────────────────────────────────┘ │ │
│                   verdicts ≥ 50 ◀────────────────────────────────────────────┘ │
│                   new files in data/incoming/ (lab captures)                  │
│   → one run at a time, cool-down (e.g. 24 h)                                  │
│   → train 3 seeds into runs/ → gate → [auto-promote?] → promote_model.sh      │
│     → smoke test → rollback on failure → detector picks up new models         │
└───────────────────────────────────────────────────────────────────────────────┘
```

Rules the design keeps: one door into `models/` (Part B); detection never trains; training never blocks
detection; every decision logged (`runs/promotion_log.jsonl`); auto-promote stays opt-in.

---

## 5. Plan

| # | Work | Fixes | Effort |
|---|---|---|---|
| A | Alert caps: newest / highest score first + "N more" summary | C1 | ~1 h |
| B | Console Promote → `part_b.py` / `promote_model.sh` (one door) | C2 | ~1–2 h |
| C | Detection takes `runs/.pipeline.lock` | H1 | ~30 min |
| D | Incremental detection (offsets + 5-min context, append alerts) | H4, C1 | ~4–6 h |
| E | `scripts/learner.py`: drift / inbox / verdict triggers → Part B, cool-down, one at a time | H2 | ~3 h |
| F | `scripts/soc.sh up/down/status/logs`: background services, pid files, health checks, restart on crash | H3 | ~2–3 h |
| G | Drift on normal-looking traffic + minimum volume (= Task 6) | M1 | ~2–3 h |
| H | Retention settings + GitHub Actions CI + untrack outputs | M2–M4 | ~1–2 h |

Order: **C, A, B** first (small, they remove the silent failures), then **F** (the single command), **E**
(learner), **D** (incremental), **G**, **H**. All of it is code only — no new data, no Kali.

---

## 6. References

1. Google Cloud. *MLOps: Continuous delivery and automation pipelines in machine learning* (levels 0–2;
   continuous training triggers: on schedule, on new data, on drift; model validation before deployment).
   https://cloud.google.com/architecture/mlops-continuous-delivery-and-automation-pipelines-in-machine-learning
2. E. Breck et al. *The ML Test Score: A Rubric for ML Production Readiness and Technical Debt Reduction.*
   IEEE Big Data 2017. https://research.google/pubs/pub46555/
3. M. Zinkevich. *Rules of Machine Learning* (training–serving skew, Rules #29–#37).
   https://developers.google.com/machine-learning/guides/rules-of-ml
4. A. Wiggins. *The Twelve-Factor App* — VI Processes, IX Disposability, XI Logs. https://12factor.net/
5. D. Sculley et al. *Hidden Technical Debt in Machine Learning Systems.* NeurIPS 2015.

## Status — safety fixes (branch `safety-fixes`, 2026-11-20)

| Fix | Done | What changed | Test |
|---|---|---|---|
| **C1** alert caps | ✅ | `engine.py`: rows ranked strongest score first, newest on ties (`_prioritise`), caps in `ALERT_CAPS`; everything beyond a cap becomes one **"N more" overflow alert** (count, top domains/clients, time range). No silent `break` left. | `tests/test_safety_fixes.py` (4) |
| **C2** console Promote | ✅ | `training-gui/core/registry.py`: in Capstone mode Promote runs `scripts/part_b.py --run … --auto-promote` over every run trained the same way (gate ≥ 3 seeds → lock → `promote_model.sh` → smoke test → auto-rollback). "Confirm to override" can't skip the gate. Roll back runs `rollback_model.sh`. `models/archive/` is never moved. Demo mode unchanged. | 3 tests |
| **H1** detection lock | ✅ | New `src/dns_detect/utils/pipeline_lock.py` (flock + heartbeat file in `runs/.pipeline.readers/`, works on Windows/WSL). The dashboard's `run_pipeline()` holds it for the whole run; `part_b.py` refuses to promote while any reader is active. Stale heartbeats (> 20 min) are ignored. | 4 tests |

Full suite: 428 passed, 2 skipped, 1 failed — `test_labeling.py::test_parent_domain_psl_private_suffixes`
(pre-existing: needs the online public-suffix list; `labeling.py` untouched).
