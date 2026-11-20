# SOC automation research and design (Phase 2) — 2026-11-20

Scope: how to build `scripts/soc.sh` and the Learner around the fixed design (two independent services,
Detector and Learner, linked by the existing gate and lock). This is input for your approval. **No code yet.**
Ground truth for the repo is `docs/Week7/PROJECT_MAP_2026-11-20.md` ("the map"); file names below come from it.
Citations are numbered [n] and listed in section E. Every URL was opened on 2026-11-20 unless section E says otherwise.

---

## A. Findings

### A1. Supervising two long-running services with one command, without root (WSL)

**Process groups are the unit of stop.** `kill(2)` with a negative PID sends the signal to every process in that
process group [12]. `setsid` starts a program in a new session (new group) [13], and Python's
`subprocess.Popen(start_new_session=True)` calls `setsid()` in the child before exec [20]. If each supervised child is
started this way, `os.killpg(pgid, SIGTERM)` reaches its whole tree. That is what `dashboard/server.py` needs:
its `pipeline_steps` children are started by `subprocess.run` and stay in its group, and server.py has no SIGTERM
handler (map §a1).

**TERM → wait → KILL is the standard.** systemd sends `KillSignal=` (default SIGTERM) and escalates to
`FinalKillSignal=` (default SIGKILL) after `TimeoutStopSec=`. Its default `KillMode=control-group` kills every remaining
process of the unit, not just the main one, and it advises against modes that let processes escape [3][2]. supervisord
has the same idea as `stopwaitsecs` (default 10 s), and `stopasgroup`/`killasgroup` send the stop or kill signal to the
whole process group. Its docs name programs that do not forward signals to children as the use case [7].

**Restart with exponential backoff.** systemd ≥ 254 (the page documents 262) has `RestartSec=`, `RestartSteps=` and
`RestartMaxDelaySec=`. The delay grows geometrically from RestartSec to RestartMaxDelaySec, for example 10 s → 20 → 40 → 80 → 160 s, then stays at 160 s.
The page describes `RestartSteps=` as the setting that "Configures the number of exponential steps to take to increase the interval of auto-restarts" [2].
Rate limiting (`StartLimitBurst`/`StartLimitIntervalSec`) stops restarts entirely when a unit starts too often [5].
supervisord's backoff is linear, "adding one second each time", and after `startretries` (default 3) the program goes
to FATAL and needs a manual restart [8][7]. Its `startsecs` (default 1 s) is the "must stay up this long to count as
started" rule, which is the basis for resetting the backoff after a healthy period [7].

**Idempotent start.** A PID file alone is racy: PIDs get reused and the file goes stale. A `flock` held for the
supervisor's whole lifetime is reliable, because "a lock is automatically dropped when the file is closed" [16], and the
kernel closes the file when the process dies. A second `up` probes the lock with `flock -n` and starts nothing [16]. The
repo already uses this pattern (`runs/.pipeline.lock`, `runs/.promote.lock`, `src/dns_detect/utils/pipeline_lock.py`).

**Health checks.** Neither the systemd nor the supervisord pages above define HTTP health checks. Both only watch process
exit. An HTTP probe (`/api/health` on :9000, `/healthz` on :8787, both already in the repo) has to live in our own
supervisor. Restart only after several failed probes in a row, past a startup grace period. This is the same "broad
enough not to trigger spuriously" principle Sculley et al. give for action limits [21].

**Logs and rotation.** supervisord captures child stdout and rotates it by size (`stdout_logfile_maxbytes` default 50 MB,
`stdout_logfile_backups` default 10) [7]. Python's `RotatingFileHandler` does the same with `maxBytes`/`backupCount` [19].
`logrotate` needs a scheduler (cron/root) and, for programs that cannot reopen logs, `copytruncate`. Its man page warns
that with copytruncate "some logging data might be lost" [17]. If the supervisor reads each child's stdout pipe and writes it
with size rotation, no external tool is needed.

**Lower-priority training.** `nice` adds 10 by default. The range runs from −20 (most favourable) to 19 (least) [14].
`ionice -c3` (idle) is allowed for non-root users since 2.6.25. An idle-class process gets disk time only when nothing
else wants it [15]. The kernel honours I/O priorities only in the BFQ and mq-deadline schedulers [18]. On WSL2, files
under `/mnt/c` go through the Windows file share, not a Linux block scheduler, so **`ionice` is probably a no-op for this
repo**. *(This is an inference: no source states it for WSL.)* Keep `ionice` because it is harmless, but rely on `nice` for
acceptance criterion 1. systemd's equivalents are `Nice=` and `IOSchedulingClass=idle` [4].

**systemd --user vs supervisord vs a small own supervisor.**
- *systemd --user* would give all of the above for free (user units in `~/.config/systemd/user` [5]). But on WSL it
  needs `[boot] systemd=true` in `/etc/wsl.conf` and `wsl --shutdown`. For Kali, Microsoft also says to install
  `systemd systemd-sysv` with `sudo apt-get` [10]. Editing `/etc/wsl.conf` needs root. The default is `false` [11]. Units
  survive logout only with `loginctl enable-linger` [6]. This breaks the "no sudo" rule unless systemd is already on
  (map question 3).
- *supervisord* (4.3.0) installs with pip into the venv, and its docs do not require root to run it [9]. But it brings
  its own daemon, config and control socket. Its backoff is linear and gives up after `startretries` (FATAL) [8]. That
  conflicts with "each service restarts on its own".
- *Own supervisor* (Python stdlib + bash front-end): fits the repo conventions and works with or without systemd. It can
  be tested with pytest. We copy the proven semantics: group kill [3][7], TERM→KILL timeout [2], exponential backoff
  with reset [2][7], size-rotated logs [7][19].

**WSL specifics.** The distro keeps running for about 8 s after the last shell closes. Instances also shut down after
being idle (`instanceIdleTimeout` in the Windows-side `%UserProfile%\.wslconfig`, default 15000 ms; the docs say to
"Set to -1 to disable auto shutdown") [11]. `wsl --shutdown` stops all distros at once [11]. The docs do not say whether
background processes alone count as "not idle". **Not verified.** It must be tested in Phase 4. `[boot] command=` runs
as root from `/etc/wsl.conf` [11], so boot-time auto-start is out of scope (no sudo).

### A2. Continuous training: when to retrain

- Google's MLOps level 1 lists five pipeline triggers: on demand, on a schedule, on new training data, on performance
  degradation ("The model is retrained when there is noticeable performance degradation."), and on significant changes
  in feature distributions [1]. Our fixed design uses three of them: new data (b, c) and distribution change (a).
- Level 1 puts **data validation before training**, to decide whether to retrain or stop the pipeline. It also puts
  **model validation** after training, where the new model must beat the current one before promotion. A metadata store
  records every run, including pointers to previous models for rollback [1].
- **False drift triggers.** Sculley et al. warn that fixed thresholds in a changing system go stale. They recommend
  monitoring with limits that are "broad enough not to trigger spuriously" [21]. The repo already shows this failure:
  `data/processed/monitoring_report.json` says `retrain_recommended: true` (PSI on query_length 8.03, saturated scores)
  because `data/raw` holds attack-only traffic (map §b). Arp et al. call this kind of mismatch **sampling bias (P1)**.
  It was at least partly present in about 90 % of the 30 papers they reviewed [24]. Retraining on the same files does not
  remove drift that comes from what is being *measured*. So trigger (a) must be (i) counted over several distinct
  monitoring reports, (ii) edge-triggered, and (iii) tied to having something new to train on (design in §C5).
- **Minimum new samples / cooldown / one at a time.** Google says to pick a cadence based on how fast data changes and
  how costly retraining is [1]. Zinkevich Rule #8 says to measure how fast the model goes stale before choosing how often
  to update it [23]. The repo already sets the verdict floor: `settings.yaml feedback.min_verdicts 50` (map §a2).
  `train_models.sh` writes shared `data/processed/merged_*` files, so the learner must hold a single-run lock (map §a3).
- **Keep unreviewed labels out.** Arp et al. P2 (label inaccuracy): check labels, and *delay labelling until the ground
  truth is stable*, to avoid label shift [24]. Here that means: count only records in
  `dashboard/data/alert_management.json` that have a `verdict`, and only verdicts older than a settle time (an analyst
  may change one). Train only through `scripts/export_feedback_labels.py`. Never use unreviewed alerts or model outputs as
  labels. Sculley et al. warn about **direct and hidden feedback loops**, where a model shapes its own future training
  data [21]. Analysts only judge alerts the model raised. So verdict labels must go only into the *training* split. The
  gate's fixed test rows must stay untouched (open question D-8).

### A3. Safe promotion for a high-stakes detector

- The ML Test Score's infrastructure tests include "Model quality is validated before serving." (Infra 4), canarying
  (Infra 6) and rollback (Infra 7). Its monitoring tests include training/serving skew (Mon 3), staleness (Mon 4) and
  prediction-quality regression (Mon 7) [22]. Zinkevich Rule #9 says to check for problems before exporting a model, and
  Rule #24 says to measure the delta between the new and production models [23]. Google level 1 adds online validation
  (canary or A/B) after offline validation [1].
- The repo already covers most of this. Offline gate: `scripts/compare_models.py` + `config/success_criteria.yaml`
  (3 seeds, same split, recall ≥ 0.95, FPR budget, not worse than `models/` on the same rows). Schema check and archive:
  `scripts/promote_model.sh`. Post-promote smoke test with automatic rollback: `scripts/smoke_models.py` →
  `scripts/rollback_model.sh`. Audit log: `runs/promotion_log.jsonl` (map §a2–a3). **Shadow/canary scoring does not
  exist.** Adding it means changing the detector (`dns_detect.fusion.bridge`), which is out of scope. The smoke test is
  the offline stand-in. Default human approval (`auto_promote: false`) covers the remaining risk.
- **Locking between serving and promotion.** `part_b.py` refuses to promote (exit 3) while `runs/.pipeline.lock` is held
  or heartbeats in `runs/.pipeline.readers/` are fresh (< 20 min). As described in the map, this is a *probe*, then
  `promote_model.sh`. A detection run could start in the gap between them (open question D-11). The learner must
  **retry** on exit 3, not fail. Section C sets a bounded retry policy.
- **Action limits** [21]: cap automatic actions (training runs per day, auto-promotions per week), so a fault cannot
  churn `models/`.

### A4. Intrusion-detection specifics

- **Base-rate fallacy.** Axelsson shows that "the false alarm rate is the limiting factor" for an IDS, because attacks
  are rare. In his example scenario, a useful Bayesian detection rate needs about 1 false alarm per 100,000 events [25].
  Sommer & Paxson add that, because errors are costly, "even a very small rate of false positives can quickly render an
  NIDS unusable" [26]. Arp et al. P7/P8 recommend precision/recall, and reporting false positives against the benign
  base rate to show analyst workload [24]. *Consequence:* the gate's FPR budget in `success_criteria.yaml` is the most
  important check, and it must not be loosened to make automation "pass". An automatic promote should need explicit
  opt-in, as already designed.
- **Outside the closed world** [26]: ML is better at finding things like what it has seen than at finding true novelty.
  Traffic is diverse and bursty, and "anomaly" is not "attack". Their advice is to keep the scope narrow, compare
  against simple baselines, and check false positives with operators. The repo's gate already requires beating every
  rule baseline on every seed. Kali-lab captures are lab-only data (Arp P9 [24]). A model that passes the gate on lab
  data is still a candidate, not proof. That supports *stop at "ready to promote"* by default.
- **Data snooping / temporal leakage (Arp P3)** [24]: new data must not leak into the fixed test split. The learner must
  reuse the existing split manifest (`run_candidate_seeds.sh SPLIT`), and must not let `--new-split` reshuffle old test
  rows into training. `train_new_data.sh` step 5 uses `--new-split`. Check what it does to existing test rows
  (open question D-9).
- **Poisoning (Arp P10)** [24]: auto-training on analyst verdicts and dropped-in capture files is an attack surface. The
  defences are the `SHA256SUMS` checks (already in `train_new_data.sh`), reviewed verdicts only, the gate, and manual
  promotion by default.

---

## B. ADOPT / ADAPT / SKIP

| # | Practice (source) | Decision | Reason, naming the repo file it affects or reuses |
|---|---|---|---|
| 1 | Separate serving and training pipelines [1] | ADOPT | New `scripts/learner.py` runs under its own supervisor. `dashboard/server.py` watch loop stays detection-only, unchanged. |
| 2 | Retrain on new data [1] | ADOPT | Triggers (b) `data/processed/week7/*.json` + `SHA256SUMS`, and (c) `dashboard/data/alert_management.json`. |
| 3 | Retrain on distribution change [1] | ADAPT | `data/processed/monitoring_report.json` fires on attack-only `data/raw`. Use N consecutive distinct reports, edge-triggered, plus a new-data requirement (§C5). |
| 4 | Scheduled retraining [1] | SKIP | Not one of the three fixed triggers. Would retrain on unchanged `models/training_provenance.json` files. |
| 5 | Data validation before training [1] | ADOPT (reuse) | `scripts/train_new_data.sh` steps 1–3 (`sha256sum -c`, `check_<RUN>.json`). Learner ignores capture files not listed in `SHA256SUMS`. |
| 6 | Model validation vs production [1][22 Infra 4][23 #9,#24] | ADOPT (reuse, unchanged) | `scripts/compare_models.py` + `config/success_criteria.yaml` through `scripts/part_b.py`. Learner never calls the gate itself. |
| 7 | Canary / shadow serving [1][22 Infra 6] | SKIP (future) | Would need changes to `dns_detect.fusion.bridge` and `dashboard/server.py`, which must stay as today. `scripts/smoke_models.py` is the offline stand-in. |
| 8 | Fast rollback [22 Infra 7] | ADOPT (reuse) | `scripts/rollback_model.sh`, `models/archive/`, called by `part_b.py` on smoke failure. |
| 9 | Run metadata / audit [1] | ADOPT | Append learner decisions to `runs/promotion_log.jsonl` with `"source":"learner"`. part_b lines stay as they are. |
| 10 | Group kill on stop [3][7][12] | ADOPT | `dashboard/server.py` children (`pipeline_steps`) and `train_models.sh` children get `killpg`. |
| 11 | TERM → timeout → KILL [2][3][7] | ADOPT | `scripts/soc_supervisor.py` with `stop_timeout_s` per service. |
| 12 | Exponential backoff with reset after healthy [2][7 startsecs] | ADOPT | `scripts/soc_supervisor.py`. State in `runs/soc/state/*.json`. |
| 13 | Give up after N failures (FATAL) [8] / start rate limit [5] | SKIP | Criterion 2 says each service restarts on its own. Cap the delay (`backoff_max_s`) instead of stopping. |
| 14 | flock-based single instance [16] | ADOPT | `runs/soc/<svc>.supervisor.lock`. Same pattern as `src/dns_detect/utils/pipeline_lock.py`. |
| 15 | HTTP health probes | ADOPT | `/api/health` (`dashboard/server.py`), `/healthz` (`scripts/technitium_push_listener.py`). Learner writes a heartbeat file. |
| 16 | Size-rotated logs, written by the supervisor [7][19] | ADOPT | New `logs/soc/*.log`. Replaces `scripts/.push_listener.log` only when started via soc.sh. `setup_pushlogger.sh` unchanged. |
| 17 | logrotate + copytruncate [17] | SKIP | Needs cron/root and can lose lines. Rotation lives in `scripts/soc_supervisor.py`. |
| 18 | `nice` training [14] | ADOPT | Learner wraps `scripts/train_new_data.sh` / `scripts/run_candidate_seeds.sh` in `nice -n 10`. |
| 19 | `ionice -c3` [15][18] | ADAPT | Use only if `ionice -c3 true` succeeds. Probably no effect on `/mnt/c` (WSL). Not relied on for criterion 1. |
| 20 | systemd --user units [5][6][10] | SKIP (now) | Needs `/etc/wsl.conf` + apt (sudo) on Kali. `soc_supervisor.py --foreground` keeps the option open later. |
| 21 | supervisord [7][8][9] | SKIP | Extra daemon and config. Linear backoff and FATAL conflict with criterion 2. Its semantics are copied into `soc_supervisor.py`. |
| 22 | Minimum new samples [1][23 #8] | ADOPT | `min_new_verdicts: 50`, same as `config/settings.yaml feedback.min_verdicts`. |
| 23 | Cooldown + one run at a time | ADOPT | `runs/soc/learner.lock`, plus a probe of `runs/.promote.lock`. Needed because `train_models.sh` writes shared `data/processed/merged_*`. |
| 24 | Reviewed labels only, after they settle [24 P2] | ADOPT | Count only `records[*].verdict` with `verdict_at` older than `verdict_settle_minutes`. Export only via `scripts/export_feedback_labels.py`. |
| 25 | Feedback-loop guard [21] | ADAPT | Verdict rows go into training only, never into the split in `runs/<RUN>_split.json`. Must be confirmed in `train_models.sh --feedback` (D-8). |
| 26 | FPR budget / base rate in the gate [24 P7–P8][25][26] | ADOPT (unchanged) | `config/success_criteria.yaml` stays untouched. Learner logs the gate's FPR from `runs/<RUN>_gate.json` in its decision line. |
| 27 | Human approval by default [26][24 P9] | ADOPT | `auto_promote: false` in `config/soc.yaml`. `part_b.py` without `--auto-promote` exits 10 and prints the command. |
| 28 | Action limits [21] | ADOPT | `max_runs_per_day`, `max_auto_promotions_per_week` in `config/soc.yaml`. Checked against `runs/promotion_log.jsonl`. |
| 29 | Serving/promotion lock + retry | ADOPT/ADAPT | Reuse `runs/.pipeline.lock` + `runs/.pipeline.readers/` checks inside `part_b.py`. Learner adds bounded retry on exit 3. |
| 30 | Unexpected-change guard | ADOPT | Learner hashes `models/` before and after every training step. A change outside `part_b.py` is logged as `models_changed_unexpectedly`. |

---

## C. Design

### C1. Recommended supervisor

**Recommendation: one small Python supervisor per service (`scripts/soc_supervisor.py detector|learner`), started and
controlled by a bash front-end `scripts/soc.sh`.** It needs no root, no systemd and no new package beyond the venv's
PyYAML (already used for `config/*.yaml`). There is one supervisor *per service*, not one for both. That way a crash or
hang in the learner's supervisor cannot touch the detector's, which matches criterion 2. Each supervisor:
- holds `runs/soc/<svc>.supervisor.lock` (flock -x) for its lifetime [16] → idempotent `up`;
- is started by soc.sh with `setsid -f` [13] (survives terminal close), stdin from /dev/null;
- starts each child with `start_new_session=True` [20] (own process group), at the child's configured `nice`;
- pipes child stdout+stderr into `logs/soc/<child>.log` with size rotation [7][19];
- restarts a child on any exit (unless stopping), after `delay = min(base·2^(n-1), max)`. `n` resets to 0 once the
  child has been healthy for `reset_after_healthy_s` [2][7];
- after a child exits, and before restarting it, runs `killpg(pgid, TERM)` → wait → `killpg(pgid, KILL)` on the old
  group, so no orphaned `pipeline_steps` or `train_models.sh` are left [3][12];
- on start, kills any group recorded in `runs/soc/state/<child>.json` that is still alive, but only after checking
  `/proc/<pid>/cmdline`. This handles strays from a supervisor that was SIGKILLed;
- on SIGTERM: stops its children (TERM group → `stop_timeout_s` → KILL group) and exits 0. For the learner, if
  `runs/.promote.lock` is held, it first waits up to `promote_grace_s`, so a promote is never cut in half (see D-12);
- has a `--foreground` flag for tests and for a possible future systemd user unit.

The detector supervisor manages **two children**: `listener` and `dashboard`. Each restarts independently. The learner
supervisor manages one child: `learner`.

### C2. Files

| File | New / edited | Purpose |
|---|---|---|
| `scripts/soc.sh` | new | `up / down / restart [svc] / status / logs [svc] [-f]`. `set -euo pipefail`, `cd "$(dirname "$0")/.."`. |
| `scripts/soc_supervisor.py` | new | Per-service supervisor (C1). `ROOT = Path(__file__).resolve().parent.parent`. |
| `scripts/learner.py` | new | Trigger loop (C5). Calls only existing Part B scripts. |
| `src/dns_detect/soc/` (`config.py`, `state.py`, `triggers.py`) | new, optional | Pure functions for the triggers and state, so tests can import them. Could also live inside `learner.py`. |
| `config/soc.yaml` | new | All settings (C3). |
| `tests/test_soc_supervisor.py`, `tests/test_learner_triggers.py`, `tests/test_soc_cli.py`, `tests/fixtures/soc/*` | new | C8. |
| `scripts/run_candidate_seeds.sh` | **edited (≈3 lines)**, backup `scripts/run_candidate_seeds.sh.bak_<YYYYmmdd_HHMMSS>` | `FEEDBACK` env pass-through: if set, append `--feedback "$FEEDBACK"` to every seed's `train_models.sh` call. Default empty = behaviour unchanged. **Needs your OK (map Q2).** |
| `scripts/train_new_data.sh` | unchanged, but must be committed first | Already exists (uncommitted on `safety-fixes`). Run name: confirm whether it takes `RUN_NAME` from the environment (D-10). |
| `README.md`, `docs/Week7/SOC_BUILD_NOTE_<date>.md` | edited / new | Phase 3 documentation (README backup first). |
| `.gitignore` | edited (1–2 lines), backup | Ignore `runs/soc/` and `logs/soc/`. |

Not touched: `scripts/run_all.sh`, `scripts/run_pipeline.sh`, `dashboard/server.py`, `scripts/part_b.py`,
`scripts/compare_models.py`, `config/success_criteria.yaml`, `scripts/promote_model.sh`, `scripts/smoke_models.py`,
`scripts/rollback_model.sh`, `models/`, `data/`, `outputs/`.

### C3. `config/soc.yaml` (proposed defaults)

```yaml
# One-command operation (scripts/soc.sh). Safe defaults: nothing is promoted automatically.
python: null                    # null = $SOC_PYTHON, else active $VIRTUAL_ENV/bin/python, else python3
state_dir: runs/soc             # PIDs, locks, state.json (new files only)
log_dir: logs/soc
log_rotate: {max_bytes: 10485760, backups: 5}   # 10 MB x 5 per child log
keep_train_logs: 20             # logs/soc/train_<RUN>.log kept (only files soc wrote)

detector:
  listener:
    cmd: ["{python}", "scripts/technitium_push_listener.py", "--port", "8787"]
    health_url: http://127.0.0.1:8787/healthz
  dashboard:
    cmd: ["{python}", "dashboard/server.py", "--port", "9000"]   # add --host 0.0.0.0 only with a real ADMIN_TOKEN
    health_url: http://127.0.0.1:9000/api/health
  technitium_url: http://127.0.0.1:5380   # status only; Docker is NOT managed by soc.sh
  nice: 0
  stop_timeout_s: 15

learner:
  cmd: ["{python}", "scripts/learner.py"]
  heartbeat_stale_s: 180        # 3 x poll: learner considered hung -> restarted
  stop_timeout_s: 30
  promote_grace_s: 180          # on stop, wait this long if runs/.promote.lock is held

health: {interval_s: 15, timeout_s: 5, startup_grace_s: 90, fail_threshold: 4}
restart_backoff: {base_s: 2, max_s: 300, reset_after_healthy_s: 120}

poll_interval_s: 60
cooldown_minutes: 1440          # 24 h after ANY training run (success, FAIL, exit 4, aborted)
max_runs_per_day: 2             # action limit [21]
training_priority: {nice: 10, ionice_class: 3}   # ionice used only if `ionice -c3 true` works

triggers:
  drift:                        # (a)
    enabled: true
    report: data/processed/monitoring_report.json
    consecutive_reports: 3      # distinct reports (by sha256) with retrain_recommended: true
    edge_triggered: true        # fire once; re-arm only after a report with retrain_recommended: false
    require_new_data: true      # fire only if >=1 untrained capture or >=1 settled verdict exists (C5)
  captures:                     # (b)
    enabled: true
    dir: data/processed/week7
    pattern: "*.json"
    require_sha256sums: true    # only files listed in SHA256SUMS and passing sha256sum -c
    settle_seconds: 120         # file mtime must be this old (copy finished)
  verdicts:                     # (c)
    enabled: true
    store: dashboard/data/alert_management.json   # honours SOC_DASHBOARD_DATA_DIR like server.py
    min_new_verdicts: 50        # = settings.yaml feedback.min_verdicts
    verdict_settle_minutes: 60  # ignore verdicts newer than this (analyst may change them)
    export_url: http://127.0.0.1:9000

train:
  seeds: "42 43 44"
  split: null                   # null = run_candidate_seeds.sh default (live model split)

auto_promote: false             # true = pass --auto-promote / AUTO_PROMOTE=1. CLI: learner --auto-promote
max_auto_promotions_per_week: 1
promote_retry:                  # only when part_b exits 3 AND its log line says busy/detection running
  interval_s: 120
  max_attempts: 15              # 30 min > 20-min heartbeat staleness in pipeline_lock.py
```

Env overrides for tests and the live check (same style as `PART_B_*`): `SOC_CONFIG`, `SOC_PYTHON`, `SOC_TRAIN_CMD`
(replaces the training command; gets `--trigger X --run RUN`), `SOC_EXPORT_CMD`, `SOC_PART_B_CMD`, `SOC_NOW` (fake clock).

### C4. State and logs (new files only)

```
runs/soc/detector.supervisor.{pid,lock}   runs/soc/learner.supervisor.{pid,lock}
runs/soc/state/{listener,dashboard,learner}.json   # pid, pgid, started_at, restarts, last_exit, backoff_n, healthy_since
runs/soc/learner.lock                     # flock -x while a training run is in progress (inherited by the training child)
runs/soc/learner.heartbeat                # touched every loop iteration
runs/soc/learner_state.json               # trigger memory (below), written atomically (tmp + os.replace)
logs/soc/{supervisor-detector,supervisor-learner,listener,dashboard,learner}.log (+ .1..5)
logs/soc/train_<RUN>.log                  # full output of one training run
```

`learner_state.json`:
```json
{"drift": {"armed": true, "consecutive": 0, "last_report_sha256": null},
 "captures": {"trained": {"capture_x.json": "<sha256>"}},
 "verdicts": {"trained_until": "2026-11-20T10:00:00Z", "trained_count": 0},
 "last_run": {"run": null, "trigger": null, "started_at": null, "finished_at": null, "exit": null},
 "cooldown_until": null, "pending_promote": null}
```
On first start, the state is seeded from what exists: all current captures are marked trained only if they appear in
`models/training_provenance.json` source files, and `trained_until` is the newest existing `verdict_at`. This way
starting soc does not trigger on old history. **D-5 asks you to confirm this.**

### C5. Learner loop

```
startup: load config, state; if state.last_run has started_at but no finished_at and learner.lock is free:
         log {event:"run_aborted"}; set finished_at; cooldown_until = now + cooldown   # killed mid-run
loop every poll_interval_s (touch heartbeat each time; SIGTERM -> finish current wait, exit 0):
  # ---- evaluate (cheap, read-only) ----
  drift   = read monitoring_report.json (JSON error -> treat as "no new report")
            if sha256 changed: consecutive = consecutive+1 if retrain_recommended else 0
                               if not retrain_recommended: armed = true
            drift_due = armed and consecutive >= N
  caps    = files in captures.dir matching pattern, listed in SHA256SUMS, sha verified, mtime older than settle,
            whose sha256 is not in state.captures.trained
  verd    = records with verdict set and verdict_at > trained_until and verdict_at < now - settle
  new_data = len(caps) > 0 or len(verd) > 0
  due: (b) if caps;  (c) if len(verd) >= 50;  (a) if drift_due and (new_data or not require_new_data)
       drift_due but no new data -> log once {decision:"skipped", reason:"drift_without_new_data"}, armed=false
  pick ONE by priority (b) > (c) > (a); the others stay due for later
  # ---- gates before starting ----
  if none due: continue (no log line)
  if now < cooldown_until -> log once per (trigger, cooldown window) {decision:"skipped", reason:"cooldown"}
  if runs today >= max_runs_per_day -> skipped "action_limit"
  if flock -n runs/soc/learner.lock fails, or runs/.promote.lock busy, or a foreign train_models.sh is running
       -> skipped "locked" (retry next poll, no cooldown)
  # ---- run ----
  RUN = soc_<trigger>_<UTC yyyymmdd_HHMMSS>; hash models/ -> H0
  env: RUN_NAME=RUN, SEEDS, SPLIT; AUTO_PROMOTE=1 only if auto_promote and weekly limit not reached, else unset
  (b) nice -n 10 [ionice -c3] bash scripts/train_new_data.sh data/processed/week7
  (c) python scripts/export_feedback_labels.py --url <export_url>   (fails -> log error, cooldown)
      FEEDBACK=data/feedback/verdict_labels.json nice ... bash scripts/run_candidate_seeds.sh
  (a) new data -> the (b) or (c) command for what is new (captures take priority); else run_candidate_seeds.sh defaults
  child runs in the learner's process group, holding learner.lock fd; output -> logs/soc/train_<RUN>.log
  log {event:"run_started", trigger, run, inputs:{captures:[sha..], verdicts:n, drift_consecutive}}
  wait (polling, heartbeat kept fresh)
  outcome = exit code + last part_b line in promotion_log.jsonl with name == RUN
     0  promoted            10 ready to promote (print `part_b.py --name RUN --seeds ... --auto-promote`)
     1  gate FAIL           2  smoke failed, rolled back
     3  busy -> pending_promote = {run, attempts:0} (only if auto_promote; else treat as 10)
     4  data missing -> log reason, cooldown, inputs NOT marked trained
     other -> error, cooldown
  mark inputs trained for exits 0/1/2/10/3 (training completed); cooldown_until = now + cooldown
  hash models/ -> H1; if H1 != H0 and outcome not in (0, 2): log {event:"models_changed_unexpectedly"} (alert)
  log {event:"run_finished", trigger, run, exit, outcome, gate_fpr?, gate_recall?}
  # ---- promote retry (separate from triggers; does not train) ----
  if pending_promote and due: SOC_PART_B_CMD or `python scripts/part_b.py --name RUN --seeds "..." --auto-promote`
     3 -> attempts+1, until max_attempts then log "ready_to_promote_manually"; 0/1/2 -> log and clear
```

Every learner line goes to `runs/promotion_log.jsonl` as **one JSON line** (single `O_APPEND` write) with
`"source": "learner"`, plus `time`, `event`, `decision`, `trigger`, `reason`, `run`, `exit`, `git_commit`. part_b
lines have no `source` field, so readers can tell them apart. Idle polls are not logged, so the log does not flood.

The learner never calls `train_models.sh`, `promote_model.sh` or `rollback_model.sh` directly. A test checks the
allowlist of commands it can build.

### C6. `soc.sh` sub-commands and exit codes

- **`up`**: resolve python and config. For each service in order (detector, then learner): if `flock -n` on its
  supervisor lock fails → print "already running (pid N)" and start nothing. Otherwise `setsid -f <python>
  scripts/soc_supervisor.py <svc>`. If port 9000 or 8787 is already taken by a process soc did not start, print
  `port in use by PID X (not managed by soc)` and do not start that child. Then wait up to
  `startup_grace_s` for the health URLs, and print a summary. Exit 0 if both are running and healthy. Exit 2 if they
  started but are not healthy yet. Exit 1 on an error.
- **`down`**: learner first, then detector. Send SIGTERM to the supervisor PID, after checking `/proc/PID/cmdline` is
  `soc_supervisor.py`. Wait `stop_timeout_s + promote_grace_s + 5` for the learner, `stop_timeout_s + 5` for the
  detector. If a supervisor is still alive, SIGKILL it and `kill -KILL -<pgid>` every recorded child group. Then scan
  for strays with `pgrep -f` on `technitium_push_listener.py|dashboard/server.py|scripts/learner.py|soc_supervisor.py|
  train_models.sh|run_candidate_seeds.sh|train_new_data.sh`, limited to processes whose cwd is the repo. Exit 0 if
  there are none. Exit 1 and list them otherwise. Running `down` when nothing is running exits 0.
- **`restart [detector|learner]`**: `down` then `up` for the named service (default: both). Restarting one service
  never touches the other.
- **`status`**: per child: state (running / backoff / stopped), PID, uptime, restarts, last exit, health. Then: the
  last learner decision line (time, trigger, decision, reason), the last gate result (newest part_b line: decision, run),
  the live model (`models/PROMOTED.json` name/run + sha256, with a ✓ if a fresh sha256 of the listed files matches),
  pending "ready to promote" (newest part_b line with exit/decision "ready" and no later promoted line for the same
  name, printed with its promote command), cooldown remaining, and Technitium reachable yes/no. Exit 0 if both
  services are running, 3 if any is not running (our own convention, so scripts can use it).
- **`logs [detector|learner] [-f]`**: `tail -n 200` (or `tail -F` with `-f`, which survives rotation) on
  listener+dashboard logs, the learner log plus its newest `train_<RUN>.log`, or all of them. Exit 0.
- Unknown command → usage, exit 1.

### C7. Acceptance criteria: how each is met and shown

Live check (Phase 4) setup: `sha256sum` of every file under `models/` → `before.txt`. Run the real `soc.sh up`.
Set `SOC_TRAIN_CMD=tests/fixtures/soc/fake_train.sh`, which burns CPU on all cores for 120 s (it needs no root
stress tool, just a Python busy loop per core), writes fake `runs/<RUN>_s*/evaluation_metrics.json`, and then calls the
**real** `scripts/part_b.py` with `PART_B_GATE` pointing to a stub that passes (or fails). Use short
`cooldown_minutes`/`poll_interval_s` from a demo `SOC_CONFIG`. `dashboard/server.py --demo` is only for UI screenshots;
criterion 1 needs the real watch loop.

1. **Different speeds.** Training is a separate process tree at nice 10 under another supervisor, and it never takes
   `runs/.pipeline.lock`. *Show:* send N probe queries through the listener (`POST /push`, marker domain
   `soc-probe-<n>.invalid`) before and during the CPU-burning fake training. Measure the time from POST until
   `monitoring_report.json`/alerts are rewritten. Report median and max. Pass if the median during training is
   ≤ 1.5× the baseline *(proposed threshold, D-13)*. `ps -o pid,ni,cmd` shows NI=10 for training and 0 for the detector.
2. **Failures don't spread.** *Show:* (i) `kill -9` the learner during fake training → status shows only the learner's
   restart count +1, training group gone (`pgrep`), `run_aborted` logged, detector PID/uptime unchanged, probes still
   scored; (ii) stub gate FAIL → part_b exit 1, `models/` hash unchanged, detector unchanged; (iii) `kill -9` the
   dashboard → it restarts after backoff, no orphaned pipeline steps, learner PID/restarts unchanged; (iv) kill it again
   quickly → the restart delay doubles (seen in `supervisor-detector.log`).
3. **Different triggers.** *Show:* probes alone (new log lines) → no `run_started` line. Then, one at a time:
   (b) copy a fixture capture + `SHA256SUMS` line into a **temporary** `captures.dir` (demo config, so the real
   `data/processed/week7` is not touched) → one run; (c) a demo `SOC_DASHBOARD_DATA_DIR` with 50 settled verdicts →
   one run; 49 → none; (a) a demo `report` path with 3 distinct `retrain_recommended: true` reports → one run (with
   `require_new_data:false` in the demo config), a 4th → none (edge-triggered). Two triggers inside the cooldown →
   `skipped: cooldown`. A held `runs/soc/learner.lock` → `skipped: locked`.
4. **Safety.** *Show:* with the default `auto_promote:false`, the PASS stub → part_b exit 10, "ready to promote" in
   `status`, and `after.txt` == `before.txt`. Grep the code: the only `models/` writer reachable from soc is
   `promote_model.sh` via `part_b.py`. Busy-detection behaviour is shown in pytest with stubs (exit 3 → retries), not
   live. Smoke-fail rollback is the existing `part_b.py` path, covered in pytest with `PART_B_SMOKE` failing. Every
   decision: `jq 'select(.source=="learner")' runs/promotion_log.jsonl`.

After `soc.sh down`: `pgrep -af` on the patterns above prints nothing, and `models/` is hashed a final time.

### C8. Test plan (pytest, `tmp_path`, stubs only, never real training)

- `test_learner_triggers.py`: (b) fires on a new listed+verified file. It does not fire for an unlisted file, a
  sha mismatch, a file younger than the settle time, or an already-trained sha. (c) 49 → no, 50 → yes. Unsettled and
  empty verdicts are not counted. `trained_until` is respected. (a) 2 reports → no, 3 distinct → yes, the same report
  re-read 3× → no, 4th after firing → no, re-armed after a `false` report. `require_new_data` true/false. Priority
  b > c > a. Exit 4 → inputs not marked, cooldown set. Exit 1/10 → inputs marked. Corrupt JSON in the report or store
  → no crash, no trigger.
- Cooldown and action limit with `SOC_NOW`. Lock: a held `learner.lock` or `.promote.lock` → `skipped: locked`, the
  training stub is not called.
- Promotion: `auto_promote:false` → stub sees no `AUTO_PROMOTE`/`--auto-promote` even if `AUTO_PROMOTE=1` is in the
  parent env. `true` → passed. Exit 3 + busy → retries up to `max_attempts` then `ready_to_promote_manually`. The
  weekly limit is respected.
- Log: each decision is exactly one parseable JSON line with `source:"learner"`. Idle polls write nothing.
- Command allowlist: the learner never builds `train_models.sh`/`promote_model.sh` commands. A `models/` change during
  a stub run → `models_changed_unexpectedly`.
- `test_soc_supervisor.py` (a child `sleep`/Python script that spawns a grandchild): group stop leaves no grandchild.
  TERM-ignoring child → KILL after the timeout. Crash → restart with delays 2, 4, 8 (fake clock), reset after healthy.
  Health failures ≥ threshold → restart. One child crashing does not restart its sibling. Second instance → lock refused.
- `test_soc_cli.py` (bash via subprocess, `SOC_CONFIG` pointing at `tmp_path`, stub children): `up` twice → one
  supervisor per service. `status` contains the expected fields and exit codes 0/3. `down` → no matching processes. `logs`
  prints the files. `restart learner` keeps the detector PID.

---

## D. Risks and open questions (recommended answer in **bold**)

Map questions:
1. **Drift trigger (a)**: fires today on attack-only data. **Use N=3 distinct consecutive reports, edge-triggered, and
   `require_new_data: true`. In practice, drift then lowers the bar for reviewed data (≥ 1 capture or verdict instead
   of 50), but never retrains on identical files. The real fix is Task 6 (drift measured on normal-looking traffic).**
   *This is the one place where trigger (a) is narrowed. Please confirm.*
2. **What each trigger trains on**: **(b) `train_new_data.sh data/processed/week7`. (c) export + `run_candidate_seeds.sh`
   with the 3-line `FEEDBACK` pass-through (backup first). (a) whatever new data exists, otherwise defaults (only if
   require_new_data is false). One trigger per run, no combining.** Reason: `train_new_data.sh` trains seed 42 itself,
   so passing feedback to only some seeds would make the seeds differ.
3. **venv / systemd**: **default to `$VIRTUAL_ENV` or `~/Capstone/.venv/bin/python` (please confirm the path), and do
   not use systemd.** Run `cat /etc/wsl.conf; ps -p 1 -o comm=` to check.
4. **Promote refused (exit 3)**: **retry every 120 s, up to 15 tries (30 min, longer than the 20-min heartbeat
   staleness), only with auto-promote. After that, log "ready to promote" and leave it to you.**
5. **Tu2023 files only on the Kali VM → exit 4**: **acceptable: log `data_missing`, cooldown, inputs not marked as
   trained.** `status` should show this clearly. Also: should the first start seed the state so existing week7 files
   don't trigger? **Yes, for files already in `training_provenance.json`.**
6. **Training console vs learner**: **yes, they should not run together. Phase 3: the learner refuses to start if a
   `train_models.sh` it did not start is running. Blocking the console the other way would mean editing
   `dashboard/server.py`/training-gui, which is out of scope; record it as a known gap.**

New:
7. `part_b.py` exit 3 means both "busy/detection running" and "error". **Retry only when part_b's log line says
   busy or detection, otherwise treat it as an error.** Phase 3 must read part_b's exact `decision` strings.
8. Verdict labels and the test split: **confirm `train_models.sh --feedback` adds rows only to training, never to the
   fixed test rows the gate compares on.** Otherwise the gate would be judged on model-selected samples (feedback
   loop [21], snooping [24]). The uploaded snapshot of `train_models.sh`/`settings.yaml` in my workspace has no
   `--feedback` flag or `feedback:` section, so it predates Task 12. Verify on the branch.
9. `train_new_data.sh` step 5 uses `--new-split`. **Confirm that it extends the split and does not reshuffle old test
   rows.**
10. Run naming: **confirm `train_new_data.sh` honours `RUN_NAME`.** Otherwise the learner cannot link its run to the
    part_b log line, and would fall back to "newest part_b line after run start".
11. Probe-then-promote gap in `part_b.py` (detection could start between `pipeline_running()` and `promote_model.sh`).
    **Leave as is for now (do not change Part B scripts). Note it as a known risk. A later fix is for part_b to hold
    `flock -x runs/.pipeline.lock` during promote+smoke.**
12. `down` during a promote: `promote_model.sh` moves files and then copies them, so it is not atomic. **The learner's
    stop waits up to `promote_grace_s` while `.promote.lock` is held. If interrupted anyway, `rollback_model.sh` is the
    recovery.**
13. Criterion 1 threshold: **median latency during training ≤ 1.5× baseline**. Probes append marker lines to the real
    `data/raw/<date>.log` through the listener. **OK to add a few `soc-probe-*.invalid` lines, or run the live check on
    a copy of the repo?** (Hard rule: data/ must not be rewritten. Appending is how the listener always works, but it is
    still your data.)
14. After a detector crash, its heartbeat file in `runs/.pipeline.readers/` blocks promotion for up to 20 min.
    **Accept it (covered by the retry window). Do not delete files under runs/.**
15. Other readers of `runs/promotion_log.jsonl` (training console, docs scripts) may assume part_b's schema. **Phase 3
    greps for readers and makes them skip `source=="learner"` lines only if they break. Fallback: a separate
    `runs/soc/learner_log.jsonl`. That would deviate from criterion 4, so it needs your OK.**
16. WSL idle shutdown with no terminal open is not documented for background-only processes. **Test it in Phase 4. If
    the distro stops, set `instanceIdleTimeout=-1` in the Windows-side `.wslconfig` (no sudo) or keep one terminal
    open.**
17. `ionice` is probably ineffective on `/mnt/c`. **Keep it as best-effort and rely on `nice`.** Heavy sklearn `n_jobs=-1`
    can still compete for memory bandwidth. If criterion 1 fails, add `train.max_threads` (sets `OMP_NUM_THREADS`).

---

## E. Sources (opened 2026-11-20)

1. Google Cloud Architecture Center — *MLOps: Continuous delivery and automation pipelines in machine learning* —
   https://cloud.google.com/architecture/mlops-continuous-delivery-and-automation-pipelines-in-machine-learning
   (302 → https://docs.cloud.google.com/architecture/mlops-continuous-delivery-and-automation-pipelines-in-machine-learning) — last updated 2024-08-28.
2. freedesktop.org — *systemd.service(5)* — https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html — systemd 262 ("latest").
3. freedesktop.org — *systemd.kill(5)* — https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html — systemd 262.
4. freedesktop.org — *systemd.exec(5)* — https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html — systemd 262.
5. freedesktop.org — *systemd.unit(5)* — https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html — systemd 262.
6. freedesktop.org — *loginctl(1)* — https://www.freedesktop.org/software/systemd/man/latest/loginctl.html — systemd 262.
7. Supervisor — *Configuration File* — http://supervisord.org/configuration.html — Supervisor 4.3.0 docs.
8. Supervisor — *Subprocesses* — http://supervisord.org/subprocess.html — Supervisor 4.3.0 docs.
9. Supervisor — *Running Supervisor* — http://supervisord.org/running.html — Supervisor 4.3.0 docs.
10. Microsoft Learn — *Use systemd to manage Linux services with WSL* — https://learn.microsoft.com/en-us/windows/wsl/systemd — last updated 2025-03-17.
11. Microsoft Learn — *Advanced settings configuration in WSL* — https://learn.microsoft.com/en-us/windows/wsl/wsl-config — last updated 2026-10-16.
12. man7.org — *kill(2)* — https://man7.org/linux/man-pages/man2/kill.2.html — Linux man-pages 6.19, 2026-06-05.
13. man7.org — *setsid(1)* — https://man7.org/linux/man-pages/man1/setsid.1.html — util-linux, 2026-05-24.
14. man7.org — *nice(1)* — https://man7.org/linux/man-pages/man1/nice.1.html — GNU coreutils 9.11, April 2026.
15. man7.org — *ionice(1)* — https://man7.org/linux/man-pages/man1/ionice.1.html — util-linux, 2026-05-24.
16. man7.org — *flock(1)* — https://man7.org/linux/man-pages/man1/flock.1.html — util-linux, 2026-05-24.
17. man7.org — *logrotate(8)* — https://man7.org/linux/man-pages/man8/logrotate.8.html — page rendered 2026-09-09 (upstream version date not shown).
18. The Linux Kernel documentation — *Block io priorities* — https://docs.kernel.org/block/ioprio.html — document dated 2005-03-11 (site build 7.4.0-rc3).
19. Python documentation — *logging.handlers* — https://docs.python.org/3/library/logging.handlers.html — Python 3.15 docs.
20. Python documentation — *subprocess* — https://docs.python.org/3/library/subprocess.html — current 3.x docs (`process_group` added in 3.11).
21. D. Sculley et al. — *Hidden Technical Debt in Machine Learning Systems* — NeurIPS (NIPS) 28, 2015 — https://papers.nips.cc/paper/5656-hidden-technical-debt-in-machine-learning-systems
22. E. Breck, S. Cai, E. Nielsen, M. Salib, D. Sculley — *The ML Test Score: A Rubric for ML Production Readiness and Technical Debt Reduction* — IEEE Big Data 2017 — https://research.google/pubs/the-ml-test-score-a-rubric-for-ml-production-readiness-and-technical-debt-reduction/ (test list read from https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/46555.pdf).
23. M. Zinkevich — *Rules of Machine Learning: Best Practices for ML Engineering* — Google for Developers — https://developers.google.com/machine-learning/guides/rules-of-ml — last updated 2025-08-25.
24. D. Arp et al. — *Dos and Don'ts of Machine Learning in Computer Security* — USENIX Security 2022 (pp. 3971–3988) — https://www.usenix.org/conference/usenixsecurity22/presentation/arp ; PDF https://www.usenix.org/system/files/sec22-arp.pdf
25. S. Axelsson — *The Base-Rate Fallacy and the Difficulty of Intrusion Detection* — ACM TISSEC 3(3):186–205, 2000 — DOI https://doi.org/10.1145/357830.357849. *The ACM page returned an error to my fetcher. Text verified from the course copy https://www.profsandhu.com/cs6393_s20/p186-axelsson.pdf.*
26. R. Sommer, V. Paxson — *Outside the Closed World: On Using Machine Learning for Network Intrusion Detection* — IEEE S&P 2010, pp. 305–316, DOI 10.1109/SP.2010.25 — https://ieeexplore.ieee.org/document/5504793 (*the IEEE page did not render for my fetcher*). Text verified from https://www1.icsi.berkeley.edu/pubs/networking/outsidethe10.pdf. Venue and pages taken from https://researchr.org/publication/SommerP10/bibtex.

Not verified / not used: LSB init-script exit-code conventions (soc.sh's `status` exit 3 is our own choice); whether
WSL keeps a distro alive for background-only processes; whether BFQ/mq-deadline apply to WSL2's virtual disk.

---

## F. Review against the Phase 1 map and the hard rules (lead, 2026-11-20)

The research agent worked from a partial repo snapshot. I checked its "verify on the branch" items against the live repo:

| Item | Finding on the branch | Effect on the design |
|---|---|---|
| D-8 feedback rows and the test split | `src/dns_detect/ingest/feedback.py` drops verdict rows whose id is in the base manifest's `test` set (lines 163–165); `train_models.sh --feedback` and `settings.yaml feedback:` exist (Task 12, merged) | Trigger (c) is safe for the gate. No change. |
| D-9 `--new-split` in `train_new_data.sh` | It **is** a fresh time-ordered split, on purpose: the new captures are the newest rows and land in the test set; all 3 seeds then share that split | Expected. The gate compares candidate vs `models/` on that new split. Documented, no change. |
| D-10 `RUN_NAME` | `train_new_data.sh` and `run_candidate_seeds.sh` both honour `RUN_NAME` | The learner links runs to part_b log lines by name. |
| D-7 exit 3 meaning | Logged decision `"not promoted: run_pipeline.sh is running"` = detection busy; a held `.promote.lock` prints "another Part B run is promoting" and logs nothing; `"promote failed, models/ unchanged"` = error | Retry only on the first two; everything else is an error + cooldown. |
| D-15 readers of `promotion_log.jsonl` | Only `scripts/part_b.py` (writer) and `tests/test_part_b_automation.py` (reads its own tmp log) | Learner lines with `"source":"learner"` in the same file are safe. Criterion 4 met without a second log. |
| D-11 probe-then-promote gap | Real: `part_b.py` probes the detection lock, then promotes. Criterion 4 says "never while a detection run holds the lock" | **Recommend fixing in Phase 3** (needs your OK, see question 3): part_b takes `flock -x` on `runs/.pipeline.lock` (non-blocking) and holds it through promote + smoke test. On POSIX the dashboard's `LOCK_SH` then waits until the swap is done, which closes the gap. About 10 lines, backup first. |
| Hard rule "don't rewrite data/" | The learner itself writes nothing in `data/`. The existing scripts still write `data/processed/*` and `data/feedback/*` as today | Covered by map assumption 4. |
| Hard rule "reuse Part B scripts" | Learner calls only `train_new_data.sh`, `run_candidate_seeds.sh`, `export_feedback_labels.py` and `part_b.py` (promote retry) | OK. Edits proposed only as pass-throughs: `run_candidate_seeds.sh` FEEDBACK, and optionally `part_b.py` (D-11). |
| D-13 latency probes in `data/raw` | Appending `soc-probe-*.invalid` lines is what the listener always does, but it is your data | Asked as question 4 below. Alternative: run the live check on a scratch copy of the repo under WSL `~/`. |
