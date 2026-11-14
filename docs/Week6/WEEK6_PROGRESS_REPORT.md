# Week 6 Progress Report: Week 5 Evaluated, Path B Replaced

**DNS Traffic Anomaly Detection · session summary · 2026-11-12 to 2026-11-14**

This report covers the work after the Week 6 dashboard was built: auditing what Week 5 left unfinished, running the missing v3 evaluations, and replacing Path B's autoencoder with an Isolation Forest that trains in about a minute.

Detailed documents:

- [V3_EVALUATION_RESULTS.md](V3_EVALUATION_RESULTS.md): every evaluation number, with how it was produced.
- [PATH_B_ISOLATION_FOREST.md](PATH_B_ISOLATION_FOREST.md): the Path B change, the algorithm, the code and the results.
- [next task.md](next%20task.md): the open tasks with their commands and checklist.

---

## Contents

1. [Summary](#1-summary)
2. [Where the session started](#2-where-the-session-started)
3. [What was done](#3-what-was-done)
4. [Results](#4-results)
5. [Code and tooling changes](#5-code-and-tooling-changes)
6. [Problems hit and lessons](#6-problems-hit-and-lessons)
7. [Status at the end of the session](#7-status-at-the-end-of-the-session)
8. [Next steps](#8-next-steps)

---

## 1. Summary

- **Week 5 was not complete.** An audit found that v3 was trained but never evaluated beyond the frozen test set. Tasks 0–3 of the Week 5 plan have now been run.
- **v3 does not raise false alarms on unseen benign traffic:** 1 of 25,222 queries in CIC capture 3 (0.004%), the same as the baseline.
- **Every tunnel tool is caught when it is left out of training:** recall 1.0 on all 8 tools in the leave-one-tool-out test. False alarms in that test are 0.35–0.59%, above the 0.1% budget.
- **Path B now uses an Isolation Forest.** The autoencoder had recall 0.0 on v3 and took about 6 h 37 min to train. The Isolation Forest scores recall 1.0 on the same data and trains in about a minute.
- **Multi-seed check:** over 5 seeds, v3's Path A false alarms stay at 8–9 while the baseline's range from 9 to 25. No difference between runs is proven by the non-overlap rule (v3 vs baseline is borderline), but v3 is far more stable.
- **The full system is as good as before and 11 times faster to train:** `runs/v3_iforest` has fusion recall 1.0 and 7 false alarms on the frozen test set, the same as v3, and trained in 39 min 5 s instead of 7 h 17 min.

---

## 2. Where the session started

| Item | State |
|---|---|
| `runs/v3` (8 tools, 100,000 attack / 118,334 benign) | trained (7 h 17 min); only frozen-test results recorded |
| v3 on unseen benign traffic (CIC capture 3) | not run |
| Leave-one-tool-out | not run |
| Multi-seed check | not run |
| Path B (Transformer autoencoder) | recall 0.0 on v3; about 6 h 37 min of the 7 h 17 min training |
| Week 6 dashboard | built, not tested end to end |

---

## 3. What was done

| Date | Work |
|---|---|
| 2026-11-12 | Audit of the repository against the Week 5 documents. Result: Week 5 incomplete; 7 checklist items open. Created [next task.md](next%20task.md) with every open task, its command and expected output. |
| 2026-11-12 | Analysed why Path B is slow (batch size 32, about 99,000 overlapping training windows, early stopping without a minimum gain, CPU only in the VM) and what fits the machine. Chose to replace the autoencoder with the Isolation Forest already trained as Path B's baseline. |
| 2026-11-12 to 14 | Implemented the Isolation Forest as a selectable Path B model (`--path-b-model iforest`). Pushed to `main` (commit `9598ca4`). |
| 2026-11-14 | On Kali: Path B-only test on v3's exact data. 65.8 s, numbers identical to the v3 baseline line. |
| 2026-11-14 | Wrote `scripts/week5_eval.sh` (Week 5 Tasks 0–3 in one command) and ran it: files checked, comparison confirmed, CIC capture 3 and leave-one-tool-out recorded. |
| 2026-11-14 | Fixed `run_cv.py`: leave-one-tool-out was also "leaving out" benign sources. |
| 2026-11-14 | Full training run with the Isolation Forest Path B: `runs/v3_iforest`, 39 min 5 s. |

---

## 4. Results

All numbers below were produced on the Kali VM and are recorded with their commands in [V3_EVALUATION_RESULTS.md](V3_EVALUATION_RESULTS.md).

### 4.1 Frozen test set (2,568 rows, 1,168 benign, all attacks dnsexfiltrator)

| Run | Fusion recall | Fusion false alarms | Path A false alarms | OR rule false alarms |
|---|---|---|---|---|
| baseline | 1.0 | 23 | 23 | 116 |
| v_dnsshell | 1.0 | 7 | 7 | 113 |
| v_det | 1.0 | 38 | 36 | 119 |
| v3 | 1.0 | 7 | 8 | 87 |
| **v3_iforest** | **1.0** | **7** | 8 | 110 |

### 4.2 Unseen benign traffic (CIC capture 3, 25,222 queries, budget 25)

| Run | False alarms | Rate |
|---|---|---|
| baseline | 1 | 0.004% |
| v_dnsshell | 0 | 0.000% |
| v_det | 1 | 0.004% |
| **v3** | **1** | **0.004%** |
| **v3_iforest** | **1** | **0.004%** |

### 4.3 Leave-one-tool-out (v3's training data)

Recall **1.0 for all 8 tools** (cobaltstrike, det, dns2tcp, dns_shell, dnscat2, dnsexfiltrator, iodine, ozymandns). False alarms 0.35–0.59%, mean 0.427%, against a threshold set for 0.1%.

### 4.4 Multi-seed check (Path A false alarms, seeds 42–46)

| Run | Mean | SD | Min–max |
|---|---|---|---|
| baseline | 18.2 | 7.56 | 9–25 |
| v_dnsshell | 8.2 | 1.79 | 7–11 |
| v_det | 22.0 | 9.14 | 13–36 |
| **v3** | **8.6** | **0.55** | **8–9** |

No difference is proven by the non-overlap rule: dns_shell's help and det's harm are within training randomness, and v3 vs baseline is borderline (ranges touch at 9). v3 is far more stable.

### 4.5 Path B: autoencoder vs Isolation Forest (same data, split and seed)

| | Autoencoder | Isolation Forest |
|---|---|---|
| Recall / FPR (test windows) | 0.000 / 6.227% | **1.000 / 9.341%** |
| PR-AUC | 0.787 | **1.0** |
| Attack median score ÷ benign 99th-percentile score | 0.573 | **1.35** |
| Path B training time | about 6 h 37 min | **65.8 s** |
| Full training run | 7 h 17 min | **39 min 5 s** |

---

## 5. Code and tooling changes

| File | Change |
|---|---|
| `src/dns_detect/models/path_b_predict.py` | `fit_iforest()`; the loader picks the model from `"model_type"` in the threshold file; scoring supports the Isolation Forest; TensorFlow no longer required for an Isolation Forest model |
| `src/dns_detect/models/path_b_train.py` | `--model {trafficformer,iforest}`; saves `<name>_iforest.pkl` |
| `scripts/train_models.sh` | `--path-b-model` option, file checks, `path_b_model_type` in the run metadata |
| `scripts/run_pipeline.sh`, `dashboard/server.py` | accept the `.pkl` Path B model |
| `scripts/run_multiseed.py` | `--path-b-model` pass-through |
| `scripts/week5_eval.sh` (new) | Week 5 Tasks 0–3 in one command, one log, one summary block |
| `scripts/run_cv.py` | leave-one-tool-out now holds out attack families only |
| `tests/test_path_b_iforest.py` (new) | 5 unit tests for the Isolation Forest path; with the existing Path B and bridge tests, 47 passed on Kali (2026-11-14) |

The autoencoder remains the default, so earlier runs and saved models are unchanged. Details: [PATH_B_ISOLATION_FOREST.md](PATH_B_ISOLATION_FOREST.md).

---

## 6. Problems hit and lessons

| Problem | Cause | Fix / lesson |
|---|---|---|
| First Path B test "finished" in 0.05 s with no output | `PYTHONPATH` was unset and Kali still had the old code; `2>/dev/null` hid the error | `export PYTHONPATH=src` in every terminal; use `2>&1` so errors stay visible |
| A push created an empty branch | Bash line continuation (`\`) used in PowerShell, so `git add` failed | In PowerShell use one command per line, or a backtick for continuation |
| `git pull` refused to run on Kali | Every training run rewrites four tracked files in `data/processed/` | `git stash` or `git checkout data/processed/` after copying the run's labeled file into its run folder |
| Leave-one-tool-out reported recall 0.0 for two "tools" and a headline of 0.8 | `run_cv.py` treated the benign sources `benign_cic` and `benign_tu2023` as tools | Fixed: only attack families are held out. The real headline over 8 tools is 1.0 |
| No progress visible while a script ran | Python buffers output written into a pipe | `week5_eval.sh` now sets `PYTHONUNBUFFERED=1` |
| Step 10 of training prints nothing for roughly 20–25 minutes | Path A's comparison Transformer trains with `verbose=0` | Expected. It is not used in any decision; a `--no-transformer` option for `train_models.sh` would remove most of that time |
| `wait` seemed to hang | It only waits for jobs started in the same terminal, and holds the terminal until they end | Use `while pgrep -f train_models.sh ...; do sleep 60; done` in any terminal |

**Machine constraints** (Kali VM on an i9-13900H laptop): about 4 virtual CPUs, 7.7 GiB RAM, no GPU (the laptop's RTX 4060 is not visible to the VM). Neural-network training runs on the CPU, which is why the autoencoder took hours and why the Isolation Forest fits the machine.

---

## 7. Status at the end of the session

| Item | Status |
|---|---|
| Week 5 Tasks 0–3 (files, comparison, CIC capture 3, leave-one-tool-out) | ✅ |
| Path B Isolation Forest implemented and pushed | ✅ |
| Path B-only test on v3 data | ✅ 65.8 s, identical numbers |
| Full run `runs/v3_iforest` | ✅ fusion 1.0 / 7 false alarms, 39 min 5 s |
| v3_iforest on CIC capture 3; Path B metrics confirmed from the saved file | ✅ 1 / 25,222; Path B recall 1.0, fusion 7 false alarms |
| Unit tests (`test_path_b_iforest.py`, `test_path_b_load.py`, `test_bridge.py`) | ✅ 47 passed |
| Pipeline run with `runs/v3_iforest` | ❌ |
| Multi-seed check (Week 5 Tasks 4–5) | ✅ baseline 9–25, v_dnsshell 7–11, v_det 13–36, v3 8–9 (Path A false alarms, 5 seeds) |
| Conclusion and the replace-`models/` decision (Task 6) | ✅ candidate `runs/v3_iforest`; `models/` kept until mentor approval |
| Mentor agreement on a non-deep-learning Path B | ❌ |
| Week 6 dashboard end-to-end test (Task 8) | ❌ |

---

## 8. Next steps

In order (commands in [next task.md](next%20task.md)):

1. ~~`bash scripts/week5_eval.sh --skip-lofo`~~ done: v3_iforest confirmed (Path B recall 1.0, fusion 7 false alarms, CIC capture 3 1 / 25,222).
2. ~~Unit tests (Task 10.1)~~ done: 47 passed. Still to do: the pipeline with `runs/v3_iforest` (Task 10.5).
3. ~~Multi-seed check (Tasks 4–5)~~ done: v3 8–9 vs baseline 9–25 false alarms; no difference proven by the non-overlap rule, v3 far more stable. Optional: the full check including Path B and the fusion, now practical with the Isolation Forest.
4. ~~Conclusion and decision (Task 6)~~ done: candidate `runs/v3_iforest` (same final results as v3, a Path B that works); `models/` stays unchanged until the mentor approves the Isolation Forest Path B.
5. Save the result files in git (Task 7), test the dashboard (Task 8), fix stale documentation (Task 9).
6. Ask the mentor to agree that Path B may be a classical machine-learning model.
