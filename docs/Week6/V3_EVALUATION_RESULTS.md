# v3 Evaluation Results (Week 5 Tasks 0–3 and Task 10)

**DNS Traffic Anomaly Detection · results recorded 2026-11-14 on the Kali VM**

Week 5 trained the combined model `runs/v3` (8 tunnel tools, 100,000 attack / 118,334 benign rows) but recorded only its frozen-test results. This document records the evaluations run afterwards, how each was produced, and what each result means.

Reproduce Tasks 0–3 with one command: `bash scripts/week5_eval.sh` (`--skip-lofo` stops after Task 2). The plan and the remaining tasks are in [next task.md](next%20task.md); the tables also live in [V3_BALANCED_TRAINING.md](../Week5/V3_BALANCED_TRAINING.md), section 6.

---

## Contents

1. [Task 0: the Week 5 files exist](#1-task-0-the-week-5-files-exist)
2. [Task 1: frozen test set, every run](#2-task-1-frozen-test-set-every-run)
3. [Task 2: unseen benign traffic](#3-task-2-unseen-benign-traffic)
4. [Task 3: leave-one-tool-out](#4-task-3-leave-one-tool-out)
5. [Task 10: v3 with the Isolation Forest Path B](#5-task-10-v3-with-the-isolation-forest-path-b)
6. [What the results show](#6-what-the-results-show)
7. [Still to measure](#7-still-to-measure)

---

## 1. Task 0: the Week 5 files exist

All Week 5 outputs live only on the Kali VM (`runs/` and `logs/` are not in git), so they were checked first.

| Item | Result |
|---|---|
| `runs/baseline`, `runs/v_dnsshell`, `runs/v_det`, `runs/v3` | present |
| `runs/v3/evaluation_metrics.json`, `split_manifest.json`, `merged_labeled.json` | present |
| `runs/v3/merged_labeled.json` rows | **218,334** (expected 218,334) |
| v3 training log `logs/training_20261107_220017.log` | present; its lines match the Week 5 report |
| Tu et al. converted files (`data/external/tu2023/*.json`) | 9 |
| CIC capture 3 (`data/external/cic/cic_benign_test.json`) | present |

---

## 2. Task 1: frozen test set, every run

Read from each run's saved `evaluation_metrics.json`. The frozen test set has 2,568 rows (1,168 benign, 1,400 attack); every run is scored on the same rows. All its attacks are dnsexfiltrator.

| Run | Path A recall | Path A false alarms | Path A PR-AUC | Path B recall | Path B FPR (windows) | OR rule false alarms | Fusion recall | **Fusion false alarms** |
|---|---|---|---|---|---|---|---|---|
| baseline | 1.0 | 23 | 0.9957 | 1.0 | 8.79% | 116 | 1.0 | **23** |
| v_dnsshell | 1.0 | 7 | 1.0 | 1.0 | 8.88% | 113 | 1.0 | **7** |
| v_det | 1.0 | 36 | 1.0 | 1.0 | 8.24% | 119 | 1.0 | **38** |
| v3 | 1.0 | 8 | 1.0 | **0.0** | 6.23% | 87 | 1.0 | **7** |

- **The Week 5 table (V3_BALANCED_TRAINING.md 6.2) is confirmed** from the saved metrics, number for number.
- **Two Path B calculations exist.** The "Path B FPR (windows)" column is Path B's own rate per 20-query window (its `path_b` metrics block). The Week 5 table lists Path B false alarms per row inside the fusion step (baseline 112 of 1,168). Both are correct; they are not the same measurement.

---

## 3. Task 2: unseen benign traffic

CIC-Bell-DNS-EXF-2021 capture 3: 25,222 benign queries from another network, never used in training. Every query flagged is a false alarm. Scored with Path A (`path_a --infer`). The project's budget is 0.1%, about 25 queries.

| Run | False alarms | Rate | Within 0.1%? |
|---|---|---|---|
| baseline | 1 | 0.004% | ✅ |
| v_dnsshell | 0 | 0.000% | ✅ |
| v_det | 1 | 0.004% | ✅ |
| **v3** | **1** | **0.004%** | ✅ |

v3's 12-times-larger training set did not raise false alarms on unseen benign traffic. The per-query scores are saved in `runs/v3/cic_test_results.csv`.

---

## 4. Task 3: leave-one-tool-out

**Why it matters:** the frozen test set contains only dnsexfiltrator, so "recall 1.0" there says nothing about the other seven tools. This test measures each tool as an unseen tool.

**How it works** (`scripts/run_cv.py --strategies lofo --lofo-feature-sets step3` on `runs/v3/merged_labeled.json`): for each tool, a new Random Forest is trained on benign data plus the other seven tools. The alarm threshold is set at a 0.1% false-alarm rate on validation benign rows. The model is scored on the left-out tool and on the latest 20% of benign rows. It tests v3's training data with Path A's feature set, not the saved v3 model.

| Tool left out | Recall | False-alarm rate |
|---|---|---|
| cobaltstrike | 1.0000 | 0.444% |
| det | 1.0000 | 0.401% |
| dns2tcp | 1.0000 | 0.587% |
| dns_shell | 1.0000 | 0.368% |
| dnscat2 | 1.0000 | 0.414% |
| dnsexfiltrator | 1.0000 | 0.410% |
| iodine | 1.0000 | 0.351% |
| ozymandns | 1.0000 | 0.439% |
| **8 tools** | **mean 1.0, min 1.0** | **mean 0.427%** |

- **Recall:** every tool is caught without being in the training data, including iodine, the only tool with misses when the Week 4 baseline saw it unseen (4,996 of 5,000).
- **False alarms:** 0.35–0.59%, about four times the 0.1% the threshold was set for. The threshold does not hold on later benign traffic: the same validation-to-test drift as on the frozen test set.
- **Correction to the raw output.** The run also listed `benign_cic` and `benign_tu2023` with recall 0.0, and a headline of mean 0.8 / min 0.0. These are benign data sources, not tools: `run_cv.py` only excluded a family named exactly `benign`. They have no attacks to recall, so they are excluded above. `run_cv.py` has been fixed to hold out attack families only.

Output file: `runs/v3/cv_lofo.json`.

---

## 5. Task 10: v3 with the Isolation Forest Path B

`runs/v3_iforest` is trained on exactly v3's data and split, with Path B replaced by an Isolation Forest ([PATH_B_ISOLATION_FOREST.md](PATH_B_ISOLATION_FOREST.md)).

| | `runs/v3` | `runs/v3_iforest` |
|---|---|---|
| `[8/12]` data | 100,000 attack / 118,334 benign, 8 tools | identical |
| `[9/12]` split | train 183,203 / val 32,563 / test 2,568 | identical |
| `[10/12]` Path A | F1 0.9972, PR-AUC 1 | identical |
| `[11/12]` Path B | autoencoder, threshold 0.01741, recall 0.0 | **Isolation Forest**, threshold 0.4907, recall 1.000 in the Path B-only test |
| **`[12/12]` Fusion recall / false alarms** | 1.0 / 7 | **1.0 / 7** |
| OR rule false alarms | 87 | 110 |
| Training time | 7 h 17 min | **39 min 5 s** |

The Path B recall of 1.000 (FPR 9.341%, PR-AUC 1.0) comes from the Path B-only run on the same data, split and seed (65.8 s). The full run's saved metrics are still to be read back (section 7).

---

## 6. What the results show

1. **v3 is at least as good as every earlier run on false alarms:** 7 on the frozen test set (baseline 23) and 1 of 25,222 on unseen benign traffic.
2. **Recall generalises across tools:** 1.0 on every tool when left out of training, so the frozen test set's dnsexfiltrator-only attacks are not hiding a weak tool.
3. **The false-alarm threshold drifts:** set for 0.1% on validation rows, it gives 0.35–0.59% on later benign rows in leave-one-tool-out, and 0.6% (7 of 1,168) on the frozen test set. On benign traffic from another network (CIC capture 3) it stays at 0.004%.
4. **The Isolation Forest fixes Path B without changing the final result:** the fusion stays at recall 1.0 and 7 false alarms, and training drops from 7 h 17 min to 39 min.
5. **Single seed.** Every number above comes from one training run (seed 42). Whether 23 → 7 is larger than training randomness is answered by the multi-seed check.

---

## 7. Still to measure

| Measurement | How | Where it goes |
|---|---|---|
| v3_iforest on CIC capture 3, and its Path B metrics from the saved file | `bash scripts/week5_eval.sh --skip-lofo` | sections 2, 3 and 5 here; next task.md 13.4 |
| Multi-seed check (5 seeds) for baseline, v_dnsshell, v_det, v3 (and v3_iforest) | next task.md Tasks 4–5 | V3_BALANCED_TRAINING.md table 6.6 |
| Pipeline run with `runs/v3_iforest` | next task.md 13.5 | next task.md checklist |
| Conclusion and the replace-`models/` decision | next task.md Task 6 | V3_BALANCED_TRAINING.md section 6.5 |
