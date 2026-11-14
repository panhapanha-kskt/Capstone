# Path B: Replacing the Autoencoder with an Isolation Forest

**DNS Traffic Anomaly Detection · design, implementation and results · 2026-11-14**

Path B is the unsupervised half of the detector: it learns from benign traffic only and flags windows of queries that look unusual. Until now it was a Transformer autoencoder (`dns_trafficformer`). This document explains why it was replaced by an Isolation Forest, how the Isolation Forest works, what changed in the code, and what the results are.

Progress context: [WEEK6_PROGRESS_REPORT.md](WEEK6_PROGRESS_REPORT.md). All numbers: [V3_EVALUATION_RESULTS.md](V3_EVALUATION_RESULTS.md).

---

## Contents

1. [Why the autoencoder was replaced](#1-why-the-autoencoder-was-replaced)
2. [Why the Isolation Forest](#2-why-the-isolation-forest)
3. [How the Isolation Forest works](#3-how-the-isolation-forest-works)
4. [What stays the same](#4-what-stays-the-same)
5. [Implementation](#5-implementation)
6. [How to use it](#6-how-to-use-it)
7. [Results](#7-results)
8. [Limitations](#8-limitations)
9. [References](#9-references)

---

## 1. Why the autoencoder was replaced

Two problems appeared when v3 was trained on 218,334 rows (100,000 attack, 118,334 benign):

| Problem | Evidence |
|---|---|
| **It stopped detecting attacks** | Recall 0.000 on the frozen test windows. The typical attack window had a reconstruction error only 0.573 times the alarm threshold: the model reconstructed tunnel traffic better than unusual benign traffic. |
| **Training took too long** | About 6 h 37 min of the 7 h 17 min run (65 epochs, up to about 290 s each, CPU only). A 1-million-row run was estimated at 1–2.5 days. |

The likely reason for the first problem, not verified: tunnel queries are extremely repetitive and easy to reconstruct, while 118,000 varied benign rows widened what the model treats as normal.

The slow training comes from the settings and the machine, not the model's size: batch size 32 (3,107 steps per epoch), about 99,000 heavily overlapping training windows, early stopping without a minimum improvement, and no GPU in the Kali VM.

---

## 2. Why the Isolation Forest

| Reason | Detail |
|---|---|
| **It already worked on this data** | `path_b_train.py` trained an Isolation Forest as Path B's baseline in every run. On v3 it scored recall 1.000, FPR 9.341%, PR-AUC 1.0, against the autoencoder's 0.000 / 6.227% / 0.787. |
| **Training time barely grows with the data** | Each tree is built from a random sample of 256 windows, so training takes seconds whether there are 100,000 or 1,000,000 windows. Only scoring grows, in one pass. |
| **It fits the machine** | CPU only, low memory, no new environment. The VM has about 4 virtual CPUs, 7.7 GiB RAM and no GPU. |
| **It keeps Path B's role** | Still unsupervised, still trained on benign windows only, still a different view from Path A's supervised Random Forest. |
| **It follows evaluation best practice** | Arp et al. (2022) recommend keeping a complex model only if it beats a simple baseline. The autoencoder did not. |

**Not chosen: a smaller, faster neural network.** It would train faster than the Transformer, but it would still detect by reconstruction error, the idea that gave recall 0.0 on v3.

---

## 3. How the Isolation Forest works

Isolation Forest (Liu, Ting & Zhou, 2008), implemented with scikit-learn's `IsolationForest`.

**Idea:** anomalies are few and different, so random cuts separate them from the rest quickly. The model does not learn what normal traffic looks like; it measures how easy a sample is to isolate.

**Input (unchanged from Path B):** one sample is a window of 20 consecutive queries from one client. Each query has the Path B features (11 in the saved models: length, entropy, subdomain count, digit ratio, longest label, plus 5-minute behaviour features), scaled with the training minimum and range. The window is flattened into one row of 20 × 11 = 220 numbers. Only benign windows are used for training.

**Training:**

1. Build 200 trees.
2. Each tree uses a random sample of 256 benign windows.
3. At each node, pick a random feature and a random cut between that feature's minimum and maximum in the node.
4. Split until each window is alone or the tree reaches depth 8 (log₂ 256).

No epochs, no loss function, no gradients.

**Scoring:** a window's path length h(x) is the number of splits needed to isolate it, averaged over the 200 trees. The anomaly score is

s(x) = 2^(−E[h(x)] / c(n))

where c(n) is the average path length of a random tree built on n = 256 samples. A score near 1 means the window was isolated quickly (anomalous); around 0.5 or below means normal. scikit-learn returns the negative of this score, so the code uses `-score_samples()`: higher means more anomalous.

**Threshold:** the 99th percentile of the scores on benign validation windows, the same rule the autoencoder used. About 1% of benign validation windows are flagged by design.

**Why it isolates tunnels:** tunnel windows have extreme values (long, high-entropy, many unique subdomains, 20 times in a row), so a few random cuts separate them. Benign windows sit among many similar ones.

---

## 4. What stays the same

Only Path B's algorithm changes.

| Unchanged | Detail |
|---|---|
| Path A | Random Forest, its features, threshold and results |
| Data and split | Same dataset, same train/validation/test split, same frozen test set |
| Path B inputs | Same features, same 20-query per-client windows, benign-only training |
| Path B threshold rule and metrics | 99th percentile of benign validation scores; precision, recall, F1, FPR, PR-AUC, ROC-AUC, recall per tool |
| Score sent to the fusion | `ml_score_B` = sigmoid of the score's z-score, 0 to 1 |
| Fusion, bridge, detection engine | Code not edited. The fusion is retrained on the new scores as step 12 of every training run |
| Default | `trafficformer` (the autoencoder). Nothing changes unless `iforest` is requested |

---

## 5. Implementation

Pushed to `main` in commit `9598ca4`.

**One switch point.** Every part of the system gets Path B's score through `score_records()` in `path_b_predict.py`: the detection pipeline (`fusion/bridge.py`), fusion training (`scripts/train_fusion.py`), `scripts/verify_models.py` and `scripts/make_evasion_set.py`. The model is swapped behind that function, so none of these callers changed.

**How a run records its model.** `<name>_threshold.json` gets a `"model_type"` field. The loader reads it first: `"iforest"` loads `<name>_iforest.pkl`; anything else, or no field (older runs), loads the Keras autoencoder as before. A leftover `.keras` file in a folder with `"model_type": "iforest"` is ignored.

| File | Change |
|---|---|
| `src/dns_detect/models/path_b_predict.py` | `fit_iforest()`, `flatten_windows()`, `iforest_model_path()`; `load_model_artifacts()` dispatches on `"model_type"`; `compute_reconstruction_errors()` returns `-score_samples()` for an Isolation Forest; TensorFlow imported only if available |
| `src/dns_detect/models/path_b_train.py` | `--model {trafficformer,iforest}`; the Isolation Forest branch skips the autoencoder and saves `<name>_iforest.pkl`; `model_type` and `n_estimators` written to the threshold file and the metrics |
| `scripts/train_models.sh` | `--path-b-model trafficformer\|iforest`; expected model file per type; `path_b_model_type` in `training_metadata.json`; step 11 prints `(iforest, ...)` |
| `scripts/run_pipeline.sh` | reads `"model_type"` from the threshold file to find the model file |
| `dashboard/server.py` | accepts `<name>_iforest.pkl` as a trained Path B model |
| `scripts/run_multiseed.py` | `--path-b-model` pass-through |
| `tests/test_path_b_iforest.py` | 5 tests: abnormal windows score above the threshold, one score per window, same seed gives same scores, the loader reads the `.pkl` from the threshold file, a missing `.pkl` is an error |

When the autoencoder is used, the Isolation Forest baseline is computed exactly as before (same 200 trees, same seed, same threshold rule), so baseline numbers in older logs stay comparable.

---

## 6. How to use it

Training (on Kali, `PYTHONPATH=src`):

```bash
# whole pipeline: Path A + Isolation Forest Path B + fusion
DNS_DETECT_MODELS_DIR=runs/<name> ./scripts/train_models.sh --force-retrain --path-b-model iforest --files ...

# Path B only
python3 -m dns_detect.models.path_b_train --filename <labeled>.json --data_dir <dir> --n_days 20 \
    --save_name dns_trafficformer --split-manifest <manifest> --seed 42 --model iforest

# multi-seed with Path B and fusion
python3 scripts/run_multiseed.py --data <labeled> --manifest <manifest> --path-b-model iforest
```

Files a run writes for Path B:

- `dns_trafficformer_iforest.pkl`: the model;
- `dns_trafficformer_threshold.json`: contains `"model_type": "iforest"`;
- `dns_trafficformer_norm.json`: unchanged format.

Nothing else is needed at prediction time: the pipeline and the fusion read the model type from the threshold file.

---

## 7. Results

All runs on the Kali VM, same data (218,334 rows), split and seed (42) as v3.

### 7.1 Path B alone (2026-11-14)

```
[*] Benign-only training windows: 99408 (dropped 83510 attack windows)
[*] Path B model: Isolation Forest (200 trees) on 99408 benign windows
Isolation Forest: recall=1.000  FPR=9.341%  PR-AUC=1.0  | attack median score / benign p99 score = 1.35
   dnsexfiltrator   isolation forest recall=1.000
real    65.81s
```

| | Autoencoder | Isolation Forest |
|---|---|---|
| Recall | 0.000 | **1.000** (1,381 of 1,381 attack windows) |
| FPR | 6.227% | 9.341% (about 102 of 1,092 benign windows) |
| PR-AUC | 0.787 | **1.0** |
| Attack median ÷ benign 99th percentile | 0.573 | **1.35** |
| Time | about 6 h 37 min | **65.8 s** |

The numbers are identical to the Isolation Forest baseline line in the v3 training log, as expected with the same data, split and seed.

### 7.2 Full system, `runs/v3_iforest` (2026-11-14)

```
[10/12] Path A trained (F1 0.9972, PR-AUC 1)
[11/12] Path B trained (iforest, window 20, anomaly threshold 0.4907)
[12/12] Fusion trained (test: recall 1, false alarms 7 vs OR rule 110)
✓ Training complete in 39m 5s
```

| | `runs/v3` | `runs/v3_iforest` |
|---|---|---|
| Path A | F1 0.9972, PR-AUC 1, 8 false alarms | identical |
| Path B recall / FPR (test windows) | 0.0 / 6.23% | **1.0** / 9.34% |
| Fusion recall / false alarms (frozen test) | 1.0 / 7 | **1.0 / 7** |
| OR rule false alarms | 87 | 110 |
| CIC capture 3 (unseen benign, Path A) | 1 / 25,222 | 1 / 25,222 |
| Training time | 7 h 17 min | **39 min 5 s** |

Read from each run's saved `evaluation_metrics.json` with `scripts/week5_eval.sh` (2026-11-14).

- The final decision is unchanged: the fusion catches every attack with 7 false alarms.
- The OR rule rose because the Isolation Forest flags more benign windows by itself; the system decides with the fusion, not the OR rule.
- Roughly 20–25 of the 39 minutes are step 10's comparison Transformer (Path A, not used in any decision), estimated from progress checks during the run. Path B took about a minute.

**Not yet measured:** the fusion weights of v3_iforest, and the multi-seed spread.

---

## 8. Limitations

- **More false alarms from Path B alone:** 9.34% of benign test windows against the autoencoder's 6.23%. The threshold was set for 1% on validation windows; later benign traffic scores higher. PR-AUC 1.0 shows the ranking is perfect, so the issue is where the cut sits, not the model.
- **Chosen after seeing test results.** The Isolation Forest was selected partly on its frozen-test numbers, a mild form of data snooping. It is backed by checks not used for the choice (CIC capture 3, leave-one-tool-out, multi-seed), some still pending.
- **The frozen test set contains only dnsexfiltrator attacks,** so Path B's recall 1.0 there is for one tool.
- **Not a deep-learning model.** If the project requires Path B to be deep learning, this needs the mentor's agreement; the autoencoder remains available with the default setting.
- **Order inside a window is ignored.** The 20 queries are flattened into one row, so the sequence is not modelled the way a Transformer models it.
- **Memory at 1 million rows** is still a problem: loading the merged JSON and building windows would likely exceed the VM's 7.7 GiB. This change removes the time problem, not the memory one.

---

## 9. References

1. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation Forest. *IEEE International Conference on Data Mining (ICDM)*, 413–422.
2. Arp, D., et al. (2022). Dos and Don'ts of Machine Learning in Computer Security. *USENIX Security Symposium*. https://arxiv.org/abs/2010.09470
3. scikit-learn. `IsolationForest`. https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
4. [WEEK5_PROGRESS_REPORT.md](../Week5/WEEK5_PROGRESS_REPORT.md), section 3.7: the autoencoder's recall 0.0 on v3 (Finding 1).
