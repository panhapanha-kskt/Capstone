# Week 4 Changes: Fusion V2 and Bridge V2

**DNS Traffic Anomaly Detection · learned-fusion rework (`fusion/stacker.py`) and ML-bridge rework (`fusion/bridge.py`) · 2026-11-04**

Branch `feat/fusion-v2`, commits `94dc939` (Fusion V2) and `602e3d9` (Bridge V2), based on `main` at `cb0c671`.
The branch is not merged.

## Summary

This week rebuilt the two layers between the base models and the Week-4 detection engine:

- **Fusion V2** (`src/dns_detect/fusion/stacker.py`) is a new version of the logistic-regression fusion of Path A, Path B and the rules. It handles a missing Path B score correctly, treats rules R3 and R4 separately, transforms both scores onto a proper scale, freezes its configuration inside the model file, and sets its alarm threshold on rows the model never saw. A Neyman-Pearson threshold (a false-alarm limit with a statistical guarantee) is implemented and used whenever the data allows it.
- **Bridge V2** (`src/dns_detect/fusion/bridge.py`) is a rework of the ML bridge that feeds Week 4. It now:
  - stops with an error instead of quietly treating a missing model as "benign";
  - keeps Path B's "no score yet" as empty instead of 0;
  - joins scores to records by an explicit `row_id`;
  - makes one decision through the learned fusion;
  - derives confidence tiers from measured benign alarm volume;
  - sends Week 4 a single threat score;
  - refuses heuristic training labels unless asked.

**Outcome:**

- **Path A and Path B were not retrained or changed.** Their model files and source code have identical SHA-256 hashes before and after (`docs/research/fusion_v2_integrity.json`).
- **Fusion V2 is not promoted.** On the held-out test split it makes exactly the same decisions as V1 (31 false alarms out of 1,169 benign, recall 1.000) and has a better Brier score (0.0074 vs 0.0095). It fails the promotion gate, so `ensemble.fusion` stays `lr` (V1). V2 can be selected with `lr_v2`.
- **Bridge V2 is in place** and passes 5 of its 6 checks. The 6th check is the Fusion V2 gate. With the detection allowlist applied to every method, the learned fusion (V1) raises **85.5 alarms per 10,000 benign queries, against 393.5 for the old OR rule**, with recall 1.000 for both.
- **The unchanged Week-4 engine** processes the new bridge output and produces the same 1,388 alerts as before.
- **Tests:** all 196 pass (112 before, 84 new).

Full technical reports:
[`docs/research/STACKER_V2_IMPLEMENTATION_REPORT.md`](../research/STACKER_V2_IMPLEMENTATION_REPORT.md) and
[`docs/research/BRIDGE_V2_IMPLEMENTATION_REPORT.md`](../research/BRIDGE_V2_IMPLEMENTATION_REPORT.md).

---

## Contents

1. [Ground rules that were kept](#1-ground-rules-that-were-kept)
2. [What was wrong before](#2-what-was-wrong-before)
3. [Where the task assumptions did not match the code](#3-where-the-task-assumptions-did-not-match-the-code)
4. [Fusion V2: stacker.py](#4-fusion-v2-stackerpy)
5. [Neyman-Pearson threshold: thresholds.py](#5-neyman-pearson-threshold-thresholdspy)
6. [Training: train_fusion.py](#6-training-train_fusionpy)
7. [Bridge V2: bridge.py](#7-bridge-v2-bridgepy)
8. [Label provenance and the training guard](#8-label-provenance-and-the-training-guard)
9. [Configuration changes](#9-configuration-changes)
10. [Dashboard change](#10-dashboard-change)
11. [Evaluation scripts](#11-evaluation-scripts)
12. [Results](#12-results)
13. [Tests](#13-tests)
14. [Model and source protection](#14-model-and-source-protection)
15. [Behaviour changes users will notice](#15-behaviour-changes-users-will-notice)
16. [How to run everything](#16-how-to-run-everything)
17. [File-by-file change list](#17-file-by-file-change-list)
18. [Limitations and next steps](#18-limitations-and-next-steps)

---

## 1. Ground rules that were kept

| Rule | How it was checked |
|---|---|
| Path A and Path B are not retrained, replaced or modified | Model files and `path_a.py`, `path_b_predict.py`, `path_b_train.py` hashed before and after: identical |
| Week-3 feature extraction is not changed | `parsing/dns_parser.py` and `features/*` hashes identical |
| Week-4 detection engine is not changed | `detection/engine.py` hash identical; engine run on the new output |
| V1 fusion artefacts are not deleted or overwritten | `models/fusion_lr.pkl` and `.json` hashes identical; `save_v2` refuses to write over them |
| Held-out test rows are never used for fitting or thresholds | Test `test_threshold_ignores_held_out_test_labels` flips every test label and checks the models are identical |
| No new runtime dependencies | The binomial tail is computed with the standard library (`math.lgamma`); `requirements.txt` is unchanged |
| V2 is promoted only if the evaluation says so | Gate computed by `scripts/eval_fusion.py`; it failed, so the config default was not switched |

---

## 2. What was wrong before

### 2.1 Fusion V1 (`stacker.py`)

V1 was `LogisticRegression(class_weight="balanced")` over `[ml_score_A, ml_score_B, has_score_B, rule_hits]`.

| Problem | Effect |
|---|---|
| `has_score_B = (ml_score_B > 0)` was rebuilt from the score value | A real score of 0 or below would count as "missing" |
| R3 and R4 were added together into one `rule_hits` input | The two rules could not get different weights |
| Raw probabilities fed straight into the logistic regression | Path A is a calibrated probability and Path B is a squashed z-score, so they are on different scales |
| Rule thresholds were re-read from `settings.yaml` at every inference | Editing the config silently changed the trained model's inputs |
| The threshold was set on the same rows the model was fitted on | The false-alarm estimate was in-sample |
| No version field in the model file | No safe way to add a new format |

### 2.2 The ML bridge (`bridge.py`)

| Problem | Effect |
|---|---|
| Missing Path A model → `ml_score_A = 0`, `ml_label_A = 0` for every record | An unavailable detector looked like a quiet, benign network |
| Path B's coverage mask was dropped | Records without a Path B window got score 0 instead of "no score"; the same with `--no-path-b` |
| Path A, Path B and the Week-3 columns were matched by position | No check that row *i* in one frame is row *i* in the other. Week-3 columns were silently skipped when lengths differed |
| Missing model inputs were zero-filled by the parser | A missing feature was invisible |
| Two separate scores went to Week 4 | `ml_combined_score` plus a second hand-weighted `ml_threat_score = 0.4·attack_count/6 + 0.35·A + 0.25·B` |
| `ml_combined_label_thr` | Compared the blended score with Path A's own threshold, a threshold never fitted to that score. Nothing read it |
| Fixed confidence cut points 0.8 / 0.5 / 0.3 | Not tied to anything measured |
| `--label-only` labelled every unlabeled record `attack_count ≥ 1` | That rule fires on **528 of 8,353 benign rows (6.32%)** and misses 566 of 10,000 attacks |
| `attack_type_id` | Taken from whichever name came first in `attack_signature`, so the same record could get different ids |
| Leftovers | Unused `from tensorflow import keras` import; `run_path_b`'s docstring placed after a statement |

---

## 3. Where the task assumptions did not match the code

Before implementing, each assumption in the supplied task was checked against the code and the data. These differences changed what was built.

1. **Missing Path B scores are 0, not NaN.**
   - `path_b_predict.score_records` never returns NaN. Rows without a window get `0.0` together with `covered=False`, and the bridge threw `covered` away.
   - Fix: carry `covered` through, so those rows become NaN with `has_score_B = 0`.
   - On today's data Path B only outputs values strictly between 0 and 1, so V1's `b > 0` test happened to give the right answer. The flaw is structural, not a measured error.
2. **Path B's score is bounded but is not a probability.**
   - It is `sigmoid((error − mean) / std)`, so `logit(ml_score_B)` recovers the z-score exactly.
   - V2 standardises that z-score with statistics saved at training time, rather than treating it as a probability.
3. **The Neyman-Pearson guarantee cannot be met on this data.**
   - For α = 0.001 and δ = 0.05 it needs at least 2,995 benign calibration rows. The validation split has 1,169 benign rows, and V2's calibration part has 599.
   - The algorithm is fully implemented and tested. On this data it reports "insufficient samples", and the trainer falls back to the project's existing empirical rule and records that in the model file. No guarantee is claimed.
4. **Path A and Path B were trained once, on `time_seed42.json`.**
   - The other split manifests put Path A/B's own training rows into their test sets, so the evaluation uses only the validation and test rows of `time_seed42` and re-splits those.
5. **Training labels were never heuristic.**
   - All 18,353 training rows have `label_source = provenance`: labels from the capture file, i.e. ground truth.
   - The 6.32% heuristic false-alarm rate is real, but only the bridge's `--label-only` path uses that rule, and no pipeline script calls it.
6. **The project already has a label provenance system.**
   - `ingest/labeling.py` writes `label_source` ∈ {`file`, `provenance`, `manifest`, `weak_behavioral`, `abstain`}, and Path A already drops `weak_behavioral` rows.
   - The existing vocabulary was kept and one value, `heuristic`, was added. Renaming everything to the task's {`manifest`, `heuristic`} would have broken that code.
7. **There is no `path_a_predict.py` or `Week4_detection_engine.py`.**
   - Path A inference is `path_a.score_frame`, and Week 4 is `src/dns_detect/detection/engine.py`.
8. **The "supplied audit" document was not attached and is not in the repository.**
   - Issue ids (H1, H2, M5) and "references 13–15" come only from the task text. `REFERENCES.md` has no numbering, so new references were added as a named section.
9. **The parser never drops or reorders rows.**
   - So the old positional join was correct on current data, just unguarded. The new code checks it instead of assuming it.

---

## 4. Fusion V2: `stacker.py`

V1 (`FUSION_INPUTS`, `fusion_inputs`, `fit`, `save`, `load`, `predict`) is **unchanged**. Everything below is new code added after it.

### 4.1 Inputs (`FUSION_INPUTS_V2`)

| Input | Definition | Why |
|---|---|---|
| `logit_A` | `logit(clip(ml_score_A, 1e-6, 1 − 1e-6))` | Path A is a calibrated probability; the clip keeps 0 and 1 finite (±13.8) |
| `score_B` | `(logit(clip(ml_score_B)) − μ_B) / σ_B`; 0 where missing | Recovers Path B's z-score and puts it on a standard scale. μ_B = 7.327, σ_B = 4.962, saved in the model file |
| `has_score_B` | 1 where `ml_score_B` is present in the raw column, 0 where it is NaN | Taken **before** any filling: a real 0.0 counts as present, NaN as missing |
| `r3_tunnel` | `query_length > 100` and `entropy > 4.0` | Rule R3, its own input |
| `r4_deep` | `subdomain_depth > 5` | Rule R4, its own input |

Expected behaviour (each case is covered by a test):

| `ml_score_B` | `has_score_B` |
|---|---|
| NaN | 0 |
| 0.0 | 1 |
| positive | 1 |
| negative | 1 |

### 4.2 Input validation (`_numeric`)

- A missing `ml_score_A` column raises `KeyError`.
- NaN, infinite or non-numeric values in `ml_score_A` raise `ValueError` naming the bad rows.
- `ml_score_B` may be NaN; ±inf raises.
- The rule columns are required. The aliases `query_entropy` and `subdomain_count` are accepted.
- **Nothing is silently replaced with 0.**

### 4.3 Frozen specification

`build_spec()` records the rule thresholds (read from `settings.yaml` at **training** time) and the Path B scaling from the training rows. Both are stored in the model file and used at inference, so later edits to `settings.yaml` no longer change a trained model's inputs (test `test_rule_thresholds_frozen_after_config_change`).

### 4.4 Training procedure (`fit_v2`)

```
validation rows of time_seed42 (2,569 = 1,400 attack / 1,169 benign)
 ├─ fit_cal_split, grouped by parent domain:
 │     fit part          1,970 rows (all 1,400 attacks + 570 benign) → spec + logistic regression
 │     calibration part    599 rows (benign only, other parent domains) → threshold + tier cut points
 ├─ grouped out-of-fold scores: StratifiedGroupKFold(5) on parent domain → calibration diagnostics
 └─ save → models/fusion_lr_v2.pkl + models/fusion_lr_v2.json
```

Design decisions:

- **`class_weight=None`.** The threshold decides the false-alarm rate whatever the class balance. The validation prior (54.5% attack) is stored as `class_prior_validation`. No prior correction is applied, because no real deployment prevalence has been measured. Balanced weights were evaluated as a comparison only.
- **The calibration part is benign-only.** A false-alarm threshold needs only benign scores, and every attack row is needed for fitting. Parent domains containing any attack go to the fit part.
- **The deployed model is the fit-part model. It is not refitted on 100% of the rows.** The task's design calibrated the threshold on out-of-fold scores from five ~80% models and then deployed a 100% refit. That threshold would belong to different models than the one deployed. Here the threshold is set on rows the deployed model never saw, which is also what the Neyman-Pearson guarantee requires.
- **Out-of-fold scores are diagnostics only.** They feed the Brier score, the reliability table, the ECE (expected calibration error) and the coefficient stability. The code asserts that no parent domain appears on both sides of a fold and that every row is scored exactly once.
- **Why stratified GroupKFold.** The validation rows contain only two attack parent domains (daumel.xyz with 600 rows, dns2tcp-txt.com with 800). Stratification keeps attacks in the training part of every fold. Plain GroupKFold is the fallback.
- **Alarm rule `fusion_score > threshold` (strict).** This matches the Neyman-Pearson guarantee; ties can only lower the false-alarm rate.
- **Naming.** The output is called `fusion_score`, not a probability. The out-of-fold calibration looks perfect (ECE 2.5e-5), but only because Path A separates the validation rows perfectly. On the test period, 22 benign rows score between 0.5 and 0.8.

### 4.5 Versioned model files

The V2 metadata (`models/fusion_lr_v2.json`) contains:

| Field | Value or content |
|---|---|
| `model_version` | 2 |
| `feature_schema` | `FUSION_INPUTS_V2` |
| `rule_thresholds` | the frozen R3/R4 thresholds |
| `transform` | logit, EPS = 1e-6 |
| `score_B_scaling` | mean, std, number of rows |
| `coefficients`, `intercept` | |
| `threshold`, `threshold_rule` | `">"` |
| `threshold_method` | `neyman_pearson` / `empirical_fallback_gap_midpoint` |
| `fpr_budget` | 0.001 |
| `delta` | 0.05 |
| `n_cal_benign` | 599 |
| `n_required_for_np` | 2,995 |
| `rows` | validation / fit / calibration / attack / benign counts |
| `class_prior_validation`, `class_weight` | |
| `tier_boundaries`, `tier_source` | benign q90 / q99 / alarm threshold |
| `cv` | method, folds, group, seed |
| `oof_calibration` | Brier, ECE, base rate |
| `dataset_sha256` | |
| `label_provenance` | |
| `versions` | Python, NumPy, pandas, scikit-learn |
| `trained_at`, `random_seed`, `split`, `test_rows` | |

Loading and safety:

| Function | Behaviour |
|---|---|
| `load_versioned(version=None)` | Loads V2 when present, else V1. A metadata file without `model_version` is V1. Unknown versions, missing keys or a wrong schema raise `FusionSchemaError` |
| `predict_versioned(df, model, meta)` | Sends each model to its own input builder and alarm rule (V1 `>=`, V2 `>`) |
| `save_v2(...)` | Validates the metadata and refuses to write over the V1 files |
| `validate_meta_v2(meta)` | Checks the required keys, schema, threshold rule, rule thresholds and a positive Path B std |

### 4.6 Other new functions

| Function | Purpose |
|---|---|
| `fit_cal_split(y, groups, seed)` | Grouped fit / benign-only calibration split |
| `oof_folds`, `oof_scores` | Grouped out-of-fold indices and scores, with the leakage assertions |
| `calibration_report(y, p)` | Brier score, 10-bin reliability table, ECE |
| `tier_boundaries(benign_scores, threshold)` | Monotone q90 ≤ q99 ≤ threshold; q99 only when there are ≥ 100 benign rows |
| `choose_threshold(...)` | Neyman-Pearson when possible, otherwise the empirical fallback, with a logged warning |
| `current_rule_thresholds()` | Reads the rule thresholds from `settings.yaml` (training only) |

---

## 5. Neyman-Pearson threshold: `thresholds.py`

`threshold_for_fpr` is **unchanged**. New additions:

| Function | What it does |
|---|---|
| `np_violation_bound(n, k, alpha)` | Upper bound on P(false-alarm rate > α) when the threshold is the k-th smallest of n benign scores: Σⱼ₌ₖⁿ C(n,j)(1−α)ʲ α⁽ⁿ⁻ʲ⁾, computed in log space |
| `np_min_samples(alpha, delta)` | Smallest n for which any threshold meets the guarantee: n ≥ ln δ / ln(1−α). **2,995** for α = 0.001, δ = 0.05 |
| `np_threshold(benign_scores, alpha, delta=0.05)` | Umbrella algorithm of Tong, Feng & Li (2018). Sort benign scores, pick the smallest k with bound ≤ δ (binary search), alarm when score > s₍ₖ₎ |
| `InsufficientCalibrationError` | Raised when n is below the minimum; carries n and the required n |

Checks performed:

- **Order-statistic convention and comparison direction** were derived independently: a strict `>` rule with the k-th smallest benign score.
- **Ties** under the strict rule only lower the realised false-alarm rate (test with 3,990 tied zeros).
- **The bound** matches an exact `math.comb` computation, and k = n matches the closed form (1 − α)ⁿ.
- **Simulation:** 2,000 trials at α = 0.01, δ = 0.05, n = 1,000. The bound was violated in **2.6%** of trials, within the 5% allowed.
- **Input validation:** α and δ must lie strictly between 0 and 1, and the scores must be finite and non-empty.

The docstring states the conditions the guarantee needs:
- the calibration rows were not used to fit the scorer;
- they resemble deployment benign traffic;
- the guarantee says nothing about drift.

**Empirical fallback** (used on this data):
- The project's existing `threshold_for_fpr` puts the threshold midway between the budget quantile of benign scores and the lowest attack score above it.
- Because the calibration part is benign-only, the deployed model's scores on the fit part's attacks supply the upper edge.
- This matters here: benign calibration scores sit near 2.4e-5, so a threshold "just above the benign maximum" would flag any benign row with a non-zero Path A score. The fitted threshold is 0.500.

---

## 6. Training: `train_fusion.py`

New options (V1 stays the default):

| Option | Effect |
|---|---|
| `--version 2` | Trains Fusion V2 → `models/fusion_lr_v2.{pkl,json}` and `models/fusion_fallback_quantiles.json`; adds `fusion_v2` to `models/evaluation_metrics.json` |
| `--delta` | Neyman-Pearson confidence parameter (default 0.05) |
| `--seed` | Seed for the grouped fit/calibration split and cross-validation (default 42) |
| `--class-weight none\|balanced` | V2 only, default `none` |
| `--tiers-for-v1` | Writes `models/fusion_lr_tiers.json` (confidence-tier cut points for the existing V1 model) without training anything |
| `--allow-heuristic-labels` | Experimental: train even if some labels are untrusted |

Other changes:

- **Shared scoring.** `score_dataset()` scores the labelled file once and keeps Path B coverage (`covered_B`). For V2, uncovered rows become NaN.
- **Label check.** Labels are checked with `validate_training_labels` before fitting.
- **Separate metrics key.** V2 results go to a new `fusion_v2` key; the existing `fusion` key is not touched.
- **Fallback quantiles.** `models/fusion_fallback_quantiles.json` holds the sorted benign *validation* scores of Path A (1,169 values) and Path B (1,150 values), for the bridge's development fallback.

---

## 7. Bridge V2: `bridge.py`

### 7.1 New flow

```
records ── row_id = position in file ── check_features(raw records)   ← before the parser zero-fills
   │
   ├─ Path A: run_path_a ────────────────── join_on_row_id ─┐
   │                                                        │
   ├─ Path B: run_path_b ─ check_path_b_alignment ──────────┤  uncovered → NaN, has_score_B = 0
   ▼
merge_ml_scores
   fusion: lr / lr_v2 → stacker.load_versioned → predict_versioned        fusion_method = lr
   model missing      → production: error | development: OR rule         fusion_method = or_fallback
   fusion: or         → explicit OR (fusion_status = or_configured)       fusion_method = or_fallback
   no Path A score    → empty score, UNSCORED, "ml_unscored"              fusion_method = degraded
   comparison columns always: ml_combined_label_or, ml_combined_score_legacy
   confidence tiers: HIGH / MEDIUM / LOW / CLEAN / UNSCORED
   detection allowlist: alarm suppressed, score kept
ensure_week4_compatible: ml_threat_score = ml_combined_score (0 when suppressed), legacy score kept
Week-3 columns joined back by row_id → output JSON (null, never NaN) + <output>.meta.json
```

### 7.2 Production and development modes

| Situation | Production (default) | Development (`--dev`) |
|---|---|---|
| Path A model missing | `ModelUnavailableError`, exit code 1, no output | With `--allow-missing-path-a`: every record `degraded`, empty score, `ml_verdict_A = "SKIP"`, tier `UNSCORED` |
| Fusion model missing (`fusion: lr` / `lr_v2`) | `ModelUnavailableError` | OR rule with a warning; `fusion_method = or_fallback`, `fusion_status = fallback` |
| Missing feature columns | `MissingFeaturesError` listing all of them | With `--fill-missing-features`: zero-filled, flagged per row (`features_filled`), recorded in `<output>.meta.json` |
| Path B model missing | Allowed (Path B is optional by design), logged, scores empty | Same |
| `--no-path-b` | Path B scores all empty, `has_score_B = 0` | Same |

`--allow-missing-path-a` and `--fill-missing-features` are rejected outside development mode.

### 7.3 Path A and Path B

- `run_path_a(week3_json_path=None, df=None)` raises `ModelUnavailableError` (naming the missing file and the training command) when `dns_tunnel_rf.pkl` or `dns_scaler.pkl` is absent. It returns `row_id`, `ml_score_A`, `ml_label_A` and `ml_verdict_A`.
- `degraded_path_a(row_ids)` builds the development-only "no Path A" frame: empty scores, verdict `SKIP`, never `benign`.
- `run_path_b(...)`:
  - its docstring now comes first;
  - TensorFlow is imported only inside it, so the bridge module loads without TensorFlow;
  - it returns `(ml_score_B, ml_label_B, has_score_B)` with NaN on records without a window.
- `check_path_b_alignment(path, df, n)`: Path B's API is positional and its code could not change. So the bridge checks that Path B returned one score per record, and that the parser's re-read `client_ip` order equals the bridge's, before joining.

### 7.4 Record identity

- **`row_id`.** Each record gets `row_id` = its position in the input file, assigned once.
- **`join_on_row_id(base, other, name)`** raises `AlignmentError` when there is:
  - a missing `row_id` column or values;
  - duplicate ids;
  - ids in the scores that match no record;
  - records without scores.

  It merges one-to-one (`validate="one_to_one"`).
- **Week-3 columns** are joined back by `row_id`, never by position.
- **Order.** The output is sorted by `row_id`, so it keeps the input order.

### 7.5 Feature validation

`check_features(raw)` checks the **raw** records before the parser zero-fills anything. Each `FEATURES_8` input counts as present if any of its source columns exists:

| Feature | Accepted source columns |
|---|---|
| `query_length` | `query_length` |
| `query_entropy` | `query_entropy`, `entropy` |
| `has_digits` | `has_digits`, `domain` |
| `answer_count` | `answer_count`, `answer_size` |
| `subdomain_count` | `subdomain_count`, `subdomain_depth` |
| `longest_label` | `longest_label`, `first_label_length`, `domain` |
| `digit_ratio` | `digit_ratio`, `numeric_ratio` |
| `unique_char_ratio` | `unique_char_ratio`, `domain` |

It also reports rows where every source column is null.

### 7.6 One decision path

- **The stacker decides.** When a learned model exists, `ml_combined_score` and `ml_combined_label` come only from it (`fusion_method = lr`, `fusion_status = ok`). V1 gets its own legacy inputs (missing Path B → 0), so **V1's output is unchanged**.
- **Comparison columns are always written:**
  - `ml_combined_label_or`: the OR of the per-path labels;
  - `ml_combined_score_legacy`: the old `max(A, 0.6·A + 0.4·B)`.
- **`--weight-a` and `--weight-b`** are kept for compatibility. They now only shape `ml_combined_score_legacy` and print a deprecation warning.
- **`ml_combined_label_thr` was removed.** It compared the blend with Path A's own threshold, and nothing read it.
- **Development fallback score.** It is the empirical benign quantile, `searchsorted(benign_sorted, score, side="right") / n`, using the frozen benign validation distributions:
  - the fused fallback score is `max(qA, qB)`, or `qA` when Path B is missing;
  - scores above the observed range map to 1;
  - an empty or missing distribution file gives an empty score and tier `UNSCORED`.

  It is marked as a fallback and is not presented as equivalent to the learned fusion.
- **Run summary.** The console summary and `<output>.meta.json` report the count of each `fusion_method` and `fusion_status`, Path B coverage, missing Path A scores, alarms, OR-rule alarms, allowlist suppressions and the tier table.

### 7.7 Confidence tiers

| Tier | Rule | Benign rows per 10,000 by design |
|---|---|---|
| HIGH | the fused alarm (same comparison as the label) | ≤ 10 |
| MEDIUM | score ≥ benign q99 | ≈ 90 |
| LOW | benign q90 ≤ score < q99 | ≈ 900 |
| CLEAN | score < benign q90 | ≈ 9,000 |
| UNSCORED | no score (degraded, or fallback without quantiles) | — never CLEAN |

Where the cut points come from:

| Model | Source |
|---|---|
| V2 | Benign calibration-part scores of the deployed model (in the model file) |
| V1 | Sidecar `models/fusion_lr_tiers.json` (q90 0.0143, q99 0.0213, threshold 0.4875), from V1's scores on its own validation rows (in-sample, labelled as such) |
| Development fallback | The quantile scale itself (0.90 / 0.99) |
| None available | The old 0.8 / 0.5 / 0.3 cut points, with `confidence_method = legacy_fixed` |

The cut points are forced into order (q90 ≤ q99 ≤ threshold). Tied quantiles collapse a band, and the code doesn't fail on that. The tiers measure alarm volume and **are not attack probabilities**.

### 7.8 One threat score for Week 4

- **`ml_threat_score = ml_combined_score`.** Allowlist-suppressed rows get 0, so Week 4's Rule 6 cannot re-raise an alarm the allowlist removed. That was a real gap once the threat score became the fused score.
- **`ml_threat_score_legacy`** keeps the old `0.4·clip(attack_count, 0, 6)/6 + 0.35·A + 0.25·B`.
- **Rule evidence** stays available as `attack_count` and `attack_signature`, unchanged. No hidden rule boost was added.

### 7.9 JSON output

Missing and infinite values are written as `null` (`json.dump(..., allow_nan=False)` after conversion), never as the non-standard `NaN` token.

### 7.10 Output columns

| Status | Columns |
|---|---|
| Kept (Week-4 contract) | `ml_combined_score`, `ml_combined_label`, `ml_confidence`, `ml_threat_score`, `ml_combined_verdict`, `ml_score_A`, `ml_label_A`, `ml_verdict_A`, `ml_score_B`, `ml_label_B`, `suppressed_by_allowlist`, all Week-3 columns |
| Kept, now always present | `ml_combined_label_or` |
| New | `row_id`, `has_score_B`, `fusion_method`, `fusion_status`, `confidence_method`, `ml_combined_score_legacy`, `ml_threat_score_legacy`; `features_filled` (only with `--fill-missing-features`) |
| New value | `ml_confidence = "UNSCORED"`, `ml_combined_verdict = "ml_unscored"` |
| Removed | `ml_combined_label_thr` |

---

## 8. Label provenance and the training guard

### 8.1 `--label-only` (`generate_labels_from_week3`)

- Trusted labels (`file`, `provenance`, `manifest`, or no source given) are kept and tagged with their source.
- Records without a trusted label are **refused by default**. The error points to `scripts/label_from_manifest.py` and `ingest/labeling.py`.
- With `--allow-heuristic-labels` (and only then), they are labelled `attack_count ≥ 1` and tagged `label_source = "heuristic"`, with a warning giving the count and percentage.
- The label counts per source are printed.

### 8.2 Attack type

- `attack_type_id` now uses an explicit priority, most severe first:

  `CACHE_POISONING > ENCODING > HIGH_ENTROPY > RANDOM_SUBDOMAIN > NXDOMAIN_FLOOD > AMPLIFICATION`

- The id map is unchanged, so existing consumers still work.
- New multi-hot columns `attack_type_<NAME>` show every type present.

### 8.3 Training guard (`ingest/labeling.py`)

- **New `validate_training_labels(records, allow_untrusted=False)`** counts labels by source. It raises `UntrustedLabelError` when any labelled row has a source outside `file` / `provenance` / `manifest`, unless explicitly allowed; then it logs a warning and returns the counts for the training metadata.
- **New `UNTRUSTED_SOURCES = {"weak_behavioral", "heuristic"}`.**
- **Called from:**
  - `scripts/train_models.sh`, before Path A/B training (new flag `--allow-heuristic-labels`);
  - `scripts/train_fusion.py`;
  - `scripts/run_multiseed.py` (new flag `--allow-heuristic-labels`, passed on to fusion training).
- **Path A/B source was deliberately left unchanged.** So calling `python -m dns_detect.models.path_a --train` directly bypasses the guard; this is documented. Path A already drops `weak_behavioral` rows itself.
- **Current data passes:** 18,353 `provenance`, 0 untrusted.

### 8.4 Bug fixed: label laundering

`label_records` used to re-tag any untrusted `label_source` as `file` (trusted) when relabelling an already-labelled file. A heuristic or weak label fed back through the pipeline would then pass as ground truth. Known untrusted sources are now kept as they are (test `test_relabeling_does_not_launder_untrusted_sources`).

### 8.5 Weak supervision and cleanlab

These were investigated and not added:
- **Snorkel label model.** `labeling.py` already implements Snorkel-style labelling functions. A label model over the six Week-3 flags would rest on the same `attack_count` rule whose 6.32% benign false-alarm rate started this work. Those flags' errors are correlated, which breaks the label model's independence assumption.
- **cleanlab** is a reasonable future label-quality *audit* of the provenance-labelled rows. It was not added, to avoid a new dependency, and its output would not prove a label wrong.

---

## 9. Configuration changes

`config/settings.yaml`, section `ensemble`:

```yaml
  # Primary decision in fusion/bridge.py:
  #   "lr"    learned logistic-regression fusion V1 (scripts/train_fusion.py → models/fusion_lr.pkl)
  #   "lr_v2" fusion V2 (scripts/train_fusion.py --version 2 → models/fusion_lr_v2.pkl) — experimental,
  #           see docs/research/STACKER_V2_IMPLEMENTATION_REPORT.md (promotion gate not passed)
  #   "or"    legacy OR of the per-path labels (comparison / explicit choice)
  # A missing learned model stops the bridge in production; in development it falls back to "or".
  fusion: lr
  # production: missing Path A or fusion model is an error (fail closed).
  # development: OR fallback / degraded records are allowed and clearly marked (bridge --dev).
  bridge_mode: production
```

- `fusion` is unchanged (`lr`). `bridge_mode` is new.
- `rf_weight` / `tf_weight` are kept; their comment now says they only shape the legacy comparison score.
- Invalid values for `fusion` or `bridge_mode` raise `ValueError`.

`.gitignore` gained `.venv/`.

---

## 10. Dashboard change

`dashboard/server.py` is the only change outside the planned files:

- **Why it was needed.** The unchanged Week-4 engine copies `ml_score_B` into alert details with `float(row.get(...))`. That turns the bridge's `null` (a record without a Path B window) into NaN, and the engine's own `json.dump` writes it as a bare `NaN` token: 9 occurrences in the new alert file, 0 before. Python reads that fine, but the browser's `JSON.parse` rejects the whole `/api/state` response.
- **The fix.** A new `_finite()` helper turns NaN and ±inf into `null` before serving `/api/state`, and the response is encoded with `allow_nan=False`.
- **The engine itself was not changed.**

---

## 11. Evaluation scripts

### 11.1 `scripts/eval_fusion.py` (new, read-only)

- **Data:** only the `time_seed42` validation and test rows, which Path A/B never trained on. That is 5,138 rows (2,800 attack / 2,338 benign, base rate 54.5%) with 2 attack parent domains, 47 benign parent domains and 99.3% Path B coverage.
- **Runs:**
  - a **reference run**: fusion fitted on validation, scored once on the manifest's test rows;
  - **resampled runs** with the project's own `splits.build_indices` for `capture_group`, `parent_domain_group` and `time` × seeds 42–46.
- **Methods compared, on identical test rows:** Path A, Path B, OR rule, V1 (refitted per run), V2 (refitted per run), V2 with balanced weights.
- **Metrics:**
  - recall, FPR with a 95% Wilson interval, alarms per 10,000 benign rows;
  - precision, F1, PR-AUC, Brier score (not for Path B, whose score isn't a probability);
  - confusion matrix, PR-curve points, 10-bin reliability table;
  - coefficients with their spread across runs, correlation matrix and VIF (variance inflation factor) of the V2 inputs;
  - the OOF/calibration score alignment.
- **Duplicate detection.** On this pool the two grouped strategies cannot keep both classes in every fold, so both fall back to the *same* random row split. The script detects identical runs and excludes them from the gate. There are 10 distinct runs, not 15.
- **Promotion gate:** the six criteria from the task, reported as exact counts (k / n).
- **Output:** `outputs/fusion_eval/results.json`. The `--cache` option reuses the base-model scores, so a run takes about 25 seconds.

### 11.2 `scripts/eval_bridge.py` (new, read-only)

- **Data:** the 2,569 test rows (1,400 attack / 1,169 benign); all labels are `provenance`.
- **Methods:** OR gate, legacy max-blend (at Path A's threshold, i.e. the old `_thr` rule), LR V1 and LR V2. All run through `merge_ml_scores`, the production code path, with **the detection allowlist applied to every method's decision**, so the comparison is fair.
- **Ablations:**
  - Path A removed: production must refuse; development must mark every row degraded;
  - Path B removed: every Path B score must be empty;
  - with `--cli-ablation`, the real bridge process is run against a temporary models folder without `dns_tunnel_rf.pkl`.
- **Also checks:** reproducibility, data integrity and the six bridge promotion criteria.
- **Output:** `outputs/bridge_eval/results.json`.

---

## 12. Results

### 12.1 Fusion, honest test split (fitted on validation, tested once; 1,169 benign / 1,400 attack)

| Method | Recall | FPR (95% CI) | False alarms | Alarms / 10k benign | Precision | F1 | PR-AUC | Brier |
|---|---|---|---|---|---|---|---|---|
| Path A | 1.000 | 2.65% (1.87–3.74) | 31 | 265.2 | 0.978 | 0.989 | 0.9936 | 0.0076 |
| Path B | 1.000 | 5.47% (4.31–6.93) | 64 | 547.5 | 0.956 | 0.978 | 1.0000 | — |
| OR rule | 1.000 | 7.10% (5.76–8.72) | 83 | 710.0 | 0.944 | 0.971 | 0.9936 | — |
| Fusion V1 | 1.000 | 2.65% (1.87–3.74) | 31 | 265.2 | 0.978 | 0.989 | 1.0000 | 0.0095 |
| **Fusion V2** | 1.000 | 2.65% (1.87–3.74) | 31 | 265.2 | 0.978 | 0.989 | 1.0000 | **0.0074** |
| V2, balanced weights | 1.000 | 2.40% (1.66–3.44) | 28 | 239.5 | 0.980 | 0.990 | 1.0000 | 0.0072 |

**Every method is more than 20× over the 0.1% budget on this split.** The test benign traffic comes from a later period than the validation traffic, and no threshold method fixes that kind of drift.

### 12.2 Fusion, resampled runs (means)

| Split (runs) | Path A FPR | OR FPR | V1 FPR / recall | V2 FPR / recall | V1 Brier | V2 Brier |
|---|---|---|---|---|---|---|
| Random rows (5) | 1.65% | 3.70% | 0.00% / 0.994 | 0.11% / 1.000 | 0.0042 | 0.0017 |
| Time (5) | 0.00% | 0.00% | 0.00% / 1.000 | 0.00% / 1.000 | 0.0001 | ≤ 0.0001 |

Random-row splits mix the validation and test periods, so they are optimistic about drift. The reference run in 12.1 is the honest drift test.

### 12.3 What the fusion learned

| | V2 (validation fit) | V2 across 10 runs | V1 across 10 runs |
|---|---|---|---|
| Path A weight | 0.771 | 0.68–0.76 (sd 0.34–0.38) | 9.4–9.5 (sd ≤ 0.05) |
| Path B weight | 0.048 | 2.57–2.88 (sd 1.9–2.3) | 2.56 |
| `has_score_B` weight | 0.023 | −0.16 to −0.17 (negative in 80% of runs) | −0.94 to −1.07 (always negative) |
| R3 / R4 weights | 0 / 0 | 0 / 0 | `rule_hits` 0 |

- **Path A and Path B are strongly collinear** (correlation 0.963, VIF 14.1 each). That is why V2's Path B weight swings between runs.
- **R3 and R4 never fire in the evaluation pool.** R3 fires on 2,535 rows, all in Path A/B's training rows (dns2tcp), and R4 on none. Their weights are therefore 0, which is correct.
- **The negative `has_score_B` weight was investigated, not forced positive.** Only 38 validation rows lack a Path B score (19 benign + 19 attack, all at the start of a client's traffic before the 20-query window fills), so the weight is weakly determined. It isn't leakage (coverage depends only on window position), and it isn't a transform bug (the same sign appears in V1).

### 12.4 Fusion V2 promotion gate (10 distinct runs)

| Criterion | Result |
|---|---|
| 1. FPR within budget in ≥ 95% of runs | **Fail**: 9 / 10, and the reference run (not counted) is at 2.65% |
| 2. Recall no more than 0.01 below V1 | Pass: 10 / 10 |
| 3. PR-AUC above the best single path | **Fail**: 4 / 10 (ties at 1.0) |
| 4. Fewer alarms per 10k than OR | Pass: 5 / 10 lower, 5 tied at 0 (means 5.7 vs 185) |
| 5. Brier below V1 | Pass: 10 / 10 |
| 6. Backward compatibility | Pass |

→ **V2 stays experimental.** Ten runs are reported as exact counts, not as a statistical guarantee.

### 12.5 Bridge, test rows with the allowlist applied to every method

| Method | Recall | FPR | Alarms / 10k benign | Precision | F1 |
|---|---|---|---|---|---|
| OR gate | 1.000 | 3.94% | 393.5 | 0.968 | 0.984 |
| OR gate without allowlist (reference) | 1.000 | 7.10% | 710.0 | 0.944 | 0.971 |
| Legacy max-blend | 1.000 | 1.11% | 111.2 | 0.991 | 0.995 |
| **LR fusion V1 (default)** | 1.000 | 0.86% | 85.5 | 0.993 | 0.996 |
| LR fusion V2 | 1.000 | 0.86% | 85.5 | 0.993 | 0.996 |

### 12.6 Bridge ablations

| Case | Result |
|---|---|
| Path A removed, production (`merge_ml_scores`) | `ModelUnavailableError` |
| Path A removed, development | 2,569 / 2,569 degraded, 0 silently benign, all `UNSCORED` |
| Path A removed, real bridge process, production | Exit code 1, no output file written |
| Same, `--dev --allow-missing-path-a` | Exit 0; 18,353 / 18,353 degraded, 0 silently benign |
| Path B removed | 2,569 / 2,569 Path B scores empty; V1 recall 1.000, FPR 0.17% (2 false alarms) |

### 12.7 Bridge, full file (18,353 records), old vs new

| Check | Result |
|---|---|
| Path A scores | Identical row by row |
| Path B scores on covered rows (18,220) | Identical |
| Path B empty scores | 133 = the uncovered records (first 19 queries of each of 7 clients); the old output had 0.0 on exactly those rows |
| V1 fused score and label | Identical: 10,028 alarms before the allowlist, 10,007 after, 21 suppressed |
| OR label, legacy blend, legacy threat score | Identical to the old formulas |
| Allowlisted rows' `ml_threat_score` | 0 |
| Confidence tiers (old → new) | HIGH 10,020 → 10,028 · MEDIUM 8 → 98 · LOW 2 → 290 · CLEAN 8,323 → 7,937 · UNSCORED 0 |

### 12.8 Confidence tiers on test rows: designed vs observed benign volume (per 10,000 benign)

| Tier | By design | V1 observed | V2 observed |
|---|---|---|---|
| HIGH | ≤ 10 | 265.2 | 265.2 |
| MEDIUM | ≈ 90 | 641.6 | 154.0 |
| LOW | ≈ 900 | 1,394.4 | 1,248.9 |
| CLEAN | ≈ 9,000 | 7,698.9 | 8,331.9 |

The gap is the same validation→test drift: test-period benign traffic scores higher than validation benign traffic. V2's cut points sit closer to the design for the lower tiers.

### 12.9 Week-4 engine (unchanged code)

| | Old bridge output | New bridge output |
|---|---|---|
| Exit code | 0 | 0 |
| Total alerts | 1,388 | 1,388 |
| Rule 5 ML-flagged queries | 10,007 | 10,007 |
| Rule 6 additional alerts | 0 | 0 (9,999 deduplicated against Rule 5) |

`monitoring.monitor` also runs on the new output (exit 0). It drops empty scores itself.

---

## 13. Tests

`pytest tests/ -q` → **196 passed, 0 failed.** Before this work: 112 passed.

### 13.1 `tests/test_stacker.py` (new, 44 tests)

| Area | Tests |
|---|---|
| Missing values | Missing Path B → `has_score_B = 0`; real 0.0 present; negative scores present; V1 builder unchanged |
| Validation | Missing `ml_score_A` → `KeyError`; NaN / inf / text in A → `ValueError`; inf in B → `ValueError`; missing rule column raises (not filled); column aliases accepted |
| Transforms | Clipping keeps 0 and 1 finite; exact logit values; Path B logit recovers z; standardisation uses saved statistics |
| Rules | R3 and R4 independent; thresholds frozen after a config change |
| Model files | V1 loads and predicts identically; V2 save/load validates the schema; missing metadata key raises; unknown version raises; V2 never overwrites V1 |
| Neyman-Pearson | Minimum of 2,995 matches the closed form; bound at k = n matches (1−α)ⁿ; bound matches the exact binomial tail; smallest valid order statistic picked; guarantee holds in simulation; insufficient samples raise; bad α/δ rejected; ties never exceed the budget; fallback recorded in metadata; Neyman-Pearson used when there are enough rows |
| Grouped CV | No parent domain on both sides of a fold; every row gets exactly one OOF score; fit and calibration parts disjoint and calibration benign-only; flipping test labels changes no model |
| Consistency | Training and inference transforms identical; metadata complete; tier cut points in order; repeated training deterministic; strict alarm rule |

### 13.2 `tests/test_bridge.py` (new, 40 tests)

Path A and Path B are stubbed, so these run without TensorFlow or trained models.

| Area | Tests |
|---|---|
| Fail closed | Missing Path A raises by default; `--allow-missing-path-a` needs development mode; development marks every record degraded / `SKIP` / `UNSCORED` / `ml_unscored`; production merge rejects unscored rows |
| Path B coverage | 25 records, window 20: records 1–19 empty with `has_score_B = 0`, covered rows keep their scores, a real 0.0 stays 0.0; `--no-path-b` leaves all empty and the JSON contains no `NaN` |
| `row_id` joins | Shuffled scores re-aligned; duplicate, missing and unmatched ids raise; Path B order or length mismatch raises; output keeps input order and Week-3 columns |
| Fusion method | Missing model raises in production; development uses `or_fallback`; the learned model is the decision; V2 mode works; invalid settings rejected; `_thr` column removed |
| Tiers and fallback | Benign-quantile edge cases; fallback uses the frozen quantiles; tiers in order with ties; inverted cut points repaired; V1 sidecar used; tier summary reports designed volume |
| Threat score | Threat score = fused score, legacy formula kept; allowlisted alarm cannot come back through the threat score; legacy blend formula; CLI weights print a deprecation warning and only change the legacy score |
| Features | Missing feature column raises; `--fill-missing-features` development only and recorded; null rows reported |
| Labels | Trusted labels kept and tagged; unlabelled or untrusted records refused by default; heuristic labels need opt-in and are tagged; training guard rejects heuristic labels; relabelling does not launder untrusted sources; attack-type priority independent of signature order |
| Week-4 contract | All required columns present; **the unchanged engine runs as a subprocess on bridge output**; output deterministic |

### 13.3 Existing tests updated

Two assertions in `tests/test_thresholds_fusion.py` encoded behaviour the task deliberately changed:

1. **`test_merge_lr_mode_falls_back_to_or_without_model`.** Production now raises, so the test runs in development mode and checks `fusion_method == "or_fallback"`. `ml_combined_label_or` is now always present; previously it was absent in that case.
2. **`test_allowlist_suppresses_alarm_but_keeps_score`.** In OR mode `ml_combined_score` is now the benign-quantile score, not raw Path A. The test now checks the score is unchanged by suppression and that `ml_combined_score_legacy` is 0.95. The comparison is NaN-safe, so it also passes on a clone without the fallback quantiles file.

---

## 14. Model and source protection

Recorded in [`docs/research/fusion_v2_integrity.json`](../research/fusion_v2_integrity.json).

| Group | Files | Before = after |
|---|---|---|
| Path A models | `dns_tunnel_rf.pkl`, `dns_tunnel_gbt.pkl`, `dns_scaler.pkl`, `dns_threshold.json`, `bigram_table.json`, `dns_tunnel_transformer.keras` | Yes |
| Path B models | `dns_trafficformer.h5`, `dns_trafficformer_norm.json`, `dns_trafficformer_threshold.json` | Yes |
| Fusion V1 | `fusion_lr.pkl`, `fusion_lr.json` | Yes |
| Protected source | `models/path_a.py`, `models/path_b_predict.py`, `models/path_b_train.py`, `models/splits.py`, `parsing/dns_parser.py`, `detection/engine.py`, `features/*.py` | Yes |

Examples of the hashes (SHA-256):

| File | SHA-256 (before and after) |
|---|---|
| `dns_tunnel_rf.pkl` | `87e3d746a5554f0365f8d8f7de495338000f276c0e8aac173f3527a8714bbcd6` |
| `dns_trafficformer.h5` | `3b49736276bfb90d7fc55da59b6d55b8da5520df4245d29b962119edd7c0077c` |
| `fusion_lr.pkl` | `a5e30c119d543aecf6fa8164c58117115385f5fbe68f0e16aa1c87848e4bc4c4` |

New model files: `fusion_lr_v2.pkl`, `fusion_lr_v2.json`, `fusion_fallback_quantiles.json`, `fusion_lr_tiers.json`. `models/` is gitignored, so these exist only locally; they are recreated with the commands in §16.

`models/evaluation_metrics.json` is tracked in git. It only gained the key `fusion_v2`; every other key is byte-equal to the previous version.

**Reproducibility:** re-running `eval_fusion.py` gives identical per-run results and an identical gate. Re-running the bridge gives an identical output frame.

---

## 15. Behaviour changes users will notice

1. **The pipeline stops if the fusion model is missing.** A fresh clone has no `models/fusion_lr.pkl` (gitignored), so `run_pipeline.sh` and the dashboard stop with a clear error. Train the fusion (§16), or run the bridge with `--dev`, or set `bridge_mode: development`.
2. **Path B scores can be empty.** Records without a Path B window now have `ml_score_B = null` and `has_score_B = 0` instead of 0.0.
3. **New confidence value `UNSCORED`.** Week 4's Rule 5 only uses the tier for severity (`HIGH` → High, anything else → Medium), so it works unchanged.
4. **More records in MEDIUM and LOW** (98 and 290 instead of 8 and 2 on the full file), because the cut points now come from benign score volume instead of fixed numbers.
5. **Week 4's Rule 6 effectively goes quiet.** With `ml_threat_score = ml_combined_score`, Rule 6 (≥ 0.7 on rows the fused label didn't flag) can only fire between 0.7 and the alarm threshold. V1's threshold is 0.4875, so that range is empty. Rule 6 also produced 0 alerts before.
6. **`ml_combined_label_thr` is gone.**
7. **Deprecation notice.** `--weight-a` / `--weight-b` print it. The dashboard still passes them.
8. **Each bridge run also writes `<output>.meta.json`** with the run summary.
9. **`--label-only` now refuses unlabelled records** unless `--allow-heuristic-labels` is given.
10. **Training scripts refuse untrusted labels** unless `--allow-heuristic-labels` is given.
11. **Engine alert JSON can contain `NaN`** for records without a Path B window. The dashboard cleans this before serving; other alert readers must accept it.

---

## 16. How to run everything

```bash
# Environment used for the results above
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt pytest      # Windows path; use .venv/bin on Linux

# Fusion V1 (unchanged default) and its confidence-tier sidecar
python scripts/train_fusion.py --labeled data/processed/merged_features_labeled.json \
    --split-manifest data/processed/splits/time_seed42.json
python scripts/train_fusion.py --tiers-for-v1 --labeled data/processed/merged_features_labeled.json \
    --split-manifest data/processed/splits/time_seed42.json

# Fusion V2 (experimental) + development fallback quantiles
python scripts/train_fusion.py --version 2 --labeled data/processed/merged_features_labeled.json \
    --split-manifest data/processed/splits/time_seed42.json

# Bridge (production mode by default)
python -m dns_detect.fusion.bridge --week3 data/week3_features_all.json \
    --output data/week3_features_with_ml.json --path-b-model dns_trafficformer
python -m dns_detect.fusion.bridge ... --dev                         # allow OR fallback
python -m dns_detect.fusion.bridge ... --dev --allow-missing-path-a  # development only

# Week 4 on the bridge output (unchanged)
python -m dns_detect.detection.engine --input data/week3_features_with_ml.json \
    --output data/week4_unified_alerts.json

# Evaluations (read-only)
python scripts/eval_fusion.py --labeled data/processed/merged_features_labeled.json \
    --split-manifest data/processed/splits/time_seed42.json --cache outputs/fusion_eval/scored.pkl
python scripts/eval_bridge.py --labeled data/processed/merged_features_labeled.json \
    --split-manifest data/processed/splits/time_seed42.json --cli-ablation

# Tests
python -m pytest tests/ -q
```

- **On Windows**, set `PYTHONIOENCODING=utf-8` first. Several existing scripts print characters such as "→" that the Windows console code page cannot encode.
- **Module commands** need `PYTHONPATH=src` when run from the repository root.

---

## 17. File-by-file change list

### Modified

| File | Change |
|---|---|
| `src/dns_detect/fusion/stacker.py` | +454 lines. Fusion V2 inputs, validation, frozen spec, grouped fit/calibration split, grouped OOF, calibration report, tier cut points, threshold choice, versioned save/load/predict, schema validation. V1 unchanged |
| `src/dns_detect/models/thresholds.py` | +103 lines. `np_violation_bound`, `np_min_samples`, `np_threshold`, `InsufficientCalibrationError`. `threshold_for_fpr` and `rates` unchanged |
| `src/dns_detect/fusion/bridge.py` | Rewritten (635 added / 317 removed). Modes, fail-closed Path A, NaN Path B coverage, `row_id` joins, feature validation, single learned decision, fallback score, tiers, single threat score, null-safe JSON, run summary, label provenance, attack-type priority. Public functions kept |
| `src/dns_detect/ingest/labeling.py` | +43 lines. `UNTRUSTED_SOURCES`, `UntrustedLabelError`, `validate_training_labels`; untrusted sources no longer relabelled as `file` |
| `scripts/train_fusion.py` | `--version 2`, `--delta`, `--seed`, `--class-weight`, `--tiers-for-v1`, `--allow-heuristic-labels`; shared `score_dataset`; label check; fallback quantiles; `fusion_v2` metrics key |
| `scripts/train_models.sh` | Label provenance check before Path A/B training; `--allow-heuristic-labels` flag and help text |
| `scripts/run_multiseed.py` | Label check before training; `--allow-heuristic-labels` passed on to fusion training |
| `config/settings.yaml` | `ensemble.bridge_mode: production`; documented `fusion` values including `lr_v2`; clarified legacy weights |
| `dashboard/server.py` | `_finite()` and `allow_nan=False` for `/api/state` |
| `tests/test_thresholds_fusion.py` | Two assertions updated (§13.3); `pytest` import |
| `docs/Week3/ML_IMPROVEMENT_GUIDE.md` | "Step 7 — V2" subsection; checklist line updated |
| `docs/research/REFERENCES.md` | New section "Fusion and bridge" (Tong et al. 2018, Wolpert 1992, Niculescu-Mizil & Caruana 2005, Guo et al. 2017, Brier 1950, Wilson 1927, King & Zeng 2001, scikit-learn docs) |
| `README.md` | Fusion training command; note on production mode and `--dev` |
| `models/evaluation_metrics.json` | New key `fusion_v2` |
| `.gitignore` | `.venv/` |

### Created

| File | Purpose |
|---|---|
| `scripts/eval_fusion.py` | Read-only Path A / Path B / OR / V1 / V2 evaluation with duplicate detection and the promotion gate |
| `scripts/eval_bridge.py` | Read-only bridge evaluation: four methods, ablations, CLI ablation, bridge gate |
| `tests/test_stacker.py` | 44 tests |
| `tests/test_bridge.py` | 40 tests |
| `docs/research/STACKER_V2_IMPLEMENTATION_REPORT.md` | Full Fusion V2 report |
| `docs/research/BRIDGE_V2_IMPLEMENTATION_REPORT.md` | Full Bridge V2 report |
| `docs/research/fusion_v2_integrity.json` | Before/after hashes and test counts |
| `docs/Week4/CHANGES.md` | This document |

### Unchanged on purpose

`models/path_a.py`, `models/path_b_predict.py`, `models/path_b_train.py`, `models/splits.py`, `parsing/dns_parser.py`, `features/*`, `detection/engine.py`, `monitoring/monitor.py`, `requirements.txt`, and every Path A / Path B / V1 model file.

---

## 18. Limitations and next steps

### Limitations

1. **No Neyman-Pearson guarantee yet.** It needs 2,995 benign calibration rows; there are 599. More benign data is the only way to get it.
2. **Drift between periods.** Every method is about 26× over the false-alarm budget on the later test period. Neither V2 nor the Neyman-Pearson guarantee addresses drift.
3. **Ceiling effect.** Recall is 1.0 almost everywhere, and the test attacks are one family (dnsexfiltrator), so PR-AUC ties at 1.0 and cannot separate the methods.
4. **Validation rows are not fresh for the base models.** Path A uses them for its calibration and threshold, and Path B for its threshold, so their scores there are optimistic. The fusion inherits that.
5. **Leakage cannot be fully ruled out.** Path A's training row ids were not saved, and its recorded dataset version (`7eeea4…`) differs from the manifest's (`88a5f2…`).
6. **The grouped splits fall back to random rows** on this pool, and random rows mix time periods.
7. **Path B recomputes slightly differently.** Under Keras 3 with the legacy `.h5` rebuild, it gives 64 test false alarms where the stored metrics say 71. Path A and V1 are unaffected.
8. **The label guard can be bypassed** by calling the Path A/B training modules directly.
9. **`row_id` is position-based**, because Path B's API is positional. The order check uses `client_ip`.
10. **V1's confidence-tier cut points are in-sample.**
11. **The development fallback score's Path A quantile is coarse**, because Path A is exactly 0 on every benign validation row.

### Next steps

1. Collect at least 2,995 benign calibration rows from the deployment period.
2. Add a drift-aware recalibration of the threshold on recent benign traffic.
3. Build a test split with more than one attack family, so the methods stop tying at recall 1.0.
4. Look into Path B's false alarms on the test period: without Path B, V1 had 2 false alarms instead of 10.
5. Reduce the Path A / Path B collinearity, for example by regularising or dropping one input, once there is more data.
6. Decide the future of Week 4's Rule 6, which the single threat score makes redundant with Rule 5.
7. Run a label-quality audit with confident learning (cleanlab) on the provenance-labelled rows.
8. Review the draft branch before merging, and decide whether demos should default to development mode.
