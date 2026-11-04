# Fusion V2 (`fusion/stacker.py`) — implementation report

Branch `feat/fusion-v2`. Every number below was produced by running the code in this branch:
- training: `scripts/train_fusion.py --version 2`
- evaluation: `scripts/eval_fusion.py`, output in `outputs/fusion_eval/results.json`
- tests: `pytest tests/`

Environment: Python 3.13.14, NumPy 2.5.4, pandas 3.1.0, scikit-learn 1.9.1, TensorFlow 2.21.

**Decision: V2 is experimental.** It is not promoted, and `ensemble.fusion` stays `lr` (V1). See §14.

---

## 1. Original V1 architecture

`ml_combined = LogisticRegression(class_weight="balanced")` over four inputs:

```
[ml_score_A, ml_score_B, has_score_B = (ml_score_B > 0), rule_hits = R3 + R4]
```

- It is fitted on the validation rows of `time_seed42.json`.
- The threshold comes from `threshold_for_fpr(y_val, p_val, 0.001)`, computed on the **same rows** the model was fitted on.
- It is used by the bridge when `ensemble.fusion: lr`.
- Rule thresholds are read from `settings.yaml` at every inference.

V1 is kept byte-identical: `models/fusion_lr.{pkl,json}`, hashes unchanged (§12).

## 2. Problems found

These were checked against the code, not taken from the audit.

| # | Problem | What the code actually does |
|---|---|---|
| H2 | Missing Path B score looks like a real score | `path_b_predict.score_records` never returns NaN. Rows without a window get `0.0` and `covered=False`. The bridge and `train_fusion.py` dropped `covered`, so "missing" arrived as 0, and V1's `has_score_B = (b > 0)` then rebuilt missingness from the value. On this data Path B only emits values in (0, 1), so V1 got the right answer by accident. The flaw is structural, not a measured error. |
| — | Path B scale | `ml_score_B = sigmoid((err − μ)/σ)`. It is bounded in (0, 1) but is **not** a probability. Its logit is exactly the z-score of the reconstruction error (test `test_path_b_logit_recovers_z_score`). |
| — | Path A scale | Isotonic-calibrated tree ensemble. On the validation rows **every** score is exactly 0 or 1 (2 unique values), so Path A alone separates validation perfectly. |
| — | Rules combined | R3 + R4 were summed into one input. R3 fires on 2,535 rows, **all in Path A/B's training rows** (dns2tcp). R4 fires on 0 rows. Neither fires anywhere in the validation or test pool. |
| — | Thresholds live | V1 re-reads the rule thresholds from `settings.yaml` at inference, so editing the config silently changes the model's inputs. |
| — | In-sample threshold | V1's threshold is set on the rows the model was fitted on. |

## 3. V2 architecture

```
validation rows (time_seed42 val, 2,569 = 1,400 attack / 1,169 benign)
 ├─ fit_cal_split (grouped by parent_domain):
 │     fit part   1,970 rows  (all 1,400 attacks + 570 benign)  → spec + LogisticRegression
 │     cal part     599 rows  (benign only, disjoint parent domains) → threshold + tier cut points
 ├─ grouped OOF (StratifiedGroupKFold(5), groups = parent_domain) → calibration diagnostics only
 └─ artefact models/fusion_lr_v2.{pkl,json} (V1 files untouched)
inference: fusion_inputs_v2(df, saved spec) → predict_proba → fusion_score > threshold
```

The deployed model is the fit-part model itself. It is **not** refitted on 100% of the rows, so the threshold belongs to the exact model that uses it (§7).

## 4. Feature engineering (`FUSION_INPUTS_V2`)

| Input | Definition |
|---|---|
| `logit_A` | `logit(clip(ml_score_A, 1e-6, 1 − 1e-6))`, range ±13.8 |
| `score_B` | `(logit(clip(ml_score_B)) − μ_B) / σ_B` with μ_B = 7.327, σ_B = 4.962 from the fit part (1,944 present rows); 0 when missing |
| `has_score_B` | 1 when `ml_score_B` is present in the **raw** column, before any fill (NaN → 0, real 0.0 → 1, negative → 1) |
| `r3_tunnel` | `query_length > 100 and entropy > 4.0` (thresholds frozen in the metadata) |
| `r4_deep` | `subdomain_depth > 5` (frozen) |

Validation rules:
- `ml_score_A` is required (`KeyError` if absent) and must be finite and complete (`ValueError` lists the rows).
- `ml_score_B` may be NaN; ±inf raises.
- Rule columns are required (aliases `query_entropy` / `subdomain_count` are accepted).
- Nothing is silently zero-filled.

## 5. Logistic regression methodology

- `LogisticRegression(class_weight=None, C=1, max_iter=5000)`.
- **Class prior.** The validation prior is 54.5% attack, which is far above any real deployment. The FPR threshold makes the *decision* independent of the prior, but the *score* is calibrated to a 54.5% prior.
- **Why no prior correction.** No deployment prevalence has been measured, so applying King & Zeng's correction would be guesswork. The assumption is recorded in the metadata as `class_prior_validation`.
- **Balanced weights** were evaluated as a comparison only (`fusion_v2_balanced`, §10).
- **Fitted coefficients:** `logit_A` 0.771, `score_B` 0.048, `has_score_B` 0.023, `r3_tunnel` 0, `r4_deep` 0; intercept 0.033.
- **Why R3/R4 are 0.** Their columns have zero variance on validation, and L2 regularisation drives a constant column's weight to 0. They carry no evidence on these rows.
- **Collinearity.** On the fit rows, corr(`logit_A`, `score_B`) = 0.963, with VIF 14.1 for each. Above 10 is a usual warning level. This explains the unstable `score_B` coefficient across runs (sd 1.9–2.3, §10).
- **Negative `has_score_B` weight** (V1: −0.74; V2: negative in 80% of runs, mean −0.17 ± 0.18). It was investigated, not clamped:
  - Only 38 validation rows lack a Path B score (19 benign + 19 attack: the first 19 queries of each client), so the weight is weakly identified.
  - It is not leakage: Path B coverage depends only on window position.
  - It is not a transform bug: the sign is the same in V1 and V2.

## 6. Missing-value handling

The raw NaN mask is the missingness indicator, and `score_B` is 0 where it's missing (standard missing-indicator encoding). `train_fusion.py --version 2` attaches `covered` from `score_records`, so uncovered rows are NaN from the start.

## 7. Cross-validation methodology and the 80% → 100% question

- **OOF.** `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)` on `parent_domain`. This is the class-balancing variant of GroupKFold; plain GroupKFold is the fallback if it can't be built.
- **Checks.** The code asserts no parent domain appears on both sides of any fold, and that every row is scored exactly once (tests 14, 15). 0 folds were skipped.
- **Why stratified.** Validation has only **2 attack parent domains** (daumel.xyz with 600 rows, dns2tcp-txt.com with 800). Each fold holding one of them trains on the other, which amounts to leaving one attack domain out.
- **What OOF is used for:** Brier score, the reliability table, ECE and coefficient stability. It is **not** used to set the deployed threshold.
- **Why not threshold on OOF and deploy a 100% refit.** The audit's design calibrates on OOF scores from fold models (each trained on ~80% of the rows) and then deploys a refit on all of them. The threshold then belongs to different models from the one deployed. V2 avoids this: the threshold is set on a benign-only calibration part that the deployed model never saw.
- **Alignment check** (benign score quantiles 0.5 / 0.9 / 0.99 / 0.999):

| | q0.5 | q0.9 | q0.99 | q0.999 |
|---|---|---|---|---|
| OOF benign | 1.9e-5 | 2.9e-5 | 3.0e-5 | 3.0e-5 |
| Deployed model, calibration part | 2.3e-5 | 2.4e-5 | 2.4e-5 | 2.4e-5 |

The two are of the same order. Benign scores are tightly clustered because Path A is exactly 0 on every benign validation row.

## 8. Neyman-Pearson threshold (`thresholds.np_threshold`)

The umbrella algorithm of Tong, Feng & Li (2018), checked independently:
- Sort the n benign calibration scores in ascending order and alarm when `score > s₍ₖ₎` (**strict**).
- The bound is P(population FPR > α) ≤ Σ_{j=k}^{n} C(n,j)(1−α)^j α^{n−j} = P(Binomial(n, 1−α) ≥ k).
- Choose the smallest k with bound ≤ δ (binary search; computed in log space).

Order-statistic convention and comparison direction:
- s₍ₖ₎ is the k-th *smallest* score. The FPR of `score > s₍ₖ₎` exceeds α only if s₍ₖ₎ lies below the (1−α) benign quantile. That requires at least k of the n draws below that quantile, which is exactly the binomial tail above.
- With ties, the strict rule can only lower the realised FPR, so the bound still holds (test `test_np_ties_strict_rule_never_exceeds_budget`).

Minimum sample size:
- k = n is the weakest case, with bound (1−α)ⁿ. So n ≥ ln δ / ln(1−α).
- For α = 0.001 and δ = 0.05 that gives **2,995** (`np_min_samples`, test-pinned).

Verification:
- In a 2,000-trial simulation at α = 0.01, δ = 0.05, n = 1,000 (uniform benign scores, so the FPR is known exactly), the bound was violated in **2.6%** of trials, within δ = 5%.
- The bound matches an exact `math.comb` evaluation, and k = n matches the closed form.

Preconditions, stated in the docstring:
- the calibration rows were not used to fit the scorer;
- they are exchangeable with deployment benign traffic;
- **the guarantee says nothing about drift.**

**On this data:** the calibration part has 599 benign rows against the 2,995 needed. `InsufficientCalibrationError` is raised, logged, and the trainer falls back to the empirical rule. The metadata records `threshold_method = "empirical_fallback_gap_midpoint"`, `n_cal_benign = 599`, `n_required_for_np = 2995`. **No FPR guarantee is claimed.**

**The empirical fallback** is `threshold_for_fpr`, the project's existing budget rule:
- It places t midway between the budget quantile of benign scores and the lowest attack score above it.
- The calibration part is benign-only, so the attack edge comes from the deployed model's scores on the fit part's attacks (in-sample, documented).
- Why the midpoint matters here: benign calibration scores sit at about 2.4e-5. A threshold "just above the benign maximum" would flag any new benign row with a non-zero Path A score, and 46 benign test rows have one. The fitted threshold is 0.500.

## 9. Calibration methodology

On grouped OOF validation scores: Brier 6.6e-10, ECE 2.5e-5. **That does not show the score is a probability.**
- The validation rows are perfectly separable through Path A.
- On the test split, scores fall in the 0.5–0.8 band for 22 benign rows whose true attack share is 0 (10-bin table in `results.json → reference_run → fusion_v2 → test_reliability`).

So the output is always named `fusion_score`. The metadata keeps only the flag `oof_ece_below_0_05`, which is not a calibration claim. A low FPR is not the same as good calibration, and neither is shown on the drifting test period.

## 10. Evaluation methodology (`scripts/eval_fusion.py`)

**Leakage control.**
- Path A and Path B were trained once, on the time_seed42 train rows.
- Only that manifest's validation and test rows were used: 5,138 rows, 2,800 attack / 2,338 benign, base rate 54.5%, 2 attack parent domains, 47 benign parent domains, Path B coverage 99.3%.
- Other manifests' test sets contain Path A/B training rows, so they were not used.

**Splits.**
- The pool is re-split with the project's own `splits.build_indices` for {capture_group, parent_domain_group, time} × seeds 42–46.
- Fusion models are refitted on each run's train+val part and scored once on its test part.
- Thresholds are never tuned on a test part (test `test_threshold_ignores_held_out_test_labels` flips every test label and asserts identical models).

**What the 15 runs actually are.**
- On this pool, `capture_group` (3 source files) and `parent_domain_group` (2 attack domains) cannot keep both classes in every fold, so `grouped_split` falls back to **random row splits**. The two strategies produce **identical** rows for each seed. The 5 duplicates are detected and excluded.
- The time split is deterministic. Its 5 seeds differ only in V2's internal fit/calibration split.
- So: **10 distinct evaluable runs** (5 random-row + 5 time).
- **Random-row splits mix the validation and test time periods.** That lets the fusion see test-period benign traffic during fitting, so these runs are optimistic about drift. The honest drift test is the **reference run**: fusion fitted on validation, scored once on the manifest's test rows.

### 10.1 Reference run (manifest val → test; 1,169 benign / 1,400 attack)

| Method | Recall | FPR (95% Wilson CI) | False alarms | Alarms / 10k benign | Precision | F1 | PR-AUC | Brier |
|---|---|---|---|---|---|---|---|---|
| Path A | 1.000 | 2.65% (1.87–3.74) | 31 | 265.2 | 0.978 | 0.989 | 0.9936 | 0.0076 |
| Path B | 1.000 | 5.47% (4.31–6.93) | 64 | 547.5 | 0.956 | 0.978 | 1.0000 | n/a* |
| OR rule | 1.000 | 7.10% (5.76–8.72) | 83 | 710.0 | 0.944 | 0.971 | 0.9936† | n/a |
| Fusion V1 | 1.000 | 2.65% (1.87–3.74) | 31 | 265.2 | 0.978 | 0.989 | 1.0000 | 0.0095 |
| **Fusion V2** | 1.000 | 2.65% (1.87–3.74) | 31 | 265.2 | 0.978 | 0.989 | 1.0000 | **0.0074** |
| V2, balanced weights | 1.000 | 2.40% (1.66–3.44) | 28 | 239.5 | 0.980 | 0.990 | 1.0000 | 0.0072 |

\* Path B's sigmoid(z) is not a probability, so no Brier score is given. † The OR rule is ranked by the legacy blend.

Confusion for V1 and V2: TP 1,400, FP 31, TN 1,138, FN 0.

**Every method misses the 0.1% budget by more than 20×.** The test benign traffic comes from a later period than validation, and no threshold rule fixes that kind of shift.

### 10.2 Resampled runs (pool; mean over runs)

| Split (runs) | Method | FPR | Recall | Alarms / 10k | Brier |
|---|---|---|---|---|---|
| random rows (5) | Path A | 1.65% | 1.000 | 165.2 | 0.0043 |
| | Path B | 2.51% | 0.994 | 250.7 | — |
| | OR | 3.70% | 1.000 | 370.4 | — |
| | V1 | 0.00% | 0.994 | 0.0 | 0.0042 |
| | V2 | 0.11% | 1.000 | 11.4 | 0.0017 |
| time (5) | all methods | 0.00% | 1.000 | 0.0 | ≤ 0.0001 |

Per-run V2 false alarms, random rows: 0, 0, 0, 0, 2 (of 351 benign). V1: 0 in all five runs, but it misses 1–4 attacks per run.

**Coefficient stability (V2, 10 runs):**

| Input | Mean | sd | Share negative |
|---|---|---|---|
| `logit_A` | 0.68–0.76 | 0.34–0.38 | 0 |
| `score_B` | 2.57–2.88 | 1.9–2.3 | 0 |
| `has_score_B` | −0.16 to −0.17 | 0.17–0.18 | 0.8 |
| R3 / R4 | 0 | 0 | — |

V1 by comparison: `ml_score_A` 9.4–9.5 (sd 0.05); `has_score_B` −0.94 to −1.07 (always negative).

## 11. Test results

- `pytest tests/ -q`: **196 passed, 0 failed.** That breaks down as 112 pre-existing tests, 44 new in `tests/test_stacker.py`, and 40 new in `tests/test_bridge.py`.
- `tests/test_stacker.py` covers the 20 required tests, plus:
  - the exact binomial tail and closed form;
  - the 2,995 minimum;
  - parameter validation;
  - ±inf / NaN / text inputs;
  - aliases;
  - V1 builder unchanged;
  - refusal to overwrite V1;
  - the Neyman-Pearson path when there are enough rows;
  - the strict alarm rule.
- The baseline before any change was 112 passed.

## 12. Compatibility and model protection

- V1 loads through `load_versioned(1)`, and its predictions are identical to `stacker.predict` (`eval_fusion.compat_check`: `v1_identical = true`).
- The V2 schema validates. Unknown versions, a missing key or a wrong schema raise `FusionSchemaError`.
- SHA-256 hashes before and after are identical for every Path A artefact (`dns_tunnel_rf.pkl`, `dns_tunnel_gbt.pkl`, `dns_scaler.pkl`, `dns_threshold.json`, `bigram_table.json`, `dns_tunnel_transformer.keras`), every Path B artefact (`dns_trafficformer.h5`, `_norm.json`, `_threshold.json`), and V1 (`fusion_lr.pkl`, `fusion_lr.json`).
- Source files `path_a.py`, `path_b_predict.py`, `path_b_train.py`, `dns_parser.py`, `splits.py`, `features/*` and `detection/engine.py` are also identical.
- New files: `fusion_lr_v2.pkl`, `fusion_lr_v2.json`, `fusion_fallback_quantiles.json`, `fusion_lr_tiers.json`.
- `evaluation_metrics.json` only gained the key `fusion_v2`; all other keys are byte-equal.
- Reproducibility: re-running `eval_fusion.py` gives identical per-run results and an identical gate.

## 13. Limitations

1. **The Neyman-Pearson guarantee is unavailable**: 599 benign calibration rows against the 2,995 needed. Collecting more benign data is the only way to get it.
2. **Distribution shift.** The validation and test periods differ, and every method's test FPR is about 26× the budget. Neither V2 nor the Neyman-Pearson guarantee addresses this.
3. **Ceiling effect.** Recall is 1.0 almost everywhere, and test attacks are a single family (dnsexfiltrator). PR-AUC ties at 1.0, so these splits can't separate the methods.
4. **The validation rows are not fresh for the base models.** Path A uses them for isotonic calibration and its threshold; Path B for its 99th-percentile threshold. Their scores there are optimistic, and the fusion inherits that.
5. **Leakage cannot be fully ruled out.** Path A's training row ids weren't saved, and `dns_threshold.json` records dataset_version `7eeea4…` while the manifest says `88a5f2…`.
6. **Grouped splits degenerate on this pool** (random-row fallback), and random rows mix time periods.
7. **The Path B recomputation differs from the stored metrics.** Under Keras 3 with the legacy `.h5` rebuild, the test false alarms come out as 64, while `evaluation_metrics.json` stores 71 from the original environment. V1 / Path A are unaffected (31 in both).
8. **R3/R4 carry no evidence** in the pool, and Path A/B are strongly collinear (VIF 14).

## 14. Promotion decision

Gate over 10 distinct runs (exact counts; 10 runs are no statistical guarantee):

| Criterion | Result | Detail |
|---|---|---|
| 1. FPR ≤ 0.1% in ≥ 95% of runs | **FAIL** | 9 / 10, and the reference run (not in the count) is at 2.65% |
| 2. Recall ≥ V1 − 0.01 | pass | 10 / 10 (V2 mean 1.000, V1 0.997) |
| 3. PR-AUC > best single path | **FAIL** | 4 / 10; ties at 1.0 (ceiling) |
| 4. Alarms / 10k below OR | pass | 5 / 10 strictly lower; the other 5 tie at 0 (means 5.7 vs 185) |
| 5. Brier below V1 | pass | 10 / 10 (0.0009 vs 0.0022); also 0.0074 vs 0.0095 on the reference run |
| 6. Backward compatibility | pass | V1 identical, V2 schema valid, 196 tests |

**V2 stays experimental.** It can be selected with `ensemble.fusion: lr_v2`, and V1 remains the default. V2 matches V1's decisions on the honest test, improves the Brier score, and fixes the structural flaws in §2. It does not reduce false alarms under drift, and it can't claim the Neyman-Pearson guarantee.

Evidence needed before promotion:
- ≥ 2,995 benign calibration rows from the deployment period (unlocks the Neyman-Pearson threshold);
- a test split with more than one attack family, and one where the methods don't all hit recall 1.0;
- a re-run of the gate on those.

## 15. Implemented vs proposed

**Implemented:**
- V2 inputs, validation and frozen spec;
- versioned artefacts and loader;
- the grouped benign-only calibration part;
- grouped OOF diagnostics;
- the Neyman-Pearson threshold with the empirical fallback;
- tier cut points;
- `eval_fusion.py` with duplicate detection and the gate;
- the label-provenance guard.

**Proposed, not implemented:**
- collect more benign calibration data;
- a drift-aware recalibration step (recalibrate the threshold on recent benign traffic);
- drop or regularise one of the collinear Path A/B inputs;
- monotonic constraints, but only if justified after more data. Negative weights were not clamped.
