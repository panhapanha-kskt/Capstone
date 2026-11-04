# Bridge V2 (`fusion/bridge.py`) — implementation report

Branch `feat/fusion-v2`. All numbers come from runs of this branch:
- `python -m dns_detect.fusion.bridge` on `data/processed/merged_features_labeled.json` (18,353 rows);
- `scripts/eval_bridge.py --cli-ablation`, output in `outputs/bridge_eval/results.json`;
- the unchanged Week-4 engine, `python -m dns_detect.detection.engine`;
- `pytest tests/`.

Fusion V2 itself is described in `STACKER_V2_IMPLEMENTATION_REPORT.md`.

**Decision:** the bridge reliability changes are in. Learned fusion V1 (`ensemble.fusion: lr`) is confirmed as the default decision path, and Fusion V2 is not promoted. See §15.

> **Source document.** The "supplied audit" Markdown was not attached and is not in the repository. Its issue IDs (H1, H2, M5, B10) and "references 13–15" are taken from the task text. `docs/research/REFERENCES.md` is not numbered, so the new references were added as a named section (§ "Fusion and bridge") instead.

## 1. Original architecture

```
records → load_as_dataframe → Path A score_frame ──────┐
records → Path B score_records (positional) ───────────┤ merge_ml_scores: OR label, max-blend score,
                                                       │ optional LR (fusion: lr), allowlist,
                                                       │ fixed tiers 0.8/0.5/0.3
ensure_week4_compatible: ml_threat_score = 0.4·attack_count/6 + 0.35·A + 0.25·B
Week-3 columns copied back only "if len(week3_df) == len(df_merged)"
```

## 2. Issues identified (verified against the code)

| ID | Issue | Finding |
|---|---|---|
| H1 | Missing Path A model | `run_bridge` caught `FileNotFoundError` and wrote `ml_score_A = 0`, `ml_label_A = 0` for every record: an unavailable detector looked like a quiet network. |
| H2 | Path B coverage | `score_records` returns `covered`, but `run_path_b` dropped it. Uncovered records got score 0 and label 0; `--no-path-b` and "model missing" also wrote zeros. |
| M5 | Positional joins | Path A / Path B / Week-3 columns were matched by position. Week-3 columns were silently skipped if the lengths differed. Today's parser never drops or reorders rows (checked), so alignment was correct but unguarded. |
| — | Missing features | The parser zero-fills absent `FEATURES_8` columns, so a missing input was invisible. |
| — | Two scores | `ml_combined_score` (LR or max-blend) and a second hand-weighted `ml_threat_score` fed Week 4 separately. |
| — | `ml_combined_label_thr` | Compared the max-blend with Path A's own threshold. Nothing in the repository reads it. |
| — | Tiers | The fixed 0.8/0.5/0.3 cut points aren't tied to any calibrated quantity. |
| — | Labels | `--label-only` labelled every unlabeled record `attack_count ≥ 1`. On the labelled data that rule fires on **528 of 8,353 benign rows (6.32%)** and misses 566 of 10,000 attacks. The trained models were **not** affected: all 18,353 training rows are `label_source = provenance` (file-level ground truth), and no pipeline script calls `--label-only`. |
| — | Label laundering | `ingest/labeling.label_records` re-tagged any untrusted `label_source` (e.g. `weak_behavioral`) as `file`, which is trusted, when relabelling a labelled file. |
| — | `attack_type_id` | Taken from whichever name came first in `attack_signature`. |
| — | Cleanup | Unused `from tensorflow import keras`; `run_path_b`'s docstring sat after a statement. |

## 3. New bridge architecture

```
records ─ row_id = file position ─ check_features(raw)  (before the parser's zero-fill)
   │
   ├─ Path A run_path_a ──────── join_on_row_id ──┐  missing model: production → ModelUnavailableError
   │                                              │                 dev + --allow-missing-path-a → degraded
   ├─ Path B run_path_b ── check_path_b_alignment ─┤  uncovered → NaN, has_score_B = 0
   │        (positional API: length + client_ip order verified, then joined by row_id)
   ▼
merge_ml_scores ── one decision ──────────────────────────────────────────────
   fusion: lr / lr_v2  → stacker.load_versioned → predict_versioned        fusion_method = lr
   model missing       → production raise | dev: OR + benign-quantile score fusion_method = or_fallback
   fusion: or          → explicit OR (status or_configured)                fusion_method = or_fallback
   no Path A score     → NaN score, UNSCORED, "ml_unscored"                fusion_method = degraded
   comparison: ml_combined_label_or, ml_combined_score_legacy (always)
   tiers: HIGH = alarm | MEDIUM ≥ benign q99 | LOW ≥ q90 | CLEAN | UNSCORED
   allowlist: alarm suppressed, score kept
ensure_week4_compatible: ml_threat_score = ml_combined_score (0 if suppressed); legacy kept
Week-3 columns joined back by row_id; JSON with null (never NaN) + <output>.meta.json
```

The mode comes from `ensemble.bridge_mode`, which defaults to `production`, or from the `--dev` flag.

## 4. Path A and Path B integration

- **Path A** is `path_a.score_frame`, unchanged. `run_path_a` raises `ModelUnavailableError` when `dns_tunnel_rf.pkl` or `dns_scaler.pkl` is missing.
- **Path B** is `path_b_predict.score_records`, unchanged and imported lazily, so TensorFlow loads only when Path B runs. `run_path_b` returns `(score, label, covered)` with NaN off-window. A missing Path B model is allowed, because Path B is optional by design. It is logged, and its scores stay NaN.

Verified on the 18,353 rows: **Path A scores are identical row by row** to the pre-change bridge, and **Path B scores are identical on all 18,220 covered rows**.

## 5. Missing-value handling

- NaN Path B scores = 133 = the uncovered records (the first 19 queries of each of 7 clients).
- The old output had 0.0 on exactly those 133 rows.
- `has_score_B` is 1/0, and a real 0.0 stays distinguishable from a missing score (tests H2).
- `--no-path-b` gives all-NaN.
- **Output JSON uses `null`.** It is written with `json.dump(..., allow_nan=False)` after converting NaN/inf to `None`.

## 6. Record identity and joining

- `row_id` = position in the input file, assigned once.
- `join_on_row_id` raises `AlignmentError` on missing, duplicate or unmatched ids, or on records without scores, and merges with `validate="one_to_one"`.
- Path B's positional output is checked first for length and per-row `client_ip` order, re-read with the parser's `load_multifeature_with_meta`.
- The output is sorted by `row_id`, so the original order is preserved.

## 7. Fusion decision workflow

- Exactly one decision: the stacker's, when its artefact exists. `--weight-a` / `--weight-b` now only shape `ml_combined_score_legacy` and emit a `DeprecationWarning`; the dashboard still passes them and sees the warning.
- **V1 output is unchanged.** On the 18,353 rows the fused score and label are identical to the old bridge: 10,028 alarms before the allowlist, 10,007 after, and 21 suppressed. The OR label (10,099) and both legacy formulas also reproduce exactly.
- The summary and `.meta.json` report the count per `fusion_method` / `fusion_status` (here `{"lr": 18353}`).

**Fallback score (development only):**
- `q = searchsorted(benign_sorted, s, side="right") / n`, using the frozen benign *validation* distributions in `models/fusion_fallback_quantiles.json`: Path A 1,169 values, Path B 1,150.
- The fused fallback score is `max(qA, qB)`, or `qA` alone when Path B is missing. Scores above the observed range give 1. An empty or missing artefact gives a NaN score and `UNSCORED`.
- **Limitation:** Path A is exactly 0 on every benign validation row, so `qA` is 1.0 for any non-zero Path A score. The fallback score therefore resolves alarm volume poorly. It is a degraded mode and is marked as one, not presented as equivalent to LR.

## 8. Confidence tier methodology

**Cut points** come from benign scores of the deployed fusion model on rows it was not fitted on:
- **V2:** benign calibration-part scores of the deployed model (599 rows; `tier_boundaries` in the metadata). These are out-of-sample for that exact model, which is what out-of-fold scores are meant to approximate.
- **V1:** sidecar `models/fusion_lr_tiers.json` (q90 0.0143, q99 0.0213, HIGH 0.4875). V1 was fitted on those rows, so these are in-sample, labelled `tier_source: v1_in_sample_val`.
- **No source:** the legacy cut points, with `confidence_method = legacy_fixed`.

**Assignment rules:**
- HIGH ⇔ the fused alarm, using the same comparison as the label.
- Boundaries are forced monotone (q90 ≤ q99 ≤ threshold). Tied quantiles collapse a band. Fewer than 100 benign rows means q99 isn't estimated.
- **Missing or degraded scores are `UNSCORED`, never CLEAN.**

**Expected vs observed benign volume** (test rows, 1,169 benign, per 10,000 benign):

| Tier | By design | V1 observed | V2 observed |
|---|---|---|---|
| HIGH | ≤ 10 | 265.2 | 265.2 |
| MEDIUM | ≈ 90 | 641.6 | 154.0 |
| LOW | ≈ 900 | 1,394.4 | 1,248.9 |
| CLEAN | ≈ 9,000 | 7,698.9 | 8,331.9 |

The gap is the validation→test shift described in the Stacker report, §10.1: test-period benign traffic scores higher than validation benign traffic. The tiers are alarm-volume bands, not attack probabilities. V2's cut points sit closer to the design volumes for MEDIUM, LOW and CLEAN.

Full run (18,353 rows, V1): HIGH 10,028 · MEDIUM 98 · LOW 290 · CLEAN 7,937 · UNSCORED 0. Before the change: HIGH 10,020 · MEDIUM 8 · LOW 2 · CLEAN 8,323.

## 9. Label provenance

- The existing vocabulary is kept: `file`, `provenance` and `manifest` are trusted; `weak_behavioral`, `abstain` and the new **`heuristic`** are not.
- Renaming to the audit's {manifest, heuristic} would have broken `labeling.py` and Path A's existing trust filter.
- **`--label-only`:**
  - keeps trusted labels;
  - **refuses** records without a trusted label;
  - with `--allow-heuristic-labels` (only then) uses `attack_count ≥ 1`, tags those rows `heuristic`, and warns with the count and percentage.
- **Training guard.** `ingest/labeling.validate_training_labels` is called from `scripts/train_models.sh`, `scripts/train_fusion.py` and `scripts/run_multiseed.py`. It refuses untrusted labels unless `--allow-heuristic-labels` is given, and the fusion metadata records the provenance counts. The current training data passes: 18,353 `provenance`, 0 untrusted.
  - **Known gap:** calling `python -m dns_detect.models.path_a --train` directly bypasses the guard, because Path A/B source was kept unchanged on purpose. `path_a.py` already drops `weak_behavioral` rows itself.
- **Laundering fix.** `label_records` now keeps `weak_behavioral` / `heuristic` as-is when relabelling.
- **`attack_type_id`** uses an explicit priority, most severe first: CACHE_POISONING > ENCODING > HIGH_ENTROPY > RANDOM_SUBDOMAIN > NXDOMAIN_FLOOD > AMPLIFICATION. There are also multi-hot `attack_type_<NAME>` columns, and the ID map is unchanged.
- **Weak supervision / cleanlab.**
  - `labeling.py` already implements Snorkel-style labelling functions (agreement of `min_attack_votes`), and Path A excludes their output.
  - A Snorkel label model over the six Week-3 flags was not added: those flags are the `attack_count` rule whose 6.32% benign false-alarm rate motivated this change, so their errors are correlated, which violates the label model's independence assumption.
  - cleanlab is a sensible next step as a label-quality *audit* on the provenance-labelled rows. It wasn't added, to avoid a new dependency, and its output wouldn't prove a label wrong.

## 10. Week-4 compatibility

- **Required columns present:** `ml_combined_score`, `ml_combined_label`, `ml_confidence`, `ml_threat_score`.
- **Comparison columns:** `ml_combined_label_or`, `ml_combined_score_legacy`, `ml_threat_score_legacy`.
- **New columns:** `row_id`, `has_score_B`, `fusion_method`, `fusion_status`, `confidence_method`.
- **Removed:** `ml_combined_label_thr`. Nothing read it.

**The unchanged engine runs on both outputs** (`detection/engine.py`, hash identical):

| | Old bridge output | New bridge output |
|---|---|---|
| Exit code | 0 | 0 |
| Total alerts | 1,388 | 1,388 |
| Rule 5 ML-flagged | 10,007 | 10,007 |
| Rule 6 additional | 0 | 0 (9,999 deduplicated against Rule 5) |

- **Rule 6 behaviour change.** With `ml_threat_score = ml_combined_score`, Rule 6 (≥ 0.7 on rows the fused label didn't flag) can only fire between 0.7 and the alarm threshold. With V1's threshold of 0.4875 that range is empty, so Rule 6 effectively goes quiet. It also produced 0 alerts on the old output.
- **Allowlist hole closed.** Allowlisted alarms now get `ml_threat_score = 0`, so Rule 6 can't re-raise them; the score stays in `ml_combined_score` for audit.
- **NaN in alerts.** The engine copies `ml_score_B` into alert details with `float(row.get(...))`, which turns `null` into NaN, and its own `json.dump` writes a bare `NaN` token: 9 occurrences in the new alerts file, 0 before. Python reads that fine, but a browser's `JSON.parse` does not.
  - **The dashboard (`dashboard/server.py`) now converts NaN/inf to `null`** before serving `/api/state` (`_finite`, `allow_nan=False`). The engine is unchanged.
- **`monitoring.monitor`** reads the new output fine: exit 0, NaN scores dropped. Its drift warning compares live data with the training statistics and is unrelated to this change.

## 11. Evaluation methodology (`scripts/eval_bridge.py`)

- **Rows:** time_seed42 **test** rows (2,569 = 1,400 attack / 1,169 benign), all `provenance` labels, so independent and none heuristic. Path B coverage is 100%.
- **Method:** all four methods go through `merge_ml_scores`, the production code path, with **the detection allowlist applied to every method's decision.** Without that, the OR column would be measured before suppression and the comparison would be unfair.
- **Per-split / per-seed figures** for the learned methods come from `eval_fusion.py` (10 distinct runs; Stacker report §10.2).
- **Legacy max-blend threshold:** Path A's own threshold (0.5), i.e. the old `_thr` rule.

## 12. Before-and-after metrics (test rows, allowlist applied)

| Method | Recall | FPR | Alarms / 10k benign | Precision | F1 | PR-AUC |
|---|---|---|---|---|---|---|
| OR gate | 1.000 | 3.94% | 393.5 | 0.968 | 0.984 | 0.9936 |
| OR gate, no allowlist (reference) | 1.000 | 7.10% | 710.0 | 0.944 | 0.971 | 0.9936 |
| Legacy max-blend | 1.000 | 1.11% | 111.2 | 0.991 | 0.995 | 0.9936 |
| **LR fusion V1 (default)** | 1.000 | 0.86% | 85.5 | 0.993 | 0.996 | 1.0000 |
| LR fusion V2 | 1.000 | 0.86% | 85.5 | 0.993 | 0.996 | 1.0000 |

Share of non-LR records for V1 and V2: 0.

**Ablations:**

| Case | Result |
|---|---|
| Path A removed, `merge_ml_scores` in production | raises `ModelUnavailableError` |
| Path A removed, development | 2,569 / 2,569 degraded, 0 silently benign, all UNSCORED |
| Path A removed, **bridge CLI** (temp models dir without `dns_tunnel_rf.pkl`), production | exit code 1, no output file |
| Same, `--dev --allow-missing-path-a` | exit 0, 18,353 / 18,353 degraded, 0 silently benign |
| Path B removed | 2,569 / 2,569 Path B NaN; V1 recall 1.000, FPR 0.17% (2 false alarms) |

Without Path B, V1 has fewer false alarms on this test period: 2 instead of 10. That fits Path B's 5.5% test FPR (Stacker report §10.1) and is worth investigating, but a single split doesn't justify a change.

**Data integrity (full file):** 18,353 rows; Path B uncovered 133; Path A missing 0; alignment errors 0; heuristic labels 0; trusted labels 18,353 (`provenance`); degraded records 0.

## 13. Test results

- `pytest tests/ -q`: **196 passed, 0 failed.** The baseline before any change was 112 passed.
- `tests/test_bridge.py` has 40 tests, with Path A/B stubbed so they run without TensorFlow or models:
  - fail-closed and degraded propagation;
  - the 25-record / window-20 coverage case (records 1–19 NaN, a real 0.0 kept);
  - shuffled, duplicate, missing and unmatched `row_id`;
  - the Path B order check;
  - fusion method in production vs development, V2 mode, invalid settings;
  - tier monotonicity, ties and UNSCORED;
  - V1 sidecar tiers, the fallback quantiles;
  - threat score and legacy formulas;
  - the allowlist → threat score fix;
  - the CLI weights deprecation;
  - feature validation, the dev-only fill and its record;
  - label provenance, the training guard, the laundering fix, the attack-type priority;
  - Week-4 columns, **the unchanged engine run as a subprocess on bridge output**;
  - determinism.
- **Two existing assertions were updated** in `tests/test_thresholds_fusion.py`, because the spec deliberately changes that behaviour:
  1. Missing fusion model with `fusion: lr`: production now raises, so the test runs development mode and checks `fusion_method == or_fallback`. `ml_combined_label_or` is now always present (it used to be absent there).
  2. Allowlist test: in OR mode `ml_combined_score` is now the benign-quantile score, not raw Path A. The test now checks the score is unchanged by suppression, and that `ml_combined_score_legacy` is 0.95.

## 14. Remaining limitations

1. **Production mode is the default.** A fresh clone has no `models/fusion_lr.pkl` (gitignored), so `run_pipeline.sh` and the dashboard stop with a clear error until fusion is trained, or `--dev` is passed / `bridge_mode: development` is set.
2. **The label guard can be bypassed** by calling Path A/B training modules directly.
3. **`row_id` is position-based**, because Path B's API is positional. The order check uses `client_ip`. Two records with the same client swapped would pass, but the parser has no code path that reorders rows.
4. **V1's tier cut points are in-sample.**
5. **The fallback score's Path A quantile is coarse** (§7).
6. **The engine writes NaN into alert JSON** for records without a Path B window. The dashboard cleans it; other alert consumers must accept NaN or treat `ml_score_B` as optional.
7. **Week-4 Rule 6 is effectively silent** under learned fusion (§10).

## 15. Final promotion decision

`eval_bridge.py` gate:

| Criterion | Result |
|---|---|
| 1. LR alarms / 10k below the OR gate | pass (85.5 vs 393.5) |
| 2. LR recall within 0.02 of OR | pass (1.000 vs 1.000) |
| 3. Independent labels | pass (0 untrusted of 2,569) |
| 4. Reproducible | pass (identical scores on re-run; `eval_fusion` re-run identical) |
| 5. Production failure behaviour | pass (all ablations above) |
| 6. Fusion V2 statistical gate | **fail** (Stacker report §14) |

- **Bridge V2 changes:** in place. The fail-closed behaviour, coverage, `row_id`, single decision, tiers, single threat score, label provenance and Week-4 compatibility are verified.
- **Learned fusion V1 is confirmed as the default decision** (`ensemble.fusion: lr`, criteria 1–5).
- **Fusion V2 stays experimental** (`lr_v2`).
- **Still pending for a production promotion of the branch:** review of the draft PR; a decision on the production-mode default for demos (limitation 1); and the evidence listed in the Stacker report §14 for V2.

## 16. Remaining work

- Collect deployment-period benign data: it is needed for the Neyman-Pearson threshold and to measure drift.
- Add a drift-aware threshold recalibration.
- A label-quality audit with confident learning (cleanlab) on the provenance-labelled rows.
- Decide Week 4 Rule 6's future, since the single threat score makes it redundant with Rule 5.
- Investigate Path B's test-period false alarms (§12, Path B ablation).
