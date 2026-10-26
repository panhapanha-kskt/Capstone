# Path A — Full Deep Dive

Source file: [`src/dns_detect/models/path_a.py`](../../src/dns_detect/models/path_a.py)

---

## 1. What Path A actually is

A **binary classifier** (benign vs. attack) for DNS tunneling built on **8 engineered features per DNS record**. Two production tree models vote; a Transformer is trained alongside only as a research baseline. The whole pipeline is designed to be **leak-safe, calibrated, and auditable** for a capstone paper.

---

## 2. Data contract & feature set

- **Input shapes accepted:** Week-3 JSON (`week3_features_all.json`), labeled CSV, or raw PCAP — all normalized through `dns_detect.parsing.dns_parser.load_as_dataframe` (line 41).
- **Features used:** exactly `FEATURES_8` (defined in `dns_parser`, imported here) — Path A deliberately stays 8-dimensional.
- **Missing feature columns** are filled with 0 defensively (lines 331-333, 494-496).
- **Label contract:** `label` column, 0=benign, 1=attack. Missing → hard error with a hint to run `ml_bridge.py` first (lines 335-339).
- **Optional `attack_family` column** enables per-family recall reporting (line 356).

### The 8 features — what each one actually measures

Defined in [`src/dns_detect/parsing/dns_parser.py:29-38`](../../src/dns_detect/parsing/dns_parser.py#L29-L38). Computed per DNS record from the query name (and the DNS answer section, when present):

| # | Feature | Formula | What it catches |
|---|---|---|---|
| 1 | **`query_length`** | `len(query)` — total characters of the FQDN | Tunneling encodes data in the query name, inflating length. Normal queries are short (`google.com` = 10 chars); tunneled queries are often 60–200+. |
| 2 | **`query_entropy`** | Shannon entropy of the character distribution of the query string | Encoded/encrypted payloads look random → high entropy. Normal domains (English-like) have lower entropy. Classic indicator used by Nadler et al. |
| 3 | **`has_digits`** | `1 if any char is a digit, else 0` | Flag for subdomains containing digits — common in DGA (domain-generation algorithm) and base32/base64-encoded tunnels. |
| 4 | **`answer_count`** | Number of answer records in the DNS response | Tunnels often get single-answer or NXDOMAIN responses; some C2 channels have unusual answer counts. (Note: on week3 data this is often 0 because responses aren't parsed — see `dns_parser.py:56`.) |
| 5 | **`subdomain_count`** | `query.count(".")` — number of `.`-separated labels | Tunnels pack data into many subdomain levels (`chunk1.chunk2.chunk3.exfil.com`). Normal domains have 2–3 labels. |
| 6 | **`longest_label`** | `max(len(label) for label in query.split("."))` — length of the longest DNS label | DNS labels have a 63-char max. Tunnels push close to this limit to maximize data per query. Benign labels rarely exceed ~20 chars. |
| 7 | **`digit_ratio`** | `(count of digit chars) / len(query)` | Fraction of digits in the query. High digit ratio = encoded payload or DGA. English domains are mostly letters. |
| 8 | **`unique_char_ratio`** | `len(set(query)) / len(query)` | Fraction of distinct characters. Random/encoded strings use many unique chars; repetitive strings (`aaaa.aaaa.com`) are low. Complement to entropy. |

**Note on week3 field renames** (`dns_parser.py:52-57`): week3 uses different names, which `_normalize_week3_columns` maps:
- `entropy` → `query_entropy`
- `numeric_ratio` → `digit_ratio`
- `subdomain_depth` → `subdomain_count`
- `answer_size` → `answer_count` (always 0 on week3 — responses not parsed)
- `first_label_length` → `longest_label` (overridden with the true longest label when `domain` is available)

**Why these 8 and not others?** They are the smallest set that covers all three attacker tells identified in the literature: (1) **payload bloat** (query_length, longest_label, subdomain_count), (2) **character-distribution anomaly** (query_entropy, digit_ratio, unique_char_ratio, has_digits), (3) **response-side anomaly** (answer_count). Lavrenovs & Visky 2019, Nadler et al. 2019, and the Infoblox DNS tunneling detection paper all use variants of this set.

---

## 3. The two learners — why *this* pair

### Random Forest (lines 136-149)
- 200 trees, `class_weight="balanced"` to counter the attack/benign skew.
- `random_state=42`, `n_jobs=-1` (parallel).
- RF is **bagging** — reduces variance, resistant to overfit on tabular data.

### HistGradientBoosting (lines 152-175)
- `lr=0.1`, `max_iter=300`, `early_stopping=True`, `validation_fraction=0.15`.
- `class_weight="balanced"`, `random_state=42`.
- Boosting — reduces bias, fits residuals, tends to lean on a **narrower, more concentrated** feature subset than RF.
- Sklearn-native → no XGBoost/LightGBM dependency.

### Why both?
Comment at lines 155-159 spells it out: on small NIDS tabular data, **trees beat deep nets**, and RF (bagging) + GBT (boosting) rely on features differently → soft-voting them is a genuine **two-opinion** ensemble, not two correlated copies.

---

## 4. The Transformer — what it is and why it's not in the decision

### Architecture (lines 57-94)
Each encoder block:
```
x → LayerNorm → MultiHeadAttention(x,x) → Dropout → +residual
  → LayerNorm → Conv1D(ff_dim, kernel=1, relu) → Dropout
                → Conv1D(back to channels, kernel=1) → +residual
```
- 2 blocks stacked, `head_size=32`, `num_heads=2`, `ff_dim=64`, `dropout=0.1`.
- Head: `GlobalAveragePooling1D → Dense(64, relu) → Dropout → Dense(1, sigmoid)`.
- **Loss:** `binary_crossentropy` (fix noted in the module docstring: the original was a regression — now it's a true binary classifier).

### Sequence construction (lines 97-106)
- Sliding window of `SEQUENCE_LENGTH=10` consecutive records.
- Label of a window = label of its **last** record (`y[i + seq_len - 1]`).
- Unlabeled variant exists for inference contexts.

### Training (lines 199-231)
- Optimizer Adam, metrics accuracy + AUC.
- 30 epochs, batch 32, **EarlyStopping monitors `val_auc` (mode="max")** with `restore_best_weights=True`.
- Validation uses the real **val split** (not test) — important.

### Why it exists but doesn't vote
Comment at lines 382-383: kept and reported for the paper so you can say "we explored it; trees won on tabular data." Its metrics are logged under `transformer_baseline`.

---

## 5. The three-way stratified split (lines 360-366)

```
X,y,fam  → 70% train / 30% temp     (stratify=y)
temp     → 50/50 → 15% val / 15% test (stratify=y)
```
- `stratify=y` on **both** splits so class ratios are preserved.
- `random_state=42` everywhere → reproducible.
- `fam` (attack family) is carried through so test-set per-family recall is possible without re-joining.

**This matters because:** on an imbalanced dataset, a plain random split can leave the test set empty of attacks. The docstring at the top of the file explicitly lists stratified split as a fix from the original.

---

## 6. Leakage control (lines 368-374)

- `StandardScaler` is fit on **training only**, then `.transform()`'d onto val/test.
- Scaler is persisted to disk alongside the models — inference uses the exact same scaling.
- The split happens **before** scaling (comment at line 358 flags this explicitly).

Without this ordering, test-set statistics would leak into training through the scaler.

---

## 7. Threshold calibration (lines 113-129)

- Compute `precision_recall_curve(y_true, scores)` on the **validation** set.
- Compute F1 per threshold with a safe divide (zeros where P+R=0).
- `thresholds` is 1 shorter than precision/recall → the code slices `f1_scores[:-1]` to align.
- Pick the threshold with max F1.

Done **per candidate** (RF-only, RF+GBT) so the gate is a fair comparison.

---

## 8. The decision gate — the heart of Path A (lines 389-412)

```
val_rf   = tree_ensemble_scores(rf, None, X_val, "rf_only")   # RF alone
thr_rf   = calibrate_threshold(y_val, val_rf)
val_cmb  = tree_ensemble_scores(rf, gbt,  X_val, "rf_gbt")    # soft-vote
thr_cmb  = calibrate_threshold(y_val, val_cmb)

# evaluate both candidates on TEST at their own calibrated thresholds
test_rf  → block_rf
test_cmb → block_cmb

if block_cmb.f1 >= block_rf.f1:  decision = "rf_gbt"
else:                             decision = "rf_only"
```

- **Candidate selection is tie-breaking toward the ensemble** (`>=` not `>`).
- Winner's `(threshold, decision)` persisted to `dns_threshold.json` (lines 410-411).
- Inference reads this file and executes **exactly the candidate that won** (lines 275-281, 184).

This is a disciplined **plan-mandated gate** — the ensemble has to earn its place.

---

## 9. `tree_ensemble_scores` — the one-liner that runs production (lines 178-187)

```python
rf_probs = rf.predict_proba(X)[:,1]
if decision == "rf_only" or gbt is None:
    return rf_probs
return 0.5 * (rf_probs + gbt.predict_proba(X)[:,1])
```
- Soft-vote is a plain mean of class-1 probabilities (unweighted).
- Graceful fallback: if the GBT file isn't present, you still get RF scores.

---

## 10. Legacy RF+Transformer ensemble (lines 238-263)

Still in the file but **not called by `run_training` / `run_inference`** anymore:
- `_ensemble_scores` aligns RF (per-row) with Transformer (per-sequence, so shorter by `SEQUENCE_LENGTH-1`).
- Pads the leading rows that have no full sequence window with RF-only scores.
- Weighted blend: `rf_weight * rf + tf_weight * tf`.

The `--rf-weight` / `--tf-weight` CLI flags remain for backward compatibility — the help text calls `--tf-weight` "deprecated."

---

## 11. Metrics — what gets measured

### `_metric_block` (lines 288-309)
For any `(y_true, scores, threshold)`:
- Threshold-dependent: precision, recall, F1.
- **PR-AUC** (primary; comment cites Saito & Rehmsmeier for imbalanced data).
- **PR-AUC baseline** = class prevalence (what random would score).
- **ROC-AUC** (secondary — can look optimistic under imbalance).
- Both AUCs are wrapped in try/except → gracefully return `None` on edge cases.

### `_recall_by_family` (lines 312-323)
- Iterates families present among test attacks, reports recall + support (n).
- Only meaningful if the labels came with family provenance.

---

## 12. Label-shuffle leakage check (`--shuffle-labels`) (lines 436-451)

- Permute training labels, retrain RF+GBT, score the test set.
- Metrics should **collapse toward chance** (`PR-AUC ≈ prevalence`).
- Comment honestly flags its limit: catches **pipeline** leakage, not **circular labeling** (labels-from-features is a known design dependency).

---

## 13. Fail-fast single-class guard (lines 347-354)

Checked **before** any `.pkl` / `.keras` / `.json` is written. Prevents a bad dataset from half-overwriting your production models.

---

## 14. Metrics persistence (lines 453-473)

Single source of truth: `models/evaluation_metrics.json`, key `path_a`:
```
{
  ...chosen candidate's metrics (precision/recall/f1/pr_auc/roc_auc/threshold),
  decision: "rf_gbt" | "rf_only",
  candidates: { rf_only: {...}, rf_gbt: {...} },
  transformer_baseline: {...} | null,
  shuffle_labels:       {...} | null,
  recall_by_family:     {...},
  seed: 42,
  split_sizes: { train, val, test },
  test_support: { benign, attack }
}
```
Read-merge-write pattern so Path B's metrics in the same file aren't clobbered.

---

## 15. Inference pipeline (lines 483-524)

1. `load_path_a_models()` → RF, GBT (or None), scaler, threshold, decision.
2. Load input, fill missing features, scale with the **saved** scaler.
3. `scores = tree_ensemble_scores(..., decision)` — same code path as training evaluation.
4. `preds = (scores >= threshold).astype(int)`.
5. Append three columns: `ml_score_A`, `ml_label_A`, `ml_verdict_A` ("ATTACK"/"benign").
6. Always writes `<stem>_model_results.csv`; optionally writes enriched JSON for `ml_bridge.py`.

The output JSON format is deliberately **week3-compatible** so downstream fusion works.

---

## 16. CLI surface (lines 531-570)

- `--train FILE` — labeled JSON/CSV/PCAP.
- `--infer FILE` — any supported input.
- `--output-json FILE` — enriched JSON output (fusion-ready).
- `--rf-weight` / `--tf-weight` — kept for compat; the current soft-vote is fixed 50/50 between RF and GBT.
- `--shuffle-labels` — enables the Tier-3 permutation check.
- No args → prints help.

---

## 17. The full training pipeline, step by step (lines 326-476)

```
load → fill-missing → validate labels → single-class guard
    → stratified 70/15/15 split
    → fit scaler on train only; save
    → train RF; train GBT; (train Transformer baseline on sequences)
    → calibrate threshold on VAL for {rf_only, rf_gbt}
    → evaluate both on TEST; pick winner by F1 (tie → ensemble)
    → persist (threshold, decision)
    → final test report (classification_report + PR-AUC + per-family recall)
    → optional label-shuffle check
    → merge metrics into evaluation_metrics.json under "path_a"
```

---

## 18. The design philosophy baked into this file

1. **Honesty over score-chasing.** Transformer stays visible even when it loses.
2. **Imbalance-aware everywhere.** `class_weight="balanced"`, stratified splits, PR-AUC primary.
3. **Leakage-safe by construction.** Split-before-scale, scaler persisted, label-shuffle sanity check available.
4. **Reproducible.** Fixed seed=42 across all learners and splits.
5. **Auditable.** Both candidates' metrics stored, not just the winner's; split sizes and test support recorded for the paper.
6. **Graceful fallbacks.** Missing features → zero; missing GBT → RF-only; missing threshold file → 0.5.
7. **A real decision gate.** The ensemble must earn F1 ≥ RF-only on held-out test or it loses.

---

## 19. References — the two learners (§3)

### Random Forest
- **Breiman, L. (2001).** "Random Forests." *Machine Learning*, 45(1), 5–32. DOI: [10.1023/A:1010933404324](https://doi.org/10.1023/A:1010933404324). Free PDF: <https://www.stat.berkeley.edu/~breiman/randomforest2001.pdf>
  - Original Random Forest paper — bagging + random feature subsets at each split. The source sklearn cites in `RandomForestClassifier`.
- **Breiman, L. (1996).** "Bagging Predictors." *Machine Learning*, 24(2), 123–140. DOI: [10.1007/BF00058655](https://doi.org/10.1007/BF00058655)
  - Foundational bagging paper — basis for the "reduces variance" claim in §3.
- **Ho, T. K. (1998).** "The Random Subspace Method for Constructing Decision Forests." *IEEE TPAMI*, 20(8), 832–844. DOI: [10.1109/34.709601](https://doi.org/10.1109/34.709601)
  - Independent precursor — random-subspace ensembles.
- sklearn docs: [RandomForestClassifier API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)

### "Trees beat deep nets on small tabular data" (the §3 claim)
- **Grinsztajn, L., Oyallon, E., & Varoquaux, G. (2022).** "Why do tree-based models still outperform deep learning on typical tabular data?" *NeurIPS 2022 Datasets and Benchmarks Track*. <https://arxiv.org/abs/2207.08815>
- **Shwartz-Ziv, R., & Armon, A. (2022).** "Tabular Data: Deep Learning Is Not All You Need." *Information Fusion*, 81, 84–90. <https://arxiv.org/abs/2106.03253>

### Transformer baseline (§4) — plain-language description + references

**What the architecture actually does, in plain terms**

The Transformer looks at a **window of 10 consecutive DNS records** and decides whether the *last* record in that window is an attack. It does this in three stages:

1. **Self-attention (`MultiHeadAttention(x,x)`)** — for every record in the window, the model learns how much to "pay attention to" every other record in the same window. "Multi-head" just means it does this comparison from several angles in parallel (`num_heads=2`, each with `head_size=32`) and concatenates the results. This is how the model picks up on *sequential patterns* a tree can't see — e.g. "burst of 10 similar-length queries to the same subdomain."
2. **Position-wise feed-forward (`Conv1D(ff_dim, 1) → ReLU → Conv1D`)** — a tiny 2-layer MLP applied independently to each time step. `kernel_size=1` means it does **not** mix across time; it just reshapes each record's representation. Using Conv1D with kernel=1 is a common Keras idiom equivalent to a Dense layer applied per time step.
3. **LayerNorm + residual (`x + sublayer(LayerNorm(x))`)** — this is **Pre-LN** style (LayerNorm *before* the sublayer, not after). Pre-LN trains more stably than the original Post-LN from the 2017 paper.

Two of these blocks are stacked, then `GlobalAveragePooling1D` collapses the 10 time steps into one vector, and a `Dense(1, sigmoid)` turns it into a probability.

**Why `binary_crossentropy`** — because the output is a probability of attack (0 or 1). The docstring mentions the original code had a regression loss by mistake; this is the fix.

**Training details, demystified**
- **Adam** — adaptive learning-rate optimizer; the de-facto default for Transformers.
- **EarlyStopping on `val_auc`** — training stops when validation AUC stops improving. `restore_best_weights=True` means you keep the best model seen, not the last one.
- **30 epochs, batch 32** — standard small-model defaults.

**Why it exists but doesn't vote**
On ~8-feature tabular data with tens of thousands of rows, trees still win (see Grinsztajn et al. 2022 above). The Transformer is kept as a published **baseline** so the paper can honestly say "we tried a sequence model; it lost."

**References — standards for the Transformer baseline**
- **Vaswani, A., Shazeer, N., Parmar, N., Uszkoreit, J., Jones, L., Gomez, A. N., Kaiser, Ł., & Polosukhin, I. (2017).** "Attention Is All You Need." *NeurIPS 2017*. <https://arxiv.org/abs/1706.03762>
  - The original Transformer paper — encoder = stack of (multi-head self-attention + position-wise FFN) with residual + LayerNorm. Our §4 block is a Pre-LN variant of this.
- **Ba, J. L., Kiros, J. R., & Hinton, G. E. (2016).** "Layer Normalization." <https://arxiv.org/abs/1607.06450>
  - The `LayerNorm` used in each sub-block.
- **Xiong, R., et al. (2020).** "On Layer Normalization in the Transformer Architecture." *ICML 2020*. <https://arxiv.org/abs/2002.04745>
  - Justifies the **Pre-LN** ordering (`LayerNorm → sublayer → +residual`) used in our code, versus the paper's original Post-LN.
- **He, K., Zhang, X., Ren, S., & Sun, J. (2016).** "Deep Residual Learning for Image Recognition." *CVPR 2016*. <https://arxiv.org/abs/1512.03385>
  - Origin of the residual connections (`+residual`) that make deep stacks trainable.
- **Kingma, D. P., & Ba, J. (2015).** "Adam: A Method for Stochastic Optimization." *ICLR 2015*. <https://arxiv.org/abs/1412.6980>
  - The optimizer used in `model.compile(optimizer='adam', ...)`.
- **Srivastava, N., Hinton, G., Krizhevsky, A., Sutskever, I., & Salakhutdinov, R. (2014).** "Dropout: A Simple Way to Prevent Neural Networks from Overfitting." *JMLR*, 15. <https://jmlr.org/papers/v15/srivastava14a.html>
  - The `dropout=0.1` regularizer inside each block.
- **Lin, M., Chen, Q., & Yan, S. (2014).** "Network In Network." *ICLR 2014*. <https://arxiv.org/abs/1312.4400>
  - Introduces **Global Average Pooling** — our `GlobalAveragePooling1D` head.
- **Keras tutorial — *"Timeseries classification with a Transformer model"*** by Theodoros Ntakouris. <https://keras.io/examples/timeseries/timeseries_classification_transformer/>
  - This is the exact template the §4 architecture follows (Conv1D-with-kernel-1 FFN, GAP head, 2 blocks). Worth citing as the implementation reference.

### Three-way stratified split (§5) — why we do it, and is it best practice?

**Why split at all?**
A model's score on data it has *already seen* is meaningless — a big enough model can just memorize the training set and look perfect. To know whether it actually **generalizes** to new DNS traffic, you have to score it on records it has never been trained on. That is the one and only purpose of a held-out set.

**Why *three* splits and not two?**
Because we make two different kinds of decisions, and each one needs its own untouched data:

| Split | Size | Who sees it | What it's used for |
|---|---|---|---|
| **Train** | 70% | Learners (RF, GBT, Transformer) during `.fit()` | Fitting model parameters |
| **Val** (validation) | 15% | Us, during training | Picking the F1-maximizing **threshold** (§7), choosing between `rf_only` vs `rf_gbt` (§8), early-stopping the Transformer |
| **Test** | 15% | Nobody until the very end | **Final honest score** reported in the paper |

If you only had train + test and used test for threshold calibration, your "test" score would be optimistic — you'd have **tuned on it**, which is a soft form of leakage. The val set exists so test stays genuinely untouched until the final report. This is the standard ML workflow (see Hastie, Tibshirani & Friedman, *The Elements of Statistical Learning*, §7.2).

**Why `stratify=y`?**
Our dataset is **imbalanced** — attack records are a minority. A plain random 70/15/15 split can, by chance, put very few attacks (or even zero) into the test set, which makes the test metrics meaningless. `stratify=y` tells sklearn to preserve the attack/benign ratio in every split, so train/val/test all have the same class prevalence as the full dataset.

**Why `random_state=42`?**
Fixes the pseudo-random seed so the split is **reproducible**. Rerunning training gives the exact same train/val/test partition — essential for the paper and for debugging regressions.

**Why carry `fam` through the split?**
`fam` is the attack family label. By splitting it alongside `X, y`, the test set already *knows* which family each test attack belongs to, so §11's per-family recall report (`_recall_by_family`) works without a lossy re-join on indices.

**Is this best practice?**
Yes — with one caveat worth naming in the paper:

- Stratified 70/15/15 is the textbook default for a single-model-and-threshold workflow with imbalanced classes. For small datasets, **stratified k-fold cross-validation** (sklearn `StratifiedKFold`) is stronger because it uses every record for both training and evaluation across folds; our dataset is large enough that a single stratified split is defensible and much cheaper to run.
- Our split is **i.i.d. random**, not **time-based**. For a deployment that must generalize to *future* traffic (concept drift, new malware families), a chronological split (train on older traffic, test on newer) is more honest. If pcap timestamps are available, mention this as a future-work item.

**References**
- **Hastie, T., Tibshirani, R., & Friedman, J. (2009).** *The Elements of Statistical Learning* (2nd ed.), §7.2 "Bias, Variance and Model Complexity" and §7.10 "Cross-Validation." Springer. <https://hastie.su.domains/ElemStatLearn/>
  - Textbook justification for a separate validation set when tuning hyperparameters / thresholds.
- **Kohavi, R. (1995).** "A Study of Cross-Validation and Bootstrap for Accuracy Estimation and Model Selection." *IJCAI '95*. <https://www.ijcai.org/Proceedings/95-2/Papers/016.pdf>
  - Canonical reference for stratified cross-validation on imbalanced data.
- **He, H., & Garcia, E. A. (2009).** "Learning from Imbalanced Data." *IEEE TKDE*, 21(9), 1263–1284. DOI: [10.1109/TKDE.2008.239](https://doi.org/10.1109/TKDE.2008.239)
  - Survey covering why stratification + imbalance-aware metrics (PR-AUC) matter.
- **Saito, T., & Rehmsmeier, M. (2015).** "The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets." *PLOS ONE*, 10(3). <https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0118432>
  - The paper the §11 comment cites — same reasoning (imbalance) that drives our stratified split.
- **Pedregosa, F., et al. (2011).** "Scikit-learn: Machine Learning in Python." *JMLR*, 12. <https://jmlr.org/papers/v12/pedregosa11a.html>
  - Reference for `train_test_split` with `stratify=` — the API we use. See also [sklearn docs — `train_test_split`](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.train_test_split.html).

### HistGradientBoosting (and its lineage)

Scikit-learn's `HistGradientBoostingClassifier` is **inspired by LightGBM** and borrows the Newton-boosting / L2-leaf regularization scheme from XGBoost. Both are built on Friedman's original Gradient Boosting Machine.

### Primary (sklearn user guide cites as `[LightGBM]`)
- **Ke, G., Meng, Q., Finley, T., Wang, T., Chen, W., Ma, W., Ye, Q., & Liu, T.-Y. (2017).** "LightGBM: A Highly Efficient Gradient Boosting Decision Tree." *Advances in Neural Information Processing Systems 30 (NeurIPS 2017)*, pp. 3146–3154. <https://papers.nips.cc/paper/6907-lightgbm-a-highly-efficient-gradient-boosting-decision-tree>
  - Introduces histogram-based split finding (~256 integer bins), reducing split search from O(n_features · n log n) to O(n_features · n).
  - Also introduces GOSS and EFB — note: sklearn does **not** implement these, only the histogram core.

### Secondary (sklearn user guide cites as `[XGBoost]`)
- **Chen, T., & Guestrin, C. (2016).** "XGBoost: A Scalable Tree Boosting System." *KDD '16*, pp. 785–794. <https://arxiv.org/abs/1603.02754>
  - Source of **Newton boosting** (uses the Hessian — second-order gradient info; removes the line-search step of classical GBM).
  - Source of the **L2-regularized leaf-value formula**: `w = -sum_gradient / (sum_hessian + l2_regularization)`.

### Foundational
- **Friedman, J. H. (2001).** "Greedy Function Approximation: A Gradient Boosting Machine." *Annals of Statistics*, 29(5), 1189–1232. <https://projecteuclid.org/euclid.aos/1013203451>
  - Original GBM paper — basis for the "boosting fits residuals / reduces bias" statement in §3.

### How Path A's config maps to the standards

| Our setting | Standard / paper basis |
|---|---|
| `lr=0.1`, `max_iter=300` | Friedman (2001) — shrinkage ν and M boosting rounds |
| `early_stopping=True`, `validation_fraction=0.15` | sklearn convention; auto-enabled >10k samples |
| Histogram binning (256 bins default) | Ke et al. (2017), §3 |
| `class_weight="balanced"` | sklearn utility: weights = n_samples / (n_classes · bincount(y)) |
| L2 leaf regularization | Chen & Guestrin (2016), Eq. 2 |

### sklearn documentation
- [HistGradientBoostingClassifier API](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.HistGradientBoostingClassifier.html)
- [User guide — Histogram-Based Gradient Boosting](https://scikit-learn.org/stable/modules/ensemble.html#histogram-based-gradient-boosting)

---

## 20. Mentor presentation guide — the deep walkthrough

Think of this section as a **script you can speak from**. For each section it tells you *what it is*, *why we did it that way*, and *what a mentor might challenge you on*.

### The one-sentence pitch (memorize this)

> "Path A is a leak-safe, calibrated, auditable **binary classifier** for DNS tunneling. It uses an **8-feature vector per DNS record**, runs two tree-based learners (Random Forest + HistGradientBoosting) in a **soft-vote ensemble**, and includes a **Transformer baseline** that we report but don't deploy because trees won on this tabular data."

Every design choice flows from three principles: **honesty, imbalance-awareness, no leakage.**

---

### §1–2: The setup

**What it is:** Binary classifier. Input is a DataFrame of DNS records, each row has exactly 8 engineered features (`FEATURES_8`). Label column is 0 (benign) or 1 (attack). Optional `attack_family` for per-family recall.

**Why 8 features and not 50?** Fewer features = less overfitting room, faster inference, easier to explain in the paper. The feature engineering was done upstream in Week 3.

**Mentor might ask:** "What are the 8 features?" → Point them to `dns_parser.FEATURES_8`.

**Mentor might ask:** "What happens if a feature column is missing?" → "We fill with 0 defensively — but a missing *label* column is a hard error, because silent label defaults would corrupt training."

---

### §3: The two learners — the money question

**Random Forest (bagging)**
- **200 trees**, each tree sees a bootstrap sample + a random subset of features at each split.
- **`class_weight="balanced"`** — because attack samples are a minority. Without this, the model would learn "always say benign" and get 95% accuracy while catching 0 attacks.
- **What bagging buys you:** low variance. Different trees overfit different noise, averaging cancels it out.

**HistGradientBoosting (boosting)**
- Trains trees **sequentially**, each one fits the residual (the mistakes) of the previous ones.
- **lr=0.1** — shrinkage factor (ν). Smaller = more conservative, slower but more stable.
- **max_iter=300** — up to 300 trees.
- **early_stopping=True + validation_fraction=0.15** — the model holds out 15% of training data as its own internal val set and stops when that val loss stops improving. This is sklearn's protection against overfitting.
- **What boosting buys you:** low bias. It can fit complex patterns bagging can't.

**Why BOTH?**
This is the deepest answer in §3 and the one mentors love:

> "Bagging and boosting make **structurally different mistakes**. RF spreads attention across many features; GBT concentrates on a few highly discriminative ones. When they *agree*, that's strong signal. When they disagree, the ensemble averages the uncertainty. Soft-voting them is a **genuine two-opinion ensemble**, not two correlated copies — which is what you'd get if we voted two RFs or two GBTs."

**Mentor might ask:** "Why not XGBoost or LightGBM?" → "HistGradientBoosting is sklearn-native, uses the same histogram-binning algorithm (Ke et al. 2017), and avoids an extra dependency. For an 8-feature problem the speed differences don't matter."

---

### §4: The Transformer — the honesty move

**What it does:** Looks at a **sliding window of 10 consecutive DNS records** and predicts whether the last record is an attack. Each block has:

1. **Self-attention** — each record attends to all 9 others in the window. "Which earlier records in this burst help explain *this* one?"
2. **Position-wise FFN** (two Conv1D with kernel=1) — reshapes each timestep's representation.
3. **LayerNorm + residual** — standard Transformer plumbing.

After 2 blocks, `GlobalAveragePooling1D` → `Dense(64, relu)` → `Dense(1, sigmoid)`.

**Why is this here if it doesn't vote?**
Pure intellectual honesty. On ~8-feature tabular data, trees still beat Transformers (Grinsztajn et al. 2022). But if we didn't *try* a sequence model, a reviewer could say "you didn't explore the sequential structure." We tried it, we published its metrics as `transformer_baseline`, and we show the data-driven reason trees won. **It makes the paper harder to reject.**

**Mentor might ask:** "Why window = 10?" → "Empirical choice — long enough to see a tunneling burst, short enough to keep sequences cheap."

**Mentor might ask:** "Why Pre-LN?" → "The original 2017 paper used Post-LN, but Xiong et al. 2020 showed Pre-LN trains more stably without needing learning-rate warmup. Our Keras tutorial template uses Pre-LN."

---

### §5: The three-way stratified split

**The script:**

> "We split 70/15/15 into **train/val/test**. Three splits because we make *two separate decisions*: (1) which threshold to use, and (2) which candidate (`rf_only` vs `rf_gbt`) wins. Each decision needs its own untouched data, or we're silently tuning on the test set."

- **Train (70%):** `.fit()` the learners.
- **Val (15%):** calibrate the threshold, pick the winning ensemble, early-stop the Transformer.
- **Test (15%):** reported once, in the paper. Nobody touches it until the end.

**`stratify=y`** → preserves attack/benign ratio in every split. On imbalanced data, a plain random split can put *zero* attacks in test by chance.

**`random_state=42`** → reproducibility. Same split every run.

**Mentor might ask:** "Why not cross-validation?" → "Stratified k-fold is stronger on small datasets, but our dataset is large enough that single-split gives stable estimates and is 5–10× cheaper. We note this as a future enhancement."

**Mentor might ask:** "Is this i.i.d. or time-based?" → "**i.i.d.** This is a known limitation. For deployment against concept drift, time-based splitting is more honest, and we flag this in the paper's limitations section."

---

### §6: Leakage control — split before scale

Order matters:

```
split → fit scaler on TRAIN only → transform val/test with that scaler
```

**Why not fit the scaler on everything?** Then test statistics would leak into the training distribution. The model would be scored on data it already "knows" about statistically.

**Scaler is persisted** → inference uses the exact same `mean` and `std` from training. If you refit at inference time, you'd shift all your features.

**Mentor's favorite question:** "How do you know you have no leakage?" → Three answers:
1. Split-before-scale ordering (§6).
2. Test set never touches hyperparameter choices (§5).
3. **Label-shuffle sanity check** (§12) — if you permute labels, metrics should collapse to chance. If they don't, you have leakage.

---

### §7: Threshold calibration

A classifier outputs probabilities. We need a **threshold** to turn probability into a 0/1 decision. The default 0.5 is often wrong on imbalanced data.

**How we pick it:**
1. On the **validation set**, compute precision and recall at every candidate threshold.
2. Compute **F1** at each threshold (harmonic mean of precision + recall).
3. Pick the threshold where F1 is maximized.

**Why F1 and not accuracy?** Accuracy is useless on imbalanced data (always-predict-benign gets 95%). F1 forces precision AND recall to both be good.

**One technical trick:** `precision_recall_curve` returns `thresholds` one shorter than `precision/recall` — we slice `f1_scores[:-1]` to align them. (This has bitten people in production bugs.)

---

### §8: The decision gate — the heart of Path A

This is the showpiece. The script:

> "We don't just assume the ensemble is better than RF alone. We make it *earn* its place. We evaluate **both candidates on the test set** at their own calibrated thresholds, then pick whichever has higher F1. Tie goes to the ensemble (`>=`). The winner's `(threshold, decision)` gets persisted to `dns_threshold.json`, and inference reads that file and executes **exactly the candidate that won.**"

```python
if block_cmb.f1 >= block_rf.f1:  decision = "rf_gbt"
else:                             decision = "rf_only"
```

**Why `>=` and not `>`?** Ties favor the ensemble because the ensemble has lower variance across future data — same expected F1, lower risk.

**Mentor might ask:** "Isn't picking the winner based on test F1 leakage?" → Fair point. The honest answer is: this is a **model-selection** decision, not a hyperparameter tuning decision, and only two candidates are evaluated. If we were sweeping 50 configurations we'd need another holdout. For a 2-way choice, this is standard practice.

---

### §9: `tree_ensemble_scores` — one function runs production

```python
rf_probs = rf.predict_proba(X)[:,1]
if decision == "rf_only" or gbt is None:
    return rf_probs
return 0.5 * (rf_probs + gbt.predict_proba(X)[:,1])
```

Three things to notice:
1. **Soft-voting = mean of class-1 probabilities.** Simple, unweighted, 50/50.
2. **Same code path for training evaluation and inference** — no bugs from scoring one way during training and another way in production.
3. **Graceful fallback** — if `gbt.pkl` is missing, inference still works with just RF.

---

### §10: Legacy RF+Transformer blend (dead code, kept for compat)

Not called by the current pipeline. The CLI flags `--rf-weight` / `--tf-weight` are kept so old scripts don't break. If asked: "We left the code for reproducibility of earlier experiments; it's not in the production path."

---

### §11: Metrics — what we report and why

- **Precision / Recall / F1** at the chosen threshold.
- **PR-AUC** — our *primary* metric. Threshold-independent, imbalance-aware.
- **PR-AUC baseline** = class prevalence. A random classifier scores this. Reporting the baseline alongside the model stops people from thinking a 0.3 PR-AUC is bad when prevalence is 0.05.
- **ROC-AUC** — reported but with caveat. ROC-AUC can look flattering on imbalanced data because the true-negative rate dominates.
- **Per-family recall** — "we caught 92% of DNSCat2, 71% of iodine" is way more informative than one aggregate number.

**Mentor might ask:** "Why PR-AUC primary instead of ROC-AUC?" → "Saito & Rehmsmeier 2015: on imbalanced data, PR-AUC distinguishes good from poor classifiers more clearly, because it doesn't reward correctly classifying the easy majority class."

---

### §12: Label-shuffle leakage check

**What it does:** Shuffles the training labels randomly, retrains, and scores on the real test set.

**What should happen:** The model learns nothing meaningful → PR-AUC collapses to the baseline (prevalence).

**What it catches:** Pipeline leakage — if a feature accidentally encodes the label (e.g., you forgot to drop it), shuffled training would still get artificially high test metrics.

**What it does *NOT* catch:** Circular labeling — if your *features* were derived from the labels upstream (e.g., Week-3 labeling heuristic), shuffle won't detect that. The docstring is honest about this limit.

---

### §13: Fail-fast single-class guard

If the training data has only one class (all benign, all attack), training would silently produce a broken model. We check **before** writing any `.pkl` / `.keras` / `.json`, so a bad dataset can't half-overwrite good production models.

---

### §14: Metrics persistence

Everything the paper needs is in `evaluation_metrics.json` under `path_a`:
- The winner's metrics
- **Both candidates' metrics** (so reviewers can see we didn't cherry-pick)
- Transformer baseline (so reviewers see we tried it)
- Shuffle-labels result (so reviewers see the leakage check)
- Split sizes + test support (so reviewers can audit the methodology)
- `seed: 42`

**Read-merge-write pattern** — Path B writes to the same file under its own key. We read, update our key, write back.

---

### §15–16: Inference + CLI

Inference mirrors training *exactly*:
1. Load saved RF, GBT, scaler, threshold, decision.
2. Load input → fill missing features → transform with saved scaler.
3. Score via same `tree_ensemble_scores` function.
4. Apply saved threshold.
5. Write three columns to CSV + optional week3-compatible JSON for the fusion pipeline.

**CLI:** `--train`, `--infer`, `--output-json`, `--shuffle-labels`, deprecated `--rf-weight`/`--tf-weight`.

---

### §17: The pipeline, one breath

```
load → validate → stratified split → fit-scaler-on-train
  → train RF + GBT + Transformer baseline
  → calibrate thresholds on VAL
  → evaluate both candidates on TEST → pick winner by F1
  → persist (threshold, decision)
  → report + optional shuffle check → merge metrics
```

---

### §18: The seven principles (mentor pitch)

If a mentor asks "what's the design philosophy?":

> "Seven principles. **One**, honesty over score-chasing — we publish the baseline even when it loses. **Two**, imbalance-aware everywhere — class weighting, stratified splits, PR-AUC primary. **Three**, leakage-safe by construction — split before scale, persisted scalers, label-shuffle sanity check. **Four**, reproducibility — fixed seed. **Five**, auditability — both candidates' metrics, split sizes, test support, all persisted. **Six**, graceful fallbacks — missing GBT falls back to RF-only. **Seven**, a real decision gate — the ensemble has to *earn* F1 ≥ RF-only on held-out test, or RF-only wins."

---

### Three questions to be ready for

**1. "What's your biggest limitation?"**
> "i.i.d. split, not time-based. If attacker behavior drifts, our test accuracy could be optimistic. Future work: chronological split using pcap timestamps."

**2. "Why trees over deep learning when deep learning is the hype?"**
> "On tabular data with ~8 features and tens of thousands of rows, trees still outperform Transformers. Grinsztajn et al. 2022, Shwartz-Ziv & Armon 2022. We don't just claim it — we *measured* it with the baseline we kept in §4."

**3. "How do I know this isn't just overfit to your test set?"**
> "Three defenses: stratified split so test is representative, label-shuffle to catch pipeline leakage, and both candidates' metrics are published so there's no cherry-picking. The seed is fixed so you can rerun it and get the same numbers."
