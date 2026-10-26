# Path B — Full Deep Dive (Train + Predict)

Source files:
- [`src/dns_detect/models/path_b_train.py`](../../src/dns_detect/models/path_b_train.py)
- [`src/dns_detect/models/path_b_predict.py`](../../src/dns_detect/models/path_b_predict.py)

---

## 1. What Path B actually is

An **unsupervised anomaly detector** for DNS traffic built as a **Transformer autoencoder** ("Trafficformer"). Unlike Path A (supervised tabular classifier), Path B:

- Trains on **benign-only** sliding windows → learns what "normal" looks like.
- At inference, measures **reconstruction error** per window → high error = unlike normal = anomaly.
- Windows are **per-client, time-ordered** so each window is a real temporal sequence, not a random mix.
- Output score (`ml_score_B`) is a sigmoid of the error's z-score, so it fuses cleanly with Path A's probability.

The design is research-backed: multi-feature reconstruction (Kitsune), DNS-tunneling feature set (Nadler), per-host sequencing to avoid cross-contamination.

---

## 2. Feature set & data contract

- **Features (`PATH_B_FEATURES`):** length, entropy, subdomain count, digit ratio, longest label — a multi-feature vector per record, **not** a scalar.
- **Required metadata per record:** `client_ip`, `timestamp` (used as `order`), and (train only) `label`.
- **Loader:** `dns_detect.parsing.dns_parser.load_multifeature_with_meta(path, features)` returns `(X, labels, client_ip, order)`.
- **Why multi-feature:** Kitsune proves reconstruction works better over multi-dim vectors; Nadler's tunneling study shows length+entropy+label-structure together separate tunnels from normal DNS far more reliably than any one signal.

---

## 3. The "Trafficformer" architecture (train lines 53-77)

```
Input (window_size, F)
  └→ TransformerEncoder × 3   (reuses Path A's encoder: LN → MHA → +res → LN → Conv1D(ff) → Conv1D(back) → +res)
  └→ Dense(64, relu) → Dropout(0.4)
  └→ Dense(F, linear)   # SAME shape as input — reconstruction
```

Hyperparameters:
- `head_size=64`, `num_heads=3`, `ff_dim=3`, `num_transformer_blocks=3`
- `dropout=0.25`, `mlp_dropout=0.4`
- Loss: **MSE** on the reconstruction (output ≈ input)
- Optimizer: Adam, `lr=1e-4`
- Encoder block is **imported from `path_a.transformer_encoder`** — single implementation shared across paths.

Why an autoencoder here? If the model is only ever shown benign windows during training, it learns to reconstruct benign patterns well and attack patterns poorly. The reconstruction error itself becomes the anomaly score — no labels needed at inference.

---

## 4. Per-client windowing — the key technique (predict lines 100-128)

```python
for cip in unique(client_ip):
    idx = where(client_ip == cip)
    idx = idx[argsort(order[idx], stable)]      # chronological per host
    for i in range(len(idx) - window_size + 1):
        w = idx[i : i + window_size]
        windows.append(X[w])
        last_idx.append(w[-1])                   # window's score belongs to its last record
```

Why this matters:
- **A window never crosses host boundaries** → each window represents a real behavioural sequence from one client.
- **Stable sort by timestamp** inside each client → preserves order even on ties.
- The window's score is assigned to its **last record** (`last_idx`), aligning with the "when did the anomaly manifest" question.
- Clients with fewer than `window_size` records produce **no windows** → those records simply get no Path B score (`covered=False` later).

Returned shape: `windows (N, window_size, F)`, `last_idx (N,)`, optional `y_win (N,)` where `y_win = 1` if **any** record in the window is attack (`labels[w].max()`).

---

## 5. Per-feature min-range normalization (predict lines 94-97, train lines 177-191)

```python
f_min = X_train.min(axis=0)
f_rng = X_train.max(axis=0) - f_min
f_rng = where(f_rng > 0, f_rng, 1.0)             # zero-range guard
Xn = (X - f_min) / f_rng
```

- Fit **on train rows only** → zero leakage.
- Saved to `<save_name>_norm.json` with the feature list, so inference uses the exact same scaling.
- Loader is **back-compatible**: old scalar artifacts are promoted to length-1 lists (predict lines 82-83).
- Features are stored alongside `min`/`range` so if `PATH_B_FEATURES` changes later, inference still uses the trained set.

---

## 6. The stratified-chronological split (train lines 152-174)

**The problem:** The project's attack captures (2019/2024) all predate the benign capture (2026). A naive global time cut `train = oldest 70%` would push every attack into train and leave val/test with zero positives → Path B could never be evaluated.

**The solution:**
```python
for cls in unique(labels):
    cls_idx = where(labels == cls)
    cls_idx = cls_idx[argsort(order[cls_idx], stable)]   # chronological WITHIN class
    tr = cls_idx[:70%]
    val = cls_idx[70%:85%]
    te  = cls_idx[85%:]
```

- Each class is sorted by time independently, then cut 70/15/15.
- Concatenating yields splits that **carry both classes** while still respecting chronology **within each class**.
- Not perfect (classes still live in different absolute time windows), but it's the honest compromise that lets the model be evaluated at all.

---

## 7. Benign-only training (train lines 204-218)

```python
x_train_ben = x_train[yw_train == 0]
x_valid_ben = x_valid[yw_valid == 0]
```

- Autoencoder trained **only on benign windows** → learns the manifold of normal DNS behaviour.
- `MIN_BENIGN = 10` floor: if benign windows are too few, falls back to all windows with a warning (degraded, but training still happens).
- Fit signature: `model.fit(x_train_ben, x_train_ben, ...)` — **target = input** (reconstruction).

Callbacks:
- `EarlyStopping(monitor="val_loss", patience=10, restore_best_weights=True)`
- `ModelCheckpoint(save_best_only=True, mode="min")` → best model (lowest val MSE) persists to `.h5`.

---

## 8. The threshold — percentile of benign-validation error (train lines 84-100)

```python
if method == "percentile":
    thr = np.percentile(val_errors, 99.0)        # default
else:                                             # "mean_std" fallback
    thr = mean + multiplier * std
```

Why percentile over mean+kσ:
- Reconstruction errors are **right-skewed** → mean+kσ overestimates the threshold.
- The 99th percentile asks "what error level does only 1% of benign traffic exceed?" — directly interpretable as a benign false-positive budget.
- Mean+kσ kept as a fallback for research comparison.

Also saved alongside:
- `error_mean`, `error_std` → used by the inference-time sigmoid.
- `window_size`, `n_features`, `method`.

Default percentile is pulled from `config/settings.yaml` via `_default_percentile()` (train lines 40-46).

---

## 9. The scoring pipeline at inference (predict lines 148-172)

```python
model, threshold, window_size, error_mean, error_std, norm, features = load_model_artifacts(save_name)
X, _labels, client_ip, order = load_multifeature_with_meta(path, features)
Xn = normalize_features(X, norm)

windows, last_idx, _ = build_client_windows(Xn, client_ip, order, window_size)
errors   = compute_reconstruction_errors(model, windows)    # per-window MSE
scores   = normalize_scores(errors, error_mean, error_std)  # z-score → sigmoid
anomalies = (errors > threshold).astype(int)
```

Then map window-level results back to record-level:
```python
out_scores[last_idx] = scores        # all other rows stay 0
out_anom[last_idx]   = anomalies
covered[last_idx]    = True          # which records were actually scored
```

The `covered` mask is important — downstream fusion knows which rows have a real Path B opinion and which don't (short-history clients, head-of-window records).

---

## 10. Reconstruction error (predict lines 131-136)

```python
reconstructed = model.predict(X_windows, verbose=0)
return np.mean(np.square(X_windows - reconstructed), axis=(1, 2))
```

- Element-wise squared difference across both the time axis (window_size) and feature axis (F).
- One scalar MSE per window.
- Empty-input guard returns `np.zeros(0)`.

---

## 11. The score normalization — why sigmoid of z-score (predict lines 139-145)

```python
z = (errors - error_mean) / error_std
return 1.0 / (1.0 + np.exp(-z))
```

- Raw MSE is unbounded and dataset-dependent → not directly comparable to Path A's probability.
- Z-score re-centers each error against the benign-validation distribution captured at train time.
- Sigmoid squashes to `(0, 1)` — same units as a classifier probability.
- Result: `ml_score_B ∈ (0, 1)` where 0.5 ≈ "typical benign," → 1 as the error grows unusual.
- This is what makes fusion with Path A sensible: both paths speak the same probabilistic language.

Edge case: if `error_std == 0`, returns all zeros (degenerate benign distribution).

---

## 12. Artifact layout — what gets saved and loaded

Train writes to `models/`:
- `<save_name>.h5` — the Keras model (best-val-loss checkpoint).
- `<save_name>_norm.json` — `{features, min, range}` for per-feature scaling.
- `<save_name>_threshold.json` — `{threshold, method, window_size, n_features, error_mean, error_std}`.
- `evaluation_metrics.json` under key `"path_b"` — merge-write (preserves Path A's block).

Predict loads via `load_model_artifacts()`:
- Accepts both `.h5` and `.keras` extensions (predict lines 51-57).
- Falls back to `threshold=0.01, window_size=20, mean=0, std=1` if the threshold file is missing (with a warning).
- Falls back to identity normalization if the norm file is missing (with a warning that accuracy will drop).
- `compile=False` on load → doesn't need the training optimizer state for inference.

---

## 13. Final evaluation on held-out test (train lines 263-306)

Only runs if the test set actually contains both classes:
```python
test_errors = compute_reconstruction_errors(model, x_test)
test_pred   = (test_errors > threshold).astype(int)
```

Reports:
- Full `classification_report` (precision/recall/F1 per class).
- **PR-AUC (primary)** with class prevalence as the baseline — honest for imbalanced data.
- **ROC-AUC (secondary)** — can look optimistic under imbalance.
- Per-split window counts and per-class support.

All of this is merged under `"path_b"` in `evaluation_metrics.json` next to Path A's block — single source of truth for the paper.

---

## 14. CLI surfaces

### Train
```
python -m dns_detect.models.path_b_train \
  --filename merged_features_labeled.json \
  --n_days 20 \
  --save_name dns_trafficformer \
  --data_dir data/processed \
  [--threshold-method percentile|mean_std] [--percentile 99] [--multiplier 2.5]
```

### Predict
```
python -m dns_detect.models.path_b_predict \
  --filename week3_features_all.json \
  --save_name dns_trafficformer \
  [--data_dir data] [--model_dir .../models] [--output results.csv]
```

The CSV output writes `ml_score_B`, `is_anomaly`, `scored` (the `covered` mask), and `verdict_B` ("ANOMALY" / "normal") per record.

---

## 15. The `get_predict()` convenience (predict lines 179-196)

Returns a dict suitable for programmatic callers (e.g. the fusion bridge):
```python
{
  "num_records":   int,
  "num_windows":   int,                # == covered.sum()
  "num_anomalies": int,
  "anomaly_rate":  float,              # over covered records only
  "threshold":     float,
  "scores":        [... per record ...],
  "anomalies":     [... per record ...],
}
```

Note `anomaly_rate` is computed over `scored` rows only — not diluted by the unscored ones.

---

## 16. Why Path B is accurate — the techniques that compound

1. **Benign-only training** — the autoencoder has nothing to copy from attacks, so reconstruction fails exactly on them.
2. **Multi-feature reconstruction** — attacks that beat one feature (e.g. masking length) still trip entropy or label structure; the MSE sums across all features.
3. **Per-client sequencing** — a tunneling client's rhythm (bursts, label patterns) is visible only within its own window, not when mixed with other hosts.
4. **Transformer encoder** — multi-head attention captures long-range dependencies inside the 20-record window that an LSTM/CNN would lose.
5. **Percentile threshold** — robust to the right-skew of reconstruction errors; directly expressible as a FPR budget.
6. **Z-score sigmoid output** — comparable to Path A's probability, so the fusion layer can combine them additively.
7. **Train-only normalization + persisted scaler** — zero leakage, identical scaling at inference.
8. **Stratified-chronological split** — honest evaluation despite the dataset's time structure.
9. **EarlyStopping on val_loss + best-checkpoint save** — model that persists is the one with the best unseen-benign reconstruction, not the last epoch's.
10. **Covered-mask semantics** — downstream never confuses "I say normal" with "I didn't score this row."

---

## 17. The full training pipeline, step by step

```
load_multifeature_with_meta(file)
  → X, labels, client_ip, order
stratified-chronological 3-way split (per class, 70/15/15)
fit per-feature (min, range) on TRAIN rows only; save norm.json
Xn = normalize_features(X, norm)
for each split: build_client_windows(Xn[sl], client_ip[sl], order[sl], window_size, labels[sl])
drop attack windows from train/val (benign-only training)
build Trafficformer (encoder × 3 → MLP → Dense(F, linear))
compile(MSE, Adam 1e-4)
fit(x_train_ben, x_train_ben, EarlyStopping, ModelCheckpoint→.h5)
val_errors = reconstruction MSE on benign val windows
threshold = percentile(val_errors, 99); save threshold.json with (mean, std, window_size, n_features)
if test is mixed: compute test_errors; threshold → preds; log PR-AUC/ROC-AUC/precision/recall/F1
merge metrics into evaluation_metrics.json under "path_b"
```

## 18. The full inference pipeline, step by step

```
load_model_artifacts(save_name) → model, threshold, window_size, mean, std, norm, features
load_multifeature_with_meta(file, features) → X, _, client_ip, order
Xn = normalize_features(X, norm)
windows, last_idx = build_client_windows(Xn, client_ip, order, window_size)   # per-client, chronological
errors   = per-window MSE
scores   = sigmoid((errors - mean) / std)   # (0,1) for fusion with Path A
anomalies = errors > threshold
project window-level scores onto records via last_idx; keep a covered mask
emit per-record (ml_score_B, is_anomaly, scored, verdict_B)
```

---

## 19. The design philosophy

- **Unsupervised, by design.** Path A is the supervised signal; Path B provides an independent "does this behave like normal DNS?" opinion.
- **Honest evaluation.** Stratified-chronological split chosen for a reason, documented in-code.
- **Fusion-ready.** Score lives in `(0, 1)` so it combines with Path A's probability without rescaling heuristics.
- **Leak-safe.** Train-only normalization, benign-only training, held-out test.
- **Reproducible.** Fixed window size, saved threshold + norm + model together.
- **Graceful degradation.** Missing threshold/norm files → warnings + safe fallbacks instead of hard failure.
- **Shared encoder.** Imports Path A's `transformer_encoder` → single implementation to audit.
- **Covered semantics.** A record without enough per-client history is explicitly unscored, not silently labelled benign.
