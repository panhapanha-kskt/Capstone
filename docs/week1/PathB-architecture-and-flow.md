# Path B — Architecture & End-to-End Flow

Source files:
- Training: [`src/dns_detect/models/path_b_train.py`](../../src/dns_detect/models/path_b_train.py)
- Inference: [`src/dns_detect/models/path_b_predict.py`](../../src/dns_detect/models/path_b_predict.py)
- Shared helpers: `build_client_windows`, `normalize_features`, `compute_reconstruction_errors` live in `path_b_predict.py` and are imported by the trainer.

This document is the **architectural map** of Path B — the autoencoder-based, per-client, multi-feature sequence anomaly detector.

---

## 0. Path B in one sentence

> "Path B is a **Trafficformer autoencoder** that learns to reconstruct **benign** DNS traffic from **per-client, time-ordered sliding windows** of 5-feature vectors. A record is flagged **anomalous** when the model's reconstruction error exceeds the **99th-percentile** of benign-validation error. It emits `ml_score_B` ∈ (0,1) for fusion with Path A."

Core idea: **unsupervised** — never trained on attacks. Attacks look weird to a model that has only seen "normal."

---

## 1. High-level system diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│         PATH B — TRAFFICFORMER (per-client sequence autoencoder)             │
│         Multi-feature • Per-host windows • Reconstruction-error anomaly      │
└─────────────────────────────────────────────────────────────────────────────┘

   INPUT                       PARSING                     FEATURIZATION
   ─────                       ───────                     ─────────────
┌──────────────┐          ┌────────────────────┐        ┌─────────────────┐
│  labeled     │─────────▶│ load_multifeature_ │───────▶│ PATH_B_FEATURES │
│  features    │          │   with_meta()      │        │   (5 cols)      │
│  JSON        │          │                    │        │                 │
│              │          │ returns:           │        │ query_length    │
│  (needs      │          │  X          (N, F) │        │ query_entropy   │
│   timestamp  │          │  labels     (N,)   │        │ subdomain_count │
│   + client_ip)│         │  client_ip  (N,)   │        │ digit_ratio     │
└──────────────┘          │  order      (N,)   │        │ longest_label   │
                          └──────────┬─────────┘        └────────┬────────┘
                                     │                           │
                                     ▼                           │
                        STRATIFIED-CHRONOLOGICAL SPLIT           │
                        (per class → sorted by time → 70/15/15)  │
                                     │                           │
                                     ▼                           │
                       ┌─────────────────────────┐               │
                       │ Per-feature NORMALIZE   │◀──────────────┘
                       │ (min-range on TRAIN     │
                       │  rows only)             │
                       └────────────┬────────────┘
                                    ▼
                       ┌─────────────────────────┐
                       │ build_client_windows()  │
                       │  group by client_ip     │
                       │  sort by timestamp      │
                       │  sliding window=N_DAYS  │
                       │  NEVER cross hosts      │
                       └────────────┬────────────┘
                                    ▼
                             (n_win, N_DAYS, F)
                                    │
                                    │   ╔══════ TRAINING PATH ══════╗
                                    ├──▶║  Drop attack windows      ║
                                    │   ║  Train on BENIGN only     ║
                                    │   ║  Loss: MSE(x, decoder(x)) ║
                                    │   ║  Adam, lr=1e-4, 200 epochs║
                                    │   ║  EarlyStopping val_loss   ║
                                    │   ╚═════════════╦═════════════╝
                                    │                 │
                                    │                 ▼
                                    │     ┌────────────────────────┐
                                    │     │ On BENIGN VAL windows: │
                                    │     │ compute per-window MSE │
                                    │     │ threshold = p99 of     │
                                    │     │   benign errors        │
                                    │     └───────────┬────────────┘
                                    │                 ▼
                                    │        PERSIST ARTIFACTS
                                    │        ────────────────
                                    │        <save>.h5
                                    │        <save>_threshold.json
                                    │        <save>_norm.json
                                    │        evaluation_metrics.json["path_b"]
                                    │
                                    │   ╔══════ INFERENCE PATH ═════╗
                                    └──▶║  Load artifacts           ║
                                        ║  Reconstruct every window ║
                                        ║  err = MSE(x, model(x))   ║
                                        ║  anomaly = (err > thr)    ║
                                        ║  score_B = sigmoid(z(err))║
                                        ║  Assign to LAST record of ║
                                        ║   each window             ║
                                        ╚═════════════╦═════════════╝
                                                      ▼
                                            ┌────────────────────┐
                                            │ OUTPUT (per record)│
                                            │  ml_score_B ∈ (0,1)│
                                            │  is_anomaly {0,1}  │
                                            │  scored {T,F}      │
                                            │  verdict_B         │
                                            └────────────────────┘
```

---

## 2. Why Path B is unsupervised (and different from Path A)

| Aspect | Path A | Path B |
|---|---|---|
| **Learning paradigm** | Supervised (needs labels during training) | Unsupervised (only needs *benign* examples) |
| **Features per record** | 8 (FEATURES_8) | 5 (PATH_B_FEATURES) |
| **Unit of inference** | 1 record = 1 prediction | 1 window of N records (per client) = 1 prediction |
| **Model family** | Tree ensemble (RF + GBT soft-vote) | Transformer autoencoder (Trafficformer) |
| **What it learns** | "Which features separate attack from benign" | "What benign DNS traffic looks like" |
| **Decision rule** | `score ≥ calibrated_threshold → ATTACK` | `reconstruction_error > p99_benign → ANOMALY` |
| **Robustness to new attack families** | Needs retraining with examples | Catches **novel** attacks by looking "weird" |

**Mentor's one-liner for Path B:**
> "Path B is a safety net for the unknown. Path A can only recognize attacks it was trained on; Path B flags *anything* that doesn't look like normal traffic."

---

## 3. The 5 features used by Path B

Defined in [`dns_parser.py:42-48`](../../src/dns_detect/parsing/dns_parser.py#L42-L48):

```python
PATH_B_FEATURES = [
    "query_length",      # total characters of the FQDN
    "query_entropy",     # Shannon entropy of the query string
    "subdomain_count",   # number of "." in the query
    "digit_ratio",       # digits / total chars
    "longest_label",     # length of the longest "."-separated label
]
```

**Why 5 and not 8?** The comment in `dns_parser.py:40-42` explains it:

> "A single scalar (query length) is too weak (Kitsune/Nadler): the autoencoder reconstructs this vector instead."

- Dropped from FEATURES_8: `has_digits` (redundant with `digit_ratio`), `answer_count` (always 0 on week3 data), `unique_char_ratio` (highly correlated with `query_entropy`).
- The 5 kept features all have **continuous dynamic range**, which is what an MSE-reconstruction loss needs. Binary indicators like `has_digits` would make the MSE dominated by the continuous features anyway.

---

## 4. The input contract — more demanding than Path A

Path B needs **three extra columns** that Path A doesn't:

| Column | Why Path B needs it |
|---|---|
| `timestamp` (or `order`) | To sort records chronologically within each client |
| `client_ip` | To group records so a window never mixes two hosts |
| `label` (training only) | To filter out attack rows (benign-only training) |

If `timestamp` is missing, `load_multifeature_with_meta` falls back to **row index** as the ordering, which is fine for already-ordered captures.

---

## 5. The stratified-chronological split — a Path-B-specific trick

This is one of Path B's smartest design decisions. The comment at [`path_b_train.py:152-158`](../../src/dns_detect/models/path_b_train.py#L152-L158) explains it:

> "Why not a global time cut: on this project the attack captures (2019/2024) all predate the benign capture (2026), so sorting by time globally and taking 70/15/15 drops every attack into train and leaves val/test with no positives — Path B can't be evaluated."

**The fix:**

```
                     ALL RECORDS (by class)
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
    ┌────────────────┐              ┌────────────────┐
    │ BENIGN rows    │              │ ATTACK rows    │
    │ sorted by time │              │ sorted by time │
    └───────┬────────┘              └───────┬────────┘
            │                               │
    cut 70% / 15% / 15%             cut 70% / 15% / 15%
            │                               │
    ┌───────┼───────┐               ┌───────┼───────┐
    ▼       ▼       ▼               ▼       ▼       ▼
  tr_ben val_ben te_ben           tr_atk val_atk te_atk
    │       │       │               │       │       │
    └───┬───┘       │               └───┬───┘       │
        └───────────┼───────────────────┘           │
                    ▼                               │
                train split  ◀────── concat ──────┐ │
                                                  │ │
                val split    ◀────── concat ──────┤ │
                                                  │ │
                test split   ◀────── concat ──────┴─┘
```

Each split keeps both classes while still respecting chronology **within each class**. This is the compromise between pure time-based (ideal but infeasible here) and pure random (loses temporal order).

---

## 6. Per-feature normalization (min-range, train-only)

```python
X_tr   = X[train_mask]                 # TRAIN rows only
f_min  = X_tr.min(axis=0)              # per-feature min, shape (5,)
f_rng  = X_tr.max(axis=0) - f_min      # per-feature range, shape (5,)
X_norm = (X - f_min) / f_rng           # applies to train/val/test
```

**Why min-range and not StandardScaler (like Path A)?** Reconstruction-error autoencoders work better on **bounded inputs** (roughly [0,1]) because the output layer's linear activation can span that range cleanly. Z-scored inputs can push values into [-5, +5], which is harder to reconstruct.

**Saved to disk** as `<save_name>_norm.json`:
```json
{
  "features": ["query_length", "query_entropy", "subdomain_count", "digit_ratio", "longest_label"],
  "min":   [1.0, 0.0, 0, 0.0, 1],
  "range": [254.0, 5.7, 12, 1.0, 63]
}
```

---

## 7. `build_client_windows` — the heart of the sequence construction

```python
def build_client_windows(X, client_ip, order, window_size, labels=None):
    for cip in unique(client_ip):            # one host at a time
        idx = where(client_ip == cip)        # all its records
        idx = idx[argsort(order[idx])]       # time-ordered
        for i in range(len(idx) - window_size + 1):
            w = idx[i : i + window_size]     # a sliding window
            windows.append(X[w])             # shape (window_size, F)
            last_idx.append(w[-1])           # anchor for inference
            if labels is not None:
                y_win.append(labels[w].max())  # attack if any record is attack
```

**Visual:**

```
Client 10.0.0.42 records (sorted by time):
  idx:  3  7  11  22  41  58  60  79  83  97  ...
                │   │   │   │   │   │   │   │
                └──window 0────┘           │   │
                   └──window 1────┘        │   │
                      └──window 2────┘     │   │
                               ...         │   │
                                     └──window K───┘

Client 10.0.0.55 records (sorted by time):   ← different host, separate windows
  idx:  2  5  18  34  52  67  ...
```

**Invariants:**
- A window **never crosses a host boundary** (two different clients never appear in the same sequence).
- A window **respects time order** within a host.
- A window's **label** = 1 if *any* record in it is an attack (conservative — benign-only training needs clean windows).
- A client with fewer than `window_size` records produces **no windows** (their records get score 0 / `scored=False` at inference).

---

## 8. The Trafficformer architecture

Built by `build_trafficformer()` in `path_b_train.py:53-77`. The encoder blocks are the **same** `transformer_encoder` function used by Path A's baseline — imported directly.

```
INPUT: (batch, window_size=N_DAYS, F=5)

   │
   ▼
┌───────────────────────────────────────┐
│  Transformer Encoder Block 1          │
│    head_size=64, num_heads=3, ff_dim=3│
│    dropout=0.25                       │
│    (same Pre-LN structure as Path A)  │
└───────────────┬───────────────────────┘
                ▼
┌───────────────────────────────────────┐
│  Transformer Encoder Block 2          │
└───────────────┬───────────────────────┘
                ▼
┌───────────────────────────────────────┐
│  Transformer Encoder Block 3          │
└───────────────┬───────────────────────┘       (batch, N_DAYS, F)
                ▼
┌───────────────────────────────────────┐
│  Dense(64, relu)                      │
│  Dropout(0.4)                         │       (batch, N_DAYS, 64)
└───────────────┬───────────────────────┘
                ▼
┌───────────────────────────────────────┐
│  Dense(F, linear)       ← same F as   │
│                           the input!  │
└───────────────┬───────────────────────┘       (batch, N_DAYS, F)
                ▼
             OUTPUT: a RECONSTRUCTION of the input

   LOSS: mean_squared_error(input, output)
   OPTIMIZER: Adam, learning_rate=1e-4
```

**Key architectural choices:**
- **Output has the same shape as the input** — this is what makes it an autoencoder. There's no classifier head.
- **No bottleneck layer** — this isn't a classical compress-then-expand autoencoder. The Transformer blocks *are* the latent reasoning. The model is forced to reconstruct from attention-mixed features.
- **Trained ONLY on benign windows** — so it learns a tight manifold of "normal."
- **At inference time, attacks look weird** — the model has never seen their pattern, so reconstruction error spikes.

---

## 9. The anomaly threshold — 99th percentile of benign-val errors

```python
val_errors = compute_reconstruction_errors(model, x_valid_ben)
threshold  = np.percentile(val_errors, 99.0)      # p99 by default
```

**Why percentile instead of mean + k·σ?**
Reconstruction errors on benign data are usually **right-skewed** (lots of easy windows, a long tail of hard ones). mean + k·σ assumes a normal distribution and either misses the tail (false negatives) or flags the top of the normal tail (false positives). The percentile is **non-parametric** — it just says "flag the top 1% of what we've seen look like."

**Saved to disk** as `<save_name>_threshold.json`:
```json
{
  "threshold":   0.0423,
  "method":      "percentile_99",
  "window_size": 20,
  "n_features":  5,
  "error_mean":  0.0082,
  "error_std":   0.0147
}
```

---

## 10. The training pipeline, step by step

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  python -m dns_detect.models.path_b_train \                                  │
│       --filename labeled.json --n_days 20 --save_name dns_trafficformer      │
└─────────────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────┐
│ 1. LOAD              │  X, labels, client_ip, order =
│                      │     load_multifeature_with_meta(path)
│                      │  F = X.shape[1]       # typically 5
└──────────┬───────────┘
           ▼
┌──────────────────────┐  for cls in [0, 1]:
│ 2. STRATIFIED-       │      idx = where(labels == cls); sort by order[idx]
│    CHRONOLOGICAL     │      cut 70/15/15
│    SPLIT per class   │      concat into train/val/test masks
└──────────┬───────────┘
           ▼
┌──────────────────────┐  f_min = X[train].min(axis=0)
│ 3. PER-FEATURE       │  f_rng = X[train].max(axis=0) - f_min
│    NORMALIZE (train- │  Xn    = (X - f_min) / f_rng
│    derived)          │  save: <save>_norm.json
└──────────┬───────────┘
           ▼
┌──────────────────────┐  for each split:
│ 4. BUILD WINDOWS     │     build_client_windows(Xn[split],
│    (per client,      │                           client_ip[split],
│     time-ordered)    │                           order[split],
│                      │                           n_days,
│                      │                           labels[split])
└──────────┬───────────┘
           ▼
┌──────────────────────┐  x_train_ben = x_train[y_train == 0]
│ 5. KEEP ONLY         │  if too few benign → fall back to ALL windows
│    BENIGN WINDOWS    │  (MIN_BENIGN = 10)
│    for training      │
└──────────┬───────────┘
           ▼
┌──────────────────────┐  model = build_trafficformer(
│ 6. BUILD MODEL       │             input_shape=(n_days, F),
│                      │             head_size=64, num_heads=3,
│                      │             ff_dim=3, num_transformer_blocks=3,
│                      │             mlp_units=[64],
│                      │             mlp_dropout=0.4, dropout=0.25)
│                      │  loss = MSE
│                      │  optimizer = Adam(lr=1e-4)
└──────────┬───────────┘
           ▼
┌──────────────────────┐  model.fit(x_train_ben, x_train_ben,   # reconstruction
│ 7. TRAIN             │              epochs=200, batch_size=32,
│                      │              validation_data=(x_valid_ben,
│                      │                               x_valid_ben),
│                      │              callbacks=[EarlyStopping(val_loss,
│                      │                                        patience=10),
│                      │                         ModelCheckpoint(.h5)])
└──────────┬───────────┘
           ▼
┌──────────────────────┐  val_errors = compute_reconstruction_errors(
│ 8. CALIBRATE         │                   model, x_valid_ben)
│    THRESHOLD on      │  threshold  = percentile(val_errors, 99.0)
│    BENIGN VAL ERRORS │  save: <save>_threshold.json
└──────────┬───────────┘
           ▼
┌──────────────────────┐  test_errors = compute_reconstruction_errors(
│ 9. EVALUATE on       │                    model, x_test)
│    MIXED TEST        │  test_pred   = (test_errors > threshold)
│                      │  compute precision, recall, F1, PR-AUC, ROC-AUC
└──────────┬───────────┘
           ▼
┌──────────────────────┐  evaluation_metrics.json["path_b"] = {
│10. MERGE METRICS     │    precision, recall, f1, pr_auc, roc_auc,
│                      │    threshold, threshold_method, window_size,
│                      │    features, split_sizes, test_support
│                      │  }
└──────────────────────┘
```

---

## 11. The inference pipeline, step by step

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  python -m dns_detect.models.path_b_predict \                                │
│       --filename week3_features_all.json --save_name dns_trafficformer       │
└─────────────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────┐  model, threshold, window_size, error_mean, error_std,
│ 1. LOAD ARTIFACTS    │       norm, features = load_model_artifacts(save_name)
│                      │  # reads: <save>.h5, <save>_threshold.json, <save>_norm.json
└──────────┬───────────┘
           ▼
┌──────────────────────┐  X, _labels, client_ip, order =
│ 2. LOAD INPUT        │     load_multifeature_with_meta(path, features)
└──────────┬───────────┘
           ▼
┌──────────────────────┐  Xn = (X - norm["min"]) / norm["range"]
│ 3. APPLY SAVED       │  # same scaler as training
│    NORMALIZATION     │
└──────────┬───────────┘
           ▼
┌──────────────────────┐  windows, last_idx, _ = build_client_windows(
│ 4. BUILD WINDOWS     │                           Xn, client_ip, order,
│                      │                           window_size)
│                      │  # SAME function as training → same semantics
└──────────┬───────────┘
           ▼
┌──────────────────────┐  reconstructed = model.predict(windows)
│ 5. RECONSTRUCT       │  errors        = mean((windows - reconstructed)²,
│                      │                        axis=(1,2))
│                      │  # per-window scalar error, shape (n_win,)
└──────────┬───────────┘
           ▼
┌──────────────────────┐  z = (errors - error_mean) / error_std
│ 6. z-score →         │  score_B = sigmoid(z)   # ∈ (0,1)
│    sigmoid → score_B │  # for fusion with Path A's score
└──────────┬───────────┘
           ▼
┌──────────────────────┐  anomalies = (errors > threshold).astype(int)
│ 7. ANOMALY           │
│    DECISION          │
└──────────┬───────────┘
           ▼
┌──────────────────────┐  n = len(X)
│ 8. ASSIGN SCORE to   │  out_scores = zeros(n); out_anom = zeros(n)
│    EACH WINDOW'S     │  covered   = zeros(n, dtype=bool)
│    LAST RECORD       │  out_scores[last_idx] = scores
│                      │  out_anom[last_idx]   = anomalies
│                      │  covered[last_idx]    = True
└──────────┬───────────┘
           ▼
┌──────────────────────┐  OUTPUT CSV:
│ 9. WRITE OUTPUTS     │    ml_score_B, is_anomaly, scored, verdict_B
│                      │  Records not at window end: score=0, scored=False
└──────────────────────┘
```

**Why score only the LAST record of each window?**
Any other choice double-counts. A record in the middle of a client's stream is the "last record" of exactly one window ending at it. Attributing the window's verdict to the last record makes the output **one-score-per-record** and keeps alignment with Path A straightforward.

---

## 12. The soft score (`ml_score_B`) — how fusion-ready output is made

Raw reconstruction error is **unbounded** (0 to very large). For fusion with Path A's `ml_score_A ∈ [0,1]`, we need a bounded score. Path B uses a **z-score sigmoid**:

```python
def normalize_scores(errors, error_mean, error_std):
    z = (errors - error_mean) / error_std
    return 1.0 / (1.0 + np.exp(-z))     # sigmoid → (0, 1)
```

**Visual:**

```
errors (raw)      z-score                   sigmoid → ml_score_B
──────────────    ─────────────────────    ────────────────────
0.001 (easy)     (0.001 - 0.008) / 0.015    ≈ 0.38      → likely benign
0.040 (hard)     (0.040 - 0.008) / 0.015    ≈ 0.89      → suspicious
0.120 (anomaly)  (0.120 - 0.008) / 0.015    ≈ 0.99+     → anomaly
```

**Note:** the hard anomaly/not-anomaly decision uses the saved **threshold** on raw error, *not* the sigmoid score. The sigmoid is purely for the fusion layer.

---

## 13. The artifact set — what Path B owns on disk

```
models/
├── dns_trafficformer.h5                   # Keras autoencoder weights
├── dns_trafficformer_norm.json            # per-feature min-range (train-derived)
├── dns_trafficformer_threshold.json       # p99 threshold + error stats
└── evaluation_metrics.json                # shared with Path A; Path B owns "path_b" key
```

**Contents of `evaluation_metrics.json` → `path_b`:**
```json
{
  "precision": 0.87,
  "recall":    0.74,
  "f1":        0.80,
  "pr_auc":    0.91,
  "pr_auc_baseline": 0.07,
  "roc_auc":   0.96,
  "threshold": 0.0423,
  "threshold_method": "percentile_99",
  "window_size": 20,
  "features": ["query_length", "query_entropy", "subdomain_count", "digit_ratio", "longest_label"],
  "split_sizes": {
    "train_windows":          8420,
    "val_windows":            1812,
    "test_windows":           1803,
    "benign_train_windows":   7980
  },
  "test_support": { "benign": 1710, "attack": 93 }
}
```

---

## 14. Data shapes — a cheat sheet

| Stage | Variable | Shape | Notes |
|---|---|---|---|
| Raw load | `X` | `(N, 5)` | PATH_B_FEATURES only |
| Raw load | `labels`, `client_ip`, `order` | `(N,)` each | metadata for splitting + windowing |
| After split (per class, chronological) | `X[train]` | `(≈0.70·N, 5)` | train chunk only |
| After normalize | `Xn` | `(N, 5)` | min-range scaled per feature |
| After `build_client_windows` | `windows` | `(n_win, N_DAYS, 5)` | per host, time-ordered |
| After `build_client_windows` | `last_idx` | `(n_win,)` | row index of each window's last record |
| After `build_client_windows` | `y_win` | `(n_win,)` | max of labels in window |
| Benign-only train input | `x_train_ben` | `(n_benign_win, N_DAYS, 5)` | the model only ever sees these |
| Model output (reconstruction) | `recon` | `(n_win, N_DAYS, 5)` | same shape as input |
| Per-window MSE | `errors` | `(n_win,)` | mean over (window_size, F) axes |
| Score (sigmoid of z) | `scores` | `(n_win,)` | in (0, 1) |
| Final per-record output | `out_scores`, `out_anom`, `covered` | `(N,)` each | aligned to original row order |

---

## 15. Error-handling / fallback map

| Condition | Behavior | Code location |
|---|---|---|
| Threshold JSON missing at inference | Fall back to `threshold = 0.01`, `window_size = 20` | `load_model_artifacts`, lines 71-73 |
| Normalization JSON missing | Use `min=0, range=1` (raw values — accuracy drops) | lines 86-89 |
| Old single-feature `.json` format | Promote scalar to 1-element list | lines 82-83 |
| Fewer than `MIN_BENIGN=10` benign train windows | Fall back to ALL train windows with a warning | lines 208-211 |
| Fewer than `MIN_BENIGN=10` benign val windows | Calibrate on ALL val windows with a warning | lines 215-218 |
| Zero per-client windows (clients too short) | Hard error — "lower --n_days or add traffic" | lines 200-202 |
| Test set has one class | Skip classification metrics; print warning | lines 307-309 |
| `error_std == 0` in score normalization | Return all-zero scores (avoid divide-by-zero) | lines 142-143 |

---

## 16. The whole thing in 20 lines (mentor pitch)

```
Path B is an UNSUPERVISED anomaly detector for DNS tunneling.

INPUT:  labeled features JSON with timestamp + client_ip + 5 continuous features
FEATS:  query_length, query_entropy, subdomain_count, digit_ratio, longest_label

PIPELINE (training):
  1. stratified-CHRONOLOGICAL 70/15/15 split per class (benign/attack separately)
  2. per-feature min-range normalization from TRAIN rows only (saved as JSON)
  3. build sliding windows WITHIN each client's time-ordered stream (never crosses hosts)
  4. filter: keep BENIGN windows only
  5. train Trafficformer autoencoder (3 Pre-LN blocks + MLP + linear reconstruction)
       - loss = MSE(input, output); Adam lr=1e-4; EarlyStopping on val_loss
  6. compute reconstruction errors on BENIGN VAL windows
  7. threshold = 99th percentile of those errors (robust to right-skewed error dist)
  8. evaluate on mixed TEST → F1, PR-AUC, ROC-AUC → merge into evaluation_metrics.json

PIPELINE (inference):
  load artifacts → load scalar norm JSON → build windows → reconstruct → MSE
  → anomaly = (error > threshold) → score_B = sigmoid(z-score of error)
  → assign to each window's LAST record → write per-record CSV with ml_score_B

OUTPUT:  ml_score_B ∈ (0,1), is_anomaly ∈ {0,1}, scored ∈ {T,F}, verdict_B
```

---

## 17. Three questions a mentor will ask

**1. "Why benign-only training? Why not just train supervised like Path A?"**
> "Two reasons. First, we don't trust that we've labeled every attack family — a supervised model only recognizes what it's seen. Second, Path B is explicitly a *novelty detector* complement to Path A. By never showing it attacks during training, we force it to learn a tight description of normal, so anything unlike normal — including attacks we've never seen — lights up as anomalous."

**2. "Why windows per client and not global sliding windows?"**
> "A sequence that mixes two clients isn't a real conversation — it's a time-shuffled artifact of our capture. A window of (client A record, client B record, client A record) would teach the model that A and B's traffic patterns are temporally related, which they aren't. Per-client windowing respects actual sessions."

**3. "Why percentile threshold and not mean + k·σ?"**
> "Benign reconstruction errors are right-skewed, not Gaussian. mean + k·σ either misses the long tail (false negatives) or flags normal tail traffic (false positives). The 99th percentile is non-parametric — it just says 'flag the top 1% of what we've already seen is normal.' It's the right tool for a one-tailed decision on a skewed distribution."
