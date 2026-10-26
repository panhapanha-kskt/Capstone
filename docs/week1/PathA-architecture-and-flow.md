# Path A — Architecture & End-to-End Flow

Source file: [`src/dns_detect/models/path_a.py`](../../src/dns_detect/models/path_a.py)
Companion doc: [`PathA-explaination.md`](./PathA-explaination.md) (deep dive on *why* each choice was made)

This document is the **architectural map** of Path A — the pictures, the data shapes, the file I/O, and the exact flow of bytes from raw input to final verdict.

---

## 0. High-level system diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PATH A — BINARY DNS CLASSIFIER                     │
│                             (benign vs. attack)                              │
└─────────────────────────────────────────────────────────────────────────────┘

   INPUT                    PARSING             FEATURIZATION        MODELS
   ─────                    ───────             ─────────────        ──────
┌──────────┐           ┌─────────────┐        ┌──────────────┐   ┌─────────┐
│  PCAP    │──────┐    │             │        │              │   │   RF    │
│  (.pcap) │      │    │ dns_parser  │        │  FEATURES_8  │   │ (200    │
└──────────┘      │    │             │───────▶│  per record  │──▶│  trees) │
┌──────────┐      ├───▶│ load_as_    │        │              │   └────┬────┘
│   CSV    │      │    │ dataframe() │        │ query_length │        │
│ (labeled)│      │    │             │        │ query_entropy│        │ soft
└──────────┘      │    │ · normalize │        │ has_digits   │        │ vote
┌──────────┐      │    │   week3 cols│        │ answer_count │        ▼
│ week3    │──────┘    │ · derive    │        │ subdomain_cnt│    ┌──────┐
│  JSON    │           │   missing   │        │ longest_label│    │ MEAN │
└──────────┘           │ · fill NaN  │        │ digit_ratio  │    │ 50/50│
                       │             │        │ unique_char_ │    └──┬───┘
                       └─────────────┘        └──────┬───────┘       │
                                                     │          ┌────┴────┐
                                                     │          │  GBT    │
                                                     │          │ (histo- │
                                                     │          │  gram)  │
                                                     ▼          └─────────┘
                                            ┌──────────────┐
                                            │ StandardScaler│
                                            │  (fit on     │
                                            │   TRAIN only)│
                                            └──────┬───────┘
                                                   │
                            ┌──────────────────────┴──────────────────────┐
                            │                                             │
                            ▼                                             ▼
                   ┌─────────────────┐                          ┌──────────────┐
                   │  TRAINING MODE  │                          │ INFERENCE    │
                   │  (--train)      │                          │ MODE         │
                   └────────┬────────┘                          │ (--infer)    │
                            │                                   └──────┬───────┘
                            ▼                                          │
              ┌─────────────────────────────┐                          │
              │ Stratified 70/15/15 split   │                          │
              │ (train / val / test)        │                          │
              └────────────┬────────────────┘                          │
                           ▼                                           │
              ┌─────────────────────────────┐                          │
              │ Train RF, GBT, Transformer  │                          │
              └────────────┬────────────────┘                          │
                           ▼                                           │
              ┌─────────────────────────────┐                          │
              │ Threshold calibration on VAL│                          │
              │   for {rf_only, rf_gbt}     │                          │
              └────────────┬────────────────┘                          │
                           ▼                                           │
              ┌─────────────────────────────┐                          │
              │ DECISION GATE on TEST       │                          │
              │  pick winner by F1          │                          │
              │  tie → ensemble (rf_gbt)    │                          │
              └────────────┬────────────────┘                          │
                           ▼                                           │
          ┌────────────────────────────────┐                           │
          │ PERSIST ARTIFACTS to disk      │◀──────────────────────────┤
          │  dns_rf_model.pkl              │                           │
          │  dns_gbt_model.pkl             │     load_path_a_models()  │
          │  dns_transformer_model.keras   │                           │
          │  dns_scaler.pkl                │                           │
          │  dns_threshold.json            │                           │
          │  evaluation_metrics.json       │                           │
          └────────────────────────────────┘                           │
                                                                       ▼
                                                        ┌───────────────────────┐
                                                        │ tree_ensemble_scores()│
                                                        │  → apply threshold    │
                                                        │  → emit verdict       │
                                                        └──────────┬────────────┘
                                                                   ▼
                                                        ┌──────────────────────┐
                                                        │ OUTPUTS              │
                                                        │  <stem>_model_       │
                                                        │    results.csv       │
                                                        │  enriched JSON       │
                                                        │  (fusion-ready)      │
                                                        └──────────────────────┘
```

---

## 1. The three input paths — all roads lead to one DataFrame

Path A accepts three input types; `dns_parser.load_as_dataframe()` is the single funnel that normalizes them.

```
┌─────────────┐
│  .pcap      │ ──▶ scapy → extract DNS layers → compute FEATURES_8 → DataFrame
└─────────────┘
┌─────────────┐
│  .csv       │ ──▶ pandas.read_csv → rename cols → DataFrame
└─────────────┘      (expects FEATURES_8 columns + label)

┌─────────────┐
│ week3 .json │ ──▶ json.load → _normalize_week3_columns() → DataFrame
└─────────────┘      renames: entropy→query_entropy, etc.
```

**Output shape (all three paths):**
```
DataFrame with columns:
  query_length, query_entropy, has_digits, answer_count,
  subdomain_count, longest_label, digit_ratio, unique_char_ratio,
  label                               ← required for training
  attack_family                       ← optional, enables per-family recall
  domain                              ← optional, used to derive missing features
```

---

## 2. Featurization — the 8 numbers per record

Every record becomes an 8-dim vector. Formulas computed in [`dns_parser.py:99-106`](../../src/dns_detect/parsing/dns_parser.py#L99-L106):

```python
features = {
    "query_length":      len(query),
    "query_entropy":     shannon_entropy(query),
    "has_digits":        int(any(c.isdigit() for c in query)),
    "answer_count":      len(dns_response.answers),
    "subdomain_count":   query.count("."),
    "longest_label":     max(len(label) for label in query.split(".")),
    "digit_ratio":       sum(c.isdigit() for c in query) / len(query),
    "unique_char_ratio": len(set(query)) / len(query),
}
```

**Resulting matrix shape:**
```
       query_length  query_entropy  has_digits  answer_count  ...  unique_char_ratio
rec_0       12            3.42          0            1        ...        0.75
rec_1       87            4.91          1            0        ...        0.42
rec_2       15            3.11          0            1        ...        0.80
...
rec_N      224            5.03          1            0        ...        0.31

Shape: (N_records, 8)
```

---

## 3. The training pipeline — step by step

> **Plain English:** This is what happens when you run `python path_a.py --train some_file.json`. The diagram below shows **16 numbered steps** in order. Read them like a recipe — each box describes *one thing the code does*, with the actual Python next to it. The boxes on the **left** are the step name; the text on the **right** is the code that runs. Steps 1–8 prepare the data, steps 9–11 train the three models, steps 12–16 decide which model wins and save everything.
>
> **The three big ideas to notice:**
> 1. **Steps 5–7 happen in a strict order** — split *first*, then scale. If you scale before splitting, test-set statistics leak into training (see §6 of [PathA-explaination.md](./PathA-explaination.md)).
> 2. **Steps 9 and 10 train two independent models** on the exact same training data. We'll let them disagree and average later.
> 3. **Steps 12–13 are the "decision gate"** — we train both the RF-only and RF+GBT candidates, calibrate thresholds for each on the *validation* set, then test both on the *test* set. The one with higher F1 wins. This is why we need three splits (train/val/test), not two.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  run_training(input_file, shuffle=False)                                     │
└─────────────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────┐
│ 1. LOAD            │   df = load_as_dataframe(input_file)
│                    │   Shape: (N, 10+)  rows=records, cols=features+label+family
└──────────┬─────────┘
           ▼
┌────────────────────┐
│ 2. FILL MISSING    │   for feat in FEATURES_8:
│    FEATURES        │       if feat not in df: df[feat] = 0
└──────────┬─────────┘
           ▼
┌────────────────────┐
│ 3. VALIDATE LABELS │   if "label" not in df: RAISE
│                    │   Hint: run ml_bridge.py first
└──────────┬─────────┘
           ▼
┌────────────────────┐
│ 4. SINGLE-CLASS    │   if df["label"].nunique() < 2: RAISE
│    GUARD           │   Prevents half-overwriting prod models
└──────────┬─────────┘
           ▼
┌────────────────────┐   X   = df[FEATURES_8].values            # (N, 8)
│ 5. EXTRACT         │   y   = df["label"].values               # (N,)
│    X, y, fam       │   fam = df.get("attack_family", None)
└──────────┬─────────┘
           ▼
┌────────────────────┐   X_tmp, X_test, y_tmp, y_test, fam_tmp, fam_test =
│ 6. STRATIFIED      │     train_test_split(X, y, fam,
│    SPLIT           │                      test_size=0.30,
│    70/15/15        │                      stratify=y,
│                    │                      random_state=42)
│                    │
│                    │   X_train, X_val, y_train, y_val, fam_train, fam_val =
│                    │     train_test_split(X_tmp, y_tmp, fam_tmp,
│                    │                      test_size=0.50,
│                    │                      stratify=y_tmp,
│                    │                      random_state=42)
└──────────┬─────────┘
           ▼                            Shapes:
                                        X_train (0.70N, 8)   y_train (0.70N,)
                                        X_val   (0.15N, 8)   y_val   (0.15N,)
                                        X_test  (0.15N, 8)   y_test  (0.15N,)
┌────────────────────┐
│ 7. FIT SCALER      │   scaler = StandardScaler().fit(X_train)
│    ON TRAIN ONLY   │   X_train = scaler.transform(X_train)
│                    │   X_val   = scaler.transform(X_val)
│                    │   X_test  = scaler.transform(X_test)
│                    │   joblib.dump(scaler, "dns_scaler.pkl")
└──────────┬─────────┘
           ▼
┌────────────────────┐
│ 8. OPTIONAL:       │   if shuffle: np.random.shuffle(y_train)
│    SHUFFLE LABELS  │   (leakage sanity check — metrics should drop to chance)
└──────────┬─────────┘
           ▼
┌────────────────────┐
│ 9. TRAIN RF        │   rf = RandomForestClassifier(
│                    │           n_estimators=200,
│                    │           class_weight="balanced",
│                    │           random_state=42, n_jobs=-1).fit(X_train, y_train)
│                    │   joblib.dump(rf, "dns_rf_model.pkl")
└──────────┬─────────┘
           ▼
┌────────────────────┐
│10. TRAIN GBT       │   gbt = HistGradientBoostingClassifier(
│                    │            learning_rate=0.1, max_iter=300,
│                    │            class_weight="balanced",
│                    │            early_stopping=True,
│                    │            validation_fraction=0.15,
│                    │            random_state=42).fit(X_train, y_train)
│                    │   joblib.dump(gbt, "dns_gbt_model.pkl")
└──────────┬─────────┘
           ▼
┌────────────────────┐
│11. TRAIN           │   # Build sliding windows of length 10
│    TRANSFORMER     │   X_seq, y_seq = make_sequences(X_train, y_train, seq_len=10)
│    (baseline)      │   Shape: (N-9, 10, 8)
│                    │
│                    │   transformer = build_model(...)   # 2 Pre-LN blocks
│                    │   transformer.fit(X_seq, y_seq,
│                    │                   epochs=30, batch_size=32,
│                    │                   callbacks=[EarlyStopping(monitor="val_auc",
│                    │                                            mode="max",
│                    │                                            restore_best_weights=True)])
│                    │   transformer.save("dns_transformer_model.keras")
└──────────┬─────────┘
           ▼
┌────────────────────┐
│12. CALIBRATE       │   For each candidate ∈ {"rf_only", "rf_gbt"}:
│    THRESHOLDS      │     scores_val = tree_ensemble_scores(rf, gbt, X_val, candidate)
│    ON VAL          │     p, r, thr  = precision_recall_curve(y_val, scores_val)
│                    │     f1         = 2*p*r / (p+r + eps)
│                    │     threshold[candidate] = thr[argmax(f1[:-1])]
└──────────┬─────────┘
           ▼
┌────────────────────┐
│13. DECISION GATE   │   For each candidate:
│    ON TEST         │     scores_test = tree_ensemble_scores(rf, gbt, X_test, candidate)
│                    │     block[candidate] = _metric_block(y_test, scores_test,
│                    │                                       threshold[candidate])
│                    │
│                    │   if block["rf_gbt"].f1 >= block["rf_only"].f1:
│                    │       decision = "rf_gbt"
│                    │   else:
│                    │       decision = "rf_only"
└──────────┬─────────┘
           ▼
┌────────────────────┐
│14. PERSIST         │   json.dump({"threshold": threshold[decision],
│    (threshold,     │              "decision":  decision},
│     decision)      │             open("dns_threshold.json", "w"))
└──────────┬─────────┘
           ▼
┌────────────────────┐
│15. FINAL REPORT    │   • classification_report on y_test, preds[decision]
│                    │   • PR-AUC primary, ROC-AUC secondary
│                    │   • Per-family recall (if `fam` column present)
└──────────┬─────────┘
           ▼
┌────────────────────┐
│16. MERGE METRICS   │   metrics = json.load("evaluation_metrics.json")
│    into shared     │   metrics["path_a"] = {
│    JSON            │       **block[decision],
│       (read-merge- │       "decision": decision,
│        write)      │       "candidates": {"rf_only": block["rf_only"],
│                    │                      "rf_gbt":  block["rf_gbt"]},
│                    │       "transformer_baseline": tf_metrics,
│                    │       "shuffle_labels":       shuffle_metrics,
│                    │       "recall_by_family":     recall_by_family,
│                    │       "seed": 42,
│                    │       "split_sizes": {...},
│                    │       "test_support": {...},
│                    │   }
│                    │   json.dump(metrics, open("evaluation_metrics.json", "w"))
└────────────────────┘
```

---

## 4. The decision gate — why both candidates run on test

> **Plain English:** We don't *assume* the ensemble (RF+GBT) is better than RF alone — we **measure it on real held-out data**. Here's the trick: we train both candidates once, then evaluate each one on *val* to find its best threshold, and *then* on *test* to see which actually performs better. The winner's `(threshold, decision)` is saved to disk, and from that moment on, **inference always uses the winning candidate** — never the loser.
>
> **Why this is honest:**
> - RF-only might win because the GBT just adds noise on this dataset.
> - RF+GBT might win because the two trees see things differently and their disagreement is informative.
> - **We don't know in advance** — so we let the data decide.
>
> **Why each candidate uses its own threshold:**
> If we gave the ensemble the same threshold as RF-only, we'd be comparing them unfairly (their probability distributions are different). Each one gets its own best-F1 threshold on val, and *then* they compete on test at those thresholds. That's a fair fight.

```
                        ┌─────────────────────────┐
                        │   Trained RF, GBT       │
                        └───────────┬─────────────┘
                                    │
          ┌─────────────────────────┴─────────────────────────┐
          │                                                   │
          ▼                                                   ▼
┌──────────────────────┐                        ┌──────────────────────┐
│  Candidate A:        │                        │  Candidate B:        │
│  rf_only             │                        │  rf_gbt (soft-vote)  │
└──────────┬───────────┘                        └──────────┬───────────┘
           │                                               │
           ▼                                               ▼
    scores on VAL                                    scores on VAL
           │                                               │
           ▼                                               ▼
   calibrate_threshold                            calibrate_threshold
   → thr_rf (max F1 on val)                       → thr_cmb (max F1 on val)
           │                                               │
           ▼                                               ▼
    scores on TEST                                   scores on TEST
    applied at thr_rf                                applied at thr_cmb
           │                                               │
           ▼                                               ▼
    block_rf = {prec, rec, f1,                     block_cmb = {prec, rec, f1,
                pr_auc, roc_auc}                               pr_auc, roc_auc}
           │                                               │
           └───────────────────────┬───────────────────────┘
                                   ▼
                       ┌──────────────────────────┐
                       │  if block_cmb.f1 >=      │
                       │     block_rf.f1:         │
                       │       decision = "rf_gbt"│
                       │  else:                   │
                       │       decision = "rf_only"│
                       └──────────────┬───────────┘
                                      ▼
                     ┌──────────────────────────────┐
                     │ Save (threshold, decision)   │
                     │ to dns_threshold.json        │
                     └──────────────────────────────┘
```

**Key invariant:** each candidate uses its *own* calibrated threshold on test. The ensemble doesn't borrow RF's threshold — that would be an unfair comparison.

---

## 5. The soft-vote math

> **Plain English:** "Soft-vote" sounds fancy; it's **just an average**. Each tree model outputs a *probability* that a record is an attack (a number between 0 and 1). RF says "I'm 82% sure" and GBT says "I'm 91% sure" → the ensemble's answer is `(0.82 + 0.91) / 2 = 0.865`. Then we compare that average to the saved threshold.
>
> **Why "soft" instead of "hard" vote:**
> - **Hard vote** would be: each model says 0 or 1, and we count votes. With only 2 models, hard voting always ties on disagreement. Useless.
> - **Soft vote** keeps the *confidence*. If RF says 0.51 (barely attack) and GBT says 0.89 (very confidently attack), soft-voting correctly treats this as "pretty confidently attack" (0.70). Hard voting would have called it 1-1 tie.
>
> **Why 50/50 and not weighted:**
> We didn't tune the weights. 50/50 is the simplest baseline and avoids a hyperparameter that needs its own validation holdout. If one model is clearly stronger, the decision gate (§4) picks RF-only instead of the ensemble, which is cleaner than weight tuning.

```
┌─────────────────────────────────────────────────────────────────────┐
│  tree_ensemble_scores(rf, gbt, X, decision)                          │
└─────────────────────────────────────────────────────────────────────┘

rf_probs  = rf.predict_proba(X)[:, 1]      # P(attack) from RF    shape (N,)

if decision == "rf_only" or gbt is None:
    return rf_probs

gbt_probs = gbt.predict_proba(X)[:, 1]     # P(attack) from GBT   shape (N,)
return 0.5 * (rf_probs + gbt_probs)        # equal-weight average shape (N,)
```

**Visual:**
```
    RF           GBT           Soft-vote
    ──           ───           ─────────
    0.82         0.91          (0.82 + 0.91) / 2 = 0.865  →  >= 0.60 threshold  →  ATTACK
    0.14         0.08          (0.14 + 0.08) / 2 = 0.110  →   < 0.60 threshold  →  benign
    0.55         0.42          (0.55 + 0.42) / 2 = 0.485  →   < 0.60 threshold  →  benign
    0.73         0.68          (0.73 + 0.68) / 2 = 0.705  →  >= 0.60 threshold  →  ATTACK
```

---

## 6. The Transformer baseline — detailed block diagram

> **Plain English:** The Transformer looks at a **sliding window of 10 consecutive DNS records** from the same stream, and predicts whether the *last* record in the window is an attack. The idea: maybe looking at a *sequence* of records (burstiness, repeated patterns) reveals attacks that looking at records one-at-a-time can't catch.
>
> **How to read the diagram below:**
> - **Each "Encoder Block"** = one layer of "pay attention to all the other records in the window + reshape each record's features." Two blocks stacked = the model does this twice.
> - **`MultiHeadAttention(x, x)`** = each record in the window asks "which of my 9 neighbors should I pay attention to?" "Multi-head" just means it asks that question from several angles in parallel.
> - **`Conv1D(kernel=1)`** = a tiny per-timestep MLP (reshapes each record's features without mixing across time). Keras uses Conv1D-with-kernel-1 as a shortcut for "Dense layer applied to each timestep independently."
> - **`LayerNorm` before each sublayer** = this is "Pre-LN" style. Trains more stably than the original 2017 "Post-LN" (which put LayerNorm *after* each sublayer).
> - **`GlobalAveragePooling1D`** = collapse the window of 10 records into a single 8-dim vector by averaging across time. Now we have one representation per window.
> - **`Dense(1, sigmoid)`** = final output: one probability per window.
>
> **Why it exists but doesn't get to vote:** On 8-feature tabular data, trees still beat Transformers. We trained this baseline *honestly* — real val split, real early-stopping, published metrics — so the paper can defensibly say "we tried a sequence model and it lost."

```
INPUT: sequence of 10 consecutive records, each 8-dim           (batch, 10, 8)
                                │
                                ▼
                   ╔════════════════════════════╗
                   ║      ENCODER BLOCK 1       ║
                   ╚════════════╦═══════════════╝
                                │
                                ▼
            ┌──────────────────────────────────────┐
            │  x_norm = LayerNorm(x)               │
            │  attn   = MultiHeadAttention(        │
            │             num_heads=2,              │
            │             head_size=32,             │
            │             query=x_norm,             │
            │             value=x_norm)             │
            │  attn   = Dropout(0.1)(attn)         │
            │  x      = x + attn        ← residual │
            └──────────────┬───────────────────────┘
                           ▼
            ┌──────────────────────────────────────┐
            │  x_norm = LayerNorm(x)               │
            │  ff     = Conv1D(ff_dim=64,          │
            │                   kernel_size=1,     │
            │                   activation="relu") │
            │           (x_norm)                   │
            │  ff     = Dropout(0.1)(ff)           │
            │  ff     = Conv1D(channels=8,         │
            │                   kernel_size=1)(ff) │
            │  x      = x + ff          ← residual │
            └──────────────┬───────────────────────┘
                           ▼
                   ╔════════════════════════════╗
                   ║      ENCODER BLOCK 2       ║
                   ║   (same as Block 1)        ║
                   ╚════════════╦═══════════════╝
                                │
                                ▼                              (batch, 10, 8)
                   ┌─────────────────────────┐
                   │ GlobalAveragePooling1D  │  → collapse time axis
                   └────────────┬────────────┘                 (batch, 8)
                                ▼
                   ┌─────────────────────────┐
                   │  Dense(64, relu)        │
                   └────────────┬────────────┘                 (batch, 64)
                                ▼
                   ┌─────────────────────────┐
                   │  Dropout(0.1)           │
                   └────────────┬────────────┘
                                ▼
                   ┌─────────────────────────┐
                   │  Dense(1, sigmoid)      │ → probability of attack
                   └────────────┬────────────┘                 (batch, 1)
                                ▼
                      LOSS: binary_crossentropy
                      OPTIMIZER: Adam
                      METRICS: accuracy, AUC
```

**Note:** this is **Pre-LN** style (LayerNorm *before* the sublayer). The original 2017 Transformer paper used Post-LN. Pre-LN trains more stably without needing warmup — see Xiong et al. 2020.

**Sequence construction (sliding window):**
```
Record indices: 0 1 2 3 4 5 6 7 8 9 10 11 12 ...
                └─────── window 0 ────────┘               label = y[9]
                  └─────── window 1 ────────┘             label = y[10]
                    └─────── window 2 ────────┘           label = y[11]
                                        ...
```

---

## 7. The inference pipeline

> **Plain English:** This is what happens when you run `python path_a.py --infer new_capture.pcap` to score **new, unlabeled** traffic. The whole point of training was to produce the artifacts we now load from disk. Inference **must mirror training exactly** — same features, same scaler, same ensemble function, same threshold — or you'd introduce silent bugs where training and inference disagree on how to score the same record.
>
> **The golden rule shown in the diagram:**
> **Step 4** uses the **saved scaler from training** (not a fresh one). If we re-fit a scaler on the inference data, each inference batch would have different scaling → the model's learned decision boundaries would be meaningless. The saved `.pkl` guarantees inference uses the exact mean/std the model was trained to expect.
>
> **Why Step 5 calls the *same* `tree_ensemble_scores()` function as training:**
> This is deliberate — zero code duplication. During training this function scored val and test; during inference it scores production records. If a bug were ever introduced, it would break both training and inference consistently (easy to catch) instead of just one of them (silent production incidents).
>
> **The three output columns** (`ml_score_A`, `ml_label_A`, `ml_verdict_A`): one for the probability, one for the 0/1 decision, one for human-readable "ATTACK"/"benign". The CSV is for humans; the enriched JSON (if `--output-json` is set) is week3-schema-compatible so it can be fed into the downstream fusion step without further transformation.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  run_inference(input_file, output_json=None)                                 │
└─────────────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────┐
│ 1. LOAD MODELS     │   rf, gbt, scaler, threshold, decision =
│                    │       load_path_a_models()
│                    │   # reads: dns_rf_model.pkl, dns_gbt_model.pkl,
│                    │   #        dns_scaler.pkl, dns_threshold.json
└──────────┬─────────┘
           ▼
┌────────────────────┐   df = load_as_dataframe(input_file)
│ 2. LOAD INPUT      │   # same funnel as training: pcap/csv/json → DataFrame
└──────────┬─────────┘
           ▼
┌────────────────────┐
│ 3. FILL MISSING    │   for feat in FEATURES_8:
│    FEATURES        │       if feat not in df: df[feat] = 0
└──────────┬─────────┘
           ▼
┌────────────────────┐   X = df[FEATURES_8].values           # (N, 8)
│ 4. EXTRACT X       │   X = scaler.transform(X)             # use SAVED scaler
│    + SCALE         │
└──────────┬─────────┘
           ▼
┌────────────────────┐   scores = tree_ensemble_scores(      # same function
│ 5. SCORE           │                rf, gbt, X, decision)  # as training
│    (ensemble)      │                                       # shape (N,)
└──────────┬─────────┘
           ▼
┌────────────────────┐
│ 6. APPLY THRESHOLD │   preds = (scores >= threshold).astype(int)
└──────────┬─────────┘
           ▼
┌────────────────────┐   df["ml_score_A"]   = scores
│ 7. APPEND COLS     │   df["ml_label_A"]   = preds
│                    │   df["ml_verdict_A"] = ["ATTACK" if p else "benign"
│                    │                         for p in preds]
└──────────┬─────────┘
           ▼
┌────────────────────┐   df.to_csv(f"{input_stem}_model_results.csv")
│ 8. WRITE OUTPUTS   │   if output_json:
│                    │       write enriched JSON (week3-compatible for fusion)
└────────────────────┘
```

---

## 8. The artifact set — what Path A owns on disk

> **Plain English:** These are the **6 files Path A writes to disk** after training. They are everything inference needs to score new records — no retraining required. Think of these as the "frozen brain" of Path A.
>
> **What each file is for:**
> - **`dns_rf_model.pkl`** — the trained Random Forest. A pickled sklearn object containing 200 trees and their learned splits.
> - **`dns_gbt_model.pkl`** — the trained HistGradientBoosting model. Same idea, but boosted trees.
> - **`dns_transformer_model.keras`** — the Transformer baseline. **Saved for reproducibility but NOT loaded at inference** — the production pipeline is tree-only.
> - **`dns_scaler.pkl`** — the StandardScaler fit on the training rows. This is the one that must be reused at inference (§7's golden rule).
> - **`dns_threshold.json`** — a tiny JSON with two keys: `threshold` (the F1-maximizing probability cutoff) and `decision` (`"rf_only"` or `"rf_gbt"` — which candidate won the gate in §4). Inference reads this to know *which model to use* and *what threshold to apply*.
> - **`evaluation_metrics.json`** — the paper's data source. Contains both candidates' metrics (so a reviewer can see we didn't cherry-pick), the transformer baseline (so a reviewer can see we tried a sequence model), the shuffle-labels check (so a reviewer can see we tested for leakage), split sizes, test support, random seed, and the final per-family recall. This is Path A's **auditable receipt**.
>
> **The read-merge-write pattern** on `evaluation_metrics.json`: Path B *also* writes to this file (under its own `"path_b"` key). To avoid clobbering, we read the current file → update only the `"path_a"` key → write back. This is also why both paths must agree on the file format.

```
models/
├── dns_rf_model.pkl              # RandomForestClassifier (joblib)
├── dns_gbt_model.pkl             # HistGradientBoostingClassifier (joblib)
├── dns_transformer_model.keras   # Keras Transformer baseline (not used in prod)
├── dns_scaler.pkl                # StandardScaler fit on TRAIN only (joblib)
├── dns_threshold.json            # {"threshold": 0.42, "decision": "rf_gbt"}
└── evaluation_metrics.json       # shared with Path B; Path A owns the "path_a" key
```

**Contents of `evaluation_metrics.json` → `path_a`:**
```json
{
  "precision": 0.94,
  "recall":    0.89,
  "f1":        0.91,
  "pr_auc":    0.97,
  "roc_auc":   0.99,
  "threshold": 0.42,
  "decision":  "rf_gbt",
  "candidates": {
    "rf_only": {"precision": ..., "recall": ..., "f1": ..., "pr_auc": ..., "roc_auc": ..., "threshold": ...},
    "rf_gbt":  {"precision": ..., "recall": ..., "f1": ..., "pr_auc": ..., "roc_auc": ..., "threshold": ...}
  },
  "transformer_baseline": {...} | null,
  "shuffle_labels":       {...} | null,
  "recall_by_family":     {"dnscat2": {"recall": 0.92, "n": 2341},
                           "iodine":  {"recall": 0.71, "n":  980}},
  "seed": 42,
  "split_sizes":  {"train": 70000, "val": 15000, "test": 15000},
  "test_support": {"benign": 14250, "attack": 750}
}
```

---

## 9. The data shapes — a cheat sheet

| Stage | Variable | Shape | Notes |
|---|---|---|---|
| Raw load | `df` | `(N, 10+)` | rows = records, cols = features + label + optional |
| Feature extract | `X` | `(N, 8)` | FEATURES_8 only |
| Labels | `y` | `(N,)` | 0 or 1 |
| Family | `fam` | `(N,)` | strings or None |
| After split | `X_train` | `(0.70·N, 8)` | — |
| After split | `X_val` | `(0.15·N, 8)` | — |
| After split | `X_test` | `(0.15·N, 8)` | — |
| After scale | same shapes | — | zero-mean, unit-var per column |
| Transformer input | `X_seq` | `(0.70·N - 9, 10, 8)` | sliding windows of length 10 |
| Transformer labels | `y_seq` | `(0.70·N - 9,)` | label of the *last* record in each window |
| RF scores | `rf_probs` | `(N,)` | P(attack) |
| GBT scores | `gbt_probs` | `(N,)` | P(attack) |
| Soft-vote | `scores` | `(N,)` | mean of rf_probs and gbt_probs |
| Predictions | `preds` | `(N,)` | 0 or 1 after thresholding |

---

## 10. The error-handling / fallback map

| Condition | Behavior | Code location |
|---|---|---|
| Missing feature column in input | Fill with 0 | lines 331-333, 494-496 |
| Missing `label` column at training | Hard error with hint to run `ml_bridge.py` | lines 335-339 |
| Only one class in training data | Hard error — no artifacts written | lines 347-354 |
| GBT model file missing at inference | Fall back to RF-only scoring | line 184 |
| `dns_threshold.json` missing | Fall back to threshold = 0.5 | load_path_a_models |
| `precision_recall_curve` edge case (all same probs) | Try/except → return `None` for AUCs | lines 288-309 |

---

## 11. The whole thing in 20 lines (if a mentor asks for the elevator pitch)

```
Path A is a binary DNS tunneling classifier built on 8 engineered features.

INPUT:  pcap / csv / week3 json  →  normalized DataFrame
FEATS:  query_length, query_entropy, has_digits, answer_count,
        subdomain_count, longest_label, digit_ratio, unique_char_ratio

PIPELINE (training):
  1. stratified 70/15/15 split
  2. StandardScaler fit on TRAIN only (prevents leakage)
  3. train Random Forest (bagging, 200 trees)
  4. train HistGradientBoosting (boosting, 300 iters, early stopping)
  5. train Transformer baseline (sliding window length 10, 2 Pre-LN blocks)
  6. calibrate F1-optimal threshold on VAL for BOTH candidates
  7. decision gate on TEST: pick higher-F1 candidate (ties → ensemble)
  8. persist (threshold, decision) + metrics

PIPELINE (inference):
  load artifacts → scale with SAVED scaler → score via same ensemble func
  → apply saved threshold → emit {ml_score_A, ml_label_A, ml_verdict_A}

OUTPUT:  CSV + enriched JSON (week3-compatible for downstream fusion)
```
