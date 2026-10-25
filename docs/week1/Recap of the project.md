# Recap of the Project — DNS Traffic Anomaly Detection

**Project:** DNS Traffic Anomaly Detection Using Hybrid ML Fusion
**Institution:** CADT — Department of Telecommunications and Networking
**Academic Year:** 2025–2026
**Team:** Mao Sovanrathana, Vutthin Vattanak, Ken Chomnan, Tith Sopanha
**Advisor:** Mr. Roeum Makara

This document is a recap compiled from the full set of files inside [docs/](../). It
summarizes what the system is, how it is built, how data flows end to end, and the
honest state of its results and limitations as of the current branch.

---

## 1. What the project is, in one paragraph

DNS query logs from a **Technitium DNS server** (running in Docker alongside an ELK
stack for visibility) are parsed into per-query feature records. Those records are
scored by **two independent ML paths** — a supervised Random Forest + Gradient Boosting
ensemble (Path A, with a Transformer kept only as a baseline) and an unsupervised
Trafficformer autoencoder (Path B) — whose outputs are **fused** into a combined threat
score. A **detection engine** then applies six rules (four Microsoft Sentinel–style
rules + two ML rules), a per-client Z-score layer, and optional Microsoft Defender
Threat Intelligence enrichment, producing **unified, MITRE ATT&CK–tagged alerts** in
JSON and CSV. A **monitoring** step compares live traffic against the training snapshot
and recommends retraining when drift appears. A C-based **attack simulator** generates
labeled malicious traffic in the lab; an Nginx-based "Phone Store" demo app generates
realistic benign traffic. The whole thing is a **"two-opinion" detector**: Path A is
precise on known attacks, Path B flags novel behavior that deviates from learned-normal
traffic.

---

## 2. High-level architecture

```
                     LAB / RED TEAM                          INFRASTRUCTURE
 ┌─────────────────────────┐                      ┌──────────────────────────────────┐
 │ attacks/attack.c        │  DNS attack traffic  │ Technitium DNS (Docker)          │
 │ (multi-threaded C tool) ├────────────────────► │  → writes query logs             │
 └─────────────────────────┘   lab.local :53      │ Filebeat → Logstash → Elastic/   │
 ┌─────────────────────────┐  benign traffic      │ Kibana  (visibility & hunting)   │
 │ infra/nginx-lab (store) ├────────────────────► │                                  │
 └─────────────────────────┘                      └────────────────┬─────────────────┘
                                                                   │ raw *.log
                                                                   ▼
┌──────────────────── DETECTION PIPELINE (src/dns_detect) ─────────────────────────────┐
│ data/raw/*.log                                                                       │
│    │                                                                                 │
│    ▼  features/extractor.py                                                          │
│ ① FEATURE EXTRACTION  → per-query records + 6 heuristic attack flags                 │
│    │  week3_features_all.json                                                        │
│    ▼  fusion/bridge.py                                                               │
│ ② ML BRIDGE (fusion) ──┬── Path A: models/path_a.py   (RF + GBT, TF baseline)        │
│    │                   └── Path B: models/path_b_predict.py (Trafficformer)          │
│    │  week3_features_with_ml.json  (+10 ML columns)                                  │
│    ▼  detection/engine.py                                                            │
│ ③ DETECTION ENGINE  → 6 rules + Z-score + optional MDTI → unified alerts             │
│    │  week4_unified_alerts.json / .csv                                               │
│    ▼  monitoring/monitor.py                                                          │
│ ④ MONITORING  → PSI drift / alert-volume / score-health → retrain recommendation     │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

Two shell orchestrators drive this: [`scripts/train_models.sh`](../../scripts/train_models.sh)
(build the models) and [`scripts/run_pipeline.sh`](../../scripts/run_pipeline.sh)
(score new logs using those models).

---

## 3. Components, at a glance

| Area | Files |
|------|-------|
| Config / paths | `src/dns_detect/config.py`, `src/dns_detect/utils/paths.py`, `config/settings.yaml` |
| Shared parser | `src/dns_detect/parsing/dns_parser.py` (handles `.log`, `.json`, `.csv`, `.pcap`, `.traff`) |
| Stage ① Features | `src/dns_detect/features/extractor.py`, `src/dns_detect/features/eda.py` |
| Stage ② ML paths | `src/dns_detect/models/path_a.py` (RF + GBT + TF), `path_b_train.py`, `path_b_predict.py` |
| Stage ② Fusion | `src/dns_detect/fusion/bridge.py` |
| Stage ③ Detection | `src/dns_detect/detection/engine.py` (6 rules + Z-score + MDTI) |
| Stage ④ Monitoring | `src/dns_detect/monitoring/monitor.py` (PSI drift + alert health) |
| Orchestration | `scripts/train_models.sh`, `scripts/run_pipeline.sh`, `scripts/pipeline_awareness_check.sh` (auto-generated) |
| Red team | `attacks/attack.c`, `attacks/Makefile` |
| Lab infra | `infra/technitium-elk/` (Technitium + ELK Docker stack), `infra/nginx-lab/` (Phone Store benign traffic) |

Nothing is hardcoded to a machine: `utils/paths.py` finds `PROJECT_ROOT` by walking up
to `config/settings.yaml`; `config.py` exposes a dot-accessible `settings` object with
env overrides. Models live in `models/`, data in `data/raw` and `data/processed`, run
logs in `logs/`.

---

## 4. The flow — training

Goal: turn raw logs into **trained models + calibrated thresholds + metadata**. Driven
by `scripts/train_models.sh`.

```
STEP: SOURCE DISCOVERY
  Collect inputs from --data-dir / --files / default data/raw
  SHA256 each file and look it up in trained_files_registry.json
    --retrain       → skip files already in the registry
    --force-retrain → ignore registry, take everything
    default         → train only if a path's models are missing
  Bucket survivors into SRC_LOG / SRC_PCAP / SRC_JSON / SRC_CSV
          │
          ▼
STEP 0-A/0-B: PRE-PROCESS
  .log  → features.extractor --input L --output J
  .pcap → tshark → dns_parser → J
          │
          ▼
STEP 0-C: MERGE
  Concat JSON + CSV → data/processed/merged_features_all.json
  Write training_provenance.json (sources, counts, checksums)
          │
          ▼
STEP 0-D: EDA (non-gating)
  features.eda → eda_report.json
          │
          ▼
STEP 1: LABEL
  fusion.bridge --label-only → merged_features_labeled.json
  (preferred: provenance labels from data/attack_manifest.csv;
   fallback: heuristic labels from attack_count ≥ 1)
          │
    ┌─────┴─────┐
    ▼           ▼
STEP 2: PATH A           STEP 3: PATH B
  70/15/15 stratified      70/15/15 CHRONOLOGICAL within class
  Scaler fit on TRAIN      min/range from TRAIN only
  RF (200 trees) + GBT     Per-client windows of 20 (benign only)
  Threshold = F1-max       Threshold = 99th percentile MAE on val
  on validation            → trafficformer.h5 + norm + threshold
          │                           │
          └───────────┬────────────────┘
                      ▼
STEP: SAVE MEMORY + AWARENESS
  training_metadata.json (sample counts, feature snapshot, history)
  evaluation_metrics.json (held-out test metrics)
  Regenerate pipeline_awareness_check.sh (drift check for runtime)
```

**Anti-leakage discipline** — explicit and verified:

- Split happens **before** scaling.
- Scaler / normalization fit on **train only**.
- Sequences and sliding windows are built **inside** each split; no window straddles a
  split boundary.
- Thresholds are calibrated on **validation**.
- Final metrics are reported on a **held-out test** set, into
  `models/evaluation_metrics.json`.
- Path B trains on **benign-only** windows (autoencoder best practice) and splits
  **chronologically** per class (time series).

---

## 5. The flow — detection

Goal: score **new** logs with the already-trained models and emit alerts. Nothing is
retrained here.

```
PREFLIGHT
  models/ contains Path A (and optionally Path B) artifacts?
  dns_detect importable? deps present? data/raw/*.log exists?
  Source pipeline_awareness_check.sh → training context + drift check
          │
          ▼
STEP 1 — FEATURE EXTRACTION
  features.extractor  → week3_features_all.json
          │
          ▼
STEP 2 — ML BRIDGE (inference)
  fusion.bridge --weight-a 0.6 --weight-b 0.4
    Path A: joblib.load RF + keras TF + scaler
            X_scaled → RF.predict_proba
            seqs(10) → transformer       → ml_score_A = 0.6·RF + 0.4·TF
    Path B: load trafficformer + threshold + norm
            lengths → normalize → windows(20) → reconstruct → MSE
            ml_score_B = sigmoid(z(error)); anomaly = error > threshold
    Merge: ml_combined_score  = max(A, 0.6·A + 0.4·B)  (Path B can only raise)
           ml_combined_label  = (label_A == 1) OR (label_B == 1)  (OR-gate at each
                                                                     calibrated threshold)
           ml_threat_score    = 0.4·(attack_count/6) + 0.35·A + 0.25·B
           ml_confidence       = HIGH ≥0.8 | MEDIUM ≥0.5 | LOW ≥0.3 | CLEAN <0.3
  → week3_features_with_ml.json  (+10 ML columns)
          │
          ▼
STEP 3 — DETECTION ENGINE
  detection.engine --zscore 2.0 --csv
    Z-score baseline built from BENIGN subset only
    Rule 1  Excessive NXDOMAIN (>200 per client / 15 min)       T1568, T1008
    Rule 2  Multi-client, same error (≥2 clients / 10 min)      T1568, T1573
    Rule 3  DNS tunneling (query_length>100 AND entropy>4.0)    T1572, T1048
    Rule 4  Deep subdomains (depth>5)                           T1572
    Z-score anomaly on entropy / length / subdomain depth
    Rule 5  ML attack label (ml_combined_label == 1)            T1572, T1568, T1048
    Rule 6  ML threat score ≥ 0.7 (deduped against Rule 5)      T1572, T1568
    Optional: MDTI (passive DNS + reputation) via Graph API
  → week4_unified_alerts.json  (+ .csv)
          │
          ▼
STEP 4 — MONITORING
  monitoring.monitor
    PSI drift per feature vs training feature_snapshot
    alert-volume sanity + ML-score saturation check
  → monitoring_report.json { retrain_recommended: bool, reasons }
```

The engine is **backward compatible**: without ML columns, Rules 5–6 silently skip and
it behaves as the original 4-rule + Z-score detector.

---

## 6. One query's journey (micro-flow)

Follow the log line `x9f2kd.base32.lab.local` end to end:

1. **Extractor** parses the line → record with `entropy≈4.6`, `query_length=22`,
   `subdomain_depth=2`; the `.base32.` marker fires the Encoding detector →
   `attack_signature="ENCODING"`, `attack_count=1`.
2. **Bridge / Path A** builds the 8-feature vector, scales it; RF + Transformer produce
   `ml_score_A` (e.g. 0.82).
3. **Bridge / Path B** reconstructs the surrounding 20-length window of query lengths;
   a normal-length name reconstructs well, so `ml_score_B` is low (e.g. 0.20).
4. **Bridge / fusion:** `ml_combined_score = max(0.82, 0.6·0.82 + 0.4·0.20) = 0.82`; if
   it clears the calibrated threshold → `ml_combined_label=1`,
   `ml_confidence="HIGH"`, `ml_threat_score = 0.4·(1/6)+0.35·0.82+0.25·0.20 = 0.40`.
5. **Engine:** Rule 3 does *not* fire (length 22 < 100), but **Rule 5** fires on the ML
   label → a High alert with MITRE T1572/T1568/T1048, the domain, client IP, the ML
   scores in `details`, and an investigation priority.
6. **Monitoring** factors this record's features into the PSI drift comparison against
   the training snapshot.

---

## 7. Red team + lab

- **`attacks/attack.c`** — multi-threaded C DNS attack generator (raw sockets, Linux /
  Kali). Mirrors the `lab.local` zone records (A, NS, MX, TXT, RP, SOA, DNAME, CNAME) so
  queries hit valid record types. Reads real subdomain wordlists (`-w`, `-W`). Live
  dashboard shows QPS, wordlist progress, query distribution. Attack modes:
  `--random-subdomains`, `--nxdomain-flood`, `--amplification`, `--cache-poison`,
  `--random-types`, `--random-ports`, `--edns0-buffer`, `--all-attacks`. The six
  heuristics in the extractor are tuned to catch these.
- **`infra/technitium-elk/`** — Docker stack: Technitium DNS (`:53`, admin `:5380`),
  Elasticsearch 8.11.1, Logstash (grok-parses Technitium lines into Elastic indices
  `technitium-dns-YYYY.MM.dd`), Kibana (`:5601`), Filebeat (ships the log files to
  Logstash). This stack is for **visibility and hunting**; the Python pipeline reads
  the raw `*.log` files directly from `data/raw/`.
- **`infra/nginx-lab/`** — HTTPS "Phone Store" demo (Nginx + Firebase Auth/Firestore)
  on `lab.local`. Its only role is to generate realistic benign DNS traffic — the
  "normal" baseline Path B learns to reconstruct and Z-score baselines are built from.

---

## 8. The machine-learning process (in detail)

The ML side is a **two-opinion** system. Each path is trained and used independently,
then their outputs are combined by a fusion rule. Everything below reflects what the
code actually does in `src/dns_detect/models/` and `src/dns_detect/fusion/`.

### 8.1 Inputs and the 8-feature vector (Path A)

Every query becomes an 8-feature row (`FEATURES_8` in `parsing/dns_parser.py`):

| Feature | What it measures |
|---|---|
| `query_length` | Full domain length in characters |
| `query_entropy` | Shannon entropy of the domain string |
| `has_digits` | 1 if the domain contains any digit, else 0 |
| `answer_count` | Number of answers in the response (currently always 0 — placeholder) |
| `subdomain_count` | Number of dots (depth) |
| `longest_label` | Length of the longest label (recomputed from the real domain) |
| `digit_ratio` | Share of digit characters |
| `unique_char_ratio` | Share of unique characters |

### 8.2 Labels (the single most important decision)

- **Preferred — provenance labels (Tier 1).** `scripts/label_from_manifest.py` marks a
  query as attack if its timestamp falls inside an attack window in
  `data/attack_manifest.csv` and the client IP matches the attacker. Everything else is
  benign. This is the CIC-IDS2017 recipe: label by capture, not by rule.
- **Fallback — heuristic labels.** If no manifest exists, `fusion.bridge --label-only`
  reads `attack_count` from the extractor's six heuristics: `label = 1 if attack_count ≥ 1`.
  This is **circular labeling** — the ML can only learn what the heuristics already
  catch. We keep it as a fallback but prefer the manifest.

### 8.3 Path A — supervised ensemble

Production score = soft vote of **Random Forest** + **HistGradientBoosting**, with a
decision gate that keeps the pair only if its held-out F1 is at least the RF-only F1
(otherwise falls back to RF alone). A **Transformer** classifier is trained but kept
only as a baseline (reported under `transformer_baseline`, excluded from the decision).

```
X (8 features) ──► split 70/15/15 (stratified) ──► fit StandardScaler on TRAIN only
                                                       │
     ┌─────────────────────────────────────────────────┴──────────────────────────────┐
     ▼                              ▼                                                 ▼
 RandomForest (200 trees,     HistGradientBoosting              Transformer baseline
 class_weight="balanced")                                       (seq len 10, 2 blocks,
     │                              │                           2 heads) — reported only
     └── P_rf(attack) ──┐  ┌── P_gbt(attack) ──┐
                        ▼  ▼
                   soft vote = mean(P_rf, P_gbt) = ml_score_A
                        │
                        ▼
             Threshold calibrated on VAL set via precision-recall F1 max
                        │
                        ▼
          Decision gate: use RF+GBT only if F1(rf_gbt) ≥ F1(rf_only)
                        │
                        ▼
       Final metrics on held-out TEST → models/evaluation_metrics.json
```

**Why this choice:** tree models beat deep networks on small/medium tabular data
(Grinsztajn et al. NeurIPS 2022); FT-Transformer is only competitive above ~10K rows,
and our set is ~8K/18K rows and 8 features. RF spreads importance across features;
boosting concentrates on a few. Combined they are two real "opinions".

**Artifacts saved:** `dns_tunnel_rf.pkl`, `dns_tunnel_gbt.pkl`, `dns_tunnel_transformer.keras`,
`dns_scaler.pkl`, `dns_threshold.json` (with `threshold`, `decision`).

### 8.4 Path B — unsupervised reconstruction

A **Trafficformer autoencoder** that learns to reconstruct *normal* windows of DNS
traffic. If a new window reconstructs badly, it is anomalous.

```
records sorted by time, split 70/15/15 CHRONOLOGICALLY within each class
                        │
                        ▼
  For each client_ip inside each split, build sliding windows of length 20
  across 5 features: query_length, query_entropy, subdomain_count,
                     digit_ratio, longest_label
                        │
                        ▼
  Normalize per feature using min/range from TRAIN only
                        │
                        ▼
  Train Trafficformer (3 transformer blocks, 3 heads, key-dim 64) on
  BENIGN windows only; loss = MSE reconstruction
                        │
                        ▼
  Threshold = 99th percentile of MSE on BENIGN VALIDATION windows
  (replaces mean + 2.5σ, which assumed Gaussian errors)
                        │
                        ▼
  At inference: ml_score_B = sigmoid((error − μ)/σ);
                anomaly if error > threshold
```

**Why per-client windows:** sequence-anomaly work builds windows per host so a window
is a real temporal sequence from one caller, not a mix of different hosts.

**Artifacts saved:** `dns_trafficformer.h5`, `dns_trafficformer_norm.json`,
`dns_trafficformer_threshold.json`.

### 8.5 Fusion — how the two opinions combine

In `fusion/bridge.py`, after each path produces its score and label:

```
ml_score_A  = soft vote of RF + GBT (0..1)
ml_score_B  = sigmoid of z-scored reconstruction error (0..1)

ml_combined_score = max(ml_score_A, 0.6·ml_score_A + 0.4·ml_score_B)
                       └─ Path B can only RAISE the score, never lower it
ml_combined_label = (ml_label_A == 1) OR (ml_label_B == 1)
                       └─ OR-gate: either path can fire at its own calibrated threshold
ml_threat_score   = 0.4·(attack_count/6) + 0.35·A + 0.25·B
ml_confidence     = HIGH ≥0.8 | MEDIUM ≥0.5 | LOW ≥0.3 | CLEAN <0.3
```

**Why `max` and OR-gate:** the earlier design compared the weighted fused score against
Path A's own threshold (0.955). That meant even with Path A at 1.0, the fused value
reached 0.955 only if Path B ≥ 0.89 — Path B dragged Path A *down*. The current rule
lets each path fire at its own calibrated threshold.

### 8.6 Evaluation discipline

- **PR-AUC** as the primary metric (not accuracy), reported with the prevalence baseline
  (because the classes are imbalanced — Saito & Rehmsmeier 2015).
- **ROC-AUC** and **F1** reported alongside.
- **Per-attack-family recall** from the manifest's `family` column — shows which tools
  are caught and which are missed.
- **Label-shuffle test** (`--shuffle-labels`): retrain on permuted labels; if the pipeline
  does not leak, metrics collapse to the prevalence baseline. (Catches pipeline leakage;
  does **not** catch circular labeling.)
- **Leave-one-tool-out** test: train without a tool family, test on it. This is the real
  generalization number.

All metrics are persisted to `models/evaluation_metrics.json` under `path_a`
(with `candidates`, `decision`, `transformer_baseline`, `shuffle_labels`,
`recall_by_family`) and `path_b`.

---

## 9. Path A & Path B — core ML logic (deep dive)

What follows is the actual math and control flow inside each path, lifted from
`src/dns_detect/models/path_a.py` and `src/dns_detect/models/path_b_train.py`. This is
the "what makes it machine learning" layer.

### 9.1 Path A — core logic

**Problem framing.** Binary classification: given one DNS query represented as an
8-feature row `x ∈ ℝ⁸`, output `P(attack | x)`. Two tree learners vote; a Transformer
is trained alongside as a baseline only.

**Training pipeline (step by step):**

```
1. Load labeled DataFrame → X = df[FEATURES_8].values   (shape = N × 8)
                              y = df["label"].values     (0 benign, 1 attack)

2. Stratified 3-way split (seed 42):
     (X_train, y_train)  70 %
     (X_val,   y_val)    15 %
     (X_test,  y_test)   15 %

3. StandardScaler.fit(X_train)   ← fit on TRAIN only
     X_train = scaler.transform(X_train_raw)
     X_val   = scaler.transform(X_val_raw)
     X_test  = scaler.transform(X_test_raw)
   Each feature now has μ=0, σ=1 over the training distribution.

4. Train two production learners on the SCALED features:
     rf  = RandomForestClassifier(n_estimators=200, class_weight="balanced")
     gbt = HistGradientBoostingClassifier(learning_rate=0.1, max_iter=300,
                                          early_stopping=True, validation_fraction=0.15,
                                          class_weight="balanced")

5. Also train a Transformer baseline on sequences:
     Build (window=10) sliding sequences of feature rows
     X_seq[i] = [x_i, x_{i+1}, …, x_{i+9}]      (shape = (N−9) × 10 × 8)
     y_seq[i] = y_{i+9}
     Train a Transformer encoder (2 blocks, 2 heads, head_size 32, ff_dim 64,
     dropout 0.1) with GlobalAveragePooling1D + sigmoid output.
     Loss: binary_crossentropy. Optimizer: Adam. EarlyStopping on val AUC.
     → kept only for reporting, excluded from the production decision.

6. Soft-vote on the validation set:
     P_rf   = rf.predict_proba(X_val)[:, 1]
     P_gbt  = gbt.predict_proba(X_val)[:, 1]
     score_rf_only = P_rf
     score_rf_gbt  = 0.5 · P_rf + 0.5 · P_gbt     (mean probability)

7. Calibrate each candidate's threshold on validation via precision-recall F1 max:
     precision, recall, thresholds = precision_recall_curve(y_val, score)
     F1 = 2·P·R / (P + R)
     thr = thresholds[argmax(F1)]

8. Evaluate both candidates on the HELD-OUT test set.
   Decision gate (the only knob that chooses the model):
     if F1(rf_gbt, test) >= F1(rf_only, test):
         decision = "rf_gbt"
     else:
         decision = "rf_only"
   Persist {threshold, decision} to models/dns_threshold.json.
```

**Inference (the formula actually used in production):**

```
X_scaled = scaler.transform(df[FEATURES_8].values)

P_rf  = rf.predict_proba(X_scaled)[:, 1]
P_gbt = gbt.predict_proba(X_scaled)[:, 1]

ml_score_A = 0.5 · P_rf + 0.5 · P_gbt      if decision == "rf_gbt"
           = P_rf                           if decision == "rf_only"

ml_label_A = (ml_score_A >= threshold)
```

**What each learner "sees":**

| Learner | Model class | Reads | Produces |
|---|---|---|---|
| Random Forest | 200 bootstrapped trees, Gini splits | 8 scaled features | majority-vote probability `P_rf` |
| HistGradientBoosting | Sequential boosted trees, log-loss | Same 8 scaled features | boosted probability `P_gbt` |
| Transformer (baseline) | Multi-head self-attention over 10-step windows | 10×8 feature sequences | sigmoid attack probability (reported only) |

**Why soft-voting the two trees works:** RF spreads feature importance across many
features (bagging decorrelates trees); boosting concentrates on the hardest residuals
and reweights a few features heavily. Their mistakes are not perfectly correlated, so
averaging their probabilities reduces variance without hurting bias — a textbook
"two-opinion" ensemble on tabular data.

### 9.2 Path B — core logic

**Problem framing.** Unsupervised anomaly detection: learn a model `g_θ(w) ≈ w` that
reconstructs *benign* windows well; anything that reconstructs **badly** is anomalous.
No attack labels are used during training.

**Inputs.** Each query becomes a 5-feature row (`PATH_B_FEATURES`):
`query_length, query_entropy, subdomain_count, digit_ratio, longest_label`.
Rows carry a `client_ip` and a time `order` field alongside.

**Training pipeline (step by step):**

```
1. Load records → X ∈ ℝ^{N×5}, labels, client_ip[N], order[N]

2. Stratified-chronological split per class (so each split holds both classes):
     for cls in {0, 1}:
         idx = indices where labels == cls, sorted by order
         k   = len(idx)
         train:    idx[0 : 0.70·k]
         val:      idx[0.70·k : 0.85·k]
         test:     idx[0.85·k : k]
   Concatenate the per-class masks → one train/val/test partition.

3. Per-feature min–range normalization from TRAIN rows ONLY:
     f_min = X_train.min(axis=0)
     f_rng = X_train.max(axis=0) − f_min      (replace 0 with 1 to avoid /0)
     Xn    = (X − f_min) / f_rng               (applied to all splits)

4. Build PER-CLIENT sliding windows inside each split:
     For every client_ip, sort its records by `order`, then take overlapping
     windows of length W (=20). Window label = max label across the W rows.
     Shape of each split: (num_windows, W=20, F=5).
     A window never mixes clients, and never straddles a split boundary.

5. Keep BENIGN windows only for training the autoencoder:
     x_train_ben = x_train[yw_train == 0]
     x_valid_ben = x_valid[yw_valid == 0]
   (Fallback: if too few benign windows exist, falls back to all windows with a
   warning — the threshold then becomes less trustworthy.)

6. Build the Trafficformer autoencoder:
     Input:   (W, F) = (20, 5)
     Body:    3 transformer_encoder blocks (num_heads=3, head_size=64, ff_dim=3,
              dropout=0.25)   — each block is LayerNorm → MultiHeadAttention →
              residual → LayerNorm → Conv1D(ff_dim) → Conv1D(F) → residual
     Head:    Dense(64, relu) → Dropout(0.4) → Dense(F, linear)
     Output:  same shape as input → the model's reconstruction ŵ of the window w
     Loss:    mean_squared_error(w, ŵ)
     Optim:   Adam, lr = 1e-4
     Callbacks: EarlyStopping(val_loss, patience=10),
                ModelCheckpoint(best val_loss)

7. Threshold calibration on BENIGN VALIDATION windows:
     errors = MSE(w, ŵ) for each benign val window
     threshold = percentile(errors, 99.0)     ← robust to skew
                 (fallback: mean(errors) + 2.5 · std(errors))
     Also save error_mean, error_std for the inference-time sigmoid.

8. Held-out test evaluation on MIXED windows:
     test_errors = MSE(w, ŵ) for every test window
     test_pred   = (test_errors > threshold).astype(int)
     Report precision / recall / F1 / PR-AUC / ROC-AUC → evaluation_metrics.json
```

**Inference (the formula actually used in production):**

```
For each new window w of W rows from one client_ip:
    ŵ    = model.predict(w)
    err  = MSE(w, ŵ) = mean((w − ŵ)²)
    anomaly = (err > threshold)              # binary decision

    z            = (err − error_mean) / error_std
    ml_score_B   = 1 / (1 + exp(−z))         # sigmoid → smooth 0..1 score
    ml_label_B   = anomaly
```

**Why this is machine learning (not a rule):** at no point is the model told "a long
query is bad" or "high entropy is suspicious". It learns from benign-only windows
what the joint distribution of `(length, entropy, depth, digit_ratio, longest_label)`
*looks like* across a client's temporal sequence. A query stream that violates that
joint distribution — in any of the 5 features, or in how they correlate within a 20-step
window — reconstructs badly. That is the detection signal.

### 9.3 Core-logic cheat-sheet

| Property | Path A | Path B |
|---|---|---|
| Supervision | Supervised (needs labels) | Unsupervised (benign only) |
| Input unit | One query (row) | A window of W=20 queries from one client |
| Features | 8 (`FEATURES_8`) | 5 (`PATH_B_FEATURES`) |
| Normalization | StandardScaler (z-score) on train | min–range from train |
| Model(s) | RF (200 trees) + HistGBT soft-voted; Transformer baseline reported only | Trafficformer autoencoder (3 encoder blocks → Dense head) |
| Loss | Binary cross-entropy (TF) / Gini + log-loss (trees) | MSE reconstruction |
| Split policy | Stratified 70/15/15 | Stratified-chronological per class, 70/15/15 |
| Threshold | F1-max on PR curve (validation) | 99th percentile of MSE on benign val |
| Decision | `(0.5·P_rf + 0.5·P_gbt) ≥ thr` or RF-only | `MSE(w, ŵ) > thr` |
| Output score | `ml_score_A ∈ [0,1]` | `ml_score_B = sigmoid(z(err))` |
| Picks up | Known attack shapes it has seen in training | Behavior unlike learned-normal (zero-day-ish) |

Combined into one call: `ml_combined_score = max(ml_score_A, 0.6·A + 0.4·B)` with an
OR-gate on labels — see §8.5.

### 9.4 Core-logic steps side by side

The same stages, laid out as one table so Path A and Path B can be read against each
other row by row.

| # | Stage | Path A | Path B |
|---|-------|--------|--------|
| 1 | **Load** | `X = df[FEATURES_8].values` (N × 8), `y = df["label"].values` | `X ∈ ℝ^{N×5}`, `labels`, `client_ip[N]`, `order[N]` |
| 2 | **Split** | Stratified 70/15/15 on `y`, seed 42 | Stratified-chronological per class: sort each class by `order`, cut 70/15/15, concat |
| 3 | **Normalize** | `StandardScaler.fit(X_train)`; transform val+test (μ=0, σ=1 per feature) | `f_min, f_rng = min, max−min` from TRAIN only; `Xn = (X − f_min) / f_rng` |
| 4 | **Reshape** | Flat rows (no windows for RF/GBT); for TF baseline: sliding seqs of 10 | Per-client sliding windows W=20 inside each split → shape `(num_windows, 20, 5)` |
| 5 | **Filter for training** | Use all train rows (balanced class weights handle imbalance) | Keep BENIGN windows only (`yw_train == 0`) — autoencoder learns "normal" |
| 6 | **Model** | RF(200 trees, balanced) **+** HistGBT(lr 0.1, 300 iters, early stop, balanced) **+** Transformer baseline (2 blocks, 2 heads, sigmoid) | Trafficformer AE: 3 encoder blocks (3 heads, head_size 64, ff_dim 3, dropout 0.25) → Dense(64, relu) → Dense(F, linear) |
| 7 | **Loss / fit** | Trees: Gini + log-loss (native). TF: binary cross-entropy + Adam + EarlyStopping(val AUC) | MSE reconstruction + Adam(lr=1e-4) + EarlyStopping(val_loss, patience 10) + ModelCheckpoint(best) |
| 8 | **Score formula** | `P_rf = rf.predict_proba(X)[:,1]`; `P_gbt = gbt.predict_proba(X)[:,1]`; `score = 0.5·P_rf + 0.5·P_gbt` | `ŵ = model.predict(w)`; `err = mean((w − ŵ)²)`; `score = sigmoid((err − μ_err) / σ_err)` |
| 9 | **Threshold calibration** | F1-max on precision-recall curve over validation scores | 99th percentile of `err` on BENIGN validation windows (fallback: `mean + 2.5·σ`) |
| 10 | **Decision gate** | Keep RF+GBT only if `F1(rf_gbt, test) ≥ F1(rf_only, test)`, else fall back to RF-only | None — the percentile threshold is the decision |
| 11 | **Final decision** | `ml_label_A = (ml_score_A ≥ threshold)` | `ml_label_B = (err > threshold)` |
| 12 | **Held-out evaluation** | Precision / Recall / F1 / PR-AUC / ROC-AUC on test set; per-family recall; label-shuffle check | Precision / Recall / F1 / PR-AUC / ROC-AUC on MIXED test windows |
| 13 | **Artifacts** | `dns_tunnel_rf.pkl`, `dns_tunnel_gbt.pkl`, `dns_tunnel_transformer.keras`, `dns_scaler.pkl`, `dns_threshold.json` | `dns_trafficformer.h5`, `dns_trafficformer_norm.json`, `dns_trafficformer_threshold.json` |
| 14 | **What signal it captures** | Known attack *shapes* in the feature space the heuristics or manifest marked | *Deviation* from the learned joint distribution of 5 features inside a 20-step per-client sequence |

---

## 10. Before vs. after — the fix round

Four bugs were caught in a 2026-10-24 audit against the current literature. All four
have been fixed; retrained on 18,353 records. The headline numbers below come from
`docs/MODEL_EVALUATION_2026-10-24.md` and `docs/progress.md`.

### 9.1 What changed

| # | Fix | File | Problem → Resolution |
|---|-----|------|----------------------|
| 1 | **Path B now evaluable** | `models/path_b_train.py` | Global chronological split put all attacks in train and 0 attacks in val/test. Now split **chronologically within each class**, so each split has both. |
| 2 | **Fusion threshold** | `fusion/bridge.py` | Fused score was compared against Path A's own threshold (0.955), making Path B drag Path A down. Now `max(A, w·A+w·B)` + OR-gate at each path's own threshold. |
| 3 | **Base64 heuristic tightened** | `features/extractor.py` | Base64 check reused the uppercased string → any length-mod-4 alnum domain passed (incl. `google.com`, `apple.com`). Now checks original case, requires length ≥ 24, requires mixed case or a digit. |
| 4 | **`longest_label` honest** | `parsing/dns_parser.py` | `longest_label` was secretly `first_label_length` (r = 0.98 with `query_length`). Now recomputed from the real domain. `answer_count` annotated as a known-zero placeholder. |

### 9.2 Headline metrics

| | **Before patches** | **After patches** |
|---|---|---|
| Path A F1 (chosen branch) | 1.0000 (`rf_only`) | 0.9997 (`rf_gbt`) |
| Path A ROC-AUC | 1.000 | 1.000 |
| **Path B F1** | **not evaluated** (test had 0 attacks) | **1.0000** |
| Benign heuristic FP rate | **23.8 %** | **6.3 %** (4× cleaner labels) |
| Benign records / clients | 5,662 / 1 | 8,353 / 4 |
| Attack families covered | 2 (dns2tcp, dnsexfiltrator) | 2 (same) |
| Single-feature AUC (`query_length`) | 0.998 | **still 0.998** |
| Leave-one-tool-out recall (dns2tcp) | 0.32 | **still 0.32** |
| Leave-one-tool-out recall (dnsexfiltrator) | 0.00 | **still 0.00** |
| Evaluation on unseen data | None | None |

### 9.3 What genuinely improved vs. what did not

**Genuinely improved — engineering correctness:**

- Path B evaluation unblocked (structural bug fixed).
- Fusion logic no longer dilutes Path A.
- Benign false-positive rate dropped 4× after the base64 fix.
- `longest_label` is honest.
- Richer provenance (manifest labels), richer evaluation (PR-AUC, per-family recall,
  shuffle test).

**Did not improve — because it is a data problem, not a code problem:**

- Headline F1 is still ~1.00 because `query_length` alone separates the classes with
  AUC 0.998 on this dataset.
- Leave-one-tool-out recall is unchanged (0.32 and 0.00): the model learns tool
  fingerprints, not tunneling behavior.
- Only two attack tool families are represented.
- No evaluation on data the model never saw at training time.

### 9.4 The honest one-liner

> The code is now correct enough to trust. The results are not yet strong enough to
> claim. The next real jump comes from **external holdout data** (DNSTunnel2026 on
> Zenodo), not more code.

---

## 11. Honest state of the results

Reported in `docs/MODEL_EVALUATION_2026-10-24.md` and `docs/progress.md`:

| Metric | After the fix round (18,353 records) |
|---|---|
| Path A F1 (chosen branch, `rf_gbt`) | 0.9997 |
| Path B F1 | 1.0000 |
| Benign heuristic FP rate | 6.3% (down from 23.8%) |
| ROC-AUC with `query_length` alone | **0.998** |
| Leave-one-tool-out recall (dns2tcp) | 0.32 |
| Leave-one-tool-out recall (dnsexfiltrator) | **0.00** |

**What that means — in plain words:**

- The 1.00 is a function of **dataset easiness**, not model sophistication. A single
  feature (`query_length`) splits the classes almost perfectly on this data.
- The model **learns tool fingerprints**, not tunneling behavior. On an unseen tool,
  the ranking stays correct but the decision threshold collapses.
- Benign is one short pcap (≈50 s, 4 clients, one subnet). It cannot represent "normal
  network traffic".
- There is no evaluation on data the model never saw during training.

The project is now **structurally correct**: labels come from an attack manifest
(provenance labels), the Path B evaluation is unblocked (per-class chronological
splits), fusion uses `max(A, w·A+w·B)` with an OR-gate, the base64 heuristic is tightened,
and `longest_label` is computed from the real domain string. The remaining weakness is
**data breadth**, not code. The planned next step — the one that converts "1.00 on an
easy dataset" into a defensible claim — is to run `scripts/verify_models.py --holdout`
against **DNSTunnel2026** (Zenodo) or a similar external set.

---

## 12. Known caveats, in one list

- **Circular labeling (legacy fallback).** If no manifest exists, labels still come from
  the extractor's own heuristics — the ML can only learn what the rules already catch.
  Manifest labels (Tier 1 fix) are the correct path.
- **Path B is multi-feature now** (5 features) but the autoencoder is a single network,
  not a Kitsune-style ensemble.
- **Thresholds** live partly in code / CLI rather than fully in `settings.yaml` — the
  YAML is the intended single source but not yet wired into every module.
- **Rule thresholds** (Rule 2 = 2 clients, Rule 4 = depth 5) are low for production.
- `docs/Document_DNS.md` describes the **pre-restructure** `scripts/*.py` layout; the
  live code is the `src/dns_detect/` package.

Not yet built (see `docs/PLAN.md`): Wazuh detection/alerting, Telegram human-in-the-loop
approval, near-real-time streaming, separate attacker-manifest ground truth as the
default, canary domains, dry-run mode with a kill switch.

---

## 13. Quick-start cheat sheet

```bash
# 0. Install deps
python -m pip install -r requirements.txt

# 1. (lab) bring up Technitium + ELK
cd infra/technitium-elk && docker compose up -d && cd ../..

# 2. (lab, Kali) build & run the attacker
cd attacks && make && \
  sudo ./attack 127.0.0.1 lab.local --all-attacks -t 8 -r 5000 -d 120 \
       -w subdomains.txt -W nxdomains.txt && cd ..

# 3. Copy Technitium logs into the pipeline input
cp infra/technitium-elk/data/dns_logs/*.log data/raw/

# 4. Train once
./scripts/train_models.sh

# 5. Detect
./scripts/run_pipeline.sh
# → data/processed/week4_unified_alerts.json (+ .csv) + monitoring_report.json
```

---

## 14. The one-sentence version

A hybrid DNS anomaly detector that pairs a supervised RF + GBT classifier with an
unsupervised Trafficformer autoencoder, fuses them into MITRE-tagged alerts over a
Technitium + ELK lab, and — after a round of leakage, labeling, and fusion fixes — is
now **correct enough to trust and limited enough to be honest about**: the remaining
work is broader data, not more code.
