# Document: DNS Traffic Anomaly Detection System

## Project Overview

**Project Name:** DNS Traffic Anomaly Detection Using Hybrid Machine Learning Fusion

**Institution:** Cambodia Academy of Digital Technology (CADT), Department of Telecommunications and Networking

**Team Members:** Mao Sovanrathana, Vutthin Vattanak, Ken Chomnan, Tith Sopanha

**Advisor:** Mr. Roeum Makara

**Academic Year:** 2025–2026

This project implements a multi-layered DNS anomaly detection system designed for a Capture The Flag (CTF) / security research context. It combines rule-based detection (Microsoft Sentinel-style rules), statistical analysis (Z-score profiling), and hybrid machine learning (supervised + unsupervised) to identify DNS-based threats such as tunneling, exfiltration, NXDOMAIN floods, amplification attacks, and cache poisoning attempts.

---

## Directory Structure

```
Detecting-DNS-Traffic/
├── README.md                          # Academic paper / full research documentation
├── scripts/                           # Core Python and Bash scripts
│   ├── DNS_feature_extractor.py       # Week 3: Feature extraction from Technitium logs
│   ├── dns_parser.py                  # Shared DNS input parser (supports multiple formats)
│   ├── Model.py                       # Path A: RF + Transformer ensemble (supervised)
│   ├── Train.py                       # Path B: Trafficformer training (unsupervised)
│   ├── Predict.py                     # Path B: Trafficformer inference
│   ├── Ml_bridge.py                   # Fusion bridge: connects Week 3 → ML → Week 4
│   ├── Week4_detection_engine.py      # Unified detection engine (rules + stats + ML)
│   ├── Run_Pipeline.sh                # Full detection pipeline runner
│   ├── Train_Models.sh                # ML model trainer with smart retrain
│   ├── attack.c                       # DNS attack simulation tool (C)
│   ├── model/                         # Local model artifacts (during runtime)
│   └── *.pkl, *.keras, *.json         # Copies of model files used during execution
├── data/                              # Feature files, alerts, and intermediate data
│   ├── week3_features_all.json        # Extracted features from DNS logs
│   ├── week3_features_with_ml.json    # Features enriched with ML scores
│   ├── week3_attack_summary.json      # Attack detection summary
│   ├── week3_suspicious_domains.json  # Flagged suspicious domains
│   ├── week4_unified_alerts.json      # Final detection alerts (JSON)
│   ├── week4_unified_alerts.csv       # Final detection alerts (CSV)
│   ├── merged_features_all.json       # Merged training dataset
│   ├── merged_features_labeled.json   # Labeled dataset for supervised training
│   ├── blocked_domains.txt            # Domain blocklist
│   ├── daily_summary.csv              # Daily traffic summary
│   └── dns_features_all.csv           # All DNS features in CSV
├── model_memory/                      # Persistent trained model storage
│   ├── dns_tunnel_rf.pkl              # Random Forest model
│   ├── dns_tunnel_transformer.keras   # Transformer classifier model
│   ├── dns_scaler.pkl                 # StandardScaler for feature normalization
│   ├── dns_threshold.json             # Calibrated ensemble threshold
│   ├── dns_trafficformer.h5           # Trafficformer reconstruction model
│   ├── dns_trafficformer_norm.json    # Normalization parameters for Path B
│   ├── dns_trafficformer_threshold.json # Anomaly threshold for Path B
│   ├── training_metadata.json         # Rich training metadata and history
│   ├── training_provenance.json       # Source file provenance tracking
│   ├── trained_files_registry.json    # SHA256 registry of all trained files
│   └── pipeline_awareness_check.sh    # Auto-generated drift detection script
├── logs/                              # Pipeline and training execution logs
│   ├── pipeline_*.log                 # Detection pipeline run logs
│   └── training_*.log                 # Model training session logs
├── technitium-dns/                    # DNS server infrastructure
│   ├── docker-compose.yml             # Docker stack (Technitium + ELK)
│   ├── filebeat.yml                   # Log shipping configuration
│   ├── logstash.conf                  # Log parsing pipeline
│   └── data/dns_logs/                 # Raw DNS server log files
└── nginx-1.28.1/                      # Web server (demo "Phone Store" app)
    ├── conf/nginx.conf                # HTTPS configuration for lab.local
    └── html/
        ├── index.html                 # Phone Store frontend
        ├── customer.js                # Firebase-backed e-commerce logic
        └── styles.css                 # Styling
```

---

## Architecture and Workflow

The system follows a phased, weekly development structure with a clear data pipeline:

### High-Level Pipeline Flow

```
DNS Server Logs (Technitium)
        │
        ▼
┌─────────────────────────────────┐
│  Week 3: Feature Extraction     │  DNS_feature_extractor.py
│  (20+ features per query)       │
└─────────────────┬───────────────┘
                  │  week3_features_all.json
                  ▼
┌─────────────────────────────────┐
│  ML Bridge (Fusion Layer)       │  Ml_bridge.py
│  ┌─────────┐   ┌─────────────┐ │
│  │ Path A   │   │  Path B     │ │
│  │ RF+Trans │   │ Trafficfmr  │ │
│  │ (8-feat  │   │ (sequence   │ │
│  │ classif.)│   │ reconstruct)│ │
│  └────┬─────┘   └──────┬──────┘ │
│       │ ml_score_A     │ ml_score_B
│       └───────┬────────┘        │
│               ▼                 │
│      Combined ML Score          │
│   (weighted: 0.6A + 0.4B)      │
└─────────────────┬───────────────┘
                  │  week3_features_with_ml.json
                  ▼
┌─────────────────────────────────┐
│  Week 4: Detection Engine       │  Week4_detection_engine.py
│  ┌──────────────────────┐       │
│  │ Rule 1: NXDOMAIN     │       │
│  │ Rule 2: Multi-client │       │
│  │ Rule 3: Tunneling    │       │
│  │ Rule 4: Deep subdomain│      │
│  │ Rule 5: ML label     │ (NEW) │
│  │ Rule 6: ML score     │ (NEW) │
│  │ Z-score: Statistical │       │
│  │ MDTI: Threat Intel   │       │
│  └──────────────────────┘       │
└─────────────────┬───────────────┘
                  │
                  ▼
         Unified Alerts (JSON + CSV)
         with MITRE ATT&CK mapping
```

---

## Component Details

### 1. DNS Server Infrastructure (`technitium-dns/`)

The project runs a **Technitium DNS Server** inside Docker alongside an ELK stack (Elasticsearch, Logstash, Kibana) for log aggregation and visualization.

**Docker Compose Stack:**
- **technitium-dns** — DNS server on port 53 (UDP/TCP) with a web admin panel on port 5380. DNS query logs are stored in `data/dns_logs/`.
- **Elasticsearch** — Search and analytics engine (port 9200), single-node mode.
- **Logstash** — Parses Technitium log lines using a grok pattern, extracting timestamp, client IP, protocol, query domain, record class, and record type. Outputs to Elasticsearch indices named `technitium-dns-YYYY.MM.dd`.
- **Kibana** — Visualization dashboard (port 5601) connected to Elasticsearch.
- **Filebeat** — Ships log files from `data/dns_logs/` to Logstash on port 5044.

The DNS server is configured with a zone (`lab.local`) containing multiple record types: A, NS, MX, TXT, RP, SOA, DNAME, CNAME — providing realistic targets for the attack simulation tool.

### 2. DNS Attack Simulation Tool (`scripts/attack.c`)

A multi-threaded C program that generates various DNS attack patterns against the Technitium DNS server. This is the **red team** component used to create labeled attack traffic for training and evaluation.

**Attack Modes:**
| Mode | Flag | Description |
|---|---|---|
| Random Subdomains | `--random-subdomains` | Floods with wordlist-derived subdomain permutations |
| NXDOMAIN Flood | `--nxdomain-flood` | Queries non-existent domains to generate NXDOMAIN responses |
| DNS Amplification | `--amplification` | Sends ANY queries with large EDNS0 buffer (4096 bytes) |
| Cache Poisoning | `--cache-poison` | Rapid burst of queries with varying transaction IDs |
| Random Types | `--random-types` | Randomizes across A, NS, MX, TXT, RP, SOA, AAAA, DNAME, CNAME, ANY |
| Random Source Ports | `--random-ports` | Creates new socket per packet for port randomization |
| EDNS0 Buffer | `--edns0-buffer` | Requests large EDNS0 payload size |
| All Attacks | `--all-attacks` | Enables all modes simultaneously |

**Key Features:**
- Uses the `n0kovo_subdomains` wordlists (huge + large) — no random string generation; attacks use real subdomain patterns.
- Configurable thread count (up to 20), QPS rate limiting, and duration.
- Live animated dashboard showing QPS, wordlist progress, threat meter, and query distribution.
- Mirrors the actual Technitium zone records so queries target valid record types.

### 3. Feature Extraction — Week 3 (`scripts/DNS_feature_extractor.py`)

Parses raw Technitium DNS server log files and extracts 20+ features per DNS query. This is the foundational data preparation step.

**Log Parsing:**
Extracts from each log line: timestamp, client IP/port, protocol (UDP/TCP), QNAME (domain), QTYPE (query type), QCLASS, RCODE (response code), answer size, and transaction ID.

**Extracted Features:**

| Feature | Description |
|---|---|
| `entropy` | Shannon entropy of domain name (high entropy = suspicious) |
| `subdomain_depth` | Number of subdomain levels (dot count) |
| `query_length` | Total character length of domain name |
| `numeric_ratio` | Ratio of digits to total characters |
| `consecutive_pattern_score` | Detects repetitive character patterns |
| `first_label_length` | Length of the leftmost domain label |
| `first_label_entropy` | Entropy of leftmost label (often carries payload) |
| `num_labels` | Total number of domain labels |
| `hour_of_day` | Hour extracted from timestamp (temporal feature) |
| `day_of_week` | Day of week (temporal feature) |
| `query_rate` | Approximate queries per second per domain |

**Attack Pattern Detectors (rule-based flags):**

| Detector | Pattern | Threshold |
|---|---|---|
| NXDOMAIN Flood | NXDOMAIN response + high-entropy first label | entropy > 3.5 |
| Random Subdomains | Deep structure (≥4 labels) + random-looking labels | entropy > 3.0, numeric ratio 0.2–0.8 |
| Amplification | ANY query type or query length > 512 bytes | — |
| Cache Poisoning | ≥5 queries to same domain within 1 second with ≥3 different TXIDs | — |
| Encoding (Base32/64) | `.base32.` or `.base64.` in domain, or character-set analysis | ratio > 0.9 (base32), > 0.95 (base64) |
| High Entropy | Entropy > 4.0 with long first label (≥20 chars) | — |

Each query receives an `attack_signature` (comma-separated list of detected patterns) and an `attack_count` (number of patterns triggered).

**Outputs:** `week3_features_all.json`, `week3_attack_summary.json`, `week3_suspicious_domains.json`, `week3_project_summary.json`

### 4. Shared DNS Parser (`scripts/dns_parser.py`)

A unified input parser used by all ML components. Single source of truth — prevents duplication.

**Supported Input Formats:**
- `.pcap` / `.pcapng` / `.cap` — via Scapy
- `.json` / `.jsonl` / `.ndjson` — JSON records
- `.csv` — CSV feature tables
- `.log` — Technitium or Zeek log files
- `.traff` — Legacy format (one integer per line)

**Core Feature Set (`FEATURES_8`):**
Used by Path A (Model.py) for the 8-dimensional feature vector:
1. `query_length` — Total domain name length
2. `query_entropy` — Shannon entropy of the domain
3. `has_digits` — Binary flag: does the domain contain digits?
4. `answer_count` — Number of answer records in the response
5. `subdomain_count` — Number of dots in the domain
6. `longest_label` — Length of the longest label
7. `digit_ratio` — Ratio of digit characters
8. `unique_char_ratio` — Ratio of unique characters

**Column Remapping:**
Week 3 uses different column names (e.g., `entropy` → `query_entropy`, `subdomain_depth` → `subdomain_count`). The parser handles this mapping transparently.

**Two Loader Functions:**
- `load_as_dataframe()` — Returns a DataFrame with FEATURES_8 columns (for Path A).
- `load_as_array()` — Returns a 1-D array of query lengths (for Path B time-series input).

### 5. Path A: Supervised Ensemble (`scripts/Model.py`)

A supervised binary classifier using **Random Forest + Transformer** ensemble.

**Random Forest:**
- 200 estimators, balanced class weights (handles imbalanced attack/normal ratio).
- Trained on the 8-feature vector (`FEATURES_8`).
- Outputs probability of attack: `P(attack)`.

**Transformer Classifier:**
- Multi-head attention architecture (2 heads, 32 key dimensions, 2 transformer blocks).
- Takes sequences of 10 consecutive feature vectors as input (`SEQUENCE_LENGTH = 10`).
- Binary output via sigmoid activation + binary cross-entropy loss.
- Early stopping on validation AUC.

**Ensemble Logic:**
```
combined_score = rf_weight * P_rf(attack) + tf_weight * P_tf(attack)
prediction = 1 if combined_score >= threshold else 0
```
Default weights: 0.5 / 0.5 (configurable). The threshold is calibrated via precision-recall curve to maximize F1 on the validation set.

**Training Pipeline:**
1. Load labeled data (requires `label` column: 0=benign, 1=attack).
2. Scale features with `StandardScaler`.
3. Stratified train/test split (70/30).
4. Train RF and Transformer independently.
5. Calibrate ensemble threshold on the test set.
6. Save 4 artifacts: `dns_tunnel_rf.pkl`, `dns_tunnel_transformer.keras`, `dns_scaler.pkl`, `dns_threshold.json`.

### 6. Path B: Unsupervised Anomaly Detector (`scripts/Train.py` + `scripts/Predict.py`)

A **Trafficformer** — sequence reconstruction model using transformer blocks.

**Architecture:**
- Input: sliding windows of query lengths (default window size: 20).
- Encoder: 3 transformer blocks (3 heads, 64 key dimensions, feed-forward dim 3).
- Decoder head: Dense layers reconstructing the input window.
- Loss: Mean Squared Error (reconstruction task).
- Output: same shape as input (the model learns to reconstruct normal traffic patterns).

**Anomaly Detection Logic:**
```
reconstruction_error = MSE(original_window, reconstructed_window)
if reconstruction_error > threshold → ANOMALY
```
The threshold is set as `mean(errors) + 2.5 * std(errors)` on the validation set, meaning ~99% of normal traffic falls below it.

**Score Normalization:**
Raw reconstruction errors are converted to a [0, 1] probability-like score (`ml_score_B`) using a Z-score sigmoid transform:
```
z = (error - error_mean) / error_std
ml_score_B = 1 / (1 + exp(-z))
```

**Training Outputs:** `dns_trafficformer.h5`, `dns_trafficformer_threshold.json`, `dns_trafficformer_norm.json`

### 7. ML Bridge — Fusion Layer (`scripts/Ml_bridge.py`)

The central orchestrator that connects Week 3 features → both ML paths → Week 4 detection engine.

**Two Operating Modes:**

1. **Label Generation Mode** (`--label-only`):
   Converts Week 3 `attack_count` field into binary labels for training:
   - `attack_count >= 1` → `label = 1` (attack)
   - `attack_count == 0` → `label = 0` (benign)
   Also assigns `attack_type_id` (0–6) for multi-class analysis.

2. **Inference Mode** (default):
   - Runs Path A (RF + Transformer) → `ml_score_A`, `ml_label_A`
   - Runs Path B (Trafficformer) → `ml_score_B`, `ml_label_B`
   - Computes combined score and label:
     ```
     ml_combined_score = 0.6 * ml_score_A + 0.4 * ml_score_B
     ml_combined_label = 1 if (label_A == 1 OR label_B == 1 OR combined_score >= 0.5)
     ```
   - Assigns confidence tiers: HIGH (≥0.8), MEDIUM (≥0.5), LOW (≥0.3), CLEAN (<0.3)
   - Computes `ml_threat_score`:
     ```
     ml_threat_score = 0.4 * (attack_count/6) + 0.35 * ml_score_A + 0.25 * ml_score_B
     ```

**Output:** `week3_features_with_ml.json` — original Week 3 features enriched with 10 new ML columns.

### 8. Detection Engine — Week 4 (`scripts/Week4_detection_engine.py`)

The final unified detection engine combining all detection layers into prioritized alerts.

**Detection Layers:**

| Layer | Rules | Source |
|---|---|---|
| Rule-Based | Rule 1: Excessive NXDOMAIN (>200 in 15min) | Microsoft Sentinel ASIM |
| Rule-Based | Rule 2: Multiple clients same error (≥2 unique) | Microsoft Sentinel ASIM |
| Rule-Based | Rule 3: DNS tunneling (length >100 OR entropy >4.0) | Project requirement |
| Rule-Based | Rule 4: Deep subdomain (depth >5) | Project requirement |
| ML-Based | Rule 5: ML combined label == 1 | ML Bridge |
| ML-Based | Rule 6: ML threat score ≥ 0.7 | ML Bridge |
| Statistical | Z-score anomaly on entropy, query_length, subdomain_depth | NetSleuthXplorer |
| Threat Intel | Microsoft Defender TI (optional) | MDTI API |

**Z-Score Detection:**
Builds per-IP baselines for each feature, then flags queries where |Z-score| > 2.0 (configurable). Z > 3 → High severity.

**MDTI Integration (Optional):**
If Azure credentials are provided, enriches alerts with:
- Passive DNS resolution via Microsoft Graph API
- Host reputation scores
Suspicious reputation increases threat score by 50 and escalates severity to High.

**Alert Format:**
Each alert includes: UUID, timestamp, rule name/source, severity (High/Medium/Low), client IP, domain, detailed context, MITRE ATT&CK tactics and techniques (T1568, T1572, T1048, T1573, T1008, T1046), and investigation priority.

**Outputs:** `week4_unified_alerts.json` (structured report), `week4_unified_alerts.csv` (flat table).

### 9. Pipeline Orchestration

#### Training Pipeline (`scripts/Train_Models.sh`)

Handles all model training with smart data management.

**Workflow:**
1. **Source Discovery** — Scans for CSV, JSON, PCAP, and LOG files from specified directories or the default DNS log directory.
2. **Pre-processing** — Raw `.log` files are processed through `DNS_feature_extractor.py`; `.pcap` files through `tshark` + `dns_parser.py`.
3. **Merging** — All sources are merged into `merged_features_all.json`.
4. **Label Generation** — `Ml_bridge.py --label-only` creates labeled dataset.
5. **Path A Training** — `Model.py --train` trains RF + Transformer.
6. **Path B Training** — `Train.py` trains the Trafficformer.
7. **Memory Save** — All model artifacts are copied to `model_memory/` for persistence.

**Smart Retrain (v3):**
- Maintains a SHA256 registry of every file ever trained on (`trained_files_registry.json`).
- `--retrain` skips already-trained files; only genuinely new data triggers retraining.
- `--force-retrain` retrains on everything regardless.
- Records full provenance (source files, checksums, record counts, timestamps).

**Training Metadata:**
Saves rich metadata including: training date, sample counts (attack/benign), attack types seen, feature snapshots (mean/std/min/max), model file paths, ensemble weights, and a history of up to 10 training sessions.

**Data Drift Detection:**
Auto-generates `pipeline_awareness_check.sh` that compares live traffic feature distributions against training-time feature snapshots. Z-score > 3 on any feature triggers a drift warning.

#### Detection Pipeline (`scripts/Run_Pipeline.sh`)

Runs the full detection workflow using previously trained models.

**Workflow:**
1. **Preflight** — Checks that trained models exist in `model_memory/`, verifies all scripts and Python packages.
2. **Step 1** — Week 3 feature extraction from new DNS logs.
3. **Step 2** — ML Bridge: loads trained models from memory, scores new traffic.
4. **Step 3** — Week 4 Detection Engine: runs all 6 rules + Z-score + MDTI.

**Options:**
- `--week3-only` — Stop after feature extraction.
- `--detect-only` — Skip extraction, run detection on existing features.
- `--zscore N` — Custom Z-score threshold.

### 10. Web Application (`nginx-1.28.1/`)

A supplementary **Phone Store** e-commerce demo served over HTTPS via Nginx on the `lab.local` domain. This generates legitimate DNS traffic as baseline data.

**Technical Stack:**
- **Nginx 1.28.1** with SSL (self-signed cert for `lab.local`).
- **Firebase** backend (Authentication + Firestore) for user auth, product catalog, cart, and orders.
- Frontend: vanilla HTML/CSS/JavaScript.

**Purpose in the Project:**
The web application runs on the `lab.local` domain served by the Technitium DNS server. Users browsing the store generate normal DNS queries (A records, HTTPS traffic), providing the benign traffic baseline that the ML models learn as "normal." This legitimate traffic is essential for:
- Training Path B (Trafficformer learns normal query-length patterns).
- Establishing Z-score baselines.
- Ensuring the attack simulation generates distinguishable anomalies against a realistic background.

---

## Data Flow Summary

### Training Phase

```
Raw DNS Logs (.log)  ──→  DNS_feature_extractor.py  ──→  week3_features_all.json
                                                              │
                                                              ▼
                                                       Ml_bridge.py --label-only
                                                              │
                                                              ▼
                                                    merged_features_labeled.json
                                                       ┌──────┴──────┐
                                                       ▼             ▼
                                                   Model.py      Train.py
                                                  (Path A)      (Path B)
                                                       │             │
                                                       ▼             ▼
                                                 model_memory/  model_memory/
                                                 (RF, TF,       (Trafficformer,
                                                  Scaler,        threshold,
                                                  threshold)     norm params)
```

### Detection Phase

```
New DNS Logs  ──→  DNS_feature_extractor.py  ──→  week3_features_all.json
                                                        │
                                           ┌────────────┘
                                           ▼
                                      Ml_bridge.py (inference)
                                      Load models from model_memory/
                                           │
                                           ▼
                                   week3_features_with_ml.json
                                           │
                                           ▼
                                 Week4_detection_engine.py
                                  (6 rules + Z-score + MDTI)
                                           │
                                           ▼
                                  week4_unified_alerts.json
                                  week4_unified_alerts.csv
```

---

## Key Design Decisions

### 1. Two-Opinion ML Architecture
The system uses two independent ML paths that each see the data differently:
- **Path A** (supervised) excels at recognizing known attack patterns it was trained on.
- **Path B** (unsupervised) catches novel/zero-day attacks by detecting deviations from learned normal behavior.
The fusion ensures both "known-bad" and "unknown-anomalous" traffic is flagged.

### 2. Weak Labeling from Rule-Based Detectors
Instead of manual labeling, the system bootstraps ML labels from Week 3's rule-based attack detectors (`attack_count >= 1` → attack). This enables fully automated training on new data without human annotation.

### 3. Persistent Model Memory
Models are stored in `model_memory/` separately from the runtime `scripts/model/` directory. The training pipeline copies artifacts to/from this persistent store, enabling:
- Retrain-free detection runs.
- Smart incremental retraining.
- Full provenance tracking and data drift detection.

### 4. MITRE ATT&CK Alignment
All alerts are tagged with MITRE ATT&CK tactics and techniques, enabling direct integration with SOC workflows and SIEM platforms. Mapped techniques include:
- T1572 (Protocol Tunneling)
- T1568 (Dynamic Resolution)
- T1048 (Exfiltration Over Alternative Protocol)
- T1573 (Encrypted Channel)
- T1008 (Fallback Channels)
- T1046 (Network Service Discovery)

### 5. Backward Compatibility
The detection engine works with or without ML scores. If `Ml_bridge.py` hasn't been run, Rules 5 and 6 are simply skipped, and the system falls back to the original 4 Sentinel rules + Z-score detection.

---

## Technology Stack

| Component | Technology |
|---|---|
| DNS Server | Technitium DNS Server (Docker) |
| Log Aggregation | ELK Stack (Elasticsearch 8.11.1, Logstash, Kibana, Filebeat) |
| ML Framework | TensorFlow/Keras, scikit-learn |
| Data Processing | pandas, NumPy |
| Packet Parsing | Scapy (optional, for PCAP input) |
| Attack Simulation | Custom C tool with pthreads |
| Web Server | Nginx 1.28.1 (HTTPS/SSL) |
| Web App Backend | Firebase (Auth + Firestore) |
| Threat Intelligence | Microsoft Defender TI (MDTI) via Graph API |
| Orchestration | Bash scripts with colored output and error handling |

---

## How to Use

### First-Time Setup

```bash
# 1. Start the DNS infrastructure
cd technitium-dns/
docker-compose up -d

# 2. Generate attack traffic (from a separate machine or container)
cd scripts/
gcc -o attack attack.c -lpthread -lm
./attack 192.168.18.143 lab.local --all-attacks -t 8 -r 5000 -d 120

# 3. Train the ML models (run once)
./Train_Models.sh

# 4. Run detection
./Run_Pipeline.sh
```

### Ongoing Detection

```bash
# Run detection with saved models (no retraining needed)
./Run_Pipeline.sh

# If new training data is available
./Train_Models.sh --retrain        # Smart: only new files
./Train_Models.sh --force-retrain  # Full retrain
```

### Individual Components

```bash
# Feature extraction only
python DNS_feature_extractor.py --input /path/to/log --output /path/to/output.json

# Generate labels for training
python Ml_bridge.py --week3 data/week3_features_all.json --label-only --output data/labeled.json

# Train Path A
python Model.py --train data/labeled.json

# Train Path B
python Train.py --filename week3_features_all.json --n_days 20 --save_name dns_trafficformer

# Run inference
python Ml_bridge.py --week3 data/week3_features_all.json --output data/with_ml.json --path-b-model dns_trafficformer

# Run detection engine
python Week4_detection_engine.py --input data/with_ml.json --output data/alerts.json --csv
```

---

## Summary

This project implements a complete DNS security monitoring pipeline spanning from raw packet capture through ML-powered anomaly detection to actionable, MITRE-mapped alerts. The hybrid "Two-Opinion" architecture (supervised ensemble + unsupervised reconstruction) provides defense-in-depth: Path A catches known attack patterns with high precision, while Path B surfaces novel behavioral anomalies. The system is designed for the academic/CTF context but follows production-grade practices including persistent model memory, smart incremental retraining, data drift detection, and full training provenance tracking.
