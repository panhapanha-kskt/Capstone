# Understanding the Project — DNS Traffic Anomaly Detection

> A deep walkthrough of the architecture, data flow, processing stages, and every file's
> purpose. Written from a direct reading of the source in `src/dns_detect/`, `scripts/`,
> `attacks/`, `infra/`, and `config/` — not from the older docs, which describe a previous
> `scripts/`-based layout that has since been restructured into a proper Python package.

**Project:** DNS Traffic Anomaly Detection Using Hybrid ML Fusion
**Context:** CADT Capstone (2025–2026), CTF / security-research lab
**Current branch:** `main`

---

## 1. What the system does, in one paragraph

Raw DNS query logs from a **Technitium DNS server** are parsed into per-query feature
records. Those records are scored by **two independent ML paths** — a supervised
Random-Forest + Transformer ensemble (Path A) and an unsupervised Trafficformer
autoencoder (Path B) — whose scores are **fused** into a combined threat score. A
**detection engine** then applies six rules (four Microsoft-Sentinel-style rules + two
ML rules), a Z-score statistical layer, and optional Microsoft Defender Threat
Intelligence enrichment, producing **unified, MITRE ATT&CK-tagged alerts** in JSON and
CSV. A **monitoring** stage watches for data drift and recommends retraining. A C-based
**attack simulator** generates labeled malicious traffic in the lab, and an **ELK +
Technitium** Docker stack provides ingestion and visibility.

The design is a **"two-opinion" model**: Path A recognizes *known* attack patterns with
high precision; Path B flags *novel* behavior that deviates from learned-normal traffic.

---

## 2. High-level architecture

```
                         LAB / RED TEAM                         INFRASTRUCTURE
 ┌─────────────────────────┐                      ┌──────────────────────────────────┐
 │ attacks/attack.c        │  DNS attack traffic  │ Technitium DNS (Docker)           │
 │ (multi-threaded C tool)  ├────────────────────► │  → writes query logs              │
 └─────────────────────────┘   lab.local :53      │ Filebeat → Logstash → Elastic/    │
 ┌─────────────────────────┐  benign traffic      │ Kibana  (visibility & hunting)    │
 │ infra/nginx-lab (store) ├────────────────────► │                                   │
 └─────────────────────────┘                      └────────────────┬──────────────────┘
                                                                    │ raw *.log
                                                                    ▼
┌──────────────────────────── DETECTION PIPELINE (src/dns_detect) ─────────────────────┐
│                                                                                       │
│  data/raw/*.log                                                                       │
│       │                                                                               │
│       ▼  features/extractor.py                                                        │
│  ① FEATURE EXTRACTION  → per-query records + 6 heuristic attack flags                 │
│       │  week3_features_all.json                                                      │
│       ▼  fusion/bridge.py                                                             │
│  ② ML BRIDGE (fusion) ──┬── Path A: models/path_a.py   (RF + Transformer)            │
│       │                  └── Path B: models/path_b_predict.py (Trafficformer)        │
│       │  week3_features_with_ml.json  (+10 ML columns)                                │
│       ▼  detection/engine.py                                                          │
│  ③ DETECTION ENGINE  → 6 rules + Z-score + MDTI → unified alerts                      │
│       │  week4_unified_alerts.json / .csv                                             │
│       ▼  monitoring/monitor.py                                                        │
│  ④ MONITORING  → PSI drift / alert-volume / score-health → retrain recommendation    │
│                                                                                       │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

Two orchestrators drive this: `scripts/train_models.sh` (one-time / retrain) builds the
models; `scripts/run_pipeline.sh` runs detection on new logs using the saved models.

---

## 3. Repository layout and what each file is for

### 3.1 Top level

| Path | Purpose |
|------|---------|
| `README.md` | Slim project overview + quick start. |
| `requirements.txt` | Pinned Python deps: numpy, pandas, scikit-learn, tensorflow, joblib, tqdm, python-dateutil, requests, pytz, scapy, pyyaml. |
| `AUDIT_REPORT.md` | Deep standards-compliance audit (circular labeling, OR-vs-AND, dedup, etc.) with run instructions. The **authoritative** description of logic + known weaknesses. |
| `RESTRUCTURE_PLAN.md` | The record of how the old `scripts/*.py` monolith was moved into `src/dns_detect/`. Explains the "before" layout and the move table. |
| `docs/README_full.md` | Full academic paper. |
| `docs/Document_DNS.md` | Technical documentation (describes the **pre-restructure** layout — treat as historical). |
| `docs/PLAN.md` | Capstone extension plan (Wazuh, Telegram HITL, near-real-time, attack manifests). Future work, not yet built. |
| `.env.example` | Template for MDTI credentials and path overrides. |
| `config/settings.yaml` | **Single source of truth** for all paths, model filenames, training params, ensemble weights, and detection thresholds. |

### 3.2 The Python package — `src/dns_detect/`

```
src/dns_detect/
├── config.py                  # YAML settings loader + env overrides
├── utils/paths.py             # Finds PROJECT_ROOT (dir containing config/settings.yaml)
├── parsing/dns_parser.py      # Shared input parser (log/json/csv/pcap/traff) — "single source of truth"
├── features/
│   ├── extractor.py           # ① Stage 1: Technitium log → feature records + attack flags
│   └── eda.py                 # Exploratory data analysis (profiling, runs during training)
├── models/
│   ├── path_a.py              # Path A: RF + Transformer supervised ensemble (train + infer)
│   ├── path_b_train.py        # Path B: Trafficformer autoencoder training
│   └── path_b_predict.py      # Path B: Trafficformer inference (reconstruction error)
├── fusion/bridge.py           # ② Stage 2: label gen + Path A/B inference + score fusion
├── detection/engine.py        # ③ Stage 3: rules + Z-score + MDTI → unified alerts
└── monitoring/monitor.py      # ④ Stage 4: drift (PSI) + alert-volume + score-health → retrain trigger
```

### 3.3 Orchestration & lab — `scripts/`, `attacks/`, `infra/`

| Path | Purpose |
|------|---------|
| `scripts/train_models.sh` | Training orchestrator (v3 "smart retrain"): discover sources, pre-process, merge, EDA, label, train Path A + B, write metadata/provenance/registry, regenerate drift script. |
| `scripts/run_pipeline.sh` | Detection orchestrator: preflight → extract → bridge → engine → monitor, with timing and alert summaries. |
| `scripts/pipeline_awareness_check.sh` | **Auto-generated** by `train_models.sh`; prints training context and does a quick Z-score drift check. Sourced by `run_pipeline.sh`. |
| `attacks/attack.c` | Multi-threaded C DNS attack simulator (red team). |
| `attacks/Makefile` | Build rules for `attack.c` (Linux raw sockets — Kali). |
| `infra/technitium-elk/docker-compose.yml` | Technitium DNS + Elasticsearch + Logstash + Kibana + Filebeat stack. |
| `infra/technitium-elk/logstash.conf` | Grok pattern parsing Technitium log lines into Elastic fields. |
| `infra/technitium-elk/filebeat.yml` | Ships `data/dns_logs/*.log` to Logstash. |
| `infra/nginx-lab/` | "Phone Store" HTTPS demo app (Firebase-backed) that generates benign DNS traffic as the normal baseline. |
| `tests/test_smoke.py` | Import + config-load smoke tests. |

### 3.4 Data & model directories (mostly gitignored, kept with `.gitkeep`)

| Path | Contents |
|------|----------|
| `data/raw/` | Raw Technitium `*.log` files (pipeline input). |
| `data/processed/` | Generated: `week3_features_all.json`, `*_with_ml.json`, `week4_unified_alerts.json/.csv`, `merged_*`, `eda_report.json`, `monitoring_report.json`. |
| `models/` | Trained artifacts + `training_metadata.json`, `training_provenance.json`, `trained_files_registry.json`, `evaluation_metrics.json`. |
| `logs/` | Per-run `pipeline_*.log` and `training_*.log`. |
| `outputs/` | Reserved for exports. |

---

## 4. Configuration and path resolution

Everything hangs off two small modules so nothing is hardcoded to a machine:

- **`utils/paths.py`** — `find_project_root()` walks up from the file (or honors the
  `DNS_DETECT_HOME` env var) until it finds `config/settings.yaml`, exposing
  `PROJECT_ROOT`. Every module resolves `models/`, `data/` etc. relative to this.
- **`config.py`** — loads `config/settings.yaml` into a dot-accessible `settings`
  namespace, with env overrides `DNS_DETECT_MODELS_DIR` and `DNS_DETECT_LOG_DIR`.
  `resolve_path("models_dir")` turns a config key into an absolute path.

`config/settings.yaml` holds the knobs that matter:

```yaml
ensemble:   rf_weight 0.6   tf_weight 0.4   combined_threshold 0.5
training:   path_b_window_size 20   threshold_multiplier 2.5   sequence_length 10
detection:  zscore 2.0  nxdomain 200  multi_client 2
            tunneling_length 100  tunneling_entropy 4.0
            subdomain_depth 5  ml_score 0.7
```

> Note: the detection engine and models currently take several of these thresholds from
> their own defaults/CLI flags rather than reading `settings.yaml` everywhere — the YAML
> is the intended single source but not yet wired into every module. This is called out
> in `AUDIT_REPORT.md` as a minor issue.

---

## 5. The shared parser — `parsing/dns_parser.py`

Every ML component reads input through this one module so there is no duplicated parsing
logic. It accepts `.pcap/.pcapng/.cap`, `.json/.jsonl/.ndjson`, `.log`, `.csv`, and
`.traff`.

Two output shapes, two consumers:

- **`load_as_dataframe(path)`** → DataFrame with the **8-feature vector** used by Path A:
  `FEATURES_8 = [query_length, query_entropy, has_digits, answer_count, subdomain_count,
  longest_label, digit_ratio, unique_char_ratio]`.
- **`load_as_array(path)`** → 1-D integer array of **query lengths** (the time-series
  signal used by Path B).
- **`load_values_and_labels(path)`** → `(lengths, labels)` aligned per record; used by
  Path B training for benign-only training and test metrics.

It also transparently **remaps Week-3 column names** (the extractor's names) to model
names — e.g. `entropy → query_entropy`, `subdomain_depth → subdomain_count`,
`numeric_ratio → digit_ratio`, `answer_size → answer_count`,
`first_label_length → longest_label` — so the extractor's output feeds the models without
re-extraction. Missing `FEATURES_8` columns are zero-filled.

---

## 6. Stage ① — Feature extraction (`features/extractor.py`)

The `DNSFeatureExtractor` class parses raw Technitium log lines and builds one feature
record per DNS query.

**Log line format** (parsed by regex):
```
[2026-03-18 13:43:05 Local] [172.19.0.1:60486] UDP QNAME: www.lab.local; QTYPE: A; QCLASS: IN; RCODE: NoError; ANSWER: [...]
```
It pulls timestamp, client IP/port, protocol, QNAME, QTYPE, QCLASS, RCODE, answer size,
and transaction ID. Non-query lines (server startup, cache loads) are skipped because they
have no `QNAME:`.

**Per-domain features computed:** Shannon `entropy`, `subdomain_depth` (dot count),
`query_length`, `numeric_ratio`, `consecutive_pattern_score`, TLD / main domain /
`num_labels`, and first-label analysis (`first_label`, `first_label_length`,
`first_label_entropy` — the first label often carries tunneling payload). Plus temporal
`hour_of_day`, `day_of_week`, and an approximate `query_rate`.

**Six heuristic attack detectors** (these produce the weak labels later):

| Detector | Trigger |
|----------|---------|
| NXDOMAIN flood | RCODE NXDOMAIN + `nxdomain-` pattern or high first-label entropy (>3.5) |
| Random subdomains | ≥4 labels with ≥2 high-entropy (>3.0) mixed-alnum labels |
| Amplification | QTYPE ANY/255, or oversized query, or EDNS0/TCP indicator |
| Cache poisoning | ≥5 queries to same domain within 1 s with ≥3 distinct TXIDs |
| High entropy | entropy >4.0 with a long (≥20) first label |
| Encoding | `.base32.`/`.base64.` markers or base32/base64 character-ratio analysis |

Each record gets an **`attack_signature`** (comma-joined names, or `NORMAL`) and an
**`attack_count`** (how many detectors fired).

**CLI modes:**
- `--input <log> --output <json>` — single-file mode (used per-log by the trainer).
- No args — batch mode: scans `data/raw/*.log` → `data/processed/week3_features_all.json`
  plus `week3_attack_summary.json`, `week3_suspicious_domains.json`,
  `week3_project_summary.json`.

---

## 7. Stage ② — ML bridge and the two paths (`fusion/bridge.py`)

The bridge is the orchestrator that connects extraction → both ML paths → detection. It
has **two modes**.

### 7.1 Label-generation mode (`--label-only`)

Used during training. Converts the extractor's heuristic output into supervised labels:

```
label = 1 if attack_count >= 1 else 0
attack_type_id = map(first signature name → 0..6)
```

> This is the project's **weak-labeling** strategy: ML is trained on the heuristics'
> verdicts. `AUDIT_REPORT.md` flags this as **circular labeling** — the ML can only learn
> what the heuristics already catch. It's the single most important caveat to the whole
> ML claim.

### 7.2 Inference mode (default)

Runs both paths and merges their scores into each record.

**Path A — supervised ensemble (`models/path_a.py`)**
- **Random Forest:** 200 trees, `class_weight="balanced"`, on the scaled 8-feature vector → `P(attack)`.
- **Transformer:** 2 blocks, 2 heads, key-dim 32; consumes sequences of `SEQUENCE_LENGTH=10`
  consecutive feature vectors; sigmoid output + binary-cross-entropy → `P(attack)`.
- **Ensemble:** `ml_score_A = rf_weight·P_rf + tf_weight·P_tf`. The first `pad` samples
  (no full window) fall back to the RF score alone.
- **Threshold:** calibrated on a validation split via the precision-recall F1 maximum,
  saved to `dns_threshold.json`.

**Path B — unsupervised reconstruction (`models/path_b_train.py` / `path_b_predict.py`)**
- Input is the 1-D series of query lengths, normalized with **train-derived** min/range.
- **Trafficformer:** 3 transformer blocks (3 heads, key-dim 64) → dense reconstruction of
  a 20-length window; MSE loss. It learns to reconstruct *normal* windows.
- **Anomaly logic:** `reconstruction_error = MSE(window, reconstructed)`; `error > threshold`
  → anomaly, where `threshold = mean + 2.5·std` of benign validation errors.
- **Score:** `ml_score_B = sigmoid((error − error_mean)/error_std)` → a 0–1 score the
  bridge can combine.

> `AUDIT_REPORT.md` notes Path B uses only `query_length` (a single scalar) — a
> multi-feature window would be stronger.

### 7.3 Score fusion (`merge_ml_scores` + `ensure_week4_compatible`)

```
ml_combined_score = 0.6·ml_score_A + 0.4·ml_score_B
ml_combined_label = 1 if ml_combined_score >= calibrated_threshold   # weighted gate
ml_confidence     = HIGH ≥0.8 | MEDIUM ≥0.5 | LOW ≥0.3 | CLEAN <0.3
ml_threat_score   = 0.4·(attack_count/6) + 0.35·ml_score_A + 0.25·ml_score_B
```

> The combined label now decides from the **weighted fused score against one calibrated
> threshold**. The code comments record that this replaced an earlier OR-gate
> (`label_A OR label_B OR score≥0.5`) that let either path fire unilaterally — the audit's
> "OR-gate fusion" issue, now fixed in the merge step.

Output: the original records enriched with ten new columns, written to
`week3_features_with_ml.json`. If models are missing, Path A/B are skipped gracefully
(scores set to 0) so the pipeline still runs — the engine then simply has no ML rules to
fire.

---

## 8. Stage ③ — Detection engine (`detection/engine.py`)

The engine loads the ML-enriched JSON (auto-detecting whether ML columns are present) and
runs layered detection. Three classes:

- **`MDTIIntegration`** — optional Microsoft Defender Threat Intelligence via Graph API
  (OAuth client-credentials). Enriches alerts with passive DNS + host reputation; a bad
  reputation adds +50 to threat score and escalates severity to High. No-ops without creds.
- **`ZScoreDetector`** — builds a **per-client-IP baseline** (mean/std per feature) and
  flags `|z| > threshold` (default 2.0; z>3 → High). The baseline is built from the
  **benign subset** (filtered by `label` / `ml_combined_label` / `attack_count == 0`) to
  avoid the audit's "contaminated baseline" problem.
- **`RuleBasedDNSDetector`** — the six rules plus orchestration.

**The six rules:**

| # | Rule | Fires when | Severity | MITRE |
|---|------|-----------|----------|-------|
| 1 | Excessive NXDOMAIN | > 200 NXDOMAIN per client per 15-min window | Med/High | T1568, T1008 |
| 2 | Multiple clients, same error | ≥ 2 distinct clients error on one domain / 10 min | Low→High | T1568, T1573, T1008 |
| 3 | DNS tunneling | `query_length > 100` **AND** `entropy > 4.0` | High | T1572, T1048 |
| 4 | Deep subdomains | `subdomain_depth > 5` | Medium | T1572 |
| 5 | ML attack label | `ml_combined_label == 1` (severity from `ml_confidence`) | Med/High | T1572, T1568, T1048 |
| 6 | ML high threat score | `ml_threat_score >= 0.7` **and not already flagged by Rule 5** | Med/High | T1572, T1568 |

> Rule 3 uses **AND** (both signals) — the audit's recommendation, replacing an earlier OR.
> Rule 6 **deduplicates** against Rule 5 so the same query isn't reported twice (audit's
> "alert duplication" fix). Z-score runs between rules 4 and 5.

Each alert (`create_alert`) carries a UUID, timestamp, rule name/source, severity, client
IP, domain, a `details` dict, a human description, MITRE tactics/techniques, and an
investigation priority. Output is `week4_unified_alerts.json` (structured, with run
metadata and `rules_used`) and, with `--csv`, a flat `week4_unified_alerts.csv`.

The engine is **backward compatible**: without ML columns, rules 5–6 silently skip and it
behaves as the original 4-rule + Z-score detector.

---

## 9. Stage ④ — Monitoring (`monitoring/monitor.py`)

Post-deployment health check comparing live scored data against the training baseline in
`models/training_metadata.json`. Three signals:

1. **Data drift** — Population Stability Index (PSI) per `FEATURES_8` feature against a
   normal proxy reconstructed from the saved mean/std snapshot. Bands: `<0.1` stable,
   `0.1–0.25` moderate, `>0.25` major (→ retrain).
2. **Alert volume** — alert rate vs live queries; an implausibly high rate (>50%) or zero
   alerts is flagged.
3. **Score health** — if ML scores saturate (nearly all ~0 or ~1) the model is no longer
   discriminating → recalibrate/retrain.

It always exits 0 and writes `monitoring_report.json` with a `retrain_recommended` boolean
and reasons; the operator (or `run_pipeline.sh`) decides. **EDA** (`features/eda.py`) is
the training-time analog — it profiles the merged dataset (class balance, missing values,
per-feature stats, correlation, red flags) before labeling, informing but never gating.

---

## 10. Orchestration flows

### 10.1 Training — `scripts/train_models.sh`

```
discover sources (--data-dir / --files / default data/raw)
  └─ smart retrain: skip files whose SHA256 is in trained_files_registry.json
0-A  pre-process raw .log  → features/extractor.py --input → JSON
0-B  pre-process .pcap     → tshark → dns_parser → JSON   (needs tshark)
0-C  merge all JSON+CSV    → merged_features_all.json  (+ provenance, + registry update)
0-D  EDA profiling         → features/eda.py → eda_report.json
1    label generation      → fusion/bridge.py --label-only → merged_features_labeled.json
2    train Path A          → models/path_a.py --train   (RF + Transformer + scaler + threshold)
3    train Path B          → models/path_b_train.py     (Trafficformer + norm + threshold)
     write training_metadata.json (+ feature_snapshot) + regenerate pipeline_awareness_check.sh
```

Models (and metadata/provenance/registry) land in `models/` — one canonical location the
Python package loads directly (the old "copy dance" into `scripts/` is gone).

**Smart-retrain modes:** default = train only if a path's models are missing;
`--retrain` = train only on files not seen before (by checksum registry);
`--force-retrain` = retrain on everything; `--path-a-only` / `--path-b-only` restrict scope.

Both Path A (`path_a.py`) and Path B (`path_b_train.py`) use proper **3-way splits**
(train / val / test), fit the scaler / normalization on **train only**, build sequences
**within** each split (no window crosses a boundary), calibrate the threshold on
**validation**, and report final metrics on a **held-out test** set into
`models/evaluation_metrics.json`. Path B trains **benign-only** (autoencoder best practice)
and splits **chronologically** (it's a time series).

### 10.2 Detection — `scripts/run_pipeline.sh`

```
preflight: check models/ exist, dns_detect importable, deps present, logs available
Step 1  features/extractor.py        → week3_features_all.json      (skippable: --detect-only)
Step 2  fusion/bridge.py (inference) → week3_features_with_ml.json  (weights 0.6/0.4, Path B if trained)
Step 3  detection/engine.py          → week4_unified_alerts.json/.csv  (--zscore N)
Step 4  monitoring/monitor.py        → monitoring_report.json  (prints retrain recommendation)
```

`--week3-only` stops after extraction. The script refuses to run detection if no models
exist and tells the user to train first.

---

## 11. The lab: attack simulator and infrastructure

### 11.1 `attacks/attack.c`

A multi-threaded (up to 20 threads) raw-socket DNS attack generator that mirrors the live
`lab.local` Technitium zone records (A, NS, MX, TXT, RP, SOA, DNAME, CNAME) so queries hit
valid record types. It reads real subdomain wordlists (no default path baked in — pass
`-w` for the subdomain list and `-W` for the NXDOMAIN list). A live animated dashboard
shows QPS, wordlist progress, and query distribution.

**Attack modes:** `--random-subdomains` (needs `-w`), `--nxdomain-flood` (needs `-W`),
`--amplification` (EDNS0 + ANY), `--cache-poison`, `--random-types`, `--random-ports`,
`--edns0-buffer`, and `--all-attacks`. Load controls: `-t` threads, `-r` QPS, `-d`
duration. Build on Linux via `attacks/Makefile` (raw sockets → Kali/root).

> These are the attacks the extractor's six heuristics are tuned to catch, which is why
> the heuristic flags double as training labels.

### 11.2 `infra/technitium-elk/`

Docker Compose stack: **Technitium DNS** (`:53` UDP/TCP, admin `:5380`, logs to
`./data/dns_logs`), **Elasticsearch** 8.11.1 (`:9200`, single-node), **Logstash** (grok-
parses Technitium lines → `technitium-dns-YYYY.MM.dd` indices), **Kibana** (`:5601`), and
**Filebeat** (ships the log files to Logstash). This stack is for **visibility and
hunting**; the Python pipeline reads the raw `*.log` files directly.

### 11.3 `infra/nginx-lab/`

An HTTPS "Phone Store" demo (Nginx + Firebase Auth/Firestore, vanilla HTML/CSS/JS) served
on `lab.local`. Its only role in the system is to generate **realistic benign DNS traffic**
— the "normal" baseline that Path B learns to reconstruct and that the Z-score baselines
are built from.

---

## 12. Data artifacts and the model store

**Pipeline data (`data/processed/`):**

| File | Produced by | Contents |
|------|-------------|----------|
| `week3_features_all.json` | extractor | Per-query features + heuristic flags |
| `merged_features_all.json` | trainer merge | All training sources concatenated |
| `merged_features_labeled.json` | bridge `--label-only` | Above + `label`, `attack_type_id` |
| `week3_features_with_ml.json` | bridge inference | Features + 10 ML columns |
| `week4_unified_alerts.json` / `.csv` | engine | Final alerts + run metadata |
| `eda_report.json` | eda | Pre-training data profile |
| `monitoring_report.json` | monitor | Drift / volume / health + retrain flag |

**Model store (`models/`):** Path A = `dns_tunnel_rf.pkl`, `dns_tunnel_transformer.keras`,
`dns_scaler.pkl`, `dns_threshold.json`. Path B = `dns_trafficformer.h5`,
`dns_trafficformer_threshold.json`, `dns_trafficformer_norm.json`. Plus
`evaluation_metrics.json` (held-out test metrics), `training_metadata.json` (last-trained,
sample counts, feature snapshot, history), `training_provenance.json` (source files +
checksums), and `trained_files_registry.json` (SHA256 of every file ever trained on — the
basis for smart retrain).

---

## 13. End-to-end quick start

```bash
# 0. Install deps
python -m pip install -r requirements.txt

# 1. (lab) bring up Technitium + ELK
cd infra/technitium-elk && docker compose up -d && cd ../..

# 2. (lab, Kali) build & run the attacker to generate labeled traffic
cd attacks && make && \
  sudo ./attack 127.0.0.1 lab.local --all-attacks -t 8 -r 5000 -d 120 \
       -w subdomains.txt -W nxdomains.txt && cd ..

# 3. copy Technitium logs into the pipeline input
cp infra/technitium-elk/data/dns_logs/*.log data/raw/

# 4. train once
./scripts/train_models.sh

# 5. detect
./scripts/run_pipeline.sh
# → data/processed/week4_unified_alerts.json (+ .csv) and monitoring_report.json
```

On Windows without Git Bash, run the stages directly, e.g.:
```powershell
$env:PYTHONPATH = "src"
python -m dns_detect.features.extractor
python -m dns_detect.fusion.bridge  --week3 data/processed/week3_features_all.json `
    --output data/processed/week3_features_with_ml.json --path-b-model dns_trafficformer
python -m dns_detect.detection.engine --input data/processed/week3_features_with_ml.json `
    --output data/processed/week4_unified_alerts.json --zscore 2.0 --csv
```

---

## 14. Key design decisions and honest caveats

**Design strengths**
- **Two-opinion ML:** supervised precision (Path A) + unsupervised novelty (Path B).
- **Package + config separation:** no machine-specific paths; `settings.yaml` + `paths.py`.
- **Leakage-aware training:** split-before-scale, per-split sequences, train-only
  normalization, validation-calibrated thresholds, held-out test metrics.
- **Provenance & smart retrain:** checksummed registry, metadata history, drift script.
- **MITRE ATT&CK tagging** on every alert; backward-compatible (works with or without ML).

**Caveats (documented in `AUDIT_REPORT.md`)**
- **Circular labeling** — ML labels come from the extractor's own heuristics, so ML inherits
  their blind spots. The biggest limitation of the ML claim.
- **Path B is single-feature** (query length only).
- **Thresholds** live partly in code/CLI rather than fully in `settings.yaml`.
- Some rule thresholds (Rule 2 = 2 clients, Rule 4 = depth 5) are low for production.
- The older `docs/Document_DNS.md` describes the **pre-restructure** `scripts/*.py` layout;
  the live code is the `src/dns_detect/` package described here.

**Not yet built (see `docs/PLAN.md`):** Wazuh detection/alerting, Telegram human-in-the-loop
approval, near-real-time streaming, separate attacker-manifest ground truth, canary domains.

---

## 15. Process flow — step by step

This section traces the **control + data flow** concretely: who calls what, what file goes
in, what comes out. There are two runnable processes — **training** (build models, run
once / on new data) and **detection** (score new traffic, run anytime). Both are thin shell
orchestrators over the same `dns_detect` package.

### 15.0 The lab prerequisite flow (how logs are born)

```
attack.c  ──DNS queries──►  Technitium DNS  ──appends──►  data/dns_logs/*.log
nginx-lab ──benign DNS ──►      (Docker)                        │
                                                  copy ─────────┘
                                                      ▼
                                              data/raw/*.log      ← pipeline input
```

Nothing in the Python pipeline runs until raw `*.log` files exist in `data/raw/`. The
attacker generates malicious queries, the store app generates benign ones, Technitium logs
both, and you copy those logs into `data/raw/`.

---

### 15.1 Training process flow — `./scripts/train_models.sh`

The goal: turn raw logs into **trained models + a calibrated threshold + metadata**. Each
numbered box is a step inside the script; the arrows show the file handed to the next step.

```
┌ STEP: SOURCE DISCOVERY ───────────────────────────────────────────────┐
│ Collect inputs from --data-dir / --files / default data/raw            │
│ For each file, SHA256 it and look it up in trained_files_registry.json │
│   • --retrain      → skip files already in the registry (new only)     │
│   • --force-retrain→ ignore registry, take everything                  │
│   • default        → only run if a path's models are missing           │
│ Bucket survivors into SRC_LOG / SRC_PCAP / SRC_JSON / SRC_CSV          │
└──────────────────────────────┬─────────────────────────────────────────┘
                               ▼
┌ STEP 0-A/0-B: PRE-PROCESS raw inputs into feature JSON ────────────────┐
│ .log  → python -m dns_detect.features.extractor --input L --output J   │
│ .pcap → tshark → dns_parser → J      (only if tshark installed)        │
│ Registers each ORIGINAL source file in trained_files_registry.json     │
└──────────────────────────────┬─────────────────────────────────────────┘
                               ▼
┌ STEP 0-C: MERGE ───────────────────────────────────────────────────────┐
│ Concatenate all JSON + CSV records → data/processed/merged_features_all.json │
│ Write training_provenance.json (source files, counts, checksums)       │
└──────────────────────────────┬─────────────────────────────────────────┘
                               ▼
┌ STEP 0-D: EDA (profiling, non-gating) ─────────────────────────────────┐
│ python -m dns_detect.features.eda → eda_report.json                    │
│ class balance · missing values · per-feature stats · correlations      │
└──────────────────────────────┬─────────────────────────────────────────┘
                               ▼
┌ STEP 1: LABEL ─────────────────────────────────────────────────────────┐
│ python -m dns_detect.fusion.bridge --label-only                        │
│ attack_count ≥ 1 → label 1, else 0  → merged_features_labeled.json     │
└──────────────┬───────────────────────────────┬────────────────────────┘
               ▼                                ▼
┌ STEP 2: TRAIN PATH A ───────────────┐  ┌ STEP 3: TRAIN PATH B ──────────────┐
│ python -m dns_detect.models.path_a  │  │ python -m dns_detect.models.        │
│   --train merged_features_labeled   │  │   path_b_train --filename …        │
│ 70/15/15 stratified split           │  │ 70/15/15 CHRONOLOGICAL split        │
│ fit StandardScaler on TRAIN only    │  │ min/range from TRAIN only           │
│ train RF (200 trees)                │  │ build 20-length benign-only windows │
│ train Transformer (seq len 10)      │  │ train Trafficformer (reconstruction)│
│ calibrate threshold on VAL (F1 max) │  │ threshold = mean+2.5·std on benign  │
│ final metrics on held-out TEST      │  │   VAL; final metrics on TEST        │
│ → dns_tunnel_rf.pkl, …transformer,  │  │ → dns_trafficformer.h5,             │
│   dns_scaler.pkl, dns_threshold.json│  │   …_threshold.json, …_norm.json     │
└──────────────┬──────────────────────┘  └───────────────┬────────────────────┘
               └───────────────┬───────────────────────────┘
                               ▼
┌ STEP: SAVE MEMORY + AWARENESS ─────────────────────────────────────────┐
│ training_metadata.json  (last_trained, sample counts, feature_snapshot,│
│                          training_history[-10])                        │
│ evaluation_metrics.json (path_a + path_b held-out test metrics)        │
│ regenerate scripts/pipeline_awareness_check.sh (drift check for runtime)│
└────────────────────────────────────────────────────────────────────────┘
```

**Why the splits matter (anti-leakage):** scaler/normalization are fit on train only;
sequences and windows are built *inside* each split so none straddles a boundary; the
threshold is tuned on validation; the test set touches neither training nor calibration, so
its metrics are the honest ones. Path B additionally trains on **benign windows only** (an
autoencoder should learn "normal") and splits by **time**, not shuffled.

---

### 15.2 Detection process flow — `./scripts/run_pipeline.sh`

The goal: score **new** logs with the already-trained models and emit alerts. Nothing is
retrained here.

```
┌ PREFLIGHT ─────────────────────────────────────────────────────────────┐
│ • models/ contains Path A (and optionally Path B) artifacts?           │
│ • `from dns_detect.config import settings` imports OK? (PYTHONPATH=src) │
│ • deps present (pandas, sklearn, tensorflow, …)                        │
│ • data/raw/*.log exist, or cached week3_features_all.json exists?      │
│ • source pipeline_awareness_check.sh → print training context + drift  │
│ If no models at all → STOP: "run ./scripts/train_models.sh first"      │
└──────────────────────────────┬─────────────────────────────────────────┘
                               ▼
┌ STEP 1 — FEATURE EXTRACTION ───────────────────────────────────────────┐
│ python -m dns_detect.features.extractor   (batch mode, scans data/raw) │
│ raw *.log ──regex parse──► per-query records + 6 heuristic flags       │
│ → data/processed/week3_features_all.json                               │
│ (skipped by --detect-only; stops here if --week3-only)                 │
└──────────────────────────────┬─────────────────────────────────────────┘
                               ▼
┌ STEP 2 — ML BRIDGE (inference) ────────────────────────────────────────┐
│ python -m dns_detect.fusion.bridge --week3 … --output … --weight-a 0.6 │
│                                     --weight-b 0.4 [--path-b-model …]   │
│                                                                         │
│   load_as_dataframe → FEATURES_8                                        │
│        │                                                                │
│   ┌────┴─ Path A: joblib.load RF + keras transformer + scaler ─────┐   │
│   │   X_scaled → RF.predict_proba  ┐                               │   │
│   │   seqs(10) → transformer       ┘ ml_score_A = 0.6·RF + 0.4·TF  │   │
│   └──────────────────────────────────────────────────────────────┘   │
│   ┌────── Path B: load trafficformer + threshold + norm ───────────┐   │
│   │   lengths → normalize → windows(20) → reconstruct → MSE error  │   │
│   │   ml_score_B = sigmoid(z(error)) ; anomaly = error > threshold │   │
│   └──────────────────────────────────────────────────────────────┘   │
│   merge:  ml_combined_score = 0.6·A + 0.4·B                            │
│           ml_combined_label = score ≥ calibrated threshold             │
│           ml_threat_score   = 0.4·(attack_count/6)+0.35·A+0.25·B       │
│           ml_confidence      = HIGH/MEDIUM/LOW/CLEAN                    │
│ → data/processed/week3_features_with_ml.json  (+10 ML columns)         │
│ (if a model is missing, that path's scores = 0 and it's skipped)       │
└──────────────────────────────┬─────────────────────────────────────────┘
                               ▼
┌ STEP 3 — DETECTION ENGINE ─────────────────────────────────────────────┐
│ python -m dns_detect.detection.engine --input … --output … --zscore 2 --csv │
│   load JSON → detect ML columns present? (enables rules 5 & 6)         │
│   build Z-score baseline from the BENIGN subset only                   │
│   run: Rule1 NXDOMAIN · Rule2 multi-client · Rule3 tunneling(AND) ·     │
│        Rule4 deep-subdomain · Z-score · Rule5 ML label ·               │
│        Rule6 ML threat (deduped vs Rule5) · optional MDTI enrichment   │
│ → week4_unified_alerts.json  (+ week4_unified_alerts.csv)              │
└──────────────────────────────┬─────────────────────────────────────────┘
                               ▼
┌ STEP 4 — MONITORING ───────────────────────────────────────────────────┐
│ python -m dns_detect.monitoring.monitor --live … --alerts … --output … │
│   PSI drift per feature vs training feature_snapshot                   │
│   alert-volume sanity + ML-score saturation check                      │
│ → monitoring_report.json  { retrain_recommended: true/false, reasons } │
│   run_pipeline.sh prints "RETRAIN recommended" or "models healthy"     │
└────────────────────────────────────────────────────────────────────────┘
```

---

### 15.3 One query's journey (the micro-flow)

To make it concrete, follow a single log line `x9f2kd.base32.lab.local` end to end:

1. **Extractor** parses the line → record with `entropy≈4.6`, `query_length=22`,
   `subdomain_depth=2`, and because of `.base32.` the Encoding detector fires →
   `attack_signature="ENCODING"`, `attack_count=1`.
2. **Bridge / Path A** turns it into the 8-feature vector, scales it, and the RF +
   Transformer ensemble produce `ml_score_A` (e.g. 0.82).
3. **Bridge / Path B** reconstructs the surrounding 20-length window of query lengths; a
   normal-length name reconstructs well, so `ml_score_B` may be low (e.g. 0.20).
4. **Bridge / fusion:** `ml_combined_score = 0.6·0.82 + 0.4·0.20 = 0.57`; if that clears the
   calibrated threshold, `ml_combined_label=1`, `ml_confidence="MEDIUM"`; and
   `ml_threat_score = 0.4·(1/6)+0.35·0.82+0.25·0.20 = 0.40`.
5. **Engine:** Rule 3 does *not* fire (length 22 < 100), but **Rule 5** fires on
   `ml_combined_label==1` → a High/Medium alert with MITRE T1572/T1568/T1048, the domain,
   client IP, the ML scores in `details`, and an investigation priority.
6. **Monitoring** later sees this record's features in the live set and factors them into
   the PSI drift comparison against the training snapshot.

---

### 15.4 Control-flow summary (who calls whom)

```
train_models.sh ─calls→ features.extractor      (per .log)
                ─calls→ features.eda
                ─calls→ fusion.bridge --label-only
                ─calls→ models.path_a --train     → imports parsing.dns_parser
                ─calls→ models.path_b_train       → imports parsing.dns_parser,
                                                      models.path_a.transformer_encoder

run_pipeline.sh ─calls→ features.extractor        (batch)
                ─calls→ fusion.bridge              → imports parsing.dns_parser,
                                                      models.path_a, models.path_b_predict
                ─calls→ detection.engine
                ─calls→ monitoring.monitor

every module ──► utils.paths.PROJECT_ROOT ──► config/settings.yaml, models/, data/
```

The package has a clean dependency spine: `parsing/dns_parser.py` is the leaf everything
reads through; `models/path_a.py` is imported by both `path_b_train.py` and `fusion/bridge.py`;
and `utils/paths.py` + `config.py` anchor every module to the project root so no path is
machine-specific.
```