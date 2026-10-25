# DNS Traffic Anomaly Detection — Deep Audit Report

**Date:** 2026-10-23
**Auditor:** Claude (AI-assisted code & architecture review)
**Project:** DNS Traffic Anomaly Detection — CADT Capstone Project
**Branch:** `restructure`

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture & Logic Walkthrough](#architecture--logic-walkthrough)
3. [Running the Project](#running-the-project)
   - [Native Windows](#native-windows)
   - [Kali VM (Lab Testing)](#kali-vm-lab-testing)
   - [Technitium DNS Server Setup](#technitium-dns-server-setup)
4. [Attack Simulator Setup](#attack-simulator-setup)
5. [Build Fix — attack.c Warnings](#build-fix--attackc-warnings)
6. [Deep Audit: Standards Compliance](#deep-audit-standards-compliance)
   - [What Follows Best Practice](#-what-follows-best-practice)
   - [Issue 1: Circular Labeling](#issue-1-circular-labeling)
   - [Issue 2: Rule 3 OR vs AND](#issue-2-rule-3--or-instead-of-and-for-tunneling-detection)
   - [Issue 3: Alert Duplication](#issue-3-rules-5-and-6-double-fire-no-alert-deduplication)
   - [Issue 4: Contaminated Z-score Baseline](#issue-4-z-score-baseline-built-from-attack-contaminated-data)
   - [Issue 5: Single-Feature Autoencoder](#issue-5-path-b-uses-only-query_length)
   - [Issue 6: OR-Gate Fusion](#issue-6-fusion-or-gate-bypasses-weighted-scores)
   - [Minor Issues](#minor-issues)
7. [Standards Reference Table](#standards-reference-table)
8. [Improvement Recommendations](#improvement-recommendations)
9. [Sources](#sources)

---

## Project Overview

Detects DNS-based attacks (tunneling, NXDOMAIN floods, amplification, cache poisoning) using a two-path ML fusion approach:

- **Path A:** Random Forest + Transformer ensemble (supervised classification)
- **Path B:** Trafficformer autoencoder (unsupervised anomaly detection)
- **ML Bridge:** Fuses both paths into a combined threat score
- **Detection Engine:** 6 rules + Z-score + MITRE ATT&CK mapping

---

## Architecture & Logic Walkthrough

```
Raw DNS Logs (.log)
       │
       ▼
┌─────────────────────────────────────────────┐
│  STEP 1: Feature Extraction (extractor.py)  │
│  Parses Technitium log lines → per-domain   │
│  feature records (JSON)                     │
└─────────────────┬───────────────────────────┘
                  │  week3_features_all.json
                  ▼
┌─────────────────────────────────────────────┐
│  STEP 2: ML Bridge (bridge.py)              │
│  Runs Path A + Path B → merges scores       │
└────┬──────────────────────────┬─────────────┘
     │                          │
     ▼                          ▼
┌──────────────────┐  ┌───────────────────────┐
│  Path A (RF+TF)  │  │  Path B (Trafficformer)│
│  8-feature vector│  │  Query-length series   │
│  → ml_score_A    │  │  → ml_score_B          │
└──────────────────┘  └───────────────────────┘
                  │
                  ▼  week3_features_with_ml.json
┌─────────────────────────────────────────────┐
│  STEP 3: Detection Engine (engine.py)       │
│  6 rules → unified alerts                   │
└─────────────────────────────────────────────┘
                  │
                  ▼  week4_unified_alerts.json
```

### STEP 1 — Feature Extractor (`src/dns_detect/features/extractor.py`)

Parses raw Technitium `.log` lines and computes per-domain features:

| Feature | What it measures |
|---------|-----------------|
| `query_length` | Length of the full domain string |
| `entropy` | Shannon entropy — randomness of characters (tunneling = high) |
| `subdomain_depth` | How many dots — `a.b.c.d.lab.local` = 5 levels |
| `numeric_ratio` | % of digits in domain name |
| `first_label_length` | Length of leftmost label |
| `answer_size` | Number of answers in the response |
| `response_code` | NOERROR, NXDOMAIN, SERVFAIL, etc. |
| `attack_count` | How many of the 6 built-in heuristic patterns match |
| `attack_signature` | Which patterns matched (e.g. `NXDOMAIN_FLOOD,HIGH_ENTROPY`) |

**Output:** `week3_features_all.json`

### STEP 2 — ML Bridge (`src/dns_detect/fusion/bridge.py`)

#### Path A — Supervised Classification (`src/dns_detect/models/path_a.py`)

Two models working together on the 8-feature vector:

1. **Random Forest** (200 trees, balanced classes) → `P(attack)` per query
2. **Transformer** (2 blocks, 2 heads) — takes sequences of 10 feature vectors, outputs `P(attack)` via sigmoid

Ensemble formula:
```
ml_score_A = rf_weight × RF_prob + tf_weight × TF_prob  (default 60/40)
```

Threshold calibrated via precision-recall F1 optimization on the validation set.

#### Path B — Unsupervised Anomaly Detection (`src/dns_detect/models/path_b_train.py` / `path_b_predict.py`)

1. Converts queries to a 1-D time series of query lengths
2. **Trafficformer** autoencoder (3 transformer blocks) learns to reconstruct windows of 20 consecutive query lengths
3. At inference: `reconstruction_error = MSE(input_window, reconstructed_window)`
4. If error > threshold → anomaly
5. `ml_score_B` = sigmoid of the Z-score of the reconstruction error (normalized to 0–1)

Threshold = `mean_error + 2.5 × std_error` from validation set.

#### Score Fusion

```
ml_combined_score = 0.6 × ml_score_A + 0.4 × ml_score_B

ml_combined_label = 1 if (ml_label_A == 1) OR (ml_label_B == 1) OR (combined_score ≥ 0.5)

ml_threat_score   = 0.4 × (attack_count/6) + 0.35 × ml_score_A + 0.25 × ml_score_B

ml_confidence = HIGH (≥0.8) | MEDIUM (≥0.5) | LOW (≥0.3) | CLEAN (<0.3)
```

**Output:** `week3_features_with_ml.json`

### STEP 3 — Detection Engine (`src/dns_detect/detection/engine.py`)

6 detection rules on the ML-enriched data:

| Rule | Type | What it catches | Severity |
|------|------|----------------|----------|
| **Rule 1** Excessive NXDOMAIN | Sentinel | >200 NXDOMAIN per client per 15min | Medium/High |
| **Rule 2** Multi-client errors | Sentinel | ≥2 clients error on same domain | Medium |
| **Rule 3** DNS tunneling | Heuristic | query_length >100 OR entropy >4.0 | High |
| **Rule 4** Deep subdomains | Heuristic | subdomain_depth >5 | Medium |
| **Rule 5** ML attack label | ML | ml_combined_label == 1 | High |
| **Rule 6** ML threat score | ML | ml_threat_score ≥ 0.7 | High |

Plus **Z-score statistical detection** and optional **Microsoft Defender TI** enrichment.

**Output:** `week4_unified_alerts.json` + `.csv`

### Training Flow (one-time)

```
week3_features_all.json
       │
       ├──► bridge.py --label-only → week3_features_labeled.json
       │         (labels from attack_count: ≥1 → attack)
       │
       ├──► path_a.py --train → RF + Transformer models
       │
       └──► path_b_train.py → Trafficformer autoencoder
```

---

## Running the Project

### Native Windows

**Prerequisites:** Python 3.13 (Windows Store), Git Bash

```bash
# Install dependencies
cd /c/Programming-CTF/Detecting-DNS-Traffic
python3 -m pip install -r requirements.txt

# Verify
PYTHONPATH=src python3 -c "from dns_detect.config import settings; print('OK')"

# Train once (models already shipped, optional)
./scripts/train_models.sh

# Run detection
./scripts/run_pipeline.sh
```

**PowerShell alternative (no Git Bash needed):**

```powershell
cd C:\Programming-CTF\Detecting-DNS-Traffic
$env:PYTHONPATH = "src"
python -m dns_detect.features.extractor
python -m dns_detect.fusion.bridge --week3 data/processed/week3_features_all.json --output data/processed/week3_features_with_ml.json --path-b-model dns_trafficformer --weight-a 0.6 --weight-b 0.4
python -m dns_detect.detection.engine --input data/processed/week3_features_with_ml.json --output data/processed/week4_unified_alerts.json --zscore 2.0 --csv
```

**Windows gotchas:**
- `--break-system-packages` flag in scripts is Linux-only — install deps upfront to avoid it
- CRLF line endings: fix with `sed -i 's/\r$//' scripts/*.sh` if needed

### Kali VM (Lab Testing)

#### Lab Topology

```
┌─────────────┐      DNS attack traffic      ┌──────────────────────┐
│   Kali VM   │ ───────────────────────────▶ │  Technitium DNS      │
│  attack.c   │   (lab.local, port 53)       │  (Docker container)  │
└─────────────┘                              └──────────┬───────────┘
                                                        │ .log files
                                                        ▼
                                             ┌──────────────────────┐
                                             │  Detection pipeline  │
                                             └──────────────────────┘
```

### Technitium DNS Server Setup

```bash
cd infra/technitium-elk
docker compose up -d technitium-dns
```

**Configuration (http://localhost:5380):**

1. **Zones** → Add Zone → `lab.local` (Primary)
2. Add DNS records:

| Type | Name | Value |
|------|------|-------|
| A | `@` | `<Kali IP>` |
| A | `www` | `<Kali IP>` |
| TXT | `@` | `"v=spf1 a mx ~all"` |
| MX | `@` | `mail.lab.local` (priority 10) |
| A | `mail` | `<Kali IP>` |
| NS | `@` | `ns1.lab.local` |
| A | `ns1` | `<Kali IP>` |

3. **Settings → Logging:**
   - ☑ **Log All Queries** (critical — without this, only admin logs are captured)
   - ☑ **Use Local Time**
   - **Enable Logging To** → File
   - **Log Folder Path** → `/etc/dns/logs` (maps to `./data/dns_logs/` on host)
   - Save Settings

4. **Verify:** `dig @127.0.0.1 lab.local`

---

## Attack Simulator Setup

### Build (Kali only — requires Linux raw sockets)

```bash
cd attacks
make clean && make
```

### Attack Flags

| Flag | Attack |
|------|--------|
| `--random-subdomains` (needs `-w wordlist`) | Subdomain/tunneling flood |
| `--nxdomain-flood` (needs `-W wordlist`) | NXDOMAIN flood |
| `--amplification` | EDNS0 + ANY amplification |
| `--cache-poison` | Cache poisoning sim |
| `--random-types` / `--random-ports` / `--edns0-buffer` | Query/port/buffer variation |
| `--all-attacks` | Everything |
| `-t` threads · `-r` qps · `-d` duration(s) | Load controls |

### Running Attacks

```bash
# Generate wordlists
echo -e "admin\ntest\nmail\nwww\nftp\ndev\nstaging\napi\ndb\nbackup\nvpn\nportal\nlogin\ncloud\nintranet" > /tmp/subdomains.txt
echo -e "randomjunk123\nthisdomaindoesnotexist\nfakedomain99\nasdqwe456\nnonexistent\nbogus-host\nzzz-invalid" > /tmp/nxdomains.txt

# Light test — 15 seconds
sudo ./attack 127.0.0.1 lab.local -t 4 -r 500 -d 15 --random-subdomains -w /tmp/subdomains.txt -W /tmp/nxdomains.txt

# Full attack — all types
sudo ./attack 127.0.0.1 lab.local --all-attacks -t 8 -r 5000 -d 120 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -W /usr/share/wordlists/dirb/common.txt
```

### Generate Benign Baseline Traffic

```bash
for i in $(seq 1 100); do
  dig @127.0.0.1 lab.local A +short
  dig @127.0.0.1 www.lab.local A +short
  dig @127.0.0.1 mail.lab.local MX +short
  sleep 0.1
done
```

### Feed Logs Into Pipeline

```bash
cp infra/technitium-elk/data/dns_logs/*.log data/raw/
./scripts/run_pipeline.sh
```

---

## Build Fix — attack.c Warnings

Two issues were fixed in `attack.c`:

### 1. `printf` with NULL (`%s` format)

`DEFAULT_WORDLIST` and `DEFAULT_NXDOMAIN_WORDLIST` are `#define`d as `NULL`, passed to `%s` in `print_usage()`.

**Fix:** Ternary guard:
```c
printf("  -w PATH  Subdomain wordlist (default: %s)\n",
       DEFAULT_WORDLIST ? DEFAULT_WORDLIST : "none");
```

### 2. `strncpy` from NULL source

Same macros fed into `strncpy` at struct initialization.

**Fix:** Removed dead code — the struct is already zero-initialized, so copying NULL was a no-op anyway:
```c
/* wordlist defaults are NULL — paths stay zero-initialized */
```

**Commits:** `f7c9ec9`, `758b8d0` on `restructure` branch.

---

## Deep Audit: Standards Compliance

### ✅ What Follows Best Practice

| Component | Standard/Source | Why it's correct |
|-----------|----------------|-----------------|
| Two-path fusion (supervised + unsupervised) | NIST SP 800-86, SANS ICS | Combines signature detection (known attacks) with anomaly detection (zero-day) |
| MITRE ATT&CK mapping | MITRE ATT&CK Framework, NIST CSF | Every rule maps to real tactics/techniques (T1572, T1568, T1048) |
| Rule 1 — NXDOMAIN flood | Microsoft Sentinel ASIM DNS | Time-windowed (15min) + per-client grouping + threshold matches Sentinel analytic rule |
| Rule 3 features — length + entropy | Nadler et al. 2019 | Length >100 and entropy >4.0 are well-established tunneling indicators |
| F1 threshold calibration | ML best practice for imbalanced datasets | PR-curve F1 optimization is correct for cybersecurity where precision matters |
| Path B reconstruction anomaly | Mirsky et al. 2018 (Kitsune) | Autoencoder reconstruction error as anomaly signal is standard in network anomaly detection |

---

### Issue 1: Circular Labeling

**Code:** `bridge.py` — `label = 1 if attack_count >= 1 else 0`

Labels come from the extractor's own 6 heuristic patterns. The ML is trained to mimic the heuristics — it can never detect attacks the heuristics miss.

| Standard | Reference |
|----------|-----------|
| **NIST AI 100-2e2025** | [Adversarial ML Taxonomy](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) — classifies data poisoning as a training-time attack. Circular labels are self-poisoning. |
| **Medina-Arco et al. 2024** | [Contaminated Training Datasets for ML-NIDS](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10819357/) — mislabeled attack traffic in training sets degrades IDS accuracy. |
| **CIC-Bell-DNS-2021** | [UNB Dataset](https://www.unb.ca/cic/datasets/dns-2021.html) — benchmark DNS dataset with labels from independent threat intelligence feeds, not self-detection. |
| **arXiv 2305.01337** | [Better Labeling for Network Security Datasets](https://ar5iv.labs.arxiv.org/html/2305.01337) — label quality directly determines classifier ceiling. |

**Correct practice:** Labels from independent ground truth: curated datasets (CIC-Bell-DNS-2021), threat intel feeds, or human analyst review.

---

### Issue 2: Rule 3 — OR Instead of AND for Tunneling Detection

**Code:** `engine.py` — fires on `query_length > 100` **OR** `entropy > 4.0` separately.

| Standard | Reference |
|----------|-----------|
| **Nadler et al. 2019** | [DNS Exfiltration Detection](https://arxiv.org/pdf/1709.08395) — iodine tunneling has length >100 AND entropy >3.0. Each feature alone has high false-positive rate. |
| **MITRE ATT&CK T1071.004** | [DNS Detection](https://attack.mitre.org/techniques/T1071/004/) — DET0400 recommends multi-signal behavioral detection over single-feature thresholds. |
| **Microsoft Sentinel DNS Essentials** | [ASIM DNS Rules](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/DNS%20Essentials/Analytic%20Rules/ExcessiveNXDOMAINDNSQueriesStaticThresholdBased.yaml) — tunneling hunting query uses conjunction (length AND unique domains AND total queries). |
| **SafeDNS MITRE Mapping** | [DNS Threats to ATT&CK](https://blog.safedns.com/mapping-dns-layer-threats-to-the-mitre-att-ck-framework/) — recommends chaining DNS anomalies to reduce false positives. |

**Correct practice:** `query_length > 100 AND entropy > 4.0` — both conditions simultaneously.

---

### Issue 3: Rules 5 and 6 Double-Fire (No Alert Deduplication)

**Code:** Rule 5 fires on `ml_combined_label == 1`, Rule 6 fires on `ml_threat_score >= 0.7`. They overlap heavily.

| Standard | Reference |
|----------|-----------|
| **NIST SP 800-61 Rev. 3** | Computer Security Incident Handling Guide — requires correlating related events into incidents. |
| **NIST SP 800-53 Rev. 5** | AU-6 (Audit Record Review) requires correlation. SI-4 (System Monitoring) requires alert aggregation and deduplication. |
| **SOC Alert Fatigue Research** | [Rapid7](https://www.rapid7.com/fundamentals/alert-fatigue-cybersecurity/), [Fidelis](https://fidelissecurity.com/threatgeek/best-practices/strategies-to-reduce-alert-fatigue-in-soc/), [Prophet Security](https://www.prophetsecurity.ai/blog/how-to-reduce-alert-fatigue-in-cybersecurity-best-practices) — SOC teams ignore 30–50% of alerts due to fatigue. |
| **arXiv 2605.08316** | [AI-Driven SOC Alert Screening Survey](https://arxiv.org/pdf/2605.08316) — recommends deduplication and grouping before triage. |

**Correct practice:** Merge Rules 5 and 6 into one, or deduplicate in `run_detection()`.

---

### Issue 4: Z-score Baseline Built from Attack-Contaminated Data

**Code:** `engine.py` — `build_baseline(df)` then `run_detection(df)` — same DataFrame for both.

| Standard | Reference |
|----------|-----------|
| **NIST SP 800-94** | [Guide to IDPS](https://csrc.nist.gov/pubs/sp/800/94/final) — anomaly-based IDPS should build profiles from a known-clean training period. |
| **FortiDDoS Guidance** | Recommends 2–14 day clean learning period "free of attacks and long enough to be representative." |
| **IntechOpen — Anomaly Detection in IDS** | [Chapter 88343](https://www.intechopen.com/chapters/88343) — "requires comprehensive baseline data to define normal patterns." |

**Correct practice:** Build baseline from a separate, verified-clean time period, then apply to new/mixed data.

---

### Issue 5: Path B Uses Only query_length

**Code:** `path_b_train.py` — `data = load_as_array(...)` reduces every query to one integer.

| Standard | Reference |
|----------|-----------|
| **Mirsky et al. 2018 (Kitsune)** | [NDSS 2018](https://arxiv.org/pdf/1802.09089v1.pdf) — reference autoencoder NIDS uses ensemble over multi-dimensional feature vectors, not a single scalar. |
| **Nadler et al. 2019** | [arXiv 1709.08395](https://arxiv.org/pdf/1709.08395) — uses multiple features per query: length, entropy, label count, character distribution, response size. |
| **Nature 2026** | [Anomaly-based IDS Evaluation](https://www.nature.com/articles/s41598-026-38317-w) — multi-feature models consistently outperform single-feature approaches. |
| **arXiv 1906.11246** | [DNS Tunneling Detection](https://arxiv.org/pdf/1906.11246) — computes entropy per label (max, min, avg, median, variance) alongside length and timing features. |

**Correct practice:** Feed the autoencoder a multi-feature window: `[query_length, entropy, inter_arrival_time, subdomain_depth, response_code_numeric]` at minimum.

---

### Issue 6: Fusion OR-Gate Bypasses Weighted Scores

**Code:** `bridge.py` — `ml_combined_label = (label_A == 1) OR (label_B == 1) OR (score >= 0.5)`

| Standard | Reference |
|----------|-----------|
| **Mills et al. 2024** | [Hybrid ML Ensemble Stacking IDS](https://onlinelibrary.wiley.com/doi/full/10.1155/2024/5775671) — weighted stacking where each model's weight is set by validation performance. 99.81% accuracy. |
| **PORTFILER** | [arXiv 2112.13798](https://arxiv.org/pdf/2112.13798) — weighted ensembles balance FP-prone unsupervised detectors against precise supervised ones. |
| **arXiv 2604.14685** | Multi-View Fusion for Provenance-Based IDS — normalize score scales before fusing, use weighted variants. |

**Correct practice:** `ml_combined_label = (ml_combined_score >= calibrated_threshold)` as the sole decision variable. Remove the OR gate.

---

### Minor Issues

| Issue | Current | Better | Standard |
|-------|---------|--------|----------|
| RF+TF weight mismatch | Training uses 0.5/0.5, config says 0.6/0.4, bridge uses 0.6/0.4 | Read from `settings.yaml` everywhere | Configuration management |
| Rule 2 threshold = 2 | Fires when just 2 clients hit same errored domain | Typically 5–10 in production SIEM | Microsoft Sentinel defaults |
| Rule 4 depth > 5 | `a.b.c.d.e.f.google.com` is depth 7 and legit (CDNs) | Combine with entropy or exclude known CDN TLDs | Nadler et al. 2019 |
| No alert rate limiting | Rule 3 caps at 100, Rule 5/6 at 200, no time throttle | Max N alerts per rule per hour | NIST SP 800-61 |
| MITRE T1046 on Z-score | T1046 = Network Service Discovery — wrong for DNS stats | T1071.004 (Application Layer Protocol: DNS) | MITRE ATT&CK |
| No false-positive feedback | No mechanism for analyst to mark FPs | FP labels feed back into retraining | NIST AI 100-2 |

---

## Standards Reference Table

| # | Issue | Primary Standard | Supporting References |
|---|-------|-----------------|----------------------|
| 1 | Circular labeling | **NIST AI 100-2e2025** (data poisoning taxonomy) | CIC-Bell-DNS-2021, Medina-Arco 2024 |
| 2 | OR → AND in Rule 3 | **Nadler et al. 2019** + **MITRE T1071.004 DET0400** | Microsoft Sentinel DNS Essentials |
| 3 | Alert duplication | **NIST SP 800-61 Rev. 3** + **SP 800-53 AU-6/SI-4** | SOC alert fatigue research |
| 4 | Contaminated baseline | **NIST SP 800-94** (clean training period) | FortiDDoS guidance, IntechOpen IDS |
| 5 | Single-feature autoencoder | **Kitsune (NDSS 2018)** (multi-feature ensemble) | Nadler 2019, arXiv 1906.11246 |
| 6 | OR-gate fusion | **Mills et al. 2024** (weighted stacking) | PORTFILER, Multi-View Fusion |

---

## Improvement Recommendations

### High Impact
1. **Real tests** — unit tests that validate parser output, detection rule logic, and score fusion math
2. **CI/CD pipeline** — GitHub Actions workflow for lint + test on push
3. **`pyproject.toml`** — proper Python packaging instead of PYTHONPATH hacks

### Medium Impact
4. **Live/streaming mode** — tail log files in real-time, detect per window
5. **Dashboard / visualization** — alert timeline, attack breakdown, ML score distribution
6. **Split detection engine** — 987-line monolith → separate rule modules
7. **Cross-platform CLI** — `python -m dns_detect.cli train/detect` entry point

### Nice to Have
8. **Alert output formats** — Slack/Discord webhooks, Syslog, STIX/TAXII
9. **Model performance tracking** — accuracy/precision/recall per training run
10. **Full Docker Compose** — DNS server → attack → detection → dashboard in one `docker compose up`
11. **Default wordlists** — ship in `attacks/wordlists/` for first-time users

---

## Sources

- [NIST AI 100-2e2025 — Adversarial ML Taxonomy](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [NIST SP 800-94 — Guide to IDPS](https://csrc.nist.gov/pubs/sp/800/94/final)
- [NIST SP 800-86 — Forensic Techniques in IR](https://csrc.nist.gov/pubs/sp/800/86/final)
- [MITRE ATT&CK T1071.004 — DNS](https://attack.mitre.org/techniques/T1071/004/)
- [Nadler et al. 2019 — DNS Exfiltration Detection](https://arxiv.org/pdf/1709.08395)
- [Mirsky et al. 2018 — Kitsune NDSS](https://arxiv.org/pdf/1802.09089v1.pdf)
- [CIC-Bell-DNS-2021 Dataset](https://www.unb.ca/cic/datasets/dns-2021.html)
- [BCCC-CIC-Bell-DNS-2024 Dataset](https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/malicious-dns-and-attacks-bccc-cic-bell-dns-2024/)
- [Medina-Arco et al. 2024 — Contaminated Training Datasets](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10819357/)
- [Mills et al. 2024 — Hybrid ML Ensemble Stacking IDS](https://onlinelibrary.wiley.com/doi/full/10.1155/2024/5775671)
- [Microsoft Sentinel DNS Essentials — NXDOMAIN Rule](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/DNS%20Essentials/Analytic%20Rules/ExcessiveNXDOMAINDNSQueriesStaticThresholdBased.yaml)
- [SafeDNS — Mapping DNS Threats to MITRE ATT&CK](https://blog.safedns.com/mapping-dns-layer-threats-to-the-mitre-att-ck-framework/)
- [Rapid7 — Alert Fatigue in Cybersecurity](https://www.rapid7.com/fundamentals/alert-fatigue-cybersecurity/)
- [arXiv 2605.08316 — AI-Driven SOC Alert Screening Survey](https://arxiv.org/pdf/2605.08316)
- [IntechOpen — Anomaly Detection in IDS](https://www.intechopen.com/chapters/88343)
- [Nature 2026 — Anomaly-based IDS Comprehensive Evaluation](https://www.nature.com/articles/s41598-026-38317-w)
- [arXiv 1906.11246 — DNS Tunneling Detection Features](https://arxiv.org/pdf/1906.11246)
- [Labeling for Network Security Datasets](https://ar5iv.labs.arxiv.org/html/2305.01337)
- [Fidelis Security — SOC Alert Fatigue](https://fidelissecurity.com/threatgeek/best-practices/strategies-to-reduce-alert-fatigue-in-soc/)
- [Prophet Security — Alert Fatigue Best Practices](https://www.prophetsecurity.ai/blog/how-to-reduce-alert-fatigue-in-cybersecurity-best-practices)
