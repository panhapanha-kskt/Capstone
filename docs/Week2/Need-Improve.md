# Need-Improve: review of the Week 2 training dataset

**DNS Traffic Anomaly Detection · scope: the training data and how it is split, labeled and evaluated (`scripts/train_models.sh` stages 3–9)**

This is a review, not a change. No project code was modified to write it. It combines:
- the Week 2 documents (`PROGRESS.md`, `AddingEDA/REPORT.md`)
- a check of the code and data, run read-only
- research on best practice for machine learning in security
- the Stanford CS229/CS230 cheat sheets (the project's `dns-ml-tuning` skill)

## Summary

Week 2 made the pipeline **trustworthy as engineering**: every row is traceable, exact-copy leakage is gone, labels are no longer circular, and the model is graded only on real labels. What it cannot yet show is that the model **detects DNS tunneling in general**. Four measurements made for this review show the gap:

| Measurement (current labeled data, Week 2 split) | Result | What it means |
|---|---|---|
| Random Forest on the 8 features | F1 **1.000** | looks perfect |
| A one-line rule: record type is TXT/KEY/NULL | F1 **1.000** | a rule this simple does as well as the model, so the data is too easy |
| Random Forest **without** entropy and length | F1 **1.000** | even the weaker features separate the classes, so the test can't rank features or models |
| Train without one tool, test on that tool | recall **0.357** (DNSExfiltrator), **0.318** (dns2tcp) | on a tool it has never seen, the model misses about two thirds of the attack |

The in-sample score says "solved"; the unseen-tool score says the model has mostly learned **these captures**. The priority for Week 3 is therefore **better data and a better evaluation design**, not more model tuning.

---

## 1. How the data compares with best practice

The reference is [Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*](https://www.usenix.org/system/files/sec22summer_arp.pdf) (USENIX Security 2022). It lists ten pitfalls and found every reviewed paper affected by at least three.

| # | Pitfall | Status | Evidence in this project |
|---|---|---|---|
| P1 | Sampling bias: data doesn't represent the real problem | 🔴 | Benign = **one capture, 2 hours, 4 clients** (two are Docker IPs, one is `127.0.0.1`). Attack = **2 tools, 5 captures of ~1.4 min**, sampled to 2,000 queries each |
| P2 | Label inaccuracy | 🟢 | Manifest → behaviour rules → abstain replaced the circular `attack_count` rule |
| P3 | Data snooping: test information leaks into design | 🟡 | Labeling thresholds validated on the data that shaped them; Path A picks RF-only vs RF+GBT on the **test** set |
| P4 | Spurious correlations: shortcuts unrelated to the attack | 🔴 | Attacks are 100 % TXT/KEY, benign has none; one client IP per tool; source file = label; 683 days between attack and benign captures |
| P5 | Biased parameter selection | 🟡 | Same test-set model choice as P3 |
| P6 | Inappropriate baseline | 🔴 | No simple baseline reported; a record-type rule already scores F1 1.0 |
| P7 | Inappropriate performance measures | 🟢 | PR-AUC with its baseline, per-family recall, trusted-label score |
| P8 | Base-rate fallacy: unrealistic attack share | 🔴 | 54.5 % of the data is attack; real DNS traffic is a tiny fraction |
| P9 | Lab-only evaluation | 🔴 | No external dataset; unseen-tool recall 0.32–0.36 |
| P10 | Inappropriate threat model | 🟡 | Not discussed: low-entropy encodings, slow tunnels, A/AAAA tunnels |

---

## 2. What Week 2 did well (keep these)

1. **Provenance on every row** (`source_file`, `source_type`, `label_source`, `dup_key`). This is the traceability practice behind [Datasheets for Datasets](https://arxiv.org/abs/1803.09010v1), and it is what makes every check in this document possible.
2. **Duplicates measured, then handled before splitting.** Hashing the model-visible feature vector before the split is the method used in recent intrusion-detection leakage work ([IoT shortcut-learning study](https://arxiv.org/pdf/2609.28725)). The doc shows the measured leak (79.8 % → 0 %), not just a claim.
3. **Abstain instead of guessing labels**, as in weak supervision ([Snorkel](https://www.vldb.org/pvldb/vol11/p269-ratner.pdf)).
4. **Grading on real labels only.** Separating training labels from evaluation labels addresses P2 and P3.
5. **Labeling rules based on how tunnels behave, not tool signatures** ([Farnham, SANS](https://www.sans.org/white-papers/34152); [Nadler et al.](https://arxiv.org/pdf/1709.08395); [Ozery et al., NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-388-paper.pdf)), with an allowlist for known look-alikes.
6. **Automatic ground truth for lab attacks**, including choosing the right clock. Clock mismatch is a documented cause of time-window labeling errors ([Engelen et al., CICIDS2017](https://intrusion-detection.distrinet-research.be/WTMC2021/Resources/wtmc2021_Engelen_Troubleshooting.pdf)).
7. **Two EDA stages**, including a labeled-vs-unlabeled shift check and an implications section that links findings to decisions.
8. **Honest reporting**: the doc states the split fix didn't change the score and that the data is too easy.
9. **Tests and configuration**: 35 unit tests; thresholds in `config/settings.yaml`, not hard-coded.

---

## 3. What needs to improve

Each item lists the evidence, why it matters, what to do, and how to know it's done. Priorities: 🔴 limits what results can claim · 🟡 weakens a specific result · 🟢 documentation and reproducibility. Effort: S (hours), M (a day or two), L (several days).

### 🔴 N1. The model has learned the captures, not the attack

- **Evidence:** in-sample F1 1.000; leave-one-tool-out recall 0.357 (DNSExfiltrator) and 0.318 (dns2tcp).
- **Why it matters:** the deployed detector will mostly meet tools and sessions it has never seen. The in-sample number is the wrong headline.
- **What to do:** make the **unseen-tool score** the headline metric. Report it next to the in-sample score in every progress report (`scripts/verify_models.py` already has a leave-one-family-out check).
- **Done when:** every results table has both an in-sample and an unseen-tool column.
- **Effort:** S

### 🔴 N2. The split only separates exact copies

- **Evidence:** `dup_key` groups identical feature vectors. Queries from the same tunnel session, under the same parent domain and from the same client, still appear on both sides of the split.
- **Why it matters:** the test measures "recognises a session it has seen". Best practice splits by capture or scenario ([IoT shortcut-learning study](https://arxiv.org/pdf/2609.28725); [ICS meta-review](https://arxiv.org/pdf/2608.24757)) and by time ([TESSERACT](https://arxiv.org/abs/1807.07838)).
- **What to do:** add two more evaluation splits: **grouped by capture or parent domain**, and **by time** (train on earlier captures, test on later ones). Keep the current split as the in-sample number.
- **Done when:** results are reported for three splits (exact-copy, capture/domain, time), and the doc calls the current one "free of exact-copy leakage" rather than "leak-free".
- **Effort:** M

### 🔴 N3. Shortcuts outside the tunnel behaviour

- **Evidence:** a record-type rule (TXT/KEY/NULL) reaches F1 1.000. Benign traffic contains no TXT/KEY queries at all. Each tool has its own client IP. Every source file holds one class. Attack and benign are 683 days apart.
- **Why it matters:** any feature touching record type, client, time or source gives the label away ([Arp et al.](https://www.usenix.org/system/files/sec22summer_arp.pdf) P4; capture artifacts as shortcuts in the [Network intrusion datasets survey](https://arxiv.org/pdf/2502.06688)).
- **What to do:**
  - Collect **benign traffic that uses TXT/MX/KEY**: mail servers (SPF, DKIM, DMARC), ACME/Let's Encrypt challenges, DNSSEC validation.
  - Capture benign and attack traffic **in the same period**, from the **same clients**.
  - Never use client IP, time or source as model features.
- **Done when:** in EDA #1, no single field (record type, client, date, source) separates the classes with AUC above 0.95.
- **Effort:** L (data collection)

### 🔴 N4. No simple baseline

- **Evidence:** best entropy threshold (chosen on training data): F1 0.956. Entropy > 4.0 from the literature: F1 0.883. Record-type rule: F1 1.000. Random Forest: F1 1.000.
- **Why it matters:** without a baseline, the value of ML is unproven (P6). The skill's *ablative analysis* (CS229 §4.3) says the same: the gain has to be measured against something simpler.
- **What to do:** report three baselines (entropy threshold, length threshold, record-type rule) on every split, including the unseen-tool split, next to RF/GBT and Path B.
- **Done when:** a baselines table sits in the results section, and the ML models beat them on the unseen-tool and time splits.
- **Effort:** S

### 🔴 N5. The attack share is unrealistic

- **Evidence:**
  - 54.5 % of the training/test data is attack (attack files sampled to 2,000 queries each, per `docs/week0/MODEL_EVALUATION_2026-10-24.md`).
  - The Random Forest made 0 false alarms on 1,193 benign test rows. That only proves the false-alarm rate is **below about 0.25 %** (the "rule of three" 95 % bound).
  - At that bound, precision at realistic attack shares would be:

| Attack share | Precision (worst case within the bound) | False alarms per 1,000,000 queries |
|---|---|---|
| 50 % (current test) | 0.997 | up to ~1,250 |
| 1 in 100 | 0.801 | up to ~2,490 |
| 1 in 1,000 | 0.285 | up to ~2,510 |
| 1 in 10,000 | 0.038 | up to ~2,510 |

- **Why it matters:** this is the base-rate fallacy ([Axelsson](https://www.profsandhu.com/cs6393_s20/p186-axelsson.pdf); [Base-rate fallacy redux](https://arxiv.org/pdf/2203.08801)). The current benign test set is **too small to prove** the detector is usable. TESSERACT requires realistic class ratios at test time ([Pendlebury et al.](https://arxiv.org/abs/1807.07838)).
- **What to do:**
  - Collect much more benign traffic (days, many clients). With about 300,000 benign test queries, a zero-false-alarm result bounds the rate below 0.001 %.
  - Report precision and false alarms per 1,000,000 queries at attack shares of 1:100, 1:1,000 and 1:10,000.
  - Choose the alarm threshold for a target false-alarm budget, not for maximum F1.
- **Done when:** the results include a precision-at-prevalence table and a stated false-alarm budget.
- **Effort:** M (with N3's data)

### 🔴 N6. The labeling rules were checked on their own development data

- **Evidence:** "0 wrong labels" was measured on the same 18,353 rows whose patterns informed the thresholds (for example, > 50 unique subdomains).
- **Why it matters:** this is development accuracy, not validation (P3).
- **What to do:** validate the rules, unchanged, on an **external** labeled set such as [CIC-Bell-DNS-EXF-2021](https://www.unb.ca/cic/datasets/dns-exf-2021.html). Report coverage, wrong labels and the share left out per family. Freeze the thresholds before looking at the results.
- **Done when:** the doc reports the labeling rules' accuracy on data they were not designed on.
- **Effort:** M

### 🟡 N7. Leaving rows out keeps only the easy cases

- **Evidence:** abstained rows (79 benign in validation, plus attacker background traffic) never reach training.
- **Why it matters:** the training set loses its hardest examples (borderline CDN names, slow tunnels), so the model learns an easier problem than the real one.
- **What to do:** report the share left out per source and per family. Hand-review a sample (e.g. 100 rows) and feed confirmed labels back in.
- **Done when:** the share of rows left out is reported in the Step 8 output and the progress report.
- **Effort:** S

### 🟡 N8. Dropping conflicting rows hides the hardest errors

- **Evidence:** with the NXDOMAIN log included, 35 feature vectors (945 rows) appear with both labels, and Path A drops them.
- **Why it matters:** these are exactly the queries the features cannot separate. Dropping them makes the test look better and hides the cause.
- **What to do:** keep them in a separate **error-analysis** set (CS229 §4.3). Report their count and the share they represent, and use them to justify per-client behaviour features.
- **Done when:** conflicts appear in the results as a named error category, not only in a log line.
- **Effort:** S

### 🟡 N9. Behaviour labels depend on the whole batch and ignore time

- **Evidence:** the labeling rules compute per-domain statistics over the entire input file. A parent domain labeled attack is attack at every moment.
- **Why it matters:** adding or removing other data can change a row's label, so labels aren't reproducible across runs. A long-lived benign domain that once carried a tunnel gets labeled attack throughout.
- **What to do:** compute the rule statistics per time window (e.g. 1 hour per parent domain), and save the labeling settings and allowlist hash with the model metadata.
- **Done when:** relabeling the same data alone or inside a bigger batch gives the same labels.
- **Effort:** M

### 🟡 N10. "Trusted" labels are an assumption, not a check

- **Evidence:** file labels assume every query in a capture is attack or benign. The current tunnel set was filtered to the three tunnel domains (all 10,000 attack rows fall under them), which is good. But this isn't documented or enforced for future captures.
- **Why it matters:** public datasets built this way contain labeling errors ([Engelen et al.](https://intrusion-detection.distrinet-research.be/WTMC2021/Resources/wtmc2021_Engelen_Troubleshooting.pdf); [Errors in CICIDS2017](https://dl.acm.org/doi/10.1007/978-3-031-31108-6_2)).
- **What to do:**
  - Always convert attack captures with `--domain <tunnel domain>`.
  - Record the filter in the datasheet.
  - Audit the trusted labels with confident learning ([Northcutt et al.](https://arxiv.org/pdf/1911.00068), the `cleanlab` package).
- **Done when:** the datasheet lists the domain filter used for every attack capture, and a label-noise audit has been run.
- **Effort:** S–M

### 🟡 N11. Path A and Path B are evaluated on different splits

- **Evidence:** Path A splits by feature vector; Path B splits each class by time (`path_b_train.py`).
- **Why it matters:** the fused detector (Path A + Path B) has no common holdout to be scored on, and the two paths' numbers can't be compared.
- **What to do:** create **one fixed, versioned split file** (row id → train/val/test) shared by both paths and by the fusion evaluation.
- **Done when:** both paths and the fusion report metrics on the same test rows.
- **Effort:** M

### 🟡 N12. Sampling breaks Path B's sequences

- **Evidence:** attack captures were sampled to 2,000 queries per file. The sample keeps time order but leaves gaps.
- **Why it matters:** Path B learns from windows of 20 consecutive queries per client. In sampled attack captures, those windows contain queries that weren't actually consecutive.
- **What to do:** sample **contiguous time blocks** (or whole sessions), not random queries, when balancing classes.
- **Done when:** the sampling method is documented, and attack windows come from consecutive queries.
- **Effort:** S

### 🟡 N13. Results come from one run, without uncertainty

- **Evidence:** F1 0.985 (with the NXDOMAIN log) comes from one seed and one split, with a stand-in Transformer baseline.
- **Why it matters:** with small, highly correlated data, a single split can swing results a lot (CS229 §4.2 recommends k-fold cross-validation for noisy single splits).
- **What to do:** repeat the grouped cross-validation 5 times and report mean ± standard deviation.
- **Done when:** every headline metric has a spread.
- **Effort:** S

### 🟢 N14. The dataset isn't versioned

- **Evidence:** `merged_features_*.json` is overwritten every run, and models don't record which dataset produced them.
- **What to do:** compute a dataset hash (sorted file checksums plus schema) and store it in `training_metadata.json`. Consider DVC for the raw captures ([DVC versioning](https://oneuptime.com/blog/post/2026-01-25-dvc-data-versioning/view); [dataset lineage](https://dev.to/beefedai/implementing-dataset-versioning-and-lineage-for-reproducible-ml-3n7l)).
- **Done when:** any model can be traced to the exact dataset version.
- **Effort:** S

### 🟢 N15. There's no datasheet

- **What to do:** one page in the [Datasheets for Datasets](https://arxiv.org/abs/1803.09010v1) format, covering:
  - motivation
  - composition (rows, classes, families, clients, record types)
  - collection (tools, dates, capture setup, domain filters, sampling)
  - labeling (file / manifest / behaviour, thresholds)
  - known limitations (N1–N12)
  - intended use
- **Done when:** `docs/Week3/DATASHEET.md` exists and the progress report links to it.
- **Effort:** S

### 🟢 N16. Wording in `PROGRESS.md` should be more precise

| Current wording | Suggested |
|---|---|
| "Path A's split no longer leaks" | "Path A's split is free of exact-copy leakage; leakage within a session or capture remains (N2)" |
| "0 wrong labels" | "0 wrong labels on the development data; not yet validated externally (N6)" |
| "F1 0.985, precision 0.971" | "one run, one split, stand-in Transformer baseline (N13)" |
| PR-AUC values | add "at 54.5 % attack share (N5)" |
| Summary | add one line: "unseen-tool recall is 0.32–0.36" (N1) |

**Effort:** S

---

## 4. Recommended evaluation protocol for Week 3

Report this table for every model and baseline:

| Split → | Exact-copy grouped (current) | Capture / domain grouped | Time-based | Leave one tool out | External set (CIC-Bell-DNS-EXF-2021) |
|---|---|---|---|---|---|
| F1 · PR-AUC (mean ± sd, 5 runs) | | | | | |
| Recall per family | | | | | |
| Precision at 1:1,000 attack share | | | | | |
| False alarms per 1,000,000 benign queries | | | | | |

Rows: record-type rule · entropy threshold · length threshold · Path A · Path B · fusion.
Evaluate on **real labels only**, and list conflicting rows separately as an error category.

---

## 5. Roadmap

| Order | Items | Why first | Effort |
|---|---|---|---|
| 1 | N4 baselines, N1 unseen-tool headline, N16 wording | Cheap, and they change how the current results are read | S |
| 2 | N2 extra splits, N13 repeated runs, N11 shared split | Makes every later number comparable and honest | M |
| 3 | N3 + N5 data collection (same period, same clients, benign TXT/MX, long benign capture, low-entropy tunnels) | The single biggest lever: fixes shortcuts, sampling bias and base rate together | L |
| 4 | N6 external validation, N10 label audit, N7 abstain review | Turns "trusted labels" into checked labels | M |
| 5 | N8 error analysis, then per-client behaviour features | Uses the NXDOMAIN finding to guide the model, not just the data | M |
| 6 | N9 windowed labeling, N12 contiguous sampling | Reproducibility and Path B realism | M |
| 7 | N14 dataset hash, N15 datasheet | Reproducibility and documentation | S |

**A diagnostic note from the skill (CS229 §4.3, bias/variance):** when training and test scores are both ≈ 1.0, bias and variance cannot be diagnosed at all, because the test set is too easy to show anything. Roadmap steps 1–3 are what make model tuning meaningful again.

---

## 6. Week 3 checklist

- [ ] Baselines table (record type, entropy, length) next to the models
- [ ] Unseen-tool recall reported as a headline number
- [ ] Capture/domain-grouped and time-based splits added
- [ ] One shared, versioned split for Path A, Path B and fusion
- [ ] 5 repeated runs with mean ± standard deviation
- [ ] Benign capture: several days, many clients, includes TXT/MX/DNSSEC traffic, same period as the attacks
- [ ] Attack captures: more tools (iodine, dnscat2), A/AAAA tunnels, low-entropy encoding, slow rate; manifest recorded
- [ ] Precision and false alarms at 1:100 / 1:1,000 / 1:10,000 attack shares
- [ ] Labeling rules validated on CIC-Bell-DNS-EXF-2021 with frozen thresholds
- [ ] Label-noise audit (confident learning) and hand review of 100 abstained rows
- [ ] Conflicting rows reported as an error category
- [ ] Dataset hash in the model metadata, and `DATASHEET.md` written
- [ ] `PROGRESS.md` wording updated (N16)

---

## Appendix: how the new measurements were made

All read-only, on `labeled_tunnels.json` + `labeled_benign.json` (18,353 rows), using the project's own feature loader (`load_as_dataframe`, `FEATURES_8`) and Week 2 split (`grouped_split` on `feature_vector_key`, seed 42):
- **Baselines:** best entropy threshold chosen on the training split only, then scored on the test split. Entropy > 4.0 from the literature. Record type in {TXT, KEY, NULL}.
- **Ablation:** Random Forest (200 trees, balanced class weights) with entropy and length removed.
- **Unseen tool:** Random Forest trained on everything except one family (plus all benign), recall measured on that family.
- **Attack share:** precision = R·π / (R·π + FPR·(1−π)), with FPR at its 95 % upper bound of 3 / 1,193 (no false alarms observed on 1,193 benign test rows).

## References

- Arp, D. et al. *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security 2022: https://www.usenix.org/system/files/sec22summer_arp.pdf · CACM 2024 summary: https://cacm.acm.org/research-highlights/pitfalls-in-machine-learning-for-computer-security/
- Pendlebury, F. et al. *TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time*, USENIX Security 2019: https://arxiv.org/abs/1807.07838 · extended version: https://arxiv.org/pdf/2402.01359
- Gebru, T. et al. *Datasheets for Datasets*: https://arxiv.org/abs/1803.09010v1
- Engelen, G., Rimmer, V., Joosen, W. *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*: https://intrusion-detection.distrinet-research.be/WTMC2021/Resources/wtmc2021_Engelen_Troubleshooting.pdf
- *Errors in the CICIDS2017 Dataset and the Significant Differences in Detection Performances It Makes*: https://dl.acm.org/doi/10.1007/978-3-031-31108-6_2
- Axelsson, S. *The Base-Rate Fallacy and the Difficulty of Intrusion Detection*: https://www.profsandhu.com/cs6393_s20/p186-axelsson.pdf
- *Base-Rate Fallacy Redux and a Deep Dive Review in Cybersecurity*: https://arxiv.org/pdf/2203.08801
- Northcutt, C., Jiang, L., Chuang, I. *Confident Learning: Estimating Uncertainty in Dataset Labels*: https://arxiv.org/pdf/1911.00068
- *Unmasking Shortcut Learning in IoT Intrusion Detection*: https://arxiv.org/pdf/2609.28725
- *ICS Cybersecurity Datasets: A Systematic Meta-Review*: https://arxiv.org/pdf/2608.24757
- *Network Intrusion Datasets: A Survey, Limitations, and Recommendations*: https://arxiv.org/pdf/2502.06688
- Farnham, G. *Detecting DNS Tunneling*, SANS: https://www.sans.org/white-papers/34152
- Nadler, A., Aminov, A., Shabtai, A. *Detection of Malicious and Low Throughput Data Exfiltration Over the DNS Protocol*: https://arxiv.org/pdf/1709.08395
- Ozery, Y., Nadler, A., Shabtai, A. *Information-Based Heavy Hitters for Real-Time DNS Data Exfiltration Detection*, NDSS 2024: https://www.ndss-symposium.org/wp-content/uploads/2024-388-paper.pdf
- Ratner, A. et al. *Snorkel*, VLDB 2018: https://www.vldb.org/pvldb/vol11/p269-ratner.pdf
- CIC-Bell-DNS-EXF-2021 dataset: https://www.unb.ca/cic/datasets/dns-exf-2021.html
- DVC data versioning: https://oneuptime.com/blog/post/2026-01-25-dvc-data-versioning/view · dataset lineage: https://dev.to/beefedai/implementing-dataset-versioning-and-lineage-for-reproducible-ml-3n7l
- Amidi, A. & S. *Stanford CS229 / CS230 cheat sheets* (project skill `dns-ml-tuning`): bias/variance diagnosis, k-fold cross-validation, ablative and error analysis.
