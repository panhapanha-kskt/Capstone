# Model Evaluation Report — 2026-10-24

Status of the DNS tunnel detector after the provenance-labeled training run of
2026-10-23 (`./scripts/train_models.sh --files labeled_tunnels.json labeled_benign.json --force-retrain`),
with an independent check of whether the scores mean what they appear to mean.

**Summary:** Path A scores 1.00 on every metric, and the pipeline has no label
leakage. But the task is close to trivial on this data: a single feature
(`query_length`) separates the classes with ROC-AUC 0.998. The model generalizes
poorly to tunneling tools it has not seen, Path B produced no evaluation metrics,
and the Path A + Path B fusion uses the wrong threshold.

---

## 1. Progress so far

### 1.1 Data labeling (provenance labels)

Every query is labeled by the capture file it came from (`scripts/make_labeled_features.py`),
not by the heuristic rules.

| Source file | Queries used | Family | Label |
|---|---|---|---|
| `benign_dns.pcap` | 5,662 (all) | benign | 0 |
| `dns2tcp_key_down.pcapng` | 2,000 of 22,996 | dns2tcp | 1 |
| `dns2tcp_key_up.pcapng` | 2,000 of 25,018 | dns2tcp | 1 |
| `dns2tcp_txt_down.pcapng` | 2,000 of 23,574 | dns2tcp | 1 |
| `dns2tcp_txt_up.pcapng` | 2,000 of 25,014 | dns2tcp | 1 |
| `dnsexfiltrator_txt_up.pcap` | 2,000 of 111,718 | dnsexfiltrator | 1 |
| **Total** | **15,662** | | 5,662 benign / 10,000 attack (63.8% attack) |

Attack files were sampled at 2,000 queries each (`--max-per-file 2000`, seed 42).

Outputs: `data/processed/labeled_benign.json`, `data/processed/labeled_tunnels.json`,
merged into `merged_features_all.json`, then `merged_features_labeled.json`.

### 1.2 Training run

- **Path A:** Random Forest + HistGradientBoosting on 8 features, with a
  Transformer sequence classifier kept as a baseline only. Split 70/15/15
  (stratified): train 10,963 / val 2,349 / test 2,350.
- **Path B:** Trafficformer autoencoder on 5 features, per-client windows of 20
  queries, trained on benign windows only. Threshold = 99th percentile of benign
  validation reconstruction error (0.00278).
- Total run time: 14 m 9 s. All artifacts are in `models/`.

### 1.3 Reported results (`models/evaluation_metrics.json`)

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC | Threshold |
|---|---|---|---|---|---|---|
| **Path A: RF only (chosen)** | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.955 |
| Path A: RF + GBT | 1.000 | 0.999 | 1.000 | 1.000 | 1.000 | 0.977 |
| Path A: Transformer baseline | 0.684 | 0.885 | 0.772 | 0.788 | 0.683 | 0.5 |
| Path B: Trafficformer | — | — | — | — | — | 0.00278 |
| Heuristic rules (`attack_count > 0`) | 0.875 | 0.943 | — | — | — | — |

- The PR-AUC you would get by chance (the share of attacks) is 0.638.
- Path A recall per family on the test set: dns2tcp 1.000 (n=1,219), dnsexfiltrator 1.000 (n=281).
- Path B has no metrics because its test set contained no attacks (see §3.1).

---

## 2. Verification: does the 1.00 mean what we claim?

Checks were run with `scripts/verify_models.py` plus an extra diagnostic script.

| Check | Result | Verdict |
|---|---|---|
| Label-shuffle (train on permuted labels) | ROC-AUC 0.509, PR-AUC 0.646 (chance ≈ 0.638) | ✅ No pipeline leakage |
| Split so no domain appears in both train and test | F1 1.00, PR-AUC 1.00 | ✅ Not caused by repeated domains |
| Feature vectors that occur with both labels | 0 | Classes do not overlap at all |
| `query_length` alone | ROC-AUC 0.998 (one split at 25.5 → F1 0.998) | ⚠ One feature is enough |
| `query_entropy` alone | ROC-AUC 0.994 | ⚠ |
| Train without dns2tcp, test on dns2tcp | Recall 0.318, PR-AUC 1.0 | ⚠ Weak on unseen tool |
| Train without dnsexfiltrator, test on it | Recall 0.000, PR-AUC 1.0 | ⚠ Fails on unseen tool |

**Feature importance (RF):**

| Feature | Importance |
|---|---|
| query_entropy | 0.316 |
| query_length | 0.259 |
| has_digits | 0.171 |
| digit_ratio | 0.149 |
| subdomain_count | 0.058 |
| longest_label | 0.040 |
| unique_char_ratio | 0.008 |
| answer_count | 0.000 |

**What this means.** The 1.00 is not a bug, but it reflects how easy this dataset
is, not how capable the model is.

In the unseen-tool tests, PR-AUC stayed at 1.0 while recall collapsed. So the
model still ranks unseen tunnels above benign traffic. It is the decision
threshold, tuned on the tools seen in training, that fails to transfer.

### 2.1 Why the dataset is easy

- **One host and one capture per class.** All benign traffic is about 50 seconds
  of browsing (2026-10-23 23:15:26 to 23:16:16) from a single client,
  `192.168.223.132`. Each attack file is one client talking to one tunnel domain:
  `dns2tcp-key.com`, `dns2tcp-txt.com` or `daumel.xyz`.
- **Very little variety.** 11,070 of the 15,662 feature rows are exact duplicates.
  Distinct feature vectors per file:

  | File | Distinct vectors (of rows) |
  |---|---|
  | benign | 801 of 5,662 |
  | dns2tcp_key_down | 88 of 2,000 |
  | dns2tcp_txt_down | 103 of 2,000 |
  | dns2tcp_key_up | 1,291 of 2,000 |
  | dns2tcp_txt_up | 1,281 of 2,000 |
  | dnsexfiltrator | 857 of 2,000 |

  All dns2tcp queries are one of four lengths (26, 79, 101 or 194 characters).
- **Differences that are not the attack itself.** Attack captures are from 2019
  and 2024, benign from 2026. Attacks use KEY/TXT queries; benign uses A/AAAA/MX.
  None of these are model features today, but adding timestamp, client IP or
  query type as a feature would let the model learn the capture, not the attack.

**Recommended wording for the paper:** "The classes are separable on this data
(single-feature AUC 0.998); generalization to unseen tunneling tools is limited
(recall 0.32 / 0.00 in leave-one-family-out tests)."

---

## 3. Logic issues found

### 3.1 Path B cannot be evaluated with the current split (high)

**File:** `src/dns_detect/models/path_b_train.py` (chronological split, around lines 150–160)

Records are sorted by time across the whole dataset, then cut 70/15/15. Every
attack capture predates the benign capture, which gives:

| Split | Benign | Attack |
|---|---|---|
| train | 963 | 10,000 |
| val | 2,349 | 0 |
| test | 2,350 | 0 |

The autoencoder learned "normal" from only 963 benign queries (about 10 seconds
of browsing), and the test set has no attacks to score.

**Fix:** split by time *within* each client or source file, so every split
contains both classes.

### 3.2 The fused score is compared to the wrong threshold (high)

**File:** `src/dns_detect/fusion/bridge.py`, `merge_ml_scores` (around lines 200–212)

The fused score is `ml_combined_score = 0.6·A + 0.4·B`, but it is compared against
Path A's own threshold (0.955, from `dns_threshold.json`).

- Even when Path A is fully certain (A = 1.0), the fused score only reaches 0.955
  if Path B ≥ (0.955 − 0.6) / 0.4 ≈ 0.89.
- Path B gives a score of 0 to the first 19 records of each client and to any
  record that does not end a window (`covered=False`).
- Result: the fused detector mostly ignores Path A.

**Fix:** tune a separate threshold on the fused score, and fall back to Path A
alone for records Path B did not score.

### 3.3 The base64 rule flags normal domains (medium)

**File:** `src/dns_detect/features/extractor.py`, around lines 196–217

The domain is uppercased (correct for the base32 check), but the same string is
reused for the base64 check. Any plain letters-and-digits domain whose length is
a multiple of 4 then passes, and there is no minimum length.

- Domains wrongly flagged include `www.google.com`, `microsoft.com`, `apple.com`
  and `www.cloudflare.com`.
- 1,350 of 5,662 benign queries (**23.8%**) get `attack_count > 0`; 1,348 of those
  carry the `ENCODING` signature.
- `attack_count` also feeds `ml_threat_score` in `bridge.py`, so the error spreads
  to that score.

### 3.4 Two features do not measure what their names say (medium)

- **`longest_label`** is filled from `first_label_length`
  (`WEEK3_TO_MODEL_MAP` in `src/dns_detect/parsing/dns_parser.py`). For
  `www.scientificamerican.com` it is 3, not 17. It is also highly correlated with
  `query_length` (r = 0.98).
- **`answer_count`** is always 0, because DNS responses are not parsed
  (`response_code: unknown`). It carries no information.

### 3.5 The Transformer baseline is set up unfairly (low)

**File:** `src/dns_detect/models/path_a.py`, `run_training`

`train_test_split` shuffles rows before `build_sequences`, so each 10-record
"sequence" is a set of unrelated queries. The baseline (F1 0.77) is acceptable as
a weak reference point, but it does not support the claim that "transformers
underperform on this task".

### 3.6 Misleading log message (low)

`train_models.sh` prints "No attack manifest … falling back to heuristic
attack_count labels", but the bridge keeps the provenance labels ("Preserved 15662
existing ground-truth label(s)"). The training labels are correct; the warning is
not.

---

## 4. Next steps

1. **Re-run verification and save the report** from a root shell
   (`models/` is root-owned):
   `python3 scripts/verify_models.py` → `models/verification_report.json`
2. **Fix §3.1** (per-source split for Path B), then re-train so Path B reports
   real test metrics.
3. **Fix §3.2–3.4**, then re-train with `./scripts/train_models.sh --force-retrain`.
4. **Build a separate test set the model never trained on:** benign traffic from a
   different host or day, plus a tunneling tool not in training (iodine or
   dnscat2). Then run:
   `python3 scripts/verify_models.py --holdout <benign.json> <tunnel.json>`
   This is the number that best measures real-world performance.
5. **Make the benign data more varied:** several hosts, longer captures, different
   times of day. Aim for benign traffic to be at least half the dataset.

---

## Appendix: artifacts referenced

| Path | Contents |
|---|---|
| `models/evaluation_metrics.json` | Path A metrics (Path B block absent) |
| `models/dns_threshold.json` | `{"threshold": 0.955, "decision": "rf_only"}` |
| `models/dns_trafficformer_threshold.json` | Path B threshold 0.00278, window 20, 5 features |
| `models/training_metadata.json` | Run metadata, feature snapshot |
| `data/processed/eda_report.json` | Exploratory data analysis of the merged dataset |
| `logs/training_20261023_232847.log` | Full training log |
