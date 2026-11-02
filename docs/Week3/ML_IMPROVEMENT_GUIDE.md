# ML improvement guide: step by step

**Goal:** make Path A, Path B and fusion catch tools they were not trained on, raise few false alarms on real traffic, and resist simple evasion.

The models already score about 1.0 on the current test data, so higher accuracy there means nothing. Judge every change by these numbers instead:

| Metric | Now | Target |
|---|---|---|
| Unseen-tool recall (leave one tool out) | 0.32–0.35 | ≥ 0.80 |
| False alarms per 10,000 benign queries | unknown | ≤ 1 |
| Record-type rule F1 (shortcut check) | 1.00 | < 0.95 |
| Evasion test-set recall | not measured | reported, rising |
| External dataset recall | not measured | reported |

Work through the steps in order. Each step ends with a **Done when** check. Do not start the next step until the check passes and the numbers are recorded.

Related documents: [Need-Improve.md](../Week2/Need-Improve.md) · [EVALUATION_REPORT.md](../research/EVALUATION_REPORT.md) · [DATASHEET.md](DATASHEET.md)

---

## Step 1 — Record the starting point

**Effort:** ½ day · **Type:** measurement only

Without a baseline you cannot prove that any later change helped.

```bash
python scripts/run_cv.py \
  --labeled data/processed/labeled_tunnels.json data/processed/labeled_benign.json \
  --out models/cv_baseline.json
python scripts/verify_models.py
```

Write down:
- unseen-tool recall per family (`by_strategy.lofo` in the JSON)
- record-type rule F1 on every split
- false-positive rate (`fpr`) of each baseline

**Done when:** `models/cv_baseline.json` exists and is never overwritten. Later runs use a different `--out` name (`cv_step2.json`, `cv_step3.json`, …).

---

## Step 2 — Fix the evaluation mistakes in Path A

**Effort:** 1 day · **Type:** code · **Files:** [path_a.py](../../src/dns_detect/models/path_a.py), [dns_parser.py](../../src/dns_detect/parsing/dns_parser.py)

1. **Choose the model on validation, not test.** In `run_training`, the RF-only vs RF+GBT gate compares `block_rf` and `block_cmb`, which are computed on `X_test`. Compute both on `X_val` instead, and use the test set only for the final report.
2. **Remove `answer_count` from `FEATURES_8`.** It is 0 in every PCAP row, so it reveals which source a row came from, not how the traffic behaves. Retrain afterwards, because the scaler and models expect 8 inputs.
3. **Calibrate the scores.** Wrap each tree model in `sklearn.calibration.CalibratedClassifierCV(method="isotonic", cv="prefit")` and fit it on the validation set. Fusion's HIGH / MEDIUM / LOW tiers (0.8 / 0.5 / 0.3) then mean real probabilities.
4. **Set the threshold from a false-alarm budget.** Replace `calibrate_threshold` (maximum F1) with: the smallest threshold whose false-positive rate on validation benign rows is ≤ 0.1 %. Put the budget in `config/settings.yaml`, for example `training.path_a_max_fpr: 0.001`.

**Done when:**
- `grep -n "X_test" src/dns_detect/models/path_a.py` shows the test set used only in the final-report block
- `models/dns_threshold.json` records the FPR budget that produced the threshold
- `pytest tests/` passes

---

## Step 3 — Add behaviour features (the "smart" part)

**Effort:** 2–3 days · **Type:** code · **New file:** `src/dns_detect/features/aggregates.py`

Path A judges each query on its own. The research behind your labeling rules (Nadler et al. 2019; Ozery et al., NDSS 2024) shows that tunnels stand out when queries are **grouped by domain and by client**. For every query, compute statistics over the **previous 5 minutes**:

| Feature | Grouped by | Catches |
|---|---|---|
| `uniq_subdomains_5m` | parent domain | Tunnels: each name is queried once |
| `uniq_ratio_5m` = unique ÷ total queries | parent domain | Same, normalised for busy domains |
| `info_chars_per_min` = subdomain characters per minute | parent domain | Data exfiltration volume |
| `nxdomain_share_5m` | client | Random-subdomain floods, enumeration |
| `qps_client_5m` = queries per minute | client | Fast tunnels, floods |
| `iat_std_5m` = std. deviation of time between queries | client + parent domain | Beaconing (very regular timing) |
| `tunnel_rr_share_5m` = share of TXT/NULL/KEY | client | Tunnel record-type use |
| `bigram_logprob` = average character-pair likelihood | per query | DGA names, encoded data |

Rules for implementing it:
- **Past only.** Each window covers `[t − 5 min, t)`. A window that includes later queries leaks future information.
- **Reuse existing code:** `parent_domain`, `subdomain_part` and `entropy` from [labeling.py](../../src/dns_detect/ingest/labeling.py).
- **Bigram model:** build the character-pair frequency table from the **training benign rows only** and save it to `models/bigram_table.json`.
- **One code path:** call the same function from feature extraction (detection) and from training, so both compute identical features.
- Add the new columns to a new list `FEATURES_AGG` in [dns_parser.py](../../src/dns_detect/parsing/dns_parser.py), and train Path A on `FEATURES_8 + FEATURES_AGG`.

Tests to add (`tests/test_aggregates.py`):
- a query never sees queries that come after it
- 60 unique subdomains of one parent within 5 minutes gives `uniq_subdomains_5m` = 60 at the last query
- identical input gives identical output in training and detection

**Done when:** unseen-tool recall from `run_cv.py` (LOFO) is higher than in Step 1. Save the run as `models/cv_step3.json`.

---

## Step 4 — Fix Path B

**Effort:** 2 days · **Type:** code · **Files:** [path_b_train.py](../../src/dns_detect/models/path_b_train.py), [path_b_predict.py](../../src/dns_detect/models/path_b_predict.py)

1. **Add a bottleneck.** The encoder blocks add their input back to their output (residual connections), and nothing forces compression, so the model can learn to copy any window, attacks included. After the encoder, flatten each window and compress it to a small vector (for example `Dense(8)`), then expand back to `(window, features)`. Alternatively, train as a denoising autoencoder: add noise to the input and reconstruct the clean window.
2. **Add the Step 3 aggregate features** to `PATH_B_FEATURES`.
3. **Add a simple baseline.** Train `sklearn.ensemble.IsolationForest` on the same features, using benign training rows only.
4. **Compare at the same false-alarm rate.** Set both thresholds for the same FPR on validation benign rows, then compare unseen-tool recall. Keep the better model. If the Isolation Forest is as good, prefer it: it is simpler, faster and easier to explain.

**Done when:** on the test split, the median reconstruction error of attack windows is clearly above the 99th percentile of benign windows, and the Trafficformer-vs-Isolation-Forest comparison is written up.

---

## Step 5 — One shared split for every model

**Effort:** 1 day · **Type:** code · **Files:** [path_a.py](../../src/dns_detect/models/path_a.py), [path_b_train.py](../../src/dns_detect/models/path_b_train.py), [splits.py](../../src/dns_detect/models/splits.py)

1. Add a `--split-manifest PATH` option to both training scripts.
2. When it is given, load it with `splits.read_manifest(path)` and turn it into row indices with `splits.apply_manifest(manifest, row_ids)`, instead of building a new split.
3. Score fusion on the same manifest's test rows.

**Done when:** Path A, Path B and fusion report metrics on exactly the same test rows (same `n_test` and the same manifest file name in their metrics).

---

## Step 6 — Collect better data (the biggest lever)

**Effort:** several days of lab time · **Type:** data collection

The model can only learn what the data shows it. Today every attack is TXT/KEY and no benign query is, so the model learns "TXT means attack".

**Benign traffic.** Several days, several machines, captured in the **same period** as the attacks:
- mail traffic: SPF, DKIM and DMARC lookups (TXT)
- Let's Encrypt certificate renewals: `_acme-challenge` lookups (TXT)
- DNSSEC validation: DNSKEY and DS lookups
- CDNs, cloud services, antivirus and software-update lookups (long, random-looking but benign names)
- normal browsing, from at least 5 machines

**Attack traffic.** Record every run with `./scripts/run_all.sh --with-attack "…"` so the manifest holds the ground truth:
- tools: iodine, dnscat2, dns2tcp, DNSExfiltrator
- slow rate: 1 query every 10–30 seconds
- short labels (under 20 characters)
- tunnels over A and AAAA records
- dictionary-word encodings (low entropy)

**When converting:**
- convert attack captures with `--domain <tunnel domain>` so only tunnel queries are labeled attack
- sample with `utils/sampling.sample_contiguous_blocks` so Path B windows stay continuous
- record every capture in [DATASHEET.md](DATASHEET.md)

**Done when:**
- the record-type rule's F1 is below 0.95 (`run_cv.py`)
- there are more than 300,000 benign test queries, which bounds the false-alarm rate below 0.001 % if none fire
- the capture-grouped split no longer falls back to random rows

---

## Step 7 — Smarter fusion

**Effort:** 1 day · **Type:** code · **File:** [bridge.py](../../src/dns_detect/fusion/bridge.py)

Today an alarm fires if **either** path fires (an OR rule), so the false alarms of both paths add up.

1. Build a table on the **validation** split with these columns: `ml_score_A`, `ml_score_B`, `has_score_B` (0 for a client's first 19 queries), the number of rule hits (R1–R4) and the largest absolute z-score.
2. Train `LogisticRegression(class_weight="balanced")` on it and save it to `models/fusion_lr.pkl`.
3. Set its threshold from the same false-alarm budget as Step 2.
4. Keep the OR rule available as an option for comparison.

**Done when:** at the same false-alarm rate, fusion has higher recall than Path A alone and Path B alone.

---

## Step 8 — Test against evasion

**Effort:** 2 days · **Type:** code + data · **New file:** `scripts/make_evasion_set.py`

Generate tunnel variants the model has not seen, based on the attack captures from Step 6:

| Variant | How |
|---|---|
| Slow | Spread the same queries over 10× the time |
| Short labels | Split data into labels of at most 15 characters |
| Low entropy | Encode the data with a word list instead of base32 |
| Hex | Hex encoding instead of base32 or base64 |
| Spread | Rotate queries across 5 parent domains |
| A/AAAA | Use A or AAAA queries instead of TXT |

1. Score every variant and record what is missed.
2. Add about half of each variant to training data.
3. Keep the other half as a fixed **evasion test set** that is never used for training.

**Done when:** evasion recall per variant is reported in every evaluation from now on.

---

## Step 9 — External validation

**Effort:** 1–2 days · **Type:** data + code

1. Download CIC-Bell-DNS-EXF-2021: https://www.unb.ca/cic/datasets/dns-exf-2021.html
2. Write `scripts/convert_cic_dns.py` to map its fields to your feature format.
3. Test the trained models **without retraining** on it.
4. Run the labeling rules on it with their thresholds frozen: `python -m dns_detect.ingest.labeling --input <converted>.json --validate`.

**Done when:** recall, false-alarm rate and labeling accuracy on the external set are reported. This closes Need-Improve.md N6.

---

## Step 10 — Keep it learning

**Effort:** ongoing · **Files:** [monitor.py](../../src/dns_detect/monitoring/monitor.py), [labeling.py](../../src/dns_detect/ingest/labeling.py)

1. **Review the uncertain cases.** Send alerts with a fused score between 0.4 and 0.6, plus abstained rows, to a person for review (the Telegram label-back idea in PLAN_v2).
2. **Feed confirmed labels back** into training with `label_source = "manual_review"`, and treat them as trusted labels.
3. **Retrain on drift.** Retrain when `monitoring_report.json` shows `retrain_recommended: true` (PSI > 0.25), or when the reviewed backlog grows past an agreed size.
4. **Trace every model to its data.** Store `dataset_hash` ([dataset_hash.py](../../src/dns_detect/utils/dataset_hash.py)) and `labeling_config_hash` in `training_metadata.json` for each training run.

**Done when:** each model in `models/` can be traced to its dataset hash, and reviewed labels are flowing back into training.

---

## Checklist

- [ ] Step 1 — baseline saved to `models/cv_baseline.json`
- [ ] Step 2 — gate on validation, `answer_count` removed, scores calibrated, FPR-budget threshold
- [ ] Step 3 — `aggregates.py` with past-only windows, tests, LOFO recall improved
- [ ] Step 4 — Path B bottleneck, Isolation Forest baseline, comparison written up
- [ ] Step 5 — shared split manifest used by Path A, Path B and fusion
- [ ] Step 6 — new benign and attack captures, record-type rule F1 < 0.95, > 300,000 benign test queries
- [ ] Step 7 — logistic-regression fusion beats each path at the same FPR
- [ ] Step 8 — evasion test set built and reported
- [ ] Step 9 — CIC-Bell-DNS-EXF-2021 results reported
- [ ] Step 10 — review loop and dataset hash in place

## After every step

1. `pytest tests/` passes.
2. Run `run_cv.py` with a new `--out` name and compare it with `models/cv_baseline.json`.
3. Write one line in the progress report: what changed, unseen-tool recall before → after, false-alarm rate before → after.
4. If a change makes unseen-tool recall worse, revert it, even if in-sample F1 went up.
