# Week 3 test report: improved ML vs Week 2

**DNS Traffic Anomaly Detection · testing the ML improvements (ML_IMPROVEMENT_GUIDE Steps 2–5, 7, 8) against the Week-2 version**

## Summary

The new version **detects far more of what Week 2 missed**: tunnels encoded differently, tunnels spread over several domains, and tunnel tools it was never trained on. The cost is **a small number of new false alarms** on benign websites hosted under shared domains (blogspot.com, CDNs), because they look like tunnels: many unique subdomains under one parent domain.

| Test | Week 2 (before) | Week 3 (after) | Better |
|---|---|---|---|
| Unseen tool, worst case, at the same false-alarm budget | recall 0.855 | **recall 1.000** | after |
| Unseen tool, false alarms on later benign traffic | 8.2 % | **3.4 %** | after |
| Evasion: hex-encoded tunnel (Path A) | **0 %** caught | **100 %** | after |
| Evasion: dictionary-word tunnel (Path A) | **0 %** | **100 %** | after |
| Evasion: tunnel spread over 5 domains (Path A) | 25 % | **100 %** | after |
| Evasion: short labels (Path A) | 55 % | **100 %** | after |
| Path B: attack windows caught (sanity check) | 60 % | **100 %** | after |
| Lab held-out test, Path A false alarms (same rows) | **0 / 1,169** | 31 / 1,169 (2.65 %) | before |
| Outside benign traffic (CIC, 66,497 queries), Path A false alarms | **0** | 17 (0.026 %) | before |
| Outside benign traffic, Path B false alarms | **0** | 1 window | before (by 1) |

**Verdict:** a large gain in detection for a small, explainable rise in false alarms. Every new false alarm on the outside data is a free-hosting or CDN subdomain. That is a known false-positive pattern for DNS-tunnel detection, and an allowlist or the Step 6 benign data can fix it.

---

## 1. What was tested

| Change | Guide step | Files |
|---|---|---|
| Model choice and threshold set on validation, never on test | 2 | `models/path_a.py` |
| `answer_count` removed from model inputs (always 0 in PCAP data) | 2 | `parsing/dns_parser.py` |
| Calibrated scores; threshold from a 0.1 % false-alarm budget | 2 | `models/path_a.py`, `models/thresholds.py` |
| Behaviour features over a past-only 5-minute window, plus a benign character-pair model | 3 | `features/aggregates.py` |
| Path B bottleneck + input noise; Isolation Forest baseline | 4 | `models/path_b_train.py` |
| One shared split manifest for Path A, Path B and fusion | 5 | `models/splits.py` |
| Learned fusion (logistic regression) | 7 | `fusion/stacker.py`, `scripts/train_fusion.py` |
| Evasion test set | 8 | `scripts/make_evasion_set.py` |

**Before** = the Week-2 models saved in `models/backup_before_step2/` and the Week-2 recipe (8 per-query features, uncalibrated RF + HistGBT, threshold at maximum F1). **After** = the current models in `models/`.

## 2. Test data

| Data | Rows | Role |
|---|---|---|
| Lab labeled set (`labeled_tunnels.json` + `labeled_benign.json`) | 18,353 (10,000 attack / 8,353 benign) | training + lab tests |
| Shared time split (`splits/time_seed42.json`) | train 13,215 · val 2,569 · test 2,569 | same rows for every model |
| CIC-Bell-DNS-EXF-2021, benign capture 3 (`cic_benign_test.json`) | 25,222 queries | outside benign test |
| CIC-Bell-DNS-EXF-2021, benign captures 1+2 (`cic_benign_train.json`) | 41,275 queries | outside benign test (not trained on) |
| Evasion variants (`data/processed/evasion/`) | 7 × 5,000 test rows | evasion test |

**CIC attack captures were not used.** They were recorded with a 96-byte packet limit, so 99.2 % of attack queries are cut off (benign: 0.1 %). The tunnel domain is missing, and "was the packet cut?" alone would reveal the label.

## 3. Results

### 3.1 Rule baselines (Test ML 1, `run_cv.py`)

The baseline rows are **identical before and after**. That is expected: they are fixed rules on the same data, and they measure the data, not the model.

| Rule (F1, mean ± sd, 5 seeds) | exact_copy | capture_group ⚠ | parent_domain | time |
|---|---|---|---|---|
| Record type ∈ {TXT, KEY, NULL} | 1.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 | 1.000 ± 0.000 |
| Length, threshold fitted on train | 0.966 ± 0.003 | 0.988 ± 0.001 | 0.480 ± 0.002 | 0.930 ± 0.000 |
| Entropy, threshold fitted on train | 0.956 ± 0.004 | 0.981 ± 0.002 | 0.648 ± 0.136 | 0.962 ± 0.000 |
| Entropy > 4.0 (literature) | 0.891 ± 0.005 | 0.912 ± 0.005 | 0.804 ± 0.093 | 0.985 ± 0.000 |

⚠ All benign rows come from one capture, so the capture split falls back to random rows. The record-type rule still scores 1.000 everywhere: the data shortcut is unchanged until new benign TXT/KEY traffic is collected (Step 6).

### 3.2 Unseen tool (leave one tool out)

**Week-2 measurement** (fixed 0.5 cutoff, no benign rows in the test): mean recall 0.350, worst 0.318.

That protocol turned out to be unreliable. With the old features, DNSExfiltrator's recall moves between **0.08, 0.38 and 1.00** depending only on how many benign rows are left out of training. The tool sits on the decision boundary, so 0.350 is not a stable number.

**Week-3 protocol:** each fold sets its threshold on a benign validation slice under the same 0.1 % budget. The test holds the unseen tool plus the latest 20 % of benign traffic (1,670 rows), so recall and false alarms are measured together.

| Feature set | dns2tcp | DNSExfiltrator | Recall mean / worst | Benign false alarms |
|---|---|---|---|---|
| Week 2 (8 features) | 0.855 | 1.000 | 0.927 / 0.855 | 8.2 % |
| − `answer_count` | 0.814 | 1.000 | 0.907 / 0.814 | 5.2 % |
| Behaviour features only | 1.000 | 1.000 | 1.000 / 1.000 | 3.4 % |
| **Week 3 (per-query + behaviour)** | **1.000** | **1.000** | **1.000 / 1.000** | **3.4 %** |
| Week 3 + record-type share | 1.000 | 1.000 | 1.000 / 1.000 | 3.6 % |

- The behaviour features are what generalise across tools. The record-type share adds nothing and was switched off (`training.exclude_features`).
- **None of the feature sets meets the 0.1 % budget on the later benign traffic.** All 62 false alarms in the Week-3 row come from one machine's CDN and update lookups (`*.gallerycdn.vsassets.io`, Microsoft telemetry, `.localdomain`), which appear only after the first 5 minutes of the benign capture.

### 3.3 `verify_models.py`

In Week 2 it failed (`merged_features_labeled.json` missing). The file is now built by the project's merge and labeling modules, and the script runs. It still checks the **old 8 features** with its own throwaway models:

| Check | Result |
|---|---|
| Shortcut | ⚠ `query_entropy` alone separates the classes (AUC 0.992) |
| Duplicate leakage | ✅ no score gap between random and domain-grouped splits |
| Unseen tool | ⚠ 0.32 (dns2tcp), 0.56 (DNSExfiltrator) |
| Label shuffle | ✅ collapses to chance, so no pipeline leakage |

### 3.4 Lab held-out test (same rows for both versions)

The Week-2 recipe was retrained on exactly the training rows of `time_seed42.json` and scored on the same 2,569 test rows (1,400 attack, all DNSExfiltrator; 1,169 benign).

| Path A | Recall | False alarms | Precision | F1 | PR-AUC | Threshold |
|---|---|---|---|---|---|---|
| Week 2 recipe | 0.9986 (2 missed) | **0 / 1,169** | 1.000 | **0.999** | 1.000 | 0.792 (max F1) |
| Week 3 | **1.000** | 31 / 1,169 (2.65 %) | 0.978 | 0.989 | 0.994 | 0.500 (budget) |

On traffic that resembles its training data, the Week-2 recipe is slightly better. The 31 Week-3 false alarms are the late-capture CDN traffic described in 3.2. The new threshold was set at 0 false alarms on validation, but validation contains no CDN fan-out.

| Path B (window level, same split) | Recall | False alarms | Notes |
|---|---|---|---|
| Week 3 autoencoder (bottleneck) | 1.000 | 70 / 1,093 (6.4 %) | median attack error = 1.86 × the 99th-percentile benign error |
| Isolation Forest baseline | 1.000 | 186 / 1,093 (17.0 %) | same threshold rule |

**Sanity check, not a held-out test:** on the whole lab set, which includes rows each model trained on, the Week-2 Path B flagged only **60 %** of attack windows (0.15 % of benign). Week 3 flagged **100 %** (1.06 % of benign). Without the bottleneck, the old autoencoder reconstructed many attack windows as well as benign ones.

### 3.5 Fusion (same test rows)

| Decision rule | Recall | False alarms | Precision |
|---|---|---|---|
| Path A alone | 1.000 | 31 (2.65 %) | 0.978 |
| Path B alone | 1.000 | 71 (6.07 %) | 0.952 |
| OR rule (current default) | 1.000 | **90 (7.70 %)** | 0.940 |
| **Learned fusion** | 1.000 | **31 (2.65 %)** | 0.978 |

The learned weights are Path A 8.78, Path B 2.79, "Path B had a window" −0.74, rule hits 0.00. The learned fusion **removes 59 of the OR rule's 90 false alarms** at the same recall. It is trained (`models/fusion_lr.pkl`) but not yet switched on (`ensemble.fusion: or`).

### 3.6 Outside benign traffic (CIC-Bell-DNS-EXF-2021)

Every query is benign, so every alarm is a false alarm. Neither version was trained on this data.

| | Queries | Path A before | Path A after | Path B before | Path B after |
|---|---|---|---|---|---|
| Capture 3 | 25,222 | **0** | 14 (0.056 %) | 0 / 25,203 windows | 0 / 25,203 |
| Captures 1+2 | 41,275 | **0** | 3 (0.007 %) | 0 / 41,256 windows | 1 / 41,256 |
| **Total** | **66,497** | **0** (< 0.005 %*) | **17 (0.026 %)** | **0** | **1** |

\* Rule of three: zero alarms in 66,497 queries bounds the rate below 3 ÷ 66,497 at 95 % confidence.

The Week-3 Path A stays **within its 0.1 % budget** on traffic it never saw. The 14 flagged queries in capture 3 are 13 different `*.blogspot.com` blogs and one `*-my.sharepoint.com` site. These are free-hosting services where every user gets a subdomain, so the domain shows the many-unique-subdomains pattern of a tunnel.

### 3.7 Evasion variants (recall on the 5,000 test rows of each variant)

| Variant | Path A before | Path A after | Path B before | Path B after |
|---|---|---|---|---|
| Original tunnel | 1.000 | 1.000 | 0.594 | 1.000 |
| 10× slower | 1.000 | 1.000 | 0.594 | 1.000 |
| Short labels (≤ 15 chars) | 0.551 | **1.000** | 0.543 | 1.000 |
| Dictionary words | **0.000** | **1.000** | 1.000 | 1.000 |
| Hex encoding | **0.000** | **1.000** | 1.000 | 1.000 |
| Spread over 5 domains | 0.249 | **1.000** | 0.600 | 1.000 |
| A/AAAA instead of TXT | 1.000 | 1.000 | 0.594 | 1.000 |

The Week-2 Path A recognised how the training tools encode data. Change the encoding and it misses the tunnel completely. The Week-3 model also looks at how much unique data flows to a domain, and that does not change with the encoding.

## 4. Bugs found and fixed during testing

| Problem | Effect | Fix |
|---|---|---|
| Path B could not be loaded from `.h5` under Keras 3 (`TypeError: too many positional arguments`), including the Week-2 model | Path B never scored anything in detection on this machine | `path_b_predict.py` rebuilds the architecture and loads the weights; training now saves `.keras` |
| `verify_models.py` failed: merged labeled file missing | No verification in Week 2 | File built through `ingest.merge` + `ingest.labeling` |
| Threshold sat just above 0 when validation was perfectly separable | Any benign score > 0 raised an alarm (46 false alarms) | Threshold set in the middle of the gap between benign and attack scores (31 false alarms, same recall) |
| `run_cv.py` scored raw entropy/length as probabilities, and overwrote `evaluation_metrics.json` | Wrong baseline F1 (0.705); training metrics lost | Uses each rule's own decision; writes `cv_metrics.json` |
| Merge warned that window features were missing from PCAP rows | Misleading warning | Schema check limited to per-record features |

## 5. Limitations

1. **Attack data is the same 2 tools.** Evasion variants are rewritten from those captures, and the training data included the original queries. The evasion test measures robustness to re-encoding, not to new tools.
2. **No outside attack data.** The CIC attack captures are cut at 96 bytes.
3. **Narrow lab benign data.** One capture with 4 clients; the first 5 minutes contain no CDN traffic. This explains most Week-3 false alarms.
4. **Single run** for the trained models (seed 42, one split). Only the baselines and the unseen-tool test are repeated or fold-based.
5. **Window features in the evasion test** are computed from the tunnel alone, without other traffic from the same client.
6. `verify_models.py` still tests the old 8 features.

## 6. Next steps

| Priority | Action | Expected effect |
|---|---|---|
| 1 | Switch on the learned fusion (`ensemble.fusion: lr`) | 90 → 31 false alarms on the lab test, same recall |
| 2 | Add free-hosting and CDN parents (`blogspot.com`, `sharepoint.com`, `vsassets.io`, …) to a detection allowlist, or train with CIC captures 1+2 (keep capture 3 for testing) | Removes the outside false alarms seen here |
| 3 | Collect same-period benign TXT/MX/DNSSEC traffic and new tunnel tools (Step 6) | Removes the record-type shortcut; enables real capture-grouped tests |
| 4 | Retrain Path B so it is saved as `.keras` | Normal model loading |
| 5 | Update `verify_models.py` to the Week-3 features | Verification matches the deployed model |

## 7. How to reproduce

```bash
pytest tests -q                                                     # 86 tests
python3 scripts/run_cv.py --labeled data/processed/labeled_tunnels.json data/processed/labeled_benign.json --out models/cv_step3.json
python3 scripts/verify_models.py
PYTHONPATH=src python3 -m dns_detect.models.path_a --train data/processed/merged_features_labeled.json --split-manifest data/processed/splits/time_seed42.json
PYTHONPATH=src python3 -m dns_detect.models.path_b_train --filename merged_features_labeled.json --data_dir data/processed --n_days 20 --save_name dns_trafficformer --split-manifest data/processed/splits/time_seed42.json
python3 scripts/train_fusion.py --labeled data/processed/merged_features_labeled.json --split-manifest data/processed/splits/time_seed42.json
python3 scripts/make_evasion_set.py && python3 scripts/make_evasion_set.py --evaluate
PYTHONPATH=src python3 -m dns_detect.models.path_a --infer data/external/cic/cic_benign_test.json
PYTHONPATH=src python3 -m dns_detect.models.path_b_predict --filename data/external/cic/cic_benign_test.json --save_name dns_trafficformer --data_dir .
```

Week-2 models for the "before" columns: `models/backup_before_step2/`.
