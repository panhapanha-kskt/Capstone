# Model card: v3_iforest

**DNS-tunnel detector · promoted to `models/` from `runs/v3_iforest` · card written 2026-11-19**

| Field | Value |
|---|---|
| Version | `v3_iforest` (trained 2026-11-14T13:19:29Z on the Kali VM `ounnha`, 39 min 5 s) |
| Replaces | autoencoder Path B model (trained 2026-10-24); archived under `models/archive/autoencoder_pathB_<date>/` |
| Approval | Isolation Forest Path B approved by mentor 2026-11-17 |
| Transfer | `v3_iforest.tar.gz`; SHA-256 `ae717a04f4cf91286116f865e7827ccc4383fd7ab816de6083ae35ae0142ed26`, identical on the VM and on Windows |
| Seed | 42 |
| Split | per-class time-ordered 72/14/14, extended from `time_seed42.json`; test frozen (2,568 rows: 1,168 benign, 1,400 attack); split SHA-256 `672ce6c7…cea0` |

## Training data

218,334 rows: 100,000 attack and 118,334 benign.

| Source | Rows | Class |
|---|---|---|
| labeled_tunnels.json (dns2tcp, dnsexfiltrator) | 10,000 | attack |
| tunnels_cobaltstrike / det / dnscat2 / dns_shell / iodine / ozymandns.json | 15,000 each | attack |
| labeled_benign.json | 8,353 | benign |
| cic_benign_train.json (CIC-Bell-DNS) | 41,275 | benign |
| benign_alexa.json (Tu 2023) | 68,710 | benign |

## Models

| Part | What | Inputs | Decision |
|---|---|---|---|
| Path A | Random Forest, 200 trees, balanced, isotonic-calibrated (gate chose `rf_only`) | `PATH_A_FEATURES` (per-query + 5-minute behaviour features), train-quantile clipping, StandardScaler | alarm when score ≥ 0.3372 (set for ≤ 0.1% false alarms on validation) |
| Path B | **Isolation Forest**, 200 trees, trained on benign windows only | windows of 20 queries per client × 11 features (`PATH_B_FEATURES`, same order as live), min/range scaling from train rows | anomaly when score > 0.4907 (99th percentile of benign validation windows) |
| Fusion | Logistic regression V1 (A score 12.92, B score 2.91, has-B −3.49, rule hits 0.68) | Path A and Path B scores | alarm when probability ≥ 0.4874 |

The Path B feature list was checked against the live pipeline on 2026-11-19: same 11 names, same order. The Path A list also matches.

## Results on the frozen test set (reported at training time)

| Detector | Recall | False alarms / 1,168 benign | FPR |
|---|---|---|---|
| Fusion | 1.000 | 7 | 0.60% |
| Path A | 1.000 | 8 | 0.68% |
| Path B (Isolation Forest) | 1.000 | — | 9.34% |

**Other checks (Week 5–6 reports):**
- Unseen benign traffic (CIC capture 3): 1 false alarm in 25,222 queries.
- Leave-one-tool-out: recall 1.0 on all 8 tools, with false alarms of 0.35–0.59%.
- 5 seeds (fusion): 8.2 ± 0.84 false alarms, recall 1.0 every seed.

## Known limits

- **The 0.1% false-alarm target is not met** on the test set (0.60%) or on held-out tools (0.35–0.59%).
- **A record-type rule (TXT/KEY/NULL) is a very strong baseline** on this data; see `docs/Week6/ML_IMPROVEMENT_IMPLEMENTATION_2026-11-19.md`.
- **Path B alone flags about 9% of benign windows.** The fusion relies mainly on Path A.
- **`fusion_lr_v2` and `fusion_fallback_quantiles.json` were not part of this run.** The bridge uses fusion V1 (`ensemble.fusion: lr`), and the development-mode OR fallback has no quantile file.

## File hashes (SHA-256)

`scripts/promote_model.sh` re-checks these after copying and writes them to `models/PROMOTED.json`.

| File | SHA-256 |
|---|---|
| dns_tunnel_rf.pkl | 7303d346f3065513110b6db41a5de7dc4863ed55e9a67deaee542d32be4fb50a |
| dns_tunnel_gbt.pkl | 0475095f2368b43f63dea574972d3c89ffe44dbcbb84fbf0c397df1ff30a1fb5 |
| dns_scaler.pkl | d5e5ce80f3ba5deeb50b06e053dafdfaca16d1f6b0fe5a6206475161e9f6af51 |
| dns_threshold.json | 4b6a726a8bbb0d18ca1342dc8530e9b799c4caf7649ecad3f94b493ba14fbe72 |
| bigram_table.json | ae0afe93813867e6ffe2de350ced1744108b7fa3db09fde95f31480dc2b1e1d8 |
| dns_trafficformer_iforest.pkl | f0ed619e786b8be1b41278f8b11525295ee7c9e01990d5660e7fb11951ee2715 |
| dns_trafficformer_norm.json | 237f3af69c277b718c8b4448f510b49f264a61800d0776a3eefca023eaeb718c |
| dns_trafficformer_threshold.json | dd80a2cb57be496bd72895539bd7db10c97010f729f04b800a67cd16945a1875 |
| fusion_lr.pkl | 74735a972a26ea71caedb14ffa29ce88c81b6c26744518235683dfe3ce2ee1f9 |
| fusion_lr.json | ae44672834a79646d85f842816c6ce2dae6781b8e87e27a90ba20ff29988eabe |
| fusion_lr_tiers.json | bb97e068af3af675c8daf23fddc3b4245401798450330958f0e78f90df29970c |
| evaluation_metrics.json | 0e4701129deba90678c58f6ee659ba16429724f3745a1649b24ddb69e336cb17 |
| training_metadata.json | c3a315440937b070c507d4c24f522abd969d994343356fb6e21086f96fffcfa3 |
| training_provenance.json | 2293fcb8201268aaebf0ea65a48973bf17fce3ae023cbe81a57dae911337579f |
| trained_files_registry.json | bf39f66250dedac374a43037d58f1dcb766ed15e64063580b5cc35bcbcaaa2f0 |
| split_manifest.json | a050e4f812be645e1e0dc57d6a8618362a563ae98ddb69bc05c91e8a9a730abf |
| merged_labeled.json (training data, stays in `runs/v3_iforest`) | 5752d842008a149bc650708ce35315e712ed01162a43e53aafd0f8e634182f3f |
