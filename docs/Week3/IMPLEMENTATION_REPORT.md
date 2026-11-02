# Week 3 Improvements: Implementation Report

**DNS Traffic Anomaly Detection · implementing the fixes, limitations and next steps from `docs/Week3/TEST_REPORT.md` · 2026-11-01**

## Summary

The Week-3 follow-up fixes cut Path A false alarms on the outside benign test (CIC capture 3, 25,222 queries) from 14 to 0, and on the lab test from 31 to 14 of 1,169, with recall unchanged at 1.000.

The work answers the bugs, limitations and next steps in the Week-3 test report. It ran in four phases: quick code fixes, removing the free-hosting and CDN false alarms, tooling for new data, and stronger evaluation. All 94 automated tests pass (86 before, 8 new).

The new models live in `models_week4/`; the Week-3 models in `models/` are untouched. Path B retraining, the fusion retrain and the evasion runs were still in progress when this report was written. Their sections say so.

---

## Background: what Week 3 left open

The Week-3 test report showed a large detection gain over Week 2, at the cost of new false alarms on benign sites under shared parent domains. It listed these open items, each mapped here to the phase that addresses it.

| Week-3 item | Type | Addressed in |
|---|---|---|
| Learned fusion trained but not switched on | Next step 1 | Phase 1 |
| False alarms on blogspot.com, sharepoint.com and CDN subdomains | Next step 2 | Phase 2 |
| Record-type shortcut (TXT/KEY only in attack data) | Next step 3, Step 6 | Phase 3 (tooling) |
| Path B stored as legacy `.h5`, needs a rebuild workaround | Next step 4 | Phase 1 |
| `verify_models.py` checks the old 8 features | Next step 5, limitation 6 | Phase 1 |
| Only 2 tunnel tools; no outside attack data | Limitations 1–2 | Phase 3 |
| Narrow lab benign data (one capture, 4 clients) | Limitation 3 | Phases 2–3 |
| Single training run (seed 42) | Limitation 4 | Phase 4 |
| Evasion windows computed on the tunnel alone | Limitation 5 | Phase 4 |

Exploring the code also turned up two problems the report did not list:

- The Path B model in use was still the `.h5` file; no `.keras` file existed, so every load went through the rebuild workaround.
- `verify_models.py --holdout` scaled 8 features with a scaler fitted on 14, which fails on a shape mismatch.

---

## Phase 1: Quick fixes

Phase 1 turns on the learned fusion, prepares Path B for the `.keras` format, and makes verification check the model that is actually deployed.

### 1.1 Learned fusion switched on

- `config/settings.yaml`: `ensemble.fusion` changed from `or` to `lr`.
- No code change was needed. `fusion/bridge.py` already loads `models/fusion_lr.pkl`, falls back to the OR rule if it is missing, and keeps the OR decision in `ml_combined_label_or` for comparison.
- Week-3 effect on the same test rows: 90 false alarms with the OR rule, 31 with the learned fusion, recall 1.000 for both.
- Two new tests check that `lr` mode uses the stacker and falls back to OR when no model file exists.

### 1.2 Path B: `.keras` format and a seed

- `path_b_train.py` already saves `.keras`; the deployed model was simply older. A retrain into `models_week4/` produces the `.keras` file.
- `path_b_predict.py` still loads an old `.h5` through the rebuild workaround, but now prints a deprecation warning when it does.
- New `--seed` flag: sets `tf.keras.utils.set_random_seed` and the Isolation Forest seed, and is written into the metrics.
- Background: Keras 3 only saves natively as `.keras`, and its legacy `.h5` loader has known failures on nested and attention models ([Keras migration guide](https://keras.io/guides/migrating_to_keras_3), [keras#19441](https://github.com/keras-team/keras/issues/19441)).
- Two new tests check that `.keras` is chosen when both files exist and `.h5` is used otherwise.

### 1.3 `verify_models.py` checks the deployed features

- Default `--feature-set deployed`: every check now uses the 14 features of the saved Path A (per-query, 5-minute behaviour and bigram), read from `dns_threshold.json`. `--feature-set base8` repeats the Week-2 checks.
- Holdout bug fixed: the saved Path A is scored through `path_a.score_frame()`. The whole holdout file is scored first, so behaviour windows see all its traffic; domains seen in training are dropped afterwards.
- New leakage check grouped by parent domain, next to the existing check grouped by domain.
- The report states that `bigram_logprob` uses the saved table, fitted on training benign rows, so checks 1–4 are slightly optimistic for that feature.

First run on the deployed features, holdout = CIC capture 3 plus the hex-encoded evasion set (35,150 unseen rows): saved Path A F1 = 0.9993, recall 1.000 on both tools.

Two warnings come from the script's fixed 0.5 cutoff, not from the models:

- The parent-domain grouped split gives F1 0.52 while PR-AUC stays 0.9999. The ranking is right; only the cutoff is wrong.
- The leave-one-tool-out check gives 0.32 recall on dns2tcp. The Week-3 report already found this fixed-cutoff protocol unreliable (Section 3.2).

---

## Phase 2: Removing the outside false alarms

The blogspot.com false alarms came from how the parent domain was computed, not from the model. A Public Suffix List fix removes them, and a short detection allowlist handles the rest.

### 2.1 Parent domain from the Public Suffix List

**Root cause.** `ingest/labeling.parent_domain()` used a hand-made list of about 100 two-part suffixes such as `co.uk`. So `a.blogspot.com` and `b.blogspot.com` shared the parent `blogspot.com`, and 13 different blogs looked like one domain with 13 unique subdomains, which is exactly a tunnel's pattern.

**Fix.** The Public Suffix List (PSL) has a private section listing services where every user gets a subdomain: `blogspot.com`, `github.io`, `cloudfront.net` and many more. `parent_domain()` now uses `tldextract` with `include_psl_private_domains=True`, so each blog becomes its own registered domain ([tldextract source](https://sources.debian.org/src/tldextract/5.1.2-2/tldextract/tldextract.py)). Elastic groups DNS-tunnel statistics by the same PSL-based registered domain ([Elastic, Detecting DNS tunnels](https://www.elastic.co/blog/detecting_dns_tunnels_with_packetbeat_and_watcher)).

Design choices:

- **Offline list.** The PSL snapshot bundled with `tldextract` is used (`suffix_list_urls=()`), so results are reproducible and nothing is fetched at run time.
- **Fallback.** Names without a known suffix (`host.localdomain`, `wpad`) keep the old last-two-labels rule.
- **Same signature.** The behaviour features in `features/aggregates.py` call `parent_domain()`, so they change with no other edit. A cache (`lru_cache`) keeps it fast.
- **Tunnels still group.** A tunnel under a private suffix, such as `<data>.evil.duckdns.org`, gets the parent `evil.duckdns.org` and still fans out. A test checks this.

| Domain | Old parent | New parent |
|---|---|---|
| myblog.blogspot.com | blogspot.com | myblog.blogspot.com |
| abc.def.cloudfront.net | cloudfront.net | def.cloudfront.net |
| x.y.evil.duckdns.org | duckdns.org | evil.duckdns.org |
| contoso-my.sharepoint.com | sharepoint.com | sharepoint.com (not in the PSL) |
| a.gallerycdn.vsassets.io | vsassets.io | vsassets.io (not in the PSL) |

### 2.2 Detection-time allowlist

`sharepoint.com`, `vsassets.io` and Microsoft telemetry are not PSL private suffixes, so a short allowlist covers them. The existing `config/dns_allowlist.txt` only shaped training labels; nothing suppressed alarms at detection time.

- New file `config/detect_allowlist.txt` (18 entries) and setting `detection.allowlist_path`.
- `fusion/bridge.py` applies it after fusion: matching rows get `ml_combined_label = 0` and `suppressed_by_allowlist = True`. **The score is kept**, so suppressed rows can still be reviewed.
- Matching is per DNS label: `vsassets.io` covers `a.gallerycdn.vsassets.io`, not `notvsassets.io`. Open-source detectors handle CDN false alarms the same way ([dnsink](https://docs.rs/crate/dnsink/0.3.0/source/src/cdn_whitelist.rs), [flowscope](https://docs.rs/crate/flowscope/0.22.0/source/src/detect/patterns/dns_tunnel.rs)).
- Safety rule, enforced by a test: no dynamic-DNS or free-subdomain service (`duckdns.org`, `no-ip.com`, `ngrok.io`, `trycloudflare.com`). Anyone can run a tunnel under those.

### 2.3 CIC benign captures 1+2 in training

- New `scripts/convert_cic_dns.py` records how the CIC files were built (ML_IMPROVEMENT_GUIDE Step 9). Rebuilt files match the existing ones row for row: 41,275 and 25,222 queries.
- New `scripts/extend_manifest.py` adds the 41,275 CIC rows from captures 1+2 to the Week-3 split without moving any old row. New rows go 85 % to train and 15 % to validation, by time, and never to test. **The 2,569 test rows are exactly the Week-3 ones**, so before and after numbers compare directly.
- Capture 3 is never merged; it stays the outside false-alarm test.
- Training file: `data/processed/week4/merged_week4.json`, 59,628 rows (49,628 benign, 10,000 attack). Split: train 48,299, validation 8,760, test 2,569.

---

## Phase 3: Tooling for new data

The scripts to bring in 8 tunnel tools and multi-machine benign traffic are ready and tested. No new data has been collected or downloaded yet. The plan uses both a public dataset and new lab captures.

### 3.1 Truncation check on every capture

The CIC attack captures were unusable because a 96-byte snap length cut 99.2 % of queries. A cut query loses its domain, and the parser drops it without a warning. New `truncation_report()` in `scripts/make_labeled_features.py` counts DNS queries (packets sent to port 53) whose captured length is below their length on the wire. Converters refuse a capture above 1 % truncated.

On the CIC benign captures it reports 0.11 %, 0.08 % and 0.05 %, in line with the Week-3 report. A first version also counted DNS responses, which are longer and cut more often. It reported 19.6 % and was corrected to queries only.

### 3.2 Public dataset: 8 tunnel tools

Source: Tu, Liu and Sun, *DNS tunnelling detection by fusing encoding feature and behavioral feature*, Computers & Security 132 (2023), [doi:10.1016/j.cose.2023.103357](https://doi.org/10.1016/j.cose.2023.103357). Its [GitHub repository](https://github.com/Utah1A/DNS-tunnelling-detection-by-fusing-encoding-feature-and-behavioral-feature) holds pcaps from 8 tools under `datasets/base_malicious_dataset/`: cobaltstrike, det, dns2tcp, dns_shell, dnscat2, dnsexfiltrator, iodine and ozymandns.

Caveats from the repository:

- No license file. The README only asks users to cite the paper.
- The tunnel domain names are not documented.
- Most malicious packets are heartbeats with no payload.
- Some pcaps contain non-DNS packets; the existing parser already keeps DNS queries only.

New `scripts/convert_external_tunnels.py` handles any `<root>/<tool>/*.pcap` layout:

1. Refuses truncated captures (3.1).
2. Detects each tool's tunnel domain as the parent domain with the most queries, unless `--domain TOOL=DOMAIN` is given. Other queries are dropped, not labeled as attack.
3. Caps each tool at 5,000 queries using contiguous time blocks (`utils/sampling.sample_contiguous_blocks`), so behaviour windows and Path B windows stay intact and no tool dominates.
4. Writes `tunnels_<tool>.json` with label 1, the tool as `attack_family`, and `label_source = provenance`, plus a summary listing each detected tunnel domain for review.

### 3.3 Lab captures

New `scripts/capture_dns.sh` runs `tcpdump` on port 53 with full packets (`-s 0`) and a new file every hour, named after the host and start time. Its header carries the Step 6 checklist:

- **Benign:** at least 5 machines over several days, including real TXT, MX, DNSKEY and DS lookups (a mail client, a DNSSEC-validating resolver, certificate renewals). This targets the record-type shortcut.
- **Attack:** iodine and dnscat2 runs, recorded in `data/attack_manifest.csv`, including slow-rate and A/AAAA modes.

### 3.4 Use in evaluation

The leave-one-tool-out test in `scripts/run_cv.py` already loops over every `attack_family`. With 8 or more tools it becomes a real unseen-tool test, with no code change. Done-when targets from ML_IMPROVEMENT_GUIDE Step 6: record-type rule F1 below 0.95, and a capture-grouped split that no longer falls back to random rows.

---

## Phase 4: Evaluation rigor

Phase 4 makes results repeatable across seeds and tests evasion in a more realistic setting, without touching the production models.

### 4.1 One models folder, overridable

The `models/` path was hard-coded in 10 places across Path A, Path B, fusion, monitoring and scripts, so the documented `DNS_DETECT_MODELS_DIR` variable was ignored during training. New `MODELS_DIR` in `utils/paths.py` reads that variable (relative to the project root) or defaults to `models/`; every site now uses it. Experiments train into their own folder and never overwrite production models.

### 4.2 Multi-seed runs

- `path_a.py` gains `--seed`. It replaces the hard-coded 42 in the Random Forest, the gradient-boosting model, the validation halves used for calibration and threshold, and the label-shuffle check.
- New `scripts/run_multiseed.py` trains Path A, Path B and the fusion once per seed, each into `<out-root>/seed<N>`, and reports mean, standard deviation, min and max for recall, false-alarm rate, false-alarm count and PR-AUC. `--skip-path-b` runs Path A only.
- The manifest may contain `{seed}` to change the split per seed. With the time split only the model seed changes, because every `time_seed4x` manifest holds the same rows.

### 4.3 Evasion mixed with benign traffic

In Week 3, each evasion variant was scored on its own, so every 5-minute window held only tunnel queries. On a real machine the tunnel runs next to normal browsing, which dilutes client-level features such as queries per minute.

- New `mix_with_benign()` in `scripts/make_evasion_set.py`. For each tunnel client, benign rows are shifted onto the tunnel's start time, repeated while the tunnel runs, and given the tunnel's client address.
- New `--mix-benign FILE` option for `--evaluate`. It reports recall on the tunnel rows and the false-alarm rate on the added benign rows, under the metrics key `evasion_mixed`. Use benign data never trained on, such as CIC capture 3.
- The isolated mode stays the default, so Week-3 numbers remain comparable.
- A new test checks that every attack row is kept, the benign rows share the tunnel's client, and they stay inside its time span.

---

## Results so far

Path A now raises no false alarms on outside benign traffic and less than half as many on the lab test, with recall still 1.000. Path B, the fusion retrain and the evasion runs were still in progress at the time of writing.

### Outside benign traffic: CIC capture 3

25,222 benign queries, never trained on by any version. Every alarm is a false alarm.

| Path A version | False alarms | After detection allowlist |
|---|---|---|
| Week 3 model, Week-3 parent domain (report Section 3.6) | 14 | not available in Week 3 |
| Week 3 model, PSL parent domain | 1 | 0 |
| Week 4 model (PSL + CIC 1+2 in training) | **0** | **0** |

The PSL change alone removed the 13 blogspot alarms, without retraining. CIC captures 1+2 are no longer an outside test for the Week-4 model, because it was trained on them.

### Lab held-out test: same 2,569 rows as Week 3

1,400 attack rows (all DNSExfiltrator) and 1,169 benign rows.

| Path A version | Recall | False alarms | F1 | PR-AUC | Threshold |
|---|---|---|---|---|---|
| Week 3 (report Section 3.4) | 1.000 | 31 (2.65 %) | 0.989 | 0.994 | 0.500 |
| Week 4, seed 42 | 1.000 | **14 (1.20 %)** | **0.995** | **1.000** | 0.434 |
| Week 4, 5 seeds (mean ± sd) | 1.000 ± 0 | 10.2 ± 5.6 (0.87 %) | | 1.000 ± 0 | |

Across seeds 42–46 the false alarms range from 5 to 18 on the same rows. A single run can differ from another by more than 10 false alarms, so week-to-week comparisons should use the multi-seed mean. Recall and PR-AUC did not move at any seed.

The lab false alarms are still above the 0.1 % budget. As in Week 3, they come from the late-capture CDN and update traffic of one lab machine, which appears in the test period only.

### Still running or not yet run

- Path B retrain into `models_week4/` (saves `.keras`; at epoch 32 when this was written).
- Learned-fusion retrain on Path A + Path B Week-4 scores.
- Evasion variants, isolated and mixed with CIC capture 3.
- 5-seed run including Path B and fusion.
- Leave-one-tool-out across the 8 public tools (needs the dataset download).

---

## Files, tests and how to reproduce

### Files changed

| File | Change | Phase |
|---|---|---|
| `config/settings.yaml` | `ensemble.fusion: lr`; `detection.allowlist_path` | 1, 2 |
| `config/detect_allowlist.txt` | New: 18 CDN, telemetry and false-alarm suffixes | 2 |
| `requirements.txt` | Adds `tldextract>=5.1` | 2 |
| `src/dns_detect/ingest/labeling.py` | PSL-aware `parent_domain()` with fallback and cache | 2 |
| `src/dns_detect/fusion/bridge.py` | Allowlist suppression after fusion; `MODELS_DIR` | 2, 4 |
| `src/dns_detect/fusion/stacker.py` | `MODELS_DIR` | 4 |
| `src/dns_detect/models/path_a.py` | `--seed`; `MODELS_DIR` | 4 |
| `src/dns_detect/models/path_b_train.py` | `--seed`; `MODELS_DIR` | 1, 4 |
| `src/dns_detect/models/path_b_predict.py` | `.h5` deprecation warning; `MODELS_DIR` | 1, 4 |
| `src/dns_detect/monitoring/monitor.py` | `MODELS_DIR` | 4 |
| `src/dns_detect/utils/paths.py` | New `MODELS_DIR` honouring `DNS_DETECT_MODELS_DIR` | 4 |
| `scripts/verify_models.py` | Deployed features, holdout fix, parent-domain check | 1 |
| `scripts/make_labeled_features.py` | New `truncation_report()` | 3 |
| `scripts/make_evasion_set.py` | `mix_with_benign()`, `--mix-benign`; `MODELS_DIR` | 4 |
| `scripts/train_fusion.py` | `MODELS_DIR` | 4 |
| `scripts/convert_cic_dns.py` | New: rebuild the CIC benign files | 2 |
| `scripts/extend_manifest.py` | New: add rows to a split without moving old ones | 2 |
| `scripts/convert_external_tunnels.py` | New: per-tool public pcaps to labeled records | 3 |
| `scripts/capture_dns.sh` | New: full-packet rotating DNS capture | 3 |
| `scripts/run_multiseed.py` | New: train over seeds, report mean ± sd | 4 |

### Tests

94 tests pass (`pytest tests -q`): the 86 from Week 3 plus 8 new ones.

| Test file | New tests |
|---|---|
| `tests/test_thresholds_fusion.py` | `lr` fusion uses the stacker; falls back to OR; allowlist suppresses but keeps the score; allowlist has no dynamic-DNS entries |
| `tests/test_path_b_load.py` (new) | `.keras` preferred over `.h5`; `.h5` used when alone |
| `tests/test_labeling.py` | PSL private suffixes, a tunnel under `duckdns.org`, fallback names |
| `tests/test_evasion.py` | Mixed evasion keeps attack rows, shares the client, stays in the time span |

### How to reproduce

```bash
pytest tests -q                                                       # 94 tests
python3 scripts/convert_cic_dns.py --out-dir /tmp/cic                 # rebuild CIC files to compare
PYTHONPATH=src python3 -m dns_detect.ingest.merge \
    --input data/processed/merged_features_labeled.json data/external/cic/cic_benign_train.json \
    --output data/processed/week4/merged_week4.json
python3 scripts/extend_manifest.py --base data/processed/splits/time_seed42.json \
    --data data/processed/week4/merged_week4.json --add data/external/cic/cic_benign_train.json \
    --out data/processed/week4/splits/time_seed42_cic.json
export DNS_DETECT_MODELS_DIR=models_week4
PYTHONPATH=src python3 -m dns_detect.models.path_a --train data/processed/week4/merged_week4.json \
    --split-manifest data/processed/week4/splits/time_seed42_cic.json --no-transformer --seed 42
PYTHONPATH=src python3 -m dns_detect.models.path_b_train --filename merged_week4.json \
    --data_dir data/processed/week4 --n_days 20 --save_name dns_trafficformer \
    --split-manifest data/processed/week4/splits/time_seed42_cic.json --seed 42
python3 scripts/train_fusion.py --labeled data/processed/week4/merged_week4.json \
    --split-manifest data/processed/week4/splits/time_seed42_cic.json
python3 scripts/make_evasion_set.py --evaluate
python3 scripts/make_evasion_set.py --evaluate --mix-benign data/external/cic/cic_benign_test.json
python3 scripts/verify_models.py --holdout data/external/cic/cic_benign_test.json data/processed/evasion/hex.json
unset DNS_DETECT_MODELS_DIR
python3 scripts/run_multiseed.py --data data/processed/week4/merged_week4.json \
    --manifest data/processed/week4/splits/time_seed42_cic.json --seeds 42 43 44 45 46
```

---

## Open items and next steps

The biggest remaining gap is still the data. The code to fix it is ready, but the 8-tool dataset and multi-machine lab captures have not been brought in.

| Priority | Action | Why |
|---|---|---|
| 1 | Finish the Path B retrain, then retrain the fusion and run both evasion modes | Completes the Week-4 numbers for Path B, fusion and evasion |
| 2 | Run `run_multiseed.py` with Path B and fusion | Mean ± sd for the full pipeline, not only Path A |
| 3 | Decide on the Tu et al. 2023 dataset (no license file; citation requested), then download and convert it | Leave-one-tool-out across 8 tools instead of 2 |
| 4 | Lab captures with `capture_dns.sh`: 5+ machines, several days, real TXT/MX/DNSSEC traffic, iodine and dnscat2 runs | Removes the record-type shortcut; meets the Step 6 done-when targets |
| 5 | Promote `models_week4/` to `models/` once the results above are confirmed | Makes the Week-4 models the deployed ones |
| 6 | Score `verify_models.py` leave-one-tool-out and grouped checks with the false-alarm budget instead of a fixed 0.5 cutoff | The fixed cutoff gives misleading warnings (Phase 1.3) |

**Permissions.** The existing `models/`, `data/` and `docs/Week3/` files are owned by root, so they cannot be overwritten from the normal user account. This is why the Week-4 work was written to new folders. Before step 5, run `sudo chown -R ounnha:ounnha models data docs`.

**Lab false alarms.** The lab test still shows 10 ± 6 false alarms per 1,169 benign rows, above the 0.1 % budget. They come from one lab machine's CDN and update lookups late in the capture. More varied benign data (steps 3–4) is the lasting fix; adding those exact domains to the allowlist would hide the problem rather than solve it.
