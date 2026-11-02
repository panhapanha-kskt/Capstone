# Datasheet — DNS Traffic Anomaly Detection training data

In the format of Gebru et al., *Datasheets for Datasets* (`arxiv.org/abs/1803.09010`). Addresses Need-Improve.md **N15**.

## Motivation

- **Purpose.** Train and evaluate a DNS tunneling / exfiltration detector (Path A: RF + HistGBT ensemble; Path B: Trafficformer autoencoder) for a defensive security capstone.
- **Who created it.** This repository's authors (see `README.md`), using DNS captures recorded in a lab for the capstone plus a Technitium DNS server log from the same lab.
- **Who funded it.** No external funding; capstone coursework.

## Composition

- **Instances.** DNS queries. Each row is one query with its 8-feature vector (`FEATURES_8`): `query_length`, `query_entropy`, `has_digits`, `answer_count`, `subdomain_count`, `longest_label`, `digit_ratio`, `unique_char_ratio`.
- **Count.** 18,353 labeled rows after merge; 10,000 attack / 8,353 benign in the current Week-2 build.
- **Classes.** 2 (benign, attack). Attack family labels: `dns2tcp`, `dnsexfiltrator`, `nxdomain_enum` (ground-truth from the attack manifest), plus `tunnel` for behaviour-labeled rows.
- **Clients.** Benign capture: 4 client IPs — 2 Docker-bridge IPs and `127.0.0.1`. Attack captures: 1 client per tool. **One client per class** is a known shortcut risk (Need-Improve.md N3).
- **Record types.** Benign contains **no** TXT/KEY/NULL queries; attack is 100 % TXT/KEY. This record-type imbalance is a shortcut that a one-line rule already exploits (Need-Improve.md N4; see `src/dns_detect/models/baselines.py`).
- **Features that are known to be constants or near-constants per source type.** `answer_count` is 0 in every PCAP row (DNS answers aren't parsed from scapy inputs); see `merge_report.json` for the full list.
- **Missing data.** `response_code` is only present on Technitium log rows; absent on PCAP-derived rows.

## Collection process

- **Attack captures.** Five short captures (~1.4 min each) in a lab, using **dns2tcp** and **DNSExfiltrator**. Each capture is sampled to **2,000 queries**. Sampling in the Week-2 build is per-row random, which breaks Path B's temporal windows — Need-Improve.md N12. The `sample_contiguous_blocks` helper (`src/dns_detect/utils/sampling.py`) is the sanctioned replacement.
- **Benign capture.** One capture, 2 hours, 4 clients. Captured **683 days after** the attacks — Need-Improve.md N3/N4 shortcut.
- **Technitium log.** `2026-03-18.log` contains a lab NXDOMAIN flood (one client, 3 minutes, 99.95 % NXDOMAIN). Two other log files were empty on inspection.
- **Timestamps.** The Technitium container has no timezone set; the lab host is UTC+7. The attack manifest records which clock each window is in and labeling widens windows ± 2 s for drift.

## Preprocessing / labeling

- **Pipeline.** `scripts/train_models.sh` stages 2–8 (`features/eda_data.py`, `features/extractor.py`, `ingest/merge.py`, `ingest/labeling.py`).
- **Labeling precedence** (`src/dns_detect/ingest/labeling.py`): file label → attack manifest (± 2 s window; `source_ip` and `target_domain` filters) → weak behavioural labeling functions (many-unique-subdomains, long-encoded-labels, tunnel-record-types, nxdomain-enumeration) voting with min 2 votes → abstain.
- **Reproducibility of labels.** When `labeling.window_seconds > 0` (Need-Improve.md N9), the behavioural functions compute stats per `(parent_domain, time_window)` so adding unrelated traffic from a different time window does not change the labels of other rows. Default is `0` (whole-batch) for compatibility with Week-2 numbers.
- **Config fingerprint.** `labeling_report.json → labeling_config_hash` stores a sha256 of the frozen labeling settings slice plus the sorted allowlist.
- **Dataset fingerprint.** `src/dns_detect/utils/dataset_hash.py` computes a sha256 over the sorted (relpath, size, content-sha256) tuples of the inputs mixed with the sorted `FEATURES_8` schema; this is the `dataset_version` key in `training_metadata.json` (Need-Improve.md N14).

## Data cleaning

Cleaning runs inside `ingest/merge.py` (`ingest/cleaning.py`, thresholds under `cleaning:` in `config/settings.yaml`), before `dup_key` and labeling. Generic recipes — fix invalid characters, delete outliers, drop duplicate rows — would remove the attack signal from DNS-tunnel data, so the rules are DNS-specific:

1. **Never change what a query means.** Normalisation is only strip, lowercase and the trailing root dot (plus upper-case `query_type` / `protocol`).
2. **Reject only what cannot be real DNS**, into a quarantine file with a `reject_reason` — never a silent delete.
3. **Drop only capture artefacts**: an input file whose content was already merged, and identical copies of one packet. Repeated queries are real traffic frequency.
4. **Fit every data-dependent fix on train rows only**, save it with the model, apply it unchanged at inference.
5. **Report every change in numbers** (`merge_report.json → cleaning`, `missing_values`; `evaluation_metrics.json → path_a.missing_filled`, `clipped_values`).
6. **Never drop rows at inference.** Detection scores malformed names too — they may be the attack.

| Cleaning step (GeeksforGeeks "Data Cleaning") | Where | Decision on this data |
|---|---|---|
| Assess quality | `features/eda_data.py`, `merge.py` report | Duplicates, missing values, unparseable lines, outliers (IQR), constant features, label conflicts are reported |
| Remove irrelevant data | `cleaning.py`, `PATH_A_FEATURES` | Only model features reach the model; `answer_count` (always 0) is excluded from Path A |
| Remove duplicates | `merge.py`, `cleaning.py` | Duplicate input files skipped; identical packet copies (name, timestamp, client IP **and port**, qtype, protocol) dropped. Repeated queries kept; `dup_key` keeps copies on one side of every split |
| Fix structural errors | `cleaning.py`, parsers | Case and trailing dot normalised; Week-3 field names mapped to model names |
| Incorrect data types | `dns_parser.py` | `pd.to_numeric(errors="coerce")` on every feature |
| Invalid values | `cleaning.py` | Rejected: empty name, name > 253 chars, label > 63 (RFC 1035), label ∉ {0, 1}, infinite feature, negative length/count, ratio outside [0, 1] |
| Missing data | `dns_parser.missing_value_report` | Filled with 0 (unchanged), but counted before the fill so a stored 0 and a filled 0 stay distinguishable |
| Outliers | `models/path_a.py` (`fit_clip_bounds` / `apply_clip`) | **Capped, never removed**, at the train 0.1 % / 99.9 % quantiles (`training.path_a_clip_quantile`); caps stored in `dns_threshold.json`. Tunnels are the extreme tail, so deleting outliers would delete attacks |
| Label noise | `ingest/labeling.py`, `path_a.py` | Unconfident rows abstain (`abstained_rows.json`); feature vectors with both labels are kept out of training (`conflicts.json`) |
| Validation | `dns_parser.check_model_features` | Identity / time / provenance columns (`client_ip`, `timestamp`, `hour_of_day`, `source_file`, …) can never be model inputs — import fails if they are |
| Scaling | `path_a.py` | `StandardScaler` fit on train rows only, after capping |

**Kept on purpose, with counts from the current build** (18,353 rows → 18,349 after cleaning, 0 rejected, 4 packet copies dropped):

- **3,100 names with characters outside `[a-z0-9-_.]`, all attack** — base64 payload such as `sisaqgc/ba.dns2tcp-key.com`. Flagged `non_hostname_chars`, never fixed.
- **461 infrastructure queries, all benign** — `*.arpa` reverse lookups and bare TLDs (DNSSEC `DS`/`DNSKEY` for `com`, `org`). Real resolver traffic that live detection also sees. Flagged `infra_query`.
- **19 same-name, same-timestamp queries from different source ports** — a resolver's parallel queries, not copies.
- **Outliers** — capping at the 99.9 % quantile touched 9–67 values per feature (of 13,105 train rows); test PR-AUC, recall and false alarms were identical with and without capping on this data.

**Shortcut found while cleaning.** Benign rows are from 2026 and attack rows from 2019–2024, and the two classes share no client IP. Either column alone separates the classes, which is why they are on the forbidden-feature list rather than cleaned.

**Outputs.** `data/processed/rejected_rows.json` (quarantine, written on every merge), `data/processed/conflicts.json` (label conflicts), `data/processed/abstained_rows.json` (no confident label).

## Known limitations

Each item is cross-referenced with Need-Improve.md.

| ID | Limitation | Mitigation in-repo |
|---|---|---|
| N1 | Unseen-tool recall is 0.32–0.36 (DNSExfiltrator / dns2tcp LOFO) | `scripts/run_cv.py` reports it as a headline column |
| N2 | Split only separates exact copies; sessions still leak | `splits.STRATEGIES` adds `capture_group`, `parent_domain_group`, `time` |
| N3 | Shortcuts: record type, client IP, time, source each separate the classes with AUC > 0.95 | Documented; fix requires new data |
| N4 | No simple baseline was reported in Week 2 | `models/baselines.py` + `scripts/run_cv.py` row |
| N5 | Attack share 54.5 % (unrealistic) | `EVALUATION_REPORT.md` reports precision at 1:100 / 1:1 000 / 1:10 000 analytically |
| N6 | Labeling rules checked on their own development data | External CIC-Bell-DNS-EXF-2021 validation deferred (dataset not yet staged) |
| N7 | Share of abstained rows was not reported | `labeling_report.json → abstain_share_by_source/family` |
| N8 | Conflicting rows silently dropped | `splits.partition_conflicting_groups`; `path_a` persists them to `data/processed/conflicts.json` |
| N9 | Labeling depended on the whole batch | `labeling.window_seconds` + `parents_by_window` |
| N10 | "Trusted" labels assumed, not audited | Confident-learning audit deferred |
| N11 | Path A and Path B evaluated on different splits | `splits.{build_indices, write_manifest, read_manifest}` manifest I/O |
| N12 | Attack sampling broke Path B's sequences | `utils/sampling.sample_contiguous_blocks` |
| N13 | Results from one seed, no uncertainty | `scripts/run_cv.py` default seeds = `[42, 43, 44, 45, 46]` |
| N14 | Dataset not versioned | `utils/dataset_hash.py` |

## Licensing and distribution

- The captures and logs were produced in a private capstone lab and are **not redistributed**; attack domains were owned by the authors for the duration of each capture.
- The code is under the repository's `LICENSE` (see repo root).
- Nothing in this dataset is intended to attribute, impersonate or embarrass a real third party.

## Intended use

- Research and evaluation of DNS-tunneling detectors in a defensive context.
- **Not intended** for production deployment on live traffic until the Need-Improve.md N3/N5 data-collection follow-ups are in place; the current attack share and the client/time shortcuts make production precision unknowable.
