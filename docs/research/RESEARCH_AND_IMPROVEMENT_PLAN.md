# Research and improvement plan — DNS Traffic Anomaly Detection

**Scope note (audience).** Written for the capstone's engineering and advisor audience. The literature review is deliberately short and anchored on `docs/Week2/Need-Improve.md`; this document focuses on the plan and the research-to-implementation mapping. Full bibliography: `REFERENCES.md`.

## 1. Executive summary

The Week-2 pipeline is engineering-trustworthy (traceable rows, zero exact-copy leakage, non-circular labels) but scientifically shaky (near-perfect in-sample F1 beaten by a one-line record-type rule; leave-one-tool-out recall collapses to 0.32–0.36). Mapped against the canonical pitfalls framework in Arp et al., *Dos and Don'ts of ML in Computer Security* (USENIX Security 2022), the project trips **P1, P3, P4, P5, P6, P8, P9**.

The response implemented here (**Need-Improve.md roadmap groups 1, 2, 6, 7**) rebuilds the **evaluation design** before collecting more data. The deferred items (N3, N5, N6, N10) are explicitly data-collection or external-validation work and need resources this iteration does not have.

## 2. Existing system assessment

Mapping the project's layers to the Need-Improve.md findings:

| Layer | Files | Pitfalls (Arp) | Need-Improve items |
|---|---|---|---|
| Data collection | `data/raw/*.log|pcap`, `scripts/make_labeled_features.py` | P1, P8, P9 | N3, N5 |
| Labeling | `src/dns_detect/ingest/labeling.py` | P2 (ok), P4 (shortcut proxy) | N6, N9, N10 |
| Merge / schema | `src/dns_detect/ingest/merge.py` | P4 | N7, N8, N14 |
| Splits | `src/dns_detect/models/splits.py` | P3, P5 | N2, N11, N13 |
| Models | `src/dns_detect/models/path_a.py`, `path_b_train.py` | — | — |
| Evaluation / reporting | `scripts/verify_models.py`, `path_a.py` | P6, P9 | N1, N4, N16 |

## 3. Research methodology

1. Re-use `Need-Improve.md` as the primary literature review — it already cites Arp et al. 2022 (pitfall framework), TESSERACT (Pendlebury et al., USENIX Security 2019), Gebru et al. 2018 (datasheets), the IoT shortcut-learning study, the ICS meta-review, Farnham/SANS, Nadler et al. 2019, Ozery et al. NDSS 2024, Northcutt et al. 2021 (confident learning), Snorkel, and the CICIDS2017 troubleshooting work.
2. Confirmation pass (web search, Oct–Dec 2025) to check whether the 2024–2026 corpus has superseded this framework. Result: no — recent DNS-tunneling papers (DNS-HyXNet, Dec 2025; DoH-exfiltration evaluation, Dec 2025; Amirov et al., Jul 2025) still routinely under-document splits and over-claim with ambiguous evaluations. The pitfall framework is current.
3. Project code read (two Explore passes, read-only) to establish exact file/function responsibilities and avoid rewriting work that already exists.

## 4. Literature review (compressed)

- **Pitfalls framework.** Arp et al. 2022 enumerate P1–P10 and show that every reviewed paper in a 30-paper sample trips ≥ 3 of them. Pitfalls P3 (data snooping), P5 (biased parameter selection) and P6 (inappropriate baseline) are addressed by the shared-split-manifest + rule-baselines contribution in this iteration.
- **Temporal and realistic-prevalence evaluation.** TESSERACT (Pendlebury et al. 2019) formalises that malware classifiers must be evaluated with time-ordered splits and realistic class ratios. Applied here: the `time` strategy in `src/dns_detect/models/splits.py`, and the analytical precision-at-prevalence tables in `EVALUATION_REPORT.md`.
- **Shortcut learning.** The IoT NIDS study (arXiv 2609.28725) and the NIDS dataset survey (2502.06688) document capture-artifact shortcuts (per-session client IPs, timestamps, record-type imbalance). Applied here: `capture_group` and `parent_domain_group` strategies.
- **Weak supervision.** Snorkel (Ratner et al. VLDB 2018) legitimises abstain-or-vote labelers; the project's labeling is already in this shape. Need-Improve.md N7/N8 adds *reporting* of what the labelers abstain on.
- **DNS tunneling behaviour features.** Nadler et al. 2019 and Ozery et al. NDSS 2024 ground the behavioural labeling functions (many-unique-subdomains, high information per parent, tunnel record types). The `entropy > 4.0` rule in `src/dns_detect/models/baselines.py :: literature_entropy_rule` is Nadler's threshold.
- **Datasheets.** Gebru et al. 2018; the deliverable is `docs/Week3/DATASHEET.md` (N15).

## 5. DNS attack detection — defensive scope

For each attack vector relevant to this project, the observable DNS signal and the detection posture are summarised below. All work is defensive — no offensive capability is produced.

| Attack | Observable in DNS | Detection posture here |
|---|---|---|
| Tunneling (dns2tcp / DNSExfiltrator / iodine / dnscat2) | high query entropy, many unique subdomains per parent, tunnel record types (TXT/NULL/KEY) | Path A features + behaviour labeling; `baselines.record_type_rule` is the floor |
| Data exfiltration | long encoded labels, high `information_chars` per parent | behaviour LF `high_information` |
| NXDOMAIN enumeration / randomised-subdomain flood | high NXDOMAIN share per (client, parent) | LF `nxdomain_enumeration` |
| DGA | high per-domain entropy, short registered domains | not in scope for this iteration; feature set is query-level |
| DNS-over-HTTPS exfiltration | encrypted — not visible on port-53 captures | explicit non-scope; documented in Need-Improve.md P9 note |

## 6. Algorithm comparison

Need-Improve.md's position — and this plan's — is that the current data cannot distinguish models. Reporting more algorithms before fixing evaluation would waste work. Only when the baseline table, grouped/time splits and 5-seed CV disagree does the choice of model matter.

The in-scope implementation therefore adds **rule baselines** (`models/baselines.py`) and reuses the existing **RF + HistGBT ensemble** (Path A) and **Trafficformer autoencoder** (Path B). No new model classes.

## 7. Dataset evaluation

The datasheet (`docs/Week3/DATASHEET.md`) documents composition, collection, preprocessing, labeling and known limitations. External validation on CIC-Bell-DNS-EXF-2021 is deferred (N6; dataset not available locally).

## 8. Proposed improvements (in-scope)

### 8.1 Dataset version hash (N14)

`src/dns_detect/utils/dataset_hash.py :: dataset_hash(paths, schema, root=None)`.

Mathematical form:

```
D = sha256(  Σᵢ sorted((relpathᵢ, sizeᵢ, sha256(contentᵢ)))
           ∥ sha256(sorted schema) )
```

Trained models cite `D[:16]` in `training_metadata.json`.

### 8.2 Rule baselines (N4)

`src/dns_detect/models/baselines.py` exposes a record-type rule and two threshold rules (`entropy > t`, `length > L`). Thresholds are fitted on **train only** via `fit_threshold` (grid of 101 candidates between `min` and `max`, F1 objective). `literature_entropy_rule` freezes t = 4.0 (Nadler et al.).

Reported per split as a row in the Phase-6 table alongside Path A and Path B.

### 8.3 Shared, versioned split manifest (N2, N11, N13)

`src/dns_detect/models/splits.py`:

- `STRATEGIES = ("exact_copy", "capture_group", "parent_domain_group", "time", "lofo")`
- `build_indices(df, y, strategy, seed, held_out_family=None) → (train, val, test, method)`
- `write_manifest(path, strategy, seed, row_ids, train_idx, val_idx, test_idx, dataset_version, notes)` writes a JSON `{strategy, seed, dataset_version, row_ids: {row_id: train|val|test}}`.
- `apply_manifest(manifest, row_ids)` returns index arrays positioned for a given row ordering.

Path B's existing per-class chronological cut is now reachable by name as `strategy="time"`; the current `grouped_split` on `feature_vector_key` is `strategy="exact_copy"`.

### 8.4 Partitioned conflicts (N7, N8)

`partition_conflicting_groups` returns `(clean_mask, conflict_mask, n_bad)`. `path_a._train` persists the conflict rows to `data/processed/conflicts.json` as a named error-analysis set instead of dropping them silently.

### 8.5 Windowed labeling (N9)

`src/dns_detect/ingest/labeling.py :: domain_stats` now also computes stats per `(parent, floor(epoch_seconds / window_seconds))` when `labeling.window_seconds > 0`. `lf_decision` accepts an optional `row_window` + `parents_by_window` and prefers the per-window stats. `labeling_config_hash` + `report.labeling_config_hash` persists the fingerprint.

Mathematical form: for a row with timestamp `t` under parent `p`, let `w = ⌊t_epoch / W⌋`. The row's attack votes are taken from the `(p, w)` bucket's stats; falls back to the parent-level stats when no match exists.

### 8.6 Contiguous Path-B sampling (N12)

`src/dns_detect/utils/sampling.py :: sample_contiguous_blocks(order, target_rows, block_size, seed)` picks non-overlapping `block_size`-row contiguous blocks totalling about `target_rows`. Guarantees no Path-B window of size ≤ `block_size` spans a sampling gap.

### 8.7 Unseen-tool as headline (N1)

`scripts/run_cv.py` writes a `lofo` section containing per-family recall; the aggregated `unseen_tool_recall_mean` and `unseen_tool_recall_min` are the headline numbers for every subsequent progress report.

### 8.8 CV driver (N13)

`scripts/run_cv.py` loops over `(strategy, seed) ∈ evaluation.strategies × evaluation.seeds`. For each split, it writes a manifest and scores every baseline on the test rows. Mean ± sd across seeds goes into `models/cv_metrics.json → by_strategy.<name>.aggregate` (a separate file, so `models/evaluation_metrics.json` stays owned by Path A / Path B training).

### 8.9 Datasheet (N15), wording (N16)

`docs/Week3/DATASHEET.md` and precision edits in `docs/Week2/PROGRESS.md`.

## 9. Mathematical notes

- **Precision at prevalence** (for N5 analytical table): with recall R and false-positive rate ρ at a chosen threshold, precision at prior π is  P = R·π / (R·π + ρ·(1−π)). Need-Improve.md §Appendix shows this applied to the Week-2 numbers.
- **Grouped CV guarantee.** With `StratifiedGroupKFold(n_splits=k)`, no group appears in more than one fold; `splits.overlap_share` measures per-split leakage empirically.
- **Rule-of-three bound** (N5): zero observed FP on N benign rows gives a 95 % upper CI on the FP rate of 3/N (Jovanovic & Levy, 1997).

## 10. Evaluation methodology

See `EVALUATION_REPORT.md`. The table required by Need-Improve.md §4 is produced by `scripts/run_cv.py` and lives under `models/cv_metrics.json`.

## 11. Risks and limitations

- **Data-collection work is deferred.** Without N3 and N5 collection, the baselines will likely still beat the ML models on `capture_group` and `time` splits because the shortcut features (record type) persist across the current data. That is a *finding*, not a bug.
- **External validation deferred.** Rules trained on this corpus will not have been checked against CIC-Bell-DNS-EXF-2021. Follow-up (N6).
- **Trafficformer unchanged.** The Path-B contiguous-sampler utility is available but Path B's upstream sampling (`scripts/make_labeled_features.py`) was not touched this iteration; wire it when attack captures are re-generated.
- **Windowed labeling default is off.** `labeling.window_seconds` defaults to 0 so Week-2 numbers remain reproducible byte-for-byte. Flip to 3600 for the next training run.

## 12. Expected results

With the baseline table reported on every split, Week-3's results section becomes diagnosable:

- If baselines and models all collapse to similar F1 on `capture_group`, the model has not generalised beyond capture artifacts (Arp P4).
- If 5-seed sd is large relative to the gap between models, no model wins (Arp P5).
- If LOFO recall remains < 0.5 after N3 data collection, the feature set needs per-client behaviour features (planned follow-up).
