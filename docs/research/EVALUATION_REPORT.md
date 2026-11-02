# Evaluation report — Week 3 protocol

**Audience.** Reviewer / advisor. Week-2 reference numbers come from `docs/Week2/Need-Improve.md`. New numbers come from `scripts/run_cv.py` and are saved to `models/cv_metrics.json`, a separate file so the Path A / Path B training metrics in `models/evaluation_metrics.json` are never overwritten.

## Experimental environment

- Python 3, scikit-learn and pandas from `requirements.txt`. No GPU and no TensorFlow are needed for the baseline rows.
- Seeds `[42, 43, 44, 45, 46]`. Thresholds are fitted on the train split only and never see the test rows.
- Command:

```bash
python scripts/run_cv.py --labeled data/processed/labeled_tunnels.json data/processed/labeled_benign.json
```

## Dataset

- `data/processed/labeled_tunnels.json` (10 000 attack rows) + `data/processed/labeled_benign.json` (8 353 benign rows) = 18 353 rows, 54.5 % attack.
- `dataset_version` = `88a5f2a3c37d088c…`, from `src/dns_detect/utils/dataset_hash.py`.
- 6 source captures: 1 benign (`benign_dns.pcap`) and 5 attack captures of 2 000 rows each (4 × dns2tcp, 1 × DNSExfiltrator).
- External validation set: none. CIC-Bell-DNS-EXF-2021 is deferred (N6).

## Check against the Week-2 review

The driver re-measures, independently, the numbers that Need-Improve.md reported. They agree, which confirms that the new split and baseline code does what it claims.

| Measurement | Need-Improve.md | `run_cv.py` (exact_copy, 5 seeds) |
|---|---|---|
| Record-type rule F1 | 1.000 | 1.000 ± 0.000 |
| Entropy threshold, fitted on train, F1 | 0.956 | 0.956 ± 0.004 |
| Entropy > 4.0 (literature) F1 | 0.883 | 0.891 ± 0.005 |
| Unseen-tool recall, dns2tcp held out | 0.318 | 0.318 |
| Unseen-tool recall, DNSExfiltrator held out | 0.357 | 0.350 mean of both families (min 0.318) |

The small difference in the literature-entropy F1 comes from averaging 5 seeds instead of reporting seed 42 alone.

## Results: baselines on every split (mean ± sd over 5 seeds)

| Baseline \ Split | exact_copy | capture_group ⚠ | parent_domain_group | time |
|---|---|---|---|---|
| Record type ∈ {TXT, KEY, NULL} | **1.000 ± 0.000** | **1.000 ± 0.000** | **1.000 ± 0.000** | **1.000 ± 0.000** |
| Length, threshold fitted on train | 0.966 ± 0.003 | 0.988 ± 0.001 | 0.480 ± 0.002 | 0.930 ± 0.000 |
| Entropy, threshold fitted on train | 0.956 ± 0.004 | 0.981 ± 0.002 | 0.648 ± 0.136 | 0.962 ± 0.000 |
| Entropy > 4.0 (literature) | 0.891 ± 0.005 | 0.912 ± 0.005 | 0.804 ± 0.093 | 0.985 ± 0.000 |

All values are F1. PR-AUC and false-positive rate per cell are in `models/cv_metrics.json → by_strategy.<split>.aggregate`.

**Unseen tool (LOFO, N1 headline):** recall mean **0.350**, worst case **0.318** (2 families).

⚠ **`capture_group` could not be computed as intended.** All benign rows come from a single capture, so no split can hold out a benign capture and still keep benign rows in train, validation and test. The splitter falls back to random rows and reports this (`split method: random_rows_fallback`). This column is therefore **not** capture-separated and should not be read as one. The fallback is itself evidence for N3: the data has too few captures to support capture-level evaluation.

## What the results show

1. **The record-type shortcut survives every split.** F1 1.000 on all four splits means no split design can remove it, because benign traffic contains no TXT/KEY/NULL queries at all. This can only be fixed with new data (N3: benign TXT/MX/DNSSEC traffic), not with a better evaluation.
2. **Fitted thresholds do not carry over to unseen parent domains.** On `parent_domain_group`, threshold F1 falls to 0.48–0.65, with a large spread for entropy (± 0.136), while PR-AUC stays around 0.997. The features still rank attack above benign, but a cutoff chosen on one set of domains is in the wrong place for new domains. Threshold choice, not the features, is the weak point. This supports N5's recommendation to pick the alarm threshold from a false-alarm budget instead of from maximum F1.
3. **The time split shows almost no variance (sd 0.000).** Within each class the cut is fixed by time order, so changing the seed only reshuffles training rows. That is expected. Its numbers resemble `exact_copy` because attack and benign are 683 days apart and each class is cut separately; it measures "later sessions of the same tools", not "a later period of mixed traffic".
4. **Unseen-tool recall (0.32–0.35) is the honest headline.** It is the only measurement here that is far from 1.0.

## Analytical precision at realistic attack shares (N5)

Using precision = R·π / (R·π + ρ·(1−π)), with recall R ≈ 1 and the 95 % upper bound on the Week-2 Path A false-positive rate ρ ≤ 3 / 1 193 ≈ 0.0025 (rule of three; zero false alarms seen on 1 193 benign test rows):

| Attack share π | Precision, worst case within the bound | False alarms per 1 000 000 queries, up to |
|---|---|---|
| 54.5 % (current test) | 0.997 | ≈ 1 250 |
| 1 in 100 | 0.801 | ≈ 2 490 |
| 1 in 1 000 | 0.285 | ≈ 2 510 |
| 1 in 10 000 | 0.038 | ≈ 2 510 |

These rows are calculated, not measured. The benign test set is too small to measure them directly; about 300 000 benign test queries would be needed (N5, deferred).

## Not yet measured

- **Path A, Path B and fusion on each split manifest.** The manifests now exist in `data/processed/splits/`, but the models were not retrained per manifest in this iteration. That needs TensorFlow and a training run on the Kali machine.
- **Confusion matrices per split.** `cv_metrics.json` stores class support and false-positive rate. Full matrices for the production Path A run are written by `path_a.py`.
- **Windowed labeling (N9) and contiguous sampling (N12).** Both are implemented and unit-tested. Measuring them needs re-labeling with `labeling.window_seconds: 3600` and re-generating the attack captures.

## Ablation plan

| Experiment | Configuration | Status |
|---|---|---|
| Baseline | Week-2 split, single seed, no baselines | Need-Improve.md |
| A | + rule baselines (N4) | **measured** (table above) |
| B | + parent-domain and time splits (N2) | **measured**; capture split blocked by data |
| C | + 5-seed mean ± sd (N13) | **measured** |
| D | + windowed labeling (N9) | implemented, not measured |
| E | + Path A / Path B retrained on shared manifests (N11) | manifests written, not measured |

## Final assessment

The evaluation design can now produce comparable numbers across splits, seeds, baselines and models, and those numbers match the independent Week-2 review. They confirm that the next lever is data, not modelling. A one-line record-type rule scores F1 1.000 on every split, and the only result far from perfect is unseen-tool recall (0.32–0.35). Until the deferred N3 and N5 collection is done, no model comparison on this data can be meaningful.
