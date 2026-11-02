# Implementation report — Need-Improve.md roadmap groups 1, 2, 6, 7

**Audience.** Engineers reading diffs. Each section names the file touched, the before/after behaviour, and the mathematical / logical change where non-trivial. Deferred items (N3, N5, N6, N10) are called out at the end.

## Files modified / added

### New

| File | Purpose | Need-Improve items |
|---|---|---|
| `src/dns_detect/utils/dataset_hash.py` | Deterministic sha256 of inputs + schema | N14 |
| `src/dns_detect/utils/sampling.py` | `sample_contiguous_blocks`, `sample_contiguous_per_group` | N12 |
| `src/dns_detect/models/baselines.py` | Rule baselines + train-only threshold fitter | N4 |
| `scripts/run_cv.py` | 5-seed CV driver, writes split manifests, computes mean ± sd | N13, N11, N1 |
| `docs/Week3/DATASHEET.md` | Gebru-et-al. one-pager | N15 |
| `docs/research/RESEARCH_AND_IMPROVEMENT_PLAN.md` | This plan | — |
| `docs/research/IMPLEMENTATION_REPORT.md` | This file | — |
| `docs/research/EVALUATION_REPORT.md` | Phase-6 table and precision-at-prevalence tables | — |
| `docs/research/REFERENCES.md` | Verifiable bibliography | — |

### Modified

| File | Change | Need-Improve items |
|---|---|---|
| `src/dns_detect/models/splits.py` | +`partition_conflicting_groups`, `STRATEGIES`, `_groups_for_strategy`, `_time_split`, `_lofo_split`, `build_indices`, `write_manifest`, `read_manifest`, `apply_manifest` | N2, N7, N8, N11 |
| `src/dns_detect/models/path_a.py` | Replaces `drop_conflicting_groups` with `partition_conflicting_groups`; persists conflicts to `data/processed/conflicts.json` | N7, N8 |
| `src/dns_detect/ingest/labeling.py` | +`labeling_config_hash`, `_window_bucket`; `domain_stats` returns `parents_by_window`; `lf_decision` accepts `row_window`/`parents_by_window`; report adds `abstain_share_by_source/family`, `labeling_config_hash`, `window_seconds` | N7, N9, N14 |
| `config/settings.yaml` | +`labeling.window_seconds`, +`evaluation.{strategies, seeds, splits_dir}` | N9, N11, N13 |
| `docs/Week2/PROGRESS.md` | Precision edits per Need-Improve.md §N16 | N16 |

## Non-trivial math

### Dataset hash

Deterministic sha256 over the sorted (relative-path, byte-size, content-sha256) tuples of all inputs, mixed with the sorted schema:

```
D = sha256( ∥ᵢ (relᵢ \0 sizeᵢ \0 shaᵢ \n)  ∥  "--schema--\n"  ∥ cols... )
```

Changing any input byte, adding/removing an input, or changing the feature set changes `D`. Short form `D[:16]` is stored as `training_metadata.json → dataset_version`.

### Rule-baseline threshold fitting

`fit_threshold(y_train, values_train)` evaluates `t ∈ linspace(min(v), max(v), 101)` and returns `argmax_t F1(1[v > t], y)`. Ties are broken toward the smaller `t` (more alarms). The function is *never* passed the test set — Arp P3/P5.

### Time-based split

For each class `c`:

```
idx_c = argsort(timestamp)[y == c]
cut₁  = ⌈n_c · (1 − v − s)⌉       # train end
cut₂  = cut₁ + ⌈n_c · v⌉           # val end
```

with defaults `v = s = 0.14`. Concatenating per-class segments preserves both classes in every split even when attack and benign captures do not overlap in time (the 683-day gap in this project — Need-Improve.md P4 note).

### Windowed labeling (N9)

For each row with timestamp `t` and parent domain `p`, let

```
w = ⌊epoch(t) / W⌋        # W = labeling.window_seconds
```

The attack votes used by `lf_decision` come from the `(p, w)` bucket's stats when it exists; otherwise fall back to the per-parent union of votes across windows (which itself is a strict superset of the old whole-batch stats for same-parent-same-window rows). With `W > 0` the attack votes for a row are a function only of rows sharing `(p, w)`, not of unrelated rows — this is the reproducibility property Need-Improve.md N9 asks for.

### Contiguous Path-B sampling (N12)

Given `n` rows and `block_size = N` (Path-B window size), divide the time-sorted sequence into `⌊n / N⌋` disjoint slots. Pick `⌈target_rows / N⌉` slots uniformly without replacement; return their rows in time order. The guarantee is combinatorial: any `N`-record Path-B window entirely inside a selected slot is contiguous, and the only "gaps" are between slots — but slots are size `N`, so a window of size `≤ N` cannot straddle a gap.

## Pipeline integration points (safe additions)

The changes are deliberately additive — defaults keep the Week-2 pipeline byte-identical:

- `labeling.window_seconds` defaults to `0` (whole-batch), preserving the Week-2 labels.
- `path_a._train` now writes conflicts to disk but still trains on the same `keep` subset, so RF/GBT metrics do not change.
- `splits.grouped_split`, `drop_conflicting_groups` and `overlap_share` retain their original signatures.
- `scripts/run_cv.py` is an independent driver; nothing else in `train_models.sh` invokes it unless it is wired in later.

## Deferred items

- **N3, N5** (data collection: same-period benign TXT/MX/DNSSEC/ACME traffic; long benign capture for realistic base rate).
- **N6, N10** (external validation on CIC-Bell-DNS-EXF-2021 and confident-learning label audit).
- **Path-B sampling wiring.** `utils/sampling.py` is available; `scripts/make_labeled_features.py` has not been changed — do that when attack captures are re-generated.

## How to re-run

```bash
pytest -q
python scripts/run_cv.py --labeled data/raw/merged_features_labeled.json
```

Both commands run read-only against the current artifacts.
