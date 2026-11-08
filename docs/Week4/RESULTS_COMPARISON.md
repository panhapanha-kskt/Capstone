# Results Comparison: Old Models vs New Training Runs

**DNS Traffic Anomaly Detection · committed models vs the retrained baseline vs baseline + one new tool · updated 2026-11-07**

This document compares the new training results with the results already recorded for the old models. It is updated after each run. All numbers come from the same held-out test rows, so the comparison is fair (section 1).

| Name | What it is | Trained with |
|---|---|---|
| **Old** | the committed models in `models/` (results in `models/evaluation_metrics.json` and [CHANGES.md](CHANGES.md) §12) | old data; Path A, Path B and fusion trained by hand on `time_seed42` |
| **Baseline** | `runs/baseline` | the **same old data**, retrained with the new `train_models.sh` (shared split + fusion in one command) |
| **v_dnsshell** | `runs/v_dnsshell` | old data **+ dns_shell** (5,000 queries) |
| **v_det** | `runs/v_det` | old data **+ det** (5,000 queries) |

Each new run trained **Path A, Path B and fusion** and saved a complete model set in its own folder (`runs/<name>/`). The detection pipeline still uses the old models in `models/` unless `DNS_DETECT_MODELS_DIR=runs/<name>` is set.

Plan and commands: [NEXT_TASKS_PER_TOOL.md](NEXT_TASKS_PER_TOOL.md).

---

## Contents

1. [Why the runs are comparable](#1-why-the-runs-are-comparable)
2. [Training data](#2-training-data)
3. [Results on the frozen test set](#3-results-on-the-frozen-test-set)
4. [False alarms on unseen benign traffic (CIC capture 3)](#4-false-alarms-on-unseen-benign-traffic-cic-capture-3)
5. [Unseen-tool tests](#5-unseen-tool-tests)
6. [What the results show](#6-what-the-results-show)
7. [Cautions](#7-cautions)
8. [Still to collect](#8-still-to-collect)

---

## 1. Why the runs are comparable

- **Same test rows.** Every run is scored on the test part of `data/processed/splits/time_seed42.json`: about 1,169 benign and 1,400 attack rows, the latest 14% of each class in time.
  - The new runs log `test 2568` (1,168 benign), one row fewer. The new merge step drops exact packet copies (18,353 → 18,349 rows), and one of those copies was in the test set.
  - Runs that add a tool use an `extended` split: the new rows go to train and validation only, so the test rows are exactly the baseline's.
- **Same calculation.** All numbers in section 3 come from each run's `evaluation_metrics.json`, written by `scripts/train_fusion.py`.
- **CHANGES.md §12.1 uses a different calculation.** It reports Path B 64 and OR rule 83 false alarms for the old models, from `scripts/eval_fusion.py`, which treats missing Path B scores differently. Those are correct, but not like-for-like (section 3.4).

---

## 2. Training data

| | Old | Baseline | v_dnsshell | v_det |
|---|---|---|---|---|
| Attack rows | 10,000 | 10,000 | 15,000 | 15,000 |
| Benign rows | 8,353 | 8,349 | 8,349 | 8,349 |
| Attack tools | dns2tcp, dnsexfiltrator | same | + **dns_shell** | + **det** |
| Added tool's query types | — | — | A 4,000 · TXT 1,000 | A 5,000 |
| Split | `time_seed42` | reused | extended | extended |
| Train / val / test | 13,215 / 2,569 / 2,569 | 13,215 / 2,566 / 2,568 | 17,465 / 3,316 / 2,568 | 17,465 / 3,316 / 2,568 |
| Training time | — | 14 min | 25 min | 20 min |

---

## 3. Results on the frozen test set

### 3.1 False alarms per method

| Method | Old | Baseline | v_dnsshell | v_det |
|---|---|---|---|---|
| Path A | 31 (2.65%) | 23 (1.97%) | **7 (0.60%)** | 38 (3.25%)\* |
| Path B | 71 (6.07%) | 112 (9.59%) | 113 (9.67%) | *to collect* |
| OR rule | 90 (7.70%) | 116 (9.93%) | 113 (9.67%) | 119 (10.19%) |
| **Fusion** | **31 (2.65%)** | **23 (1.97%)** | **7 (0.60%)** | **38 (3.25%)** |

Recall is **1.0 for every method in every run**: no test attack is missed. Rates are false alarms ÷ test benign rows (1,169 old, 1,168 new). \*v_det's Path A count is inferred from the fusion count (fusion has equalled Path A in every other run) and still needs confirming (section 8).

### 3.2 Model quality

| | Old | Baseline | v_dnsshell | v_det |
|---|---|---|---|---|
| Path A F1 | 0.9890 | 0.9919 | **0.9975** | 0.9873 |
| Path A PR-AUC | 0.9936 | 0.9957 | 1.0 | 1.0 |
| Path B threshold | — | 0.04163 | 0.04145 | 0.04301 |
| Fusion alarms per 10,000 benign | ≈265 | ≈197 | **≈60** | ≈325 |

### 3.3 Fusion false alarms

```
Old         ███████████████████████████████          31
Baseline    ███████████████████████                  23   same data, new pipeline
v_dnsshell  ███████                                   7   + dns_shell   (−70% vs baseline)
v_det       ██████████████████████████████████████   38   + det         (+65% vs baseline)
```

### 3.4 Old results by the other calculation (CHANGES.md §12.1, for reference)

| Method | Recall | False alarms | FPR |
|---|---|---|---|
| Path A | 1.000 | 31 | 2.65% |
| Path B | 1.000 | 64 | 5.47% |
| OR rule | 1.000 | 83 | 7.10% |
| Fusion V1 | 1.000 | 31 | 2.65% |

Path A and the fusion match section 3.1. Path B and the OR rule differ only because of the missing-score handling.

---

## 4. False alarms on unseen benign traffic (CIC capture 3)

CIC-Bell-DNS-EXF-2021 benign capture 3 (25,222 queries) was never used for training. Every query flagged is a false alarm.

```bash
for r in baseline v_dnsshell; do
  DNS_DETECT_MODELS_DIR=runs/$r python3 -m dns_detect.models.path_a \
      --infer data/external/cic/cic_benign_test.json 2>/dev/null | tail -3
done
```

| Run (Path A) | Flagged (= false alarms) | Rate | Budget 0.1% (≈25) |
|---|---|---|---|
| Baseline | 1 / 25,222 | 0.004% | ✅ well inside |
| v_dnsshell | **0 / 25,222** | 0.000% | ✅ |
| v_det | *to collect* | | |

**This is the most realistic false-alarm number so far.** It comes from a different network, recorded by a different team, with traffic the model never saw, and the false-alarm rate is close to zero. The 0.6–3% on the frozen test set comes from that test period's own benign traffic (the validation → test drift described in CHANGES.md §12.1), not from the model flagging normal DNS in general.

---

## 5. Unseen-tool tests

Each new tool is tested with the **baseline** *before* it is added to training. The baseline has never seen it.

```bash
DNS_DETECT_MODELS_DIR=runs/baseline python3 -m dns_detect.models.path_a \
    --infer data/external/tu2023/tunnels_<tool>.json 2>/dev/null | tail -3
```

| Tool | Tunnel domain | Queries in captures | Kept | Query types | Caught by baseline |
|---|---|---|---|---|---|
| dns_shell | dnsshell-txt.com | 75,024 (5 others dropped) | 5,000 | A 4,000 · TXT 1,000 | **5,000 / 5,000 (100%)** |
| det | det-a.com | 38,365 (0 dropped) | 5,000 | A 5,000 | **5,000 / 5,000 (100%)** |

Path A uses no time features, so the 683-day gap between the attack and benign captures cannot explain these results.

---

## 6. What the results show

### 6.1 Old → Baseline (same data, new pipeline)

- Path A: 31 → 23 false alarms. The fusion follows Path A.
- Path B: 71 → 112 false alarms. Path B got worse when retrained, which raises the OR rule (90 → 116).
- Differences in the run:
  - Path A, Path B and fusion now train in one command on one shared split;
  - 4 exact packet copies are dropped;
  - a different machine (Kali, Python 3.13.12);
  - Path B saved as `.keras`;
  - run-to-run randomness.
- **The new pipeline reproduces the old quality** (recall 1.0, PR-AUC ≥ 0.99). Path B's higher false-alarm count needs a look (section 7).

### 6.2 The fusion relies on Path A alone

In every run the fusion's false alarms equal Path A's: 31 = 31, 23 = 23, 7 = 7.

Path B is **not** ignored. In the old fusion (`models/fusion_lr.json`) the weights are 8.78 for Path A and 2.79 for Path B (intercept −5.77, alarm threshold 0.49). Working through that formula:

- **Path B can never raise an alarm on its own.** With a Path A score near 0, even the highest Path B score gives an alarm probability of about 2%.
- **Path B moves the bar for Path A.** A row needs a Path A score of about 0.74 to alarm when Path B is quiet, and about 0.42 when Path B is at its highest.
- **On these test rows that never changed a decision.** Path A's scores are almost all near 0 or near 1, so few rows are borderline.

Path A and Path B scores are also strongly correlated (0.963, CHANGES.md §12.3). In practice, **the detector's decision follows Path A**, and Path B's higher false alarms don't reach the final output on this test set. The new runs' weights are in `runs/<name>/fusion_lr.json` and have not been checked yet.

### 6.3 Adding a tool can help or hurt

| Added tool | Fusion false alarms | Path A F1 | Effect |
|---|---|---|---|
| dns_shell | 23 → **7** | 0.9919 → 0.9975 | **better** |
| det | 23 → **38** | 0.9919 → 0.9873 | **worse** |

Both tools send mainly A queries, both are caught 100% before training, and both add 5,000 rows. Yet they move the false alarms in opposite directions.

A likely reason, **not yet verified:**

- det's queries may look closer to normal DNS than dns_shell's (e.g. shorter or less random labels).
- Training on them teaches Path A that milder-looking queries can be attacks. Its decision boundary moves toward benign traffic, and more test-period benign rows cross it.
- dns_shell's queries are more extreme, so they sharpen the boundary instead.

How to check:

1. **Compare the feature ranges.** Mean query length and entropy of det vs dns_shell vs the benign test rows.
2. **Look at what was flagged.** The 38 v_det test false alarms: which domains are they?
3. **Repeat with other seeds** (`scripts/run_multiseed.py`). With about 1,168 benign test rows, part of a 23 → 38 change can be randomness.

### 6.4 What this means for the plan

- **Per-tool runs answer which tools help.** dns_shell helps; det hurts on this test set.
- **The unseen-benign test (section 4) should be repeated for every run.** On CIC capture 3 the models are close to zero false alarms, and that is the number that matters for deployment. v_det's figure is needed before concluding that det hurts in general.
- **Unseen-tool recall is 100% for both new tools so far.** Path A generalises well to new tunnel tools.

---

## 7. Cautions

1. **Small test set.** About 1,168 benign test rows: one false alarm ≈ 0.09%. Differences of a few alarms are not meaningful on their own.
2. **One run per configuration (seed 42).** Run-to-run variation is not measured yet. Use `scripts/run_multiseed.py` before claiming any difference in the final report.
3. **Frozen test set: still above the 0.1% budget.** The best run (v_dnsshell) is at 0.60%. On unseen benign traffic from another network (section 4) it is 0%.
4. **New tools are not in the frozen test set.** Their rows go to train/val only. How well a tool is caught comes from the unseen-tool test (section 5).
5. **Path B worsened in the new runs** (71 → 112 false alarms). It cannot raise an alarm on its own in the fusion (§6.2), so the final output is unaffected here. It still matters for borderline rows and for Path B used alone. Worth checking: compare its validation and test reconstruction errors, or retrain it with another seed.
6. **The training data is easy.** The EDA reports that single features separate the classes (AUC up to 0.997), and 70–81% of rows repeat another row's feature vector. Unseen tools, unseen benign traffic and the leave-one-tool-out test are the meaningful tests.

---

## 8. Still to collect

```bash
cd /home/ounnha/Documents/Capstone
export PYTHONPATH=src

# v_det per-method false alarms
python3 - runs/v_det <<'EOF'
import json, sys
t = (json.load(open(f"{sys.argv[1]}/evaluation_metrics.json")).get("fusion") or {}).get("test") or {}
for k in ("path_a", "path_b", "or_rule", "learned_lr"):
    b = t.get(k) or {}
    print(f"  {k:10} recall={b.get('recall')}  fpr={b.get('fpr')}  false_alarms={b.get('false_alarms')}")
EOF

# v_det on unseen benign traffic
DNS_DETECT_MODELS_DIR=runs/v_det python3 -m dns_detect.models.path_a \
    --infer data/external/cic/cic_benign_test.json 2>/dev/null | tail -3
```

Then continue with the next tools: ozymandns, cobaltstrike, dnscat2, iodine ([NEXT_TASKS_PER_TOOL.md](NEXT_TASKS_PER_TOOL.md), Task B).
