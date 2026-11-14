# Week 5: The Balanced Combined Model (v3, ~100K attack vs ~118K benign)

**DNS Traffic Anomaly Detection · training one model on all 8 tunnel tools with a near 1:1 attack/benign balance · 2026-11-08**

Week 4 added the Tu et al. (2023) tools one at a time and measured each unseen. Week 5 trains the **single combined model** (`runs/v3`) that is the candidate to replace `models/`, scaled up from the original 5,000-per-tool cap to a balanced ~100K vs ~118K dataset.

Prior work: [NEXT_TASKS_PER_TOOL.md](../Week4/NEXT_TASKS_PER_TOOL.md) (per-tool plan and results) · [RESULTS_COMPARISON.md](../Week4/RESULTS_COMPARISON.md) (all runs side by side).

---

## Contents

1. [What Week 4 established](#1-what-week-4-established)
2. [The dataset inventory](#2-the-dataset-inventory)
3. [Why ~100K vs ~118K, not everything](#3-why-100k-vs-118k-not-everything)
4. [The three training steps](#4-the-three-training-steps)
5. [Evaluating v3](#5-evaluating-v3)
6. [Results tables (fill in)](#6-results-tables-fill-in)
7. [Checklist](#7-checklist)

---

## 1. What Week 4 established

**Unseen-tool tests (the honest recall numbers, recorded before any tool entered training data):**

| Tool | Domain | Queries | Detected | Recall |
|---|---|---|---|---|
| dns_shell | dnsshell-txt.com | 5,000 | 5,000 | 100% |
| det | det-a.com | 5,000 | 5,000 | 100% |
| ozymandns | ozymandns-txt.com | 5,000 | 5,000 | 100% |
| cobaltstrike | cobaltstrike-txt.com | 5,000 | 5,000 | 100% |
| dnscat2 | dnscat-aaaa.com | 5,000 | 5,000 | 100% |
| **iodine** | iodine-private.com | 5,000 | **4,996** | **99.92%** |

The baseline (trained on only dns2tcp + dnsexfiltrator) caught 5 of 6 unseen tools at 100% and iodine at 99.92%. iodine is the first tool with misses — the first direct evidence of a tool that benefits from being in the training data.

**Per-tool training effects on the frozen test set (2,568 rows, fusion false alarms):**

- baseline: 23 · v_dnsshell: **7** (helps) · v_det: **38** (hurts on the frozen period — but v_det on unseen benign CIC capture 3 is 1 / 25,222 = 0.004%, far inside the 0.1% budget, so det stays in).
- Per-tool training runs for ozymandns, cobaltstrike, dnscat2, iodine were **skipped**: the diagnostic story (one tool that helps, one that mildly hurts) is already established, and v3's added benign data works against exactly the problem det caused.

**Known weak point:** Path B (benign-only autoencoder) — 105–113 false alarms in every retrained run. It learns only from benign traffic, so only more benign data improves it. That is the main lever this week.

---

## 2. The dataset inventory

**Attack (raw kept-domain queries available per tool):**

| Tool | Available | Used in v3 |
|---|---|---|
| dns2tcp + dnsexfiltrator (old, `labeled_tunnels.json`) | 10,000 | 10,000 |
| dns_shell | ~75,000 | 15,000 |
| det | ~38,400 | 15,000 |
| ozymandns | ~74,800 | 15,000 |
| cobaltstrike | ~50,000 | 15,000 |
| dnscat2 | ~50,000 | 15,000 |
| iodine | ~150,400 | 15,000 |
| **Total attack** | | **100,000** |

**Benign (counted 2026-11-08, truncation 0.0% on every file):**

| Source | Rows | Used in v3 |
|---|---|---|
| Own benign (`labeled_benign.json`) | 8,353 | 8,353 |
| CIC benign train (`cic_benign_train.json`) | 41,275 | 41,275 |
| Tu ALEXA capture (`benign_alexa.json`) | 68,710 | 68,710 |
| Tu daily captures 1–3 (in `benign_tu2023.json`, 876,599 total with ALEXA) | ~807,900 | 0 (reserve) |
| **Total benign in v3** | | **118,338** |

The three Tu daily captures (real traffic, ~115 clients/day, Aug 1–3 2021) are kept as a **reserve**: an extra unseen-benign false-alarm test, or a future Path B upgrade.

---

## 3. Why ~100K vs ~118K, not everything

- **Balance beats volume.** All benign (926K) vs 100K attack is a 9:1 skew toward benign; all attack uncapped (~450K kept-domain) vs ~120K benign skews 4:1 the other way. Either skew damages threshold calibration — the false-alarm side we are optimising. ~1:1.2 keeps both classes honest.
- **Attack rows repeat.** The EDA found 81% of rows duplicate another row's exact feature vector; a tunnel sends the same encoded query shape thousands of times. 15,000 rows per tool captures a tool's behaviour; 150,000 captures it again 10 more times.
- **Equal per-tool weight.** 15,000 each means no tool dominates (uncapped, iodine would outweigh det 4:1).
- **Training time.** ~218K rows already pushes one run to an estimated 1–2 hours (Path B is the slow part); 1.3M rows would take a day per run and make the multi-seed check impractical.
- **The converter cap is a flag, not a limit:** `--max-per-family` (default 5,000) with contiguous time blocks, so Path B's 5-minute windows survive. Raising it to 15,000 is all the change needed.

**Known limitation (future work):** for multi-variant tools the converter keeps only the dominant tunnel domain, so dnscat2's MX/CNAME/TXT variants and cobaltstrike's A/AAAA variants are dropped. Converting those variants as extra families (via `--domain`) would add behaviour *diversity* — worth more than extra volume if v3 needs further improvement.

---

## 4. The three training steps

Setup in every terminal:

```bash
cd /home/ounnha/Documents/Capstone
export PYTHONPATH=src
unset DNS_DETECT_MODELS_DIR
R=data/external/tu2023/repo/datasets/base_malicious_dataset
```

### Step 0 (done 2026-11-08): convert the Tu benign captures

Moved from Week 4, Task C1. Already run; kept here so the work can be reproduced. Truncation check first (each file's `truncated_share` must be below 0.01; all four were 0.0):

```bash
python3 -c "
import sys, glob; sys.path[:0] = ['src', 'scripts']
from make_labeled_features import truncation_report
for f in sorted(glob.glob('data/external/tu2023/repo/datasets/base_benign_dataset/*.pcap')):
    print(f.split('/')[-1], truncation_report(f))" 2>/dev/null

python3 scripts/make_labeled_features.py --label 0 --family benign_tu2023 \
    --input data/external/tu2023/repo/datasets/base_benign_dataset/*.pcap \
    --output data/external/tu2023/benign_tu2023.json 2>/dev/null
```

Result: 876,599 rows (ALEXA 68,710 · daily 1: 279,141 · daily 2: 304,036 · daily 3: 224,712), about 30 minutes. Do not use `--max-per-file`: it samples single queries at random and breaks Path B's windows.

### Step 1: reconvert the 6 tools at 15,000 each (~35 min, re-parses all pcaps)

```bash
python3 scripts/convert_external_tunnels.py --root $R \
    --families dns_shell det ozymandns cobaltstrike dnscat2 iodine \
    --max-per-family 15000 --out-dir data/external/tu2023 2>/dev/null
```

Overwrites `tunnels_*.json` with 15,000-row versions. Safe: the unseen-tool tests are already recorded, and conversion is deterministic (seed 42). Check each `domain=` line again anyway.

### Step 2: ALEXA-only benign file (~3 min)

```bash
python3 scripts/make_labeled_features.py --label 0 --family benign_tu2023 \
    --input data/external/tu2023/repo/datasets/base_benign_dataset/ALEXA.pcap \
    --output data/external/tu2023/benign_alexa.json 2>/dev/null
```

### Step 3: train v3 (1–2 h estimated — run under nohup)

```bash
nohup env DNS_DETECT_MODELS_DIR=runs/v3 ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json \
            data/processed/labeled_benign.json \
            data/external/cic/cic_benign_train.json \
            data/external/tu2023/tunnels_*.json \
            data/external/tu2023/benign_alexa.json > logs/train_v3.log 2>&1 &
tail -f logs/train_v3.log
```

When done:

```bash
cp data/processed/merged_features_labeled.json runs/v3/merged_labeled.json
```

**Checks in the log:**

| Line | Expected |
|---|---|
| `[8/12] Labeled ... (families: ...)` | all 8 tools; ~100000 attack / ~118334 benign (4 benign rows are dropped by labeling, as in every run) |
| `[9/12] Split:` | `extended ... (train/val only, test frozen)` |
| `[12/12] Fusion trained` | present |

**Do not run `git checkout data/processed/` yet** — the leave-one-tool-out test (step 5.3) reads `merged_features_labeled.json`.

---

## 5. Evaluating v3

### 5.1 Frozen test set, all runs side by side

```bash
python3 - runs/baseline runs/v_* runs/v3 <<'EOF'
import json, os, sys
runs = [r for r in sys.argv[1:] if os.path.isfile(f"{r}/evaluation_metrics.json")]
print(f"{'run':18} {'A recall':>9} {'A fpr':>8} {'A PR-AUC':>9} {'B recall':>9} {'B fpr':>8} {'fus recall':>11} {'fus FA':>7} {'OR FA':>6}")
for r in runs:
    m = json.load(open(f"{r}/evaluation_metrics.json"))
    a, b = m.get("path_a") or {}, m.get("path_b") or {}
    t = (m.get("fusion") or {}).get("test") or {}
    lr, orr = t.get("learned_lr") or {}, t.get("or_rule") or {}
    f = lambda v: "-" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v))
    print(f"{os.path.basename(r):18} {f(a.get('recall')):>9} {f(a.get('fpr')):>8} {f(a.get('pr_auc')):>9} "
          f"{f(b.get('recall')):>9} {f(b.get('fpr')):>8} {f(lr.get('recall')):>11} "
          f"{f(lr.get('false_alarms')):>7} {f(orr.get('false_alarms')):>6}")
EOF
```

v3 wins if fusion recall stays 1.0 and fusion false alarms ≤ 23 (baseline). **Watch Path B especially** — with 110K new benign rows it should finally drop below its 105–113 plateau.

### 5.2 Unseen benign (two tests now)

```bash
# CIC capture 3 (25,222 queries, budget 0.1% ≈ 25)
DNS_DETECT_MODELS_DIR=runs/v3 python3 -m dns_detect.models.path_a \
    --infer data/external/cic/cic_benign_test.json 2>/dev/null | tail -4
git checkout cic_benign_test_model_results.csv

# Reserve test: one Tu daily capture was never trained on — a second, much larger unseen-benign set.
# (Build a daily-only JSON from the base_benign_dataset pcaps if desired; benign_tu2023.json also
# contains ALEXA rows, which ARE in training, so do not use that file as-is for this test.)
```

### 5.3 Leave-one-tool-out (before `git checkout data/processed/`)

```bash
python3 scripts/run_cv.py --labeled data/processed/merged_features_labeled.json --strategies lofo \
    --splits-dir runs/v3/cv_splits --out runs/v3/cv_lofo.json
git checkout data/processed/
```

### 5.4 Multi-seed check (is a difference real or chance?)

Moved here from Week 4 (NEXT_TASKS_PER_TOOL.md, Task E), extended with v3.

**Run this after 5.3.** Step 5.4.1 ends with `git checkout data/processed/`, which would delete the file that the leave-one-tool-out test reads.

#### Why

Every result so far comes from **one training run (seed 42)**. Training has randomness: the Random Forest's random trees, the validation halves used for calibration, and the autoencoder's starting weights. Training again with another seed gives slightly different false alarms. With only about 1,168 benign rows in the frozen test set, a few alarms either way can come from that randomness alone.

| Comparison | Seed 42 | Counting noise alone (95% range) | Verdict without more seeds |
|---|---|---|---|
| baseline vs v_dnsshell | 23 vs 7 | 15–35 vs 3–14 | probably real |
| baseline vs v_det | 23 vs 38 | 15–35 vs 27–52 | **unclear**: the ranges overlap |
| baseline vs v3 | 23 vs ? | | fill in after v3 finishes |

Those ranges cover only counting noise, not training randomness. The fix: train each configuration with **5 seeds** (42–46) on the **same split** and report the **mean ± standard deviation**. Only the seed changes; the data and test rows stay identical, so the spread across seeds shows exactly how much training randomness moves the result.

**Rule for the report:** a difference counts as real when the two configurations' min–max ranges across seeds do not overlap.

#### What the script does

`scripts/run_multiseed.py` trains Path A, Path B and fusion once per seed, each into its own folder (`<out-root>/seed42` … `seed46`), so `models/` and the existing runs are never touched. It prints, for every metric, the mean, standard deviation, min and max over the seeds, and saves them to `<out-root>/summary.json`.

It needs two inputs per configuration:

- `--data`: the **labeled training file** of that run (`runs/<name>/merged_labeled.json`).
- `--manifest`: the **split** of that run (`runs/<name>/split_manifest.json`).

v3 already has both (its `merged_labeled.json` is copied right after training, section 4 Step 3). The three Week 4 runs do not, so 5.4.1 rebuilds them.

#### 5.4.1 Rebuild the training files for baseline, v_dnsshell, v_det

These runs were trained before the `cp ... merged_labeled.json` line existed. Rebuild each file with the same merge and labeling steps `train_models.sh` uses. Nothing is trained; it takes seconds:

```bash
cd /home/ounnha/Documents/Capstone
export PYTHONPATH=src

mk() {   # mk <run> <input files...>
  run=$1; shift
  python3 -m dns_detect.ingest.merge --input "$@" --output runs/$run/merged_all.json 2>/dev/null
  python3 -m dns_detect.ingest.labeling --input runs/$run/merged_all.json \
      --output runs/$run/merged_labeled.json --allowlist config/dns_allowlist.txt 2>/dev/null
  python3 -c "import json; d=json.load(open('runs/$run/merged_labeled.json')); print('$run', len(d), 'rows')"
}
mk baseline   data/processed/labeled_tunnels.json data/processed/labeled_benign.json
git checkout data/processed/ 2>/dev/null; true
```

Expected: `baseline 18349 rows`, matching its `[8/12] Labeled` line.

**v_dnsshell and v_det need one extra step.** Section 4 Step 1 overwrote `tunnels_dns_shell.json` and `tunnels_det.json` with 15,000-row versions, but those runs were trained on 5,000 rows each. Rebuilt from the current files they would come out at 33349 rows instead of 23349 and not match their manifests. So recreate the 5,000-row files in a separate folder first (the `mk` function above must still be defined in the same terminal):

```bash
R=data/external/tu2023/repo/datasets/base_malicious_dataset
mkdir -p data/external/tu2023/cap5000
python3 scripts/convert_external_tunnels.py --root $R --families dns_shell det \
    --max-per-family 5000 --out-dir data/external/tu2023/cap5000 2>/dev/null

mk v_dnsshell data/processed/labeled_tunnels.json data/processed/labeled_benign.json data/external/tu2023/cap5000/tunnels_dns_shell.json
mk v_det      data/processed/labeled_tunnels.json data/processed/labeled_benign.json data/external/tu2023/cap5000/tunnels_det.json
git checkout data/processed/ 2>/dev/null; true
```

Expected: `v_dnsshell 23349 rows`, `v_det 23349 rows`. The conversion is deterministic (seed 42, same contiguous blocks), so the 5,000-row files should match the ones those runs were trained on; the `not in the manifest` check in 5.4.2 confirms it. Takes about 5 minutes (dns_shell and det only).

#### 5.4.2 Path A only, 5 seeds, all four configurations

The fusion follows Path A on this test set (RESULTS_COMPARISON.md §6.2), so Path A's spread answers the main question. `--skip-path-b` trains Path A only (no Path B, no fusion) and skips the Transformer:

```bash
for run in baseline v_dnsshell v_det v3; do
  python3 scripts/run_multiseed.py --data runs/$run/merged_labeled.json \
      --manifest runs/$run/split_manifest.json --seeds 42 43 44 45 46 \
      --out-root runs/multiseed_$run --skip-path-b 2>/dev/null | tail -8
done
```

The three Week 4 runs take minutes per seed. **v3 takes much longer** (~218K rows instead of ~20K); run it last, or on its own under `nohup` overnight:

```bash
nohup python3 scripts/run_multiseed.py --data runs/v3/merged_labeled.json \
    --manifest runs/v3/split_manifest.json --seeds 42 43 44 45 46 \
    --out-root runs/multiseed_v3 --skip-path-b > logs/multiseed_v3.log 2>&1 &
```

Each run prints a table like:

```
metric                                   mean         sd        min        max
path_a.false_alarms                   ...
path_a.fpr                            ...
path_a.pr_auc                         ...
path_a.recall                         ...
```

**Check:** `runs/multiseed_<run>/seed42/train.log` must **not** contain `row(s) are not in the manifest`. If it does, the rebuilt training file differs from the one the run was trained on (see the 5,000-row note in 5.4.1).

#### 5.4.3 Full check with Path B and fusion (optional, slow)

Only if 5.4.2 leaves a question open, or for the final report. Each seed trains Path B too. For the Week 4 runs that is 15–25 minutes per seed (1.5–2 hours per configuration); for v3, Path B alone took hours in one seed, so 5 seeds would take more than a day. Do it for a Week 4 run overnight:

```bash
nohup python3 scripts/run_multiseed.py --data runs/v_dnsshell/merged_labeled.json \
    --manifest runs/v_dnsshell/split_manifest.json --seeds 42 43 44 45 46 \
    --out-root runs/multiseed_full_v_dnsshell > logs/multiseed_v_dnsshell.log 2>&1 &
```

Then read `tail -20 logs/multiseed_v_dnsshell.log`. The fusion rows are named `fusion_learned_lr.*`.

#### 5.4.4 Read the result

Fill in [table 6.6](#66-multi-seed-check-path-a-5-seeds):

- **dns_shell helps for real** if v_dnsshell's Path A false-alarm **max** is below the baseline's **min**.
- **det hurts for real** if v_det's **min** is above the baseline's **max**.
- **v3 is better for real** if v3's **max** is below the baseline's **min**.
- **If the ranges overlap,** the difference is within training randomness. Report it as "no clear effect".

---

## 6. Results tables (fill in)

### 6.1 Training summary (`runs/v3`)

| Item | Value |
|---|---|
| `[8/12]` attack / benign / families | 100,000 / 118,334 / all 8 (cobaltstrike, det, dns2tcp, dns_shell, dnscat2, dnsexfiltrator, iodine, ozymandns) |
| `[9/12]` train / val / test | 183,203 / 32,563 / 2,568 (extended, 199,985 new rows to train/val, test frozen) |
| Path A F1 / PR-AUC | 0.9972 / 1.0 |
| Path B anomaly threshold | 0.01741 (99th percentile of benign validation error; baseline 0.04163) |
| Path B early stopping | stopped after epoch 65, best weights from epoch 55 (val_loss 0.00355) |
| Fusion recall / false alarms (vs OR rule) | 1.0 / **7** (vs 87) |
| Training time | 26,243 s (7 h 17 min) |

### 6.2 Frozen test set (2,568 rows)

| Run | Fusion recall | Fusion FA | Path A FA | Path B FA |
|---|---|---|---|---|
| baseline (10K/8.3K) | 1.0 | 23 | 23 | 112 |
| v_dnsshell | 1.0 | 7 | 7 | 113 |
| v_det | 1.0 | 38 | 36 | 105 |
| **v3 (100K/118K)** | 1.0 | **7** | **8** | 79 (recall **0.0**) |

**Path B in v3 detects nothing.** Its false alarms fell (112 → 79), but its recall fell from 1.0 to 0.0: every alarm it raises is a false one (precision 0). The autoencoder now reconstructs tunnel windows better than benign outliers. The median attack error is 0.57× the threshold, which is set at the 99th percentile of benign error. The fusion compensates by weighting Path A far more heavily (fusion weights: Path A 12.85, Path B 3.04). Path B's Isolation Forest still has recall 1.0 at 9.34% FPR.

**All attacks in the frozen test set are dnsexfiltrator.** The time-based split put the latest attack rows into the test set, so "recall 1.0" here means "catches dnsexfiltrator" in every run. Recall on the other tools comes from the unseen-tool tests (Week 4) and the leave-one-tool-out test (5.3).

### 6.3 Unseen benign

| Run | CIC capture 3 (25,222) | Rate | Within 0.1%? |
|---|---|---|---|
| baseline | 1 | 0.004% | ✅ |
| v_dnsshell | 0 | 0.000% | ✅ |
| v_det | 1 | 0.004% | ✅ |
| **v3** | **1** | **0.004%** | ✅ |

v3 recorded 2026-11-14 with `scripts/week5_eval.sh` (Path A `--infer` on `data/external/cic/cic_benign_test.json`). The 218K-row training did not raise false alarms on unseen benign traffic: v3 flags the same single query as the baseline.

### 6.4 Leave-one-tool-out (v3)

| Tool left out | Recall on it | False-alarm rate |
|---|---|---|
| dns2tcp | 1.0000 | 0.587% |
| dnsexfiltrator | 1.0000 | 0.410% |
| dns_shell | 1.0000 | 0.368% |
| det | 1.0000 | 0.401% |
| ozymandns | 1.0000 | 0.439% |
| cobaltstrike | 1.0000 | 0.444% |
| dnscat2 | 1.0000 | 0.414% |
| iodine | 1.0000 | 0.351% |
| **all 8 tools** | **mean 1.0, min 1.0** | **mean 0.427%** |

Recorded 2026-11-14 with `scripts/week5_eval.sh` (`run_cv.py --strategies lofo --lofo-feature-sets step3`, output `runs/v3/cv_lofo.json`). For each tool, a new Random Forest is trained on benign data plus the other seven tools, with the alarm threshold set at a 0.1% false-alarm rate on validation benign rows; it is scored on the left-out tool and the latest 20% of benign rows. It tests v3's training data, not the saved v3 model.

- **Recall:** every tool is caught at 100% without being in the training data, including iodine (4 misses out of 5,000 when unseen by the baseline in Week 4). The other seven tools cover each one.
- **False alarms:** 0.35–0.59%, about four times the 0.1% budget the threshold was set for on validation rows. The threshold does not hold on later benign traffic: the same validation-to-test drift as on the frozen test set. Report it as a limitation.
- **Correction to the raw output:** that run also listed `benign_cic` and `benign_tu2023` with recall 0.0 and printed a headline of mean 0.8 / min 0.0. Those two are benign sources, not tools: `run_cv.py` only excluded families named exactly `benign`. They have no attacks to recall, so they are left out above, and the headline over the 8 tools is mean 1.0 / min 1.0. `run_cv.py` now considers attack families only.

### 6.5 Conclusion (write after the tables are filled)

- Did the 12× data increase (18K → 218K rows) move the frozen-test numbers beyond the seed spread (table 6.6)?
- Did Path B finally improve with 110K extra benign rows?
- Does v3 keep recall 1.0 on the frozen test set and ~0 false alarms on CIC capture 3?
- **Decision: does `runs/v3` replace `models/`?**

### 6.6 Multi-seed check: Path A, 5 seeds

Path A false alarms on the frozen test set (about 1,168 benign rows), seeds 42–46:

| Run | Seed 42 (single run) | Mean | SD | Min | Max |
|---|---|---|---|---|---|
| baseline | 23 | | | | |
| v_dnsshell | 7 | | | | |
| v_det | 36 | | | | |
| v3 | | | | | |

Verdict (5.4.4): dns_shell helps — … · det hurts — … · v3 better than baseline — …

---

## 7. Checklist

- [x] All 6 Tu tools converted and unseen-tested (Week 4; iodine 99.92% is the headline)
- [x] Tu benign converted: 876,599 rows, truncation 0.0% on all 4 files
- [x] Benign inventory counted: 8,353 own + 41,275 CIC + 876,599 Tu
- [x] Step 1: tools reconverted at 15,000 each (domains re-checked)
- [x] Step 2: `benign_alexa.json` built (68,710 rows)
- [x] Step 3: `runs/v3` trained (log checks passed, 7 h 17 min) · `merged_labeled.json` copied
- [x] 5.1 comparison table run and copied into 6.2 (confirmed from each run's `evaluation_metrics.json`, 2026-11-14)
- [x] 5.2 CIC capture 3 false alarms recorded in 6.3 (v3: 1 / 25,222)
- [x] 5.3 leave-one-tool-out → table 6.4 (recall 1.0 on all 8 tools, false alarms 0.35–0.59%)
- [ ] 5.4.1 training files rebuilt for baseline, v_dnsshell, v_det (5,000-row dns_shell/det files recreated in `cap5000/`)
- [ ] 5.4.2 Path A multi-seed (5 seeds) for baseline, v_dnsshell, v_det, v3 → table 6.6
- [ ] 5.4.3 (optional) full multi-seed with Path B and fusion
- [ ] Conclusion 6.5 written · replace-`models/` decision made