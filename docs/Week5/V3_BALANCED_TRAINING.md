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
| `[8/12] Labeled ... (families: ...)` | all 8 tools; ~100000 attack / ~118338 benign |
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

### 5.4 Multi-seed check (is v3's difference real?)

```bash
python3 scripts/run_multiseed.py --data runs/v3/merged_labeled.json \
    --manifest runs/v3/split_manifest.json --seeds 42 43 44 45 46 \
    --out-root runs/multiseed_v3 --skip-path-b 2>/dev/null | tail -8
```

A difference vs baseline counts as real only when the two min–max ranges across seeds do not overlap. Note: with ~218K rows even Path A-only seeds take longer than Week 4's.

---

## 6. Results tables (fill in)

### 6.1 Training summary (`runs/v3`)

| Item | Value |
|---|---|
| `[8/12]` attack / benign / families | |
| `[9/12]` train / val / test | |
| Path A F1 / PR-AUC | |
| Path B anomaly threshold | |
| Fusion recall / false alarms (vs OR rule) | |
| Training time | |

### 6.2 Frozen test set (2,568 rows)

| Run | Fusion recall | Fusion FA | Path A FA | Path B FA |
|---|---|---|---|---|
| baseline (10K/8.3K) | 1.0 | 23 | 23 | 112 |
| v_dnsshell | 1.0 | 7 | 7 | 113 |
| v_det | 1.0 | 38 | 36 | 105 |
| **v3 (100K/118K)** | | | | |

### 6.3 Unseen benign

| Run | CIC capture 3 (25,222) | Rate | Within 0.1%? |
|---|---|---|---|
| baseline | 1 | 0.004% | ✅ |
| v_dnsshell | 0 | 0.000% | ✅ |
| v_det | 1 | 0.004% | ✅ |
| **v3** | | | |

### 6.4 Leave-one-tool-out (v3)

| Tool left out | Recall on it | False-alarm rate |
|---|---|---|
| dns2tcp | | |
| dnsexfiltrator | | |
| dns_shell | | |
| det | | |
| ozymandns | | |
| cobaltstrike | | |
| dnscat2 | | |
| iodine | | |

### 6.5 Conclusion (write after the tables are filled)

- Did the 20× data increase (18K → 218K rows) move the frozen-test numbers beyond the seed spread?
- Did Path B finally improve with 110K extra benign rows?
- Does v3 keep recall 1.0 on the frozen test set and ~0 false alarms on CIC capture 3?
- **Decision: does `runs/v3` replace `models/`?**

---

## 7. Checklist

- [x] All 6 Tu tools converted and unseen-tested (Week 4; iodine 99.92% is the headline)
- [x] Tu benign converted: 876,599 rows, truncation 0.0% on all 4 files
- [x] Benign inventory counted: 8,353 own + 41,275 CIC + 876,599 Tu
- [ ] Step 1: tools reconverted at 15,000 each (domains re-checked)
- [ ] Step 2: `benign_alexa.json` built (68,710 rows)
- [ ] Step 3: `runs/v3` trained (log checks passed) · `merged_labeled.json` copied
- [ ] 5.1 comparison table run and copied into 6.2
- [ ] 5.2 CIC capture 3 false alarms recorded in 6.3
- [ ] 5.3 leave-one-tool-out → table 6.4
- [ ] 5.4 multi-seed check on v3
- [ ] Conclusion 6.5 written · replace-`models/` decision made
