# Next Tasks: Adding the New Tunnel Tools One at a Time

**DNS Traffic Anomaly Detection · task plan for training on the Tu et al. (2023) tools and comparing against the baseline · 2026-11-07**

This is the work plan for the rest of Week 4. The baseline (old data) is trained. The next job is to add the new tunnel tools **one at a time**, measure what each one changes, then train on all of them together and compare with the baseline.

Background and the reason for every option: [NEW_DATASET_TRAINING_STEPS.md](NEW_DATASET_TRAINING_STEPS.md). Converter details: [CONVERTER_SPEEDUP.md](CONVERTER_SPEEDUP.md). New results vs the old models: [RESULTS_COMPARISON.md](RESULTS_COMPARISON.md).

---

## Contents

1. [Where things stand](#1-where-things-stand)
2. [Result so far: the baseline on dns_shell (unseen tool)](#2-result-so-far-the-baseline-on-dns_shell-unseen-tool)
3. [The plan](#3-the-plan)
4. [Setup (every new terminal)](#4-setup-every-new-terminal)
5. [Task A: check the baseline's false alarms on unseen benign traffic](#5-task-a-check-the-baselines-false-alarms-on-unseen-benign-traffic)
6. [Task B: the per-tool loop (5 tools)](#6-task-b-the-per-tool-loop-5-tools)
7. [Task C: train on all new data together](#7-task-c-train-on-all-new-data-together)
8. [Task D: compare everything](#8-task-d-compare-everything)
9. [Task E: multi-seed check (is a difference real or chance?)](#9-task-e-multi-seed-check-is-a-difference-real-or-chance)
10. [Results tables (fill in)](#10-results-tables-fill-in)
11. [Checklist](#11-checklist)

---

## 1. Where things stand

| Item | Status |
|---|---|
| Code on Kali | up to date: shared split, fusion in `train_models.sh`, fast converter, `.keras` fix |
| Baseline `runs/baseline` (old data: dns2tcp, dnsexfiltrator, own benign) | **done**, 14 min |
| `dns_shell` converted (`data/external/tu2023/tunnels_dns_shell.json`) | **done** |
| Baseline tested on `dns_shell` (unseen tool) | **done**: 5000 / 5000 caught ([section 2](#2-result-so-far-the-baseline-on-dns_shell-unseen-tool)) |
| `runs/v_dnsshell` (baseline data + dns_shell) | **done**, 25 min: fusion false alarms 23 → 7 ([section 2.1](#21-result-baseline--dns_shell-runsv_dnsshell)) |
| Task A: unseen benign (CIC capture 3) | **done**: baseline 1 / 25,222 · v_dnsshell 0 / 25,222 |
| det: convert · unseen test · `runs/v_det` | **done**: 5000 / 5000 caught unseen; fusion false alarms 23 → **38** (worse) ([section 2.2](#22-result-baseline--det-runsv_det)) |
| v_det on unseen benign (CIC capture 3) | **done**: 1 / 25,222 (0.004%) — det's harm is specific to the frozen test period |
| ozymandns: convert · unseen test | **done**: domain `ozymandns-txt.com`, 5000 kept; unseen test 5000 / 5000 |
| cobaltstrike: convert · unseen test | **done**: `cobaltstrike-txt.com`, 5000 kept; unseen test 5000 / 5000 |
| dnscat2: convert · unseen test | **done**: `dnscat-aaaa.com`, 5000 kept (all AAAA); unseen test 5000 / 5000 |
| iodine: convert · unseen test | **done**: `iodine-private.com`, 5000 kept (type 65399); unseen test **4996 / 5000 (99.92%)** — first tool below 100% |
| Per-tool training runs for ozymandns/cobaltstrike/dnscat2/iodine | **skipped** (going straight to the single combined model v3) |
| Training with all new data together (`runs/v3`) | to do — next step |
| Training with all new data together | to do |

Each run (`runs/baseline`, `runs/v_<tool>`) holds a complete model set: Path A, Path B and fusion. The detection pipeline still uses `models/` (the old models) unless `DNS_DETECT_MODELS_DIR=runs/<name>` is set.

All results side by side, with interpretation: [RESULTS_COMPARISON.md](RESULTS_COMPARISON.md).

### Baseline results (`runs/baseline`)

```
[8/12] Labeled 10000 attack / 8349 benign · files 18349 (families: dns2tcp,dnsexfiltrator)
[9/12] Split: reused time_seed42.json · train 13215 / val 2566 / test 2568 → runs/baseline/split_manifest.json
[10/12] Path A trained (F1 0.9919, PR-AUC 0.9957)
[11/12] Path B trained (window 20, anomaly threshold 0.04163)
[12/12] Fusion trained (test: recall 1, false alarms 23 vs OR rule 116)
✓ Training complete in 14m 8s · models saved to runs/baseline/
```

| Model | Result on the frozen test set (2,568 rows) |
|---|---|
| Path A | F1 0.9919, PR-AUC 0.9957 |
| Path B | anomaly threshold 0.04163 |
| Fusion | recall 1.0, **23 false alarms**, vs 116 for the OR rule |

The training data has known weaknesses that the EDA reported:

- `entropy` alone separates attack from benign (AUC 0.996), so the data is too easy;
- attack and benign data were captured 683 days apart;
- 81% of rows repeat another row's exact feature vector.

So the very high scores above are expected, and they are not the real test. **Unseen tools and unseen benign traffic are.**

### dns_shell conversion

```
[*] scanning 2 capture(s) from 1 tool(s) on 2 core(s)
  [  1/2] dns_shell/dnsshell_txt_down.pcapng: 12500 queries (45s)
  [  2/2] dns_shell/dnsshell_txt_up.pcapng: 62529 queries (217s)
  dns_shell        domain=dnsshell-txt.com               75024 queries →   5000 kept  (dropped 5 other)  types={'A': 4000, 'TXT': 1000}
[*] done in 220s (fast, 3 job(s))
```

- Tunnel domain `dnsshell-txt.com`: correct.
- Only 5 background queries dropped.
- Capped at 5,000 queries.
- Mostly A queries: the heartbeats this dataset is known for.

---

## 2. Result so far: the baseline on dns_shell (unseen tool)

**Question:** does the baseline, trained only on dns2tcp and dnsexfiltrator, already catch dns_shell, a tool it has never seen?

**Command:**

```bash
DNS_DETECT_MODELS_DIR=runs/baseline python3 -m dns_detect.models.path_a \
    --infer data/external/tu2023/tunnels_dns_shell.json
```

**Output** (TensorFlow info lines and scapy module-loading errors removed):

```
[*] Loading models...
[*] Reading Week 3 features JSON: data/external/tu2023/tunnels_dns_shell.json
[*] Loaded 5000 Week 3 feature records.
[*] Path A decision: rf_only  |  threshold: 0.5000

[+] CSV saved → tunnels_dns_shell_model_results.csv
    Total analyzed : 5000
    Attack detected: 5000
    Benign         : 0
```

**What it means:**

| Line | Meaning |
|---|---|
| `Path A decision: rf_only` | Path A uses the Random Forest alone; RF + gradient boosting did not do better on validation |
| `threshold: 0.5000` | a query is flagged when its attack score reaches 0.5 |
| `Attack detected: 5000` of 5000 | **100% of an unseen tool caught** |

**Interpretation:**

- **Path A generalises to dns_shell.** It recognises tunnel traffic by how the queries look and behave, not by memorising the two training tools.
- **It is not a time shortcut.** Path A's 14 inputs contain no time features: query length, entropy, digits, subdomain count, longest label, digit ratio, unique-character ratio, unique subdomains / unique ratio / information rate / NXDOMAIN share / queries per minute / timing spread over 5 minutes, and a bigram score. So the 683-day capture gap cannot explain this result.
- **Caution 1: dns_shell is an easy tunnel.** Its queries are long, random-looking subdomains, much like the training tools. Quieter tools are a harder test.
- **Caution 2: this is only recall.** A detector that flags everything would also score 5000/5000. The other half, false alarms on unseen benign traffic, is [Task A](#5-task-a-check-the-baselines-false-alarms-on-unseen-benign-traffic).
- **Caution 3: easier than real life.** Each query here sits in a 5-minute window of pure tunnel traffic. On a real machine the tunnel runs next to normal browsing, which dilutes the behaviour features.

**Noise in the raw output.** The `ERROR: Loading module scapy.layers...` blocks (`Invalid DH parameters`) and the TensorFlow `I0000 ...` lines are harmless. Kali's scapy tries to load optional modules (Kerberos, SMB, TLS) that a crypto library rejects; DNS parsing is unaffected. Add `2>/dev/null` to hide them.

### 2.1 Result: baseline + dns_shell (`runs/v_dnsshell`)

```
[8/12] Labeled 15000 attack / 8349 benign · files 23349 (families: dns2tcp,dns_shell,dnsexfiltrator)
[9/12] Split: extended time_seed42.json with 5000 new rows (train/val only, test frozen) · train 17465 / val 3316 / test 2568
[10/12] Path A trained (F1 0.9975, PR-AUC 1)
[11/12] Path B trained (window 20, anomaly threshold 0.04145)
[12/12] Fusion trained (test: recall 1, false alarms 7 vs OR rule 113)
✓ Training complete in 24m 42s · models saved to runs/v_dnsshell/
```

| | Baseline | v_dnsshell | Change |
|---|---|---|---|
| Training data | 10,000 attack / 8,349 benign | 15,000 attack / 8,349 benign | +5,000 dns_shell |
| Test rows | 2,568 | 2,568 (frozen) | same rows |
| Train / val | 13,215 / 2,566 | 17,465 / 3,316 | +4,250 / +750 |
| Path A F1 | 0.9919 | 0.9975 | better |
| Path A PR-AUC | 0.9957 | 1.0 | better |
| Path B threshold | 0.04163 | 0.04145 | about the same |
| **Fusion false alarms** | **23** | **7** | **−70%** |
| Fusion recall | 1.0 | 1.0 | no attack missed |
| OR rule false alarms | 116 | 113 | about the same |

**Interpretation:**

- **The comparison is fair.** Both runs are scored on the same frozen 2,568 test rows, so the difference comes from the training data alone.
- **Adding dns_shell helped on the original data.** dns_shell sends mostly A queries, while the original tools sent mostly TXT and KEY. With more varied attack examples, Path A and the fusion separate attack from benign more cleanly, and fewer benign rows are flagged.
- **Path B is unchanged, as expected.** It learns only from benign traffic, and no benign data was added.
- **Caution:** the test set has about 1,169 benign rows, so 23 → 7 means about 2.0% → 0.6%. This is one training run (seed 42); part of the difference may be random. `scripts/run_multiseed.py` measures that.
- dns_shell rows are not in the test set (new rows go to train/val only). How well dns_shell is caught is the unseen-tool result above: 5000 / 5000.

**Per-method false alarms on the frozen test set** (`fusion.test` in each run's `evaluation_metrics.json`):

| Method | Old (`models/`) | Baseline | v_dnsshell |
|---|---|---|---|
| Path A | 31 | 23 | 7 |
| Path B | 71 | 112 | 113 |
| OR rule | 90 | 116 | 113 |
| Fusion | 31 | 23 | 7 |

The fusion equals Path A in every run: it relies on Path A alone. Path B got worse when retrained (71 → 112), which is why the OR rule rose.

**Task A, unseen benign traffic** (CIC capture 3, 25,222 queries): baseline **1** false alarm (0.004%), v_dnsshell **0**. Both are far inside the 0.1% budget.

### 2.2 Result: baseline + det (`runs/v_det`)

**Conversion:**

```
  [  1/1] det/det_a_up.pcapng: 38365 queries (87s)
  det              domain=det-a.com                      38365 queries →   5000 kept  (dropped 0 other)  types={'A': 5000}
[*] done in 89s (fast, 3 job(s))
```

Domain `det-a.com` is correct, with no background queries; all 5,000 kept queries are type A.

**Unseen-tool test (baseline, before training on det):**

```
    Total analyzed : 5000
    Attack detected: 5000
    Benign         : 0
```

**100% of det caught without training on it.**

**Training:**

```
[8/12] Labeled 15000 attack / 8349 benign · files 23349 (families: det,dns2tcp,dnsexfiltrator)
[9/12] Split: extended time_seed42.json with 5000 new rows (train/val only, test frozen) · train 17465 / val 3316 / test 2568
[10/12] Path A trained (F1 0.9873, PR-AUC 1)
[11/12] Path B trained (window 20, anomaly threshold 0.04301)
[12/12] Fusion trained (test: recall 1, false alarms 38 vs OR rule 119)
✓ Training complete in 20m 22s · models saved to runs/v_det/
```

| | Baseline | v_dnsshell | v_det |
|---|---|---|---|
| Path A F1 | 0.9919 | 0.9975 | 0.9873 |
| Path A PR-AUC | 0.9957 | 1.0 | 1.0 |
| **Fusion false alarms** | **23** | **7** | **38** |
| Fusion recall | 1.0 | 1.0 | 1.0 |
| OR rule false alarms | 116 | 113 | 119 |

**Interpretation:**

- **Adding det made the frozen test set worse:** 23 → 38 false alarms, the opposite of dns_shell (23 → 7), although both tools send mainly A queries and both were caught 100% unseen.
- **A likely reason, not yet verified:** det's queries may look closer to normal DNS, so training on them moves Path A's boundary toward benign traffic.
- **How to check it:**
  - compare the feature ranges of det, dns_shell and benign;
  - look at which test domains v_det flags;
  - repeat with other seeds.
- **Checked (2026-11-08): v_det on CIC capture 3 (unseen benign) = 1 / 25,222 (0.004%).** det's effect is specific to the frozen test period; on fresh benign traffic v_det stays far inside the 0.1% budget, so det remains usable for the combined model.

**Per-method false alarms of v_det on the frozen test set:** Path A 36 (FPR 3.08%), Path B 105 (8.99%), OR rule 119, fusion 38. Note the fusion (38) is slightly above Path A (36) here — the first run where the fusion does not exactly equal Path A.

See [RESULTS_COMPARISON.md](RESULTS_COMPARISON.md) §6.3.

---

## 3. The plan

```
Task A   baseline on unseen benign (CIC capture 3)           → false-alarm rate
Task B   for each of the 5 tools:
           1. convert the tool                               → tunnels_<tool>.json
           2. baseline on that tool (unseen-tool test)        → recall before training on it
           3. train baseline data + that tool → runs/v_<tool> → did adding it hurt anything?
Task C   train on ALL new data together                       → runs/v3
Task D   compare baseline vs every run, plus leave-one-tool-out on v3
```

### Why one tool at a time

- **Step 2 is the most valuable number.** Before a tool is ever trained on, the baseline's recall on it is an honest unseen-tool test, like dns_shell above. Once a tool is in the training data, that test is gone.
- **Step 3 shows each tool's effect on its own.** If a run gets worse (more false alarms on the frozen test set), you know exactly which tool caused it.

### What each comparison can and cannot show

| Measure | Shows | Does not show |
|---|---|---|
| Baseline `--infer` on a new tool (step 2) | how well the model catches a tool it never saw | false alarms |
| `runs/v_<tool>` vs `runs/baseline` on the frozen test set (step 3) | whether adding the tool hurt recall or false alarms on the original data | how well the new tool is caught (its rows are never in the test set) |
| Baseline `--infer` on CIC capture 3 (Task A) | false alarms on benign traffic never seen | recall |
| Leave-one-tool-out on v3 (Task D) | for every tool: recall when that tool was left out of training | — |

### Suggested order (smallest first)

| Tool | Captures | Expected conversion time |
|---|---|---|
| det | 1 | short |
| ozymandns | 2 | short |
| cobaltstrike | 6 | medium |
| dnscat2 | 10 | medium |
| iodine | 36 (base32, base64, base128) | longest |

Each training run takes about 15 minutes (the baseline took 14m 8s).

---

## 4. Setup (every new terminal)

```bash
cd /home/ounnha/Documents/Capstone
export PYTHONPATH=src
unset DNS_DETECT_MODELS_DIR
R=data/external/tu2023/repo/datasets/base_malicious_dataset
```

- `PYTHONPATH=src` is needed for every `python3 -m dns_detect...` command (otherwise: `No module named 'dns_detect'`). `train_models.sh` sets it itself.
- `R` must end in `base_malicious_dataset`. The tool is chosen with `--families`.

---

## 5. Task A: check the baseline's false alarms on unseen benign traffic

CIC benign capture 3 was never used in training. Every query in it is benign, so every query flagged is a false alarm.

```bash
DNS_DETECT_MODELS_DIR=runs/baseline python3 -m dns_detect.models.path_a \
    --infer data/external/cic/cic_benign_test.json 2>/dev/null
```

Read `Attack detected: N` out of 25,222. **False-alarm rate = N / 25,222.** The project's budget is 0.1%, about 25 queries.

The command also writes `cic_benign_test_model_results.csv` in the project folder, with each query's score. Sort it by `ml_score_A` to see which domains cause false alarms.

---

## 6. Task B: the per-tool loop (5 tools)

Do these three steps for each tool. The example uses `det`. Replace `TOOL=det` with `ozymandns`, `cobaltstrike`, `dnscat2` and `iodine` in turn.

```bash
TOOL=det
```

### Step 1: convert the tool

```bash
python3 scripts/convert_external_tunnels.py --root $R --families $TOOL \
    --out-dir data/external/tu2023 2>/dev/null
```

Check the summary line:

```
  det   domain=<tunnel domain>   N queries →  M kept  (dropped K other)  types={...}
```

- `domain=` must be a tunnel-looking domain, not a normal site such as `google.com`. If it is wrong, re-run with `--domain $TOOL=REAL.DOMAIN`.
- `dropped K other` should be small compared with `N`.

### Step 2: unseen-tool test with the baseline

```bash
DNS_DETECT_MODELS_DIR=runs/baseline python3 -m dns_detect.models.path_a \
    --infer data/external/tu2023/tunnels_$TOOL.json 2>/dev/null | tail -4
rm -f tunnels_${TOOL}_model_results.csv
```

Write `Attack detected / Total analyzed` into [table 10.2](#102-unseen-tool-test-baseline-before-training-on-the-tool). This must run **before** step 3; afterwards the tool is no longer unseen.

### Step 3: train baseline data + this tool

```bash
DNS_DETECT_MODELS_DIR=runs/v_$TOOL ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json \
            data/processed/labeled_benign.json \
            data/external/tu2023/tunnels_$TOOL.json
cp data/processed/merged_features_labeled.json runs/v_$TOOL/merged_labeled.json   # keep the exact training file (Task E)
git checkout data/processed/
```

Check:

| Line | Expected |
|---|---|
| `[8/12] Labeled ... (families: ...)` | `dns2tcp`, `dnsexfiltrator` and the tool |
| `[9/12] Split: extended time_seed42.json with N new rows (train/val only, test frozen)` | `extended`, not `new` |
| `[12/12] Fusion trained ...` | present |

`git checkout data/processed/` restores the tracked files each training run rewrites; the results stay in `runs/`. The `cp` line before it keeps a copy of the exact labeled training file in the run folder, so the multi-seed check (Task E) can reuse it without retraining.

### Step 4: record the run's numbers

Per-method false alarms on the frozen test set, and false alarms on unseen benign traffic (CIC capture 3):

```bash
python3 - runs/v_$TOOL <<'EOF'
import json, sys
t = (json.load(open(f"{sys.argv[1]}/evaluation_metrics.json")).get("fusion") or {}).get("test") or {}
for k in ("path_a", "path_b", "or_rule", "learned_lr"):
    b = t.get(k) or {}
    print(f"  {k:10} recall={b.get('recall')}  fpr={b.get('fpr')}  false_alarms={b.get('false_alarms')}")
EOF
DNS_DETECT_MODELS_DIR=runs/v_$TOOL python3 -m dns_detect.models.path_a \
    --infer data/external/cic/cic_benign_test.json 2>/dev/null | tail -3
git checkout cic_benign_test_model_results.csv      # --infer overwrote this committed file
rm -f tunnels_*_model_results.csv
```

Add the numbers to tables 10.1 and 10.3, and to [RESULTS_COMPARISON.md](RESULTS_COMPARISON.md).

To watch Path B (step 11, the slowest), use a second terminal:

```bash
tail -f $(ls -t logs/training_*.log | head -1)
```

dns_shell is already done: steps 1–3, run folder `runs/v_dnsshell` ([section 2.1](#21-result-baseline--dns_shell-runsv_dnsshell)).

---

## 7. Task C: train on all new data together

After all 6 tools are converted.

### C1. Benign captures from the Tu repository (optional; helps Path B)

Truncation check first: each file's `truncated_share` must be below 0.01.

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

Leave out any file that fails the check. Do not use `--max-per-file`: it samples single queries at random and breaks Path B's windows.

### C2. Train

```bash
ls data/external/tu2023/tunnels_*.json      # must list exactly the 6 new tools (no dns2tcp / dnsexfiltrator)

DNS_DETECT_MODELS_DIR=runs/v3 ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json \
            data/processed/labeled_benign.json \
            data/external/cic/cic_benign_train.json \
            data/external/tu2023/tunnels_*.json \
            data/external/tu2023/benign_tu2023.json
```

Leave out the last line if C1 was skipped. Check for `families:` with all 8 tools, `Split: extended`, and `Fusion trained`.

**Keep `git checkout data/processed/` until after Task D.** The leave-one-tool-out test reads `data/processed/merged_features_labeled.json`, which this run just wrote.

---

## 8. Task D: compare everything

### D1. All runs on the frozen test set

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

Copy the output into [table 10.3](#103-frozen-test-set-every-run-vs-baseline).

**How to read it:**

| Column | Meaning | Good |
|---|---|---|
| `A recall`, `B recall`, `fus recall` | share of test attacks caught | stays at or near 1.0 |
| `A fpr`, `B fpr` | share of test benign rows wrongly flagged | lower |
| `fus FA` | fusion false alarms (baseline: 23) | lower or equal |
| `OR FA` | OR-rule false alarms (baseline: 116), for reference | — |

Every run is scored on the same 2,568 test rows, so differences come only from the training data.

### D2. False alarms of v3 on unseen benign traffic

```bash
DNS_DETECT_MODELS_DIR=runs/v3 python3 -m dns_detect.models.path_a \
    --infer data/external/cic/cic_benign_test.json 2>/dev/null | tail -4
```

Compare with Task A. More benign training data should lower the count.

### D3. Leave-one-tool-out on v3

Right after Task C, before `git checkout data/processed/`:

```bash
python3 scripts/run_cv.py --labeled data/processed/merged_features_labeled.json --strategies lofo \
    --splits-dir runs/v3/cv_splits --out runs/v3/cv_lofo.json
git checkout data/processed/
```

For every tool, this trains without it, then measures recall on it and false alarms on held-out benign data. `--splits-dir` keeps it from overwriting the committed split files in `data/processed/splits/`.

---

## 9. Task E: multi-seed check (is a difference real or chance?)

### Why

Every result so far comes from **one training run (seed 42)**. Training has randomness: the Random Forest's random trees, the validation halves used for calibration, and the autoencoder's starting weights. Training again with another seed gives slightly different false alarms. With only about 1,168 benign test rows, a few alarms either way can come from that randomness alone.

| Comparison | Seed 42 | Counting noise alone (95% range) | Verdict without more seeds |
|---|---|---|---|
| baseline vs v_dnsshell | 23 vs 7 | 15–35 vs 3–14 | probably real |
| baseline vs v_det | 23 vs 38 | 15–35 vs 27–52 | **unclear**: the ranges overlap |

Those ranges cover only counting noise, not training randomness, so even "probably real" needs checking. The fix: train each configuration with **5 seeds** (42–46) on the **same split** and report the **mean ± standard deviation**. Only the seed changes; the data and test rows stay identical. So the spread across seeds shows exactly how much training randomness moves the result.

**Rule for the report:** a difference counts as real when it is clearly larger than the spread across seeds, e.g. when the two configurations' min–max ranges don't overlap.

### What the script does

`scripts/run_multiseed.py` trains Path A, Path B and fusion once per seed, each into its own folder (`<out-root>/seed42` … `seed46`), so `models/` and your runs are never touched. It then prints, for every metric, the mean, standard deviation, min and max over the seeds, and saves them to `<out-root>/summary.json`.

It needs two inputs per configuration:

- `--data`: the **labeled training file** of that run.
- `--manifest`: the **split** of that run (`runs/<name>/split_manifest.json`).

### E1. Recreate the labeled training file for runs already done

Runs trained before the `cp` line was added to step 3 (baseline, v_dnsshell, v_det) have no saved training file. Rebuild it with the same merge and labeling steps `train_models.sh` uses. Nothing is trained, and it takes seconds:

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
mk v_dnsshell data/processed/labeled_tunnels.json data/processed/labeled_benign.json data/external/tu2023/tunnels_dns_shell.json
mk v_det      data/processed/labeled_tunnels.json data/processed/labeled_benign.json data/external/tu2023/tunnels_det.json
git checkout data/processed/ 2>/dev/null; true
```

Expected: `baseline 18349 rows`, `v_dnsshell 23349 rows`, `v_det 23349 rows`, the same counts as each run's `[8/12] Labeled` line.

### E2. Path A only, 5 seeds (fast: minutes per seed)

The fusion follows Path A on this test set (RESULTS_COMPARISON.md §6.2), so Path A's spread answers the main question. `--skip-path-b` trains Path A only (no Path B, no fusion) and skips the Transformer baseline:

```bash
for run in baseline v_dnsshell v_det; do
  python3 scripts/run_multiseed.py --data runs/$run/merged_labeled.json \
      --manifest runs/$run/split_manifest.json --seeds 42 43 44 45 46 \
      --out-root runs/multiseed_$run --skip-path-b 2>/dev/null | tail -8
done
```

Each run prints a table like:

```
metric                                   mean         sd        min        max
path_a.false_alarms                   ...
path_a.fpr                            ...
path_a.pr_auc                         ...
path_a.recall                         ...
```

**Check:** `runs/multiseed_<run>/seed42/train.log` must **not** contain `row(s) are not in the manifest`. If it does, the rebuilt training file differs from the original. Paste the message.

### E3. Full check with Path B and fusion (optional, slow)

Only if E2 leaves a question open, or for the final report. Each seed trains Path B too, about 15–25 minutes, so 5 seeds take 1.5–2 hours **per configuration**. Run it overnight:

```bash
nohup python3 scripts/run_multiseed.py --data runs/v_dnsshell/merged_labeled.json \
    --manifest runs/v_dnsshell/split_manifest.json --seeds 42 43 44 45 46 \
    --out-root runs/multiseed_full_v_dnsshell > logs/multiseed_v_dnsshell.log 2>&1 &
```

Then read `tail -20 logs/multiseed_v_dnsshell.log`. The fusion rows are named `fusion_learned_lr.*`.

### E4. Read the result

Fill in [table 10.6](#106-multi-seed-check-path-a-5-seeds):

- **dns_shell helps for real** if v_dnsshell's Path A false-alarm **max** is below the baseline's **min**.
- **det hurts for real** if v_det's **min** is above the baseline's **max**.
- **If the ranges overlap,** the difference is within training randomness. Report it as "no clear effect".

---

## 10. Results tables (fill in)

### 10.1 False alarms on unseen benign traffic (CIC capture 3, 25,222 queries)

| Run | Attack detected (= false alarms) | Rate | Within 0.1%? |
|---|---|---|---|
| baseline | 1 | 0.004% | ✅ |
| v_dnsshell | 0 | 0.000% | ✅ |
| v_det | 1 | 0.004% | ✅ |
| v3 | | | |

### 10.2 Unseen-tool test (baseline, before training on the tool)

| Tool | Domain | Queries kept | Detected | Recall |
|---|---|---|---|---|
| dns_shell | dnsshell-txt.com | 5,000 | **5,000** | **100%** |
| det | det-a.com | 5,000 | **5,000** | **100%** |
| ozymandns | ozymandns-txt.com | 5,000 | **5,000** | **100%** |
| cobaltstrike | cobaltstrike-txt.com | 5,000 | **5,000** | **100%** |
| dnscat2 | dnscat-aaaa.com | 5,000 | **5,000** | **100%** |
| iodine | iodine-private.com | 5,000 | **4,996** | **99.92%** |

### 10.3 Frozen test set: every run vs baseline

| Run | Path A recall | Path A FPR | Path A PR-AUC | Path B recall | Path B FPR | Fusion recall | Fusion false alarms |
|---|---|---|---|---|---|---|---|
| baseline | 1.0 | 1.97% (23) | 0.9957 | 1.0 | 9.59% (112) | 1.0 | 23 |
| v_dnsshell | 1.0 | 0.60% (7) | 1.0 | 1.0 | 9.67% (113) | 1.0 | 7 |
| v_det | 1.0 | 3.08% (36) | 1.0 | 1.0 | 8.99% (105) | 1.0 | 38 |
| v_ozymandns | | | | | | | |
| v_cobaltstrike | | | | | | | |
| v_dnscat2 | | | | | | | |
| v_iodine | | | | | | | |
| v3 (all) | | | | | | | |

### 10.4 Leave-one-tool-out (v3)

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

### 10.5 Conclusion (write after the tables are filled)

- Which tools did the baseline already catch without training on them, and which did it miss?
- Did adding any tool raise false alarms on the frozen test set, and is that larger than the seed spread (10.6)?
- Did v3 lower false alarms on unseen benign traffic?
- Should `runs/v3` replace `models/`?

### 10.6 Multi-seed check: Path A, 5 seeds

Path A false alarms on the frozen test set (about 1,168 benign rows), seeds 42–46:

| Run | Seed 42 (single run) | Mean | SD | Min | Max |
|---|---|---|---|---|---|
| baseline | 23 | | | | |
| v_dnsshell | 7 | | | | |
| v_det | 38 | | | | |

Verdict (E4): dns_shell helps — … · det hurts — …

---

## 11. Checklist

- [x] Baseline trained (`runs/baseline`)
- [x] dns_shell converted
- [x] dns_shell unseen-tool test: 5000 / 5000
- [x] Task A: baseline false alarms on CIC capture 3: 1 / 25,222 (v_dnsshell: 0)
- [x] dns_shell step 3 (`runs/v_dnsshell`): fusion false alarms 23 → 7
- [x] det: convert · unseen test (5000 / 5000) · train (fusion false alarms 38)
- [x] det: per-method false alarms (Path A 36 · Path B 105 · fusion 38) + CIC capture 3 check for `runs/v_det`: 1 / 25,222
- [x] ozymandns: convert (`ozymandns-txt.com`) · unseen test (5000 / 5000) · per-tool train skipped
- [x] cobaltstrike: convert (`cobaltstrike-txt.com`) · unseen test (5000 / 5000) · per-tool train skipped
- [x] dnscat2: convert (`dnscat-aaaa.com`) · unseen test (5000 / 5000) · per-tool train skipped
- [x] iodine: convert (`iodine-private.com`) · unseen test (**4996 / 5000, 99.92%**) · per-tool train skipped
- [ ] Task C: benign Tu captures (optional) and v3
- [ ] Task D: comparison table, v3 on CIC capture 3, leave-one-tool-out
- [ ] Task E1: rebuild training files for baseline, v_dnsshell, v_det
- [ ] Task E2: Path A multi-seed (5 seeds) for baseline, v_dnsshell, v_det → table 10.6
- [ ] Task E3 (optional): full multi-seed with Path B and fusion
- [ ] Results tables filled in and conclusion written
- [ ] Decide whether `runs/v3` replaces `models/`
