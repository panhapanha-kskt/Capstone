# Training on the New Dataset: Every Step Explained

**DNS Traffic Anomaly Detection · why each command is needed when training on the Tu et al. (2023) tunnel dataset · 2026-11-07**

This document explains the step-by-step commands for training Path A, Path B and the fusion on the newly cloned dataset (`data/external/tu2023/repo`). For each step it says:

- what the command does;
- why it is needed;
- what goes wrong without it;
- what to check in the output.

All commands are for **Kali Linux**, run from `/home/ounnha/Documents/Capstone`. See [TRAINING_GUIDE.md](TRAINING_GUIDE.md) for the full guide.

> **Two corrections to the instructions given earlier**
> 1. **Convert only the 6 new tools** (`--families ...` in step 2). `dns2tcp` and `dnsexfiltrator` are already in `labeled_tunnels.json`, most likely from the same captures. Converting them again leaks test data into training ([step 2](#step-2-convert-the-tunnel-captures-attack-data)).
> 2. **Do not use `--max-per-file`** for the benign captures (step 3). It picks single queries at random, which breaks the runs of consecutive queries that Path B learns from ([step 3](#step-3-convert-the-benign-captures-helps-path-b)).

---

## Contents

- [Overview](#overview)
- [Step 1: Set up the terminal](#step-1-set-up-the-terminal)
- [Step 2: Convert the tunnel captures (attack data)](#step-2-convert-the-tunnel-captures-attack-data)
- [Step 3: Convert the benign captures (helps Path B)](#step-3-convert-the-benign-captures-helps-path-b)
- [Step 4: Train the baseline](#step-4-train-the-baseline)
- [Step 5: Train on the new dataset](#step-5-train-on-the-new-dataset)
- [Step 6: Compare the two runs](#step-6-compare-the-two-runs)
- [Step 7: Clean up](#step-7-clean-up)
- [All commands in one place](#all-commands-in-one-place)

---

## Overview

The cloned repository holds **raw packet captures** (`.pcap` / `.pcapng`). The models cannot read packets. They need one **feature record** per DNS query (query length, entropy, subdomain depth, record type and so on) with a **label** (1 = attack, 0 = benign). The steps turn captures into labeled records, train two runs, and compare them fairly.

| Step | What it produces | Why |
|---|---|---|
| 1 | a working terminal | Python must find the project code and the right packages |
| 2 | `tunnels_<tool>.json` (attack records) | Path A and the fusion learn from attack examples |
| 3 | `benign_tu2023.json` (benign records) | Path B learns "normal" only from benign examples |
| 4 | `runs/baseline/` | a "before" result to compare against |
| 5 | `runs/v3/` | the "after" result, trained with the new data |
| 6 | a comparison table | shows whether the new data helped |
| 7 | a clean working copy | training rewrites tracked files |

---

## Step 1: Set up the terminal

```bash
cd /home/ounnha/Documents/Capstone
source .venv/bin/activate 2>/dev/null
export PYTHONPATH=src
unset DNS_DETECT_MODELS_DIR
ls scripts/prepare_split.py && git diff --stat data/processed/splits/
```

| Command | Why |
|---|---|
| `cd ...` | All paths in the commands are relative to the project root. |
| `source .venv/bin/activate` | Uses the Python environment that has TensorFlow and scikit-learn. `2>/dev/null` hides the error if you use the system Python instead. |
| `export PYTHONPATH=src` | The project code lives in `src/dns_detect/`. Without this, Python says `No module named 'dns_detect'`. |
| `unset DNS_DETECT_MODELS_DIR` | Clears a run folder left over from an earlier command, so models go where each step says. |
| `ls scripts/prepare_split.py` | Confirms you pulled the new `train_models.sh` code (shared split + fusion). |
| `git diff --stat data/processed/splits/` | **Must print nothing.** `time_seed42.json` is the base split that keeps the test rows the same across runs. If it changed (for example after `run_cv.py`), runs are no longer comparable. Restore it with `git checkout data/processed/splits/`. |

---

## Step 2: Convert the tunnel captures (attack data)

```bash
rm -f data/external/tu2023/tunnels_dns2tcp.json data/external/tu2023/tunnels_dnsexfiltrator.json
python3 scripts/convert_external_tunnels.py \
    --root data/external/tu2023/repo/datasets/base_malicious_dataset \
    --out-dir data/external/tu2023 \
    --families cobaltstrike det dns_shell dnscat2 iodine ozymandns
ls -lh data/external/tu2023/tunnels_*.json
```

### What it does

For each tool folder, `convert_external_tunnels.py`:

1. **Checks every capture for truncation** and skips any where more than 1% of queries are cut off (`[skip] ... truncated`). A cut-off query has lost its domain name, the main evidence of tunneling. This is why the CIC attack captures could not be used.
2. **Finds the tunnel domain**: the parent domain with the most queries in that tool's captures, e.g. `dns2tcp-key.com`.
3. **Keeps only queries under that domain.** The captures also contain the operating system's normal lookups (updates, time sync). Those are not attacks and must not be labeled as attacks.
4. **Caps each tool at 5,000 queries**, taken in **contiguous time blocks** (`utils/sampling.sample_contiguous_blocks`). The cap stops one tool, e.g. iodine with 36 captures, from dominating. Taking whole blocks keeps consecutive queries together, which the 5-minute behaviour features and Path B's 20-query windows need.
5. **Writes `tunnels_<tool>.json`** with `label = 1`, `attack_family = <tool>` and `label_source = provenance` (the label comes from the capture's origin, not from a guess).

### Speed

The converter was rewritten to be faster, with the same output:

- each capture is read once instead of twice;
- features are computed only for the queries that are kept (at most 5,000 per tool), not for every query;
- capture files are scanned in parallel on all CPU cores but one. On a 4-core machine that is 3 cores; `--jobs N` changes it.

It prints one progress line per capture (e.g. `[ 12/57] iodine_base128/iodine128_txt_up.pcapng: 8412 queries (95s)`; the 6 new tools have 57 captures) and the total time at the end. `--legacy` runs the original code path, for comparison.

You no longer need to start one converter per tool by hand: a single command uses the cores itself. Full explanation, tests and an old-vs-new comparison: [CONVERTER_SPEEDUP.md](CONVERTER_SPEEDUP.md).

### Why `--families` lists only 6 tools

`data/processed/labeled_tunnels.json` already contains `dns2tcp` and `dnsexfiltrator`. Its file names (`dns2tcp_key_down.pcapng`, ...) and 2019 timestamps match the Tu captures, so it was most likely built from them, with 2,000 queries per capture.

Converting those two tools again would cause **leakage**:

- The merge drops exact duplicate queries, but the converter keeps up to 5,000 queries per tool, so it adds *other* queries from the **same tunnel sessions**.
- Some of the original queries are in the **frozen test set**. The new neighbouring queries go to training.
- The model would then be tested on sessions it partly trained on, and the test scores would look better than they really are.

The `rm -f` line removes those two files in case an earlier run without `--families` created them. Otherwise the `tunnels_*.json` pattern in step 5 would pick them up.

### What to check

- The printed summary lists each tool's **detected domain**. It should look like a tunnel domain, not a normal site such as `google.com`. If one is wrong, re-run with `--domain TOOL=REAL.DOMAIN`.
- `ls` shows 6 files: `tunnels_cobaltstrike.json`, `tunnels_det.json`, `tunnels_dns_shell.json`, `tunnels_dnscat2.json`, `tunnels_iodine.json`, `tunnels_ozymandns.json`.

---

## Step 3: Convert the benign captures (helps Path B)

### 3a. Check for truncation

```bash
python3 -c "
import sys, glob; sys.path[:0] = ['src', 'scripts']
from make_labeled_features import truncation_report
for f in sorted(glob.glob('data/external/tu2023/repo/datasets/base_benign_dataset/*.pcap')):
    print(f.split('/')[-1], truncation_report(f))"
```

**Why:** unlike step 2's converter, `make_labeled_features.py` does **not** check truncation itself, so it is checked by hand first. Each file's `truncated_share` must be below `0.01`.

If benign captures were cut off and attack captures were not, the model could learn "cut-off packet = benign". That has nothing to do with tunneling and fails on real traffic.

### 3b. Convert

```bash
python3 scripts/make_labeled_features.py --label 0 --family benign_tu2023 \
    --input data/external/tu2023/repo/datasets/base_benign_dataset/*.pcap \
    --output data/external/tu2023/benign_tu2023.json
```

| Part | Why |
|---|---|
| `--label 0` | Every query in these captures is normal traffic, so every row is labeled benign (provenance label). |
| `--family benign_tu2023` | Records where the rows came from, so results and error analysis can tell this benign source from the others. |
| `--input .../*.pcap` | All 4 benign captures (`ALEXA.pcap` and 3 `daily_dns_*.pcap`). Leave out any file that failed 3a. |

### Why this step matters for Path B

Path B is an autoencoder trained on **benign windows only**: it learns what normal DNS looks like and flags what it cannot reconstruct. Tunnel data does not train it at all. **More benign data is the only thing that improves Path B**: it sees more kinds of normal traffic, so it raises fewer false alarms.

### Why not `--max-per-file`

`--max-per-file N` keeps N queries per file **picked one by one at random**. The kept queries are no longer consecutive:

- Path B builds windows of 20 consecutive queries per client. After random picking, a "window" joins queries that were minutes apart.
- The 5-minute behaviour features (queries per minute, unique subdomains) are computed on gaps that did not exist.

Both would make the benign data look unlike real benign traffic. If the captures are too large, pass fewer files to `--input` rather than sampling.

---

## Step 4: Train the baseline

```bash
DNS_DETECT_MODELS_DIR=runs/baseline ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json
```

Skip it if `runs/baseline/split_manifest.json` already exists, which means a baseline was trained with the new script.

| Part | Why |
|---|---|
| Baseline at all | To know whether the new data helped, you need a "before" number trained the **same way** (same script, split and seed). Older models trained with the old script used a different split, so they cannot be compared. |
| `DNS_DETECT_MODELS_DIR=runs/baseline` | Saves every model file and `evaluation_metrics.json` into `runs/baseline/`. `models/` (the production models) is not touched. |
| `--force-retrain` | Models already exist; without this the script says "nothing to do". |
| `--files ...` (old data only) | The original training data: 10,000 attack + 8,353 benign queries. |

What `train_models.sh` does, in its 12 steps: find files → EDA → convert → merge and clean → feature EDA → label → **split** → **Path A** → **Path B** → **fusion**.

---

## Step 5: Train on the new dataset

```bash
DNS_DETECT_MODELS_DIR=runs/v3 ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json \
            data/processed/labeled_benign.json \
            data/external/cic/cic_benign_train.json \
            data/external/tu2023/tunnels_*.json \
            data/external/tu2023/benign_tu2023.json
```

### Why each file is listed

| File | Content | Why |
|---|---|---|
| `labeled_tunnels.json` | 10,000 attack queries (dns2tcp, dnsexfiltrator) | The original attack data. It must stay in: the frozen test rows come from it. |
| `labeled_benign.json` | 8,353 benign queries | The original benign data, also part of the frozen test set. |
| `cic_benign_train.json` | 41,275 benign queries (CIC captures 1+2) | More normal traffic for Path B and for Path A's false-alarm control. CIC capture 3 is left out on purpose: it is the outside test set. |
| `tunnels_*.json` | up to 6 × 5,000 attack queries | The 6 new tunnel tools from step 2. |
| `benign_tu2023.json` | benign queries from step 3 | More normal traffic. Leave this line out if you skipped step 3. |

`--files` must list **all** data, old and new. Each run starts from scratch and trains only on what is listed.

### What happens to the new rows: the split

The new step 9 builds one split that Path A, Path B and the fusion all use:

- Rows already in `time_seed42.json` keep their split, so **the test set stays exactly the same** as the baseline's.
- New rows go to **train and validation only** (earliest 85% → train, rest → validation, per file, in time order). They never go to test.

**Why:** the two runs are tested on the same rows, so the difference in scores comes from the new training data, not from a different test set.

**Why the fusion needs it:** the fusion is fitted on the validation rows. If Path A or Path B had trained on those rows, their scores there would look unrealistically good, and the fusion would learn wrong weights. A shared split guarantees neither path saw the validation rows (stacked generalization; Wolpert 1992).

### What to check

| Output line | Expected | If not |
|---|---|---|
| `[3/12] Found N new file(s)` | the number of files you passed | a path is wrong |
| `[8/12] Labeled ... (families: ...)` | all 8 tools | a tunnels file is missing |
| `[9/12] Split: extended time_seed42.json with N new rows (train/val only, test frozen)` | `extended` | `new` means the old rows were not recognised; check that `labeled_tunnels.json` and `labeled_benign.json` are listed and unchanged |
| `[11/12] Path B trained ...` | present | see the log |
| `[12/12] Fusion trained ...` | present, not "skipped" | both paths must train in the same run |

Path B takes the longest (up to 200 epochs). If it fails:

```bash
tail -40 $(ls -t logs/training_*.log | head -1)
```

In that log, the Path B line `train(ben=..., atk=...)` shows how many benign rows Path B learned from. It should be much larger than in the baseline.

---

## Step 6: Compare the two runs

```bash
python3 -c "
import json
for r in ('runs/baseline', 'runs/v3'):
    m = json.load(open(f'{r}/evaluation_metrics.json'))
    print(r)
    for p in ('path_a', 'path_b'):
        b = m.get(p) or {}
        print(f'  {p}: recall={b.get(\"recall\")}  fpr={b.get(\"fpr\")}  pr_auc={b.get(\"pr_auc\")}')
    for k, b in ((m.get('fusion') or {}).get('test') or {}).items():
        print(f'  fusion {k}: recall={b.get(\"recall\")}  false_alarms={b.get(\"false_alarms\")}')"
```

### How to read it

| Metric | Meaning | Better |
|---|---|---|
| `recall` | share of attack queries caught | higher |
| `fpr` | share of benign queries wrongly flagged (false-alarm rate) | lower |
| `false_alarms` | count of benign queries wrongly flagged | lower |
| `pr_auc` | overall ranking quality, regardless of threshold | higher |

Both runs are scored on the **same test rows**, so the numbers compare directly. Expect the clearest gain in **false alarms**: the new run saw far more normal traffic.

### Testing the new tools: leave-one-tool-out

The 6 new tools are **not** in the test set (new rows never go to test), so step 6's table cannot show how well they are caught. The leave-one-tool-out test can: it trains without one tool, then tests on that tool, once for each tool.

```bash
python3 scripts/run_cv.py --labeled data/processed/merged_features_labeled.json --strategies lofo \
    --splits-dir runs/v3/cv_splits --out runs/v3/cv_lofo.json
```

| Part | Why |
|---|---|
| `merged_features_labeled.json` | After step 5 this holds all 8 tools plus all benign data. |
| `--strategies lofo` | Only the leave-one-tool-out test (the other strategies were run before). |
| `--splits-dir runs/v3/cv_splits` | `run_cv.py` writes split files. By default they go into `data/processed/splits/` and **overwrite the committed ones**, including `time_seed42.json`. That happened before on Kali. |
| `--out runs/v3/cv_lofo.json` | Keeps the results with the run they belong to. |

This test answers the most important question for a tunnel detector: **can it catch a tool it has never seen?**

---

## Step 7: Clean up

```bash
git checkout data/processed/
```

Training rewrites tracked files in `data/processed/`: the merged and labeled data, plus the merge and labeling reports. This restores the committed versions, so `git status` stays clean and the next run starts from the same base. Your results are safe: they are in `runs/`, which this command does not touch.

---

## All commands in one place

```bash
# 1. Setup
cd /home/ounnha/Documents/Capstone
source .venv/bin/activate 2>/dev/null
export PYTHONPATH=src
unset DNS_DETECT_MODELS_DIR
git diff --stat data/processed/splits/                       # must print nothing

# 2. Attack data: the 6 new tools only
rm -f data/external/tu2023/tunnels_dns2tcp.json data/external/tu2023/tunnels_dnsexfiltrator.json
python3 scripts/convert_external_tunnels.py \
    --root data/external/tu2023/repo/datasets/base_malicious_dataset \
    --out-dir data/external/tu2023 \
    --families cobaltstrike det dns_shell dnscat2 iodine ozymandns

# 3. Benign data (after the truncation check in 3a passes)
python3 scripts/make_labeled_features.py --label 0 --family benign_tu2023 \
    --input data/external/tu2023/repo/datasets/base_benign_dataset/*.pcap \
    --output data/external/tu2023/benign_tu2023.json

# 4. Baseline
DNS_DETECT_MODELS_DIR=runs/baseline ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json

# 5. New dataset
DNS_DETECT_MODELS_DIR=runs/v3 ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json \
            data/external/cic/cic_benign_train.json \
            data/external/tu2023/tunnels_*.json \
            data/external/tu2023/benign_tu2023.json

# 6. Unseen-tool test (comparison script: see step 6)
python3 scripts/run_cv.py --labeled data/processed/merged_features_labeled.json --strategies lofo \
    --splits-dir runs/v3/cv_splits --out runs/v3/cv_lofo.json

# 7. Clean up
git checkout data/processed/
```
