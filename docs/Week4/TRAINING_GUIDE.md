# Week 4 Training Guide: Testing, Training, Running and Data

**DNS Traffic Anomaly Detection · how to test, train, compare and run the pipeline, and which data the models really use · 2026-11-07**

This guide collects the questions asked this week and their answers. It covers:

- how to test the data and the code;
- how to train Path A, Path B and the fusion, and compare two training runs;
- the two flaws found in `scripts/train_models.sh`, the research behind the fix, and what was changed;
- which parts of the CIC-Bell-DNS-EXF-2021 dataset are in the project and which are used for training;
- how to add more attack data and what Path B (the unsupervised path) learns from.

All commands are for **Kali Linux**, run from the project root (`/home/ounnha/Documents/Capstone`).

---

## Contents

1. [How the pipeline fits together](#1-how-the-pipeline-fits-together)
2. [Setup](#2-setup)
3. [Testing](#3-testing)
4. [Training both paths](#4-training-both-paths)
5. [Two flaws in train_models.sh and the fix](#5-two-flaws-in-train_modelssh-and-the-fix)
6. [Comparing training runs](#6-comparing-training-runs)
7. [Evaluation (read-only)](#7-evaluation-read-only)
8. [Running the detection pipeline](#8-running-the-detection-pipeline)
9. [What data the models are trained on](#9-what-data-the-models-are-trained-on)
10. [Adding attack data](#10-adding-attack-data)
11. [Path B and unlabeled data](#11-path-b-and-unlabeled-data)
12. [Common errors](#12-common-errors)
13. [Sources](#13-sources)

---

## 1. How the pipeline fits together

```
Raw data (.log / .pcap / labeled .json)
  → extractor → merge + cleaning → labeling → EDA
  → SPLIT: one shared, time-ordered train / val / test split
  → TRAIN: Path A (RF + GBT)      Path B (Trafficformer autoencoder, benign only)
  → TRAIN: fusion (logistic regression over A + B + rules, on the validation rows)
  → DETECT: extractor → bridge (A + B + fusion) → detection engine (rules) → monitoring
```

| Stage | Command / module | Output |
|---|---|---|
| Train (everything) | `scripts/train_models.sh` | model files and `evaluation_metrics.json` in `models/` (or `$DNS_DETECT_MODELS_DIR`) |
| Detect | `scripts/run_pipeline.sh` | `data/processed/week4_unified_alerts.json` (+ `.csv`) |
| Train + detect + retrain check | `scripts/run_all.sh` | both of the above, plus `monitoring_report.json` |

---

## 2. Setup

One-time setup:

```bash
cd /home/ounnha/Documents/Capstone
sudo apt install -y python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt pytest
```

At the start of every terminal session:

```bash
cd /home/ounnha/Documents/Capstone
source .venv/bin/activate        # skip if you use the system Python with the packages installed
export PYTHONPATH=src
```

`PYTHONPATH=src` is required for every `python3 -m dns_detect...` command. Without it Python cannot find the package (see [section 12](#12-common-errors)). The shell scripts set it themselves.

---

## 3. Testing

### 3.1 Unit tests

```bash
python3 -m pytest tests/ -q
```

201 tests: 196 from earlier weeks and 5 new ones for the shared split (`tests/test_prepare_split.py`).

### 3.2 Checking the data before training

These read the data and train nothing.

```bash
# EDA reports for labeled and unlabeled data, then stop. Nothing is marked as trained.
./scripts/train_models.sh --eda-only \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json
#   → data/processed/eda_data_report.html (+ .json), data/processed/eda_report.json

# Check where the labels came from (refuses heuristic labels)
python3 -m dns_detect.ingest.labeling --input data/processed/merged_features_labeled.json --validate
```

### 3.3 Checking that the models are not cheating

```bash
# Single-feature shortcut, duplicate leakage, leave-one-family-out, label shuffle
python3 scripts/verify_models.py

# 5 split strategies × 5 seeds, mean ± sd
python3 scripts/run_cv.py --labeled data/processed/labeled_tunnels.json data/processed/labeled_benign.json \
    --out models/cv_step3.json
```

---

## 4. Training both paths

`train_models.sh` trains Path A, Path B and the fusion in one command:

```bash
./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json
```

| Option | Why it is needed |
|---|---|
| `--force-retrain` | Models already exist. Without it the script says "nothing to do" and stops. |
| `--files ...` | Points at the labeled data. Without it the script reads only the unlabeled `.log` files in `data/raw/`. With no attack manifest they can only get heuristic labels, which the training guard refuses. |

The script prints one line per step (12 steps). Check these lines:

| Step | Expected |
|---|---|
| `[8/12] Labeled ...` | both classes present; `families:` lists every attack tool in the data |
| `[9/12] Split: ...` | `reused time_seed42.json` for the same data, or `extended ... (train/val only, test frozen)` after adding data |
| `[10/12] Path A trained (F1 ..., PR-AUC ...)` | |
| `[11/12] Path B trained (window 20, anomaly threshold ...)` | |
| `[12/12] Fusion trained (test: recall ..., false alarms ... vs OR rule ...)` | |

The full output goes to `logs/training_<time>.log`.

Other useful options:

| Option | Effect |
|---|---|
| `--path-a-only` / `--path-b-only` | Train one path. The fusion is retrained only if the other path was trained on the same split. |
| `--split-manifest FILE` | Base split to reuse or extend (default `data/processed/splits/time_seed42.json`) |
| `--new-split` | Ignore the base and make a fresh time-ordered split |
| `--seed N` | Seed for Path A, Path B and a fresh split (default 42) |
| `--n-days N` | Path B window size in queries (default 20) |
| `--verbose` | Also stream the full output to the screen |

---

## 5. Two flaws in train_models.sh and the fix

### 5.1 The two flaws

1. **No shared split.** Path A made its own random grouped split, and Path B its own time split. The fusion was trained separately (`scripts/train_fusion.py`) on the `time_seed42` split. Some of the fusion's validation rows could therefore have been in Path A's training rows.
2. **No fusion.** `train_models.sh` did not train the fusion at all, yet the detection bridge runs in production mode and stops without it.

### 5.2 What the research says

A research pass checked current practice. Every point agreed with fixing both flaws:

| Question | Finding |
|---|---|
| Must a stacking (fusion) model be fitted only on rows the base models did not train on? | **Yes.** Standard since Wolpert (1992). scikit-learn's `StackingClassifier` fits its final model on `cross_val_predict` outputs for this reason. Otherwise Path A's scores on rows it memorised look too good. The fusion then gives Path A too much weight, and the alarm threshold it picks is wrong. |
| Should all models share one saved split? | **Yes.** Kapoor & Narayanan (2023) list improper train/test separation as a main leakage type. Reproducibility checklists ask for the exact split. Without a shared split, runs and models cannot be compared. |
| Time-ordered split for security data? | **Yes.** Arp et al. (2022) name "temporal snooping" as a common pitfall. TESSERACT (Pendlebury et al., 2019) shows that random splits overstate detector scores. Google's Rules of ML #33 says the same. |
| Is fitting the fusion on one validation set acceptable? | **Yes, for a small model.** A 5-input logistic regression is stable. The weak point is the threshold: about 1,200 benign validation rows at a 0.1% false-alarm budget means the threshold rests on 1 or 2 rows. |
| What when new data is added between runs? | **Keep the old test rows frozen.** New rows go to train/val only, so test scores stay comparable. |

### 5.3 What was changed

| File | Change |
|---|---|
| `scripts/train_models.sh` | New step 9 **Split**: one time-ordered split shared by Path A, Path B and fusion, saved as `<models>/split_manifest.json`. Both paths get `--split-manifest` and `--seed`. New step 12 **Fusion**: trains the V1 fusion and its confidence tiers (and V2 when `ensemble.fusion: lr_v2`). The models folder respects `DNS_DETECT_MODELS_DIR`. New options `--split-manifest`, `--new-split`, `--seed`. The split fingerprint per path is saved in `training_metadata.json`. |
| `scripts/prepare_split.py` (new) | Builds the run's split. Reuses `time_seed42.json` when it covers every row, and extends it when there are new rows (old rows keep their split, new rows go to train/val in time order, never test). Makes a fresh time split when the base covers no row. |
| `src/dns_detect/models/splits.py` | New `prepare_training_split()` with the logic above. Fails closed if a row would land in two splits, or if train or validation has only one class. |
| `tests/test_prepare_split.py` (new) | 5 tests: fresh split is time-ordered, full base is reused unchanged, new rows never reach test, unrelated base gives a fresh split, one-class validation is refused. |
| `scripts/run_pipeline.sh` | Respects `DNS_DETECT_MODELS_DIR`, so detection can run against any run folder. |
| `README.md` | Quick Start updated. |

Path A and Path B source code is unchanged.

**Fusion rule when only one path is retrained** (`--path-a-only` / `--path-b-only`): the fusion is retrained only if the other path's recorded split fingerprint matches the current split. Otherwise it is skipped with a warning, because a fusion over mismatched paths would be invalid.

### 5.4 Known limits (not changed)

- The fusion threshold rests on few benign validation rows (5.2). A bootstrap confidence interval for the false-alarm rate is a possible next step.
- New rows never go to test. New attack tools are therefore not in the test set. Use the leave-one-tool-out test for them ([section 10](#10-adding-attack-data)).
- Each run rewrites `data/processed/merged_features_*.json` and the merge and labeling reports. `git checkout data/processed/` restores the committed versions.

---

## 6. Comparing training runs

Train each run into its own folder, so `models/` is not touched:

```bash
DNS_DETECT_MODELS_DIR=runs/baseline ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json

# next run, e.g. with the CIC benign captures 1+2 added
DNS_DETECT_MODELS_DIR=runs/v2 ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json \
            data/external/cic/cic_benign_train.json
```

Two runs are comparable when they use the **same test rows** and the **same seed**. The shared split keeps the test rows the same automatically. Check for `reused` or `extended`, not `new`, in the `[9/12] Split` line.

Compare the results:

```bash
python3 - runs/baseline runs/v2 <<'EOF'
import json, sys
runs = sys.argv[1:]
M = [json.load(open(f"{r}/evaluation_metrics.json")) for r in runs]
def rows(m):
    out = {}
    for p in ("path_a", "path_b"):
        for k in ("recall", "fpr", "false_alarms", "pr_auc"):
            out[f"{p}.{k}"] = (m.get(p) or {}).get(k)
    for meth, b in ((m.get("fusion") or {}).get("test") or {}).items():
        for k in ("recall", "fpr", "false_alarms"):
            out[f"fusion:{meth}.{k}"] = b.get(k)
    return out
R = [rows(m) for m in M]
print(f"{'metric':32}" + "".join(f"{r:>16}" for r in runs))
for k in R[0]:
    print(f"{k:32}" + "".join(f"{x[k]:>16.4f}" if isinstance(x[k], float) else f"{str(x[k]):>16}" for x in R))
EOF
```

Reference: the committed models (split `time_seed42`) score:

| | Recall | False-alarm rate | False alarms | PR-AUC |
|---|---|---|---|---|
| Path A | 1.000 | 0.0265 | 31 | 0.9936 |
| Path B | 1.000 | 0.0640 | – | 1.000 |

**Seed variation.** A difference between two runs only means something if it is larger than what a different random seed alone causes. To measure that:

```bash
python3 scripts/run_multiseed.py --data data/processed/merged_features_labeled.json \
    --manifest data/processed/splits/time_seed42.json --seeds 42 43 44 45 46 \
    --out-root runs/baseline_multiseed
```

To use a run for detection, copy its files into `models/`, or set `DNS_DETECT_MODELS_DIR=runs/<name>` before `run_pipeline.sh`.

---

## 7. Evaluation (read-only)

These write only to `outputs/` and never change models or data.

```bash
M=data/processed/splits/time_seed42.json
L=data/processed/merged_features_labeled.json

python3 scripts/eval_fusion.py --labeled $L --split-manifest $M --cache outputs/fusion_eval/scored.pkl
python3 scripts/eval_bridge.py --labeled $L --split-manifest $M --cli-ablation
python3 scripts/make_evasion_set.py && python3 scripts/make_evasion_set.py --evaluate     # evasion variants
python3 -m dns_detect.models.path_a --infer data/external/cic/cic_benign_test.json        # outside false-alarm test
```

---

## 8. Running the detection pipeline

```bash
./scripts/run_pipeline.sh                       # data/raw/*.log → features → bridge → engine → monitor
./scripts/run_pipeline.sh --detect-only --zscore 2.5
./scripts/run_all.sh --skip-train               # same flow plus the retrain check
python3 dashboard/server.py                     # live dashboard, http://127.0.0.1:8000 (--demo needs no models)
```

Outputs in `data/processed/`:

- `week3_features_all.json`
- `week3_features_with_ml.json`
- `week4_unified_alerts.json` and `.csv`
- `monitoring_report.json`

Step by step:

```bash
python3 -m dns_detect.features.extractor
python3 -m dns_detect.fusion.bridge --week3 data/processed/week3_features_all.json \
    --output data/processed/week3_features_with_ml.json --path-b-model dns_trafficformer
python3 -m dns_detect.detection.engine -i data/processed/week3_features_with_ml.json \
    -o data/processed/week4_unified_alerts.json --csv
python3 -m dns_detect.monitoring.monitor --live data/processed/week3_features_with_ml.json \
    --alerts data/processed/week4_unified_alerts.json -o data/processed/monitoring_report.json
```

The bridge runs in **production mode**: it stops with an error if the Path A model or the fusion model is missing. Add `--dev` to allow a marked fallback for demos.

`run_all.sh --with-infra --with-attack "..."` brings up Technitium + ELK in Docker, runs the lab attack tool (root, raw sockets) and records the attack window in `data/attack_manifest.csv`. That manifest is what lets new `.log` traffic be labeled from ground truth.

---

## 9. What data the models are trained on

### 9.1 The current training file

`data/processed/merged_features_labeled.json` contains only the project's own captures:

| Source file | Rows | Label |
|---|---|---|
| `benign_dns.pcap` | 8,353 | benign |
| `dns2tcp_key_down.pcapng` | 2,000 | attack (dns2tcp) |
| `dns2tcp_key_up.pcapng` | 2,000 | attack (dns2tcp) |
| `dns2tcp_txt_down.pcapng` | 2,000 | attack (dns2tcp) |
| `dns2tcp_txt_up.pcapng` | 2,000 | attack (dns2tcp) |
| `dnsexfiltrator_txt_up.pcap` | 2,000 | attack (dnsexfiltrator) |

Every row has `label_source = provenance`: the label comes from the capture it was recorded in.

To check this yourself:

```bash
python3 -c "
import json, collections
d = json.load(open('data/processed/merged_features_labeled.json'))
for k, v in collections.Counter((r['source_file'], r['label']) for r in d).most_common(): print(v, k)"
```

### 9.2 The CIC-Bell-DNS-EXF-2021 dataset

The downloaded dataset (`~/Downloads/Dataset`) and what happened to each part:

| Part | In `data/external/cic/`? | Used for training? | Why |
|---|---|---|---|
| `Benign/benign_heavy_1.pcap`, `_2.pcap` | Yes (`original/`, `*_dns.pcap`, `cic_benign_train.json`, 41,275 rows) | **Not yet** in the main models. Only the Week-4 experiment (`data/processed/week4/`, `models_week4/`) used them. | Can be added with `--files data/external/cic/cic_benign_train.json` |
| `Benign/benign_heavy_3.pcap` | Yes (`cic_benign_test.json`, 25,222 rows) | **No, on purpose** | Outside false-alarm test only: traffic the model has never seen |
| `Benign/domains_*.txt` | No | No | Not needed |
| `Attacks/heavy_*.pcap` | No | **No** | Recorded with a 96-byte packet limit: 99.2% of attack queries are cut off and the domain is missing. The model could learn "cut-off packet = attack" ([TEST_REPORT.md](../Week3/TEST_REPORT.md), line 51). |
| `*-Dataset1/*.csv` | No | No | CIC's own pre-computed features, in a different format from this pipeline's features |

To check that the copies match the downloads, run the command below. Each pair of lines should show the same hash.

```bash
sha256sum ~/Downloads/Dataset/Benign/benign_heavy_*.pcap data/external/cic/original/benign_heavy_*.pcap
```

To see the CIC attack truncation yourself (any capture above 0.01 is refused):

```bash
python3 -c "
import sys, glob; sys.path[:0] = ['src', 'scripts']
from make_labeled_features import truncation_report
for f in sorted(glob.glob('/home/ounnha/Downloads/Dataset/Attacks/*.pcap')):
    print(f.split('/')[-1], truncation_report(f))"
```

---

## 10. Adding attack data

The CIC attack captures cannot be used (9.2). There are two better sources.

### 10.1 Public captures from 8 tunnel tools (Tu et al., 2023)

The repository holds pcaps from cobaltstrike, det, dns2tcp, dns_shell, dnscat2, dnsexfiltrator, iodine and ozymandns. It has no license file and asks users to cite the paper (Tu, Liu & Sun, *Computers & Security* 132, 2023).

```bash
# 1. Download
git clone --depth 1 https://github.com/Utah1A/DNS-tunnelling-detection-by-fusing-encoding-feature-and-behavioral-feature \
    data/external/tu2023/repo

# 2. Convert to labeled records (label = attack, by provenance).
#    Only the 6 tools not already in labeled_tunnels.json (see the warning below).
python3 scripts/convert_external_tunnels.py \
    --root data/external/tu2023/repo/datasets/base_malicious_dataset \
    --out-dir data/external/tu2023 \
    --families cobaltstrike det dns_shell dnscat2 iodine ozymandns

# 3. Train
DNS_DETECT_MODELS_DIR=runs/v3 ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json \
            data/external/cic/cic_benign_train.json \
            data/external/tu2023/tunnels_*.json
```

What the converter does:

- refuses truncated captures;
- keeps only queries under each tool's tunnel domain, so background OS lookups are not labeled attack;
- caps each tool at 5,000 queries in contiguous time blocks, so no tool dominates and behaviour windows stay intact;
- writes `data/external/tu2023/tunnels_<tool>.json`.

**Check its summary.** It guesses each tool's tunnel domain as the parent domain with the most queries. If a guess looks wrong (for example `google.com`), re-run with `--domain TOOL=REAL.DOMAIN`.

> **Warning: do not convert dns2tcp and dnsexfiltrator again.** `labeled_tunnels.json` was most likely built from the same Tu captures: same file names, and 2019 timestamps. It holds 2,000 queries per capture, while the converter keeps up to 5,000 per tool. Exact duplicates are dropped during the merge, but the extra queries come from the same tunnel sessions as the frozen test rows. They would land in training next to those test rows in time, which is leakage and makes the test scores look better than they are. Hence `--families` with only the 6 new tools.

After training, the `[8/12] Labeled ... (families: ...)` line should list all 8 tools: the 2 from `labeled_tunnels.json` plus the 6 new ones.

Because new rows never go to test, the new tools are not in the test set. To measure how well the model catches a tool it never saw, run the leave-one-tool-out test. `--splits-dir` keeps it from writing into the committed `data/processed/splits/` folder:

```bash
python3 scripts/run_cv.py --labeled data/processed/merged_features_labeled.json --strategies lofo \
    --splits-dir runs/v3/cv_splits --out runs/v3/cv_lofo.json
```

### 10.2 Record your own attacks

```bash
sudo ./scripts/capture_dns.sh                 # tcpdump on port 53, full packets (-s 0)
# ... run iodine or dnscat2 against your lab domain ...
python3 scripts/make_labeled_features.py --label 1 --family iodine --domain YOUR.TUNNEL.DOMAIN \
    --input <capture>.pcap --output data/processed/labeled_iodine.json
```

Then add `data/processed/labeled_iodine.json` to `--files`. `--domain` keeps only the tunnel's queries.

---

## 11. Path B and unlabeled data

> **Question:** Path B is also unsupervised learning. How can I train it with the raw DNS dataset cloned in [section 10.1](#101-public-captures-from-8-tunnel-tools-tu-et-al-2023) (step 2)?

**Answer.** One correction first: Path B is "unsupervised" only in how the model learns. **It still needs to know which rows are benign.** The autoencoder trains on **benign windows only** (`src/dns_detect/models/path_b_train.py`, line 12). It learns what normal DNS looks like, and anything it can't reconstruct well gets flagged as an anomaly. Its threshold is the 99th percentile of the benign validation error.

That changes how the step-2 data helps:

| Data | Effect on Path B |
|---|---|
| Tu tunnel pcaps (all attack) | **Does not train Path B.** Attack windows are only used to *test* it. They do train Path A and the fusion. |
| More **benign** data (e.g. CIC benign 1+2, own captures) | **This is what improves Path B.** More examples of normal traffic means fewer false alarms. |
| Raw, unlabeled pcaps | **Harmful.** Hidden tunnel traffic would be learned as "normal", and Path B would stop flagging it. |

### 11.1 The right way: one command trains both paths

Path A uses benign and attack rows. Path B automatically takes only the benign rows from the same files:

```bash
cd /home/ounnha/Documents/Capstone
export PYTHONPATH=src

# Step 2 of section 10.1: convert the 6 new Tu tools → labeled JSON
python3 scripts/convert_external_tunnels.py \
    --root data/external/tu2023/repo/datasets/base_malicious_dataset \
    --out-dir data/external/tu2023 \
    --families cobaltstrike det dns_shell dnscat2 iodine ozymandns

# Train Path A + Path B + fusion
DNS_DETECT_MODELS_DIR=runs/v3 ./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json \
            data/external/cic/cic_benign_train.json \
            data/external/tu2023/tunnels_*.json
```

In the log (`logs/training_<time>.log`), find the Path B line:

```
train(ben=..., atk=...)  val(ben=..., atk=...)  test(ben=..., atk=...)
```

`train(ben=...)` should be much larger than in the baseline, because the CIC benign rows were added. Those are the rows Path B learns from.

### 11.2 Feeding raw pcaps directly (not recommended)

`train_models.sh` accepts raw `.pcap` files. Give it the folder and the label for the whole capture. The Tu pcaps are 100% tunnel traffic, so the whole capture is labeled attack:

```bash
./scripts/train_models.sh --force-retrain --pcap-label 1 \
    --data-dir data/external/tu2023/repo/datasets/base_malicious_dataset
```

Why this is not recommended:

1. **Wrong labels.** `--pcap-label 1` marks *every* query as attack, including the operating system's normal background lookups in those captures. `convert_external_tunnels.py` keeps only the tunnel domain's queries, so its labels are clean.
2. **Refused training.** Without `--pcap-label`, the pcaps count as unlabeled, so they're labeled by behaviour rules. The training guard then refuses those labels. `--allow-heuristic-labels` overrides the guard, but those rules wrongly flag about 6% of benign traffic, and Path B would learn from those mistakes.

### 11.3 Improving Path B: add clean benign traffic

To improve Path B specifically, add more **clean benign** traffic. You can record your own on Kali while doing normal browsing, with no attacks running:

```bash
sudo ./scripts/capture_dns.sh
python3 scripts/make_labeled_features.py --label 0 --family benign \
    --input <capture>.pcap --output data/processed/labeled_benign_kali.json
```

Then add `data/processed/labeled_benign_kali.json` to `--files`.

---

## 12. Common errors

| Error | Cause | Fix |
|---|---|---|
| `No module named 'dns_detect'` | `PYTHONPATH` not set in this terminal | `export PYTHONPATH=src` |
| `No module named 'tensorflow'` / `'sklearn'` | Wrong Python (packages not installed there) | `source .venv/bin/activate` |
| `Models already trained — nothing to do` | Models exist | Add `--force-retrain` |
| `Label provenance check failed` | Training data has heuristic labels (e.g. only `.log` files, no manifest) | Use labeled files with `--files`, or record attacks in `data/attack_manifest.csv` |
| `Path A did not save ...` | Old `train_models.sh` with `DNS_DETECT_MODELS_DIR` set | Pull the updated script, or `unset DNS_DETECT_MODELS_DIR` |
| `Fusion skipped — Path A and Path B were not trained on the same split` | One path retrained alone on a different split | Retrain both paths (`--force-retrain` without `--path-*-only`) |
| Bridge stops: fusion or Path A model missing | Production mode (`ensemble.bridge_mode`) | Train with `train_models.sh`, or pass `--dev` for demos |
| Variables gone after opening a new terminal | Shell variables last one session | Re-run the setup lines in [section 2](#2-setup) |

---

## 13. Sources

- Wolpert, D. (1992). Stacked generalization. *Neural Networks* 5:241–259. Summarised in Ting & Witten, *Issues in Stacked Generalization*: https://arxiv.org/pdf/1105.5466
- scikit-learn `StackingClassifier` documentation: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.StackingClassifier.html
- Kapoor, S. & Narayanan, A. (2023). Leakage and the reproducibility crisis in ML-based science: https://arxiv.org/abs/2207.07048
- Pineau, J. ML Reproducibility Checklist: https://www.cs.mcgill.ca/~jpineau/ReproducibilityChecklist.pdf
- Arp, D. et al. (2022). Dos and Don'ts of Machine Learning in Computer Security: https://arxiv.org/pdf/2010.09470
- Pendlebury, F. et al. (2019). TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time: https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury
- Google, Rules of Machine Learning (rule #33): https://developers.google.com/machine-learning/guides/rules-of-ml
- Tu, Liu & Sun (2023). DNS tunnelling detection by fusing encoding feature and behavioral feature. *Computers & Security* 132, doi:10.1016/j.cose.2023.103357. Data: https://github.com/Utah1A/DNS-tunnelling-detection-by-fusing-encoding-feature-and-behavioral-feature
- CIC-Bell-DNS-EXF-2021 dataset (Canadian Institute for Cybersecurity)
