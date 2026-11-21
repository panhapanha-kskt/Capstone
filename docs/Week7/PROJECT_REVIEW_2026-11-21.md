# Project Review and "How do I train on a new dataset?"

**DNS Traffic Anomaly Detection · full-project review · written 2026-11-21**

This document answers one question first, then reviews the whole project.

- [0. The short answer: why you feel lost](#0-the-short-answer-why-you-feel-lost)
- [1. What the project is today (map)](#1-what-the-project-is-today-map)
- [2. The training pipeline, step by step](#2-the-training-pipeline-step-by-step)
- [3. Recipes: three kinds of "new dataset"](#3-recipes-three-kinds-of-new-dataset)
- [4. What happened with DNSTunnel2026 this morning](#4-what-happened-with-dnstunnel2026-this-morning)
- [5. Review findings](#5-review-findings)
- [6. Recommended next steps, in order](#6-recommended-next-steps-in-order)

---

## 0. The short answer: why you feel lost

There are **two completely different kinds of dataset**, and your project handles them in two completely different places. Everything confusing follows from that.

| | Kind 1: raw DNS queries | Kind 2: pre-aggregated feature table |
|---|---|---|
| One row is… | **one DNS query**: domain name, timestamp, client IP, query type, response code | **one (company, domain, 5-minute window)** with 38 numbers already computed |
| Examples you have | Technitium `.log`, Kali `.pcap`, Tu 2023 pcaps, CIC pcaps, `labeled_tunnels.json`, `labeled_benign.json` | **DNSTunnel2026** `train.csv` / `test.csv` |
| Where it trains | `scripts/train_models.sh` (12 steps) → Path A + Path B + fusion | Training console → **feature-table trainer** (`dashboard/training-gui/adapters/feature_table_train.py`) |
| What comes out | the real detector: `dns_tunnel_rf.pkl`, `dns_trafficformer_iforest.pkl`, `fusion_lr.pkl` … | **one** `model.joblib` (HistGradientBoosting) |
| Can it be promoted to `models/`? | yes, through the gate | **no, never** |
| Can it score your live Technitium traffic? | yes | **no** |
| What it is for | production detection | benchmark / comparison for the report |

**Why DNSTunnel2026 can never go through `train_models.sh`:** your pipeline computes its own features *from the domain name and the timestamps* (query length, entropy, longest label, 5-minute unique-subdomain ratio, queries per minute, 20-query windows per client …). DNSTunnel2026 does not contain a single domain name, timestamp or client IP. There is nothing to compute features from. No converter can fix that — the information isn't in the file. The authors only published the processed table; the >10 GB raw logs are not distributed.

**And the good news:** your run this morning (`20261121-104605-1ae2`, console version "v3") **worked**. Exit code 0, recall 99.9 %, false-alarm rate 0.077 % at the 0.1 % budget. You already trained on the new dataset. What is left is to finish the experiment properly (§4, §6) and to understand how to present it.

So "I need to train a new dataset" splits into:

```
Is each row ONE DNS QUERY with a domain name?
├── yes → Kind 1 → scripts/train_models.sh / run_candidate_seeds.sh   (§3 case A/B)
│         result can become the live model
└── no, rows are already features → Kind 2 → training console, feature-table trainer   (§3 case C)
          result is a benchmark number for the report, not a live model
```

---

## 1. What the project is today (map)

### 1.1 Three parts and two services

```
PART A  TRAIN          PART B  GATE / PROMOTE                 PART C  DETECT
train_models.sh   →    run_candidate_seeds.sh (≥3 seeds)  →   run_pipeline.sh / soc.sh
(12 steps, into        compare_models.py + success_criteria   Technitium log → features →
runs/<name>_s<seed>)   part_b.py: gate → shadow → promote →   Path A + Path B → fusion →
                       smoke → rollback; writes models/        detection engine → dashboard
```

`scripts/soc.sh up` runs two supervised services: the **Detector** (push listener :8787 + dashboard :9000) and the **Learner** (`scripts/learner.py`), which retrains only on three triggers (new Kali captures with checksums, ≥ 50 analyst verdicts, 3 monitoring reports in a row saying retrain). Promotion stays manual unless `--auto-promote`.

### 1.2 Code (≈ 23,500 lines)

| Area | Files | Lines | Notes |
|---|---|---|---|
| `src/dns_detect/` | parsing, features, ingest, models, fusion, detection, monitoring, soc, utils | ≈ 9,000 | the package; `dns_parser.py` holds the feature lists, `path_a.py` / `path_b_train.py` / `train_fusion.py` the three learners |
| `scripts/` | 40 scripts | ≈ 7,000 | `train_models.sh` (920 lines) is the heart; `run_pipeline.sh`, `run_all.sh`, `part_b.py`, `learner.py`, `soc.sh` |
| `dashboard/` | `server.py` (3,385 lines) + 8 pages + `training-gui/` | ≈ 6,000 | SOC dashboard, triage, verdicts, training console |
| `tests/` | 38 files, **456 test functions** | — | Week 7 notes report 354 passing (ML + dashboard + console) |
| `docs/` | 60+ markdown reports, week0 → Week7 | — | the academic paper draft is `docs/week0/README_full.md` |

### 1.3 Model inputs (the feature contract)

The live pipeline's feature lists live in `src/dns_detect/parsing/dns_parser.py` and `features/aggregates.py`:

| Model | Inputs | Count |
|---|---|---|
| **Path A** (RF, + GBT only if it helps on validation) | 7 per-query: `query_length`, `query_entropy`, `has_digits`, `subdomain_count`, `longest_label`, `digit_ratio`, `unique_char_ratio` + 7 window: `uniq_subdomains_5m`, `uniq_ratio_5m`, `info_chars_per_min`, `nxdomain_share_5m`, `qpm_client_5m`, `iat_std_5m`, (`tunnel_rr_share_5m` excluded) + `bigram_logprob` | **14** |
| **Path B** (Isolation Forest on benign 20-query windows per client) | `query_length`, `query_entropy`, `subdomain_count`, `digit_ratio`, `longest_label` + the 6 active window features | **11** |
| **Fusion** (logistic regression V1) | `ml_score_A`, `ml_score_B`, `has_score_B`, `rule_hits` | 4 |

`answer_count` is dropped (always 0 in pcap-derived rows → it would encode the capture source). `client_ip`, `timestamp`, `source_file`, `attack_family` … are **forbidden** as inputs (`FORBIDDEN_FEATURES`) because on this data they separate the classes by themselves. `schema.py` checks all of this at start-up (Week 7 Task 8).

### 1.4 Data inventory

| File / folder | Kind | Rows | Label | Used by |
|---|---|---|---|---|
| `data/processed/labeled_tunnels.json` | 1 (query rows) | 10,000 | attack (dns2tcp, dnsexfiltrator; provenance) | live model |
| `data/processed/labeled_benign.json` | 1 | 8,353 | benign | live model |
| `data/external/cic/cic_benign_train.json` / `_test.json` | 1 | 41,275 / 25,222 | benign (CIC-Bell-DNS-EXF-2021) | live model / unseen-benign test |
| `tunnels_<tool>.json` × 6 (on the Kali VM, `data/external/tu2023/`) | 1 | 15,000 each | attack (cobaltstrike, det, dns_shell, dnscat2, iodine, ozymandns) | live model |
| `benign_alexa.json` (Tu 2023, Kali VM) | 1 | 68,710 | benign | live model |
| `data/raw/*.log` | 1 (Technitium) | 4 days | unlabeled → step 8 | detection, project-default training |
| `data/processed/evasion/*.json` | 1 | — | attack variants (hex, low-entropy, slow, spread …) | evasion tests |
| `data/processed/splits/*.json` | split manifests | 5 strategies × 5 seeds | — | `prepare_split.py`, `run_cv.py` |
| **`Dataset/DNSTunnel2026/Archive/train.csv`** | **2 (feature table)** | 29,982,651 (24,908 attack) | `dnstunnel` / `safe` | feature-table trainer only |
| **`Dataset/DNSTunnel2026/Archive/test.csv`** | **2** | 7,495,663 (6,227 attack) | same | not used yet |
| `dashboard/training-gui/gui_data/datasets/train.csv` | 2 | **byte copy of the above (3.6 GB duplicated)** | | console |

Note: the live model's `training_provenance.json` lists the Tu 2023 files, which are **on the Kali VM, not on this Windows copy** (Week 7 checklist item "Copy the 7 Tu 2023 files"). `run_candidate_seeds.sh` with no `FILES=` will stop with "missing" here until they are copied.

### 1.5 Model inventory

| Location | What | Result (frozen test, 1,168 benign / 1,400 attack) |
|---|---|---|
| **`models/`** (live) | `v3_iforest`, promoted 2026-11-19, mentor-approved Path B Isolation Forest | fusion recall 1.0, **7 false alarms (0.60 %)** |
| `runs/v3_iforest/` | source of the live model | same |
| `runs/labelled_v3_iforest_s42…s61` | 20-seed study (T4) on the 2-tool bundle | 9.85 ± 5.53 false alarms, recall 1.0 |
| `runs/retrain_20261120_010558_s42…44` | first automated retrain through `part_b.py` | gate **FAIL** (FPR 0.88 % vs 0.1 %), `models/` untouched — correct behaviour |
| console `v1`, `v2` | pipeline runs on `bundle:labelled_v3` | 13 and 19 false alarms |
| **console `v3`** (`20261121-104605-1ae2`) | **feature-table model on DNSTunnel2026** | see §4 |

---

## 2. The training pipeline, step by step

`scripts/train_models.sh` accepts three input formats, all **Kind 1**:

| Input | How it is labelled |
|---|---|
| `.log` (Technitium) | unlabeled → step 8 labels it (manifest, then behaviour rules) |
| `.pcap` / `.pcapng` | `--pcap-label 0/1` or unlabeled → step 8 |
| `.json` / `.csv` of **native feature rows** | `label` 0/1 already in the row (trusted when `label_source` is `provenance` or `analyst`) |

A native row looks like this (from `labeled_tunnels.json`):

```json
{"domain": "sisaaaa…dns2tcp-key.com", "timestamp": "2019-04-24T03:46:22.757901",
 "client_ip": "198.41.0.127", "query_type": "KEY", "response_code": "unknown",
 "query_length": 194, "entropy": 4.7894, "subdomain_depth": 4, "numeric_ratio": 0.1053,
 "first_label_length": 63, "main_domain": "dns2tcp-key.com",
 "label": 1, "attack_family": "dns2tcp", "label_source": "provenance", "source_file": "dns2tcp_key_down.pcapng"}
```

The 12 steps:

| # | Step | What it does | Key file |
|---|---|---|---|
| 1–2 | which models, environment | `--retrain` skips files already in `trained_files_registry.json` (sha256); `--force-retrain` ignores it | |
| 3 | find data | `--files`, `--data-dir`, or scan `data/raw/`; `--feedback FILE` adds analyst verdicts (≥ 50) | |
| 4 | EDA #1 | labeled vs unlabeled profile, "too easy" warnings (AUC of one feature) | `features/eda_data.py` |
| 5 | pre-process | `.log` / `.pcap` → feature rows | `features/extractor.py`, `parsing/dns_parser.py` |
| 6 | merge | all sources → one file; cleaning (RFC 1035 limits, exact packet copies dropped) | `ingest/merge.py`, `ingest/cleaning.py` |
| 7 | EDA #2 | merged profile | |
| 8 | **label** | precedence: label in row → attack manifest → behaviour rules (≥ 2 votes) → left out | `ingest/labeling.py`, `config/settings.yaml: labeling` |
| 9 | **split** | one shared per-class **time-ordered 72/14/14**; test rows **frozen** by `--split-manifest`; new rows go to train/val only | `prepare_split.py`, `models/splits.py` |
| 10 | **Path A** | RF (200 trees, balanced) + HistGradientBoosting; GBT kept only if it beats RF on validation; outlier capping at train 0.1/99.9 % quantiles; isotonic calibration on half of validation, **alarm threshold on the other half at ≤ 0.1 % false alarms** | `models/path_a.py`, `models/thresholds.py` |
| 11 | **Path B** | Isolation Forest on **benign** 20-query windows per client; threshold = 99th percentile of benign validation error | `models/path_b_train.py` |
| 12 | **fusion** | logistic regression on validation rows over A score, B score, rule hits; tiers q90/q99 | `scripts/train_fusion.py` |
| end | run record | git commit, pip freeze, data sha256, split sha256, seed | `scripts/run_record.py` |

Then **Part B** (`run_candidate_seeds.sh` → `part_b.py`): train ≥ 3 seeds on the **same** split, run `compare_models.py` against `config/success_criteria.yaml` (recall ≥ 0.95 every seed; mean FPR ≤ 0.1 %; not worse than live `models/` on the same test rows; beats every rule baseline on every seed), shadow-check on current traffic, promote the median seed, smoke test, rollback on failure.

Why the gate fails today (and will keep failing): the TXT/KEY/NULL **record-type rule has 0 false alarms and 100 % recall** on the current test set, and the fusion has 7–10 false alarms. Your Week 7 notes already say it: *the data is the bottleneck, not the model.*

---

## 3. Recipes: three kinds of "new dataset"

All commands run in **WSL** from `/mnt/c/Programming-CTF/Capstone` with the venv (`source /home/Panha/dns-venv/bin/activate; export PYTHONPATH=src`).

### Case A: a new tunnel tool as pcap (Kali capture, public pcap set)

```bash
# 1. pcap → labelled native rows (one tool, one tunnel domain, contiguous blocks, max 5,000 rows)
python3 scripts/convert_external_tunnels.py --root <folder-with-one-subfolder-per-tool> \
    --out-dir data/external/<name> --families <tool>
#    or, for a single capture you recorded yourself:
python3 scripts/make_labeled_features.py --label 1 --family <tool> \
    --input data/raw/<capture>.pcapng --output data/external/<name>/tunnels_<tool>.json

# 2. check it is harder data, not more of the same (record types, one-feature AUC warnings)
python3 -m dns_detect.features.eda_data data/external/<name>/tunnels_<tool>.json

# 3. train 3 seeds on the LIVE model's data + the new file, same frozen split, then gate
RUN_NAME=v4_<tool> SEEDS="42 43 44" \
FILES="$(python3 -c 'import json;print(" ".join(f["path"] for f in json.load(open("models/training_provenance.json"))["source_files"]))') data/external/<name>/tunnels_<tool>.json" \
bash scripts/run_candidate_seeds.sh
#    → runs/v4_<tool>_s42..44, runs/v4_<tool>_gate.json, PASS/FAIL printed

# 4. only on PASS, and only when you decide:
python3 scripts/part_b.py --name v4_<tool> --seeds "42 43 44" --auto-promote
```

Your lab wrapper `scripts/train_new_data.sh` (checksums → file list → record-type rule check → EDA → 3 seeds → gate) does steps 2–3 in one command for captures listed in `data/processed/week7/SHA256SUMS`.

**Rules that matter here:** each attack capture on its **own tunnel domain** (you need ≥ 3 domains for the domain-grouped split, Task 3); never convert dns2tcp / dnsexfiltrator again (they are already in `labeled_tunnels.json` → leakage); never touch `data/processed/splits/time_seed42.json`.

### Case B: new benign traffic (Technitium log, benign pcap)

```bash
python3 scripts/make_labeled_features.py --label 0 --family benign_<source> \
    --input <files>.pcap --output data/external/<name>/benign_<source>.json
# a Technitium .log can simply be passed to --files; step 8 labels it with the behaviour rules
```

Add the file to `FILES=` exactly as in case A. Benign is what Path B learns from and what sets every threshold, so **more diverse benign (TXT/MX/SRV lookups, Windows VM in a domain) is the most valuable data you can add** — see Week 7 Task 2 B1–B3.

### Case C: a pre-aggregated feature table (DNSTunnel2026, any Kaggle-style CSV)

This is what you did this morning. It does **not** use `train_models.sh`.

**Through the console** (`python dashboard/server.py` → `/training`):
1. Put the CSV in `dashboard/training-gui/gui_data/datasets/` (a **symlink** is enough — do not copy 3.6 GB again), or upload it.
2. Choose the dataset; the console detects a feature table (numeric columns + one label column) and routes it to the feature-table trainer.
3. **Label map:** tell it which label value is attack (`dnstunnel → attack`, `safe → benign`).
4. **Evaluation dataset:** choose `test.csv`. Then the model is tested on the authors' official 7.5 M-row test split instead of a random 14 % of `train.csv`. This is the number you can compare with the paper.
5. Seed 42, then repeat with 43 and 44 (three runs, same settings) so you can report mean ± sd like everywhere else in the project.

**From the shell** (same thing, no GUI):
```bash
cd /mnt/c/Programming-CTF/Capstone
RUN_DIR=runs/dnstunnel2026_s42 \
DATASET_PATH=Dataset/DNSTunnel2026/Archive/train.csv \
PARAMS_JSON='{"seed":42,"label_map":{"dnstunnel":"attack","safe":"benign"},"eval_path":"Dataset/DNSTunnel2026/Archive/test.csv"}' \
LABEL_COLUMN=label \
python3 dashboard/training-gui/adapters/feature_table_train.py
```
(The empty folder `runs/dnstunnel2026_s42` from 03:54 this morning looks like an aborted attempt at exactly this.)

What the trainer does, so you can describe it in the report: it follows **the same standard as Path A** — per-class 72/14/14 split, outlier capping at the train 99.9 % quantile, `HistGradientBoostingClassifier` (balanced class weights, early stopping), isotonic calibration on half the validation rows, **alarm threshold on the other half at ≤ 0.1 % false alarms**, test scored once; the best-F1 threshold is reported next to it for reference. When the file does not fit in memory it keeps **all attack rows** and a random share of benign rows, weighting each kept benign row by 1/share so every metric still represents the whole file.

What it produces: `model.joblib`, `model_meta.json`, `evaluation_metrics.json`, `run_record.json`. What it is: a **benchmark of your Path A learner on a public enterprise-scale dataset**. What it is not: a Path A/B/fusion model; it cannot be promoted, cannot score Technitium logs, and is not comparable to the 7-false-alarm number of the live model (different data, different unit of analysis).

---

## 4. What happened with DNSTunnel2026 this morning

Run `20261121-104605-1ae2` (console "v3"), seed 42, log in `logs/training_20261121_10*.log` and `gui_data/runs/20261121-104605-1ae2/train.log`:

| Item | Value |
|---|---|
| Rows read | 29,982,651 (24,908 attack, 29,957,743 benign) in 106 s |
| Memory | needed ≈ 18.2 GB, budget 6.8 GB → **37.5 % of benign rows kept, weight × 2.7**; all attack rows kept |
| Split | per-class random 72/14/14 (**no timestamp column**, so no time split) |
| Model | 93 boosting rounds, 50 s |
| Alarm threshold | 0.001218 (validation false-alarm rate 0.071 % ≤ 0.10 %) |
| **Test at the 0.1 % threshold** | recall **0.9991** (3 missed of ≈ 3,487), FPR **0.077 %**, false alarms **3,220**, precision 0.52, **F1 0.68** |
| **Test at the best-F1 threshold** (reference) | **F1 0.987**, 72 false alarms |
| Budget check | FPR ≤ 0.081 % with 95 % confidence → **within the 0.1 % budget** |

How to read it:

1. **The low F1 (0.68) is not a bad model — it is the base-rate fallacy you cite (Axelsson) in action.** Benign outnumbers attack 1,200 : 1. At a 0.1 % false-alarm rate on 4.2 M benign rows you still get 3,220 false alarms against ≈ 3,500 real attacks, so precision ≈ 0.5. Report **both** operating points: the budget threshold (what a SOC would run) and the best-F1 threshold (what papers usually report, 0.987). This is a strong paragraph for the paper: the same learner reaches the 0.1 % budget on 30 M enterprise rows but still produces thousands of alarms, which is exactly why the project has a review band and analyst verdicts.
2. **One warning must be fixed before you quote these numbers.** The log says: *"FrozenEstimator does not appear to accept sample_weight … the result of the calibration is likely to be incorrect."* The isotonic calibration ignored the × 2.7 benign weights. The ranking (and so recall/FPR at a given threshold) is fine, but the calibrated probabilities and therefore the exact threshold value are off. Fix: calibrate on an unweighted sub-sample, or skip calibration for this trainer (the threshold is set on raw scores anyway). Alternatively use `eval_path=test.csv` and a smaller `test_share`, which frees memory so more benign rows fit and the weights get closer to 1.
3. **Use the official `test.csv`.** The authors published a stratified 80/20 split. Testing on it (console "Evaluation dataset", or `eval_path` above) is what makes your number comparable to the paper's XGBoost / RF / LightGBM table, and it removes the random-split caveat.
4. **Three seeds, then one page.** Write `docs/Week7/DNSTUNNEL2026_BENCHMARK.md`: dataset, what the trainer does, the two operating points with Clopper–Pearson ranges (the trainer already gives `fpr_ci95`, `recall_ci95`), the memory sampling, the calibration caveat, and the sentence "this model is compare-only; the live pipeline needs raw queries." Add a line to the README's progress table.

---

## 5. Review findings

### 5.1 What is strong (keep doing this)

- **The evaluation method is far above a typical capstone:** frozen time-ordered test split reused across runs, ≥ 3 seeds with mean ± sd, success criteria written before training, rule baselines in every table, Clopper–Pearson and domain-bootstrap ranges, run records with git commit and data hashes, leave-one-tool-out, unseen-benign check (CIC capture 3: 1 / 25,222).
- **Production safety is real:** `models/` is written only by `promote_model.sh`; gate → shadow check → promote → smoke → rollback; schema check at start-up; fail-closed bridge; lock files; promotion log. The automated retrain on 11-20 **failed the gate and left `models/` alone** — the system did what it should.
- **Honesty in the docs:** the 0.1 % target not being met, the autoencoder's recall collapsing to 0.0, and the record-type rule beating every model are all written down with evidence rather than hidden.
- **Test coverage:** 456 test functions over ML, dashboard, console, SOC supervisor and scripts.
- **Reproducibility of the data path:** converter checks snap-length truncation, keeps contiguous blocks, caps per tool, records provenance labels.

### 5.2 Known weaknesses the project already names (confirmed)

| Weakness | Evidence | Consequence |
|---|---|---|
| **One attack parent domain in the frozen test set** (all 1,400 attack test rows) | `next task.md` §1, §6.1 | every "generalises to tunnels" claim is really about one domain; the domain-grouped split (Task 3) is impossible until Task 2 captures exist |
| **Record-type rule (TXT/KEY/NULL) = perfect** on current data | `ML_IMPROVEMENT_IMPLEMENTATION_2026-11-19.md`, gate reports | the ML cannot pass the gate's "beat every rule baseline" criterion until benign data contains TXT/MX/SRV and attacks use A/CNAME |
| **0.1 % false-alarm budget not met** (0.60 % test, 0.35–0.59 % held-out tools) | `models/MODEL_CARD.md` | Task 5 operating point work is blocked on Tasks 1–3 |
| **Path B alone flags ~9–25 % of benign windows** | model card; console v2 log (25.3 %) | fusion leans almost entirely on Path A (weight 10.7 vs 3.2) |
| Benign test rows too few (1,168) to **show** a 0.1 % rate | `compare_models.py` message "needs ≥ 2,995 with no false alarms" | more benign test data is needed to even measure the target |

### 5.3 New findings from this review

1. **The project has two "v3" models with different meanings.** `runs/v3_iforest` / `models/` is the live detector; the console registry's "v3" is the DNSTunnel2026 feature-table model. Rename console versions (e.g. `ft-dnstunnel2026-s42`) or the report will confuse readers and the mentor.
2. **DNSTunnel2026 result has an unfixed calibration warning** (§4, item 2) and used a random split and 37.5 % benign sampling. Do not quote the numbers until re-run with `test.csv` and the calibration issue handled.
3. **3.6 GB duplicated:** `dashboard/training-gui/gui_data/datasets/train.csv` is a byte copy of `Dataset/DNSTunnel2026/Archive/train.csv`. Replace with a symlink (`ln -s ../../../../Dataset/DNSTunnel2026/Archive/train.csv`); the console README says symlinks work. `Dataset/` is 5.2 GB and not in `.gitignore` (only a top-level `DNSTunnel2026/` is) — check `git status` never offers to add it.
4. **The live model's training data is not on this machine.** `models/training_provenance.json` points at the Tu 2023 files on the Kali VM. Any `run_candidate_seeds.sh` here without `FILES=` stops. Copying the 7 files is an open checklist item; do it before any Windows/WSL retrain.
5. **Noisy tracked outputs:** 12 files under `data/processed/*.json` are tracked (the `!data/processed/*.json` exception) but rewritten by every pipeline run, so `git status` is always dirty (it is right now). Either move run outputs to `data/runs/<run_id>/` (your own PLAN_v2 Phase 0 proposes this) or stop tracking the ones that change on every run.
6. **Leftovers:** four `*.bak` files in `src/` (`extractor.py.bak`, `bridge.py.bak`, `path_b_train.py.bak`, `dns_parser.py.bak`); two root CSVs identical to their copies in `docs/Week5/evidence/unseen_tool/`; `cic_benign_test_model_results.csv` (6.9 MB) in the root; empty `runs/dnstunnel2026_s42`; `runs/_to_delete/`. PLAN_v2 Phase 0 lists the same cleanup and it has not happened.
7. **`config/settings.yaml` is partly stale:** `models.path_b.model_file: dns_trafficformer.h5` while the live Path B is `dns_trafficformer_iforest.pkl`; `rf_weight` / `tf_weight` belong to the legacy blend. Harmless today because the code resolves the iforest file itself, but a reader of the config gets the wrong picture.
8. **README "Current Progress" is dated 2026-11-10** and stops at the v3 comparison, while the real state (v3_iforest promoted 11-19, SOC services 11-20, DNSTunnel2026 11-21) is only in `docs/Week7/`. The README is the first thing a mentor reads.
9. **Two plans coexist:** `PLAN_v2_improvement.md` (restructure + Telegram, older) and `docs/Week7/next task.md` (current). State at the top of PLAN_v2 which parts are superseded, or move it under `docs/`.
10. **Disk:** `runs/` is 1.8 GB, mostly 20 seed folders each holding a copy of `merged_features_labeled.json`. Fine for now; archive the 20-seed study once the T4 section is final.

### 5.4 Risks for the final report

- Claiming DNSTunnel2026 as "training the system on a new dataset" would be wrong; it is a **benchmark of one learner**. Say so explicitly.
- The headline "7 false alarms, recall 1.0" is on **1,168 benign / one attack domain**. Always print it with its range (0.30–1.35 %) and the rule baseline next to it, as the Week 6 rules require.
- Only 2 analyst verdicts exist; nothing about feedback learning can be claimed yet beyond "the plumbing exists and is tested".

---

## 6. Recommended next steps, in order

| # | Step | Why first | Time |
|---|---|---|---|
| 1 | **Finish DNSTunnel2026 properly:** symlink instead of copy; re-run with `eval_path = test.csv`, seeds 42 43 44; handle the calibration warning; write `docs/Week7/DNSTUNNEL2026_BENCHMARK.md` with both operating points and ranges | you are already here; it turns a confusing run into a report section | half a day |
| 2 | **Rename console versions** so "v3" stops meaning two things | avoids a mentor question you don't want | 10 min |
| 3 | **Copy the 7 Tu 2023 files from the Kali VM** to `data/external/tu2023/` | unblocks every retrain on this machine | 30 min |
| 4 | **Back to Week 7 Task 2** (captures A3, A4, B1–B3, each attack on its own domain) via `scripts/lab_capture.sh` + `scripts/train_new_data.sh` | this is the only thing that can make the gate passable and Task 3 possible; it is **Kind 1** data, the kind the live pipeline eats | 1–2 days |
| 5 | Hygiene: delete `*.bak`, root CSVs, empty run dirs; decide on tracked `data/processed/*.json`; fix `settings.yaml` Path B file name | cheap, removes noise from every `git status` | 1 h |
| 6 | Update README progress (11-19 promotion, 11-20 SOC, 11-21 benchmark) and mark PLAN_v2 as partly superseded | first page the mentor reads | 30 min |
| 7 | Then Tasks 3 → 4 → 5 as planned in `next task.md` | | |

**One sentence to remember:** *raw queries go through `train_models.sh` and can become the live model; feature tables go through the console's feature-table trainer and become a benchmark number.* Everything else in this project follows from that split.
