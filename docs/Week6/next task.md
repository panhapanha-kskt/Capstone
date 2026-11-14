# Week 6: Next Tasks

**DNS Traffic Anomaly Detection · what is left to do, in order, with the commands · 2026-11-12, updated 2026-11-14**

Week 5 trained the combined model (`runs/v3`) but stopped before evaluating it. The Week 6 dashboard was built but not tested end to end. This file lists every open task, the exact command for each, what the output should look like, and where to write the result.

Sources: the Week 5 checklist in [V3_BALANCED_TRAINING.md](../Week5/V3_BALANCED_TRAINING.md) (section 7), the Week 5 report [WEEK5_PROGRESS_REPORT.md](../Week5/WEEK5_PROGRESS_REPORT.md) (section 9.1), and the "not yet verified" list in [WEEK6_AUDIT_AND_FORTINET_ROADMAP.md](WEEK6_AUDIT_AND_FORTINET_ROADMAP.md) (section 1.6).

---

## Contents

1. [Summary of what is open](#1-summary-of-what-is-open)
2. [Setup (every new terminal)](#2-setup-every-new-terminal)
3. [Task 0: confirm the Week 5 files still exist](#3-task-0-confirm-the-week-5-files-still-exist)
4. [Task 1: comparison table (5.1)](#4-task-1-comparison-table-51)
5. [Task 2: v3 on unseen benign traffic (5.2)](#5-task-2-v3-on-unseen-benign-traffic-52)
6. [Task 3: leave-one-tool-out (5.3)](#6-task-3-leave-one-tool-out-53)
7. [Task 4: rebuild the training files (5.4.1)](#7-task-4-rebuild-the-training-files-541)
8. [Task 5: multi-seed check (5.4.2)](#8-task-5-multi-seed-check-542)
9. [Task 6: write the conclusion and decide](#9-task-6-write-the-conclusion-and-decide)
10. [Task 7: save the evidence in git](#10-task-7-save-the-evidence-in-git)
11. [Task 8: test the Week 6 dashboard](#11-task-8-test-the-week-6-dashboard)
12. [Task 9: fix the stale documentation](#12-task-9-fix-the-stale-documentation)
13. [Task 10: Path B with Isolation Forest](#13-task-10-path-b-with-isolation-forest)
14. [Optional tasks](#14-optional-tasks)
15. [Checklist](#15-checklist)

---

## 1. Summary of what is open

| # | Task | Where the result goes | Time (estimate) | Blocks Week 5? |
|---|---|---|---|---|
| 0 | Confirm `runs/`, the Tu data and the training log exist on Kali | nowhere (a check) | 2 min | yes |
| 1 | Comparison table for all runs | V3 doc, table 6.2 | 1 min | yes |
| 2 | v3 on CIC capture 3 | V3 doc, table 6.3 | 5 min | yes |
| 3 | Leave-one-tool-out | V3 doc, table 6.4 | 15–40 min | yes |
| 4 | Rebuild training files for baseline, v_dnsshell, v_det | `runs/<name>/merged_labeled.json` | 10 min | yes |
| 5 | Multi-seed check, 5 seeds, 4 configurations | V3 doc, table 6.6 | 1–3 h (v3 is the slow one) | yes |
| 6 | Conclusion and the replace-`models/` decision | V3 doc, section 6.5 | 30 min writing | yes |
| 7 | Save the small result files in git | `docs/Week5/evidence/` | 10 min | no, but do it |
| 8 | Test the Week 6 dashboard end to end | `dashboard/docs/TESTING_REPORT.md` | 30–45 min | no (Week 6) |
| 9 | Fix stale text in the docs | several files | 20 min | no |
| 10 | Train and compare Path B with Isolation Forest | new run `runs/v3_iforest` | about 1 h | yes: do it before task 6, because it adds a second candidate model |

The time estimates are guesses, not measurements. Only Path A is trained in tasks 3 and 5, so none of them should come close to the 7 hours v3 took.

**Order matters.** Do tasks 0 to 5 in order, then task 10, then task 6. Task 5 depends on task 4. Task 6 depends on tasks 1, 2, 3, 5 and 10: its decision is now between two candidates, `runs/v3` (autoencoder Path B) and `runs/v3_iforest` (Isolation Forest Path B).

---

## 2. Setup (every new terminal)

```bash
cd /home/ounnha/Documents/Capstone
export PYTHONPATH=src
unset DNS_DETECT_MODELS_DIR
R=data/external/tu2023/repo/datasets/base_malicious_dataset
```

- `PYTHONPATH=src` is needed for every `python3 -m dns_detect...` command.
- `unset DNS_DETECT_MODELS_DIR` makes sure a leftover value from an earlier terminal does not point a command at the wrong model folder.

---

## 3. Task 0: confirm the Week 5 files still exist

Everything below reads files that are only on Kali. None of them are in git. Check them first.

```bash
ls -d runs/baseline runs/v_dnsshell runs/v_det runs/v3
ls runs/v3/evaluation_metrics.json runs/v3/split_manifest.json runs/v3/merged_labeled.json
ls data/external/tu2023/*.json
ls logs/training_20261107_220017.log
python3 -c "import json; print(len(json.load(open('runs/v3/merged_labeled.json'))))"
```

**Expected:**

- all four run folders exist;
- the three files in `runs/v3` exist;
- the row count is `218334`.

Then confirm the numbers written in the Week 5 report really are in the log:

```bash
grep -E '^\[(8|9|10|11|12)/12\]|Training complete' logs/training_20261107_220017.log
grep -E 'Autoencoder:|Isolation Forest:|fusion weights' logs/training_20261107_220017.log
```

**Expected:** the same lines as in WEEK5_PROGRESS_REPORT.md section 3.7 (100000 attack / 118334 benign, false alarms 7 vs OR rule 87, `Training complete in 26243s`).

**If something is missing:**

| Missing | What to do |
|---|---|
| `runs/v3/merged_labeled.json` | Task 3 and the v3 part of task 5 cannot run. It can only be rebuilt with the same merge and labeling steps as in task 4, using the v3 file list from V3_BALANCED_TRAINING.md section 4, Step 3. |
| `runs/baseline`, `runs/v_dnsshell` or `runs/v_det` | That configuration drops out of tasks 1 and 5. Retraining takes 15–25 minutes each (Week 4, NEXT_TASKS_PER_TOOL.md section 6). |
| the training log | The v3 numbers in the report have no source. Note that in the conclusion. |

---

## 4. Task 1: comparison table (5.1)

Prints every run's numbers on the frozen test set, from each run's `evaluation_metrics.json`.

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

**Expected** (from the Week 5 report):

| Run | Fusion recall | Fusion false alarms | OR rule false alarms |
|---|---|---|---|
| baseline | 1.0 | 23 | 116 |
| v_dnsshell | 1.0 | 7 | 113 |
| v_det | 1.0 | 38 | 119 |
| v3 | 1.0 | 7 | 87 |

**What to do with it:**

- Compare the output with table 6.2 in V3_BALANCED_TRAINING.md. The table was filled in from the log; this confirms it from the saved metrics.
- If they match, tick the 5.1 box.
- If a number differs, the saved metrics file wins. Correct the table, the report (section 3.7) and README.md.

---

## 5. Task 2: v3 on unseen benign traffic (5.2)

CIC capture 3 has 25,222 benign queries that no model was trained on. Every query flagged is a false alarm.

```bash
DNS_DETECT_MODELS_DIR=runs/v3 python3 -m dns_detect.models.path_a \
    --infer data/external/cic/cic_benign_test.json 2>/dev/null | tail -4
git checkout cic_benign_test_model_results.csv
```

The second line restores the committed CSV, which `--infer` overwrites.

**Read the output:**

```
    Total analyzed : 25222
    Attack detected: N
    Benign         : ...
```

**False-alarm rate = N / 25,222.** The budget is 0.1%, which is about 25 queries.

**Fill in** table 6.3, v3 row: `N`, the rate, and ✅ if N ≤ 25.

For reference: baseline 1, v_dnsshell 0, v_det 1.

**If N is above 25:** before `git checkout`, copy the CSV (`cp cic_benign_test_model_results.csv runs/v3/cic_test_results.csv`), then sort it by `ml_score_A` to see which domains were flagged. That goes into the conclusion as a reason not to replace `models/`.

---

## 6. Task 3: leave-one-tool-out (5.3)

**Why it matters:** the frozen test set only contains dnsexfiltrator attacks, so "recall 1.0" there says nothing about the other seven tools. This test leaves each tool out of training in turn and measures how well it is caught as an unseen tool.

```bash
python3 scripts/run_cv.py --labeled runs/v3/merged_labeled.json --strategies lofo \
    --lofo-feature-sets step3 \
    --splits-dir runs/v3/cv_splits --out runs/v3/cv_lofo.json 2>/dev/null
```

Two differences from the command in V3_BALANCED_TRAINING.md, both on purpose:

- **`--labeled runs/v3/merged_labeled.json`** reads the copy kept in the run folder instead of `data/processed/merged_features_labeled.json`. The content is the same, and it removes the risk of a `git checkout data/processed/` wiping the file first.
- **`--lofo-feature-sets step3`** runs only the feature set Path A actually uses. Without it the script compares five feature sets, which is five times the work. Drop the flag if you want the full ablation for the report.

**What it does:** for each tool, it trains a new Random Forest on benign data plus the other seven tools, sets the alarm threshold at the 0.1% false-alarm budget on validation benign rows, and scores the left-out tool plus the latest 20% of benign rows. It tests v3's **training data**, not the saved v3 model files.

**Print the table 6.4 rows:**

```bash
python3 - <<'EOF'
import json
lofo = json.load(open("runs/v3/cv_lofo.json"))["by_strategy"]["lofo"]["step3"]
for fam, b in sorted(lofo["per_family"].items()):
    if "error" in b:
        print(f"{fam:16} ERROR {b['error']}")
    else:
        print(f"{fam:16} recall={b['recall']:.4f}  fpr={b['fpr']:.4%}")
print("headline:", {k: v for k, v in lofo["headline"].items() if k != "features"})
EOF
```

**Fill in** table 6.4: one row per tool with its recall and false-alarm rate.

**How to read it:**

| Result | Meaning |
|---|---|
| recall near 1.0 for a tool | The other tools are enough to catch it. It generalises. |
| recall clearly lower for one tool | That tool is the one that needs to be in the training data. iodine is the likely candidate (it had 4 misses unseen in Week 4). |
| false-alarm rate above 0.1% | The threshold calibrated on validation benign rows did not hold on later benign rows. Note it; it's the same drift seen on the frozen test set. |

---

## 7. Task 4: rebuild the training files (5.4.1)

The multi-seed check needs each run's exact labeled training file. v3 has one. The three Week 4 runs were trained before that copy step existed, so their files have to be rebuilt. Nothing is trained here.

### 7.1 Baseline

```bash
mk() {   # mk <run> <input files...>
  run=$1; shift
  python3 -m dns_detect.ingest.merge --input "$@" --output runs/$run/merged_all.json 2>/dev/null
  python3 -m dns_detect.ingest.labeling --input runs/$run/merged_all.json \
      --output runs/$run/merged_labeled.json --allowlist config/dns_allowlist.txt 2>/dev/null
  python3 -c "import json; d=json.load(open('runs/$run/merged_labeled.json')); print('$run', len(d), 'rows')"
}
mk baseline data/processed/labeled_tunnels.json data/processed/labeled_benign.json
```

**Expected:** `baseline 18349 rows`.

### 7.2 Recreate the 5,000-row dns_shell and det files

v_dnsshell and v_det were trained on 5,000 rows per tool. Week 5 overwrote those files with 15,000-row versions, so the 5,000-row versions go into a separate folder:

```bash
mkdir -p data/external/tu2023/cap5000
python3 scripts/convert_external_tunnels.py --root $R --families dns_shell det \
    --max-per-family 5000 --out-dir data/external/tu2023/cap5000 2>/dev/null
```

**Expected:** `dnsshell-txt.com ... 5000 kept ... types={'A': 4000, 'TXT': 1000}` and `det-a.com ... 5000 kept ... types={'A': 5000}`. These must match the Week 4 conversion lines. About 5 minutes.

### 7.3 v_dnsshell and v_det

Run in the **same terminal** as 7.1, so `mk` is still defined:

```bash
mk v_dnsshell data/processed/labeled_tunnels.json data/processed/labeled_benign.json data/external/tu2023/cap5000/tunnels_dns_shell.json
mk v_det      data/processed/labeled_tunnels.json data/processed/labeled_benign.json data/external/tu2023/cap5000/tunnels_det.json
```

**Expected:** `v_dnsshell 23349 rows` and `v_det 23349 rows`.

**If a count is wrong:**

| You see | Cause |
|---|---|
| `33349 rows` | The 15,000-row file was used. Check the path contains `cap5000/`. |
| `mk: command not found` | New terminal. Paste the `mk` function from 7.1 again. |

---

## 8. Task 5: multi-seed check (5.4.2)

**Why:** every result so far is one training run with seed 42. With about 1,168 benign rows in the frozen test set, a few false alarms either way can be chance. Training each configuration with 5 seeds on the same split shows how much the number moves from randomness alone.

### 8.1 The three small runs

```bash
for run in baseline v_dnsshell v_det; do
  python3 scripts/run_multiseed.py --data runs/$run/merged_labeled.json \
      --manifest runs/$run/split_manifest.json --seeds 42 43 44 45 46 \
      --out-root runs/multiseed_$run --skip-path-b 2>/dev/null | tail -8
done
```

`--skip-path-b` trains Path A only, which takes minutes per seed.

### 8.2 v3 (slow, run it in the background)

```bash
nohup python3 scripts/run_multiseed.py --data runs/v3/merged_labeled.json \
    --manifest runs/v3/split_manifest.json --seeds 42 43 44 45 46 \
    --out-root runs/multiseed_v3 --skip-path-b > logs/multiseed_v3.log 2>&1 &
sleep 5; tail -f logs/multiseed_v3.log
```

Path A on v3 took part of the 36 minutes before Path B started in the original run, so expect roughly 20–40 minutes per seed. That is an estimate.

### 8.3 Two checks before trusting the numbers

**Check 1: the rebuilt files match the splits.** This must print nothing:

```bash
grep -l "not in the manifest" runs/multiseed_*/seed42/train.log
```

If it prints a file name, that run's rebuilt training file differs from the one it was originally trained on. Go back to task 4 for that run.

**Check 2: seed 42 reproduces the original run.** The multi-seed script trains Path A with `--no-transformer`; the original `train_models.sh` run did not. That should not change the Random Forest, but confirm it:

```bash
python3 - <<'EOF'
import json
want = {"baseline": 23, "v_dnsshell": 7, "v_det": 36, "v3": 8}
for run, w in want.items():
    try:
        s = json.load(open(f"runs/multiseed_{run}/summary.json"))
    except OSError:
        print(f"{run:12} no summary.json yet"); continue
    got = s["per_seed"]["42"].get("path_a.false_alarms")
    print(f"{run:12} seed 42 false alarms = {got}   original run = {w}   {'OK' if got == w else 'DIFFERENT'}")
EOF
```

If a run prints `DIFFERENT`, write both numbers down and say so in the conclusion. The comparison between configurations is still fair, because all four were produced the same way.

### 8.4 Print table 6.6

```bash
python3 - <<'EOF'
import json
print(f"{'run':12} {'mean':>7} {'sd':>7} {'min':>5} {'max':>5}")
for run in ("baseline", "v_dnsshell", "v_det", "v3"):
    try:
        s = json.load(open(f"runs/multiseed_{run}/summary.json"))["summary"]["path_a.false_alarms"]
    except (OSError, KeyError):
        print(f"{run:12} not available"); continue
    print(f"{run:12} {s['mean']:7.1f} {s['sd']:7.2f} {s['min']:5.0f} {s['max']:5.0f}")
EOF
```

**Fill in** table 6.6 in V3_BALANCED_TRAINING.md.

### 8.5 Read the result

The rule from the Week 5 plan: **a difference is real only when the min–max ranges do not overlap.**

| Claim | True when |
|---|---|
| dns_shell helps | v_dnsshell **max** < baseline **min** |
| det hurts | v_det **min** > baseline **max** |
| v3 is better than the baseline | v3 **max** < baseline **min** |
| no clear effect | the ranges overlap |

Write one verdict per line under table 6.6.

---

## 9. Task 6: write the conclusion and decide

Section 6.5 of V3_BALANCED_TRAINING.md has four questions. Answer each with the number that backs it.

| Question | Answer from |
|---|---|
| Did the 12× data increase move the frozen-test numbers beyond the seed spread? | table 6.6: is v3's max below the baseline's min? |
| Did Path B improve with 110K extra benign rows? | Already known: the autoencoder did not. Its false alarms fell (112 → 79) but its recall fell to 0.0 (Week 5 report, Finding 1). Task 10's Isolation Forest is the answer to this: recall 1.000 on the same data. |
| Does v3 keep recall 1.0 on the frozen test set and about 0 false alarms on CIC capture 3? | table 6.2 and table 6.3 |
| Which run replaces `models/`, if any: `runs/v3` or `runs/v3_iforest`? | the decision below |

### 9.1 A decision rule

There are now two candidates on the same data and split. They share Path A (same seed, same data) and differ only in Path B and therefore the fusion:

| | `runs/v3` | `runs/v3_iforest` |
|---|---|---|
| Path B | autoencoder, recall 0.0 | Isolation Forest, recall 1.0 |
| Fusion false alarms (frozen test) | 7 | from task 10.4 |

Replace `models/` with a candidate only if **all** of these hold for it:

- [ ] fusion recall on the frozen test set is 1.0 (task 1 / task 10.4);
- [ ] fusion false alarms on the frozen test set are at or below the baseline's 23 (task 1 / task 10.4);
- [ ] false alarms on CIC capture 3 are within the 0.1% budget, 25 or fewer (task 2);
- [ ] leave-one-tool-out recall shows no tool that v3's data fails to cover badly (task 3; same data for both candidates);
- [ ] the improvement over the baseline is larger than the seed spread (task 5).

**Choosing between them, if both pass:** prefer `runs/v3_iforest` unless its fusion false alarms are clearly worse than v3's 7. v3's Path B detects nothing, so replacing `models/` with v3 would swap the old Path B (recall 1.0) for one with recall 0.0. `runs/v3_iforest` does not have that problem. State the reasoning in the conclusion either way.

### 9.2 Carrying out the decision

**Lower-risk option:** keep `models/` as it is and run the pipeline on the chosen run by setting the folder:

```bash
DNS_DETECT_MODELS_DIR=runs/v3_iforest ./scripts/run_pipeline.sh
```

Record "`runs/v3_iforest` is the candidate; `models/` not replaced yet" as the decision. Note that the dashboard (`dashboard/server.py` line 47) always checks `models/` for trained models, so the dashboard's real mode shows a new model only after `models/` is replaced.

**If you decide to replace `models/`:** back it up first. `models_*/` is already gitignored, so the backup stays out of git.

```bash
cp -r models models_backup_before_v3
```

Copying a run's files into `models/` has not been tried in this project. The run folders also hold files that don't belong in `models/` (`merged_labeled.json`, `cv_lofo.json`, `cv_splits/`). Copy only the model files, then run `./scripts/run_pipeline.sh` once and check it loads without errors before committing anything.

For `runs/v3_iforest`, Path B is `dns_trafficformer_iforest.pkl` plus its `_threshold.json` and `_norm.json`. If the old `dns_trafficformer.h5` stays in `models/` it is ignored, because the threshold file says `"model_type": "iforest"`. Remove it anyway to avoid confusion.

### 9.3 Update the other documents

- [ ] V3_BALANCED_TRAINING.md: section 6.5 written, all boxes in section 7 ticked.
- [ ] WEEK5_PROGRESS_REPORT.md section 8: change the three ❌ rows to ✅ with the numbers.
- [ ] README.md "Remaining Work": remove the finished items, add the v3 results for CIC capture 3 and the multi-seed verdict.

---

## 10. Task 7: save the evidence in git

Today every Week 5 result exists only on the Kali VM. `logs/` is gitignored and `runs/` has never been committed. If the VM is lost, no number in the report has a source.

Copy the **small** result files into the docs folder and commit them. Do not commit model binaries or `merged_labeled.json`.

```bash
mkdir -p docs/Week5/evidence
for run in baseline v_dnsshell v_det v3; do
  mkdir -p docs/Week5/evidence/$run
  cp runs/$run/evaluation_metrics.json runs/$run/fusion_lr.json docs/Week5/evidence/$run/ 2>/dev/null
  cp runs/multiseed_$run/summary.json docs/Week5/evidence/$run/multiseed_summary.json 2>/dev/null
done
cp runs/v3/cv_lofo.json runs/v3/fusion_lr_tiers.json docs/Week5/evidence/v3/ 2>/dev/null
grep -E '^\[[0-9]+/12\]|Training complete|Autoencoder:|Isolation Forest:|fusion weights' \
    logs/training_20261107_220017.log > docs/Week5/evidence/v3/training_log_summary.txt

# Task 10 (Isolation Forest Path B)
mkdir -p docs/Week5/evidence/v3_iforest
cp runs/v3_iforest/evaluation_metrics.json runs/v3_iforest/fusion_lr.json \
   runs/v3_iforest/dns_trafficformer_threshold.json docs/Week5/evidence/v3_iforest/ 2>/dev/null
grep -E '^\[[0-9]+/12\]|Training complete|Isolation Forest:|fusion weights' \
    logs/train_v3_iforest.log > docs/Week5/evidence/v3_iforest/training_log_summary.txt 2>/dev/null

# Week 4 unseen-tool results that survived on Kali (the only saved evidence for them)
mkdir -p docs/Week5/evidence/unseen_tool
cp tunnels_det_model_results.csv tunnels_dns_shell_model_results.csv docs/Week5/evidence/unseen_tool/ 2>/dev/null
du -sh docs/Week5/evidence
```

Check the size printed by `du` before committing. If `evaluation_metrics.json` or the two CSVs are large (several MB), keep them out and commit only the other files.

**About the two CSVs:** they are in the Kali project folder, not in git. Before relying on them, confirm they are the baseline's unseen-tool results: each should have 5,000 rows and a `ml_label_A` column with 5,000 ones:

```bash
python3 -c "
import csv
for f in ('tunnels_det_model_results.csv', 'tunnels_dns_shell_model_results.csv'):
    rows = list(csv.DictReader(open(f)))
    print(f, len(rows), 'rows,', sum(r.get('ml_label_A') == '1' for r in rows), 'flagged')"
```

If the counts are not 5,000 / 5,000, they come from a different run; keep them, but do not cite them as the Week 4 result.

Also decide what to do about `runs/` showing up as untracked in `git status`. If you never want it committed, add `runs/` to `.gitignore`.

---

## 11. Task 8: test the Week 6 dashboard

The Week 6 audit lists five things that were implemented but never run end to end. The test cases and expected results are in [dashboard/docs/TESTING_REPORT.md](../../dashboard/docs/TESTING_REPORT.md).

### 11.1 Start in demo mode

```bash
python dashboard/server.py --demo --port 9000
```

Open `http://127.0.0.1:9000`.

### 11.2 Click through every page

| Route | Check |
|---|---|
| `/` | classic dashboard loads; "SOC view" button opens `/soc` |
| `/soc` | KPI tiles, three donuts, category bars and three history charts show data; the new Operational Metrics row appears |
| `/usecases` | kill-chain circles show counts; clicking a stage filters the table; search and pagination work |
| `/alerts` | grid shows alerts; column filters, sorting, row selection and the detail drawer work |
| `/events` | table loads; filters and the detail panel work; ML fields show N/A in demo mode (expected) |
| `/devices` | sources list loads with the "Sources & Collection" disclaimer |
| `/health` | a health band with reasons is shown |
| `/incidents` | incident queue loads; creating an incident works |

### 11.3 Persistence across a restart

1. On `/alerts`, open an alert. Change its status, assign an analyst, and add a note.
2. Stop the server with Ctrl+C.
3. Start it again with the same command.
4. Open `/alerts`. In demo mode the alerts are regenerated, so the same alert may not be in the feed. Confirm the saved record instead:

```bash
python3 -c "import json; d=json.load(open('dashboard/data/alert_management.json')); print(len(d), 'saved record(s)'); print(json.dumps(d, indent=2)[:600])"
```

**Expected:** the record with your status, analyst and note is still there. The exact file layout is described in `dashboard/docs/API_REFERENCE.md`; if the command prints something unexpected, read the file directly.

### 11.4 Invalid transition is refused

In the alert drawer, close an alert, then try to move it straight to **Investigating**. The server should refuse with a 409 and list the allowed next states. Only "Reopen → Open" should be offered for a closed alert.

The audit notes an error in TESTING_REPORT.md section 3.2 (it uses Escalated → Open as the example, which is the wrong one). Fix that section when you record the result.

### 11.5 Bulk Execute

Select several alerts with the checkboxes, press **Execute**, pick an action, confirm. The result box should show total, succeeded and failed counts, and the grid should refresh.

### 11.6 Real mode

```bash
python dashboard/server.py --watch infra/technitium-elk/data/dns_logs --port 9000
```

Check that real alerts appear, that management actions still work, and that no demo data shows. If the pipeline or the log folder is not available, write "real mode not tested" in the testing report instead of leaving it blank.

### 11.7 Record the results

In `dashboard/docs/TESTING_REPORT.md`, fill in the actual result for each case: passed, failed, or not tested, with the date.

---

## 12. Task 9: fix the stale documentation

Found in the Week 5 audit. None of these change a result; they stop the docs contradicting each other.

| File | Line | Problem | Fix |
|---|---|---|---|
| `docs/Week4/RESULTS_COMPARISON.md` | 63 | v_det Path A shown as `38*` (inferred) | 36 (3.08%); remove the footnote |
| `docs/Week4/RESULTS_COMPARISON.md` | 64 | v_det Path B "to collect" | 105 (8.99%) |
| `docs/Week4/RESULTS_COMPARISON.md` | 116 | v_det on CIC capture 3 "to collect" | 1 / 25,222, 0.004% |
| `docs/Week4/RESULTS_COMPARISON.md` | 131–134 | only 2 of 6 unseen tools listed | add ozymandns, cobaltstrike, dnscat2, iodine, or point to Week 5 section 3.2 |
| `docs/Week4/RESULTS_COMPARISON.md` | whole file | no v3 column | add v3, or add a line at the top pointing to the Week 5 tables |
| `docs/Week5/WEEK5_PROGRESS_REPORT.md` | 340 | "None of these changes are committed to git yet" | they were committed on 2026-11-08; delete the sentence |
| `docs/Week5/WEEK5_PROGRESS_REPORT.md` | 400 | "v3's Path B may run all 200 epochs" | it stopped after epoch 65 |
| `docs/Week5/V3_BALANCED_TRAINING.md` | 81, 135 | training time estimated at 1–2 h | actual: 7 h 17 min |
| `docs/Week5/DASHBOARD_PROGRESS.md` | 11 | says every page polls every 3 seconds | the classic page `/` polls every 2 seconds |
| `docs/Week5/DASHBOARD_PROGRESS.md` | 42–45 | mapping table does not match `/soc` | see below |
| `README.md` | 74–76 | three documentation links are broken | the files are in `docs/week0/` |
| `README.md` | 11, 26, 103 | Path B described only as the Trafficformer; "Fix Path B" listed as remaining work | after task 6: mention the Isolation Forest option (`--path-b-model iforest`) and its result, and update item 4 of "Remaining Work" |

**The `/soc` mapping differences.** The mapping table in DASHBOARD_PROGRESS.md describes the Alerts page. The Monitoring Overview uses different rules:

- the **Escalated** tile counts every new alert, not only new **and** High (`dashboard/soc.html` line 906);
- the **Alerts by Status** donut uses Escalated / Confirmed / In Progress / Closed, not Open / Investigating / Closed (`soc.html` lines 944–954);
- the **Alerts by SLA** donut counts an alert as Met when it has a MITRE technique (`soc.html` lines 959–962);
- **Response SLA** on the Alerts page is "In Progress" for Low as well as Medium (`dashboard/alerts.html` line 334).

Either add these to the doc as they are, or change the code so both pages use one rule. Changing the Escalated tile to "new and High" is the one a reviewer would notice first.

---

## 13. Task 10: Path B with Isolation Forest

**Why:** Path B's Transformer autoencoder took about 6 h 37 min of v3's 7 h 17 min training, and on v3 its recall is 0.0. Path B can now use an **Isolation Forest** instead: same features, same 20-query per-client windows, same benign-only training, same 99th-percentile threshold and the same evaluation. Only the algorithm changes. On v3's data the Isolation Forest (already trained as a baseline in every run) scored recall 1.000, FPR 9.341%, PR-AUC 1.0.

**How it is selected:**

| Where | Option | Default |
|---|---|---|
| `scripts/train_models.sh` | `--path-b-model iforest` | `trafficformer` (the autoencoder) |
| `python3 -m dns_detect.models.path_b_train` | `--model iforest` | `trafficformer` |
| `scripts/run_multiseed.py` | `--path-b-model iforest` | `trafficformer` |

Without the option nothing changes, so every earlier run still works. The model type is written into `<name>_threshold.json` as `"model_type"`; the pipeline, the fusion and the dashboard read the model from there.

**Files an Isolation Forest run writes** (instead of `dns_trafficformer.keras`):

- `dns_trafficformer_iforest.pkl` (the model)
- `dns_trafficformer_threshold.json` (contains `"model_type": "iforest"`)
- `dns_trafficformer_norm.json`

### 13.0 Get the code onto Kali

The Isolation Forest code is on `main` (commit `9598ca4`). Kali must pull it first.

```bash
cd /home/ounnha/Documents/Capstone
git status --short
python3 -c "import json; print(len(json.load(open('runs/v3/merged_labeled.json'))))"   # must print 218334
git stash push -m "v3 training outputs" -- data/processed/
git pull origin main
grep -c "iforest" src/dns_detect/models/path_b_train.py   # must print more than 0
export PYTHONPATH=src
```

- **Why the stash:** every training run rewrites four tracked files in `data/processed/`, and `git pull` refuses to run over them. `git stash` sets them aside without deleting them (`git stash list` / `git stash pop` brings them back).
- **Why the row count first:** it confirms the v3 copy in `runs/v3/` is complete before the originals are set aside. Task 3 reads that copy.
- **If `grep` prints 0,** the pull did not happen; the commands below will fail.
- **`export PYTHONPATH=src` is needed in every new terminal.** Without it Python exits in a fraction of a second with "No module named dns_detect".

### 13.1 Unit tests

```bash
python3 -m pytest tests/test_path_b_iforest.py tests/test_path_b_load.py tests/test_bridge.py -q
```

All must pass.

### 13.2 Path B only, on v3's exact data (minutes)

Writes into a scratch folder; `runs/v3` and `models/` are not touched.

```bash
time DNS_DETECT_MODELS_DIR=runs/v3_pathb_iforest python3 -m dns_detect.models.path_b_train \
    --filename merged_labeled.json --data_dir runs/v3 --n_days 20 --save_name dns_trafficformer \
    --split-manifest runs/v3/split_manifest.json --seed 42 --model iforest \
    2>&1 | grep -E 'Error|error|Path B model|Isolation Forest|isolation forest|Benign-only'
ls runs/v3_pathb_iforest/
```

Use `2>&1`, not `2>/dev/null`: if something goes wrong, the error must be visible. A run that ends in well under a second has failed before training started (usually `PYTHONPATH` unset or old code; see 13.0).

**Expected:**

- finishes in minutes, not hours;
- `Isolation Forest: recall=1.000  FPR=9.341%  PR-AUC=1.0`: the same as the baseline line in the v3 log, because the data, split and seed are the same;
- the folder holds the three files listed above and no `.keras` file.

If the numbers differ from the v3 log, stop and compare before going on.

**Result (run on Kali, 2026-11-14):**

```
[*] Benign-only training windows: 99408 (dropped 83510 attack windows)
[*] Path B model: Isolation Forest (200 trees) on 99408 benign windows
   Error stats → mean=0.4056  std=0.0269
Isolation Forest: recall=1.000  FPR=9.341%  PR-AUC=1.0  | attack median score / benign p99 score = 1.3502598219271262
   dnsexfiltrator   isolation forest recall=1.000
real    65.81s
```

| | Autoencoder (v3) | Isolation Forest |
|---|---|---|
| Path B time | about 6 h 37 min | **65.8 s** (whole command, including loading the data) |
| Recall / FPR / PR-AUC | 0.000 / 6.227% / 0.787 | **1.000 / 9.341% / 1.0** (identical to the v3 baseline line) |
| Attack median score ÷ benign p99 score | 0.573 | **1.35** |

How to read the output:

- **`ValueError: Invalid DH parameters`** lines are harmless: scapy fails to load optional crypto modules. They appear only because the `grep` matches "Error".
- **`Error stats → mean=… std=…`** is the threshold calibration on benign validation windows. For the Isolation Forest these are isolation scores; the label is shared with the autoencoder code.
- **The score ratio** is the key sign: above 1 means the typical attack window scores higher than 99% of benign windows. The autoencoder's 0.573 (below 1) is why it caught nothing.

### 13.3 Full run (Path A + Isolation Forest Path B + fusion)

```bash
nohup env DNS_DETECT_MODELS_DIR=runs/v3_iforest ./scripts/train_models.sh --force-retrain \
    --path-b-model iforest \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json \
            data/external/cic/cic_benign_train.json data/external/tu2023/tunnels_*.json \
            data/external/tu2023/benign_alexa.json > logs/train_v3_iforest.log 2>&1 &
sleep 5; tail -f logs/train_v3_iforest.log
```

Ctrl+C stops `tail`, not the training. **Expected**, in well under an hour (v3 took 7 h 17 min):

| Line | Expected |
|---|---|
| `[8/12] Labeled ...` | `100000 attack / 118334 benign`, all 8 tools: the same data as v3 |
| `[9/12] Split: ...` | `train 183203 / val 32563 / test 2568`, the same as v3 |
| `[10/12] Path A trained ...` | `F1 0.9972, PR-AUC 1`: Path A is retrained with the same data and seed, so it should match v3. If it differs, the runs are not comparable; stop and check |
| `[11/12] Path B trained ...` | `(iforest, window 20, anomaly threshold ...)` |
| `[12/12] Fusion trained ...` | `recall 1, false alarms N vs OR rule M`: **N is the number to compare with v3's 7** |

Afterwards:

```bash
cp data/processed/merged_features_labeled.json runs/v3_iforest/merged_labeled.json
grep -E '^\[(8|9|10|11|12)/12\]|Training complete' logs/train_v3_iforest.log
```

Training rewrites the four `data/processed/` files again; `git checkout data/processed/` restores them once the copy above is made.

### 13.4 Compare with v3

The task 1 script does not pick up `runs/v3_iforest` (its `runs/v_*` pattern does not match it). This shorter script compares the two runs and shows which Path B model each used:

```bash
python3 - runs/v3 runs/v3_iforest <<'EOF'
import json, sys
for r in sys.argv[1:]:
    m = json.load(open(f"{r}/evaluation_metrics.json"))
    b = m.get("path_b") or {}
    t = (m.get("fusion") or {}).get("test") or {}
    lr = t.get("learned_lr") or {}
    print(f"{r:18} PathB={b.get('model_type', 'trafficformer'):13} B recall={b.get('recall')}  "
          f"B fpr={b.get('fpr')}  fusion recall={lr.get('recall')}  fusion FA={lr.get('false_alarms')}")
EOF
```

| Measure | v3 (autoencoder) | Accept `v3_iforest` if |
|---|---|---|
| Fusion recall, frozen test set | 1.0 | 1.0 |
| Fusion false alarms, frozen test set | 7 | not clearly worse; at or below the baseline's 23 at minimum |
| Path B recall | 0.0 | 1.0 |
| Total training time | 7 h 17 min | well under 1 hour |

Then repeat [task 2](#5-task-2-v3-on-unseen-benign-traffic-52) with `DNS_DETECT_MODELS_DIR=runs/v3_iforest`; it must stay within the 0.1% budget (25 of 25,222). That check uses Path A only (`path_a --infer`), and Path A is the same as v3's, so expect the same count as v3. It confirms nothing broke; it does not test the new Path B. The fusion false alarms above are what test it.

### 13.5 The pipeline loads it

```bash
DNS_DETECT_MODELS_DIR=runs/v3_iforest ./scripts/run_pipeline.sh
```

**Expected:** `Path B model ready`, no "Path B model NOT found", and `ml_score_B` in the output.

### 13.6 What to write in the report

- Path B's model was changed because the autoencoder reached recall 0.0 on v3 and took about 6.5 hours to train; keep both results side by side.
- The choice was made after seeing test-set results. Back it with CIC capture 3 (task 2) and leave-one-tool-out (task 3), which were not used for the choice.
- Path B alone flags more benign windows (9.34% vs 6.23%); report the fusion's false alarms, which decide the final alarm.
- Get your mentor's agreement that Path B may be a classical ML model rather than deep learning.

---

## 14. Optional tasks

Not needed to close Week 5 or Week 6. Listed so they are not forgotten.

| Task | Why | Effort |
|---|---|---|
| **Other Path B fixes** | Task 10 replaces the autoencoder. If the autoencoder must stay, the remaining options from the Week 5 report are: check feature scaling, or train per benign source. | Medium |
| **Full multi-seed with Path B and fusion (5.4.3)** | Only if task 5 leaves a question open. With the Isolation Forest it is practical for v3 too: add `--path-b-model iforest` to the 5.4.3 command in V3_BALANCED_TRAINING.md. With the autoencoder, do it only for a Week 4 run overnight. | minutes per seed (iforest) · 1.5–2 h per small run (autoencoder) |
| **Test v3 on a Tu daily capture** | About 280,000 unseen benign queries, 11 times larger than CIC capture 3. Needs a daily-only JSON, because `benign_tu2023.json` also contains ALEXA, which is in training. | Low |
| **Re-run the unseen-tool tests and keep the CSVs** | Only det and dns_shell have result CSVs left on Kali (task 7 saves them). ozymandns, cobaltstrike, dnscat2 and iodine's 4,996 / 5,000 have no saved evidence. Needs 5,000-row files for those tools in `cap5000/`, then `--infer` with `runs/baseline`. | Low |
| **Look at iodine's 4 misses** | Comes for free with the task above: find which queries were missed. | Low |
| **Week 7 dashboard features** | Roadmap P0 items in WEEK6_AUDIT_AND_FORTINET_ROADMAP.md section 3.1. | Large |

---

## 15. Checklist

**Close Week 5**

- [ ] Task 0: `runs/`, Tu data and training log confirmed on Kali
- [ ] Task 1: comparison script run, table 6.2 confirmed
- [ ] Task 2: v3 on CIC capture 3 recorded in table 6.3
- [ ] Task 3: leave-one-tool-out run, table 6.4 filled
- [ ] Task 4: training files rebuilt (18349 / 23349 / 23349 rows), `cap5000/` created
- [ ] Task 5: multi-seed run for all four, both checks passed, table 6.6 filled, verdicts written
- [ ] Task 10 done first (see the Path B section below): `runs/v3_iforest` is the second candidate
- [ ] Task 6: conclusion 6.5 written, decision between `runs/v3`, `runs/v3_iforest` or keeping `models/` made and recorded
- [ ] Task 6: Week 5 report section 8 and README "Remaining Work" updated

**Protect the results**

- [ ] Task 7: evidence files copied to `docs/Week5/evidence/` (including `v3_iforest` and the two unseen-tool CSVs) and committed
- [ ] Task 7: decided whether `runs/` goes into `.gitignore`

**Close Week 6**

- [ ] Task 8: all pages checked in demo mode
- [ ] Task 8: restart persistence confirmed
- [ ] Task 8: invalid transition refused with 409
- [ ] Task 8: bulk Execute works
- [ ] Task 8: real mode tested, or marked "not tested"
- [ ] Task 8: TESTING_REPORT.md filled in, section 3.2 corrected

**Clean up**

- [ ] Task 9: RESULTS_COMPARISON.md updated
- [ ] Task 9: stale sentences fixed in the two Week 5 docs
- [ ] Task 9: dashboard mapping differences documented or fixed
- [ ] Task 9: README links fixed, Path B description updated after task 6

**Path B with Isolation Forest**

- [x] Task 10: code pulled onto Kali (`main`, commit `9598ca4`)
- [ ] Task 10: unit tests pass
- [x] Task 10: Path B-only run reproduces recall 1.000 / FPR 9.341% / PR-AUC 1.0 (65.8 s, 2026-11-14)
- [ ] Task 10: full run `runs/v3_iforest` trained, training time recorded
- [ ] Task 10: compared with v3 (fusion recall and false alarms), CIC capture 3 checked
- [ ] Task 10: pipeline runs with `DNS_DETECT_MODELS_DIR=runs/v3_iforest`
- [ ] Task 10: mentor agrees; result and reasoning written into the report
