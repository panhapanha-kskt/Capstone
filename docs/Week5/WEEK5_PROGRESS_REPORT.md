# Week 5 Progress Report: All Tunnel Tools Tested, Balanced Model Trained

**DNS Traffic Anomaly Detection · session summary · 2026-11-08**

This report covers one working session. It closes out the Week 4 plan, measures every new tunnel tool on the baseline model before training on it, counts the available benign data, and trains the single combined model (`runs/v3`) on a balanced dataset about 12 times larger than any earlier run.

Detailed plans and commands: [V3_BALANCED_TRAINING.md](V3_BALANCED_TRAINING.md) (Week 5) · [NEXT_TASKS_PER_TOOL.md](../Week4/NEXT_TASKS_PER_TOOL.md) (Week 4, now complete).

---

## Contents

1. [Summary](#1-summary)
2. [Where the session started](#2-where-the-session-started)
3. [Results](#3-results)
4. [Decisions and why](#4-decisions-and-why)
5. [v3 training: what happened](#5-v3-training-what-happened)
6. [Documentation changes](#6-documentation-changes)
7. [Problems hit and lessons](#7-problems-hit-and-lessons)
8. [Status at the end of the session](#8-status-at-the-end-of-the-session)
9. [Plan and future work](#9-plan-and-future-work) (includes [9.4 Q&A](#94-qa) and [9.5 References](#95-references))

---

## 1. Summary

- **The baseline generalises to tools it has never seen.** Trained only on dns2tcp and dnsexfiltrator, it caught 5 of the 6 new Tu et al. (2023) tools at 100% and iodine at 99.92% (4,996 of 5,000). iodine is the first tool with any misses.
- **det's harm stays in the frozen test period.** v_det had 38 fusion false alarms on the frozen test set (baseline: 23), but on unseen benign traffic (CIC capture 3) it flags 1 of 25,222 queries, the same as the baseline.
- **There is far more benign data than expected:** 926,227 rows in total, of which 876,599 came from the newly converted Tu benign captures. Before this session every model had trained on only 8,349 benign rows.
- **The combined model v3 is trained:** 100,000 attack vs 118,334 benign rows, a near 1:1 balance and about 12 times the baseline's 18,349 rows. It took 7 h 17 min. **The final model's false alarms on the frozen test set fell from 23 to 7, and it still caught every attack.** Path A alone fell from 23 to 8.
- **Path B's autoencoder now catches nothing.** After training on the larger benign set its recall dropped from 1.0 to 0.0. The fusion compensates by relying on Path A, but Path B needs fixing.
- **The frozen test set only tests one tool.** All its attacks are dnsexfiltrator, so recall on the other tools has to come from the unseen-tool tests and the leave-one-tool-out test.
- **Week 4's plan is complete.** Its remaining tasks (train v3, compare all runs, multi-seed check) moved to Week 5.

---

## 2. Where the session started

| Item | State |
|---|---|
| `runs/baseline` (dns2tcp + dnsexfiltrator, 10,000 attack / 8,349 benign) | trained, 23 fusion false alarms on the frozen test set |
| `runs/v_dnsshell` (+ dns_shell) | trained, 7 fusion false alarms |
| `runs/v_det` (+ det) | trained, 38 fusion false alarms, per-method numbers not yet recorded |
| Unseen-tool tests | done for dns_shell and det (both 5,000 / 5,000) |
| ozymandns, cobaltstrike, dnscat2, iodine | not converted |
| Tu benign captures | not converted |

---

## 3. Results

### 3.1 v_det: the missing numbers

Per-method false alarms on the frozen test set (2,568 rows, about 1,168 benign):

| Method | Recall | FPR | False alarms |
|---|---|---|---|
| Path A | 1.0 | 3.08% | 36 |
| Path B | 1.0 | 8.99% | 105 |
| OR rule | 1.0 | 10.19% | 119 |
| Fusion (learned) | 1.0 | 3.25% | 38 |

On unseen benign traffic (CIC capture 3): **1 / 25,222 (0.004%)**, far inside the 0.1% budget.

This is also the first run where the fusion (38) does not equal Path A exactly (36).

**What it means:** det raises false alarms only on the frozen test set's time period. On new benign traffic it behaves like the baseline, so det stays in the combined model.

### 3.2 Unseen-tool tests (baseline, before training on each tool)

| Tool | Tunnel domain | Raw queries on that domain | Kept | Query types kept | Detected | Recall |
|---|---|---|---|---|---|---|
| dns_shell | dnsshell-txt.com | 75,024 | 5,000 | A 4,000 · TXT 1,000 | 5,000 | 100% |
| det | det-a.com | 38,365 | 5,000 | A 5,000 | 5,000 | 100% |
| ozymandns | ozymandns-txt.com | 74,937 | 5,000 | TXT 2,832 · A 2,168 | 5,000 | 100% |
| cobaltstrike | cobaltstrike-txt.com | 50,004 | 5,000 | A 3,000 · TXT 2,000 | 5,000 | 100% |
| dnscat2 | dnscat-aaaa.com | 50,000 | 5,000 | AAAA 5,000 | 5,000 | 100% |
| **iodine** | iodine-private.com | 150,412 | 5,000 | type 65399 (private) 5,000 | **4,996** | **99.92%** |

ozymandns, cobaltstrike, dnscat2 and iodine were converted and tested in this session. Conversion took 167 s, 172 s, 384 s and 983 s respectively (iodine has 36 capture files).

**What it means:**

- The model recognises tunnels by how queries look and behave (length, entropy, subdomain counts, query rate and so on), not by memorising the two training tools. Path A has no time features, so the 683-day gap between the old attack and benign captures cannot explain this.
- iodine's 4 misses are the first sign of a tool the baseline does not fully cover. iodine is the stealthiest tool in the set and uses compact encodings and a private record type.
- These numbers measure recall only. False alarms are measured separately on benign traffic (section 3.1 and Week 4's Task A).

The large "dropped" counts for cobaltstrike (100,006), dnscat2 (200,000) and iodine (548,854) are expected. These tools ran one variant per record type, each on its own domain, and the converter keeps only the most common domain. See section 9.3.

### 3.3 Benign data inventory

The four Tu benign captures were checked for truncation (0.0% in every file) and converted:

| Capture | Queries | Clients |
|---|---|---|
| ALEXA.pcap | 68,710 | 1 |
| daily_dns_00001 (2021-08-01) | 279,141 | 115 |
| daily_dns_00002 (2021-08-02) | 304,036 | 121 |
| daily_dns_00003 (2021-08-03) | 224,712 | 81 |
| **Tu total** (`benign_tu2023.json`) | **876,599** | |

Conversion took about 30 minutes; scapy parses packets one at a time.

| Benign source | Rows | Trained on before this session? |
|---|---|---|
| Own benign (`labeled_benign.json`) | 8,353 (8,349 after labeling) | yes, by every model |
| CIC benign train | 41,275 | no |
| Tu benign | 876,599 | no |
| **Total** | **926,227** | |

### 3.4 Attack data at 15,000 rows per tool

All six tools were reconverted with `--max-per-family 15000`: 57 capture files from 6 tools, scanned on 3 cores in 797 s (about 13 minutes). Every tunnel domain matched the 5,000-row conversion. Converter summary:

```
  cobaltstrike     domain=cobaltstrike-txt.com           50004 queries →  15000 kept  (dropped 100006 other)  types={'A': 8502, 'TXT': 6498}
  det              domain=det-a.com                      38365 queries →  15000 kept  (dropped 0 other)  types={'A': 15000}
  dns_shell        domain=dnsshell-txt.com               75024 queries →  15000 kept  (dropped 5 other)  types={'A': 13500, 'TXT': 1500}
  dnscat2          domain=dnscat-aaaa.com                50000 queries →  15000 kept  (dropped 200000 other)  types={'AAAA': 15000}
  iodine           domain=iodine-private.com            150412 queries →  15000 kept  (dropped 548854 other)  types={'65399': 15000}
  ozymandns        domain=ozymandns-txt.com              74937 queries →  15000 kept  (dropped 112 other)  types={'A': 8198, 'TXT': 6802}
[*] done in 797s (fast, 3 job(s))
```

| Tool | Kept | Query types |
|---|---|---|
| cobaltstrike | 15,000 | A 8,502 · TXT 6,498 |
| det | 15,000 | A 15,000 |
| dns_shell | 15,000 | A 13,500 · TXT 1,500 |
| dnscat2 | 15,000 | AAAA 15,000 |
| iodine | 15,000 | type 65399 15,000 |
| ozymandns | 15,000 | A 8,198 · TXT 6,802 |

The smallest tool, det, has 38,365 queries on its tunnel domain, so every tool had enough data for 15,000 rows.

### 3.5 ALEXA benign file for training

```
  ALEXA.pcap                           68710 queries  family=benign_tu2023  clients=1
✅ 68710 labeled records → data/external/tu2023/benign_alexa.json
```

ALEXA was converted on its own (about 3 minutes) so that it can go into training without the three daily captures.

### 3.6 Training data size of every model

| Model | Attack | Benign | Total | Tools |
|---|---|---|---|---|
| `models/` (old production) | 10,000 | 8,349 | 18,349 | 2 |
| `runs/baseline` | 10,000 | 8,349 | 18,349 | 2 |
| `runs/v_dnsshell` | 15,000 | 8,349 | 23,349 | 3 |
| `runs/v_det` | 15,000 | 8,349 | 23,349 | 3 |
| **`runs/v3`** (training) | **100,000** | **118,338** | **218,338** | **8** |

v3's benign side is 8,353 own + 41,275 CIC + 68,710 ALEXA = 118,338. Labeling drops 4 rows, the same as in every run, leaving 118,334.

### 3.7 v3 results

**Training summary** (`logs/training_20261107_220017.log`):

```
[8/12] Labeled 100000 attack / 118334 benign · files 218334 (families: cobaltstrike,det,dns2tcp,dns_shell,dnscat2,dnsexfiltrator,iodine,ozymandns)
[9/12] Split: extended time_seed42.json with 199985 new rows (train/val only, test frozen) · train 183203 / val 32563 / test 2568 → runs/v3/split_manifest.json
[10/12] Path A trained (F1 0.9972, PR-AUC 1)
[11/12] Path B trained (window 20, anomaly threshold 0.01741)
[12/12] Fusion trained (test: recall 1, false alarms 7 vs OR rule 87)
Training complete in 26243s
```

All checks passed:

- all 8 tools are present;
- the split is `extended` and the test set is still the same 2,568 rows;
- the 199,985 new rows (218,334 − 18,349) went to training and validation only.

**Frozen test set, v3 vs earlier runs** (1,168 benign rows; recall is on the 1,400 attack rows):

| Method | Baseline | v_dnsshell | v_det | **v3** | v3 recall |
|---|---|---|---|---|---|
| Path A false alarms | 23 | 7 | 36 | **8** (0.68%) | 1.0 |
| Path B false alarms | 112 | 113 | 105 | 79 (6.76%) | **0.0** |
| OR rule false alarms | 116 | 113 | 119 | 87 (7.45%) | 1.0 |
| **Fusion false alarms** | **23** | **7** | **38** | **7 (0.60%)** | **1.0** |
| Path A F1 / PR-AUC | 0.9919 / 0.9957 | 0.9975 / 1.0 | 0.9873 / 1.0 | 0.9972 / 1.0 | |

**What it means:**

- **Path A improved the most: 23 → 8 false alarms**, with recall still 1.0. More varied attack and benign data made the main classifier more precise.
- **The fusion matches the best earlier run (7, like v_dnsshell)**, even though v3 also contains det, which pushed v_det up to 38. With much more benign data, det's effect disappears.
- **This is still one seed.** Whether 23 → 7 is larger than training randomness is answered by the multi-seed check (V3_BALANCED_TRAINING.md, section 5.4).

**Finding 1: Path B's autoencoder no longer detects attacks.**

```
Autoencoder: recall=0.000  FPR=6.227%  PR-AUC=0.787  | attack median error / benign p99 error = 0.573
Isolation Forest: recall=1.000  FPR=9.341%  PR-AUC=1.0
```

- The autoencoder flags a window when its reconstruction error exceeds a threshold set at the 99th percentile of benign validation error (0.01741, down from 0.04163 in the baseline).
- In v3, the typical attack window has an error only **0.57×** that threshold. The model reconstructs tunnel traffic *better* than unusual benign traffic, so it treats tunnels as normal.
- A likely reason, not yet verified: tunnel queries are extremely repetitive (the same query shape thousands of times), which is easy to reconstruct. Meanwhile 118,000 varied benign rows widened what the model considers normal.
- **The final model is not affected:** the fusion learned to rely on Path A (weight 12.85 for Path A vs 3.04 for Path B). But Path B as it stands adds only false alarms (precision 0).
- Path B's second detector, the **Isolation Forest, still catches every attack** (recall 1.0, 9.34% FPR).

**Path B's own evaluation** (held-out test windows, from the log):

```
── Calibrating Anomaly Threshold (benign val) ────────────────
   Error stats → mean=0.0035  std=0.0036
   Anomaly threshold: 0.0174  (percentile_99)

── Final Evaluation (held-out test set) ──────────────────────
              precision    recall  f1-score   support
      benign       0.43      0.94      0.59      1092
      attack       0.00      0.00      0.00      1381
    accuracy                           0.41      2473

Autoencoder: recall=0.000  FPR=6.227%  PR-AUC=0.7869  | attack median error / benign p99 error = 0.573
Isolation Forest: recall=1.000  FPR=9.341%  PR-AUC=1.0
   dnsexfiltrator   autoencoder recall=0.000   isolation forest recall=1.000
```

Path B scores 20-query windows rather than single queries, so its test set has 2,473 windows (1,092 benign, 1,381 attack), not 2,568 rows. Its PR-AUC of 0.787 shows the errors still rank attacks somewhat above benign; the threshold, at the 99th percentile of benign error, is simply too high for them.

**Fusion step** (from the log):

```
[*] fusion weights: {'ml_score_A': 12.850, 'ml_score_B': 3.041, 'has_score_B': -3.504, 'rule_hits': 0.676}  intercept=-5.385  threshold=0.486541

   detector         recall      FPR  false alarms  precision
   path_a            1.000   0.0068        8/1168       0.994
   path_b            0.000   0.0676       79/1168       0.000
   or_rule           1.000   0.0745       87/1168       0.941
   learned_lr        1.000   0.0060        7/1168       0.995
```

- The fusion is a logistic regression over four inputs: Path A's score, Path B's score, whether a Path B score exists, and the number of rule hits.
- Path A's weight (12.85) is about four times Path B's (3.04), so the fusion follows Path A.
- The final model's precision is 0.995: of its alarms on the frozen test set, 99.5% are real attacks.
- The alert-tier boundaries were saved to `runs/v3/fusion_lr_tiers.json`, computed from 17,663 benign validation rows.

**Finding 2: the frozen test set's attacks are all dnsexfiltrator.** Path B's per-family line lists only `dnsexfiltrator`. The time-based split put the latest attack captures into the test set, and that holds for every run, because the test set is frozen. So "recall 1.0 on the frozen test set" in every run means "catches dnsexfiltrator". For the other seven tools, recall comes from the unseen-tool tests (section 3.2) and the leave-one-tool-out test (section 9.1). The frozen test set remains valid for comparing **false alarms** between runs, because its 1,168 benign rows are identical for every run.

---

## 4. Decisions and why

### 4.1 Skip the per-tool training runs for the last four tools

Week 4 planned one training run per tool (`v_ozymandns`, `v_cobaltstrike`, `v_dnscat2`, `v_iodine`). They were skipped in favour of one combined model.

- The per-tool story is already shown by two examples: dns_shell helps (23 → 7 false alarms) and det hurts (23 → 38).
- The unseen-tool test, the part that cannot be repeated once a tool is trained on, was still done for every tool.
- The trade-off: if v3 turns out worse than the baseline, we cannot tell which tool caused it. det is the main suspect.

### 4.2 Each run is a new model, not an update of the old one

Every run trains new models from scratch on the combined data and saves them in its own folder (`runs/<name>`). Nothing is added onto an existing model. A Random Forest cannot be topped up with new data, and separate runs mean a bad run can simply be dropped. `models/` is never touched until we decide to replace it.

### 4.3 Balanced ~100K vs ~118K rather than all the data

The user asked for about 100,000 attack and 100,000 benign rows. Using everything (about 450,000 attack and 926,000 benign) was considered and rejected for v3:

- **Balance:** all benign vs 100K attack is about 9:1. Either imbalance hurts threshold calibration, and false alarms are the side being optimised.
- **Repetition:** 81% of rows repeat another row's exact feature vector (EDA). A tunnel sends the same kind of query thousands of times, so more rows add little new information.
- **Equal tool weight:** at 15,000 each, no tool dominates. Uncapped, iodine would outweigh det about 4 to 1.
- **Memory and time:** the Kali VM has 7.7 GiB of RAM. About 1.37 million rows risks running out of memory, and Path B would take many hours per run, making the 5-seed check impractical.
- **Keep an honest test set:** the three Tu daily captures (about 808,000 rows) stay out of training. They are the largest benign traffic the model has never seen, and can test it once.

### 4.4 Only the ALEXA capture goes into training

Whole files are used, not random samples, because Path B needs time-contiguous 5-minute windows. ALEXA (68,710 rows) brings the benign total to 118,338, close to the 100,000 attack rows.

---

## 5. v3 training: what happened

1. **A first launch ran on the wrong files.** The training command (step 3) was started before the reconversion (step 1) and the ALEXA file (step 2). It would have trained on the old 5,000-row tool files. It was found with `ps`, killed, and `runs/v3` was deleted.
2. **Steps 1 and 2 ran in order**, with the results in section 3.4 and 68,710 ALEXA rows.
3. **Step 3 was relaunched under `nohup`.** On the Kali clock the log is `logs/training_20261107_220017.log`.
4. **Health check:** the training script had run 2h 07m. The Path B process had run 1h 30m at about 181% CPU. `dmesg` showed no out-of-memory kills, and 6.5 GiB of RAM was available before the run.
5. **Path B training:** the Transformer autoencoder (`dns_trafficformer`) ran 3,107 batches per epoch. Validation loss improved slowly, from 0.00368 at epoch 32 to 0.00355 at epoch 55, then not at all for 10 epochs.
6. **Epochs slowed down** from about 110 s to 230–290 s each between epochs 46 and 60, then returned to about 112 s by epoch 64. So the slowdown was temporary, most likely another load on the machine, not a problem with the training.
7. **Early stopping ended Path B after epoch 65.** Training stops after 10 epochs in a row with no improvement (`patience=10`, `path_b_train.py:285`); epochs 56–65 did not beat epoch 55. The best weights, from epoch 55, were kept.
8. **Threshold calibration and fusion** followed in a few minutes: anomaly threshold 0.01741, fusion with 7 false alarms. **Total training time: 26,243 s (7 h 17 min 23 s)**, about 31 times the baseline's 14 min. The results are in section 3.7.

**Where the 7 h 17 min went** (derived from the `ps` check and the log's timestamps; the Kali clock's time zone looks wrong, so only durations are used, not clock times):

| Stage | Duration | How it was measured |
|---|---|---|
| Steps 1–10: merge, label, split, Path A | about 36 min | `ps` showed the script at 2 h 07 min and the Path B process at 1 h 30 min, so Path B started about 36.5 min in |
| Step 11: Path B (65 epochs, threshold, evaluation) | about 6 h 37 min (91% of the total) | the rest of the run after subtracting the other stages |
| Step 12: fusion and tier boundaries | about 4 min | the log's internal timestamps run from the start of step 12 to the end (about 220 s) |
| **Total** | **26,243 s = 7 h 17 min 23 s** | `Training complete in 26243s` |

For comparison:

| Run | Rows | Training time |
|---|---|---|
| baseline | 18,349 | 14 min 8 s |
| v_det | 23,349 | 20 min 22 s |
| v_dnsshell | 23,349 | 24 min 42 s |
| **v3** | **218,334** | **7 h 17 min 23 s** |

The data grew about 12 times, but training time grew about 31 times. Path B is the reason: an epoch went from seconds to 2–5 minutes (3,107 batches each), and early stopping needed 65 epochs.

**Path B validation loss, epochs 32–65** (from `logs/training_20261107_220017.log`):

| Epoch | val_loss (best so far) | Improved? | Epoch time |
|---|---|---|---|
| 32 | 0.00366 | yes | 47 s |
| 34 | 0.00365 | yes | 114 s |
| 36 | 0.00363 | yes | 128 s |
| 37–39 | — | no | 111–114 s |
| 40 | 0.00362 | yes | 112 s |
| 41–45 | — | no | 106–111 s |
| 46 | 0.00359 | yes | 189 s |
| 47 | — | no | 264 s |
| 48 | 0.00358 | yes | 269 s |
| 49–54 | — | no | 252–264 s |
| 55 | **0.00355** | yes (best) | 228 s |
| 56–58 | — | no | 230–242 s |
| 59–60 | — | no | 281–292 s |
| 61–63 | — | no | 148–195 s |
| 64–65 | — | no | 112–113 s |
| **stop** | best weights from epoch 55 restored | | |

Training loss stayed at about 0.0043 (0.0042 from epoch 60) while validation loss fell slightly and then flattened. The model did not overfit; it simply stopped finding gains. Low reconstruction loss on benign data turned out not to mean good attack detection (section 3.7, Finding 1).

---

## 6. Documentation changes

| File | Change |
|---|---|
| `docs/Week4/NEXT_TASKS_PER_TOOL.md` | v_det and all unseen-tool results filled in. Tasks C, D, E removed and replaced by a pointer to Week 5. The tables are now per-tool only. Week 4 conclusion added (section 8.4). Checklist fully ticked. |
| `docs/Week5/V3_BALANCED_TRAINING.md` (new) | v3 plan: data inventory, reasons for the balance, Step 0 (Tu benign conversion, done), Steps 1–3 (reconvert, ALEXA, train), evaluation 5.1–5.3, the full multi-seed check 5.4 (moved from Week 4 and extended with v3), results tables 6.1–6.6, checklist. |
| `docs/Week5/WEEK5_PROGRESS_REPORT.md` (new) | this report |

None of these changes are committed to git yet.

---

## 7. Problems hit and lessons

| Problem | Cause | Fix / lesson |
|---|---|---|
| `tail: cannot open 'logs/train_v3.log'` right after launching | `tail` ran before the background job had created the file | Wait a moment (`sleep 3`) before `tail -f`. Check `ps` before assuming the launch failed. |
| Training started on the wrong data | Step 3 was run before steps 1 and 2 | Run the steps in order. Check the `[8/12] Labeled` line (attack and benign counts) as soon as it appears. |
| `tail` failed on the log path | The terminal was in `/home/ounnha`, not the project folder | Use full paths, or `cd /home/ounnha/Documents/Capstone` first. |
| The multi-seed rebuild would not match v_dnsshell / v_det | The 15,000-row reconversion overwrote `tunnels_dns_shell.json` and `tunnels_det.json`, which those runs trained at 5,000 rows | Recreate the 5,000-row files in `data/external/tu2023/cap5000/` (Week 5, section 5.4.1). In future, write differently capped conversions to separate folders. |
| Tu benign conversion took about 30 minutes | 876,599 queries parsed one packet at a time on a single core | Expected; it runs only once and the JSON is reused. |
| The leave-one-tool-out test needs `data/processed/merged_features_labeled.json` | Every training run rewrites that file, and `git checkout data/processed/` restores the old one | Copy it to `runs/v3/merged_labeled.json` and run the leave-one-tool-out test before any `git checkout data/processed/`. |

---

## 8. Status at the end of the session

| Item | Status |
|---|---|
| Week 4 plan (NEXT_TASKS_PER_TOOL.md) | ✅ complete |
| All 6 tools converted and tested unseen | ✅ |
| Tu benign converted (876,599 rows) | ✅ |
| Tools reconverted at 15,000 · ALEXA file built | ✅ |
| `runs/v3` training | ✅ done in 7 h 17 min 23 s (26,243 s; Path B about 6 h 37 min of it) · fusion 7 false alarms, recall 1.0 · `merged_labeled.json` copied |
| v3 on the frozen test set | ✅ recorded (section 3.7) |
| v3 comparison table | ✅ confirmed from saved metrics (2026-11-14) |
| v3 on CIC capture 3 | ✅ 1 / 25,222 (0.004%), same as the baseline (2026-11-14) |
| v3 leave-one-tool-out | ✅ recall 1.0 on all 8 tools; false alarms 0.35–0.59%, above the 0.1% budget (2026-11-14) |
| Multi-seed check (baseline, v_dnsshell, v_det, v3) | ✅ Path A false alarms over 5 seeds: baseline 9–25, v_dnsshell 7–11, v_det 13–36, v3 8–9 (2026-11-14) |
| Decision: does v3 replace `models/`? | ❌ |

---

## 9. Plan and future work

### 9.1 Next steps (Week 5, in order)

1. ~~**Finish v3.**~~ Done: all log checks passed, and `merged_labeled.json` is copied (section 3.7).
2. **Evaluate v3 further** (V3_BALANCED_TRAINING.md, sections 5.1–5.3):
   - frozen test set: ✅ fusion 7 false alarms (baseline 23), recall 1.0;
   - **CIC capture 3:** ✅ 1 / 25,222 false alarms (0.004%), within the 0.1% budget (2026-11-14);
   - **leave-one-tool-out:** ✅ recall 1.0 on every one of the 8 tools when it is left out of training; false alarms 0.35–0.59%, above the 0.1% budget (2026-11-14, V3_BALANCED_TRAINING.md table 6.4). This is the main recall test, since the frozen test set only contains dnsexfiltrator.
3. ✅ **Multi-seed check** (section 5.4): Path A with 5 seeds for baseline, v_dnsshell, v_det and v3. A difference counts as real only when the min–max ranges across seeds do not overlap. Result (V3_BALANCED_TRAINING.md table 6.6): no difference is proven by that rule; v3 vs baseline is borderline (ranges touch at 9); v3 is far more stable (SD 0.55 vs 7.56).
4. **Write the conclusion** and decide whether `runs/v3` replaces `models/`.

### 9.2 What to watch in v3's results

- **Path B:** it was stuck at 105–113 false alarms because no benign data had been added. **Result:** its false alarms fell to 79, but its recall fell to 0.0. More benign data alone did not fix Path B; it made the autoencoder treat tunnels as normal (section 3.7, Finding 1).
- **iodine:** v3 has trained on iodine, so the leave-one-tool-out result for iodine is the honest check of how well it is covered.
- **det:** whether the det effect (23 → 38) shows up again in the combined model.

### 9.3 Future work (after v3)

| Idea | Why | Effort |
|---|---|---|
| **Fix Path B** (new, highest priority) | v3's autoencoder has recall 0.0. Options to test: use Path B's Isolation Forest (recall 1.0) as Path B's output; check the feature scaling (the new benign sources may have stretched feature ranges so that tunnel windows look average); or train the autoencoder on per-source benign windows. Compare by Path B's recall and FPR on the frozen test set and the fusion's false alarms. | Medium |
| **A test set covering every tool** (new) | The frozen test set only contains dnsexfiltrator attacks. A held-out block per tool, kept out of training like the frozen set, would measure recall on all 8 tools in one place. It needs a new split, so it can't be compared directly with the earlier runs. | Medium |
| **Test v3 on a Tu daily capture** | About 280,000 real benign queries the model has never seen, 11 times larger than CIC capture 3. A strong false-alarm claim for the report. Needs a daily-only JSON, because `benign_tu2023.json` also contains ALEXA, which is in training. | Low |
| **Look at iodine's 4 misses** | Re-run the baseline on `tunnels_iodine.json` and keep the CSV this time (it was deleted). Find which queries were missed and why. | Low |
| **Convert the dropped tool variants** | dnscat2's MX / CNAME / TXT / mixed variants and cobaltstrike's AAAA variant were dropped because the converter keeps one domain per tool. Converting them as extra families with `--domain`, still capped, adds variety of tunnel behaviour, which is worth more than more copies of the same behaviour. | Medium |
| **Shorten Path B training** | With no minimum improvement, tiny gains keep resetting early stopping; v3's Path B may run all 200 epochs. A small `min_delta` would stop it once gains become negligible. Code change; check that results do not get worse. | Low |
| **Find out why det hurts** | Compare the feature ranges of det, dns_shell and benign, and look at which test domains v_det flags. | Medium |
| **A mixed-traffic test capture** | Today every tunnel query sits in a 5-minute window of pure tunnel traffic. A capture of a tunnel running alongside normal browsing on the same machine is the realistic test. | High |
| **Train on everything (v4_full, optional)** | All ~450K attack and ~926K benign rows, as a final experiment after v3 is evaluated and the Tu daily test is done. Expect an overnight run and a risk of running out of memory on 7.7 GiB. | High |

### 9.4 Q&A

Questions raised while reviewing this report, answered from the code and the results.

#### Q1. How were exactly 5,000 queries per tool chosen for the unseen-tool tests?

The converter, `scripts/convert_external_tunnels.py`, runs three stages for each tool:

1. **Parse.** It reads every capture file of the tool (for example, all 36 iodine files) and extracts each DNS query.
2. **Domain filter.** A tool sends its tunnel traffic under one parent domain, such as `iodine-private.com`. The converter counts the queries per parent domain and keeps the most common one (`tunnel_domain`, line 69). Everything else, such as operating-system background lookups or the tool's other variants, is dropped, not labelled as attack. That's what the "dropped N other" count reports.
3. **Cap with contiguous time blocks** (`cap_family`, line 75, which calls `sample_contiguous_blocks` in `src/dns_detect/utils/sampling.py`):
   - all the tool's kept queries, across all its capture files, are sorted by timestamp;
   - the sorted sequence is cut into non-overlapping slots of **500 consecutive queries** (`--block 500`);
   - **10 slots are picked at random** with a fixed seed (42), giving 10 × 500 = **5,000 queries** (`--max-per-family 5000`, the default).

   For det, for example, 38,365 queries make 76 slots, and 10 of them are picked.

The baseline then classified all 5,000 with `--infer`, which uses Path A, and **recall = detected ÷ 5,000**.

**Why blocks, not 5,000 random single queries?** Some features look at a query's neighbours: the behaviour features summarise a 5-minute window, and Path B reads windows of 20 consecutive queries. Random single queries would break those windows and make the features meaningless. Blocks of 500 keep each window intact, and the random choice of blocks spreads the sample across the whole capture period.

**Why cap at all?** It gives every tool the same weight, keeps conversion and training fast, and 5,000 rows is enough to measure recall precisely. With 4 misses out of 5,000, iodine's true recall lies between about 99.79% and 99.97% (95% Wilson interval).

#### Q2. What do the v_det numbers in section 3.1 mean?

v_det is the model trained on the baseline data plus det. It was scored on the **frozen test set**: 2,568 rows that no run has trained on, the same rows for every run. Of these, **1,400 are attacks and 1,168 are benign**.

The model has four ways to decide whether a query is an attack, and each is scored separately:

| Method | What it does | Attacks caught | Benign wrongly flagged |
|---|---|---|---|
| **Path A** | A supervised Random Forest. It learns from labelled attack and benign examples and scores each query on 14 features (length, entropy, digits, subdomain counts, query rate and so on). | 1,400 / 1,400 | **36** / 1,168 = 3.08% |
| **Path B** | An anomaly detector: a Transformer autoencoder trained on **benign traffic only**. It learns to reconstruct normal 20-query windows and flags windows it reconstructs badly. It never sees an attack while training. | 1,400 / 1,400 | **105** / 1,168 = 8.99% |
| **OR rule** | Raises an alarm if *either* path flags. Catches everything either path catches, but also collects both paths' false alarms. | 1,400 / 1,400 | **119** / 1,168 = 10.19% |
| **Fusion (learned)** | A logistic regression that weighs Path A's and Path B's scores into one decision. This is the model's final output. | 1,400 / 1,400 | **38** / 1,168 = 3.25% |

How to read it:

- **Every method catches every attack** (recall 1.0), so the difference between them is only in false alarms.
- **Path A is far more precise than Path B** (36 vs 105 false alarms). Path B has seen only 8,349 benign rows, too little to learn what "normal" looks like. That's why v3 adds about 110,000 benign rows.
- **The fusion leans almost entirely on Path A**, because Path B adds noise. In earlier runs the fusion equalled Path A exactly; here it is 2 alarms worse (38 vs 36).
- **Compared with the baseline** (fusion 23), v_det raised false alarms by 15. On CIC capture 3, though, a separate set of 25,222 benign queries from a different source, it flags **1**, the same as the baseline. So det's effect appears only on the frozen test set's traffic, not on new traffic.

#### Q3. What are recall, FPR and false alarms?

Every prediction lands in one of four boxes, the **confusion matrix**:

| | Model says attack | Model says benign |
|---|---|---|
| **Really an attack** | True positive (TP): caught | False negative (FN): **missed attack** |
| **Really benign** | False positive (FP): **false alarm** | True negative (TN): correctly ignored |

- **Recall** (also called true positive rate or detection rate) = TP ÷ (TP + FN): *of all real attacks, what share did we catch?* Recall 1.0 means no attack was missed. iodine's 99.92% means 4 of 5,000 tunnel queries slipped through.
- **False alarms** = FP: *how many benign queries were wrongly flagged.* This is a raw count.
- **False positive rate (FPR)** = FP ÷ (FP + TN): *of all benign queries, what share was wrongly flagged?* v_det's Path A: 36 ÷ 1,168 = 3.08%.

**Why both matter, and why this project focuses on FPR:**

- Recall alone can be gamed: a detector that flags everything scores recall 1.0. Recall must always be read together with FPR.
- In a real network, benign DNS outnumbers tunnel traffic by millions to one. Even a small FPR becomes a flood of alerts for the security team: 0.1% of 10 million daily queries is 10,000 alarms a day. This is the **base-rate problem** (Arp et al., 2022). It is why the project sets a **0.1% false-alarm budget** and why most improvements target false alarms rather than recall.
- **PR-AUC** (area under the precision–recall curve), reported for Path A, summarises the trade-off over all thresholds. It is preferred over ROC-AUC when classes are imbalanced (Saito & Rehmsmeier, 2015).

#### Q4. Where does the dataset come from?

- **Attack captures and Tu benign captures:** the public repository of Tu, Liu & Sun (2023). See references [1] and [2] in section 9.5. It has one folder per tool (cobaltstrike, det, dns2tcp, dns_shell, dnscat2, dnsexfiltrator, iodine, ozymandns) and four benign captures (ALEXA plus three days of real DNS traffic). The repository states no licence and asks users to cite the paper, so every report using these numbers cites [1].
- **CIC benign captures** (training captures 1–2 and test capture 3): the CIC-Bell-DNS-EXF-2021 dataset from the Canadian Institute for Cybersecurity [3].
- **Own benign and the original dns2tcp/dnsexfiltrator data:** collected for this project in earlier weeks (documented in `docs/Week3/DATASHEET.md`).

#### Q5. How were exactly 15,000 queries per tool chosen?

The same method as Q1, with a larger cap: `--max-per-family 15000`. After the domain filter, the tool's queries are sorted by time, cut into slots of 500, and **30 slots are picked at random** (seed 42): 30 × 500 = **15,000**.

- Every tool had enough data. The smallest, det, has 38,365 queries, or 76 slots, so 30 could be picked.
- The selection is deterministic: re-running the command with the same seed gives the same rows.
- It is a fresh sample, so it isn't guaranteed to contain the same 5,000 rows as the earlier cap. That is also why the 5,000-row files have to be recreated for the multi-seed check (V3_BALANCED_TRAINING.md, section 5.4.1).
- The mix of query types changed with the larger sample (for example, ozymandns went from TXT 2,832 / A 2,168 to A 8,198 / TXT 6,802). Different blocks cover different phases of the capture, such as the upload and download channels.

**Why 15,000?** It is the number that gives about 100,000 attack rows: the old 10,000 plus 6 tools × 15,000. That matches the roughly 100,000 benign rows that were available (section 4.3).

#### Q6. Why does section 3.6 list the training data size of every model?

For four reasons:

1. **A fair comparison depends on it.** Every model is scored on the same frozen test set, so any difference in results comes only from the training data. The table shows exactly what each model learned from, so a change in false alarms can be traced to a change in data.
2. **It explains a result that would otherwise look strange.** Path B stayed at 105–113 false alarms in every retrained run. The table shows why: every model so far trained on the **same 8,349 benign rows**, and Path B learns only from benign data. Adding attack tools could never help it.
3. **It shows how big a step v3 is.** About 10 times the attack data and 14 times the benign data. If v3's results barely change, that is itself a finding: it would mean the bottleneck is data diversity, not volume.
4. **Reproducibility.** Anyone repeating the work can check their `[8/12] Labeled` line against this table.

#### Q7. Why isn't v3 trained on exactly equal benign and attack data?

**v3 is close to balanced on purpose:** 100,000 attack vs 118,338 benign, a ratio of about 1:1.18. Exact equality wasn't forced, for four reasons:

1. **Whole benign files.** The benign side is three complete sources (own 8,353, CIC 41,275, ALEXA 68,710). Path B needs time-contiguous windows, so files are added whole rather than cut to an exact number.
2. **Path A already corrects for imbalance.** Its Random Forest uses `class_weight="balanced"` (`src/dns_detect/models/path_a.py:212`). Each class is weighted inversely to its size, so 118,338 benign rows count the same in total as 100,000 attack rows. An 18% difference is fully compensated.
3. **Path B is not affected by the ratio at all.** It trains on benign data only, so more benign is simply better for it.
4. **The decision threshold is tuned on validation data.** The final threshold doesn't depend on the training ratio. And the real-world ratio is nowhere near 1:1 anyway; tunnels are rare. Balance matters during training so neither class is ignored, and 1:1.18 achieves that.

For comparison, the earlier models were **attack-heavy** (10,000–15,000 attack vs 8,349 benign, up to 1.8:1). v3 is the first run where benign is at least as large as attack.

If an exact 1:1 is wanted for the report, there are two clean options. Each is a new training run:

- **Raise the attack cap** to about 18,056 per tool, giving 10,000 + 6 × 18,056 ≈ 118,338. Every tool has enough data for this.
- **Trim ALEXA** with the same contiguous-block method to about 50,372 rows, giving 100,000 benign.

Neither is expected to change the results meaningfully, for the reasons above.

### 9.5 References

**Datasets**

1. Tu, Y., Liu, S., & Sun, Q. (2023). DNS tunnelling detection by fusing encoding feature and behavioral feature. *Computers & Security*, 132, 103357. https://doi.org/10.1016/j.cose.2023.103357
2. Tu et al. dataset repository (GitHub): https://github.com/Utah1A/DNS-tunnelling-detection-by-fusing-encoding-feature-and-behavioral-feature. Source of all six new tunnel tools and the four benign captures (`datasets/base_malicious_dataset/`, `datasets/base_benign_dataset/`). No licence is stated; the authors ask that [1] be cited.
3. Canadian Institute for Cybersecurity. CIC-Bell-DNS-EXF-2021 dataset. https://www.unb.ca/cic/datasets/dns-exf-2021.html. Source of CIC benign captures 1–2 (training) and 3 (unseen-benign test). Accompanying paper: Mahdavifar, S., et al. (2021). Lightweight Hybrid Detection of Data Exfiltration using DNS based on Machine Learning. *ICCNS 2021*.

**Methods and evaluation**

4. Arp, D., et al. (2022). Dos and Don'ts of Machine Learning in Computer Security. *USENIX Security Symposium*. https://arxiv.org/abs/2010.09470. Base-rate problem, data snooping, and why false-positive rate dominates in security detection.
5. Saito, T., & Rehmsmeier, M. (2015). The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets. *PLOS ONE*, 10(3), e0118432. https://doi.org/10.1371/journal.pone.0118432
6. scikit-learn. `RandomForestClassifier` (the `class_weight="balanced"` option used by Path A). https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
7. Keras. `EarlyStopping` callback (`patience`, `min_delta`, `restore_best_weights`, used by Path B). https://keras.io/api/callbacks/early_stopping/

**Project documents**

8. [V3_BALANCED_TRAINING.md](V3_BALANCED_TRAINING.md): Week 5 plan, commands and results tables for v3.
9. [NEXT_TASKS_PER_TOOL.md](../Week4/NEXT_TASKS_PER_TOOL.md): Week 4 per-tool plan and results.
10. [RESULTS_COMPARISON.md](../Week4/RESULTS_COMPARISON.md): all runs compared with the old models.
11. [CONVERTER_SPEEDUP.md](../Week4/CONVERTER_SPEEDUP.md): how the tunnel converter works and why it is fast.
12. `docs/Week3/DATASHEET.md`: composition and collection of the project's own data.
