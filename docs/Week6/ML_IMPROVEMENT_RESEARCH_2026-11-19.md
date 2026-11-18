# ML Improvement Research (Phases 0–3)

**DNS Traffic Anomaly Detection · Capstone · 2026-11-19**

This document covers Phases 0–3 of the research prompt: what the project already does, where it differs from published best practice, and a short list of improvements to choose from. **Nothing has been implemented or trained yet.** Phase 4 starts only after you pick items and create a branch.

How to read the evidence labels:
- **Observed** means I read it in the code (file:line given) or in a run log on this machine.
- **Reported** means it comes from an earlier doc. Those runs (`runs/v3*`, `data/external/tu2023`) are not on this machine, so I could not re-check them.
- **Assumption** means my judgement, not a measurement.

Code references are to commit `6e236ee` on `main`.

---

## Contents

1. [Phase 0: what the docs already say](#1-phase-0-what-the-docs-already-say)
2. [Phase 1: the training flow, with file:line](#2-phase-1-the-training-flow-with-fileline)
3. [Phase 1: the known facts, confirmed or corrected](#3-phase-1-the-known-facts-confirmed-or-corrected)
4. [Phase 2: research findings](#4-phase-2-research-findings)
5. [Phase 3: gap table](#5-phase-3-gap-table)
6. [Phase 3: proposed items (pick up to 8)](#6-phase-3-proposed-items-pick-up-to-8)
7. [What I need from you](#7-what-i-need-from-you)
8. [References](#8-references)

---

## 1. Phase 0: what the docs already say

Docs I read: README.md, PLAN_v2_improvement.md, config/settings.yaml, docs/Week5/V3_BALANCED_TRAINING.md, WEEK5_PROGRESS_REPORT.md, and these in docs/Week6: WEEK6_COMPLETE_REPORT.md, V3_EVALUATION_RESULTS.md, PATH_B_ISOLATION_FOREST.md, "next task.md", SOC_ML_INTEGRATION.md, TIER1_TRIAGE_REPORT.md and WEEK6_AUDIT_AND_FORTINET_ROADMAP.md.

**Work already done (Reported, on the old Kali VM):**

| Topic | Result |
|---|---|
| v3 data | 100,000 attack rows (8 tunnel tools) and 118,334 benign rows |
| Unseen benign traffic (CIC capture 3) | 1 false alarm in 25,222 queries |
| Leave-one-tool-out | recall 1.0 on all 8 tools, but false alarms of **0.35–0.59%**, above the 0.1% budget |
| Frozen test set | false-alarm rate 0.6% |
| Path B | the autoencoder had recall 0.0 and was replaced by an Isolation Forest (recall 1.0, about 1 min to train) |
| `runs/v3_iforest` | fusion recall 1.0, 7 false alarms, 39 min to train |
| 5 seeds | Path A 8.6 ± 0.55 false alarms; fusion 8.2 ± 0.84; recall 1.0 every seed |
| Feedback loop | verdicts export to `data/feedback/labels_*.csv`; **retraining on them was never done** |

**Open items the docs list:**
- mentor approval of the Isolation Forest Path B;
- `models/` still holds the old autoencoder Path B;
- threshold drift on later benign traffic;
- "why it fired" is a baseline deviation, not model attribution;
- no measurement of whether feedback labels lower false alarms.

**Latest run on this machine (Observed):** `gui_data/runs/20261119-015201-8ffe`, bundle `labelled_v3`.

| Item | Value |
|---|---|
| Rows | 59,624, but only 8,177 distinct feature vectors (**about 92% duplicates**) |
| Split | train 48,299 / validation 8,757 / test 2,568 |
| Test set | 1,168 benign, 1,400 attack |
| Path A | decision `rf_only`, 8 false alarms in 1,168 benign test rows (0.68%) |
| Path B (Isolation Forest) | false-alarm rate 25.5% on windows |
| Fusion | 13 false alarms in 1,168 benign test rows |

This run uses only 2 attack tools (dns2tcp, dnsexfiltrator), so it is not comparable with v3.

---

## 2. Phase 1: the training flow, with file:line

`scripts/train_models.sh` has 12 steps (`STEP_TOTAL=12`, line 28, printed by `say()` at lines 45–50). The main calls:

| # | Stage | Where | What it does |
|---|---|---|---|
| 1–2 | Find data, label status | train_models.sh:245–431 | sha256 registry of trained files (line 249); label status via `features.eda_data` (line 431) |
| 3 | Data EDA | train_models.sh:485 | `features.eda_data` reports PSI/KS shift from labelled to unlabelled data (eda_data.py:475) |
| 4 | Convert logs and PCAPs | train_models.sh:527, 546 | `features.extractor`; PCAPs get `--pcap-label`, or stay unlabelled until step 8 |
| 5 | Merge and clean | train_models.sh:578 | `ingest.merge` + `ingest.cleaning` (RFC 1035 limits, packet-copy removal; settings.yaml `cleaning`) |
| 6 | Feature EDA | train_models.sh:602 | `features.eda` |
| 7–8 | Label + provenance guard | train_models.sh:630 | `ingest.labeling`, behavioural labelling functions (settings.yaml `labeling`) |
| 9 | Shared split | train_models.sh:690 → prepare_split.py | `splits._time_split` (splits.py:123): per class, time-ordered, 72/14/14; the old test rows stay frozen (prepare_split.py:10) |
| 10 | Path A | train_models.sh:706 → path_a.py | RF n_estimators=200, balanced (path_a.py:212); HGB lr 0.1, max_iter 300, early stopping, balanced (lines 223–224); validation cut into a calibration half and a threshold half (line 484); isotonic calibration if there are ≥200 rows (line 132); `threshold_for_fpr` at `path_a_max_fpr` (line 492); gate `rf_gbt` only if its recall beats `rf_only` (line 497); test twin share reported (line 446) |
| 11 | Path B | train_models.sh:720 → path_b_train.py | `--model iforest` → `fit_iforest` (path_b_predict.py:59) on benign windows of 20; threshold at the 99th percentile of benign validation scores (path_b_train.py:118–131) |
| 12 | Fusion | train_models.sh:754–758 → train_fusion.py | logistic regression V1 (stacker.py:87–89, balanced), confidence tiers, optional V2; `max_fpr` from settings (train_fusion.py:108) |
| — | Metadata | train_models.sh:790–815 | counts, seed, split manifest + **split_sha256**, Path B type, file registry |

**Guards and tooling that already exist:**
- `FORBIDDEN_FEATURES` (dns_parser.py:76–79) is checked when the module is imported (`check_model_features`, lines 82–91), for both paths.
- Rule baselines: `baselines.py` has a record-type rule (line 29), entropy and length thresholds (lines 99–107) and a literature entropy rule (line 107).
- Drift monitoring: PSI against the training snapshot (monitor.py:46, 99–155), with bands at 0.10 and 0.25 (lines 42–43).
- Multi-seed: `run_multiseed.py` (seeds 42–46 by default, line 90).
- Grouped and leave-one-family-out splits exist (`grouped_split`, splits.py:62; strategies listed at line 9), but they are not the default.

---

## 3. Phase 1: the known facts, confirmed or corrected

| Fact from the prompt or earlier chat | Status |
|---|---|
| 12 steps; shared split 72/14/14 per class, time-ordered; test frozen | **Confirmed** (train_models.sh:28; splits.py:123–148; prepare_split.py:10) |
| RF 200 balanced + HGB (0.1 / 300 / early stopping / 0.15 / balanced); isotonic calibration; threshold at 0.1% FPR; gate `rf_only`/`rf_gbt` | **Confirmed** (path_a.py:212–224, 132, 492, 497). Correction: calibration falls back to sigmoid below 200 calibration rows (line 132). |
| Path B: Isolation Forest, 99th-percentile threshold, windows of 20 | **Confirmed** (path_b_predict.py:59; path_b_train.py:118–131; settings.yaml `path_b_window_size: 20`). Correction: the default is still `trafficformer` (path_b_train.py:165); Isolation Forest needs `--path-b-model iforest`. |
| Forbidden features are enforced | **Partly.** There is a runtime check at import, but **no test** asserts it (no test references `check_model_features`). |
| Each run records the split hash and seed | **Confirmed** (train_models.sh:798–801). **Missing:** git commit, pip freeze and per-file data checksums in the run folder. The sha256 registry exists (line 249), but it is not copied into the run. |
| The model learns incrementally | **Wrong.** Each run refits from scratch. `--retrain` trains on new files only. |
| v3 meets the 0.1% budget | **Wrong on later data** (Reported): 0.35–0.59% in leave-one-tool-out and 0.6% on the frozen test set. |
| The latest test set can show 0.1% FPR | **No.** With 1,168 benign test rows, one false alarm is already 0.086%. A 95% upper bound at or below 0.1% needs about 3,000 benign rows with zero false alarms (rule of three). See §4, F4. |

---

## 4. Phase 2: research findings

| # | Topic | Best practice (source) | What it means here |
|---|---|---|---|
| F1 | Evaluation pitfalls in security ML | Arp et al. studied 30 top-tier papers and found these pitfalls widespread; they also show how single pitfalls produce unrealistic results [1]. The pitfalls include sampling bias, data snooping, spurious correlations, a missing baseline and an inappropriate threshold. | The project already handles spurious correlations (`FORBIDDEN_FEATURES`) and baselines (`baselines.py`). The open risks are **near-duplicate leakage** (92% duplicate vectors) and a threshold chosen on too few benign rows. |
| F2 | Time and space bias | TESSERACT names two biases. Temporal bias comes from train/test splits that break time order. Spatial bias comes from data distributions that don't match deployment [2][3]. It argues that k-fold cross-validation inflates results by bringing future knowledge into training [4]. | The per-class time split avoids future leakage *within* a class. But benign and attack rows come from different years (splits.py:128–130). And the test set has 55% attack, far above real DNS. Any reported FPR or precision should be restated at a realistic base rate. |
| F3 | Drift detection and rejection | Transcend uses conformal evaluation to spot an ageing model before its accuracy collapses [5]. Its follow-up describes classification with rejection: likely-wrong samples are quarantined for an expert instead of auto-labelled [6]. The Transcend paper also notes a trade-off: retraining too often adds little new information [7]. | PSI drift exists (monitor.py), but nothing links it to an action. A cheap first step is a "review" band near the threshold, sent to the triage queue, plus a drift-triggered retrain *proposal*, not an automatic retrain. |
| F4 | Threshold and FPR under low base rates | scikit-learn's `TunedThresholdClassifierCV` tunes a cut-off by cross-validation and warns against tuning it on the data the model was fitted on [8]. Work on SOC alert streams notes that, at low prevalence, even a low FPR creates a large investigation load, and that F1 hides this [9]. | The threshold is already set on a separate half (path_a.py:484), which is correct. **Gap:** the FPR is reported as a point value. It should come with a confidence interval, and a warning when the benign test count is too small for the 0.1% budget. (The rule of three is standard statistics, not from these sources.) |
| F5 | Feedback and active learning | Sandia's alert-triage study found that uncertainty sampling clearly beat passive learning and needed fewer labels on real SOC alerts [10]. A Google framework uses investigation results as a continuous feedback loop to tune its model [11]. | Verdict export exists (export_feedback_labels.py), but no run has used it. The cheapest step is adding reviewed verdicts as a trusted labelled source with provenance, then measuring false alarms per rule (Week 6 next step 5). |
| F6 | Generalisation to unseen tunnels and evasion | Recent DNS-tunnel work names robustness to unseen tools as an open gap [12]. Engineered-feature models need retraining when attackers change encoding [13]. A TU Delft thesis found anomaly detectors generalise better to unseen threats, while classifiers win on seen threats [14]. Studies of tool-parameter changes show detection rates can be overly optimistic [15]. | This supports keeping Path B unsupervised beside Path A. Leave-one-tool-out already exists (run_cv.py). `make_evasion_set.py` exists, but results on it are not in the Week 6 report. Re-running it as a standing check is cheap. |
| F7 | Reproducibility and reporting | Model cards record intended use, evaluation procedure and results broken down by subgroup [16][17]. The ML reproducibility checklist asks for error bars, seeds and how hyper-parameters were chosen [18]. Kapoor & Narayanan's model info sheets target data leakage [19]. Google's Rules of ML: start with metrics and a heuristic baseline, and watch for training-serving skew [20][21]. | Seeds, mean ± sd and split hashes are present. **Missing:** git commit, pip freeze, data checksums, and per-family / per-source results in one model card per run. Training-serving skew is partly covered: features come from the same `dns_parser`, but there is no test that inference and training produce identical vectors. |
| F8 | Explanations (optional) | TreeSHAP computes exact Shapley values for tree ensembles in polynomial time [22]. Lundberg et al. also used it to monitor a deployed model by finding the features that hurt it over time [23]. | "Why it fired" is currently a deviation from the client's baseline (Week 6 limits). TreeSHAP on the RF would give real attribution, but it adds a dependency (`shap`). |

---

## 5. Phase 3: gap table

| Gap | Evidence | Risk if left | Effort |
|---|---|---|---|
| G1 No git commit, pip freeze or data checksums per run; merged data not copied into the run | train_models.sh:790–815; hard rule | Results can't be reproduced or defended | S |
| G2 No test for `FORBIDDEN_FEATURES` | no test references it | A future feature edit silently brings back the shortcut | S |
| G3 No written success criteria and no single compare gate (candidate vs current `models/` vs rule baseline, ≥3 seeds) | run_multiseed.py and baselines.py exist separately | Improvements claimed from a single run | M |
| G4 FPR reported without a confidence interval; benign test too small for 0.1% | 1,168 benign test rows (latest run) | 0.1% claims that can't be checked | S |
| G5 Duplicate vectors cross train and test in the default time split | 92% duplicates; twin share only printed (path_a.py:446) | Optimistic test metrics (F1 pitfall) | S–M |
| G6 No "train on earlier, test on later" check for benign data | splits.py:128–130 per-class cut; drift 0.35–0.59% | Threshold drift stays unmeasured until deployment | M |
| G7 Feedback labels are never used | export_feedback_labels.py only | The SOC loop never improves the model | M |
| G8 Drift has no action and there's no reject band | monitor.py ends at a report | Silent ageing | M–L |
| G9 No model attribution | Week 6 limits | Weaker explanations for analysts | M (new dependency) |

---

## 6. Phase 3: proposed items (pick up to 8)

These are numbered 1–8 in my order of priority. I didn't have the exact a–h candidate labels from your prompt in front of me, so map them by name. Each item changes one thing and is tested on validation data. The frozen test sets are used only for the final comparison.

| # | Item | Closes | What I would build | Test that proves it | Success criterion | Run cost |
|---|---|---|---|---|---|---|
| 1 | **Run record** | G1 | `scripts/run_record.py`, called at the end of train_models.sh and the GUI adapter. It writes `run_record.json` (git commit + dirty flag, `pip freeze`, sha256 of every input file, split sha256, seed) and copies `merged_features_labeled.json` into the run folder. | unit test with a temporary repo; the GUI run folder contains both files | every new run folder has a complete record | none |
| 2 | **Forbidden-feature test** | G2 | `tests/test_forbidden_features.py`: PATH_A/PATH_B lists and the saved `model_meta.json` feature lists contain none of `FORBIDDEN_FEATURES`; `check_model_features` raises on a bad list | the test itself | passes; fails if `client_ip` is added | none |
| 3 | **Success criteria + compare gate** | G3 | `config/success_criteria.yaml` (e.g. recall ≥ current, benign FPR ≤ current and ≤ 0.1% upper bound, beats every `baselines.py` rule) and `scripts/compare_models.py`. It reads ≥3 seed runs, the current `models/` (read only) and the rule baseline, and prints mean ± sd with PASS/FAIL. | unit test on fixed metric files | a gate report per candidate | uses existing runs |
| 4 | **FPR intervals** | G4 | Clopper–Pearson 95% interval for FPR and recall in Path A, fusion and the GUI metrics; a warning when the benign test count is under 3/max_fpr | unit test on known counts (0/3000 → upper bound ≈ 0.1%) | every report shows the interval | none |
| 5 | **Twin-aware metrics** | G5 | report test metrics twice: all rows, and rows **without** an exact twin in train (the grouping already exists: `feature_vector_key`) | unit test on a toy split | the two numbers are shown; the gap is recorded | Isolation Forest run, minutes |
| 6 | **Later-benign check** | G6 | evaluation-only script: score benign data captured after the training data (e.g. CIC capture 3 or new Technitium logs) with a candidate and report FPR + interval, TESSERACT-style by month if timestamps allow | test on synthetic dated data | drift measured per period | minutes |
| 7 | **Feedback labels as training input** | G7 | accept `data/feedback/labels_*.csv` as a trusted source in labeling (provenance `analyst_verdict`, reviewed flag required); compare false alarms per rule before and after, using the gate in item 3 | unit test: unreviewed rows are refused | fewer FPs on validation without losing recall, ≥3 seeds | 3 × Isolation Forest runs |
| 8 | **Review band + drift proposal** | G8 | scores within a margin of the threshold → `review` tier in the bridge output (no change to alarms); major PSI → a "retrain proposed" entry in /health, never automatic | unit tests on the bridge tiers | the tier appears; alarm counts are unchanged | none |

Left out of the 8, available on request: TreeSHAP attribution (G9, needs `shap`), and re-running the evasion set and leave-one-tool-out on the new bundle.

**My recommendation for the first wave:** items 1, 2, 3, 4, 5. They are small, need no long runs, and make every later claim checkable. Then items 6 and 7.

**Expected run time (Assumption):** with Isolation Forest on the current bundle, about 4 minutes per run (the latest run took 3 min 57 s), so 3 seeds take about 12–15 minutes. Nothing planned is near 1 hour. Re-training full v3 would be, and I'd ask first.

---

## 7. What I need from you

1. **Pick the items** (numbers from §6).
2. **Create a branch** before I change code. In PowerShell, in `C:\Programming-CTF\Capstone`, run `git switch -c ml-improvement`. Git can't create its lock files reliably from my side.
3. **Confirm the data for evaluation:** is the `labelled_v3` bundle the reference dataset, or do you want to restore the v3 data (8 tools) first? Results between the two are not comparable.

I won't write to `models/`, push, merge or modify `data/raw`, `data/external` or `Dataset/`.

---

## 8. References

1. Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security 2022. https://www.usenix.org/conference/usenixsecurity22/presentation/arp · arXiv:2010.09470
2. Pendlebury et al., *TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time*, USENIX Security 2019. https://usenix.org/conference/usenixsecurity19/presentation/pendlebury
3. Kan et al., *TESSERACT … (Extended Version)*, arXiv:2402.01359. https://arxiv.org/html/2402.01359v2
4. TESSERACT poster paper. https://s2lab.cs.ucl.ac.uk/downloads/tesseract-poster-paper.pdf
5. Barbero et al., *Transcending Transcend*, arXiv:2010.03856. https://arxiv.org/pdf/2010.03856
6. Barbero et al., arXiv abstract. https://arxiv.org/abs/2010.03856v1
7. Jordaney et al., *Transcend: Detecting Concept Drift in Malware Classification Models*, USENIX Security 2017. https://s2lab.cs.ucl.ac.uk/downloads/sec17-jordaney.pdf
8. scikit-learn, `TunedThresholdClassifierCV`. https://scikit-learn.org/1.9/modules/generated/sklearn.model_selection.TunedThresholdClassifierCV.html
9. arXiv:2605.22324 (adaptive alert screening under low prevalence). https://arxiv.org/html/2605.22324v1
10. Doak et al., *Active Learning for Alert Triage*, ICMLA 2013. https://www.osti.gov/servlets/purl/1115032
11. Momeni et al., *Democratizing ML for Enterprise Security*, arXiv:2512.08802. https://arxiv.org/pdf/2512.08802v1
12. *DNS-HyXNet*, arXiv:2512.09565. https://arxiv.org/pdf/2512.09565
13. Same as [12].
14. TU Delft thesis on ML detection of covert DNS storage channels. https://repository.tudelft.nl/file/File_e4d46d15-c2e3-43f6-afff-c821da32c8c9
15. *DNS exfiltration detection in the presence of adversarial attacks and modified exfiltrator behaviour*, Int. J. Inf. Security. https://link.springer.com/article/10.1007/s10207-023-00723-w
16. Mitchell et al., *Model Cards for Model Reporting*, FAT* 2019. https://arxiv.org/abs/1810.03993v2
17. CASRAI summary of model cards. https://casrai.org/wp/tag/model-cards/
18. CLEVA-Compass, summarising the Pineau et al. reproducibility checklist. https://arxiv.org/pdf/2110.03331
19. Kapoor & Narayanan, *Leakage and the Reproducibility Crisis in ML-based Science*. https://arxiv.org/pdf/2207.07048
20. Zinkevich, *Rules of Machine Learning*, Google. https://developers.google.com/machine-learning/guides/rules-of-ml/
21. Same as [20].
22. Lundberg et al., *Explainable AI for Trees*, arXiv:1905.04610. https://arxiv.org/pdf/1905.04610
23. Same as [22].

Dataset licence reminder: DNSTunnel2026 (Zenodo 10.5281/zenodo.20137065) is CC BY 4.0, so cite it if it's used. CIC datasets follow their own terms.
