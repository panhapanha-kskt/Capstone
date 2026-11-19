# Path B Report: Isolation Forest in production, measured honestly

**DNS Traffic Anomaly Detection · Capstone · started 2026-11-19**

This report covers the Path B production tasks:

| Task | What |
|---|---|
| T2 | Promotion |
| T9 | Error ranges |
| T4 | Seed spread |
| T3 | 0.1% target |
| T6 | Research items 6–8 |
| T7 | Feedback retraining |

Every table has the one-line **record-type rule** (TXT/KEY/NULL) as a baseline, because the data is known to be too easy.

| Task | Status |
|---|---|
| Mentor approval of the Isolation Forest Path B | ✅ 2026-11-17 |
| T2 Promote `runs/v3_iforest` to `models/` | ✅ 2026-11-19 |
| T9 Error ranges for Path B and every detector | ✅ 2026-11-19 |
| T4 Seed spread | ✅ cause found and fixes measured (§5); setting still to choose |
| T3 0.1% false-alarm target | after T4 |
| T6 Items 6–8 | after T3; item 6 needs a newer benign capture |
| T7 Retraining on feedback | blocked: 2 verdicts, one a test record (stop condition: < 50) |

---

## 1. T2: promotion record

| Item | Value |
|---|---|
| Source | `runs/v3_iforest`, trained 2026-11-14 on the Kali VM `ounnha` (seed 42, 218,334 rows, 8 tunnel tools, 39 min 5 s) |
| Route | **copied** from the VM; it was not retrained. `tar` + `scp`, archive SHA-256 `ae717a04f4cf91286116f865e7827ccc4383fd7ab816de6083ae35ae0142ed26`, identical on both ends |
| Schema check | Path B: the 11 features in `dns_trafficformer_norm.json` equal the live `PATH_B_FEATURES` (names and order). Path A: `dns_threshold.json` features equal `PATH_A_FEATURES` |
| Archive | old autoencoder models → `models/archive/autoencoder_pathB_2026-11-19_080310/` (24 entries, nothing deleted, kept out of git) |
| Copy | 16 files by `scripts/promote_model.sh`, each SHA-256 re-checked after copying → `models/PROMOTED.json`; per-file hashes in `models/MODEL_CARD.md` |
| Loader | unchanged: `load_model_artifacts` already picks the Isolation Forest from `"model_type": "iforest"` in the threshold file |
| Smoke test | `scripts/smoke_models.py --models models --reference runs/v3_iforest` on your machine: **7/7 PASS**. Model type and both feature lists match, and Path A and Path B scores on 5,000 rows are identical to the run folder |
| Git | commit `3ed0cce`, merged to `main` (`b204085`) |

**Not done yet:** a startup check inside the live bridge that refuses to run when the saved feature list differs from the code. Today that check exists in `smoke_models.py` and in the tests, not at bridge start-up. It's a small follow-up.

---

## 2. T9: how the error ranges are computed

Code: `src/dns_detect/models/uncertainty.py`; script: `scripts/evaluate_detectors.py`; tests: `tests/test_uncertainty.py` (9 tests).

For each run, the frozen test rows are scored the same way the fusion was trained (`train_fusion.score_dataset`). Four detectors are scored: fusion, Path A, Path B, and the record-type rule.

| Measure | Method |
|---|---|
| Point metrics | recall, FPR, precision, F1, PR-AUC, ROC-AUC, false alarms; **recall at FPR = 0.1%** (descriptive: the best cut-off on the same rows, an upper bound, never an operating point) |
| Exact intervals | 95% Clopper–Pearson for FPR and recall (same as Path A and fusion since 2026-11-18); Wilson for FPR alongside |
| Bootstrap | 1,000 resamples, 95% percentile intervals, **cluster bootstrap by parent domain**: whole domains are resampled, benign and attack groups separately, so near-duplicate queries move together |
| Seed spread | mean ± sd, min–max of each metric over training seeds |

The exact interval treats every query as independent. The cluster bootstrap doesn't. Where they differ a lot, the queries aren't independent: false alarms cluster on a few domains.

All metrics here are **per query**. Path B's own training report counts per **window** of 20 queries (now with ranges too: `count_unit: "window"`), so its numbers there differ from these.

---

## 3. T9 results (Observed, 2026-11-19)

Raw output: `runs/t9_labelled_v3.{json,md}` and `runs/t9_v3_iforest.{json,md}`.

Every run is scored on the same frozen test set: 2,568 rows, 1,168 benign and 1,400 attack. The 95% exact intervals are Clopper–Pearson; the bootstrap is by parent domain.

### 3.1 `v3_iforest` (the model now in `models/`)

| Detector | Recall | False alarms | FPR | FPR exact | FPR bootstrap | F1 | PR-AUC | Recall @ FPR 0.1% |
|---|---|---|---|---|---|---|---|---|
| Fusion | 100% | 8 | 0.68% | 0.30–1.35% | 0.00–2.32% | 0.997 | 1.0 | 100% |
| Path A | 100% | 10 | 0.86% | 0.41–1.57% | 0.00–2.75% | 0.996 | 1.0 | 100% |
| **Path B (Isolation Forest)** | 100% | **113** | **9.67%** | 8.04–11.52% | 5.84–14.64% | 0.961 | 1.0 | 100% |
| Record-type rule | 100% | **0** | 0.00% | 0.00–0.32% | 0.00–0.00% | 1.000 | 1.0 | 100% |

All recall intervals are 99.74–100% (exact).

### 3.2 `labelled_v3`, 3 seeds (2 tunnel tools)

| Detector | False alarms per seed (42 / 43 / 44) | Seed spread (mean ± sd, min–max) | FPR exact, widest seed | FPR bootstrap, widest seed |
|---|---|---|---|---|
| Fusion | 13 / 16 / 2 | 10.3 ± 7.4 (2–16); FPR 0.88% ± 0.63% | 0.78–2.22% (s43) | 0.00–4.07% (s43) |
| Path A | 8 / 16 / 1 | 8.3 ± 7.5 (1–16); FPR 0.71% ± 0.64% | 0.78–2.22% (s43) | 0.00–4.07% (s43) |
| **Path B** | 279 / 272 / 251 | **267 ± 15 (251–279); FPR 22.9% ± 1.3%** | 21.47–26.44% (s42) | 12.21–38.03% (s42) |
| Record-type rule | 0 / 0 / 0 | 0 | 0.00–0.32% | 0.00–0.00% |

Recall was 100% on every detector and seed.

### 3.3 What the numbers say

1. **Path B is stable across seeds but far too noisy.** It flags 22.9% ± 1.3% of benign queries on `labelled_v3` and 9.7% on v3. Its own threshold (99th percentile of benign validation *windows*) doesn't control the per-query false-alarm rate.
2. **Path B's ranking is perfect on this test set.** ROC-AUC and PR-AUC are 1.0, and recall at FPR 0.1% is 100%. Every attack scores above every benign query, so the problem is **where the threshold sits, not the model**. That makes T3 promising for Path B, but only on this easy test set (see 4).
3. **Path A and the fusion are seed-unstable; Path B isn't.** All the 2–16 spread comes from Path A, and the fusion follows Path A (§3.4).
4. **The test set is too small to support general claims:**
   - All 1,400 attack rows belong to **one parent domain** (`daumel.xyz`, `labelled_v3`). The benign rows come from 33–35 domains.
   - So the recall bootstrap can't vary ([100%, 100%]), and recall says nothing about other tunnels. Leave-one-tool-out (Week 5) is the evidence for that.
   - The FPR bootstrap is much wider than the exact interval (fusion 0–4.07% vs 0.78–2.22%), because the false alarms sit in 1–2 domains.
5. **The record-type rule is perfect on every run.** It beats every model on F1 and false alarms, so the dataset can't show the models are needed (item 5: harder data).
6. **Re-scoring v3_iforest on this machine gives slightly different counts than its training report:**

   | Detector | At training (Kali VM) | Re-scored here |
   |---|---|---|
   | Fusion | 7 | 8 |
   | Path A | 8 | 10 |
   | Path B (per query) | 104 | 113 |

   The `labelled_v3` runs, trained on this machine, reproduce exactly (fusion 13 / 16 / 2). The difference is most likely the library versions: v3 was trained on the VM, and this machine has scikit-learn 1.9.1 and pandas 3. That's **not verified**. Compare `pip freeze` on the VM to confirm.

### 3.4 Where the false alarms come from (fusion and Path A, test rows)

| Run | Fusion false alarms by domain | Path A false alarms by domain |
|---|---|---|
| labelled_v3 s42 | vsassets.io 7, io.localdomain 6 | io.localdomain 6, vsassets.io 2 |
| labelled_v3 s43 | vsassets.io 10, io.localdomain 6 | vsassets.io 10, io.localdomain 6 |
| labelled_v3 s44 | io.localdomain 2 | io.localdomain 1 |
| v3_iforest | io.localdomain 7, safebrowsing.googleapis.com 1 | io.localdomain 8, safebrowsing.googleapis.com 2 |

**Path B's false alarms are spread across normal services:** anthropic.com 79–83, microsoft.com 23–29, vsassets.io 24, hcaptcha.com 23–24 (`labelled_v3`); microsoft.com 18, anthropic.com 16, hcaptcha.com 16 (v3).

**For T4:** the seed spread is almost entirely whether the seed's Path A threshold lands above or below the **vsassets.io** queries (0–10 alarms). **io.localdomain** (1–8) alarms in every run. These two domains are where to look first.

---

## 4. Limits of these results

- One frozen test set of 2,568 rows, with all attacks from one parent domain. Numbers here say little about other tunnels or other networks.
- There's no "later normal traffic" set on this machine (T6 item 6 needs one).
- Splits are time-ordered per class but **not grouped by domain** in the default pipeline, so near-duplicate rows of a domain can sit in train and test (see the twin-free numbers in `ML_IMPROVEMENT_IMPLEMENTATION_2026-11-19.md`).
- Path B's per-query FPR depends on how a window's score is assigned to queries (each window scores its last query); the first 19 queries of a client get no Path B score.

---

## 5. T4: seed spread (20 seeds, Observed 2026-11-19)

All runs use `labelled_v3`: same data, same frozen split (sha256 `ff91ee2e…`), seeds 42–61, Isolation Forest Path B. Raw output: `runs/t4_before_20seeds.{json,md}`, `runs/labelled_v3_iforest_gate.json`.

### 5.1 Before: one model per seed

False alarms out of 1,168 benign test rows.

| Detector | False alarms (mean ± sd) | Min–max | FPR | Recall |
|---|---|---|---|---|
| Fusion | 9.85 ± 5.53 | 1–18 | 0.84% ± 0.47% | 100% every seed |
| Path A | 8.60 ± 5.34 | 1–18 | 0.74% ± 0.46% | 100% every seed |
| Path B | 268.3 ± 13.3 | 246–287 | 22.97% ± 1.14% | 100% every seed |
| Record-type rule | 0 | 0–0 | 0.00% | 100% |

**Gate (20 seeds): FAIL.**
- Passed: seeds, same split, recall floor, recall and false alarms vs the current `models/` (9.85 vs 10.00 on the same rows).
- Failed: the FPR budget (0.84% vs 0.1%) and the rule baseline (record-type F1 1.0 on every seed).

### 5.2 Cause: the model, on benign domains it never saw (not the threshold)

| Check | Result |
|---|---|
| Validation false-alarm rate | **0.0% on all 20 seeds** (7,357 benign validation rows): validation is perfectly separable, so the threshold has nothing to calibrate against |
| Path A threshold across seeds | 0.48 ± 0.05 (0.34–0.55); 0.5 on most seeds (the middle of the empty gap) |
| Threshold vs test false alarms | correlation 0.29; seeds with the same threshold 0.5 range from 4 to 18 false alarms |
| Where the false alarms are | over the 20 seeds, Path A raised 172 false alarms on only **18 distinct benign rows**: 12 `vsassets.io`, 6 `io.localdomain` |
| Those domains in train / validation / test | `vsassets.io` 0 / 0 / 24 rows; `io.localdomain` 0 / 0 / 10 rows: **test only** |
| What they are | VS Code extension downloads (`<publisher>.gallerycdn.vsassets.io`) and the same names with the resolver's search suffix (`….vsassets.io.localdomain`): long, random-looking subdomains |
| Unseen benign domains in the test set | 12 of 33 test benign domains never appear in training |

**Conclusion:** the spread is training randomness in how each Random Forest scores a few unfamiliar benign names, not the threshold position. Choosing the threshold on more validation rows can't help, because validation already has 0 false alarms. Allowlisting the two domains would be tuning to the test set, so it isn't done.

### 5.3 Fixes tried (Path A, using the 20 existing models, no retraining)

Each row combines K seed models, drawn at random 300 times. Thresholds are each seed's own **validation** threshold (score averaging uses their mean); nothing is chosen on the test set.

| Method | K | False alarms (mean ± sd) | Min–max | Recall |
|---|---|---|---|---|
| Single model (before) | 1 | 8.60 ± 5.34 | 1–18 | 100% |
| Average Path A score | 3 | 7.29 ± 2.66 | 4–16 | 100% |
| Average Path A score | 5 | 6.90 ± 1.90 | 5–14 | 100% |
| Average Path A score | 10 | 6.41 ± 1.06 | 5–11 | 100% |
| Majority vote | 5 | 7.30 ± 2.65 | 4–18 | 100% |
| Majority vote | 11 | 6.36 ± 1.04 | 5–13 | 100% |
| Fusion, majority vote | 11 | 8.47 ± 2.73 | 6–14 | 100% |

**What it shows:**
- **Combining seeds removes most of the spread** (sd 5.3 → about 1 at K = 10–11). The **mean** falls only from 8.6 to about 6.4, with a floor of about 5–6 false alarms that every combination keeps. Those are the `vsassets.io` / `io.localdomain` rows that most seeds find tunnel-like.
- **Fixing the floor needs data:** benign CDN and extension-download names in training. That's Week 7 Task 2.
- **Cost:** Path A inference about K× slower, and training K× longer.
- A Random Forest is itself an average of trees, so **one forest with K × 200 trees** should behave close to the K-seed average at the same cost and with one model file. That's **not tested yet**; it needs one training setting (`n_estimators`) and a 3–5-seed run.

### 5.4 Decision

| Item | Status |
|---|---|
| Chosen method | **not set yet.** Candidate: Path A with 1,000 trees (≈ 5-seed average); test over ≥ 3 seeds and keep it only if the seed sd falls as in §5.3 at acceptable training time |
| Why not ship score averaging now | it needs 5–10 model copies in `models/` and changes to the loader; one bigger forest is simpler if it works |
| The real fix | Week 7 Task 2 (harder, more varied benign data) and Task 3 (domain-grouped split) |
