# Week 7: Next Tasks

**DNS Traffic Anomaly Detection · ML / model work for Week 7 · written 2026-11-19**

This file lists the Week 7 tasks, in order: nine ML tasks (1–9) and five dashboard, verdict and documentation tasks (10–14) carried over from the Week 6 audits. For each task it gives:
- why it matters, with sources;
- what already exists in the code;
- the steps and commands;
- what "done" means.

All time estimates are guesses, not measurements.

**Read first:**
- [../Week6/PATH_B_REPORT.md](../Week6/PATH_B_REPORT.md): Path B promotion and the T9 error ranges.
- [../Week6/ML_IMPROVEMENT_IMPLEMENTATION_2026-11-19.md](../Week6/ML_IMPROVEMENT_IMPLEMENTATION_2026-11-19.md): items 1–5, the 3-seed gate.
- [../Week6/ML_IMPROVEMENT_RESEARCH_2026-11-19.md](../Week6/ML_IMPROVEMENT_RESEARCH_2026-11-19.md): the research behind the evaluation rules.

---

## Progress (updated 2026-11-20 01:00)

| Task | Status | Evidence |
|---|---|---|
| 1 · T4 light: seed spread | ✅ **done** | 20 seeds trained and scored. Cause found: the false-alarm domains appear only in the test set. Seed averaging and voting measured. Optional extra, not required: a 1,000-tree Path A. See [PATH_B_REPORT §5](../Week6/PATH_B_REPORT.md) |
| 2 · Harder data | ❌ not started | **your next job:** captures (normal TXT/MX/SRV + VS Code/CDN; tunnels over A/CNAME on several domains) |
| 3 · Domain-grouped split | ⏸ waiting for Task 2 | needs ≥ 3 attack domains |
| 4 · Later-traffic check | ⏸ waiting | needs a fresh normal capture |
| 5 · T3: 0.1% target + operating point | ⏸ waiting for Tasks 1–3 | — |
| 6 · Drift warning | ❌ not started | feature PSI already exists in `monitor.py`; score PSI and saved bins to add |
| 7 · Review band | ❌ not started | tiers already exist in the bridge; budget-based band and `/triage` routing to add |
| 8 · Schema check at start-up | ✅ **done** | `src/dns_detect/models/schema.py`; used by the bridge, `run_pipeline.sh` and `promote_model.sh`; 12 tests |
| 9 · Automate Part B (seeds → gate → promote) | ❌ not started | added 2026-11-20; `run_candidate_seeds.sh` already trains the seeds and calls the gate, but throws away the gate result (`\|\| true`) and never promotes |
| 10 · Verdict fixes F1–F5 + F8 | ✅ **done** (2026-11-20) | F1 unknown alerts → 404 (single and bulk); F2 "Clear verdict" in `/alerts` (drawer + bulk) and `/triage`, audited `VERDICT_CLEARED`; F3 in-flight guards; F4 same verdict = no-op; F5 no records from rejected requests; F8 `--demo` sets the training API to demo mode. Test record removed (backup kept, audited `RECORD_REMOVED`). `tests/test_dashboard_verdicts.py` 12 tests; 56 dashboard + 57 console tests pass |
| 11 · Dashboard real-mode testing | ❌ not started | only demo mode tested; no browser click-through (Chrome on Windows could not reach the WSL server); no Elasticsearch/Kibana export test |
| 12 · Verdicts → training (plumbing only) | ❌ not started | `export_feedback_labels.py` exports verdicts; training never reads them (flow map gap 23). Needs Task 10 first |
| 13 · SOC roadmap P0 | ❌ not started | missing: role landing pages, "Assigned to me" / "Unassigned" filters, playbook button, attachments, MITRE tactic × technique page |
| 14 · Out-of-date docs | ✅ **done** (2026-11-20) | `WEEK6_COMPLETE_REPORT.md` §12 names commit `277a12a`; new §16 covers the 11-18/19 work; `PATH_B_ISOLATION_FOREST.md` §8 has the measured seed spread (v3 8.2 ± 0.84; labelled_v3 20 seeds 9.85 ± 5.53) |

### Done this week (all pushed to `pathb-production`)

| Date | Work | Commit |
|---|---|---|
| 2026-11-19 | Mentor approval of the Isolation Forest Path B recorded in the Week 6 reports | `e553b8f` |
| 2026-11-19 | `runs/v3_iforest` copied from the Kali VM (archive SHA-256 verified) and **promoted to `models/`**: autoencoder archived, `MODEL_CARD.md`, `PROMOTED.json`, smoke test 7/7 | `3ed0cce` → `main` `b204085` |
| 2026-11-19 | **T9 error ranges** for every detector: exact Clopper–Pearson / Wilson, a 1,000-sample domain-cluster bootstrap, and seed spread (`uncertainty.py`, `evaluate_detectors.py`, 9 tests) | `e553b8f` |
| 2026-11-19 | Week 7 plan written with 23 primary-source references | `683c5f3` |
| 2026-11-19 | **20-seed run** on `labelled_v3`: fusion 9.85 ± 5.53 false alarms (1–18), recall 100%; gate FAIL (0.1% budget; rule baseline) | `683c5f3` (report) |
| 2026-11-19 | **T4 cause found:** validation FPR is 0 on all seeds; all Path A false alarms over 20 seeds are 18 benign rows from `vsassets.io` / `io.localdomain`, domains that appear only in the test set | `683c5f3` |
| 2026-11-19 | **Seed combining measured:** averaging 10 seeds → 6.4 ± 1.1 false alarms; majority vote of 11 → 6.4 ± 1.0; recall stays 100%. About 5–6 false alarms remain; they need data, not tuning | `683c5f3` |
| 2026-11-19 | **Isolation Forest is the default Path B** everywhere (`train_models.sh`, `path_b_train.py`, `run_multiseed.py`, training console); the autoencoder only on request | `683c5f3` |
| 2026-11-19 | **Task 8 schema check** at start-up (stops production on any feature mismatch) | `683c5f3` |

**Tests at the end of the day:** 282 ML + 101 dashboard and console tests pass. One test (`test_parent_domain_psl_private_suffixes`) needs `tldextract`, which isn't installed in my workspace.

### Next

1. **You:** Task 2 captures. Ask for the step-by-step capture guide.
2. **Me (no new data needed):** Task 6 (drift warning) and Task 7 (review band); optionally the 1,000-tree Path A test (needs one 3-seed run, about 15 min).
3. **After Task 2:** Tasks 3 → 4 → 5 on the new data.
4. **Quick wins first (no training):** Task 14 (docs, ~30 min) and Task 10 (verdict fixes) — Task 10 must come before any verdict is trusted as a label.
5. **Me (no new data needed):** Task 9, automate Part B (seeds → gate → promote) so `run_all.sh --retrain` never writes to `models/` without passing the gate.
6. **You + me:** Task 11 (real-mode dashboard and Kibana tests) needs your Technitium logs and the docker stack running.
7. **Then:** Task 12 (verdict plumbing), Task 13 (SOC P0 pages).

---

## Contents

1. [Where Week 6 ended](#1-where-week-6-ended)
2. [Rules for every task](#2-rules-for-every-task)
3. [Order and dependencies](#3-order-and-dependencies)
4. [Task 1: T4 light: cause of the seed spread and one stable threshold](#4-task-1-t4-light)
5. [Task 2: harder data](#5-task-2-harder-data)
6. [Task 3: a test set split by domain](#6-task-3-a-test-set-split-by-domain)
7. [Task 4: later-traffic check](#7-task-4-later-traffic-check)
8. [Task 5: T3: the 0.1% target and an operating point](#8-task-5-t3-the-01-target-and-an-operating-point)
9. [Task 6: drift warning](#9-task-6-drift-warning)
10. [Task 7: review band](#10-task-7-review-band)
11. [Task 8: feature-schema check at start-up](#11-task-8-feature-schema-check-at-start-up)
12. [Task 9: automate Part B: seeds, gate and promote](#12-task-9-automate-part-b-seeds-gate-and-promote)
13. [Task 10: verdict fixes F1–F5 and F8](#13-task-10-verdict-fixes-f1f5-and-f8)
14. [Task 11: dashboard testing in real mode](#14-task-11-dashboard-testing-in-real-mode)
15. [Task 12: verdicts into training (plumbing only)](#15-task-12-verdicts-into-training-plumbing-only)
16. [Task 13: SOC roadmap P0](#16-task-13-soc-roadmap-p0)
17. [Task 14: out-of-date docs](#17-task-14-out-of-date-docs)
18. [Not in Week 7](#18-not-in-week-7)
19. [Checklist](#19-checklist)
20. [References](#20-references)

---

## 1. Where Week 6 ended

| Item | State |
|---|---|
| Path B | Isolation Forest; mentor-approved 2026-11-17 |
| Live `models/` | `v3_iforest` promoted 2026-11-19 (8 tunnel tools, 218,334 rows); autoencoder archived; smoke test 7/7 |
| Fusion on the frozen test set | 8 false alarms / 1,168 benign (0.68%, exact 95% range 0.30–1.35%), recall 100% |
| Path B alone | 9.7% false alarms per query on v3; 22.9% ± 1.3% on `labelled_v3`. ROC-AUC 1.0, so the **threshold**, not the ranking, is the problem |
| Seed spread (`labelled_v3`, 3 seeds) | fusion 2–16 false alarms, all from Path A, on two domains: `vsassets.io` (0–10) and `io.localdomain` (1–8) |
| Record-type rule (TXT/KEY/NULL) | 0 false alarms, 100% recall: **beats every model** |
| Frozen test set | 2,568 rows; **all 1,400 attack rows from one parent domain**; benign from 33–35 domains |
| Analyst verdicts | 2 (one a test record) |
| 20-seed run for T4 | started 2026-11-19 15:28 (`runs/labelled_v3_iforest_s42`…`s61`) |

**What this means for Week 7:** the method is in good shape (multi-seed, error ranges, baselines, run records, gate). The **data** is the bottleneck. Tasks 2 and 3 matter more than any model change.

---

## 2. Rules for every task

These carry over from the Week 6 hard rules.

1. **Three separate sets.** Train, then calibration (thresholds and settings), then test, plus a later-traffic set after all of them. Never choose a threshold on the rows you report.
2. **Change one thing at a time,** and claim an improvement only if it holds over ≥ 3 seeds (`scripts/run_candidate_seeds.sh`, then `scripts/compare_models.py`).
3. **The record-type rule goes in every results table** (`scripts/evaluate_detectors.py` adds it). A simple baseline is one of Arp et al.'s main recommendations for ML in security [22].
4. **Every result has a run record:** git commit, packages, data hashes, split hash, seed (`scripts/run_record.py`, automatic).
5. **Never write to `models/` except through `scripts/promote_model.sh`,** after the gate passes and you decide.
6. **Tunnel tools run only in the isolated lab.** Never execute anything taken from an attack capture. Anonymise real DNS logs before sharing.
7. **If a target can't be met, say so and show the trade-off.** Don't change the evaluation until the numbers look good.

---

## 3. Order and dependencies

```
Task 1 (T4 light) ─────────────────────────────┐
Task 2 (harder data) ──► Task 3 (domain split) ─┼─► Task 5 (T3 on new data)
Task 4 (later traffic: needs a fresh capture) ──┘
Task 8 (schema check) ──► Task 6 (drift) ──► Task 7 (review band)
```

- Tasks 1 and 8 need no new data, so start them first.
- Task 2 is your capture work. Start it on day 1, because everything in the top row waits for it.
- Task 3 is **impossible on the current data:** there is only one attack domain (§6.1).
- Tasks 6–8 are pipeline and dashboard work and can run in parallel with data collection.

| # | Task | Needs | Your time | Machine time (guess) |
|---|---|---|---|---|
| 1 | T4 light | 20-seed run (running) | 1 h reading | about 80 min training + 10 min scoring |
| 2 | Harder data | lab captures | 1–2 days of captures | minutes per conversion |
| 3 | Domain split | Task 2 | 1 h | one 3-seed run, about 15 min |
| 4 | Later traffic | a capture after the training data | capture 1–3 days | minutes |
| 5 | T3 operating point | Tasks 1–3 | 2 h | 3-seed runs |
| 6 | Drift warning | Task 8 | 2–3 h | none |
| 7 | Review band | Task 6 | 2 h | none |
| 8 | Schema check | none | 1 h | none |
| 9 | Automate Part B | Task 8 (done) | 2–3 h | one 3-seed run to test it, about 15 min |
| 10 | Verdict fixes F1–F5, F8 | none | 2–3 h | none |
| 11 | Dashboard real-mode tests | Technitium logs, docker stack | 2–4 h | minutes |
| 12 | Verdicts → training plumbing | Task 10 | 2 h | none (no retrain until ≥ 50 verdicts) |
| 13 | SOC P0 pages | Task 10 for the verdict parts | 1–2 days | none |
| 14 | Out-of-date docs | none | 30–60 min | none |

---

## 4. Task 1: T4 light

**Goal:** explain the 2–16 seed spread and choose **one** threshold method that is stable across seeds, without tuning it to this test set.

### 4.1 Why

**Path A's threshold** (`threshold_for_fpr` in `src/dns_detect/models/thresholds.py`) is set on **half the validation rows** (`path_a.py`, the calibration half and the threshold half). With few benign rows, the cut-off moves with the seed: whether a group of `vsassets.io` queries lands just above or below it decides 0 or 10 false alarms.

An empirical threshold that meets the budget on the calibration rows is not guaranteed to meet it on new data. The Neyman–Pearson umbrella algorithm (Tong, Feng & Li 2018) controls the population false-alarm rate with high probability [1]. It needs a **minimum number of benign calibration rows**, which is exactly the issue here [2]. `thresholds.py` already implements it (`np_threshold`), and the fusion V2 uses it. Path A doesn't.

### 4.2 What exists

- 20 seeds training now; the 3 earlier seeds are in `runs/labelled_v3_iforest_s42..44`.
- `scripts/evaluate_detectors.py` reports per-seed false alarms, exact and bootstrap ranges, and seed spread.
- `np_threshold` and `InsufficientCalibrationError` are in `thresholds.py`.

### 4.3 Steps

1. **Score the 20 seeds** after training finishes:
   ```powershell
   bash -c "python3 scripts/evaluate_detectors.py --runs \$(for s in \$(seq 42 61); do echo runs/labelled_v3_iforest_s\$s; done) --out runs/t4_before_20seeds.json --md runs/t4_before_20seeds.md"
   ```
2. **Write the "before" table:** for each seed, the Path A threshold (from `dns_threshold.json`), validation false-alarm rate, test false alarms, and false alarms by domain. Report mean, sd, min and max.
3. **Find the cause, one factor at a time,** reading only training and validation data:
   - a. **Threshold position:** how many benign validation rows are in the threshold half? Does the threshold move more between seeds than the gap between `vsassets.io` scores and attack scores?
   - b. **Model randomness:** train with the threshold fixed to one seed's value. If the spread disappears, the cause is the threshold.
   - c. **The data split:** the split is fixed in this experiment, so it's not the cause here. State that.
4. **Try fixes in this order,** each as a separate 3-seed candidate, choosing on **validation** only:
   1. Set the threshold on **all** benign validation rows instead of half. Calibration stays on its half; only the threshold rows change, so check calibration and threshold don't overlap.
   2. Use `np_threshold` (Neyman–Pearson) for Path A with `delta = 0.05`. If there are too few benign rows, it raises `InsufficientCalibrationError`; record that rather than hiding it.
   3. Average the Path A score over K = 3 seeds (more stable scores, about 3× the Path A inference time; measure it).
5. **Pick one method:** the lowest seed sd on **validation** that keeps validation recall. Then run it once on the frozen test set, with 20 seeds.

**Done when:**
- PATH_B_REPORT has a T4 section with before/after tables (20 seeds each) and the cause stated with its evidence.
- The chosen method is a setting in `config/settings.yaml`.
- The inference cost is written down.
- **Not** done by deleting `vsassets.io` rows or adding it to an allowlist: that would be tuning to the test set.

---

## 5. Task 2: harder data

**Goal:** a dataset where the one-line record-type rule is **no longer perfect.** That needs normal traffic that uses the "tunnel" record types, tunnels that use normal record types, and tunnels from several domains.

### 5.1 Why

- **Normal traffic uses TXT, MX and SRV all the time:**
  - SPF records must be published as DNS TXT records, and receivers fetch them with TXT queries [3].
  - DKIM public keys sit in TXT records under `selector._domainkey` [4].
  - DMARC policies are TXT records at `_dmarc.<domain>` [5].
  - Mail delivery itself starts with an MX lookup.
  - Your benign data has none of this, so "TXT means attack" works only here.
- **Tunnels don't need TXT:**
  - iodine supports NULL, PRIVATE, TXT, SRV, MX, CNAME and A (returning CNAME), forced with `-T` [6].
  - dnscat2's default DNS driver uses `TXT,CNAME,MX`, and its `--dns` option sets the types (e.g. `type=A,CNAME`) [7].
- **One attack domain gives one test of generalisation:** every claim about "tunnels" is really about `daumel.xyz`.

### 5.2 Capture plan (isolated lab, Kali)

Use `scripts/capture_dns.sh` (full packets, hourly files) on the resolver or client during each session.

| # | Capture | How | Label | Target rows |
|---|---|---|---|---|
| B1 | Normal browsing and updates | normal use for 1–2 days (browser, `apt update`, VS Code, Windows updates) | benign | 20,000+ |
| B2 | Mail-style lookups | a script running `dig TXT <domain>`, `dig TXT _dmarc.<domain>`, `dig MX <domain>` over 500+ real domains (e.g. a Tranco list) at human-like intervals | benign (synthetic; say so) | 5,000+ |
| B3 | Service discovery | `dig SRV _ldap._tcp.<ad-domain>`, `_kerberos._udp`, `_sip._tls`, `_xmpp-client._tcp`; a Windows VM joined to a lab domain generates these naturally | benign | 2,000+ |
| A1 | iodine over A | `iodine -T A -r … t1.<lab-zone>` | attack (iodine, A) | 5,000 |
| A2 | iodine over CNAME | `iodine -T CNAME …` on a **different** zone, `t2.<lab-zone2>` | attack (iodine, CNAME) | 5,000 |
| A3 | dnscat2 over A/CNAME | `dnscat --dns domain=<zone3>,type=A,CNAME` | attack (dnscat2) | 5,000 |
| A4 | dnscat2 default | default types (MX/TXT/CNAME) on **another** zone | attack (dnscat2) | 5,000 |

**Rules:**
- **Each attack capture uses its own tunnel domain.** Three or more attack domains are needed for Task 3.
- **Record every capture in the manifest:** start, end, client IP, tool, record types, domain. `scripts/extend_manifest.py` keeps the labels trusted.
- **Keep timestamps:** capture B1 and the attacks over the same days, so "later traffic" can be cut off at the end (Task 4).

### 5.3 Existing public data

| Dataset | Use | Caveat |
|---|---|---|
| CIC-Bell-DNS-EXF-2021 [8] (UNB; Mahdavifar et al.) | already used for benign (`data/external/cic`); it has light and heavy exfiltration samples | earlier CIC attack captures had a 96-byte snap length (see `capture_dns.sh`); check queries aren't truncated before using its attack traffic |
| DNSTunnel2026 (Zenodo, CC BY 4.0) | already downloaded | pre-aggregated (38 features), so it can't go through `train_models.sh`; usable only via the feature-table trainer (compare-only) |
| Tu 2023 (on the Kali VM) | daily benign captures (about 280k unseen queries) | build a daily-only JSON (no ALEXA) |

### 5.4 Steps

1. Capture B1–B3 and A1–A4. Convert them with `scripts/make_labeled_features.py`, or put the pcaps in `data/raw` and pass `--pcap-label`.
2. **Before training, check the data is harder:** run `python3 -m dns_detect.features.eda_data` and confirm:
   - the record-type rule is no longer perfect (count TXT/MX/SRV in benign, A/CNAME in attack);
   - the "AUC 0.997 — data may be too easy" warnings are weaker.
3. Train with `bash scripts/run_candidate_seeds.sh`, setting `RUN_NAME=v4` and `FILES="…"`.

**Done when:**
- a v4 dataset exists with ≥ 3 attack domains, benign TXT/MX/SRV, and attack A/CNAME;
- the record-type rule's F1 on v4 is **below 1.0** (reported with its range);
- the data and its manifest are recorded in the run record.

---

## 6. Task 3: a test set split by domain

**Goal:** no parent domain appears in both training and test, so the test measures **unseen** domains, not memorised ones.

### 6.1 Why

- If rows from one group sit on both sides, the test score measures memory; this is a form of leakage [11].
- `GroupShuffleSplit` keeps every group on one side of a split [9]. `StratifiedGroupKFold` also keeps class proportions while never splitting a group [10].
- Week 6 showed 26.9% of test rows have an exact twin in training, and every Path A false alarm was on benign rows the model had **never** seen.
- **It can't be done on the current data.** With one attack domain, a domain split puts all attacks in train **or** test, never both. Task 2 has to come first.

### 6.2 What exists

- `splits.py` has a `parent_domain_group` strategy.
- `prepare_split.py --strategy parent_domain_group` builds it.
- `run_cv.py` already evaluates it.
- **Missing:** `train_models.sh` has no option to choose the split strategy for a new split.

### 6.3 Steps

1. Add `--split-strategy {time,parent_domain_group}` to `train_models.sh`, passed to `prepare_split.py`, with a test that no domain is in two splits.
2. On v4, build one domain-grouped split. Keep it **frozen** (`runs/v4_domain_split.json`) and reuse it for every v4 candidate.
3. Report both splits side by side: time split and domain split, each with error ranges and the rule baseline.

**Done when:** a frozen domain-grouped v4 split exists, has a test that it's disjoint, and PATH_B_REPORT has a time-split vs domain-split table.

---

## 7. Task 4: later-traffic check

**Goal:** score normal traffic captured **after** all training data, which the model has never seen, and report its false-alarm rate with error ranges.

### 7.1 Why

- Testing on data from the same period as training is "temporal bias", and it inflates results. TESSERACT requires training data to come before test data in time [12].
- Week 5 already saw drift: 0.1% on validation became 0.35–0.59% on later traffic.

### 7.2 Steps

1. Capture 1–3 days of **normal** traffic with `scripts/capture_dns.sh`, after the v4 training data ends.
2. Write `scripts/check_later_traffic.py`. It scores the capture with a models folder (read-only, like `evaluate_detectors.py`) and reports:
   - false alarms and false-alarm rate with exact and domain-bootstrap ranges;
   - the top 10 false-alarm domains;
   - score-distribution PSI against the **calibration** set (Task 6).
3. Add it to the standard evaluation as a section of `evaluate_detectors.py` output, or as its own step.

**Done when:**
- the later-traffic false-alarm rate for `models/` and the best v4 candidate is in PATH_B_REPORT, with ranges and top domains;
- the script is repeatable (one command) and tested on a small fixture.

---

## 8. Task 5: T3: the 0.1% target and an operating point

**Goal:** a false-alarm rate ≤ 0.1% on later traffic at a recall you report, **or** a written trade-off showing what it costs.

### 8.1 Why

- **The false-alarm rate is what limits a detector in practice:** benign traffic vastly outnumbers attacks, so the false-alarm rate has to be very low for alarms to be worth reading (Axelsson's base-rate fallacy) [13].
- Simple arithmetic: at 0.1% FPR, 1,000,000 benign queries still produce 1,000 false alarms. Your lab resolver sees thousands of queries a day, so 0.68% means tens of alarms a day.
- **Path B already ranks perfectly** (ROC-AUC 1.0); its 99th-percentile **window** threshold is what's wrong. A threshold chosen on calibration data for a query-level budget should cut its false alarms a lot.

### 8.2 Steps

1. Start from the Task 1 method. **On calibration data only,** compute the full curve of false-alarm rate vs recall for fusion, Path A and Path B: `sklearn.metrics.roc_curve` / `precision_recall_curve`, with scores taken from the cache in `runs/_eval_cache/`.
2. Pick candidate operating points at FPR = 1%, 0.5%, 0.1% and 0.05% on calibration. Report each on **test and later traffic** with error ranges: Clopper–Pearson [23] plus the domain bootstrap from `uncertainty.py`.
3. Only if 0.1% isn't reached, try these one at a time and keep only what helps on calibration:
   - **Score per client and time window instead of per query** (e.g. alarm when a client has ≥ k suspicious queries in 5 minutes). Most tunnel detection works on sessions.
   - **Feature fixes for the benign domains that cause the most false alarms.** Break down by domain and record type first; fix a feature, not a domain.
   - **A small, versioned allowlist** (`config/allowlist.yaml`): each entry has a reason, a date and a source. Report recall cost and coverage. It's a last resort, and must be chosen on calibration data, never on test.
4. **Stop and report the trade-off** if 0.1% costs more than about 10 points of recall.

**Done when:** PATH_B_REPORT has the trade-off curve (calibration), the operating-point table (test and later traffic, with ranges and the rule baseline), and a recommended operating point written into `config/settings.yaml`.

---

## 9. Task 6: drift warning

**Goal:** warn when live features or scores move away from what the model was trained on, and show it on `/health`.

### 9.1 Why

- PSI is the standard population-stability measure from credit-risk model monitoring. The industry bands (0.10 and 0.25) are rules of thumb without academic backing [14][15].
- PSI's expected value and variance depend on the **number of bins and the sample sizes** [14]. So keep the bins fixed (saved with the model) and report the window size next to every PSI.
- The ML Test Score includes monitoring that serving inputs keep the same invariants as training [16].

### 9.2 What exists (more than it seems)

- `src/dns_detect/monitoring/monitor.py` computes **feature** PSI against the training `feature_snapshot`, with bands at 0.10 and 0.25, plus a score saturation check.
- `/health` and `/api/model` already show the **maximum PSI** (`dashboard/server.py`, `_max_psi`).

**Missing:**
1. PSI of the **model scores** (Path A, Path B, fusion) against the calibration-set scores.
2. **Bin edges saved with the model,** so PSI stays comparable across runs.
3. The warnings in a log and in an API field, with thresholds in config.

### 9.3 Steps

1. At training time, save `drift_baseline.json` beside the models: per feature and per score, the bin edges (deciles of the calibration set) and the proportions.
2. Add score PSI to `monitor.py` using the saved edges. Thresholds go in `config/settings.yaml` (`monitoring.psi_warn: 0.1`, `monitoring.psi_alert: 0.25`).
3. On `/health`: show the top 5 drifting features and the score PSI, with bands and the window compared.
4. Unit tests: PSI is 0 for identical data, large for shifted data, and stable with saved edges; empty bins are handled.

**Done when:** feature and score PSI are logged on every pipeline run, shown on `/health`, the thresholds are in config, and the tests pass.

---

## 10. Task 7: review band

**Goal:** scores just under the alarm threshold go to the analyst queue as "review", instead of alarming or being dropped.

### 10.1 Why

- **Classification with a reject option** comes from Chow (1970), who described an optimum rejection rule and the trade-off between error and reject rates [17]. The survey by Hendrickx et al. covers modern methods [18].
- In security, Transcend and its successor use rejection to quarantine samples likely to be misclassified until an expert looks at them [19][20].
- The review queue is also how **verdicts** will be collected, which unblocks T7 (feedback retraining) later.

### 10.2 What exists

- `fusion/bridge.py` already assigns tiers: HIGH = alarm, MEDIUM ≥ benign q99, LOW ≥ benign q90, from `fusion_lr_tiers.json`.
- **Missing:** a band chosen for an analyst **budget**, and routing to the `/triage` queue.

### 10.3 Steps

1. **Choose the band on calibration data:** the score range just below the threshold that sends about N review items a day (N in config, default 20), based on calibration benign volume scaled to your daily query count.
2. **The bridge marks those rows `REVIEW`;** alarms don't change.
3. **`/triage` shows a "Review" case type.** The analyst's verdict feeds `scripts/export_feedback_labels.py`.
4. **Unit tests:** the band is below the threshold, never overlaps HIGH, gives about N items a day on the calibration fixture, and leaves alarm counts unchanged.

**Done when:** the review band is in config, visible in `/triage`, and tested, and the alarm count is identical with and without it.

---

## 11. Task 8: feature-schema check at start-up

**Goal:** the live pipeline refuses to start if the model's saved features don't match the code's features, so it never scores silently wrong inputs.

### 11.1 Why

- **Training-serving skew** (a difference between training and serving) is a named failure mode in Google's *Rules of Machine Learning* (Rules #29–#37) [21].
- The ML Test Score's data tests start with "feature expectations are captured in a schema", and its monitoring tests check that training and serving features match [16].
- Today the check exists only in `scripts/smoke_models.py` and the tests, not at bridge start-up.

### 11.2 Steps

1. Add `check_model_schema(models_dir)` (in `src/dns_detect/models/`). It compares:
   - `dns_threshold.json` features with `PATH_A_FEATURES` (names and order);
   - `dns_trafficformer_norm.json` features and `n_features` with `PATH_B_FEATURES`;
   - the window size with settings;
   - Path B's `model_type` against the file that exists;
   - the fusion's `inputs` against `FUSION_INPUTS`.
2. Call it at the start of the bridge and of `run_pipeline.sh`. In production mode, fail with a clear message naming the mismatched features. In development, warn.
3. Also run it in `promote_model.sh` **before** copying.
4. Tests: a matching folder passes; a reordered, missing or extra feature fails; a wrong model type fails.

**Done when:** `models/` passes, a tampered copy fails with a clear message, the bridge and `promote_model.sh` call it, and the tests pass.

---

## 12. Task 9: automate Part B: seeds, gate and promote

**Goal:** after training, the seed runs, the gate and the promote run as one command. A model reaches `models/` **only** if it passes the gate, and a failed smoke test rolls it back.

### 12.1 Why

- Google's MLOps guide describes three levels: level 0 is a manual process; level 1 automates the training pipeline (continuous training) and the delivery of the validated model; level 2 also automates the pipeline's own CI/CD [24]. Today this project is between level 0 and level 1: training (Part A) and detection (Part C) are one command each, but Part B is three commands typed by hand.
- The same guide says an automated pipeline must include **model validation** before deployment: the new model has to beat the current one on the agreed metrics [24]. Our gate (`compare_models.py` + `config/success_criteria.yaml`) is that check.
- The ML Test Score asks that a model is checked before it serves, and that a bad model can be rolled back quickly [16]. `promote_model.sh` already archives the old models; a smoke test and an automatic rollback finish the job.
- Rules of ML: keep the pipeline simple and monitored, and watch for silent failures [21]. Today the gate's result is silently ignored (`|| true`), which is a silent failure.
- Security detectors are high-stakes (Axelsson's base-rate problem [13]; Arp et al. on pitfalls [22]): a bad model floods the SOC or misses tunnels. So promote is automatic **only behind the gate and only when asked** (`--auto-promote`), and by default the run stops at "ready to promote". This also keeps the project rule *"promote only if I say so"*: the flag is saying so in advance.

### 12.2 What exists

| Piece | State |
|---|---|
| Train 3+ seeds into `runs/<name>_s<seed>` | ✅ `scripts/run_candidate_seeds.sh` |
| Gate over the seeds (vs live model and rule baseline) | ✅ `scripts/compare_models.py`, exit 0 = PASS, 1 = FAIL; already called by `run_candidate_seeds.sh` |
| Schema check, archive, copy, hash, `PROMOTED.json` | ✅ `scripts/promote_model.sh` |
| Smoke test | ✅ `scripts/smoke_models.py` (manual) |
| Gate result used | ❌ thrown away: `compare_models.py ... \|\| true` |
| Promote after PASS | ❌ never called |
| Rollback if the smoke test fails | ❌ manual |
| `run_all.sh --retrain` / `--auto-retrain` | ⚠️ train **straight into `models/`**, bypassing seeds and gate |

### 12.3 Steps

1. **Use the gate result** in `run_candidate_seeds.sh`: replace `|| true` with an `if`, set `GATE=pass|fail`, print it, and write it into `runs/<name>_gate.json` (already written by `--out`).
2. **Promote on PASS, only when asked.** With `AUTO_PROMOTE=1` (or `--auto-promote`): pick the seed to promote, run `promote_model.sh runs/<name>_s<seed> before_<name>`, then `smoke_models.py`.
   - Which seed: the one whose fusion false alarms are closest to the seed median (more typical than seed 42 by luck). Record the choice and the reason in `PROMOTED.json`.
   - Without the flag: print `ready: bash scripts/promote_model.sh runs/<name>_s<seed>` and stop.
   - On FAIL: print the failed criteria, keep `models/` unchanged, exit non-zero.
3. **Rollback:** add `scripts/rollback_model.sh` (restore the newest `models/archive/<label>_<ts>/`). Call it automatically if the smoke test fails after an auto-promote.
4. **Rewire `run_all.sh`:** `--retrain` and `--auto-retrain` call `run_candidate_seeds.sh` (runs/ → gate) instead of `train_models.sh` into `models/`. Pass `--auto-promote` through. Then re-run detection only if a model was actually promoted.
5. **Lock:** a lock file (`runs/.promote.lock`) so two runs can't promote at the same time; refuse to promote while `run_pipeline.sh` is running.
6. **Log:** one line per decision in `runs/promotion_log.jsonl` (time, run, gate result, criteria values, promoted yes/no, git commit).
7. **Tests** (`tests/test_part_b_automation.py`, with stub run folders, no real training):
   - FAIL gate → `models/` untouched, exit 1;
   - PASS gate without the flag → `models/` untouched, "ready" printed;
   - PASS gate with the flag → promoted, `PROMOTED.json` names the run and seed;
   - smoke failure → rolled back to the archived models;
   - `run_all.sh --retrain` never writes to `models/` directly.
8. Update the flow map: steps 13–15 become **Auto** (15 behind the gate); gaps 21–22 closed.

**Commands after this task:**

```bash
bash scripts/run_all.sh --retrain                  # seeds → gate → stop ("ready to promote" or FAIL)
bash scripts/run_all.sh --retrain --auto-promote   # seeds → gate → PASS? promote → smoke → (rollback if needed)
```

**Expected today:** the gate FAILS (the rule baseline has 0 false alarms on the current test set), so nothing is promoted. That is the correct, safe result; auto-promote becomes useful after Task 2's harder data.

**Done when:** one command runs seeds → gate → (promote); a FAIL never touches `models/`; a smoke failure rolls back; `--retrain` no longer writes to `models/` directly; the tests pass; the flow map shows Part B as automatic.

---

## 13. Task 10: verdict fixes F1–F5 and F8

**Goal:** an analyst verdict is only ever stored for a real alert, can be cleared, and is never saved twice or by a rejected request. Verdicts become training labels later (Task 12), so they must be clean first.

**Source:** `docs/Week6/AUDIT_training_label_unlabel_2026-11-18.md` §6 (fixes with exact line numbers and test plans).

### 13.1 Why

- A label that can be written for an alert that never existed, or written twice, is **label noise**; Arp et al. list label inaccuracy as a top pitfall of ML in security [22].
- Each saved verdict is a training example later. Google's Rules of ML warn that feedback loops and silent data errors are the hardest bugs to find [21].
- An action that is repeated (double-click, retry) must not change the result twice: the meaning of an *idempotent* request in HTTP [26].

### 13.2 What exists (checked 2026-11-20)

| Fix | What it does | State |
|---|---|---|
| F1 (High) | reject verdicts/actions on unknown alerts (404) | ❌ `server.py` `verdict` branch accepts any fingerprint; test record `deadbeefdeadbeef00` still in `dashboard/data/alert_management.json` |
| F2 (Medium) | "clear verdict" (unlabel) action, audited | ❌ no such action (`VALID_BULK_ACTIONS` has no clear) |
| F3 (Low/Med) | in-flight guard on Save verdict / action buttons | ❌ |
| F4 (Low) | same-value re-verdict is a no-op (no new audit entry) | ❌ |
| F5 (Low) | no management record created for a rejected request | ❌ |
| F6 | training console: one job at a time, locked writes | ✅ partly: second job → 409 |
| F7 | show training-console errors | ⚠️ check |
| F8 (Med) | `--demo` puts the training API in demo mode | ❌ `server.py` sets `STATE.mode = "demo"` but nothing sets the training API's mode, so a demo run could write to `<repo>/models` |

### 13.3 Steps

1. Order from the audit: **F1 → F5 → F2 → F3/F4 → F8 → F7**.
2. F1: add `alert_known(fp)` (live feed **or** existing record); 404 in `_alert_action`, per-item 404 in `_alerts_bulk`.
3. Remove the test record `deadbeefdeadbeef00` (back up `alert_management.json` first; log it in the audit log as a cleanup, not a silent edit).
4. F5: validate before creating a record. F2: `clear_verdict` action (Tier rules as for setting one; audit `VERDICT_CLEARED`; button in `/alerts` and `/triage`). F3: disable the button while the request is in flight. F4: same verdict + same reason → 200, no audit entry.
5. F8: in the `--demo` branch, set the training API to demo mode **before** it is imported; show the mode in the training UI.
6. Tests in `tests/test_dashboard_soc.py` / `test_dashboard_triage.py`: unknown fp → 404 and no record; clear works and is audited; double submit → one audit entry; `--demo` → training config `mode: demo` and `<repo>/models` mtime unchanged.

**Done when:** all six fixes are in, the test record is gone, the new tests and the existing 43 dashboard tests pass.

---

## 14. Task 11: dashboard testing in real mode

**Goal:** prove the dashboard works on real alerts from the live models, in a real browser, and exports to Elasticsearch/Kibana.

**Source:** `WEEK6_COMPLETE_REPORT.md` §11 and §14.

### 14.1 Why

- So far only demo mode (fake alerts) and unit tests were run. The ML Test Score asks for an end-to-end test of the whole pipeline with real inputs before production [16].
- The live models changed on 2026-11-19 (v3_iforest promoted), so real mode now also tests the new Path B end to end.

### 14.2 Steps

1. **Browser click-through** (fixes "Chrome on Windows could not reach the WSL server"): either run `python dashboard/server.py` on Windows, or start it in WSL with `--host 0.0.0.0` and a non-default `ADMIN_TOKEN`, then open `http://<wsl-ip>:<port>` (`wsl hostname -I`). Walk `/triage`, `/alerts`, `/soc`, `/health`: load, filter, open an alert, assign, add a note, set and clear a verdict (after Task 10). Record a checklist with PASS/FAIL and screenshots.
2. **Real mode on live Technitium logs:** `bash scripts/run_all.sh --skip-train` (uses `models/` = v3_iforest), then start the dashboard **without** `--demo`, watching the pipeline output. Check: alerts appear, `/health` shows model version `v3_iforest`, monitoring and drift fields filled.
3. **Elasticsearch/Kibana:** `docker compose up` the ELK stack; run the exporter (see `SOC_ML_INTEGRATION.md` §3); check the index exists, document count = alert count, and one Kibana view shows them. Use the Elasticsearch bulk API's per-item errors to confirm nothing was rejected [27].
4. Write results in `docs/Week7/DASHBOARD_REAL_MODE_TEST.md`; anonymise client IPs and internal domains before committing (project rule).

**Done when:** the four pages pass in a browser, a real-mode run shows v3_iforest alerts, and the Kibana index matches the alert count. Items 10–13 of the Week 6 open list are then closed.

---

## 15. Task 12: verdicts into training (plumbing only)

**Goal:** close flow-map gap 23: analyst verdicts can flow into step 8 (Label), but **no model is trained on them until there are enough**.

### 15.1 Why

- Analyst feedback is the cheapest source of hard, real labels (benign look-alikes the model flags). Transcend and its follow-up show that detectors decay without fresh labels [19][20].
- But with 2 verdicts (one a test record), training on them would be noise; §18 keeps "retraining on feedback" out of Week 7 until about 50+.
- Leakage risk: a verdict on a test-set alert must never enter training, or the test score is inflated [11].

### 15.2 Steps

1. Needs Task 10 (clean verdicts).
2. `export_feedback_labels.py` → `data/feedback/verdict_labels.json` (TP → attack, FP → benign; skip "unsure"; keep alert fingerprint and time).
3. `train_models.sh --feedback FILE`: step 8 adds these rows with `label_source = "analyst"`; **drop** any row whose time falls in the frozen test window, and print how many were dropped.
4. Minimum count: refuse `--feedback` below `feedback.min_verdicts` (config, default 50) with a clear message.
5. Record in the run record: number of verdict rows used, dropped, and the export file's sha256.
6. Tests: test-window rows dropped; below minimum → refused; labels mapped correctly.

**Done when:** the plumbing and tests exist and the flow map shows gap 23 as "connected, waiting for ≥ 50 verdicts".

---

## 16. Task 13: SOC roadmap P0

**Goal:** the P0 items from `WEEK6_AUDIT_AND_FORTINET_ROADMAP.md` §3.1 that are still missing.

### 16.1 What is missing (checked 2026-11-20)

| # (roadmap) | Item | State |
|---|---|---|
| 1 | Role-based landing pages (Tier 1 → `/alerts` mine/unassigned, Tier 2, IR → `/incidents`, Manager → `/soc`) | ❌ |
| 2 | "Assigned to me" / "Unassigned" quick filters on `/alerts` | ❌ |
| 3 | "Run playbook" button on an alert (maps to a bulk recipe) | ❌ |
| 4 | Evidence attachments per alert/incident (16 MB, path-safe) | ❌ |
| 5 | MITRE tactic × technique matrix page (`/mitre.html`), click → filter `/alerts` | ❌ only a heatmap and per-alert tactic/technique lists exist [28] |

### 16.2 Order

The roadmap's own sequencing: **1, 2, 5** first (analyst value, no new integrations), then **3 + 4 together** (both need `dashboard/data/` to hold files). Each item: tests in the dashboard suites, and a line in the Week 7 report.

**Done when:** the five items work in the browser test of Task 11 and their tests pass.

---

## 17. Task 14: out-of-date docs

**Goal:** the Week 6 documents say what is true now.

| Doc | Wrong now | Fix |
|---|---|---|
| `docs/Week6/WEEK6_COMPLETE_REPORT.md` §12 | says "Dashboard (not yet committed)" | it is committed; give the commit |
| `docs/Week6/WEEK6_COMPLETE_REPORT.md` | no mention of the 2026-11-18/19 work | add a short section: training console, ML improvement research, items 1–5, 3-seed results, v3_iforest promotion, T9 error ranges; link the reports |
| `docs/Week6/PATH_B_ISOLATION_FOREST.md` §8 | "Not yet measured: … the multi-seed spread" | measured: 3-seed fusion 8.2 ± 0.84 false alarms; 20-seed results in PATH_B_REPORT §5 |

**Done when:** each line is fixed with a date and a link to the evidence.

---

## 18. Not in Week 7

| Item | Why not now |
|---|---|
| T7: retraining on analyst feedback | 2 verdicts; about 50+ needed. Task 7 (review band) is how they get collected |
| SHAP "why it fired" | nice for analysts, but needs a new package and isn't blocking |
| Evasion test (tools tuned to hide) | do it after Task 2, when there's more than one attack domain to compare |
| Deep models for Path B | the autoencoder failed (recall 0.0) and is too slow on this machine; the Isolation Forest stays |
| Large hyperparameter or seed sweeps | the test set is too small; it would tune to noise |
| SOC roadmap P1 (saved views, watchlists, notifications, report builder, incident timeline, per-IP baselines, integrations page) | Week 8, after the P0 pages (roadmap §3.2) |
| SOC roadmap P2 (login and roles, SQLite instead of JSON files, dashboard builder, scheduled reports) | platform work; login + roles are needed before any non-localhost use (roadmap §3.3) |

---

## 19. Checklist

**Task 1: T4 light**
- [x] 20 seeds trained and scored (`runs/t4_before_20seeds.*`)
- [x] Cause written, with evidence (threshold vs model vs split): PATH_B_REPORT §5.2
- [x] Fixes tried one at a time (score averaging and voting over the 20 seeds, PATH_B_REPORT §5.3). Optional extra: a 1,000-tree Path A
- [ ] Setting in `config/settings.yaml`; inference cost noted

**Task 2: harder data**
- [ ] B1–B3 benign and A1–A4 attack captures, each attack on its own domain
- [ ] Manifest updated; EDA shows the rule is no longer perfect
- [ ] v4 trained over 3 seeds; the rule's F1 < 1.0 reported

**Task 3: domain split**
- [ ] `--split-strategy` in `train_models.sh`, with a disjointness test
- [ ] Frozen domain split for v4; time-split vs domain-split table

**Task 4: later traffic**
- [ ] Fresh benign capture after the training period
- [ ] `check_later_traffic.py` with ranges, top domains and score PSI

**Task 5: T3**
- [ ] Trade-off curve on calibration; operating points on test and later traffic
- [ ] Recommended operating point in config, or a written trade-off if 0.1% costs > 10 recall points

**Task 6: drift**
- [ ] `drift_baseline.json` saved at training; feature and score PSI; thresholds in config
- [ ] `/health` shows it; tests

**Task 7: review band**
- [ ] Band chosen on calibration for N/day; `REVIEW` in the bridge; Review cases in `/triage`; tests

**Task 8: schema check**
- [x] `check_model_schema` used by the bridge, `run_pipeline.sh` and `promote_model.sh`; tests (2026-11-19: `src/dns_detect/models/schema.py`, `tests/test_model_schema.py`, 12 tests)

**Task 9: automate Part B**
- [ ] Gate result used (no `|| true`); PASS/FAIL printed and logged
- [ ] `--auto-promote`: promote on PASS, smoke test, automatic rollback
- [ ] `run_all.sh --retrain` / `--auto-retrain` go through `runs/` and the gate, never straight to `models/`
- [ ] Lock file, `promotion_log.jsonl`, tests; flow map updated

**Task 10: verdict fixes**
- [x] F1 unknown alerts → 404; test record `deadbeefdeadbeef00` removed (backed up, audited) (2026-11-20)
- [x] F5, F2 (clear verdict), F3, F4, F8; tests pass with the existing dashboard tests (56 passed) (2026-11-20)

**Task 11: real-mode testing**
- [ ] Browser click-through of `/triage`, `/alerts`, `/soc`, `/health`
- [ ] Real-mode run on live Technitium logs with v3_iforest
- [ ] Elasticsearch/Kibana export checked against the docker stack; report written (anonymised)

**Task 12: verdicts → training**
- [ ] `--feedback` in step 8, test-window rows dropped, minimum 50, run record; tests

**Task 13: SOC P0**
- [ ] Role landing pages; Assigned/Unassigned filters; MITRE matrix page
- [ ] Playbook button; evidence attachments

**Task 14: docs**
- [x] WEEK6_COMPLETE_REPORT §12 and the 11-18/19 work; PATH_B_ISOLATION_FOREST §8 (2026-11-20)

**Each task:** commit on a branch, gate over ≥ 3 seeds where it changes a model, PATH_B_REPORT updated, this checklist ticked.

---

## 20. References

All primary sources: papers, standards, official documentation and the tools' own repositories.

1. X. Tong, Y. Feng, J. J. Li. *Neyman-Pearson classification algorithms and NP receiver operating characteristics.* Science Advances 4(2), eaao1659, 2018. doi:10.1126/sciadv.aao1659. https://pmc.ncbi.nlm.nih.gov/articles/PMC5804623
2. X. Tong, L. Xia, J. Wang, Y. Feng. *Neyman-Pearson classification: parametrics and sample size requirement.* arXiv:1802.02557. https://arxiv.org/abs/1802.02557
3. S. Kitterman. *Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1.* RFC 7208, IETF, 2014. https://rfc-editor.org/rfc/rfc7208
4. D. Crocker, T. Hansen, M. Kucherawy (eds.). *DomainKeys Identified Mail (DKIM) Signatures.* RFC 6376, IETF, 2011. https://rfc-editor.org/rfc/rfc6376
5. M. Kucherawy, E. Zwicky (eds.). *Domain-based Message Authentication, Reporting, and Conformance (DMARC).* RFC 7489, IETF, 2015. https://rfc-editor.org/rfc/rfc7489
6. iodine: official repository and manual page (`-T dnstype`). https://github.com/yarrick/iodine · https://man.archlinux.org/man/iodine.8.en
7. R. Bowes. dnscat2: official repository and README (default DNS driver `type = TXT,CNAME,MX`). https://github.com/iagox86/dnscat2
8. Canadian Institute for Cybersecurity. *CIC-Bell-DNS-EXF-2021 dataset.* https://unb.ca/cic/datasets/dns-exf-2021.html. Paper: S. Mahdavifar et al., *Lightweight Hybrid Detection of Data Exfiltration using DNS based on Machine Learning.*
9. scikit-learn. `GroupShuffleSplit`. https://scikit-learn.org/1.2/modules/generated/sklearn.model_selection.GroupShuffleSplit.html
10. scikit-learn. `StratifiedGroupKFold`. https://scikit-learn.org/1.1/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html
11. S. Kapoor, A. Narayanan. *Leakage and the Reproducibility Crisis in ML-based Science.* arXiv:2207.07048. https://arxiv.org/abs/2207.07048
12. F. Pendlebury, F. Pierazzi, R. Jordaney, J. Kinder, L. Cavallaro. *TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time.* USENIX Security 2019. https://usenix.org/conference/usenixsecurity19/presentation/pendlebury
13. S. Axelsson. *The Base-Rate Fallacy and the Difficulty of Intrusion Detection.* ACM Transactions on Information and System Security 3(3), 186–205, 2000. doi:10.1145/357830.357849 (earlier version: ACM CCS 1999)
14. B. Yurdakul, J. Naranjo. *Statistical properties of the population stability index.* Journal of Risk Model Validation. https://www.risk.net/journal-of-risk-model-validation/7725371/statistical-properties-of-the-population-stability-index
15. B. Yurdakul. *Statistical Properties of Population Stability Index.* PhD dissertation, Western Michigan University. https://scholarworks.wmich.edu/dissertations/3208/
16. E. Breck, S. Cai, E. Nielsen, M. Salib, D. Sculley. *The ML Test Score: A Rubric for ML Production Readiness and Technical Debt Reduction.* IEEE Big Data 2017. https://research.google/pubs/pub46555/
17. C. K. Chow. *On optimum recognition error and reject tradeoff.* IEEE Transactions on Information Theory 16(1), 41–46, 1970. doi:10.1109/TIT.1970.1054406
18. K. Hendrickx, L. Perini, D. Van der Plas, W. Meert, J. Davis. *Machine Learning with a Reject Option: A survey.* arXiv:2107.11277. https://arxiv.org/abs/2107.11277
19. R. Jordaney et al. *Transcend: Detecting Concept Drift in Malware Classification Models.* USENIX Security 2017. https://s2lab.cs.ucl.ac.uk/downloads/sec17-jordaney.pdf
20. F. Barbero, F. Pendlebury, F. Pierazzi, L. Cavallaro. *Transcending TRANSCEND: Revisiting Malware Classification in the Presence of Concept Drift.* IEEE S&P 2022. https://arxiv.org/abs/2010.03856
21. M. Zinkevich. *Rules of Machine Learning: Best Practices for ML Engineering.* Google. https://developers.google.com/machine-learning/guides/rules-of-ml
22. D. Arp et al. *Dos and Don'ts of Machine Learning in Computer Security.* USENIX Security 2022. https://www.usenix.org/conference/usenixsecurity22/presentation/arp
23. C. J. Clopper, E. S. Pearson. *The use of confidence or fiducial limits illustrated in the case of the binomial.* Biometrika 26(4), 404–413, 1934 (the exact interval used for every FPR and recall range).
24. Google Cloud. *MLOps: Continuous delivery and automation pipelines in machine learning* (levels 0–2; continuous training; model validation before deployment). Last reviewed 2024-08-28. https://cloud.google.com/architecture/mlops-continuous-delivery-and-automation-pipelines-in-machine-learning
25. D. Sculley et al. *Hidden Technical Debt in Machine Learning Systems.* NeurIPS 2015. https://papers.nips.cc/paper/5656-hidden-technical-debt-in-machine-learning-systems
26. R. Fielding, M. Nottingham, J. Reschke (eds.). *HTTP Semantics.* RFC 9110, IETF, 2022, §9.2.2 Idempotent Methods. https://rfc-editor.org/rfc/rfc9110#section-9.2.2
27. Elastic. *Bulk API* (per-item results and errors). https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
28. MITRE. *ATT&CK Enterprise Matrix* (tactics × techniques). https://attack.mitre.org/matrices/enterprise/
