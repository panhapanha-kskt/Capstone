# Plan: DNS Anomaly Detector v2: better models, one connected codebase, live unknown-attack hunting with Telegram

## Context
The project works end to end, but it has three weaknesses:

1. **The models are weaker than the scores suggest.**
   - F1 ≈ 1.00 comes from an easy dataset (`query_length` alone has AUC 0.998).
   - On an attack tool the model never saw, Path A recall is 0.32 and 0.00.
   - There are correctness bugs, listed in Phase 1.
2. **The files don't connect cleanly.**
   - Python is hidden inside bash scripts (the merge step, the metadata, a generated awareness script).
   - Helper scripts live outside the package, there are `.bak` copies and hard-coded `/home/ounnha` paths.
   - `settings.yaml` is only partly used, the outputs folder holds stale leftovers, and model files have no versions.
3. **Nothing runs on its own.** Detection is a manual batch job. An anomaly ends as a score in a JSON file: nobody is told, nothing explains it, and nothing compares it to what the models already know.

**Goal:** the system watches live DNS traffic. When Path B says "not normal" but Path A says "not a known attack", it opens an **unknown-attack case**, investigates it (why it's unusual, which known attack it resembles, what the client was doing) and sends the case to **Telegram** with *Confirm attack* / *False positive* buttons. Your answers become labeled data for the next training run, so today's unknown attack becomes tomorrow's known one.

Decisions already made:
- Telegram: notify + label buttons, with **no** network actions such as blocking.
- Speed: near real-time watcher (about a 10-second cycle).
- Codebase: full restructure.

---

## Target architecture

```
 Technitium log ──► live/watcher ──► features (+ per-client behavior) ──► Path A ─┐
 (tail, ~10 s)       per-client                                       Path B ─┼─► fusion ──► category
                     rolling buffer                                           │      KNOWN_ATTACK
                                                                rules/Z-score ┘      UNKNOWN_CANDIDATE
                                                                                     RULE_ONLY · CLEAN
                                                                                        │
                       ┌────────────────────────────────────────────────────────────────┘
                       ▼
          live/cases (group per client, dedupe, rate-limit)
                       ▼
          investigation/ (why unusual · compare to known families · client activity)
                       ▼
          notify/telegram ──► 📱 case card + [✅ Confirm attack] [❌ False positive] [🔍 Details]
                       ▼                      │
          data/runs/live/…/cases/*.json       ▼
                                  notify/feedback ──► data/feedback/confirmed_cases.jsonl
                                                          ▼
                                  dns_detect label --from-feedback ──► dns_detect train  (you decide when)
```

### Target folder layout
```
Capstone/
├── config/settings.yaml            single source: paths, features, thresholds, watcher, telegram
├── .env (not committed)            TELEGRAM_BOT_TOKEN, TELEGRAM_ALLOWED_USER_IDS, TELEGRAM_CHAT_ID
├── src/dns_detect/
│   ├── __main__.py                 CLI: train | detect | watch | bot | investigate | label | verify
│   ├── config.py · artifacts.py    every file path resolved here from settings.yaml
│   ├── schema.py                   field names, FEATURES_A, FEATURES_B, week-3 rename map (one copy)
│   ├── ingest/                     technitium_log.py · pcap.py · labeling.py · merge.py
│   ├── features/                   extractor.py (per-query + heuristics) · behavioral.py (NEW) · eda.py
│   ├── models/path_a/              train.py · predict.py · profiles.py (NEW: known-family profiles)
│   ├── models/path_b/              model.py · train.py · predict.py
│   ├── models/registry.py          versioned model folders + models/current.json pointer
│   ├── fusion/bridge.py
│   ├── detection/engine.py
│   ├── investigation/              investigator.py · report.py
│   ├── live/                       watcher.py · buffer.py · cases.py
│   ├── notify/                     telegram.py (send) · bot.py (button listener) · feedback.py
│   ├── monitoring/monitor.py
│   ├── evaluation/verify.py        (was scripts/verify_models.py)
│   └── pipeline/                   train.py · detect.py (replaces the Python inside bash)
├── scripts/                        train.sh · detect.sh · watch.sh: one-line wrappers around the CLI
├── data/
│   ├── raw/logs/ · raw/pcaps/ · manifests/
│   ├── datasets/training_set.json · datasets/holdout/
│   ├── feedback/confirmed_cases.jsonl
│   └── runs/<run_id>/              features · with_ml · alerts.json/.csv · investigation/ · monitoring.json
├── models/<version>/ + models/current.json
└── tests/
```

---

## Phase 0: Restructure the foundation (do this first; everything else builds on it)
- **One path registry:** `artifacts.py` reads `settings.yaml` and exposes every input and output path (training set, run folder, each model file). No module builds its own path. Today names are spread across `path_a.py:47`, `path_b_train.py`, `bridge.py`, `train_models.sh:188-201` and `run_pipeline.sh:93-94`.
- **One schema module:** move `FEATURES_8`, `PATH_B_FEATURES` and the three copies of the week-3 rename map (`dns_parser.py:52-57`, `:227`, `:312`, `:396`) into `schema.py`.
- **Python orchestration:** move the inline Python in `train_models.sh` (merge, metadata, provenance, registry, awareness-script generation) into `pipeline/train.py`, and the steps of `run_pipeline.sh` into `pipeline/detect.py`. Bash scripts become one-line wrappers.
- **Move scripts into the package:**
  - `make_labeled_features.py` and `label_from_manifest.py` → `ingest/labeling.py`
  - `verify_models.py` → `evaluation/verify.py`
  - `filter_noise.py` → a `--quiet` flag
- **Versioned models:** each training run writes `models/<YYYYMMDD-HHMM>/` and updates `models/current.json`. Detection, investigation and the watcher load through `registry.py`, which also records the training data checksum.
- **Run folders:** each detection run writes into `data/runs/<run_id>/` instead of overwriting `data/processed/`.
- **Cleanup:**
  - Delete the `*.bak` files.
  - Remove the hard-coded paths in `train_quiet.sh:22,30`.
  - Move the 9 unused files (`extracted_*.json`, `pcap_feat_*.json`) to `data/archive/`.
  - Remove the legacy RF+Transformer blend and the deprecated CLI flags from `path_a.py:238-263`.
  - Rename `rf_weight`/`tf_weight` in `settings.yaml` to `weight_a`/`weight_b`, and add the missing `gbt_file`.
- Reuse existing code as it is: `DNSFeatureExtractor.parse_technitium_log_line` (extractor.py:289), `load_as_dataframe` / `load_multifeature_with_meta`, `build_client_windows`, `tree_ensemble_scores`, `merge_ml_scores`, and `RuleBasedDNSDetector` / `ZScoreDetector`.

## Phase 1: Fix correctness issues in both paths
| # | Problem (evidence) | Fix |
|---|---|---|
| 1 | Path A's winner is chosen on **test** F1 and that F1 is then reported (`path_a.py:398-404`) | Choose on val; score test once, for the winner only; keep both candidates' test numbers as information |
| 2 | **`answer_count` differs between training and detection.** Training pcaps are queries only, so it is always 0. Technitium logs record real answers (`extractor.py:337-339`), so detection sees non-zero values the model never learned | Parse DNS responses from pcaps (`ancount` in `dns_parser.py:151`, using response packets), or drop the feature until both sources supply it. Add a check that fails training if a feature has zero variance |
| 3 | Path B has **no positional encoding**, so it can't learn query order | Add sinusoidal positional encoding before the encoder blocks |
| 4 | Path B scores only the **last** query of each window, so a client's first 19 queries and any client with fewer than 20 are never scored (`path_b_predict.py:160-171`) | Give each record the max score of every window that covers it; score short clients with a padded window plus a mask |
| 5 | The drift snapshot is built from the first 12 numeric week-3 fields over benign **and** attack rows (`train_models.sh:851-867`), while the monitor looks up `FEATURES_8` names | Build the snapshot from **benign** rows using schema names. Check that every monitored feature is found |
| 6 | Stale labels say "RF + Transformer" (`engine.py:336`, `:907`) | Read the model description from the model registry |
| 7 | `week3_features_all.json` was made before the base64 fix | Gone once run folders exist; it's regenerated each run |

## Phase 2: Improve the algorithms
**Shared new feature module `features/behavioral.py`.** The current 8 features describe one domain name, so the model learns tool fingerprints. Tunneling is a behavior: many queries from one client to one parent domain. Per client, over a rolling window (last 20 queries or 60 s), and per parent domain (`main_domain`):
- query rate, and mean / standard deviation of time between queries
- unique-subdomain ratio and mean / max label length per parent domain
- NXDOMAIN share
- share of rare query types (TXT, NULL, KEY, CNAME, ANY)
- per-client entropy drift, compared with that client's own history

**Path A**
- Features become `FEATURES_A` = the 8 per-query features (with `answer_count` fixed or dropped) plus the behavioral features.
- **Grouped split by `main_domain`**, so no parent domain appears in both train and test.
- **Calibrated probabilities** (isotonic calibration on val), so the fusion weights and the 0.7 threshold mean what they say.
- The Transformer baseline becomes optional (`--with-baseline`), which shortens normal training.
- Save `family_profiles.json` per known family: mean/std per feature, a centroid in scaled space, and `radius_95`. This is the "known attacks" memory used by investigation.

**Path B**
- Positional encoding (Phase 1), plus an explicit narrow latent layer instead of relying on `ff_dim = 3`.
- Features become `FEATURES_B` = the current 5 plus the behavioral features.
- Output **per-feature error** (`compute_feature_errors`: mean over time only), to explain each hit.
- Save the benign per-feature error percentiles, to say "query_length error is at the 99.8th percentile of normal".

**Fusion and detection**
- New column `ml_category`: `KNOWN_ATTACK` (A = 1) · `UNKNOWN_CANDIDATE` (A = 0, B = 1) · `RULE_ONLY` · `CLEAN`.
- New **Rule 7, Unknown DNS anomaly**: fires on `UNKNOWN_CANDIDATE`, MITRE T1071.004 / T1572.
- **Per-host risk score with decay** (docs/week0/PLAN.md, item A7), so Telegram receives one case per host, not one message per query.

## Phase 3: Data and honest evaluation
- **More benign data:** several lab hosts browsing normally for hours, recorded with an attack manifest. A single 50-second capture isn't enough.
- **More tools:** capture iodine and dnscat2 in the lab with `attack.c` modes and a manifest. Keep one tool **only** for testing.
- **External holdout:** DNSTunnel2026 through `evaluation/verify.py --holdout`.
- **Unknown-attack drill** (new headline metric, extends `check_lofo`, verify_models.py:191). For each tool *f*: train Path A without *f*, then run the **full system** (Path A + the saved Path B + fusion + investigation). Report:
  - the share caught as `KNOWN_ATTACK`
  - the share caught as `UNKNOWN_CANDIDATE`
  - the share missed by both
  - the share of *f*'s cases placed outside every known-family radius
  - the benign false-alarm rate
- Report **known-attack** and **unseen-tool** numbers side by side in the paper.

## Phase 4: Investigation engine (`investigation/`)
Triggered for each case (one client, candidates less than `case_gap_minutes` apart):
1. **Why it's unusual:**
   - Path B's per-feature error share ("query_length explains 71%"), and where each error falls in benign training errors
   - z-score of each feature against the benign profile ("query_length 112 vs normal 14, z = +6.1")
2. **Compare to known attacks:**
   - distance to each family centroid in `family_profiles.json`, giving the nearest family and whether the case is inside its `radius_95` ("resembles dns2tcp") or outside them all ("unlike anything trained")
   - Path A's view: `P_rf`, `P_gbt`, the calibrated score vs the threshold ("Path A score 0.31; it fires at 0.42")
3. **Client activity** within ±`context_minutes`:
   - query count and rate
   - unique domains and top 5 parent domains
   - query-type mix and NXDOMAIN share
   - heuristic hits, plus any rule alerts for that IP
- Output `cases/<case_id>.json` + `.md` in the run folder. `dns_detect investigate --run <id>` also works on batch runs.

## Phase 5: Live watcher, Telegram and the feedback loop
**Watcher** (`dns_detect watch`, `live/`):
- Follows the current Technitium log file, switches to the new file when the date changes, and remembers its file offset so a restart doesn't re-read lines.
- Every ~10 s it parses new lines with the existing `parse_technitium_log_line`. Then it updates per-client rolling buffers (the last 20 queries and 60 s, for Path B windows and behavioral features), computes features and scores with Path A + Path B (models loaded once from `registry.py`), runs fusion and the stateless rules plus rolling counters (NXDOMAIN per 15 min), and assigns `ml_category`.
- **Case manager:** opens or updates a case per client, de-duplicates, and sends at most one message per host every `notify_cooldown_minutes`. High-risk cases are sent immediately; medium-risk ones go into a digest. Each case is investigated when opened or when it grows significantly.
- Writes `data/runs/live/<date>/events.jsonl` and `cases/`.

**Telegram** (`notify/`, plain `requests` against the Bot API, long polling, so no public URL or inbound port is needed):
- `telegram.py` sends the case card: client, time span, category, the top three reasons it's unusual, the nearest known family and inside/outside, Path A vs Path B scores, a summary of the client's activity, and sample domains (HTML formatting, truncated to Telegram's limit).
- Buttons: **✅ Confirm attack · ❌ False positive · 🔍 Details** (Details replies with the full `.md` report).
- `bot.py` handles `getUpdates` with `allowed_updates=["callback_query"]` and acts only when `from.id` is in `TELEGRAM_ALLOWED_USER_IDS`. `callback_data` is a short random nonce that maps to the case on the server. It calls `answerCallbackQuery` after every tap and writes an audit log (time, user ID, case, model version, answer). This follows the safety rules in docs/week0/PLAN.md §6.
- The token and allowlist come from `.env` (extend `.env.example`). They are never in the repo or in logs.

**Feedback loop**
- `feedback.py` appends each answer, with the case's records, to `data/feedback/confirmed_cases.jsonl`.
- `dns_detect label --from-feedback` turns confirmed attacks into labeled rows (family `unknown_<case_id>`, or a name you reply with) and false positives into benign rows. They are added to the training set.
- Retraining stays a decision you make (`dns_detect train`). The bot only reminds you: "5 confirmed cases since the last training — retrain?"

## Phase 6: Docs
- Update the Recap, the PathA/PathB explanation files and the two architecture artifacts to the new layout.
- Add `docs/OPERATIONS.md`: how to start the watcher and bot, the `.env` setup and the feedback workflow.

---

## Order and dependencies
```
Phase 0 ─► Phase 1 ─► Phase 2 ─► Phase 3 (evaluation numbers)
                         └──────► Phase 4 ─► Phase 5 ─► Phase 6
```
Phases 3 and 4/5 can run in parallel once Phase 2 is done. A minimal demo needs Phases 0, 1, the profiles and `ml_category` from Phase 2, then Phases 4 and 5.

## Verification
- **Phase 0:**
  - `python -m dns_detect train` and `python -m dns_detect detect` reproduce today's metrics (within noise) from the same `labeled_*.json`.
  - `grep -r "/home/ounnha"` returns nothing.
  - `pytest` passes.
  - Every path comes from `artifacts.py`: a test changes `paths.models_dir` and checks that all modules follow.
- **Phase 1:** unit tests for each fix:
  - the gate uses val (a test with mocked scores)
  - every training feature has variance above 0
  - Path B's coverage equals the number of records
  - the monitor finds every snapshot feature
- **Phase 2/3:** `python -m dns_detect verify` prints the unknown-attack drill table. Success = the full system's unseen-tool catch rate (`KNOWN_ATTACK` + `UNKNOWN_CANDIDATE`) clearly beats Path A's 0.32 / 0.00, with the benign false-alarm rate reported.
- **Phase 4:** run on a batch run; every case file has all three sections. A unit test with a synthetic case checks that the nearest family and the inside/outside result are correct.
- **Phase 5:** unit tests for log following (rotation, restart offset), case grouping and cooldown, card formatting, nonce handling, and rejection of users not on the allowlist (Telegram mocked).
- **End-to-end lab demo:**
  1. Start Technitium, then `dns_detect watch` and `dns_detect bot`.
  2. Run an attack the models weren't trained on (the held-out tool or a new `attack.c` mode).
  3. A Telegram card arrives within ~30 s, showing `UNKNOWN_CANDIDATE`, its reasons, the nearest family and the client's activity.
  4. Tap **Confirm attack**. The row appears in `confirmed_cases.jsonl`.
  5. Run `dns_detect label --from-feedback && dns_detect train`, then repeat the attack. It now shows as `KNOWN_ATTACK`.

## Out of scope
Blocking domains or isolating hosts from Telegram, Wazuh integration, and automatic retraining without your approval.
