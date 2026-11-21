# Audit: training part and detection pipeline

**DNS Traffic Anomaly Detection · code audit of `train_models.sh`, the three learners, the split code, `run_pipeline.sh`, the bridge, the engine and the monitor · 2026-11-21**

Scope: every line of `scripts/train_models.sh` (920), `scripts/prepare_split.py`, `src/dns_detect/models/splits.py`, `path_a.py`, `path_b_train.py`, `path_b_predict.py`, `thresholds.py`, `scripts/train_fusion.py`, `fusion/stacker.py` (V1), `scripts/run_pipeline.sh`, `fusion/bridge.py` (main flow), `detection/engine.py` (ML rules), `monitoring/monitor.py`, `scripts/compare_models.py`. Each finding below names the file and line, says how it was confirmed, what it breaks, and the fix. Things that are *design choices already documented in the project* are listed separately at the end so they are not mistaken for bugs.

Severity: **HIGH** = wrong result or wrong operational decision today · **MEDIUM** = wrong under a condition that Week 7 work will create, or a methodological inconsistency · **LOW** = dead code, misleading output, hygiene.

| # | Severity | Where | One line |
|---|---|---|---|
| 1 | HIGH | `monitor.py` + `train_models.sh` metadata | Drift baseline is built from the wrong columns over benign+attack rows → `retrain_recommended` is **true on every run** |
| 2 | HIGH | `splits.py::_time_split`, `dns_parser.py::load_multifeature_with_meta` | Timestamps parsed without `format="mixed"` → rows in a second format silently become NaT and are mis-ordered (all → train; Path B windows out of order) |
| 3 | HIGH | `path_b_predict.py::score_records` | Only the last query of each 20-query window gets a Path B score; first 19 queries per client and every client with < 20 queries are never scored |
| 4 | MEDIUM | `train_models.sh` steps 5–6 | Input files are marked "trained" **before** training; after a failure, `--retrain` says "models are up to date" |
| 5 | MEDIUM | `stacker.py::fit`, `compare_models.py` | Fusion V1 threshold is in-sample; the gate compares candidate **fusion** with the live model's **Path A**, scored on truncated windows |
| 6 | MEDIUM | `dns_parser.py` | `longest_label` means two different things in Path A and Path B |
| 7 | MEDIUM | `train_models.sh --pcap-label` | One label for every pcap in the run, stored as a *trusted* provenance label |
| 8 | LOW | `engine.py` Rule 6 | Rule 6 can never fire with the learned fusion |
| 9 | LOW | `run_pipeline.sh` | `set -e` exits before the `fail "…"` messages; stale-feature fallback; `PATH_B_MODEL` hard-coded |
| 10 | LOW | `path_a.py` | `conflicts.json` lands in `runs/data/processed/` for run folders |
| 11 | LOW | `path_b_train.py` | Path B normalisation fitted on train rows **including attacks** |
| 12 | LOW | `config/settings.yaml`, `src/*.bak` | Stale config and leftovers |
| 13 | INFO | `data/raw/` | The detector has processed one March lab-attack session and nothing since; the November logs contain no queries |

---

## 1. HIGH — the drift monitor always recommends retraining

**Where.** `scripts/train_models.sh` lines ~843–862 ("Feature snapshot for drift checks: mean/std/min/max of the **first 12 numeric fields**") and `src/dns_detect/monitoring/monitor.py` lines 134–155.

**Confirmed.**
```
models/training_metadata.json → feature_snapshot keys:
  entropy, subdomain_depth, query_length, numeric_ratio, consecutive_pattern_score, num_labels,
  first_label_length, first_label_entropy, client_port, answer_size, hour_of_day, day_of_week
monitor.py loops over FEATURES_8 (query_length, query_entropy, has_digits, answer_count,
  subdomain_count, longest_label, digit_ratio, unique_char_ratio) and skips names not in the snapshot
→ data/processed/monitoring_report.json: drift = {"query_length": {"psi": 8.027, "band": "major"}}
   retrain_recommended = true; reasons = [Major drift in 'query_length' (PSI=8.03), ML scores are saturated]
```
Three things go wrong at once:

1. **Name mismatch.** The snapshot uses Week-3 names (`entropy`, `subdomain_depth`, `numeric_ratio` …); the monitor looks up model names (`query_entropy`, `subdomain_count`, `digit_ratio` …). Only `query_length` matches. 1 of 8 features is monitored; none of the 7 window features is.
2. **Wrong population.** The snapshot is computed over **all labelled rows, benign and attack** (46 % attack, mean `query_length` 71.8, sd 66.3). Live traffic is compared with a bimodal mixture, so PSI is "major" by construction. The monitor then approximates the reference with a Gaussian from mean/sd, which is meaningless for a skewed length distribution.
3. **Forbidden columns in the snapshot.** `client_port`, `hour_of_day`, `day_of_week`, `answer_size` are in `FORBIDDEN_FEATURES` precisely because they encode the capture, not traffic; they are being used as a "baseline".

The second reason, *"ML scores are saturated — model is no longer discriminating"*, fires whenever the live file is mostly attack traffic (see #13: 8,098 of 8,153 rows alarm, correctly). Saturation is read as model failure instead of as "the traffic is mostly attack".

**Consequence.** `retrain_recommended` is permanently true. The SOC learner's trigger (a) counts it (`runs/soc/learner_state.json` → `drift.consecutive: 2` already); the `require_new_data` guard keeps it from training on nothing, but the drift signal carries zero information, so any new capture plus three pipeline runs always starts a retrain "because of drift". `PLAN_v2_improvement.md` Phase 1 #5 described this bug on 2026-10; it was never fixed.

**Fix.**
- In `train_models.sh`, build the snapshot from **benign train rows only**, over `PATH_A_FEATURES` (import the list; do not take "first 12 numeric fields"), and save **decile bin edges** per feature so PSI is computed against real bins, not a Gaussian (this is Week 7 Task 6 step 1).
- In `monitor.py`, loop over the saved snapshot's keys, use the saved edges, and make the saturation check conditional: only when the alarm rate is low (otherwise saturation is expected).
- Add a test: identical data → PSI ≈ 0; the current `models/` snapshot → the monitor must report more than one feature.

---

## 2. HIGH — time ordering breaks silently when timestamp formats are mixed

**Where.** `src/dns_detect/models/splits.py::_time_split` line ~146: `pd.to_datetime(df["timestamp"], errors="coerce")`; `src/dns_detect/parsing/dns_parser.py::load_multifeature_with_meta` line 414, same call. Both then replace NaT with the **row index** as the ordering key.

**Confirmed** on the machine (pandas 2.3.3):
```python
pd.to_datetime(["2019-04-24T03:46:22.757901", "2026-11-21T10:27:05", "2026-11-21 10:27:05"], errors="coerce")
→ [2019-04-24 03:46:22.757901, NaT, NaT]          # format inferred from the first value, applied strictly
pd.to_datetime(..., format="mixed")
→ all three parsed
```
Pcap-derived rows carry microseconds (`…T03:46:22.757901`); rows extracted from a Technitium `.log` carry none (`…T10:27:05`, from `datetime.strptime('%Y-%m-%d %H:%M:%S')`). Today's `merged_features_labeled.json` happens to have one format (59,624 rows, all with microseconds), which is why nothing has broken yet. The `extended` branch of `prepare_training_split` and `features/aggregates.py::epoch_seconds` already use `format="mixed"`; these two places were missed.

**Consequence.** The moment a Technitium log or a Kali capture converted through a different path is merged with the existing JSONs (Week 7 Task 2, B1 "normal browsing", Task 4 "later traffic"):
- `--new-split` / `run_cv.py` time strategy: every row of the second format gets order key = row index (< 10⁶), which sorts **before** every real epoch (≈ 1.7 × 10⁹). All such rows land in **train**, none in val/test. The "time-ordered" split is no longer time-ordered and the test set silently excludes the new source.
- Path B (`load_multifeature_with_meta`): windows for a client whose rows are in the second format are built in file order, not time order; mixed-format clients get the NaT rows first regardless of time.

**Fix.** Use `format="mixed"` in both calls (or call `aggregates.epoch_seconds`, which already does). Add a unit test that splits a frame with two timestamp formats and asserts the chronological order and that no row is ordered by its index. Two lines of code; the test is the important part.

---

## 3. HIGH — Path B never scores the first 19 queries of a client, or any client with fewer than 20

**Where.** `src/dns_detect/models/path_b_predict.py::build_client_windows` (docstring: "Clients with fewer than `window_size` records produce no windows") and `score_records` lines ~250–262: `out_scores[last_idx] = scores … covered[last_idx] = True`; every other record keeps `covered = False`, `ml_score_B = NaN`, `has_score_B = 0`.

**Confirmed** by reading, and visible in the live output: `week3_features_with_ml.json` has `has_score_B = 0` for 20 rows (19 warm-up rows of the one client + the single probe query).

**Consequence.**
- A tunnel that sends fewer than 20 queries per client, or spreads queries over several source IPs, is invisible to Path B. DNSTunnel2026's stealthy scenario (15 s between requests) and dnscat2 at low rate are exactly this.
- The fusion was trained with `has_score_B` as an input and learned a **negative** weight for it (−1.13 live, −3.49 in the model card). So an uncovered row gets a *higher* baseline fusion score than a covered benign row — the coverage gap leaks into the decision.
- `PLAN_v2_improvement.md` Phase 1 #4 described this on 2026-10 ("Give each record the max score of every window that covers it; score short clients with a padded window plus a mask"). Not done.

**Fix.** In `score_records`, after scoring, assign to every record the **maximum** score of all windows that contain it (a record at position *i* in a client's stream is covered by windows ending at *i … i+19*). For clients with fewer than 20 records, pad the window with the client's own rows repeated (or with the per-feature train median) and mark `padded = True`. Then retrain the fusion, because `has_score_B` changes meaning. Add tests: a client with 25 records → 25 covered; with 5 records → 5 covered and `padded`.

---

## 4. MEDIUM — files are marked "trained" before training succeeds

**Where.** `scripts/train_models.sh` step 5 (`register_trained_file "$log_file" …` and `… "$pcap_file" …` run during conversion) and step 6 (`MERGE_ARGS+=(--registry "$TRAINED_FILES_REGISTRY")`, so `ingest/merge.py` registers every JSON/CSV at merge time). Training happens in steps 10–12; nothing removes the entries on `fail`.

**Consequence.** If step 8 stops ("only one class"), step 9 cannot build the split, or Path A/B/fusion fail, the inputs are already in `trained_files_registry.json`. The next `./scripts/train_models.sh --retrain` prints *"No new files since last training — models are up to date"* and exits 0 with **no model trained on those files**. `run_candidate_seeds.sh` is safe because it always passes `--force-retrain`, but the training console's "only files not trained before" mode and a plain `--retrain` are not.

**Fix.** Write the registry entries into a temporary list during steps 5–6 and commit them to `trained_files_registry.json` only at the end (after the run record), or have `fail()` restore the registry from a copy taken at start.

---

## 5. MEDIUM — fusion threshold is in-sample, and the gate compares fusion with Path A

**5a. In-sample threshold.** `src/dns_detect/fusion/stacker.py::fit` (V1, the live fusion):
```python
lr = LogisticRegression(class_weight="balanced").fit(X, y_val)
thr = threshold_for_fpr(y_val, lr.predict_proba(X)[:, 1], max_fpr)   # same rows
```
The alarm threshold that promises "≤ 0.1 % false alarms" is chosen on the rows the model was just fitted to. The project's own hard rule 1 ("never choose a threshold on the rows you report") is respected for the test set but not between fit and threshold. Fusion V2 (`fit_v2`, grouped fit/calibration split + Neyman–Pearson) fixes exactly this and is not live. The V1 tiers file even says so: *"V1 was fitted on these validation rows, so its benign quantiles are in-sample."*

**5b. Gate compares different detectors.** `scripts/compare_models.py`: the candidate is judged by its **fusion** test block (`detector: fusion` in `success_criteria.yaml`), while the live model is scored with `score_frame` → **Path A only** (`_score_child`). Criterion 3 then checks "candidate fusion false alarms ≤ current Path A false alarms". The YAML comment admits "Path A level", but the check is still apples-to-oranges; on the current data it is harmless (7 vs 8) but a candidate whose Path B improves fusion can never get credit for it.

**5c. Current model scored on truncated windows.** `score_current` writes only the **test rows** to a temp file and scores them. Path A's window features (`uniq_subdomains_5m`, `qpm_client_5m`, `iat_std_5m` …) are recomputed by `score_frame` on that subset alone, so the first five minutes of every client/class in the test block see fewer neighbours than when the candidate was evaluated on the full file. The two numbers compared in criterion 3 are not computed on identical feature values.

**Fix.** 5a: split validation into fit/threshold halves in `stacker.fit` (as `path_a.py::_split_validation` already does), or promote V2. 5b: score the live model's fusion too (load `fusion_lr.pkl` from `current_models_dir` and the live Path B), or set `detector: path_a` in the criteria until that exists. 5c: score the whole merged file with the live model and select the test indices afterwards.

---

## 6. MEDIUM — `longest_label` has two definitions

**Where.** `dns_parser.py::parse_week3_json_to_df` (used by Path A, the bridge, the fusion) renames `first_label_length → longest_label` and then **overrides** it with the true longest label computed from `domain` (lines 277–286). `dns_parser.py::load_multifeature_with_meta` (used by Path B train **and** predict) applies the same rename and **does not override** (lines 392–400).

**Consequence.** Path A's `longest_label` = max label length in the name; Path B's `longest_label` = length of the first label. Each path is self-consistent between training and serving, so this is **not** training/serving skew — but `schema.py` compares names only and passes, the model card says "same 11 names, same order", and the drift monitor and any future feature-importance discussion assume one definition. It is a latent trap for anyone who "fixes" one loader.

**Fix.** Give Path B the same override (recompute from `domain` when present), retrain Path B (its norm file changes), and add the computed value to the schema check (a fixture row with a known domain must produce the same `longest_label` through both loaders).

---

## 7. MEDIUM — `--pcap-label` labels every pcap in the run the same way, as trusted truth

**Where.** `train_models.sh` step 5: `PCAP_LABEL_ARGS=(--label "$PCAP_LABEL")` is applied to **every** file in `SRC_PCAP`. `make_labeled_features.py --label` writes `label_source = provenance`, which step 8 and `validate_training_labels` treat as independent ground truth.

**Consequence.** One command cannot train on an attack pcap and a benign pcap together (Task 2 needs exactly that: A1–A4 and B1–B3). Worse, `--files attack.pcap benign.pcap --pcap-label 1` silently labels the benign capture as attack with a *trusted* source, so no guard catches it. The value is also not validated (`--pcap-label 7` is accepted).

**Fix.** Validate 0/1. Accept a per-file label (`--files a.pcap=1 b.pcap=0`) or require `data/attack_manifest.csv` when more than one pcap is given with `--pcap-label`. Your `convert_external_tunnels.py` / `make_labeled_features.py --family` route already does this correctly file by file; the shortcut in `train_models.sh` is the only unsafe path.

---

## 8. LOW — Rule 6 can never fire

**Where.** `fusion/bridge.py` sets `ml_threat_score = ml_combined_score` (fusion probability; 0 where the allowlist suppressed). `detection/engine.py::rule6_ml_threat_score` keeps rows with `ml_threat_score >= 0.7` **and** `ml_combined_label != 1`. The fusion threshold is 0.487, so every row with score ≥ 0.7 already has label 1. Rule 6 therefore selects nothing (suppressed rows have threat 0).

**Consequence.** Harmless, but the README's "6 rules" and the engine docstring (`ml_threat_score = 0.4*rule_score + 0.35*ml_score_A + 0.25*ml_score_B`) describe something that no longer exists.

**Fix.** Either delete Rule 6 or redefine it as the **review band** of Week 7 Task 7 (rows with fusion score between the MEDIUM tier cut and the alarm threshold → `REVIEW` alerts). That gives it a real job.

---

## 9. LOW — `run_pipeline.sh` error handling and fallbacks

- `set -euo pipefail` is on, so `python3 -m dns_detect.fusion.bridge … | tee -a LOG` exits the script the moment the bridge fails. The following `[[ $? -eq 0 && -f … ]] || fail "ML bridge failed"` never runs; the user sees the Python traceback and no summary line. Same for extraction, engine and monitor (the monitor has `|| warn`, so it is fine). Fix: `if ! python3 … | tee …; then fail …; fi`, or `set +e` around those blocks.
- "No `.log` files → using cached features": a run with an empty `data/raw/` silently re-scores last time's `week3_features_all.json` and emits alerts for old traffic as if new. Fix: print the cached file's mtime in the banner and the alert metadata, or require `--detect-only` to use the cache.
- `PATH_B_MODEL="dns_trafficformer"` is hard-coded; `train_models.sh --model-name X` produces a Path B the pipeline cannot find. Fix: read it from `training_metadata.json: path_b_model_name`.
- Step 1 re-extracts **every** log in `data/raw/` on every run (no incremental mode). Fine today (8,250 lines), slow later.

---

## 10. LOW — `conflicts.json` written to the wrong place for run folders

`path_a.py` line ~430: `os.path.join(_MODELS_DIR, "..", "data", "processed", "conflicts.json")`. With `DNS_DETECT_MODELS_DIR=runs/x_s42` this is `runs/data/processed/conflicts.json`. No conflicts occurred in recent runs, so the folder does not exist yet. Fix: `PROJECT_ROOT / "data" / "processed"` or write it next to the models.

---

## 11. LOW — Path B normalisation fitted on attack rows too

`path_b_train.py` line ~239: `X_tr = X[splits["train"]]; f_min = X_tr.min(axis=0); f_rng = …` — the train split contains attack rows (46 % of the data). The model is then trained on benign windows only. Not label leakage (min/max carry no labels) and consistent at inference, but the range is stretched by attack extremes (`query_length` to 253), so benign values compress into a narrow band and the Isolation Forest sees less resolution where it matters. Fix: fit `min`/`range` on **benign** train rows (`X[tr_mask & (labels == 0)]`); clip at inference.

---

## 12. LOW — stale config and leftovers

- `config/settings.yaml: models.path_b.model_file: "dns_trafficformer.h5"` — the live file is `dns_trafficformer_iforest.pkl`; the code ignores the setting, readers don't know that. `rf_weight`/`tf_weight` belong to the legacy blend only.
- `src/dns_detect/{features/extractor,fusion/bridge,models/path_b_train,parsing/dns_parser}.py.bak` — four stale copies in the package tree; `PLAN_v2` Phase 0 lists them for deletion.
- `train_models.sh` installs missing packages with `pip install … --break-system-packages` **inside the training run** (step 2). In the venv this is harmless; on a system Python it modifies the environment mid-run and the run record then records a different `pip freeze` than the one the previous run had.

---

## 13. INFO — what the detector has actually seen

`data/processed/week3_features_with_ml.json` = **8,152 rows from `data/raw/2026-03-18.log`** (one client, `192.168.197.135`, all under `lab.local` — the attack simulator session) **+ 1 row** from `2026-11-21.log` (a `test-probe.invalid` query). `2026-03-19.log` and `2026-03-20.log` contain only "Logging started / failed to notify" lines, no queries. So:

- 8,098 of 8,153 rows alarm, Path A score 1.0 on 90 % of rows. For a lab attack flood this is the expected result, not a bug — but it is the *only* traffic the pipeline has ever scored, and it is what makes finding #1's "saturation" fire.
- Technitium has logged **no client queries since March** on this machine. Either query logging is off, the PushLogger path (`scripts/technitium_push_listener.py`) is the live route and `data/raw` is stale, or the resolver has had no clients. Week 7 Task 11 (real-mode test) needs this sorted first.

---

## Not bugs (documented design choices, listed so they are not re-reported)

| Item | Where documented |
|---|---|
| Frozen test rows never receive new data; new rows go to train/val only | `prepare_split.py` docstring; the trade-off is that new attack *families* are never in test — hence the leave-one-tool-out study |
| Window features are computed on the whole file before the split | `path_a.py` comment: "uses no labels and only past traffic, so computing them before the split is what live detection does too" |
| Conflict rows (same feature vector, both labels) stay in the **test** set | `path_a.py`: "the shared test rows stay exactly as listed" |
| Path A's threshold half has ~550 benign rows, so `k = floor(0.001 × 550) = 0` and the threshold must clear the maximum benign score → seed-sensitive | Week 7 Task 1 (T4), already analysed; fix is the Neyman–Pearson threshold with ≥ 2,995 benign rows |
| The record-type rule beats every model and the gate fails | Week 6/7 reports; the fix is data (Task 2), not code |
| 20-seed and multi-seed runs copy `merged_features_labeled.json` into each run folder (1.8 GB) | `run_record.py --copy-merged`, on purpose for reproducibility |

---

## Suggested order of fixes

| Order | Finding | Effort | Why this order |
|---|---|---|---|
| 1 | #2 timestamps (`format="mixed"` ×2 + test) | 30 min | Two lines; it will bite the first time Task 2 data is merged |
| 2 | #1 drift baseline (benign rows, PATH_A_FEATURES names, saved bin edges) | 2–3 h | Removes the permanent false retrain signal; it **is** Week 7 Task 6 step 1 |
| 3 | #4 registry after success | 30 min | Prevents a silent "nothing to train" after any failure |
| 4 | #7 per-file pcap labels | 1 h | Needed before Task 2 captures are trained together |
| 5 | #3 Path B coverage (max over covering windows, padded short clients) + fusion retrain | half a day + one 3-seed run | Real detection gap for slow tunnels; changes `has_score_B` semantics |
| 6 | #5a fusion fit/threshold halves (or promote V2) | 1 h + 3-seed run | Methodological; do it with #3 since the fusion is retrained anyway |
| 7 | #6, #8, #9, #10, #11, #12 | 2–3 h total | Hygiene; #8 can become the review band (Task 7) |

Every fix that changes a model (#3, #5a, #6, #11) goes through `run_candidate_seeds.sh` → gate, as the project rules require. Fixes #1, #2, #4, #7, #9, #10 change no model and need only their unit tests.
