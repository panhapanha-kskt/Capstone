# ML Improvement — Implementation (Phase 4) and Evaluation (Phase 5)

**DNS Traffic Anomaly Detection · Capstone · 2026-11-19 · branch `ml-improvement`**

This document follows [ML_IMPROVEMENT_RESEARCH_2026-11-19.md](ML_IMPROVEMENT_RESEARCH_2026-11-19.md).

| Decision | Choice |
|---|---|
| Items | 1–5 (the recommendation) |
| Dataset | A: the `labelled_v3` bundle on this machine |
| Path B | Isolation Forest |

The live `models/` folder was only read, never written. The 3-seed training runs have **not been run yet**: they need your machine (§4).

---

## 1. What changed

| Item | Files | What it does |
|---|---|---|
| **1 Run record** | `scripts/run_record.py` (new), `scripts/train_models.sh` (end of the run), `dashboard/training-gui/adapters/feature_table_train.py` | Every run writes `run_record.json`: git commit, branch and uncommitted files; Python version and `pip freeze`; sha256 and size of every input file; split-manifest sha256; seed. In a separate run folder it also **copies `merged_features_labeled.json`** into the run. `models/` gets the record but not the data. Feature tables are recorded but not copied, because they can be several GB. A failure here never fails the training. |
| **2 Forbidden features** | `feature_table_train.py`, `tests/test_ml_improvements.py` | The GUI's feature-table trainer now drops identity, time and provenance columns before fitting and logs which ones. A timestamp column is still used for the time split, never as an input. Tests check the live feature lists, every saved `dns_threshold.json` / `model_meta.json` (models/, runs/, GUI runs; read only), and the trainer itself. |
| **3 Success criteria + gate** | `config/success_criteria.yaml` (new), `scripts/compare_models.py` (new), `scripts/run_candidate_seeds.sh` (new), `.gitignore` (`runs/`) | The criteria are written before training. `compare_models.py` reads ≥3 seed run folders and checks the candidate on each run's own frozen test rows against (a) the floors and budget, (b) the current `models/` Path A scored on the **same rows** (read only, in a child process), and (c) the rule baselines (thresholds fitted on train rows only). It prints mean ± sd and PASS/FAIL per criterion. Anything it can't measure counts as FAIL; it doesn't guess. |
| **4 FPR intervals** | `src/dns_detect/models/thresholds.py` (`rate_interval`, `min_rows_for_rate`, `budget_evidence`, `budget_message`), `path_a.py`, `scripts/train_fusion.py`, `feature_table_train.py` | Every metric block now carries a 95% Clopper–Pearson interval for FPR and recall. Path A, fusion and the GUI trainer log a **budget check**: whether the benign test rows can show the rate is within 0.1%. 2,995 benign rows with zero false alarms are needed for that. |
| **5 Twin-free metrics** | `path_a.py` (`twin_free_metrics`) | The Path A test report is repeated on test rows whose exact feature vector never appears in train. It is saved as `test_without_train_twin`, next to the existing twin share. |

Nothing changed in how models are trained or thresholds are chosen. Items 1–5 only add records, checks and reports, so trained models are the same as before for the same data and seed.

---

## 2. Tests (Observed, run in my Linux workspace on your project folder)

| Suite | Result |
|---|---|
| `tests/test_ml_improvements.py` (new, 26 tests) | **26 passed** |
| ML suites (all other tests except the dashboard and console ones) | 240 passed, 2 skipped, **1 failed**: `test_labeling.py::test_parent_domain_psl_private_suffixes` |
| `test_training_console.py`, `test_dashboard_soc.py`, `test_dashboard_triage.py`, `test_training_upload.py` | **101 passed** |

The one failure has nothing to do with these changes. `tldextract` isn't installed in my workspace, so the public-suffix lookup falls back to a simpler rule. `labeling.py` wasn't changed. On your machine, with `tldextract` installed, it should pass.

To make the Path A test runnable here, I installed `tensorflow-cpu 2.15` and `tqdm` into my workspace only. Nothing on your machine changed.

**Smoke checks (Observed):**
- **Path A on a 6,000-row sample** of the current merged data (written to a scratch folder, not `models/`) printed the new lines: *"only 644 benign test rows: they cannot show a rate below 0.100% … upper 95% bound = 0.464%"*, the FPR and recall intervals, and the twin-free test (all 773 rows, as expected with a grouped split).
- **`run_record.py`** recorded commit `670b35b`, the uncommitted files, 183 packages, and the 3 input files. Their sha256 is null in my workspace because the `/mnt/c/...` paths only exist on your machine.
- **`compare_models.py`** ran on a copy of your latest GUI run (`20261119-015201-8ffe`, one seed only):

| Detector on the same 2,568 test rows (1,168 benign) | Recall | False alarms | FPR 95% interval |
|---|---|---|---|
| Fusion (candidate) | 1.000 | 13 | — |
| **Rule: record type is TXT/KEY/NULL** | **1.000** | **0** | 0.00–0.32% |
| Rule: entropy > 4.0 (literature) | 0.999 | 42 | 2.6–4.8% |
| Rule: entropy, fitted on train | 1.000 | 92 | 6.4–9.6% |
| Rule: length, fitted on train | 1.000 | 210 | 15.8–20.3% |

The gate said FAIL, correctly: one seed instead of 3, FPR 1.11% against the 0.1% budget, and the record-type rule beats the ML model. The current `models/` couldn't be scored in my workspace: its pickles need your NumPy version, and mine was changed to install TensorFlow. On your machine the gate will score it.

---

## 3. What this already tells us (Observed)

**On `labelled_v3`, a one-line rule beats the ML model.** "Record type is TXT, KEY or NULL" catches every tunnel with zero false alarms. The tunnels in this bundle use those record types, and the benign traffic doesn't. Your settings already note the same shortcut (`exclude_features: [tunnel_rr_share_5m]`).

So on this data:
- the success criterion "beat every rule baseline" can't pass;
- Arp et al. call this a **spurious correlation**: the dataset separates the classes by record type, so the test can't show whether the ML learned tunnel *behaviour*.

What would fix it is data, not code: benign traffic that also uses TXT/NULL (mail, SPF/DKIM, service discovery), or tunnels over A/AAAA/CNAME. The criteria weren't changed to hide this.

---

## 4. Phase 5: the 3-seed run (needs your machine)

My workspace has 2 CPUs and 3 GB RAM, and stops any program after 3 minutes. One full `train_models.sh` run takes about 4 minutes on your machine, so the seeds have to run there.

In Kali, from the Windows project folder, with the venv you train with:

```bash
cd /mnt/c/Programming-CTF/Capstone
source ~/Capstone/.venv/bin/activate          # or the venv you used for the GUI runs
./scripts/run_candidate_seeds.sh
```

What it does:

| Step | Detail |
|---|---|
| Seeds | 42, 43, 44, each into `runs/labelled_v3_iforest_s<seed>/`; `models/` is never touched |
| Split | all seeds reuse your latest run's split (`…8ffe/model/split_manifest.json`), so seeds differ only in model randomness |
| Gate | runs `compare_models.py` at the end; the report is in `runs/labelled_v3_iforest_gate.json` |
| Expected time | about 12–15 minutes |

Then send me the last 20 lines it prints. I'll write the results in here as observed numbers.

After that, `data/processed/` will show as modified again. That's normal; don't commit it.

---

## 5. Commit

`git` can't create its lock files from my workspace, so please commit from PowerShell:

```powershell
cd C:\Programming-CTF\Capstone
git add .gitignore config/success_criteria.yaml scripts/run_record.py scripts/compare_models.py scripts/run_candidate_seeds.sh scripts/train_models.sh scripts/train_fusion.py src/dns_detect/models/thresholds.py src/dns_detect/models/path_a.py dashboard/training-gui/adapters/feature_table_train.py tests/test_ml_improvements.py docs/Week6/ML_IMPROVEMENT_IMPLEMENTATION_2026-11-19.md
git commit -m "ML items 1-5: run record, forbidden-feature checks, FPR intervals, twin-free metrics, success-criteria gate"
```

Don't push or merge yet.

---

## 6. Limits

- The gate compares against the current `models/` at **Path A level** only. The live Path B is the autoencoder and needs TensorFlow to re-score.
- The current model may have been trained on some of the candidate's test rows, which favours it.
- Intervals assume test rows are independent. Near-duplicate rows make them look tighter than they are, which is one more reason to read the twin-free numbers.
- `run_record.json` in `models/` (CLI runs without `DNS_DETECT_MODELS_DIR`) records the inputs but doesn't copy the data, so the live folder doesn't grow.
- Path B's own report doesn't have intervals yet; the fusion and Path A reports do.

Reference for the shortcut and the gate design: Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security 2022. The other references are in the research doc.
