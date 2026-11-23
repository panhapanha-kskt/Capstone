# Week 8 project audit and limitations

**DNS Traffic Anomaly Detection · reviewed 2026-11-23**

This audit records the current limitations of the project and the evidence behind them. It builds on the [Week 7 training audit](../Week7/AUDIT_TRAIN_PIPELINE_2026-11-21.md), the [project review](../Week7/PROJECT_REVIEW_2026-11-21.md), the [model card](../../models/MODEL_CARD.md), and the current source tree. The accompanying [Week 8 interface plan](WEB_INTERFACE_PLAN.md) covers the next authorized development scope.

## Scope and verification

The review covered the DNS parsing, training, scoring, promotion, monitoring, SOC server, training console, eight SOC pages, and the reports cited above. The previous interface change passed 56 dashboard regression tests and headless Chrome checks on eight SOC pages with local demo fixtures. Those checks exercised navigation, the Alerts assignment filter, Triage queue recovery, and case opening. They did not exercise live Technitium ingestion or Elasticsearch/Kibana delivery. The 16 artifacts listed in `models/PROMOTED.json` matched their recorded SHA-256 hashes during the review.

Severity describes the effect if a finding occurs. A documented design choice is identified separately from a defect. The numbers below are tied to the checked-in artifacts and should be updated after new evaluation runs.

## Findings

| ID | Severity | Finding and evidence | Consequence | Status |
|---|---|---|---|---|
| A1 | High | Analyst identity is supplied by the browser. `dashboard/server.py::_actor` checks that the ID exists in `analysts.json`, and `authorize` derives its tier from that ID. The API reports `authenticated: false`. | A user with access to the dashboard can select another listed analyst, including a higher tier. Attribution and four-eyes approval cannot be treated as authenticated controls. | Open. The current tier checks are workflow controls. |
| A2 | High | `scripts/train_models.sh` builds `feature_snapshot` from the first 12 numeric fields of all labeled rows. `monitor.py` checks `FEATURES_8` against that snapshot. The promoted metadata has only one matching name, `query_length`. The saved monitoring report contains only that feature, PSI 8.027, and recommends retraining. | The drift and retraining signal is unreliable. The baseline mixes benign and attack traffic and includes fields outside the model feature contract. | Open. See Week 7 audit §1. |
| A3 | High | The promoted model card reports fusion recall 1.000 and 7 false alarms among 1,168 benign test queries, a 0.60% false-positive rate. The project target is 0.10%. `config/success_criteria.yaml` judges fusion candidates, while its current-model comparison is Path A level. | The promoted operating point misses the stated budget. The gate's current-versus-candidate result is not a direct fusion-versus-fusion comparison. | Open. The rule baseline and additional data evaluation remain important. |
| A4 | High | `splits.py::_time_split` and `dns_parser.py::load_multifeature_with_meta` call `pd.to_datetime(..., errors="coerce")` without mixed-format parsing. The Week 7 audit reproduced mis-ordering with timestamps that differ in fractional seconds. | Future merged sources can be ordered incorrectly in a time split and in Path B client windows. | Open. See Week 7 audit §2. |
| A5 | Medium | `path_b_predict.py::score_records` writes scores to `last_idx`, the final query of each full 20-query window. | Early queries and clients with fewer than 20 queries lack Path B scores. This is a coverage limitation, and a scoring change would require fusion retraining and evaluation. | Open. See Week 7 audit §3. |
| A6 | Medium | `train_models.sh` registers input files during conversion and merge before all training stages complete. | A failed run can leave the registry claiming that inputs were trained, affecting later incremental retraining. | Open. See Week 7 audit §4. |
| A7 | Medium | The Week 7 audit found an in-sample fusion threshold and a gate that compares candidate fusion with current Path A. | Reported candidate gains can be biased or difficult to interpret. | Open. See Week 7 audit §5. |
| A8 | Medium | The Week 7 checklist marks dashboard testing in real mode as unfinished. The available browser checks used demo fixtures, and the Week 7 scratch live check used a temporary VM copy and stand-ins for training and the gate. | The complete browser-to-live-service workflow and Elasticsearch/Kibana export remain unverified on the intended deployment. | Open. |
| A9 | Low | `README.md` describes the autoencoder as the default Path B algorithm. `train_models.sh` currently sets `PATH_B_TYPE="iforest"`. | The quick-start explanation can lead readers to expect the wrong model. | Open documentation correction. |

## Interface findings and current state

The earlier interface review found duplicate navigation across SOC pages, missing links to Triage from three pages, placeholder navigation items, limited narrow-screen support, and silent Triage queue polling failures. The current working tree includes a shared navigation shell, mobile menu, status display, Alerts assignment filter, and visible Triage retry flow in `dashboard/static/js/chrome.js`, `dashboard/static/css/shell.css`, `dashboard/alerts.html`, and `dashboard/static/js/triage.js`. These changes passed the checks described above. They are still working-tree changes at the time of this document and should be reviewed together with the Week 8 plan.

The remaining interface work is to verify these pages against a real-mode dashboard, improve keyboard and screen-reader behavior in the data-heavy views, and make error and freshness states consistent across pages. Those items are specified in [WEB_INTERFACE_PLAN.md](WEB_INTERFACE_PLAN.md).

## Evidence boundaries

The frozen test result comes from the promoted model card. Some Week 7 notes cite eight false alarms for a different evaluation context. Keep the dataset, run, and denominator beside each metric. The saved monitoring report is evidence of the current drift output, not proof that live traffic has drifted. The demo browser checks establish interface behavior with fixtures; they do not establish live data correctness.
