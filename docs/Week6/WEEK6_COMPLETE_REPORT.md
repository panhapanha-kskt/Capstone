# Week 6 Complete Report

**DNS Traffic Anomaly Detection · Capstone · Week 6 (2026-11-10 to 2026-11-18)**

This is the single document for the whole of Week 6. It covers the SOC dashboard build, the Week 5
evaluations that were still missing, the Path B replacement, the multi-seed checks, the dashboard tests,
the production hardening and ML ↔ SOC-tool integration, and the Tier 1 triage workbench. Each part links
to its detailed document.

| Detailed document | Covers |
|---|---|
| [../../dashboard/docs/WEEK6_IMPLEMENTATION_REPORT.md](../../dashboard/docs/WEEK6_IMPLEMENTATION_REPORT.md) | the Week 6 SOC dashboard build (2026-11-10) |
| [WEEK6_AUDIT_AND_FORTINET_ROADMAP.md](WEEK6_AUDIT_AND_FORTINET_ROADMAP.md) | dashboard audit and Fortinet-parity roadmap |
| [WEEK6_PROGRESS_REPORT.md](WEEK6_PROGRESS_REPORT.md) | the ML-side session summary and status table |
| [V3_EVALUATION_RESULTS.md](V3_EVALUATION_RESULTS.md) | every v3 evaluation number and how it was produced |
| [PATH_B_ISOLATION_FOREST.md](PATH_B_ISOLATION_FOREST.md) | why and how Path B became an Isolation Forest |
| [WEEK6_SOC_HARDENING_REPORT.md](WEEK6_SOC_HARDENING_REPORT.md) | security hardening, bug fixes, SOC workflow, exporters (2026-11-17) |
| [SOC_ML_INTEGRATION.md](SOC_ML_INTEGRATION.md) | connecting the ML alerts to Elasticsearch/Kibana, syslog SIEMs and SOAR |
| [TIER1_TRIAGE_REPORT.md](TIER1_TRIAGE_REPORT.md) | the Tier 1 triage workbench `/triage` (2026-11-18) |
| [next task.md](next%20task.md) | task list, commands and checklist |
| [../../dashboard/docs/API_REFERENCE.md](../../dashboard/docs/API_REFERENCE.md), [../../dashboard/docs/TESTING_REPORT.md](../../dashboard/docs/TESTING_REPORT.md) | every endpoint; every test case and result |

---

## Contents

1. [Summary](#1-summary)
2. [Timeline](#2-timeline)
3. [Part A: the SOC dashboard](#3-part-a-the-soc-dashboard)
4. [Part B: finishing the Week 5 evaluation](#4-part-b-finishing-the-week-5-evaluation)
5. [Part C: Path B becomes an Isolation Forest](#5-part-c-path-b-becomes-an-isolation-forest)
6. [Part D: multi-seed stability](#6-part-d-multi-seed-stability)
7. [Part E: dashboard end-to-end test](#7-part-e-dashboard-end-to-end-test)
8. [Part F: production hardening and SOC workflow](#8-part-f-production-hardening-and-soc-workflow)
9. [Part G: connecting the ML model to SOC tools](#9-part-g-connecting-the-ml-model-to-soc-tools)
10. [Part H: Tier 1 triage workbench](#10-part-h-tier-1-triage-workbench)
11. [Testing summary](#11-testing-summary)
12. [Files added and changed](#12-files-added-and-changed)
13. [Problems hit and lessons](#13-problems-hit-and-lessons)
14. [Status at the end of Week 6](#14-status-at-the-end-of-week-6)
15. [Limits and next steps](#15-limits-and-next-steps)
16. [Update: work on 2026-11-18/19](#16-update-work-on-2026-111819)

---

## 1. Summary

**Machine learning**
- **The Week 5 v3 model works across tools and networks.**
  - Unseen benign traffic (CIC capture 3): 1 false alarm in 25,222 queries (0.004%).
  - Leave-one-tool-out: recall 1.0 on all 8 tunnel tools.
- **Path B now uses an Isolation Forest.** The autoencoder had recall 0.0 on v3 and took about 6 h 37 min to train. The Isolation Forest has recall 1.0 and trains in about 1 minute.
- **The full system gives the same result 11 times faster.** `runs/v3_iforest` has fusion recall 1.0 with 7 false alarms, trained in 39 min 5 s instead of 7 h 17 min.
- **The system is stable across training seeds.** Over 5 seeds, the full system (Path A + Isolation Forest Path B + fusion) gives 7–9 false alarms (mean 8.2, SD 0.84), with recall 1.0 every time.

**Dashboard**
- **SOC suite:** an 8-page SOC monitoring suite with persistent alert management, an audit trail, incidents and pipeline health. All test cases passed in demo mode.
- **Hardening:**
  - CSRF / DNS-rebinding protection and a nonce-based Content-Security-Policy.
  - React and htm served locally instead of from a CDN.
  - Ten bugs fixed.
  - Smoother rendering (304 responses, row patching, polling paused in hidden tabs).
- **SOC workflow:** analyst verdicts, MTTD / MTTA / MTTR, MITRE ATT&CK heatmap, related alerts, false-positive suppression, playbook hints, shift handover.
- **ML ↔ SOC tools:**
  - ML alerts can now be exported to Elasticsearch/Kibana (ECS, no duplicates on re-run), syslog CEF (FortiSIEM, Wazuh, Splunk, QRadar) and a signed webhook.
  - The deployed model, thresholds and drift are shown in the UI.
  - Analyst verdicts export as training labels.
- **Tier 1 workbench (`/triage`):**
  - The real 2,410-alert storm becomes 3 cases.
  - Each case has one-screen DNS evidence, an auto-evaluated DNS-tunnel checklist and an ML "why it fired" panel.
  - Analysts claim a case, close it with a mandatory classification, or escalate it with a structured handover.
  - Tier guardrails apply, with four-eyes approval for High/Critical false-positive closures.
- **Tests:** 43 dashboard tests and 47 ML unit tests pass.

---

## 2. Timeline

| Date | Work |
|---|---|
| 2026-11-10 | Week 6 SOC dashboard built: alert management, audit log, Event Explorer, Sources & Collection, Pipeline Health, Incidents, SOC overview additions, server-side use-case preferences. Testing report written (pre-execution). |
| 2026-11-12 | Audit of the repository against the Week 5 plan: Week 5 incomplete (v3 never evaluated beyond the frozen test set). Task list created. Path B slowness analysed; decision to switch to an Isolation Forest. |
| 2026-11-12 to 14 | Isolation Forest implemented as a selectable Path B (`--path-b-model iforest`). `week5_eval.sh` written; Week 5 Tasks 0–3 run. `run_cv.py` leave-one-tool-out fixed. Full run `runs/v3_iforest` (39 min). 47 unit tests passed. |
| 2026-11-14 | Multi-seed check of Path A (Tasks 4–5); conclusion and `models/` decision (Task 6); evidence saved to git (Task 7, 46 files); stale docs fixed (Task 9). |
| 2026-11-17 | Full multi-seed with Path B + fusion (5.4.3), including the seed 46 re-run. Dashboard test results recorded (Task 8). Production SOC audit; research on vendor practice; hardening, workflow features and SOC-tool exporters built. |
| 2026-11-18 | Tier 1 research and gap check; `/triage` workbench, guardrails and four-eyes approvals built; 43 dashboard tests passing. |

---

## 3. Part A: the SOC dashboard

The dashboard is a standard-library Python server (`dashboard/server.py`, no framework) that watches the
Technitium log folder. On each change it re-runs the pipeline (extractor → ML bridge → detection engine
→ monitoring) and serves the results. Persistence uses JSON files in `dashboard/data/`, with atomic writes and
`.bak` recovery. `--demo` produces synthetic alerts.

| Page | Purpose |
|---|---|
| `/` Classic | the original live alert feed and charts |
| `/soc` Monitoring Overview | KPI tiles, severity / status / SLA donuts, historical charts, operational metrics |
| `/usecases` | Cyber Kill Chain view and per-rule use cases with server-side visibility preferences |
| `/alerts` | React grid, alert drawer, bulk Execute (FortiSOAR-style) |
| `/events` | filterable Event Explorer with the pipeline's `details` |
| `/devices` | Sources & Collection: client IPs and log sources (honestly labelled: not an asset inventory) |
| `/health` | transparent health bands with reasons, freshness, drift, run history |
| `/incidents` | incident queue; response actions are only ever SIMULATED or NOT_CONFIGURED |
| `/triage` | Tier 1 triage workbench (Part H) |

Key design points:
- **Stable alert key:** `fp` is a SHA-1 of the alert's rule, client, domain, query time and description, so management records survive the pipeline's fresh UUIDs on every run.
- **Strict lifecycle:** Open → Acknowledged → Investigating → Escalated → Resolved → Closed, with an `ALLOWED_TRANSITIONS` table (invalid moves return 409).
- **Audit:** every action goes into `audit_log.json`.

---

## 4. Part B: finishing the Week 5 evaluation

Week 5 had trained `runs/v3` (8 tunnel tools, 100,000 attack / 118,334 benign rows) but recorded only its
frozen-test results. `scripts/week5_eval.sh` runs the missing tasks in one command.

**Frozen test set** (2,568 rows, 1,168 benign; all attacks dnsexfiltrator):

| Run | Fusion recall | Fusion false alarms | Path A false alarms | OR-rule false alarms |
|---|---|---|---|---|
| baseline | 1.0 | 23 | 23 | 116 |
| v_dnsshell | 1.0 | 7 | 7 | 113 |
| v_det | 1.0 | 38 | 36 | 119 |
| v3 | 1.0 | 7 | 8 | 87 |
| **v3_iforest** | **1.0** | **7** | 8 | 110 |

**Unseen benign traffic** (CIC-Bell-DNS-EXF-2021 capture 3, 25,222 queries, budget 0.1% ≈ 25): baseline 1,
v_dnsshell 0, v_det 1, **v3 1 (0.004%)**, **v3_iforest 1**.

**Leave-one-tool-out** (each tool removed from training in turn, then tested as unseen):

| Result | Value |
|---|---|
| Recall | **1.0 on all 8 tools**: cobaltstrike, det, dns2tcp, dns_shell, dnscat2, dnsexfiltrator, iodine, ozymandns |
| False alarms | 0.35–0.59% (mean 0.427%), above the 0.1% the threshold was set for |
| What the false alarms show | the same validation-to-test threshold drift seen on the frozen test set |

A bug was fixed along the way: `run_cv.py` had been treating benign data sources as "tools".

---

## 5. Part C: Path B becomes an Isolation Forest

| | Transformer autoencoder | Isolation Forest |
|---|---|---|
| Recall / FPR (test windows) | 0.000 / 6.23% | **1.000 / 9.34%** |
| PR-AUC | 0.787 | **1.0** |
| Attack median ÷ benign 99th-percentile score | 0.573 | **1.35** |
| Path B training time | ≈ 6 h 37 min | **65.8 s** |
| Full training run | 7 h 17 min | **39 min 5 s** |

- **Why:** on the CPU-only Kali VM (about 4 vCPU, 7.7 GiB RAM, no GPU), the autoencoder took hours and still missed every v3 attack.
- **How:** the Isolation Forest is selected with `--path-b-model iforest` and saved as `<name>_iforest.pkl`. The threshold file's `model_type` tells the loader which model to use, and TensorFlow is not needed for it.
- **Compatibility:** the autoencoder is still the default, so old runs load unchanged, and it is kept as future work.

---

## 6. Part D: multi-seed stability

**Path A only** (seeds 42–46, false alarms on the frozen test set):

| Run | Mean | SD | Min–max |
|---|---|---|---|
| baseline | 18.2 | 7.56 | 9–25 |
| v_dnsshell | 8.2 | 1.79 | 7–11 |
| v_det | 22.0 | 9.14 | 13–36 |
| **v3** | **8.6** | **0.55** | **8–9** |

By the non-overlap rule no difference between runs is proven, and v3 vs baseline is borderline (the ranges touch
at 9). v3's main gain is a result that barely moves between trainings.

**Full system** (Path A + Isolation Forest Path B + fusion, `run_multiseed.py --path-b-model iforest`):

| Seed | Path A FA | Fusion FA | Fusion recall | Path B recall | Path B FPR |
|---|---|---|---|---|---|
| 42 | 8 | 7 | 1.0 | 1.0 | 9.34% |
| 43 | 9 | 8 | 1.0 | 1.0 | 9.98% |
| 44 | 9 | 9 | 1.0 | 1.0 | 13.55% |
| 45 | 8 | 8 | 1.0 | 1.0 | 11.36% |
| 46 | 9 | 9 | 1.0 | 1.0 | 13.10% |
| **Summary** | **8.6 ± 0.55** | **8.2 ± 0.84 (7–9)** | **1.0** | **1.0** | 9.3–13.6% |

**Decision (Task 6):** `runs/v3_iforest` is the candidate model. `models/` stays unchanged until the mentor
agrees that Path B may be a classical ML model.

---

## 7. Part E: dashboard end-to-end test

| Category | Result |
|---|---|
| Static checks | PASS |
| Regression tests (7 cases: every page renders, `/api/state` shape, polling, drawer) | PASS |
| Feature tests (9 cases: lifecycle, invalid transition 409, restart persistence, bulk, Event Explorer, Sources honesty, health band, use-case prefs, response-action honesty) | PASS |
| Restart persistence | PASS |
| Demo mode end-to-end | PASS |
| Real mode end-to-end | not run (needs the live pipeline log folder) |

Test 3.2 was corrected along the way. The clean invalid-transition case is Closed → Investigating (409, `allowed: ["Open"]`).

---

## 8. Part F: production hardening and SOC workflow

A production-SOC audit, plus research into vendor and standards practice, found missing CSRF protection,
missing security headers, flicker, and missing analyst workflow. The sources were Fortinet, Splunk,
QRadar, Sentinel, Elastic, Wazuh, OWASP and NIST SP 800-61r3.

**Security**
- **Request checks:** a Host allowlist (DNS rebinding), JSON-only POSTs (415 otherwise), a required `X-SOC-Request: 1` header, and Origin / `Sec-Fetch-Site` checks (403 otherwise).
- **`/api/run`:** audited, and refused with 429 if repeated within 10 s.
- **Headers:** every response gets `nosniff`, `X-Frame-Options: DENY`, `no-referrer` and COOP/CORP.
- **CSP:** HTML pages get a Content-Security-Policy with a fresh nonce per response. React 18.3.1, ReactDOM and htm 3.1.1 are served from `dashboard/static/vendor/`.
- **Actors and secrets:** an unknown actor is recorded as `unknown-analyst`. Secrets are redacted (`***`), CSV exports are protected against formula injection, and exporter URLs can't be changed through the API.

**Bugs fixed (10)**
1. Closed alerts could be acknowledged.
2. Severity sorting was alphabetical.
3. The alert drawer reset its tab after every action.
4. The "Assigned To: Me" widgets did nothing.
5. The open-severity chart counted closed alerts.
6. The Incidents page polled twice.
7. A mislabelled KPI tile.
8. The bulk audit write raced with other writes.
9. The Events dropdown closed on every poll.
10. A dead duplicate state hook.

**Rendering:** `/api/state` returns an ETag and answers 304 when nothing changed. Polling pauses in hidden
tabs, and `SOC.patchList` updates rows in place, so scroll position and selection survive.

**Workflow:**
- verdicts (also as a bulk action)
- `/api/metrics`: MTTD, MTTA, MTTR, ack-SLA breaches, FP rate, workload
- ATT&CK tactic × technique heatmap
- related alerts (same IP / registered domain within a time window)
- suppressions with reason and expiry (UI only)
- playbook hints by rule and ML confidence
- shift handover report (JSON or Markdown)

---

## 9. Part G: connecting the ML model to SOC tools

**Audit finding:** the ML scores reached the dashboard and stopped there. The existing ELK stack
(`infra/technitium-elk`: Technitium, Elasticsearch 8.11, Logstash, Kibana, Filebeat) indexed only raw DNS
logs. No ML alert ever reached Kibana, nothing showed which model produced a score, and analyst decisions
never went back to the model.

| Built | What it does |
|---|---|
| `GET /api/model` | model version (hash), Path A / Path B / fusion thresholds, Path B type, training counts, drift |
| ML tab, health panel | scores against thresholds per alert; deployed model, PSI trend, exporter status |
| `dashboard/exporters.py` | background exporter, off by default, configured in `dashboard/data/response_integrations.json` |
| → Elasticsearch | `_bulk` into `dns-ml-alerts-YYYY.MM.dd` in ECS. Each document's ID is the alert's stable fingerprint, so re-runs and status changes update it instead of duplicating. The index template is in `infra/technitium-elk/kibana/`. |
| → syslog CEF | RFC 3164 + CEF over UDP/TCP for FortiSIEM, Wazuh, Splunk, QRadar |
| → webhook | JSON batches signed with HMAC-SHA256 |
| Feedback loop | `GET /api/feedback/export` and `scripts/export_feedback_labels.py` → `data/feedback/labels_*.csv` (label 1 attack, 0 benign). Retraining stays a reviewed human decision. |

Step-by-step setup is in [SOC_ML_INTEGRATION.md](SOC_ML_INTEGRATION.md).

---

## 10. Part H: Tier 1 triage workbench

**Research** drew on Sentinel, Elastic (including its DNS-tunnel investigation guide), Google SecOps,
CrowdStrike, XSOAR, Splunk, SigmaHQ, Infoblox, Unit 42, the Tranco paper, NIST SP 800-61r3, MITRE's
11 Strategies, and IDC / SANS alert-fatigue data. It gave a ranked list of 15 Tier 1 must-haves. Before this
work the dashboard had 0 fully done, 7 partial and 8 missing. After it, all 15 are covered (see
[TIER1_TRIAGE_REPORT.md](TIER1_TRIAGE_REPORT.md), section 3).

**What `/triage` does**
- **Cases:**
  - Alerts are grouped by host + detection type (default) or host + domain apex. Internal zones such as `lab.local` keep an extra label so they don't collapse into one case.
  - The real 2,410 alerts become 3 cases (or 1,949 grouped by domain).
  - Case status is derived from the member alerts, so `/alerts`, metrics and exporters agree.
- **Queue:** counts for My queue, Unassigned, SLA breached and Pending approval, plus by severity. Each case shows an ack clock and a triage clock.
- **Evidence:** taken from `week3_features_with_ml.json`, re-indexed only when the file changes (about 0.1 s): query and distinct-name counts, record types, response codes, label lengths, encodings, the 5-minute burst count, a timeline and the longest names.
- **Checklist:** 11 automatic checks based on Elastic and Sigma thresholds, plus 2 required manual checks, shown as done x/y. A suggestion (escalate / close / review) is built from them and is never applied automatically.
- **ML panel:** per-model scores against thresholds, signatures, and the top deviations from the client's own baseline.
- **Shared-source warning:** shown for resolvers, docker gateways, loopback and CGNAT addresses.
- **Actions:**
  - one-click claim (acknowledge + assign every member)
  - close with one of six Sentinel-style classifications, with false positives split into "model logic" and "bad data" (better retraining labels)
  - escalate with summary, evidence, checks done, hypothesis and recommended action, pre-filled from the evidence
  - release with a next step
- **Guardrails by tier** (from `analysts.json`):
  - When Tier 1 closes a High/Critical case as a false positive, a close request is created that a different Tier 2 analyst must approve (four-eyes).
  - Tier 1 cannot suppress, run incident actions, change use-case preferences, reopen others' closures or work escalated cases.
  - The same rules apply on the older routes and in bulk actions. Internal `_` keys are stripped from request bodies.
- **Shift:** personal stats (claimed, closed, escalated, median MTTA) and a handover dialog with Markdown download and acknowledgement.
- **Enrichment:** offline Tranco rank (manually downloaded file) and IP flags. VirusTotal / AbuseIPDB are optional (off by default), run in a background thread with rate limits, and never receive internal names or private IPs.
- **Keyboard:** `j`/`k` move, `c` claim, `x` close, `e` escalate, `/` search, `?` help. Shortcuts are ignored while typing.

**Run on the real data:** Tier 1 claimed the ML case (200 alerts), ticked the checks and closed it as
`fp_model_logic`. That produced a 202 pending request, and the Tier 1 approval was refused (403). The Tier 2
approval closed all 200 alerts, with the verdict and approver recorded.

---

## 11. Testing summary

| Suite / check | Result | Where |
|---|---|---|
| ML unit tests (`test_path_b_iforest.py`, `test_path_b_load.py`, `test_bridge.py`) | 47 passed (Kali, 2026-11-14) | WEEK6_PROGRESS_REPORT |
| Dashboard regression + feature tests (manual) | all PASS, demo mode (2026-11-17) | TESTING_REPORT 2–4 |
| `tests/test_dashboard_soc.py` (security, workflow, ML info, exporters) | 24 passed | TESTING_REPORT 5b |
| `tests/test_dashboard_triage.py` (grouping, evidence, guardrails, four-eyes, batch writes, enrichment) | 19 passed | TESTING_REPORT 5c |
| Both dashboard suites together, either order | 43 passed (WSL, 2026-11-18) | — |
| JavaScript syntax check of every page and script | pass | — |
| Real alert file, triage flow end to end | pass | TIER1_TRIAGE_REPORT 6 |
| Browser click-through of the new pages | **not done** (Chrome on Windows could not reach the WSL server) | — |
| Elasticsearch export against the docker-compose stack | **not done** | SOC_ML_INTEGRATION 3 |

Run the dashboard tests with:

```bash
python3 -m pytest tests/test_dashboard_soc.py tests/test_dashboard_triage.py -q
```

---

## 12. Files added and changed

**ML side** (committed earlier in Week 6)
- **Path B:** `src/dns_detect/models/path_b_predict.py` and `path_b_train.py` (Isolation Forest Path B).
- **Scripts:** `scripts/train_models.sh`, `run_pipeline.sh`, `run_multiseed.py` (`--path-b-model`), `scripts/week5_eval.sh` (new), and `scripts/run_cv.py` (leave-one-tool-out fix).
- **Tests:** `tests/test_path_b_iforest.py`.
- **Evidence:** `docs/Week5/evidence/` (46 result files).

**Dashboard** (committed 2026-11-17 in `277a12a`, *Week 6: SOC dashboard hardening, ML-to-SOC exporters, Tier 1 triage workbench*; on `main`)

| File | Change |
|---|---|
| `dashboard/server.py` | request security, headers, CSP nonce, ETag; verdicts, metrics, related, suppressions, handover; `/api/model`, feedback export, exporter wiring; tier permissions, batch case writes, triage API |
| `dashboard/evidence.py` (new) | case grouping, feature index, DNS evidence, checklist, ML panel, Tranco, IP flags, online enricher |
| `dashboard/exporters.py` (new) | Elasticsearch / CEF / webhook exporters and CLI |
| `dashboard/triage.html`, `dashboard/static/js/triage.js` (new) | the Tier 1 workbench |
| `dashboard/static/vendor/` (new) | React 18.3.1, ReactDOM 18.3.1, htm 3.1.1 |
| `dashboard/static/js/chrome.js` | POST header, conditional polling, `patchList`, `pollJSON`, analyst helpers, Triage nav |
| `dashboard/alerts.html`, `soc.html`, `health.html`, `events.html`, `devices.html`, `incidents.html`, `usecases.html`, `index.html` | new tabs and panels, bug fixes, smooth rendering, tier gating |
| `dashboard/docs/API_REFERENCE.md`, `TESTING_REPORT.md` | security rules, permission table, every new endpoint, test results |
| `infra/technitium-elk/kibana/dns-ml-alerts-template.json` (new) | Elasticsearch index template |
| `scripts/export_feedback_labels.py` (new) | verdicts → labelled CSV |
| `tests/test_dashboard_soc.py`, `tests/test_dashboard_triage.py` (new) | 43 tests |
| `docs/Week6/*.md` | this report, the hardening, integration and Tier 1 reports, progress report updates |

**Breaking changes for scripts and procedures:**
- every POST needs `-H 'X-SOC-Request: 1'`;
- incident response actions and use-case preferences need a Tier 2+ actor.

---

## 13. Problems hit and lessons

| Problem | Fix / lesson |
|---|---|
| First Path B test "finished" in 0.05 s | `PYTHONPATH` unset and `2>/dev/null` hid the error. Export `PYTHONPATH=src`; keep errors visible. |
| Leave-one-tool-out reported two benign sources as "tools" | `run_cv.py` now holds out attack families only. |
| `git pull` blocked on Kali | training rewrites tracked files in `data/processed/`; stash or check them out after copying run outputs. |
| No progress visible while a script ran | Python buffers piped output; `PYTHONUNBUFFERED=1`. |
| Multi-seed `summary.json` never appeared | seed 46's fusion failed on a transient file error; Path B and fusion re-run for that seed. `summary.json` is written only after every seed finishes. |
| Edits to `docs/` failed with permission denied | files were owned by root; `sudo chown -R` to the user. |
| Real alert timestamps are the pipeline run time, all within 0.5 s | case SLA clocks use a stored `first_seen_at` instead. |
| Every lab domain is `*.lab.local` from one host | grouping keeps an extra label in internal zones and defaults to host + detection type. |
| Audit entries store `new_value`, not `new` | caught in testing; case history and shift stats fixed. |
| Chrome on Windows could not reach the WSL server | test the browser on the same OS as the server, or enable WSL localhost forwarding. |

---

## 14. Status at the end of Week 6

| Item | Status |
|---|---|
| Week 5 Tasks 0–3 (files, comparison, CIC capture 3, leave-one-tool-out) | ✅ |
| Isolation Forest Path B, `runs/v3_iforest` | ✅ fusion 1.0 / 7 false alarms, 39 min |
| Multi-seed: Path A (Tasks 4–5) and full system (5.4.3) | ✅ v3 8–9; fusion 7–9, recall 1.0 every seed |
| Conclusion and `models/` decision (Task 6) | ✅ `runs/v3_iforest` promoted to `models/` on 2026-11-19 (autoencoder archived; see `models/MODEL_CARD.md`) |
| Evidence in git (Task 7), stale docs (Task 9), unit tests (Task 10) | ✅ |
| Dashboard test (Task 8) | ✅ demo mode; real mode not run |
| Production hardening, SOC workflow, exporters | ✅ built and tested |
| Tier 1 triage workbench | ✅ built and tested |
| Mentor agreement on a non-deep-learning Path B | ✅ Approved by mentor 2026-11-17 |
| Browser click-through of the new pages | ❌ |
| Live Elasticsearch / Kibana export | ❌ |
| Real-mode dashboard run with `runs/v3_iforest` exporting to Kibana | ❌ |

---

## 15. Limits and next steps

**Limits**

- **No login.** Tier guardrails are a workflow control (the actor is self-declared). Add authentication and HTTPS before any shared deployment.
- **`models/` now holds `v3_iforest` (Isolation Forest Path B), promoted 2026-11-19.** The autoencoder models are archived in `models/archive/` (not in git).
- **Threshold drift:** set for 0.1% false alarms on validation data, it gives 0.35–0.59% on later benign traffic (leave-one-tool-out) and 0.6% on the frozen test set.
- **Lab data limits the checks:** the lab data is all type-A queries with short labels under `lab.local`, so several triage checks show "absent", and Tranco / VirusTotal add nothing there.
- **"Why it fired"** is a deviation from the client's baseline, not model attribution.
- **MTTD** is pipeline latency, not attacker dwell time.
- **JSON-file persistence** suits one analyst workstation; sustained multi-analyst use needs a database.

**Next steps**

1. ~~Ask the mentor to approve the Isolation Forest Path B, then promote `runs/v3_iforest` to `models/`.~~ Done: approved 2026-11-17, promoted 2026-11-19 (`scripts/promote_model.sh`, smoke test `scripts/smoke_models.py` passed 7/7). Still to check: `/api/model` shows `iforest` after a dashboard restart.
2. Browser click-through of `/triage`, `/alerts`, `/soc` and `/health`; record the results in TESTING_REPORT 5c.
3. Start the ELK stack, enable the Elasticsearch exporter, check that the document count does not change on a re-run, and build a Kibana view.
4. Run the dashboard in real mode on a fresh Kali capture and work the queue as Tier 1 and Tier 2.
5. Collect verdicts, export them as labels, and measure whether retraining with them lowers the false-positive rate per rule.
6. Optional: SHAP explanations for the Random Forest; authentication with roles; a database backend.

---

## 16. Update: work on 2026-11-18/19

*Added 2026-11-20. Everything below happened after this report was first written. All of it is committed and merged to `main`.*

| Date | Work | Commit | Details |
|---|---|---|---|
| 2026-11-18/19 | **Training console** (`dashboard/training-gui/`): streamed dataset upload with progress, auto-advance to step 2, safer CSV check; no upload size limit; GUI fixes and tests; a second training job is refused (409) | `9b9536d`, `9811f8a`, `670b35b` | [AUDIT_training_label_unlabel_2026-11-18.md](AUDIT_training_label_unlabel_2026-11-18.md) |
| 2026-11-19 | **ML improvement research** (Phases 0–3): flow map with file:line, findings F1–F8, gaps vs published practice, items 1–8 to choose from | `670b35b` | [ML_IMPROVEMENT_RESEARCH_2026-11-19.md](ML_IMPROVEMENT_RESEARCH_2026-11-19.md) |
| 2026-11-19 | **ML items 1–5**: run record (git commit, pip freeze, data checksums, split hash, seed); forbidden-feature checks; FPR intervals; twin-free metrics; success criteria written before training + pass/fail gate (`config/success_criteria.yaml`, `scripts/compare_models.py`, `scripts/run_candidate_seeds.sh`); 26 tests | `fcc8db0` | [ML_IMPROVEMENT_IMPLEMENTATION_2026-11-19.md](ML_IMPROVEMENT_IMPLEMENTATION_2026-11-19.md) §1–2 |
| 2026-11-19 | **3-seed results on `labelled_v3`** (seeds 42/43/44): fusion 10.3 ± 7.4 false alarms (2–16), recall 100% every seed; Path B 22.9% ± 1.3% FPR. **Gate: FAIL** (FPR budget 0.1%; the record-type rule beats the model) | `4f30f09` | same doc §4b; [PATH_B_REPORT.md](PATH_B_REPORT.md) §3.2 |
| 2026-11-19 | **v3_iforest promoted to `models/`** (mentor approval 2026-11-17): autoencoder archived to `models/archive/`, `MODEL_CARD.md`, `PROMOTED.json` with SHA-256 of every file, smoke test 7/7 | `3ed0cce` → `main` `b204085` | [PATH_B_REPORT.md](PATH_B_REPORT.md) §1 |
| 2026-11-19 | **T9 error ranges** for every detector: exact Clopper–Pearson / Wilson, 1,000-sample domain-cluster bootstrap, seed spread. Live model: fusion 8 false alarms / 1,168 (0.68%, exact 0.30–1.35%, bootstrap 0.00–2.32%), recall 100%; record-type rule 0 false alarms | `e553b8f` | [PATH_B_REPORT.md](PATH_B_REPORT.md) §2–3 |

**What changed in the Week 6 conclusions:**

- §15 "Next steps" item 1 is done: the Isolation Forest Path B is live.
- The 5-seed stability result in §6 (fusion 8.2 ± 0.84) holds for `v3`. On `labelled_v3` the spread is much wider (3 seeds: 10.3 ± 7.4; 20 seeds: 9.85 ± 5.53, [PATH_B_REPORT.md](PATH_B_REPORT.md) §5). The cause is two benign domains that appear only in the test set.
- The simple record-type rule matches or beats every model on the current test set, so harder data is the next priority.

The follow-up work (20-seed T4 run, schema check at start-up, Isolation Forest as the default) and the Week 7 plan are in [../Week7/next task.md](../Week7/next%20task.md).
