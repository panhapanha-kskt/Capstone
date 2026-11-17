# Week 6 Report: SOC Dashboard Production Hardening and ML ↔ SOC Integration

**DNS Traffic Anomaly Detection · session 2026-11-17**

This report covers the second half of Week 6. The dashboard was audited as a production SOC tool
and SOC-vendor practice was researched. The dashboard was then hardened, its rendering bugs fixed,
analyst workflow features added, and the ML detector connected to the SOC tools the project already
runs (Elasticsearch/Kibana) plus any syslog SIEM or SOAR tool.

Related documents:

- [SOC_ML_INTEGRATION.md](SOC_ML_INTEGRATION.md): how to switch on each exporter and the feedback loop.
- [../../dashboard/docs/API_REFERENCE.md](../../dashboard/docs/API_REFERENCE.md): every endpoint, including the new ones.
- [../../dashboard/docs/TESTING_REPORT.md](../../dashboard/docs/TESTING_REPORT.md): test cases and results (section 5b is new).
- [WEEK6_PROGRESS_REPORT.md](WEEK6_PROGRESS_REPORT.md): the ML side of Week 6 (v3 evaluation, Isolation Forest Path B, multi-seed).

---

## Contents

1. [Summary](#1-summary)
2. [Where the session started](#2-where-the-session-started)
3. [Method: research, fit analysis, plan](#3-method-research-fit-analysis-plan)
4. [Phase 1: security hardening and bug fixes](#4-phase-1-security-hardening-and-bug-fixes)
5. [Phase 2: smooth rendering](#5-phase-2-smooth-rendering)
6. [Phase 3: SOC analyst workflow](#6-phase-3-soc-analyst-workflow)
7. [Phase 4: connecting the ML model to SOC tools](#7-phase-4-connecting-the-ml-model-to-soc-tools)
8. [Testing](#8-testing)
9. [Files changed](#9-files-changed)
10. [How to verify](#10-how-to-verify)
11. [Known limits and next steps](#11-known-limits-and-next-steps)

---

## 1. Summary

- **Security:**
  - Before this session, any web page an analyst had open could change alert state on the dashboard (no CSRF protection).
  - Every write now needs a JSON body plus a custom header, and requests from other sites are refused.
  - A strict, nonce-based Content-Security-Policy and the standard security headers are added to every response.
  - Third-party scripts are now served locally.
- **Bugs fixed (10):**
  - Closed alerts could be acknowledged.
  - Severity sorting was alphabetical.
  - The alert drawer lost its tab after every action.
  - The "Assigned To: Me" control did nothing.
  - The Incidents page polled twice.
  - A KPI tile was mislabelled.
  - The bulk audit write could race with other writes.
  - The severity chart counted closed alerts.
  - An open dropdown on the Events page closed on every refresh.
  - The integration config leaked through `/api/incidents` once secrets were added.
- **Rendering:**
  - Pages download state only when it changed (ETag / 304).
  - Polling pauses in hidden tabs.
  - Table rows are patched in place, so scroll position, selection and open menus survive a refresh.
- **SOC workflow:**
  - Analyst verdicts (true / false / benign positive, duplicate).
  - MTTD / MTTA / MTTR and ack-SLA breaches.
  - MITRE ATT&CK heatmap.
  - Related alerts.
  - False-positive suppression with an expiry date.
  - Playbook hints.
  - Shift handover report.
- **ML ↔ SOC:**
  - Alerts, with their ML scores, ATT&CK tags and analyst status, can now be exported to:
    - Elasticsearch/Kibana (ECS format, no duplicates on re-run).
    - Syslog CEF (FortiSIEM, Wazuh, Splunk, QRadar).
    - A signed webhook (SOAR).
  - The deployed model, its thresholds and drift are visible in the UI.
  - Analyst verdicts can be exported as training labels.
- **Tests:** 24 new automated tests, all passing. Every page's JavaScript passes a syntax check.

---

## 2. Where the session started

| Item | State |
|---|---|
| Dashboard | 8 pages, stdlib Python server, JSON persistence; TESTING_REPORT sections 2–4 passed in demo mode |
| Authentication | none (by design: localhost tool) |
| CSRF / Origin checks | **none**: POST accepted from any origin and any Content-Type |
| Security headers | **none** |
| Third-party scripts | React 18, ReactDOM, htm loaded from cdnjs |
| ML scores in the UI | only `ml_combined_score` on the Events page; demo alerts had no ML fields |
| Model visibility | 4 fields from `training_metadata.json` |
| ML alerts in Elasticsearch/Kibana | **never**: Filebeat shipped only raw DNS logs (`technitium-dns-*`) |
| Analyst feedback to the model | none |

---

## 3. Method: research, fit analysis, plan

The work followed four steps, as requested.

1. **Research.** One agent surveyed SOC-tool practice from defensive vendors and standards:
   - Fortinet FortiSIEM / FortiSOAR, Splunk (ES, MLTK, SOAR), IBM QRadar, Microsoft Sentinel, Elastic Security, Wazuh.
   - OWASP cheat sheets and NIST SP 800-61r3.
2. **Project audit.** A second agent traced how predictions become alerts today. It mapped `fusion.bridge` → `detection.engine` → `monitoring` → dashboard, and listed what was not wired up.
3. **Fit analysis.** A planning agent scored every research item ADOPT / ADAPT / REJECT for this project: a localhost, stdlib-only capstone that runs the ML pipeline on a CPU-only VM.
4. **Decisions** (taken by the student):
   - CSRF/Origin checks rather than a full login.
   - Build all three exporters (Elasticsearch, syslog CEF, webhook), each off by default.

**Fit analysis (main items)**

| Practice | Verdict | Reason |
|---|---|---|
| Severity-first triage queue, assigned-to-me | Adopt | data already present |
| ATT&CK coverage per tactic | Adopt | alerts already carry tactics/techniques |
| Alert correlation (IP / domain / time) | Adopt | cheap in-memory grouping; fits the DNS-tunnel pattern |
| MTTA / MTTR | Adopt | ack/resolve timestamps already stored |
| MTTD | Adapt | measured as pipeline latency (no ground-truth intrusion time) |
| Anti-CSRF | Adapt | JSON-only + custom header + Origin/Host checks; no token store needed on localhost |
| Login, session cookies, roles | Reject (for now) | server binds 127.0.0.1; cost without a threat. Revisit before any non-loopback deployment |
| CSP | Adapt | nonce-based, enforced; report-only flag for debugging |
| Rate limiting | Adapt | only on `/api/run`, the one expensive action |
| Analyst dispositions as training labels | Adopt | the key ML ↔ SOC feedback loop; export only, a human decides on retraining |
| Model inside the SIEM (Elastic `eland`), scoring API for SOAR | Reject | out of scope; the model stays in the pipeline |
| Suppression with expiry | Adapt | dashboard-only; never changes detection |
| Server push (SSE) | Adapt | version-gated polling with 304 instead; same effect, no long-lived threads |

---

## 4. Phase 1: security hardening and bug fixes

### 4.1 Request checks (`check_request` in `dashboard/server.py`)

| Check | Applies to | Failure |
|---|---|---|
| `Host` is 127.0.0.1 / localhost / ::1 / `--allow-host` names (DNS-rebinding defence) | every request | 403 |
| `Content-Type: application/json` (closes the cross-site `text/plain` form hole) | POST | 415 |
| `X-SOC-Request: 1` (a cross-site page cannot send it without a CORS preflight, which is never approved) | POST | 403 |
| `Origin` = `http://<Host>`; `Sec-Fetch-Site` = same-origin / none | POST, when sent | 403 |
| `/api/run` at most once per 10 s, audited as `PIPELINE_RUN_REQUESTED` | `/api/run` | 429 + `Retry-After` |
| `actor` must exist in `analysts.json`, else stored as `unknown-analyst` | all writes | — |

All front-end POST helpers send the header: `SOC.apiPOST` in `chrome.js`, plus the helpers in alerts, usecases and index.

### 4.2 Response headers

- **On every response:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy: same-origin`.
- **On HTML pages:**
  - The CSP is `default-src 'self'; script-src 'self' 'nonce-…'; object-src 'none'; frame-ancestors 'none'; …`.
  - A fresh nonce is generated for every response and injected into every `<script>` tag.
  - React 18.3.1, ReactDOM 18.3.1 and htm 3.1.1 were copied into `dashboard/static/vendor/`, so no third-party script origin is allowed. The demo also works offline.

### 4.3 Other hardening

- **Non-loopback warning:** binding to a non-loopback address prints a warning, and each client name must be allowed with `--allow-host`.
- **Secrets:** they are shown as `***` in `/api/incidents` and `/api/integrations`.
- **Export URLs:** exporter targets can be set only by editing the config file, never through the API, so a browser cannot redirect alerts. Only `http`/`https` URLs are accepted.
- **CSV export:** cells starting with `= + - @` are prefixed with `'` to block spreadsheet formula injection.

### 4.4 Bugs fixed

| # | Bug | Fix |
|---|---|---|
| 1 | Acknowledge on a Closed/Resolved alert silently stamped `acknowledged_at` (the guard could never trigger) | 409 "reopen it first" |
| 2 | Severity column sorted alphabetically (Medium, Low, High, Critical) | sort by severity rank, then priority, then time |
| 3 | Alert drawer jumped back to Overview after every action | reset only when a different alert opens |
| 4 | "Assigned To: Me \| All" links on the widgets did nothing | they now filter by the selected analyst |
| 5 | "Open Alerts By Severity" counted all alerts | counts open, non-suppressed alerts |
| 6 | Incidents page polled twice (two timers) | one version-aware poller |
| 7 | SOC summary tile "Escalated Alerts" showed new alerts | relabelled "New Alerts (last 45 s)" |
| 8 | Bulk-action audit written without the store lock (race) | written under the lock |
| 9 | Events source dropdown rebuilt every poll (closed while open) | rebuilt only when the list changes |
| 10 | Unused duplicate state hook in alerts.html | removed |

---

## 5. Phase 2: smooth rendering

- **ETag / 304:**
  - `/api/state` returns an `ETag` built from the state version plus a 30 s time bucket, so time-based fields still refresh.
  - Pages send it back and skip the download and re-render when nothing changed.
- **Hidden tabs:** polling pauses while a tab is hidden and catches up when it becomes visible.
- **Row patching:** `SOC.patchList` replaces only the table rows whose content changed. It is used on Events, Sources & Collection and Incidents, so scroll position, hover, focus and text selection survive a refresh. The React grid on Alerts is keyed by fingerprint, so the open drawer is kept.
- **Polling rates:** the classic page now polls every 3 s instead of 2 s, and resizing the SOC overview redraws once, debounced.

---

## 6. Phase 3: SOC analyst workflow

| Feature | Where | Endpoint |
|---|---|---|
| Verdict (true positive, false positive, benign positive, duplicate) + reason; also as a bulk action; optional `--require-verdict` before Resolve/Close | Alerts → drawer → Investigation; grid "Verdict" column | `POST /api/alerts/{fp}/verdict` |
| Queue filters: Assigned to me, Open only, Show suppressed | Alerts grid toolbar | `GET /api/alerts?assigned_to=&sort=&include_suppressed=` |
| MTTD, MTTA, MTTR (median, p90), ack-SLA breaches (High 15 min, Medium 60 min, Low 4 h), false-positive rate, workload per analyst | SOC overview → SOC PERFORMANCE row | `GET /api/metrics?hours=24` |
| MITRE ATT&CK heatmap (tactic × technique) | SOC overview | same |
| Related alerts (same client IP or registered domain, ±5 min to ±24 h) | Alerts → drawer → Related | `GET /api/alerts/{fp}/related` |
| Known-false-positive suppression (domain / client IP / rule, reason required, expiry) | drawer → Investigation | `GET/POST /api/suppressions`, `POST /api/suppressions/{id}/delete` |
| Playbook hints by rule type and ML confidence (guidance only) | drawer → Playbook | — |
| Shift handover (escalated, unassigned High, open incidents, activity, KPIs) | download | `GET /api/reports/handover?format=md` |

Suppression only hides alerts in the dashboard. The detection rules still fire, and the exporters
still send the alerts.

---

## 7. Phase 4: connecting the ML model to SOC tools

### 7.1 Audit finding

The pipeline's ML output (`ml_score_A`, `ml_score_B`, `ml_combined_score`, `ml_confidence`,
`ml_threat_score`) reached the dashboard inside each alert's `details`, but stopped there:

- **ELK:** the ELK stack in `infra/technitium-elk` indexed only raw Technitium logs, so no ML alert ever reached Kibana.
- **Model:** nothing showed which model or thresholds produced a score.
- **Feedback:** analyst decisions never went back to the model.

### 7.2 What was built

| Component | Purpose |
|---|---|
| `GET /api/model` | Deployed model summary from `models/`: model version (hash of thresholds + training metadata), Path A threshold and FPR budget, Path B type (from `model_type`, else the file present), fusion threshold and coefficients, training samples, drift. `model_version` also in `/api/state`. |
| Alerts drawer → ML tab | Path A / Path B / fusion / threat scores as bars against the deployed thresholds, confidence tier, model version, drift |
| Pipeline Health | Deployed-model panel, max-PSI trend per run (0.25 line), exporter status table |
| Demo mode | Synthetic ML scores marked `details.demo = true` and labelled on every page, so the ML views can be checked without models |
| `dashboard/exporters.py` | Background exporter to three targets. Runs after each pipeline run and about 2 s after analyst actions. Failures are reported and never break the pipeline. |
| Elasticsearch | `_bulk` into `dns-ml-alerts-YYYY.MM.dd` with ECS field names; `_id` = alert fingerprint and index date = DNS query time, so re-runs and status changes overwrite instead of duplicating. Index template shipped in `infra/technitium-elk/kibana/`. |
| Syslog CEF | RFC 3164 + CEF over UDP/TCP for FortiSIEM, Wazuh, Splunk, QRadar; correct CEF escaping |
| Webhook | JSON batches with an `X-Signature-SHA256` HMAC |
| Dedupe | CEF and webhook receive an alert only when its exported content changed; state in `dashboard/data/export_state.json` |
| Feedback loop | `GET /api/feedback/export?format=csv\|ndjson\|json` and `scripts/export_feedback_labels.py` → `data/feedback/labels_*.csv`. Label 1 = true positive, 0 = false or benign positive, empty = duplicate. Each row carries the ML scores and model version. |

All three exporters are **off by default**. They are switched on in
`dashboard/data/response_integrations.json` (re-read on every export, so no restart is needed).
Step-by-step setup is in [SOC_ML_INTEGRATION.md](SOC_ML_INTEGRATION.md).

Retraining stays a **human decision**. Analyst labels can be wrong, and feeding them straight back
would let bad labels weaken the detector, so the export is reviewed before it is merged into the
training data.

---

## 8. Testing

| Test | Result |
|---|---|
| `python3 -m pytest tests/test_dashboard_soc.py -q` (new; real server on a random port, temporary data folder) | **24 passed** (2026-11-17, WSL) |
| JavaScript syntax check of every page and `chrome.js` (Node `vm.Script`) | all pass |
| Manual curl checks on a demo server | 415 / 403 / 403 / 200 / 429 as expected; CSP and X-Frame-Options present; 304 on matching ETag |
| Exporter CLI on the real `week4_unified_alerts.json` (`--print cef`) | valid CEF lines; placeholder domain `N/A` no longer exported as a query name |
| Existing ML test suite | not run in WSL (pandas missing); unaffected by this change, run on Kali as usual |
| Browser click-through of the new tabs and panels | **to do**: the browser extension was not connected this session |
| Elasticsearch export against the docker-compose stack | **to do** (section 10, step 6) |

The 24 automated tests cover:

- Every security check and header.
- The audit and rate limit on `/api/run`.
- Rejection of unknown actors and redaction of secrets.
- The 409 transitions, including acknowledging a Closed alert.
- Verdicts, metrics, related alerts, suppressions and the handover report.
- `/api/state` staying a superset, plus the 304 response.
- Model-type detection and feedback labels, including CSV formula neutralising.
- The ECS and CEF formats.
- Elasticsearch idempotency (including across a restart) and per-item bulk errors.
- Webhook HMAC, syslog over UDP, and unreachable or `file://` targets not crashing.

---

## 9. Files changed

| File | Change |
|---|---|
| `dashboard/server.py` | request guard, security headers, CSP nonce, run audit/limit, actor check, ETag; verdicts, metrics, related, suppressions, handover; `/api/model`, feedback export, `/api/integrations`; exporter wiring; drift history; synthetic demo ML; bug fixes; `--allow-host`, `--csp-report-only`, `--require-verdict`; `SOC_DASHBOARD_DATA_DIR` env var for tests |
| `dashboard/exporters.py` (new) | ECS / CEF builders, Elasticsearch / syslog / webhook senders, background manager, CLI |
| `dashboard/static/js/chrome.js` | POST header, conditional polling, hidden-tab pause, `patchList` |
| `dashboard/static/vendor/` (new) | React 18.3.1, ReactDOM 18.3.1, htm 3.1.1 |
| `dashboard/alerts.html` | vendored scripts; ML, Related and Playbook tabs; verdict and suppress; queue filters; severity sort, drawer and widget fixes |
| `dashboard/soc.html` | SOC Performance row, ATT&CK heatmap, label fix, ETag polling |
| `dashboard/health.html` | model panel, PSI trend, exporter status |
| `dashboard/events.html`, `devices.html`, `incidents.html`, `usecases.html`, `index.html` | row patching, ETag polling, POST header, double-poll fix, demo wording |
| `dashboard/docs/API_REFERENCE.md`, `TESTING_REPORT.md` | security rules, new endpoints, new curl header, test results |
| `infra/technitium-elk/kibana/dns-ml-alerts-template.json` (new) | Elasticsearch index template |
| `scripts/export_feedback_labels.py` (new) | saves verdicts as a labelled CSV |
| `tests/test_dashboard_soc.py` (new) | 24 tests |
| `docs/Week6/SOC_ML_INTEGRATION.md` (new) | integration guide |

**Breaking change for scripts:** every POST now needs `-H 'X-SOC-Request: 1'`. All curl commands in
the dashboard docs have been updated.

---

## 10. How to verify

Restart the dashboard first, because an already-running server has the old code:
`python3 dashboard/server.py --demo --port 9000`.

1. **Unit tests:** `python3 -m pytest tests/test_dashboard_soc.py -q` → 24 passed.
2. **Security:**
   - `curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:9000/api/run -H 'Content-Type: text/plain' -d x` → 415.
   - The same POST with the JSON content type, the `X-SOC-Request: 1` header and `-H 'Origin: http://evil.test'` → 403.
3. **Headers:** `curl -s -D - -o /dev/null http://127.0.0.1:9000/alerts | grep -i 'content-security\|x-frame'` prints both.
4. **Browser:**
   - DevTools Console shows no CSP errors on any page.
   - On `/alerts`, the drawer shows 7 tabs, and saving a verdict keeps you on the Investigation tab.
   - `/soc` shows the SOC Performance row and the ATT&CK heatmap.
   - `/health` shows the model panel and the exporter table.
   - The Events table keeps its scroll position across refreshes.
5. **Workflow API:** acknowledge an alert, set a verdict, then call `/api/metrics`, `/api/alerts/<fp>/related`, `/api/reports/handover?format=md` and `/api/feedback/export?format=csv`.
6. **Elasticsearch:**
   - Run `docker compose up -d elasticsearch kibana` in `infra/technitium-elk`.
   - Set `"elasticsearch": {"configured": true, ...}` in `dashboard/data/response_integrations.json`.
   - Check `curl -s 'http://127.0.0.1:9200/dns-ml-alerts-*/_count'` twice, 30 s apart. The count must not double.
7. **Syslog (optional):** run `nc -ul 5514` and set `syslog_cef` to port 5514. CEF lines should arrive.

The full commands are in [SOC_ML_INTEGRATION.md](SOC_ML_INTEGRATION.md) and in the dashboard
TESTING_REPORT, section 5b.

---

## 11. Known limits and next steps

**Limits**

- **No login.** The dashboard is meant for `127.0.0.1`. Before any shared deployment, add authentication with roles (analyst / senior / manager / viewer) and HTTPS.
- **Path B in `models/`.** It is still the autoencoder, and `/api/model` reports it as such. It changes to IsolationForest once `runs/v3_iforest` is promoted (waiting on mentor approval).
- **MTTD.** It is pipeline latency, not attacker dwell time.
- **Registered domain.** It is approximated as the last two labels, with no public-suffix list.
- **Storage.** Persistence is still JSON files. That is fine for a single analyst workstation, but a database is needed for sustained multi-analyst use.
- **Elasticsearch security.** The compose stack runs Elasticsearch with security disabled, so keep port 9200 on localhost.

**Next steps**

1. Browser click-through of the new tabs and panels; record the results in TESTING_REPORT 5b.
2. Elasticsearch export test against the docker-compose stack; build the Kibana data view and a small dashboard (alerts by technique, HIGH-confidence open alerts).
3. Real-mode run on Kali with `runs/v3_iforest`, exporting real ML alerts to Kibana.
4. After the mentor's decision, promote `runs/v3_iforest` to `models/`. Check that `/api/model` shows IsolationForest and a new `model_version`.
5. Collect verdicts over a test period, export them with `scripts/export_feedback_labels.py`, and measure whether retraining with them lowers the false-positive rate.
