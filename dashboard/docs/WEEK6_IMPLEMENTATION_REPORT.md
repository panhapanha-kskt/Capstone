# Week 6 — SOC Monitoring Suite: Implementation Report

**Audience:** project reviewers evaluating the Week 6 dashboard extension.

**Date:** 2026-11-10

## 1. Existing architecture (Week 5 baseline)

The Week 5 dashboard was a single read-only visualisation layer over the
existing DNS detection pipeline:

- `dashboard/server.py` — stdlib `ThreadingHTTPServer`, one `/api/state`
  endpoint plus HTML routes for `/`, `/soc`, `/usecases`, `/alerts`.
- `dashboard/index.html` — Classic Dashboard (light theme).
- `dashboard/soc.html` — Monitoring Overview (dark, SVG charts).
- `dashboard/usecases.html` — Monitoring Use Cases + Cyber Kill Chain.
- `dashboard/alerts.html` — React 18 + htm alert grid.

Shortcomings addressed in Week 6:
1. Alert status, assignment, and notes were derived client-side and
   reset on refresh. The pipeline's `alert_id` is a fresh UUID per run,
   so even the alert identifier was unstable.
2. The full pipeline `details` dict (ML scores, z-scores, counts,
   reasons, `source_file`) was dropped by `build_state`.
3. There was no view of pipeline/collection health, device sources, or
   incident response.

## 2. New functionality

### 2.1 Persistent alert management
- Stable alert identifier `fp` (SHA-1 of the existing `fingerprint()`
  function in [server.py:120](../server.py#L120)).
- Status workflow: Open → Acknowledged → Investigating →
  {Escalated, Resolved} → Closed; Reopen from Resolved/Closed.
- Analyst assignment from a seeded local analyst list.
- Timestamped investigation notes (per-note author + timestamp).
- Escalation flag with audit trail.
- Bulk Execute menu on the Alerts page (acknowledge / assign / set status /
  escalate / close), with eligibility preview and per-item result report.

### 2.2 Full audit trail
Every status/assign/acknowledge/escalate/note/bulk/incident/usecase
action appends an entry to `dashboard/data/audit_log.json`. The
response always carries `"authenticated": false` since no real authn
exists.

### 2.3 Event Explorer (`/events`)
Server-side filterable table of all detection events with the real
pipeline `details` dict exposed: ML scores, z-scores, reasons, source
file, query type. Honest N/A rendering for fields the pipeline didn't
emit (common in demo mode, where `details == {}`).

### 2.4 Sources & Collection (`/devices`, honestly named)
Not a device inventory. Shows client-IP summaries (first/last seen,
event count, domain count, severity breakdown, Active/Quiet/Unknown
status derived from poll interval × 5 / × 20) and collection sources
(raw log files + pipeline `source_file` counts, size, mtime). MDTI
enrichment surfaces where available.

### 2.5 Pipeline Health (`/health`)
Transparent health bands (Healthy / Warning / Critical / Unknown) with
explicit reasons. Freshness panel separates dashboard-tick, pipeline
run time, and alerts-file mtime. Drift + score-health panel from
`monitoring_report.json`. 30-run sparkline from in-memory history.

### 2.6 Incidents (`/incidents`, SOAR-ready)
Incident queue with simulated / not-configured response actions:
watchlist IP, mark domain, create investigation report, export
evidence, firewall block request (requires fortigate config),
endpoint isolation request (requires fortiedr config). Status is
always `SIMULATED` or `NOT_CONFIGURED` — this phase never returns
`EXECUTED`.

### 2.7 SOC Overview additions
New Operational Metrics row with eight tiles grounded in persisted
management state + `/api/health`. Existing seven KPI tiles and three
historical charts are preserved unchanged.

### 2.8 Use Cases improvements
- `localStorage` prefs replaced with `GET /api/usecases` + debounced
  `POST /api/usecases/preferences`. Legacy local state is used as a
  last-resort fallback.
- Column renamed Monitoring Status → **Dashboard Visibility** with a
  tooltip clarifying it does not disable detection.
- Row-click opens a side panel with rule details, MITRE mappings,
  event/alert counts, and a server-persisted analyst note.

## 3. Backend changes

- `server.py` extended, not rewritten. Existing `State`, `build_state`,
  `fingerprint`, `_finite`, `load_alerts`, `watch_loop`, `demo_loop`,
  `run_pipeline` are untouched in behaviour.
- New `Store` class with:
  - Atomic writes (`.tmp` → `os.replace`) and `.bak` rotation.
  - JSON decode-error recovery (`.corrupt-<ts>` rename, fall back to
    `.bak`, else start empty).
  - Hand-written validators (no deps).
  - Thread-safe via `Store.lock`.
- `build_state` now adds: `fp`, `details`, `management`, `query_time`,
  `investigation_priority` per feed item; `sources` and `health`
  top-level objects.

## 4. Frontend changes

- `alerts.html` — same component tree (`App` / `SeverityPie` /
  `TypeBars` / `AlertsGrid` / `Drawer`), extended with row-action menu,
  bulk Execute menu, Investigation / Details / Audit drawer tabs,
  management-vs-derived status chips. `fp` replaces the synthetic
  ordinal ID as the React key.
- `soc.html` — new Operational Metrics panel + sidebar links.
- `usecases.html` — server-backed preferences, honest column labels,
  detail side-panel, sidebar links.
- `index.html` — four new nav buttons (Alerts / Events / Health).
- `events.html`, `devices.html`, `health.html`, `incidents.html` —
  new pages, each ≲ 300 lines, using the shared
  `/static/css/soc.css` + `/static/js/chrome.js`.
- `static/js/chrome.js` — one implementation of the sidebar/topbar +
  `SOC.pollState()` so new pages do not duplicate chrome HTML or the
  3-second poll pattern.

## 5. New routes / APIs

See [API_REFERENCE.md](./API_REFERENCE.md) for the full catalog.
Short list:

```
GET  /api/state                           (existing — strict superset)
GET  /api/alerts            /api/alerts/{fp}
POST /api/alerts/{fp}/{acknowledge,assign,status,escalate,notes}
POST /api/alerts/bulk
GET  /api/events            /api/events/{fp}
GET  /api/devices           /api/health
GET  /api/usecases          POST /api/usecases/preferences
GET  /api/incidents         POST /api/incidents
GET  /api/incidents/{id}    POST /api/incidents/{id}/action
GET  /api/audit             GET  /api/analysts
GET  /static/*
POST /api/run                             (existing — unchanged)
```

Page routes added: `/events`, `/devices`, `/health`, `/incidents`.

## 6. Persistent storage design

Directory: `dashboard/data/`. Files (each a
`{"schema_version": 1, "records": ...}` wrapper):

| File | Keyed by | Contents |
|------|---------|---------|
| `alert_management.json` | `fp` | status, assignee, timestamps, notes |
| `usecase_preferences.json` | `rule_name` | visibility, exclusion, note |
| `incident_records.json` | `inc-<10hex>` | title, alerts, actions, status |
| `audit_log.json` | append-only list | every management operation |
| `analysts.json` | `analyst_id` | seeded local roster |
| `response_integrations.json` | integration key | configured/endpoint flags |

Write path is always `*.tmp` → `os.replace`; previous version is kept
as `*.bak`. On decode failure the broken file is renamed
`*.corrupt-<epoch>` and the server falls back to `.bak` or an empty
record set.

## 7. Testing results

Static syntax verification (`python -c "ast.parse(...)"`) passes on the
extended `dashboard/server.py`. See [TESTING_REPORT.md](./TESTING_REPORT.md)
for the manual and runtime test matrix the user is expected to run.

## 8. Known limitations

- **No authentication.** `actor` on every POST is taken from the client
  request body and recorded as-is. The `authenticated: false` flag on
  audit/analyst responses is deliberate and visible.
- **Demo mode details are empty.** The demo loop produces alerts with
  `details = {}`, so Event Explorer ML/anomaly columns show N/A.
- **No real SOAR execution.** All response actions record as
  `SIMULATED` (or `NOT_CONFIGURED`) and never make outbound calls.
- **No device agents.** Sources & Collection does not and cannot claim
  hostnames, OS, or device status from DNS logs alone.
- **Localhost-only by default.** `--host 127.0.0.1` is the default for a
  reason — no TLS, no auth, no rate limit sufficient for public exposure.
- **Monitoring toggles do not disable detection rules.** Explicitly
  labelled "Dashboard Visibility" in the UI.
