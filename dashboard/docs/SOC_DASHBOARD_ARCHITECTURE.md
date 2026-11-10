# SOC Dashboard Architecture

**Audience:** engineers extending the dashboard or integrating external systems.

## 1. System architecture

```
          DNS DETECTION PIPELINE (OFF-LIMITS: src/dns_detect/)
                        │
                        ▼
         data/processed/week4_unified_alerts.json
         data/processed/monitoring_report.json
         models/training_metadata.json
                        │
                        ▼
                 dashboard/server.py
        ┌───────────────┴────────────────┐
        ▼                                ▼
  In-memory STATE                  Persistent STORE
  (alerts, history, pipeline)      (dashboard/data/*.json)
        │                                │
        └────────────┬───────────────────┘
                     ▼
              /api/state  +  /api/*  +  /static/*
                     │
    ┌────────────────┼─────────────────────────┐
    ▼                ▼                         ▼
  Pages        Shared static            Management APIs
  /, /soc,     /static/css/soc.css      POST /api/alerts/*
  /usecases,   /static/js/chrome.js     POST /api/usecases/*
  /alerts,                              POST /api/incidents/*
  /events,
  /devices,
  /health,
  /incidents
```

## 2. Shared state

The in-memory `STATE` holds:
- `alerts_data` — the parsed `week4_unified_alerts.json` (or demo alerts).
- `first_seen` — fingerprint → epoch, drives the `is_new` flag.
- `history` — up to 120 run points.
- `pipeline` — status/step/error/last_run_at/last_duration/runs.

The persistent `STORE` holds:
- `alert_management` — one record per alert fingerprint (`fp`).
- `usecase_preferences` — one record per rule name.
- `incident_records` — created incidents + their actions.
- `audit_log` — append-only list.
- `analysts` — seeded roster.
- `response_integrations` — SOAR integration configuration flags.

Both are protected by a `threading.Lock`. Lock order when both are
needed: `STATE.lock` → `STORE.lock`, never the reverse.

## 3. Data flow

**Read path (every page):**

1. Page loads inline HTML via `/` or `/soc` etc.
2. Page polls `GET /api/state` every 3 s (every 5 s for Events).
3. `build_state()` merges in-memory alert data with persisted
   management records by `fp`.
4. Page re-renders only when `state.version` changes.
5. `state.version` increments on pipeline-state changes **and** on
   management writes so pages reflect analyst actions.

**Write path (management action):**

1. Page POSTs JSON body to `/api/alerts/{fp}/<action>`.
2. `Handler._alert_action` validates body, looks up the live alert by
   `fp`, calls `STORE.apply_alert_action()`.
3. `apply_alert_action` validates the state transition against
   `ALLOWED_TRANSITIONS` (409 Conflict on invalid), mutates the
   record, appends an audit entry, and writes both files atomically.
4. `STATE.bump()` triggers a version change so the next `/api/state`
   poll re-renders the row.

## 4. Management APIs

See [API_REFERENCE.md](./API_REFERENCE.md) for the full contract,
request bodies, and response shapes.

**State-transition rules** (enforced server-side):

| From | Allowed next |
|------|-------------|
| Open | Acknowledged, Investigating, Escalated, Closed |
| Acknowledged | Investigating, Escalated, Resolved, Closed |
| Investigating | Escalated, Resolved, Closed |
| Escalated | Investigating, Resolved, Closed |
| Resolved | Closed, Open (reopen) |
| Closed | Open (reopen) |

## 5. Pipeline state vs SOC management state

| Pipeline state (read-only) | SOC management state (read/write) |
|---|---|
| alert rule, severity, timestamp, client_ip, domain | status, assigned_to, escalated |
| MITRE tactics/techniques, ML/z-score details | acknowledged_at, resolved_at, notes |
| alerts_by_rule, alerts_by_severity | updated_at, last_seen_alert_id |
| rules_used, statistical/ml/ti config | incident records, audit log |
| drift report, score_health | use-case preferences |

The dashboard never writes to `data/processed/` or `models/`.
Management writes land only in `dashboard/data/`.

## 6. Demo vs real mode

Both modes use identical management APIs and identical frontend code.
The only difference is the shape of `alerts_data`:

- `--demo` — `demo_loop` generates alerts with `details = {}` and an
  in-memory alerts file; ML/z-score fields are legitimately empty.
- `--watch <dir>` — `watch_loop` triggers the subprocess pipeline when
  `*.log` files under the watch dir change, which produces a real
  `data/processed/week4_unified_alerts.json`.

Management records persist in both modes because they are keyed by
`fp` (the fingerprint hash), which is deterministic across runs.

## 7. Future SOAR integration

`dashboard/data/response_integrations.json` is seeded with four keys
(`fortigate`, `fortiedr`, `fortisoar`, `servicenow`), each with
`{"configured": false, "endpoint": null}`. A future integration would:

1. Set `configured: true` + `endpoint: "https://…"`.
2. Add an outbound HTTP client in `Store.record_incident_action`
   guarded by an environment-variable API key.
3. Flip the returned status from `SIMULATED` to `PENDING`, then on
   confirmed success `EXECUTED` (or `FAILED` on error).

Credentials must stay in environment variables; never commit them.
