# Dashboard API Reference

**Audience:** developers integrating with the dashboard or writing additional pages.

All responses: `Content-Type: application/json`, `Cache-Control: no-store`.
All POST bodies: JSON object, `Content-Length` required and ≤ 64 KiB.
All string `actor` values are recorded as reported; there is **no
authentication**.

## Existing endpoints (preserved)

### `GET /api/state`
Returns the shared state polled by every page. Week 6 adds fields but
removes none; existing Week 5 consumers remain compatible.

**Shape (abridged):**
```json
{
  "version": 123,
  "now": 1731268900.1,
  "mode": "live" | "demo",
  "pipeline": {...},
  "totals": {...},
  "top_clients": [["1.2.3.4", 42], ...],
  "feed": [
    {
      "id":         "<pipeline UUID, unstable across runs>",
      "fp":         "a1b2c3d4e5f6a7b8",
      "time":       "2026-11-10T13:00:00",
      "rule":       "DNS Tunneling Detection",
      "source":     "Project Requirement",
      "severity":   "High",
      "client":     "192.168.0.42",
      "domain":     "x.evil.example",
      "description":"...",
      "tactics":    ["Exfiltration"],
      "techniques": ["T1572"],
      "details":    { ... pipeline details, verbatim ... },
      "is_new":     true,
      "management": {
        "status": "Investigating",
        "assigned_to": "analyst-1",
        "escalated": false,
        "acknowledged_at": "2026-11-10T13:02:00Z",
        "notes": [ {"id":"…","text":"…","author":"…","ts":"…"} ],
        "updated_at": "…",
        ...
      } /* or null */
    }
  ],
  "history": [ {"t":…,"total":…,"high":…,"medium":…,"queries":…} ],
  "monitoring": {...},
  "models": {...},
  "sources": [ {"name":"a.log","event_count":123,"kind":"raw-log-file", ...} ],
  "health": {
    "band": "Healthy" | "Warning" | "Critical" | "Unknown",
    "reasons": ["..."],
    "pipeline_status": "idle",
    "pipeline_last_run_at": 1731268890.0,
    "alerts_file_mtime": 1731268800.0,
    "alerts_file_age_seconds": 100.0,
    "retrain_recommended": false,
    "has_alerts_file": true
  }
}
```

### `POST /api/run`
Triggers a one-off pipeline run. `{ "ok": true }`.

## Alert management

### `GET /api/alerts`
```json
{ "records": [ ...feed objects... ], "total": 150, "feed_limit": 150,
  "generated": "…", "mode": "live" }
```

### `GET /api/alerts/{fp}`
```json
{ "fp": "a1b2...", "alert": {...}|null, "management": {...}|null,
  "audit": [...] }
```
`alert` may be null if the alert has aged out of the 150-item feed;
`management` still persists.

### `POST /api/alerts/{fp}/acknowledge`
Body: `{ "actor": "analyst-1" }`. Sets `acknowledged_at` and, if the
alert is Open, moves status to Acknowledged. Returns updated record.

### `POST /api/alerts/{fp}/assign`
Body: `{ "actor": "…", "analyst_id": "senior-1" | null }`.
Rejects unknown analyst ids with `400`.

### `POST /api/alerts/{fp}/status`
Body: `{ "actor": "…", "status": "Investigating", "reason": "optional" }`.
Validates against `ALLOWED_TRANSITIONS`. Invalid returns
`409 { "error": "...", "allowed": [...] }`.

### `POST /api/alerts/{fp}/escalate`
Body: `{ "actor": "…", "reason": "optional" }`. Flips `escalated=true`
and status → `Escalated`. Rejects on `Closed` (409).

### `POST /api/alerts/{fp}/notes`
Body: `{ "actor": "…", "text": "…" }`. Max 4 KiB text. Returns the
updated record including the new note object.

### `POST /api/alerts/bulk`
Body:
```json
{ "actor": "analyst-1", "action": "acknowledge|assign|status|escalate|close",
  "payload": { "status": "Investigating", "analyst_id": "…", "reason": "…" },
  "fps": ["fp1","fp2",...] }
```
Returns a per-item result:
```json
{ "total": 10, "succeeded": 8, "failed": 2,
  "results": [ {"fp":"...","code":200,"ok":true,"error":null}, ... ] }
```
Each failed item carries the server's reason (e.g. invalid transition).

## Events

### `GET /api/events?...`
Query parameters: `q`, `domain`, `ip`, `severity`, `source`,
`technique`, `from` (ISO or epoch), `to`, `limit` (1–500, default 100),
`offset`. Returns:
```json
{ "records": [...], "total": N, "offset": K, "limit": L }
```
Each record exposes the full pipeline `details` dict plus derived
columns (`anomaly_score`, `ml_combined_score`, `reason`).

### `GET /api/events/{fp}`
Full event with management + audit history.

## Devices

### `GET /api/devices`
```json
{ "clients": [ { "ip":"…", "event_count":N, "domain_count":N,
                 "first_seen":<epoch>, "last_seen":<epoch>,
                 "severity":{"High":N,...}, "status":"Active|Quiet|Unknown",
                 "enriched_dns":null, "enriched_reputation":null } ],
  "sources": [ { "name":"a.log", "kind":"raw-log-file", "size_bytes":…,
                 "mtime":…, "event_count":N } ],
  "disclaimer": "…" }
```

## Health

### `GET /api/health`
```json
{ "health": {...band/reasons...}, "monitoring": {...}, "pipeline": {...},
  "history": [last 30], "mode": "live", "watch_dir": "..." }
```

## Use cases

### `GET /api/usecases`
`{ "preferences": { "<rule_name>": {...} }, "note": "..." }`

### `POST /api/usecases/preferences`
Body: `{ "actor": "…", "rule_name": "DNS Tunneling Detection",
         "visibility": true|false, "excluded": true|false,
         "note": "optional text" }`.

## Incidents

### `GET /api/incidents`
`{ "records": [...], "integrations": {fortigate:{...}, ...} }`

### `POST /api/incidents`
Body: `{ "actor": "…", "alert_fps": [...], "title": "...", "severity": "..." }`.
Returns the created record (id = `inc-<10hex>`).

### `GET /api/incidents/{id}`
`{ "record": {...} }` or 404.

### `POST /api/incidents/{id}/action`
Body: `{ "actor": "…", "action": "watchlist_ip | mark_domain |
          create_investigation_report | export_evidence |
          firewall_block_request | endpoint_isolation_request",
          "payload": {} }`.

Response always carries `"status": "SIMULATED"` or `"NOT_CONFIGURED"`.
This project phase never returns `"EXECUTED"`.

## Audit

### `GET /api/audit?alert_fp=<fp>&incident_id=<id>&limit=<N>`
```json
{ "records": [ { "event_id":"uuid", "timestamp":"ISO",
                 "action":"STATUS_CHANGED", "actor":"analyst-1",
                 "alert_fp":"…", "incident_id":null,
                 "old_value":"Open", "new_value":"Investigating",
                 "note":null, "authenticated":false } ],
  "authenticated": false }
```

## Analysts

### `GET /api/analysts`
```json
{ "records":[{"id":"analyst-1","name":"SOC Analyst 1","role":"Tier 1"}, ...],
  "authenticated": false }
```

## Static assets

### `GET /static/<path>`
Serves files from `dashboard/static/`. Safe-joins `path` against the
static root and refuses anything resolving outside it.

## Errors

- `400` — malformed body / missing `Content-Length` / oversize body /
  validation failure (bad analyst, bad status, missing fields).
- `404` — unknown route or unknown resource.
- `405` — wrong HTTP method; `Allow` header lists the right one.
- `409` — invalid state transition; body contains `allowed` list.
- `500` — unexpected server error (logged, not surfaced in detail).

## Request-size and method limits

- Max body: `64 KiB` (`MAX_BODY_BYTES` in `server.py`).
- Max note length: `4 KiB` (`NOTE_MAX_BYTES`).
- Max incident alert_fps: 200 per incident.
- Max bulk alert operations: 200 per call.
- Audit in-memory cap: 10 000 entries (newest kept).

## Security notes

- No authentication. The `authenticated: false` flag is always returned.
- Dashboard binds to `127.0.0.1` by default. Do not expose to a public
  network without a reverse proxy, TLS, and real auth.
- No `eval()`, no shell for new endpoints. Existing `/api/run` still
  triggers the subprocess pipeline (unchanged).
