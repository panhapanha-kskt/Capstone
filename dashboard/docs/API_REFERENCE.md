# Dashboard API Reference

**Audience:** developers integrating with the dashboard or writing additional pages.

All responses: `Content-Type: application/json`, `Cache-Control: no-store`.
All POST bodies: JSON object, `Content-Length` required and ≤ 64 KiB.
There is **no login**. `actor` must be an id from `analysts.json`; any other
value is recorded as `unknown-analyst`.

## Request security (all endpoints)

| Check | Applies to | Failure |
|---|---|---|
| `Host` header is `127.0.0.1`, `localhost`, `::1` or a name passed with `--allow-host` (DNS-rebinding defence) | every request | 403 |
| `Content-Type: application/json` | POST | 415 |
| `X-SOC-Request: 1` (custom header: a cross-site page cannot send it without a CORS preflight, which this server never approves) | POST | 403 |
| `Origin`, if sent, equals `http://<Host>`; `Sec-Fetch-Site`, if sent, is `same-origin` or `none` | POST | 403 |
| `POST /api/run` at most once per 10 s | `/api/run` | 429 + `Retry-After` |

Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy` / `-Resource-Policy: same-origin`.
HTML pages also carry a `Content-Security-Policy` with a fresh script nonce per response
(`--csp-report-only` switches it to report-only for debugging). React, ReactDOM and htm are served
from `/static/vendor/`, so no third-party script origin is allowed.

Minimal curl POST:
```bash
curl -s -X POST http://127.0.0.1:9000/api/alerts/$FP/acknowledge \
  -H 'Content-Type: application/json' -H 'X-SOC-Request: 1' -d '{"actor":"analyst-1"}'
```

`GET /api/state` returns an `ETag` (`"v<version>-<30 s bucket>"`); send it back as
`If-None-Match` to get `304 Not Modified` when nothing changed.

## SOC workflow endpoints (added 2026-11-17)

| Endpoint | Purpose |
|---|---|
| `POST /api/alerts/{fp}/verdict` `{"verdict": "true_positive" \| "false_positive" \| "benign_positive" \| "duplicate", "reason"?}` | Analyst disposition; audited as `VERDICT_SET`. Also a bulk action (`"action":"verdict"`, `payload.verdict`). `--require-verdict` makes Resolved/Closed return 409 until one is set. |
| `GET /api/alerts?assigned_to=<id>&sort=severity\|age&include_suppressed=0` | Filtered queue (all parameters optional). |
| `GET /api/alerts/{fp}/related?window=900` | Alerts sharing the client IP or registered domain within ±window seconds. |
| `GET /api/metrics?hours=24` | MTTD (alert − DNS query time), MTTA, MTTR (n / mean / median / p90 seconds), ack-SLA breaches (High 15 min, Medium 60 min, Low 4 h), open by severity, verdicts, false-positive rate, per-analyst workload, ATT&CK tactic × technique counts. |
| `GET /api/reports/handover?hours=8&format=json\|md` | Shift handover: escalated and unassigned-High open alerts, open incidents, analyst activity, metrics. |
| `GET /api/suppressions` · `POST /api/suppressions` `{field: domain\|client_ip\|rule, value, reason, until?}` · `POST /api/suppressions/{id}/delete` | Known-false-positive suppressions. UI only: feed items get `"suppressed": "<id>"`; detection and export are unchanged. `reason` is required; `until` must be in the future or null. |

## Role guardrails (added 2026-11-18)

Every write checks the actor's tier: the digit in its `role` in `analysts.json` (`unknown-analyst` = 0).
Refusals are `403 {"error", "required_tier", "actor_tier"}`. This is a workflow control, not authentication.

| Action | Minimum tier |
|---|---|
| note | 0 |
| acknowledge, assign, status, escalate, verdict, bulk, claim, release, checklist, case close/escalate, handover ack, create incident | 1 |
| verdict in a false-positive class (`fp_model_logic`, `fp_bad_data`, legacy `false_positive`) on a High/Critical alert | 2 (Tier 1 uses a triage close request instead) |
| approve / reject a close request (never the requester) | 2 |
| suppressions, incident response actions, use-case preferences, force-claim | 2 |
| reopen a Resolved/Closed alert | 2, or the analyst who closed it |
| claim or close an Escalated case | 2 |

Keys starting with `_` are stripped from every request body.

Verdicts: `true_positive`, `benign_positive`, `fp_model_logic`, `fp_bad_data`, `duplicate`, `undetermined`
(and the legacy `false_positive`). Feedback labels: TP → 1; FP classes and benign → 0; duplicate and undetermined → null.

## Tier 1 triage endpoints (added 2026-11-18)

A **case** groups alerts by `group=source` (client IP + detection type: zscore / ml / nxdomain / heuristic; default)
or `group=entity` (client IP + domain apex; one extra label inside internal zones such as `lab.local`). Case
keys are `c-` + 12 hex. Case status is derived from the member alert records: PendingApproval > Escalated >
Closed (no open member) > least-advanced open status.

| Endpoint | Purpose |
|---|---|
| `GET /api/triage/queue?group=&actor=&mine=1&status=open\|<status>&severity=&q=&offset=&limit=` | Counts (`by_status`, `by_severity`, `mine`, `unassigned`, `sla_breached`, `pending_approval`, `alerts`) and a page of cases sorted by priority then triage due time. Each case has `priority`, `members`, `owner`, `ack_due` / `triage_due` (epoch), breach flags, `checklist_done/total`, `suggestion`, `source_flags`. ETag / 304. |
| `GET /api/triage/case/{key}?actor=&offset=&limit=` | `case`, paged `members`, `evidence` (query counts, types, response codes, label lengths, encodings, 5-minute volume, timeline, longest names, parsed Z-scores), `checklist`, `ml` (per-model scores, signatures, top deviations from the client baseline), `suggestion`, `source` (IP flags), `pivots`, `escalations`, `close_request`, `history`, `allowed_actions`. |
| `POST /api/triage/case/{key}/claim` `{actor, force?}` | Acknowledge + assign every open member and move it to Investigating. 409 if owned by someone else (Tier 2 may `force`). |
| `POST .../release` `{actor, next_step?}` | Unassign members; keep the next step on the case. |
| `POST .../declare` `{actor, title, severity, reason}` | Claimed analyst declares a linked incident from an Investigating case. Stores a snapshot of evidence, checklist, ML context, and triage history. Returns 201 for a new incident or 200 with `already_declared` on retry. |
| `POST .../checklist` `{actor, item_id, checked, note?}` | Tick a checklist item. `m_host_review` and `m_owner` are required before close/escalate. |
| `POST .../close` `{actor, classification, comment}` | Comment ≥ 10 chars. 200 closed, or **202** with a close request when Tier 1 closes a High/Critical case as a false positive. |
| `POST .../escalate` `{actor, summary, evidence, checks_done, hypothesis, recommended_action}` | All fields required; members become Escalated; case returns to the queue for Tier 2. |
| `GET /api/triage/requests?status=pending` · `POST /api/triage/requests/{id}/approve\|reject` `{actor, note?}` | Four-eyes approvals. |
| `GET /api/triage/me?actor=&hours=8` | Personal shift stats: claimed, closed, close requests, escalated, approved/rejected, median MTTA, open owned. |
| `GET /api/triage/handover?hours=8` · `POST /api/triage/handover/ack` `{actor, note?}` | Handover report with open cases (status, owner, next step), pending approvals and the last acknowledgement. |
| `GET /api/enrich/domain/{d}` · `GET /api/enrich/ip/{ip}` | Offline: internal zone, apex, Tranco rank (if `dashboard/data/tranco.csv` exists), IP flags. Online (VirusTotal / AbuseIPDB) only when enabled; internal names and non-public IPs are never sent. |

SLA clocks start at the case's stored `first_seen_at`: ack (`ACK_SLA_SECONDS`, stops at claim) and triage
(Critical 15 min, High 1 h, Medium 4 h, Low 8 h; stops at close, escalate or close request).

## ML ↔ SOC integration endpoints (added 2026-11-17)

| Endpoint | Purpose |
|---|---|
| `GET /api/model` | Deployed model summary from `models/`: `model_version` (hash of thresholds + training metadata), Path A threshold/decision/FPR budget, Path B type (from `model_type`, else the file present: `_iforest.pkl` → IsolationForest, `.h5`/`.keras` → autoencoder), fusion threshold and coefficients, training sample counts, drift (max PSI, retrain recommended). `/api/state` also carries `model_version`. |
| `GET /api/feedback/export?format=json\|csv\|ndjson` | One row per alert with a verdict, with its ML scores and model version. `label` 1 = true_positive, 0 = false/benign positive, null = duplicate. CSV cells starting with `= + - @` are prefixed with `'`. `scripts/export_feedback_labels.py` saves it to `data/feedback/`. |
| `GET /api/integrations` | Exporter status (`last_success`, `sent_total`, `pending`, `last_error`) and config with secrets shown as `***`. Also in `/api/state` as `integrations`. |

Exporters (`dashboard/exporters.py`) are configured only by editing
`dashboard/data/response_integrations.json` (no API can change the target URL). See
`docs/Week6/SOC_ML_INTEGRATION.md`.

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
Body: `{ "actor": "…", "alert_fps": [...], "title": "...", "severity": "...", "reason": "..." }`.
`alert_fps` may be empty for a manual incident when `reason` has at least 10 characters. Manual incidents keep `source_type: "manual"` and no placeholder alert ID.
Returns the created record (id = `inc-<10hex>`). Linked incidents declared from `/triage` also include `source_case_key`, `source_case_mode`, `source_client`, `declaration_reason`, and a `triage_snapshot` of the investigation. `/incidents?id=<incident_id>` opens a linked incident; its source link points back to `/triage?case=<case_key>&group=<mode>`.

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
