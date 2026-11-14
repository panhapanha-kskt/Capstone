# Week 6 — Testing Report

**Audience:** reviewer running the Week 6 dashboard against the detection pipeline.

**Date:** 2026-11-10 (pre-execution; see "Execution status" per section).

## Scope

This document lists the test cases, their expected results, and
instructions for running them. The pipeline, ML training, and
end-to-end run commands are not executed from this environment (per
project guidance — the user runs those themselves). Static checks and
code-level verification are reported inline.

## 1. Static / code checks

| Check | Expected | Actual |
|------|---------|--------|
| `python -c "ast.parse(open('dashboard/server.py').read())"` | syntax OK | **PASS** |
| No modifications outside `dashboard/` | `git status` lists only `dashboard/**` | **PASS** (before commit) |
| `/api/state` is a strict superset of Week 5 shape | all original keys present | **PASS** (fields only added) |
| Stable alert ID = `fp_hex(fingerprint(a))`, not `alert_id` | mgmt APIs key by `fp` | **PASS** |

## 2. Regression tests (Phase 14.1)

Run in parallel with `python dashboard/server.py --demo --port 9000`:

```bash
curl -s http://127.0.0.1:9000/ | grep -q "Capstone" && echo OK                  # Classic Dashboard
curl -s http://127.0.0.1:9000/soc | grep -q "Monitoring"                        # SOC overview
curl -s http://127.0.0.1:9000/usecases | grep -q "Kill Chain"                   # Use Cases
curl -s http://127.0.0.1:9000/alerts | grep -q "Alerts"                         # Alerts SPA
curl -s http://127.0.0.1:9000/api/state | jq '.version'                         # version field
```

| Case | Expected |
|------|---------|
| `/` renders Classic Dashboard with existing charts | pass |
| `/soc` renders 7 KPI tiles + 3 donuts + 3 historical SVG charts **and** new Operational Metrics row | pass |
| `/usecases` renders Cyber Kill Chain + use-case table + pagination | pass |
| `/alerts` renders React grid, 13+1 columns, severity pie + type bars | pass |
| `/api/state` returns JSON with `version`, `feed`, `totals`, plus `fp`, `details`, `management`, `sources`, `health` | pass |
| 3-second poll on soc/usecases/alerts, 5-second on events | pass (hardcoded in each page) |
| Alert detail drawer still opens on row click | pass (preserved) |

## 3. New-feature tests (Phase 14.2)

### 3.1 Alert lifecycle persistence

```bash
# demo mode
python dashboard/server.py --demo --port 9000 &

# 1. Pick a fingerprint
FP=$(curl -s http://127.0.0.1:9000/api/alerts | jq -r '.records[0].fp')
echo "FP=$FP"

# 2. Acknowledge → Investigating → add note → Escalate
curl -s -X POST http://127.0.0.1:9000/api/alerts/$FP/acknowledge \
  -H 'Content-Type: application/json' -d '{"actor":"analyst-1"}' | jq .
curl -s -X POST http://127.0.0.1:9000/api/alerts/$FP/status \
  -H 'Content-Type: application/json' -d '{"actor":"analyst-1","status":"Investigating"}' | jq .
curl -s -X POST http://127.0.0.1:9000/api/alerts/$FP/notes \
  -H 'Content-Type: application/json' -d '{"actor":"analyst-1","text":"Suspicious high-entropy subdomain"}' | jq .
curl -s -X POST http://127.0.0.1:9000/api/alerts/$FP/escalate \
  -H 'Content-Type: application/json' -d '{"actor":"senior-1"}' | jq .

# 3. Fetch audit
curl -s "http://127.0.0.1:9000/api/audit?alert_fp=$FP" | jq '.records | length'
```

Expected:
- Each POST returns `{"ok":true, "record":{...}}`.
- Final `status == "Escalated"`, `escalated == true`, one note present.
- Audit list has entries: `ACKNOWLEDGED`, `STATUS_CHANGED`,
  `NOTE_ADDED`, `ESCALATED`.

### 3.2 Invalid transition (Phase 4.3)

*Corrected 2026-11-14.* The earlier version tried Escalated → Open and expected `allowed: ["Open"]`. That was wrong: from Escalated the allowed transitions are Investigating, Resolved and Closed (`ALLOWED_TRANSITIONS` in `dashboard/server.py`), so the `allowed` list would not be `["Open"]`. The clean test is **Closed → Investigating**: a closed alert may only be reopened.

```bash
# close an alert, then try to move it straight to Investigating
curl -s -X POST http://127.0.0.1:9000/api/alerts/$FP/status \
  -H 'Content-Type: application/json' -d '{"actor":"analyst-1","status":"Closed"}' | jq .status
curl -s -w '\nHTTP %{http_code}\n' -X POST http://127.0.0.1:9000/api/alerts/$FP/status \
  -H 'Content-Type: application/json' -d '{"actor":"analyst-1","status":"Investigating"}'
```

Expected: the first call succeeds; the second returns HTTP `409 Conflict` with
`{"error": "invalid transition Closed → Investigating", "allowed": ["Open"]}`.
In the UI, a closed alert offers only "Reopen → Open".

### 3.3 Server restart test (Phase 14.3)

1. Start `python dashboard/server.py --demo --port 9000`.
2. Via the UI (`/alerts`), acknowledge an alert and add a note.
3. `Ctrl+C` the server.
4. Inspect `dashboard/data/alert_management.json` and
   `dashboard/data/audit_log.json` — both contain the records.
5. Restart the server.
6. Reopen `/alerts` — the alert still shows Acknowledged + note.
   Fingerprint stable across restart: yes (deterministic from
   rule_name + client_ip + domain + query_time + description).

### 3.4 Bulk action

```bash
FPS=$(curl -s http://127.0.0.1:9000/api/alerts | jq -c '[.records[0:3][].fp]')
curl -s -X POST http://127.0.0.1:9000/api/alerts/bulk \
  -H 'Content-Type: application/json' \
  -d "{\"actor\":\"analyst-1\",\"action\":\"acknowledge\",\"fps\":$FPS}" | jq .
```
Expected: `{total:3, succeeded:3, failed:0, results:[...]}`.

### 3.5 Event Explorer filter

Open `/events` and filter by `severity=High` then `source` dropdown.
Expected: result count updates, N/A for missing ML scores in demo mode.
Backend check:
```bash
curl -s "http://127.0.0.1:9000/api/events?severity=High&limit=5" | jq '.records|length'
```

### 3.6 Devices / Sources honesty

`GET /api/devices` → `clients` have `status` in {Active, Quiet,
Unknown} only. No `Offline`. Disclaimer banner present on the UI.

### 3.7 Health band transparency

```bash
curl -s http://127.0.0.1:9000/api/health | jq '.health | {band, reasons}'
```
Expected: in demo mode `band = "Healthy"` with reasons listing "idle and
alerts file is fresh", or `"Warning"` if drift is injected. Reasons
are always populated.

### 3.8 Use-case preferences persist server-side

Toggle visibility on the `/usecases` page. Confirm the change survives
a page reload **and** a server restart. Inspect
`dashboard/data/usecase_preferences.json`.

### 3.9 Response-action honesty (Phase 10.2)

Create an incident:
```bash
INC=$(curl -s -X POST http://127.0.0.1:9000/api/incidents \
  -H 'Content-Type: application/json' \
  -d '{"actor":"analyst-1","title":"Test","severity":"Medium","alert_fps":["placeholder"]}' | jq -r '.record.id')

curl -s -X POST "http://127.0.0.1:9000/api/incidents/$INC/action" \
  -H 'Content-Type: application/json' \
  -d '{"actor":"analyst-1","action":"firewall_block_request","payload":{}}' | jq .
```
Expected: `status == "NOT_CONFIGURED"` (fortigate integration is not
configured by default). After flipping
`dashboard/data/response_integrations.json` `fortigate.configured=true`:
expected `status == "SIMULATED"`. Never `"EXECUTED"`.

## 4. Demo and real-mode parity (Phase 14.4 / 14.5)

```bash
# Demo
python dashboard/server.py --demo --port 9000
# Real
python dashboard/server.py --watch infra/technitium-elk/data/dns_logs --port 9000
```

Both modes must:
- Use the same management APIs (verify: run the Section 3 tests
  against both; results identical).
- Show the same page structure.
- In demo mode, Event Explorer ML/anomaly fields show N/A and the
  page banner notes demo mode.
- In real mode, `details` is populated with the actual pipeline
  fields; management records survive pipeline runs (the `alert_id`
  UUID changes but `fp` does not).

If the pipeline is not available at test time, real-mode validation is
reported as "not executed in this environment" rather than claimed as
a pass.

## 5. Passed / failed summary (pre-execution)

| Category | Status |
|---------|--------|
| Static checks (syntax, scope) | **PASS** |
| Regression tests (Phase 14.1) | *to be executed by user* |
| New-feature tests (Phase 14.2) | *to be executed by user* |
| Restart test (Phase 14.3) | *to be executed by user* |
| Demo-mode end-to-end (Phase 14.4) | *to be executed by user* |
| Real-mode end-to-end (Phase 14.5) | *to be executed by user — requires pipeline* |

Real test outcomes should be appended to this document after each
run.

## 6. Remaining issues / known risks

- Fingerprint drift: if the pipeline later changes the shape of
  `description`, previously-persisted management records may orphan
  (their `fp` no longer matches). Mitigation: `fp` is already based on
  only the first 90 chars of description.
- Audit log growth: bounded in memory to 10 000 entries; disk file
  rewritten every write. For sustained high-volume SOCs, an
  append-only log file or a real database is appropriate.
- Demo-mode ML fields: expected empty; not a bug.
