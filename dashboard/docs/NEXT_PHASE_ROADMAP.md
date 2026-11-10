# Next-Phase Roadmap

**Audience:** project planners choosing Week 7+ work.

Week 6 delivered a SOC-style monitoring suite over the DNS detection
pipeline: persistent alert workflow, event explorer, pipeline health,
and a SOAR-ready incident queue. The following work would move the
project from "credible SOC workflow" to "production-ready SOC
platform". None of it is required by the current Week 6 scope.

## 1. Authentication and role-based access control

Current: no authentication. `actor` is a string the client provides.
Next phase would introduce:

- An auth backend (Keycloak / local accounts / LDAP).
- Session cookies or bearer tokens over TLS.
- `Authenticated: true/false` flag flips to `true` only when a real
  session is attached.
- Roles: Tier-1 analyst (acknowledge / assign / note / escalate),
  Tier-2 analyst (status transitions, resolve), IR lead (close,
  incident actions), admin (configure integrations).
- Per-endpoint role check and audit-log actor binding.

## 2. Multi-analyst SOC workflow

- Shift ownership and workload balancing (round-robin or by severity).
- "My queue" view filtered to `assigned_to == currentUser()`.
- Real-time collaboration: another analyst looking at the same alert
  should see a "viewing now" indicator (SSE or WebSocket).
- Alert comments distinct from investigation notes; notes stay
  internal, comments addressable `@someone`.

## 3. Real SOAR integrations

The simulated response-actions page already has the integration
scaffold. Real integrations:

- **FortiSOAR** (webhook into an existing playbook).
- **FortiGate** (`/api/v2/cmdb/firewall/address` to add an IP to a
  block object, then `/api/v2/cmdb/firewall/policy` to attach).
- **FortiEDR** (quarantine endpoint via REST).
- **ServiceNow** (create Incident records, tracking the SOC incident
  id as `correlation_id`).

Each integration owns a module under `dashboard/integrations/<name>.py`
with `configured_from_env()`, `execute(action, payload) -> status`,
retry/backoff, and logging. Credentials from environment only.

## 4. Threat intelligence enrichment

The pipeline already carries optional MDTI fields in `details`. A next
phase can:

- Add additional threat-intel sources (OTX, GreyNoise, VirusTotal).
- Enrich on demand from the dashboard drawer ("Enrich now").
- Cache enrichments in `dashboard/data/intel_cache.json`.

## 5. Device agent integrations

Current: no device inventory (correctly disclaimed on `/devices`).
Next phase:

- Pull endpoint inventory from Microsoft Defender for Endpoint or
  FortiEDR (hostname, OS, last-check-in, user).
- Join DNS `client_ip` to inventory, surface hostname/OS on alerts
  and events.
- Honest "device last-seen" from the agent, not from DNS activity.

## 6. Notification systems

- Email / SMS / Slack / Teams on new high-severity alerts.
- Configurable per-rule and per-severity routing.
- Digest mode for low-severity.
- Backed by APScheduler-equivalent using stdlib threads (keep
  dependency count low) or a real queue if the SOC grows.

## 7. Advanced incident reporting

- Timeline export (PDF / Markdown) of every audit event for an
  incident.
- Linkable incident URLs that render read-only.
- Evidence bundle: all involved alerts, events, notes, and
  intel-enrichments in a single ZIP.
- Compliance templates (NIST IR-6, MITRE D3FEND mappings).

## 8. Historical analytics

- Move `audit_log.json` + `alert_management.json` into SQLite for
  query performance beyond ~10 k records.
- Historical charts beyond the current 120-run in-memory window.
- Analyst productivity metrics (time-to-ack, time-to-resolve,
  reopen rate), with data staying on-prem.

## 9. Scale and reliability

- Replace the current in-process JSON store with SQLite + WAL for
  crash-safe concurrency.
- Add rate limiting per IP on management endpoints.
- Add a background job worker (or move to FastAPI + Uvicorn) when the
  stdlib-only constraint is relaxed.
- Health-check endpoint for external monitors (Kubernetes liveness).

## Not in scope for near-term

- Multi-tenant isolation.
- Public internet exposure of the dashboard (localhost-only is a
  feature, not a limitation).
- Modifying the detection pipeline itself.
