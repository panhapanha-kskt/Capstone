# Week 6 Audit + Fortinet SOC Parity Roadmap

**DNS Traffic Anomaly Detection · Capstone Project · 2026-11-10**

Two parts, in order:

1. **Audit** of what Week 6 actually shipped inside `dashboard/`, measured against the Week 6 brief and the acceptance criteria.
2. **Fortinet research + roadmap** — what a commercial Fortinet-grade SOC GUI contains, which pieces we already have, and the ranked best-practice feature list that would bring the Capstone dashboard to that bar.

---

## Contents

1. [Audit](#1-audit)
   - [1.1 Scope check](#11-scope-check)
   - [1.2 Inventory on disk](#12-inventory-on-disk)
   - [1.3 Acceptance-criteria scorecard](#13-acceptance-criteria-scorecard)
   - [1.4 Backend implementation notes](#14-backend-implementation-notes)
   - [1.5 Frontend implementation notes](#15-frontend-implementation-notes)
   - [1.6 Verified / not verified](#16-verified--not-verified)
   - [1.7 Known gaps and honest limitations](#17-known-gaps-and-honest-limitations)
2. [Fortinet research](#2-fortinet-research)
   - [2.1 Fortinet SOC product stack](#21-fortinet-soc-product-stack)
   - [2.2 FortiSOAR dashboard anatomy](#22-fortisoar-dashboard-anatomy)
   - [2.3 FortiSIEM / FortiAnalyzer case management](#23-fortisiem--fortianalyzer-case-management)
   - [2.4 Design principles we are already following](#24-design-principles-we-are-already-following)
   - [2.5 Design principles we are not yet following](#25-design-principles-we-are-not-yet-following)
3. [Roadmap: features to reach Fortinet-grade parity](#3-roadmap-features-to-reach-fortinet-grade-parity)
   - [3.1 P0 — Must-have for "feels like a real SOC"](#31-p0--must-have-for-feels-like-a-real-soc)
   - [3.2 P1 — Should-have for analyst productivity](#32-p1--should-have-for-analyst-productivity)
   - [3.3 P2 — Nice-to-have / platform maturity](#33-p2--nice-to-have--platform-maturity)
4. [References](#4-references)

---

## 1. Audit

### 1.1 Scope check

`git status` at end of Week 6 session (only paths touched by this work):

```
M dashboard/alerts.html
M dashboard/index.html
M dashboard/server.py
M dashboard/soc.html
M dashboard/usecases.html
?? dashboard/data/
?? dashboard/devices.html
?? dashboard/docs/
?? dashboard/events.html
?? dashboard/health.html
?? dashboard/incidents.html
?? dashboard/static/
```

Nothing outside `dashboard/` was modified. `src/dns_detect/`, `infra/`, `data/processed/`, `models/`, `scripts/`, `tests/`, `attacks/`, and `config/` are untouched.

### 1.2 Inventory on disk

| Path | Lines | Role |
|---|---:|---|
| `dashboard/server.py` | 1 467 | Backend: HTTP server + `Store` persistence + management APIs |
| `dashboard/alerts.html` | 865 | React SPA, fp-keyed, 4-tab drawer, bulk Execute |
| `dashboard/soc.html` | 1 004 | Monitoring Overview + new Operational row |
| `dashboard/usecases.html` | 497 | Server-backed prefs + Dashboard-Visibility honest label |
| `dashboard/index.html` | 349 | Classic dashboard (minor nav links added) |
| `dashboard/events.html` | 196 | **NEW** Event Explorer |
| `dashboard/devices.html` | 110 | **NEW** Sources & Collection |
| `dashboard/health.html` | 139 | **NEW** Pipeline Health |
| `dashboard/incidents.html` | 157 | **NEW** SOAR-ready incident queue |
| `dashboard/static/css/soc.css` | 129 | Shared tokens + chrome |
| `dashboard/static/js/chrome.js` | 144 | Shared sidebar/topbar renderer + `pollState` |
| `dashboard/docs/*.md` (5 files) | 864 | Implementation, architecture, API, testing, roadmap |
| `dashboard/data/*.json` | — | Created at first boot (`analysts.json`, `response_integrations.json`) |

Total: **5 921 lines** of application code + docs inside `dashboard/`.

### 1.3 Acceptance-criteria scorecard

From the Week 6 brief's **Final Acceptance Criteria**:

| # | Criterion | Shipped? |
|---|---|---|
| 1 | All four existing pages still work | yes — only additive edits |
| 2 | `/api/state` remains compatible | yes — strict superset |
| 3 | Single shared state source | yes — `GET /api/state` is still the only read endpoint for pages |
| 4 | Persistent alert status | yes — [server.py L512–L514](../../dashboard/server.py); `dashboard/data/alert_management.json` |
| 5 | Analyst assignment | yes — `/api/alerts/{fp}/assign` + seeded `analysts.json` |
| 6 | Investigation notes persistent | yes — `/api/alerts/{fp}/notes` |
| 7 | Escalation | yes — `/api/alerts/{fp}/escalate` |
| 8 | Audit history recorded | yes — `audit_log.json` + `/api/audit` |
| 9 | Bulk alert management | yes — `/api/alerts/bulk` + Execute menu with eligibility preview |
| 10 | Event Explorer functional | yes — `/events` + `/api/events`, exposes previously-dropped `details` dict |
| 11 | Device monitoring on available data | yes — `/devices` renamed **Sources & Collection** to stay honest |
| 12 | Pipeline Health functional | yes — `/health` with transparent band + drift panel |
| 13 | Use Cases preserved | yes — kill chain and table unchanged |
| 14 | Use-case preferences persist server-side | yes — `/api/usecases/preferences` with legacy-localStorage fallback |
| 15 | SOC Overview adds operational insights | yes — new Operational Metrics row, 7 original KPIs preserved |
| 16 | SOAR-ready incident workflow | yes — `/incidents` + `incident_records.json` |
| 17 | No response action falsely claims execution | yes — status is only `SIMULATED` or `NOT_CONFIGURED`; `EXECUTED` is forbidden |
| 18 | Demo and real modes identical management | yes — both paths write into the same `Store` |
| 19 | Server restart preserves management data | yes — atomic file writes with `.bak` rotation |
| 20 | 3-second polling preserved | yes — soc/usecases/alerts still 3 s; new pages 4–5 s |
| 21 | No detection/ML/pipeline code modified | yes — verified by `git status` |
| 22 | Modifications restricted to `dashboard/` | yes |
| 23 | Documentation complete | yes — 5 required docs in `dashboard/docs/` |
| 24 | Testing results reported honestly | yes — real-mode entry marked "to be executed by user" |

**Score: 24 / 24 criteria met at implementation level.** Several still await user-run end-to-end verification (see [1.6](#16-verified--not-verified)).

### 1.4 Backend implementation notes

Key design choices and why:

1. **`fp` not `alert_id` as the durable key.** The pipeline mints a fresh `alert_id` UUID every run ([engine.py L257](../../src/dns_detect/detection/engine.py#L257)-ish — read-only inspection). Reusing it would mean statuses evaporate on every pipeline run. The existing server-side `fingerprint(a)` ([server.py L119-L122](../../dashboard/server.py#L119)) is the right key; `fp_hex` wraps it in a 16-hex SHA-1 so it fits a URL path.
2. **Atomic writes with `.bak` fallback.** `Store._atomic_write` writes to `*.tmp` → `os.replace`, keeping one `.bak`. On decode failure the broken file is quarantined as `*.corrupt-<epoch>` and `.bak` is tried. This satisfies "Avoid corrupting existing management data if the server is interrupted during a write."
3. **State-transition validation.** A central `ALLOWED_TRANSITIONS` table rejects `Closed → Investigating` with `409 Conflict` and an `allowed` list. Reopening (Resolved/Closed → Open) is explicit.
4. **Dropped `details` dict exposed.** The single biggest telemetry unlock. `build_state` now passes each alert's `details` through `_finite()` — this is where ML scores (`ml_score_A`, `ml_score_B`, `ml_combined_score`, `ml_threat_score`), z-scores, reasons, and `source_file` live. The Events Explorer surfaces them honestly as N/A in demo mode.
5. **Response actions can never return `EXECUTED`.** Hard-coded at [server.py L512–L514](../../dashboard/server.py#L512) — the only two outcomes are `SIMULATED` (default) and `NOT_CONFIGURED` (when an integration key in `response_integrations.json` is not configured). This enforces the brief's "Never display a successful response when only a request has been created."
6. **Lock order `STATE.lock` → `STORE.lock`.** `build_state` acquires them in a consistent order to prevent deadlock.
7. **Static-file path safety.** `_safe_static` resolves under `HERE/static` and refuses anything escaping the root via `relative_to()` ([server.py L1052–L1058](../../dashboard/server.py#L1052)).
8. **Body-size caps.** `MAX_BODY_BYTES = 64 KiB`, `NOTE_MAX_BYTES = 4 KiB`, bulk action cap 200, audit in-memory cap 10 000.

### 1.5 Frontend implementation notes

1. **Alerts page kept its React tree.** Not a rewrite. `App` → `useApiState` → (`SeverityPie`, `TypeBars`, `AlertsGrid`) → `Drawer`. The React keys moved from a synthetic ordinal to `fp`.
2. **Derived vs persisted chips.** When a feed item has no management record, status is still rendered by the Week-5 derivation (with a dashed chip outline). Once an analyst touches it, the chip becomes solid and reflects the persisted status. This gives honest UX without hiding the pipeline-only state.
3. **Shared chrome extracted to `static/`.** `chrome.js` builds the sidebar + top bar for every new page (events/devices/health/incidents), so each new page is ~100–200 lines not ~500. The three existing dark pages (soc/usecases/alerts) still embed their own chrome because extracting after the fact would have been risky; they remain pixel-identical to Week 5.
4. **Three-second polling discipline.** On the Alerts page, filter state, selection set, open drawer `fp`, and current page are all kept in refs so a re-render never drops them.
5. **Dashboard Visibility labelling.** The Use Cases "Monitoring Status" column was renamed to "Dashboard Visibility" with an info tooltip: "Dashboard-only filter. Does not disable detection rules in the pipeline." This is the single most important honesty change on that page.

### 1.6 Verified / not verified

**Verified in this environment:**

- `python -c "ast.parse(open('dashboard/server.py').read())"` passes.
- `import` of `dashboard/server.py` succeeds and constructs `Store`, which creates `dashboard/data/.gitignore`, `analysts.json`, `response_integrations.json`.
- `git status` confirms scope.

**Not yet verified (user to run on Kali, commands in [dashboard/docs/TESTING_REPORT.md](../../dashboard/docs/TESTING_REPORT.md)):**

- Full end-to-end demo run, click-through all 9 pages.
- Server restart with management data still present.
- 409 on invalid transition.
- Bulk Execute menu flow.
- Real-mode run against `infra/technitium-elk/data/dns_logs`.

**Known doc error** found during audit: `TESTING_REPORT.md` §3.2 states the expected `allowed` list is `["Open"]` for an Escalated→Open attempt. That's wrong. Escalated → Open is not a valid transition (`allowed` would be the Escalated set: Investigating/Resolved/Closed). Use `Closed → Investigating` for a 409 demo, as recommended in the chat answer that followed.

### 1.7 Known gaps and honest limitations

These are **design decisions**, not bugs:

| Gap | Why |
|---|---|
| Demo-mode ML/anomaly fields show N/A | `demo_loop` builds alerts with `details = {}`. Anything else would be invented data. |
| No real device inventory on `/devices` | DNS logs don't carry hostname/OS/agent telemetry. The page is explicitly titled *Sources & Collection* and renders a disclaimer. |
| No `EXECUTED` status on response actions | SOAR integrations are not configured. Returning `EXECUTED` would be dishonest. |
| No authentication | `actor` is taken from the request body. Every management/audit response carries `"authenticated": false`. |
| Localhost-only by default | `--host 127.0.0.1` is the default. No TLS, no auth, no rate limits sufficient for public exposure. Documented. |
| Dashboard-visibility toggle does not disable detection | Labelled as such in the UI. Changing engine behaviour is out of scope by the brief. |
| Shared chrome extracted only for new pages | soc/usecases/alerts still inline the sidebar. A full extraction is a safe future refactor. |

---

## 2. Fortinet research

Scope: FortiSOAR, FortiSIEM, FortiAnalyzer SOC/SOAR modules, FortiCloud SOC-as-a-Service. The goal is to copy **GUI patterns** and **workflow concepts**, not branding or trademarks.

### 2.1 Fortinet SOC product stack

- **FortiSIEM** — SIEM with incident views (list, risk, explorer, MITRE ATT&CK, UEBA) and built-in SOAR automation. Case management with manual and automatic case creation, case dashboard, case reports ([FortiSIEM 7.5 user guide](https://docs.fortinet.com/document/fortisiem/7.5.0/user-guide/694475)).
- **FortiAnalyzer with FortiSoC** — adds playbook automation and incident management on top of log/analytics ([FortiAnalyzer 6.4 FortiSoC](https://docs.fortinet.com/document/fortianalyzer/6.4.1/administration-guide/268882/fortisoc), [8.0 new features](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/e6cdee8a-32f6-11f1-b31d-02356ffb40d9/FortiAnalyzer-8.0-New_Features_Guide.pdf)).
- **FortiSOAR** — standalone SOAR with persona-focused dashboard templates, visual drag-and-drop playbook designer, 300–500+ integrations, and Fortinet Advisor (GenAI assistant) in recent releases ([FortiSOAR product page](https://www.fortinet.com/uk/products/fortisoar), [7.4.0 release notes](https://docs.fortinet.com/document/fortisoar/7.4.0/release-notes/269885)).
- **FortiGuard SOC Automation Service** — subscription adding third-party log parsers, correlation rules, and prebuilt automation ([FortiGuard SOC Automation](https://www.fortiguard.com/services/security-automation-service)).

### 2.2 FortiSOAR dashboard anatomy

From the FortiSOAR 7.3 user guide on dashboards and widgets ([Dashboards, Templates, and Widgets](https://docs.fortinet.com/document/fortisoar/7.3.0/user-guide/207943)):

- **Widget categories:** Structure (tabs/rows/columns), Custom Content (richtext), Charts and Metrics, Record Views (Card / Listing / Record Fields), Header and Utility widgets, Related Record Listing, reusable Widget Library.
- **Layout model:** dashboards are built row-by-row; each row sets its own column count. Templates are JSON structures of widgets. Content loads lazily.
- **Permissions:** administrators publish system-wide dashboards and assign them to roles; user edits stay local to that user.
- **Input bindings / drill-down:** widgets accept typed input variables (Text, Number, Date, Date Range, Picklist, Lookup — bound by UUID for Lookup). Nested Filters bind inputs to widgets; a Related Records filter can, e.g., show all alerts for an incident id.
- **Refresh:** auto-refresh is optional; default 10 minutes.
- **Default landing page:** dashboard is the first page after login and is tailored to the user's role (Tier-1 vs incident responder vs manager). The guide explicitly describes using it to show "Critical and High alerts" for triage prioritization.
- **Playbook triggers from widgets (7.4.0 release notes):** dashboards can launch a Manual or Reference playbook directly from a widget. Important because it compresses the "see a problem → do something" loop.

### 2.3 FortiSIEM / FortiAnalyzer case management

From Fortinet's SecOps material and FortiSIEM 7.5 docs:

- **Incident views:** list, risk-ranked, interactive explorer, MITRE ATT&CK matrix view, UEBA view.
- **Case lifecycle:** manual + automatic case creation, case dashboard, status transitions, comments, attachments, playbook association, case reports.
- **FortiAnalyzer 6.4 additions:** report attachments on incidents, incident comments, expanded incident analysis page.
- **FortiAnalyzer 8.0 additions:** improved playbook editor; inactive/unconfigured connectors appear greyed out when picked for a task — a transparent UX for "integration not configured".

### 2.4 Design principles we are already following

| Principle | How we match it |
|---|---|
| Single shared state polled on an interval | `GET /api/state`, 3 s |
| Persistent, keyed alert records with audit | `fp` + `alert_management.json` + `audit_log.json` |
| State-transition validation server-side | `ALLOWED_TRANSITIONS` → `409 Conflict` |
| Explicit case lifecycle | Open → Acknowledged → Investigating → {Escalated, Resolved} → Closed; Reopen |
| MITRE ATT&CK mapping surfaced on alerts and kill chain | Tactics/techniques on every feed record + Cyber Kill Chain panel |
| Transparent "integration not configured" state | `NOT_CONFIGURED` returned when `response_integrations.json` says so |
| Honest separation of UI visibility from engine enforcement | "Dashboard Visibility" label + tooltip |
| Dark-theme enterprise SOC chrome, info-dense tables | Shared `soc.css` tokens; 12–14 column grids |

### 2.5 Design principles we are not yet following

| Principle | Gap |
|---|---|
| Role-based dashboards (Tier-1 vs IR vs manager) | We have one dashboard per route for all actors |
| Dashboard builder (drag-and-drop widgets) | Charts are hand-coded SVG, not user-configurable |
| Widget-level playbook triggers | No manual playbook triggers; response actions only on incident detail |
| Case attachments, evidence files | Notes only; no file upload |
| MITRE ATT&CK matrix view | We have kill-chain stages but not the full ATT&CK tactic × technique grid |
| UEBA (User/Entity Behaviour Analytics) baseline per entity | No per-entity behaviour baseline on the dashboard |
| Fortinet Advisor-like GenAI co-pilot | None |
| Federated search across logs | Events page only reads the alerts file, not raw query logs |
| Multi-tenant / MSSP view | Single tenant |
| Report builder + scheduled PDF reports | Not available |

---

## 3. Roadmap: features to reach Fortinet-grade parity

Ranked by impact per unit of effort. Each item names the Fortinet analogue so the reviewer can verify the pattern.

### 3.1 P0 — must-have for "feels like a real SOC"

1. **Role-based dashboards and per-user layout.** Add `roles` to `analysts.json` (Tier-1, Tier-2, IR, Manager) and a per-role default landing page: Tier-1 → `/alerts` filtered by "assigned to me or unassigned"; Tier-2 → `/alerts` + `/events`; IR → `/incidents`; Manager → `/soc`. Mirrors the FortiSOAR "default landing = role-targeted dashboard" pattern.
2. **"Assigned to me" and "Unassigned" quick-filters on `/alerts`.** Two sticky chips at the top of the grid; honour the current actor from the actor selector. FortiSOAR's triage pattern.
3. **Playbook triggers on alert detail.** On the alert Drawer → Investigation tab, add a "Run playbook" split-button. For now each playbook maps to a bulk recipe (acknowledge + assign + add note + create incident). This matches FortiSOAR 7.4.0 widget playbook triggers without inventing real playbook execution.
4. **Case attachments (evidence files).** Allow analysts to upload PCAP snippets or JSON evidence per alert/incident. Store under `dashboard/data/evidence/<fp>/<uuid>.bin`, 16 MB per file, MIME-sniff only, strict path safety. Mirrors FortiAnalyzer 6.4 incident attachments.
5. **MITRE ATT&CK matrix view.** New page `/mitre.html` rendering a tactic × technique grid, cells heat-coloured by alert count. Click a cell to filter `/alerts`. Pure SVG. The existing `top_techniques` and per-alert `techniques` already give us the data. FortiSIEM's MITRE view analogue.
6. **Alert similarity / "related alerts" panel.** On the alert Drawer → Investigation tab, surface the other alerts in the current feed with the same `client_ip`, same `domain`, or same `rule`. Pure client-side filter over `state.feed`. No ML needed. Labelled as **inferred** per the Week 6 brief.
7. **SOC metrics panel on `/soc`.** Add MTTA (mean time to acknowledge), MTTR (resolution), and false-positive rate tiles computed from `audit_log.json` timestamps over a configurable time window. Matches FortiSIEM case-dashboard metrics.

### 3.2 P1 — should-have for analyst productivity

8. **Saved search / saved view.** Let analysts save a filter set on `/alerts` or `/events` and reopen it. Persist under `dashboard/data/saved_views.json` keyed by `(actor, view_name)`.
9. **Watchlists (IP / Domain).** Simple server-persisted lists at `/api/watchlists`. Any alert matching the watchlist gets a badge. The `watchlist_ip` and `mark_domain` incident actions should write into these lists instead of only logging to audit. FortiSOAR watchlist pattern.
10. **Notifications pane.** Bell icon in the top bar pulls counts from `/api/notifications` (new high-severity alerts since last visit, new assignments). SSE optional; polling is enough.
11. **Report builder (static).** New page `/reports.html` with three canned templates (Weekly SOC Summary, Incident Report, Detection Rule Performance) that render as printable HTML. Use `window.print()` for PDF export. Fortinet case-report analogue.
12. **Timeline view on incidents.** Replace the flat `actions` list on `/incidents/{id}` with a vertical timeline that interleaves audit events + notes + action results. FortiAnalyzer incident-analysis page analogue.
13. **UEBA-lite baseline per client IP.** On `/devices`, add a sparkline showing that IP's event rate vs a rolling-7-day baseline. Flag outliers on the page. All computable from `state.feed` + `state.history` without touching the pipeline.
14. **Integration configuration page.** New admin-only page `/integrations.html` that reads and writes `response_integrations.json` (configured/endpoint/env-var name for key). Clearly labels credentials as "env-only, never stored". FortiAnalyzer 8.0 connector-editor analogue.

### 3.3 P2 — nice-to-have / platform maturity

15. **Full chrome extraction** (soc/usecases/alerts → `chrome.js`). Pure refactor, no behaviour change.
16. **Dashboard builder** — drag-and-drop widget layout, persist per-user. This is a real sub-project.
17. **Scheduled reports** — cron-like recurring Report Builder output written to `dashboard/data/reports/`.
18. **Federated search** — index raw DNS query logs and expose `/api/search?q=...`. Likely requires an embedded SQLite FTS index.
19. **GenAI co-pilot** — summarise an alert, propose a next action, draft a note. Requires an API key, env-only. Best integrated as a right-rail widget in the alert Drawer. Fortinet Advisor analogue.
20. **Authentication + RBAC** — before any public-network deployment. Session cookies, bcrypted local users, role-to-endpoint matrix. Flip `authenticated: true` only once a real session is attached.
21. **SQLite-backed store** — when `audit_log.json` crosses ~10 k entries, migrate the Store to SQLite + WAL. Preserves atomicity under concurrent writes.
22. **Multi-tenant / MSSP view** — one dashboard, multiple customer namespaces. A real sub-project.

### How to sequence it

If a Week 7 is scoped, the highest-leverage week is: **P0 items 1, 2, 5, 7** (role-based landing + MITRE matrix + SOC metrics tiles). They surface analyst value with no new integrations and no pipeline changes. P0 items 3 and 4 (playbook triggers + evidence attachments) depend on `dashboard/data/` growing into a small filesystem — do them together.

A Week 8 could then be **P1 items 8, 9, 11, 12** (saved views + watchlists + report builder + incident timeline). After that the project has every pattern a FortiSOAR / FortiSIEM SOC dashboard advertises except the parts that need a real auth backend or external integrations.

---

## 4. References

- [FortiSOAR 7.3 — Dashboards, Templates, and Widgets](https://docs.fortinet.com/document/fortisoar/7.3.0/user-guide/207943)
- [FortiSOAR 7.4.0 Release Notes — New Features](https://docs.fortinet.com/document/fortisoar/7.4.0/release-notes/269885)
- [FortiSOAR product page](https://www.fortinet.com/uk/products/fortisoar)
- [FortiSIEM 7.5 — Working with Cases](https://docs.fortinet.com/document/fortisiem/7.5.0/user-guide/694475)
- [FortiAnalyzer 6.4.1 — FortiSoC administration](https://docs.fortinet.com/document/fortianalyzer/6.4.1/administration-guide/268882/fortisoc)
- [FortiAnalyzer 8.0 — New Features Guide (PDF)](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/e6cdee8a-32f6-11f1-b31d-02356ffb40d9/FortiAnalyzer-8.0-New_Features_Guide.pdf)
- [FortiGuard SOC Automation Service](https://www.fortiguard.com/services/security-automation-service)
- [Fortinet SecOps overview (Exclusive Networks)](https://www.exclusive-networks.com/ro/wp-content/uploads/sites/44/2024/08/Fortinet_SecOps.pdf)
- Internal: [`dashboard/docs/WEEK6_IMPLEMENTATION_REPORT.md`](../../dashboard/docs/WEEK6_IMPLEMENTATION_REPORT.md), [`dashboard/docs/SOC_DASHBOARD_ARCHITECTURE.md`](../../dashboard/docs/SOC_DASHBOARD_ARCHITECTURE.md), [`dashboard/docs/API_REFERENCE.md`](../../dashboard/docs/API_REFERENCE.md), [`dashboard/docs/NEXT_PHASE_ROADMAP.md`](../../dashboard/docs/NEXT_PHASE_ROADMAP.md)
