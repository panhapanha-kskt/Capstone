# Week 5 — SOC Dashboard Suite Progress

**Date:** 2026-11-08
**Scope:** `dashboard/` folder only. No detection, ML, or pipeline code was changed.

## Summary

The single-page live dashboard was extended into a multi-page SOC-style monitoring suite,
modeled on commercial SOC products (FortiCloud SOC-as-a-Service and FortiSOAR). All pages
are served by the same zero-dependency `dashboard/server.py` (Python standard library only)
and are driven by **one shared endpoint, `GET /api/state`**, polled every 3 seconds by the
SOC pages (`/soc`, `/usecases`, `/alerts`). The classic page `/` polls every 2 seconds.
Because demo mode and real mode both write into the same server state, every page works
identically with `--demo` data and with real pipeline results — no page contains
demo-specific logic.

## Pages

| Route | File | Description |
|---|---|---|
| `/` | `index.html` | Classic dashboard (existing). Untouched except an added **"SOC view"** button linking to `/soc`. |
| `/soc` | `soc.html` | **Monitoring Overview** (FortiCloud style). Sidebar navigation, 7-tile KPI summary strip (devices, domains, pipeline runs, queries, events, high severity, escalated), donut charts for Alerts by Severity / Status / SLA, Open Alerts by Category bars, plus three history charts: Average Log Rate, Log Collection Breakdown (stacked), Threat Detection Trend. All charts are hand-drawn SVG — no libraries. |
| `/usecases` | `usecases.html` | **Monitoring Use Cases**. Cyber Kill Chain stage circles (Reconnaissance → Action) with live detection-event counts; clicking a stage filters the table. One use case per detection rule, with MITRE techniques, dominant severity, detection source, a working monitoring on/off toggle (persisted in localStorage), exclusion flag, search, and pagination. IT / OT tabs (OT is empty — no OT sensors in this lab). |
| `/alerts` | `alerts.html` | **Alerts module** (FortiSOAR style), rebuilt as a **React 18 single-page app** (React + htm from CDN, no build step). Open Alerts By Severity pie with in-slice percentages, Alerts by Type horizontal bars (Open / Investigating), and a 13-column grid: ID, Priority Weight, Severity, Assigned To, Name, Source, Type, Status, Escalated, Assigned Date, Ack SLA, Response SLA, Created On. Per-column search filters, click-to-sort headers, row selection with select-all (the Execute button enables only with a selection), pagination, and a slide-in detail drawer showing the full alert record (client IP, domain, MITRE tactics/techniques, description). |

Pages cross-link through the sidebar (Monitoring Overview / Monitoring Use Cases /
Classic Dashboard / Alerts). Branding is the project's own ("Capstone Project"), not
Fortinet's — only the layout was cloned.

## Server changes (`dashboard/server.py`, all additive)

- Routes added for `/soc`, `/usecases`, `/alerts` (HTML is read per request, so page edits
  need no restart; **route changes do**).
- The `/api/state` feed now includes each alert's `rule_source`, used by the
  Detection Source / Source columns.

## Data mapping (threat-intel layer)

Derived client-side from the pipeline's real fields; applies equally to demo and real data:

| SOC field | Derivation |
|---|---|
| Status | new alert → **Open**; older + High → **Investigating**; otherwise **Closed** |
| Escalated | new **and** High → Yes |
| Priority Weight | High 8 / Medium 5 / Low 2, +1 if new |
| Ack / Response SLA | Open → *Awaiting Action* (Response: *In Progress* for Medium), else *Met* |
| Alert Type | from rule name: DNS Tunneling, NXDOMAIN Flood, Deep Subdomain, ML Detection, Statistical Anomaly, Other |
| Kill-chain stage | from MITRE tactics: Discovery → Reconnaissance; CommandAndControl → Command and Control; Exfiltration / Impact → Action; Execution → Exploitation; Persistence → Installation |

Alert counts are consistent across pages: the feed is capped at the newest 150 alerts,
and the SOC donuts count alerts older than the cap as Closed/Met so every page's total
equals `totals.alerts`.

### Monitoring Overview (`/soc`) uses different rules

*Added 2026-11-14 after an audit.* The table above describes the **Alerts page** (`/alerts`).
The Monitoring Overview derives some of the same fields differently, so the two pages can
show different numbers for "escalated" or "status":

| Field on `/soc` | Rule on `/soc` | Rule on `/alerts` |
|---|---|---|
| **Escalated** KPI tile | every new alert (`totals.new_alerts`, `soc.html` line 906) | new **and** High |
| **Alerts by Status** donut | Escalated = new · Confirmed = older High · In Progress = older Medium · Closed = the rest (`soc.html` lines 944–954) | Open / Investigating / Closed |
| **Alerts by SLA** donut | Met = the alert has a MITRE technique (`soc.html` lines 959–962) | Ack / Response SLA from the status |

One more detail on `/alerts`: **Response SLA** is *In Progress* for open Low alerts as well
as Medium ones (`alerts.html` line 334), not only for Medium as written above.

These are documented as they are; aligning `/soc` with `/alerts` (starting with the
Escalated tile) is left for the dashboard work. Since Week 6, alerts that an analyst has
touched use their **persisted** status on `/alerts` instead of these derived rules.

## How to run

```bash
# demo mode (no models/TensorFlow needed)
python dashboard/server.py --demo --port 9000

# real mode (where the pipeline works, e.g. Kali)
python dashboard/server.py --watch infra/technitium-elk/data/dns_logs --port 9000
```

Then open `http://127.0.0.1:9000` ( `/soc`, `/usecases`, `/alerts` ).

**Windows note:** ports 8000 and 8080 fall inside Windows reserved port ranges
(`WinError 10013`). Check with `netsh interface ipv4 show excludedportrange protocol=tcp`;
port 9000 is free. Restart the server after any `server.py` change.

## Known limitations / next steps

- `/alerts` loads React from cdnjs, so its first load needs internet (cached afterwards).
  The three JS files can be vendored into `dashboard/` for fully offline use.
- Status, SLA, and assignment are **derived**, not persisted — there is no ticketing
  backend. A small JSON store in the server would make status changes stick.
- OT Use Cases tab is intentionally empty; monitoring toggles are per-browser
  (localStorage) and do not yet filter the pipeline itself.
