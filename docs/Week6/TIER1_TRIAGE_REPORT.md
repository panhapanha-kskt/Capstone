# Week 6 Report: Tier 1 SOC Triage Workbench

**DNS Traffic Anomaly Detection · session 2026-11-18**

The dashboard served every analyst the same raw alert grid. This report covers building a dedicated
**Tier 1 (L1) triage workbench** at `/triage`, following published SOC practice. The steps were: research,
a gap check against what already existed, a plan, and then the implementation.

Related: [WEEK6_SOC_HARDENING_REPORT.md](WEEK6_SOC_HARDENING_REPORT.md) (security, workflow and exporters,
2026-11-17) · [../../dashboard/docs/API_REFERENCE.md](../../dashboard/docs/API_REFERENCE.md) (endpoints and permission table)
· [../../dashboard/docs/TESTING_REPORT.md](../../dashboard/docs/TESTING_REPORT.md) section 5c.

---

## 1. Summary

- **Problem:** the real alert file has 2,410 alerts, all from one client (192.168.197.135), all under `*.lab.local`, and all stamped within 0.5 s (the pipeline run time). 2,209 of them are Z-score alerts with empty `details`. No Tier 1 analyst can triage that alert by alert.
- **Built:**
  - `/triage` groups alerts into **cases**: 3 cases for the real data, or 1,949 with per-domain grouping.
  - Each case has one-screen DNS evidence, an auto-evaluated DNS-tunnel checklist, an ML "why it fired" panel, pivots, and SLA countdowns.
  - Analysts claim a case, close it with a mandatory classification, or escalate it with a structured handover.
  - Role guardrails come from each analyst's tier, with **four-eyes approval** when Tier 1 closes a High/Critical case as a false positive.
  - Personal shift stats and an acknowledged shift handover.
- **Verdicts:** Sentinel-style classifications. False positives are split into "model logic" and "bad data", which gives the ML retraining loop better labels.
- **Tests:** 19 new tests (43 dashboard tests in total), all passing. The full workflow was run on the real alert file.

---

## 2. Research: what a Tier 1 tool must do

Sources: Microsoft Sentinel incident triage and roles documentation; Elastic Security alert management,
alert suppression and the investigation guide for "Potential DNS Tunneling via Long and Unique Subdomains";
Google SecOps cases and the Tier 1 persona; CrowdStrike Falcon detections; Palo Alto Cortex XSOAR close
reasons; Splunk ES roles and the "Suspicious DNS Traffic" analytic story; SigmaHQ DNS rules; Infoblox and
Unit 42 DNS-tunnelling research; the Tranco list paper (NDSS 2019); NIST SP 800-61r3 (2025); MITRE's
*11 Strategies of a World-Class Cybersecurity Operations Center*; and IDC 2021, Trend Micro 2021 and SANS 2025
alert-fatigue surveys.

- **The Tier 1 role:** monitor the queue, validate, enrich, scope, then close false and benign positives using runbooks or escalate. Containment and rule tuning belong to Tier 2 and above.
- **Workflow:** claim → validate → enrich → scope → classify → close with a reason, or escalate with a summary. A common time box is about 15 minutes, after which the analyst escalates.
- **Alert fatigue:** IDC found 45% of alerts are false positives and 35% of analysts ignore alerts when the queue fills. SANS 2025 has false positives as the top challenge for 73% of respondents. Grouping and deduplication are the main remedy.
- **Ranked must-haves:**
  1. A single prioritised queue with My queue and counts.
  2. One-click claim.
  3. Mandatory closure classification plus comment.
  4. An escalation form with required fields.
  5. One-screen DNS evidence.
  6. An embedded checklist with a done count.
  7. Enrichment (Tranco, WHOIS, reputation).
  8. An ML "why it fired" panel.
  9. Grouping by host and domain.
  10. SLA countdowns.
  11. A shared-IP (resolver/NAT) warning.
  12. Entity pivots.
  13. Role guardrails and four-eyes approval.
  14. A shift handover with acknowledgement.
  15. Personal shift stats.

## 3. Gap check (before → after)

| # | Must-have | Before (2026-11-17) | After |
|---|---|---|---|
| 1 | Queue + My queue + counts | partial | counts bar (My queue, Unassigned, SLA breached, Pending approval, by severity), filters, paging |
| 2 | One-click claim | missing | claim = acknowledge + assign every open member; visible owner; 409 on conflict |
| 3 | Mandatory classification + comment | 4 optional verdicts | 6 classes, comment ≥ 10 chars, required checklist items |
| 4 | Escalation form | one click | summary, evidence, checks done, hypothesis, recommended action (pre-filled from evidence) |
| 5 | DNS evidence | none for Z-score alerts | from the per-query feature file: counts, types, response codes, label lengths, encodings, 5-minute volume, timeline, longest names |
| 6 | Checklist | static text | 11 automatic checks + 2 required manual checks, done x/y |
| 7 | Enrichment | none | Tranco rank (local file), internal-zone and IP flags; optional VirusTotal / AbuseIPDB |
| 8 | ML "why" | scores only | per-model scores vs thresholds, signatures, top deviations from the client baseline |
| 9 | Grouping | none | host + detection type (default) or host + domain |
| 10 | SLA countdown | heuristic chip | ack and triage clocks per case, amber / red |
| 11 | Shared-IP warning | none | resolver / docker gateway / loopback / CGNAT flag + warning |
| 12 | Pivots | Related tab | other cases for the host, top domains, hosts querying the domain |
| 13 | Guardrails | none | tier permissions on every write; four-eyes; escalated cases are Tier 2's |
| 14 | Handover + ack | report only | handover dialog, Markdown download, acknowledgement in the audit log |
| 15 | Shift stats | none | claimed, closed, close requests, escalated, my median MTTA |

## 4. Design

### 4.1 Cases

- **Default grouping: host + detection type** (zscore / ml / nxdomain / heuristic). With alert storms like the real data this gives a handful of cases (3).
- **Alternative: host + domain apex.** The apex is the registered domain, with one extra label inside internal zones (`lab.local` by default, plus `.local`, `.lan`, `.internal`, `.corp`, `.home.arpa`). Without that, every lab alert would land in one case.
- **Status is derived** from the member alerts, so `/alerts`, metrics and exporters always agree.
- **Priority** is the highest severity among open members.
- **SLA clocks** start at the case's stored `first_seen_at`, because the pipeline re-stamps alert times on every run.

### 4.2 Checklist

The automatic checks follow Elastic's DNS-tunnel investigation guide and SigmaHQ thresholds:

| Check | What counts as present |
|---|---|
| Long labels | a label of 50+ characters |
| Volume | 25+ queries and 15+ distinct names in 5 minutes |
| Record types | TXT / NULL / CNAME / MX share above 10%, or 3+ NULL queries |
| Encoding | base32 / base64 / hex labels |
| Randomness | high entropy or random subdomains |
| NXDOMAIN | most responses are NXDOMAIN |
| ML agreement | both ML paths flag the traffic |
| Popularity | domain in the Tranco list (benign sign) |
| Benign look-alike | CDN / cloud / update keywords (benign sign) |
| Reputation | VirusTotal / AbuseIPDB result |
| Shared source | resolver / NAT / gateway / loopback (caution) |

Two manual checks are required before closing or escalating: "reviewed other cases for this host" and
"checked the asset owner or ticket". The page shows a **suggestion** (escalate / close / review) built from
these results. It is never applied automatically.

### 4.3 Guardrails

Each analyst's tier comes from the `role` field in `analysts.json`. Tier 1 can claim, work the checklist,
close Low and Medium cases, and escalate. Tier 1 cannot:

- close a High/Critical case as a false positive: a **close request** is created instead and waits for a Tier 2 analyst who is not the requester;
- suppress alerts;
- run incident response actions;
- change use-case preferences;
- reopen someone else's closed alert;
- work escalated cases.

**This is a workflow control, not security:** without a login, anyone can choose another actor. The UI and
API say so explicitly.

### 4.4 Performance and safety

- **Per-query file:** `week3_features_with_ml.json` (8,156 rows) is indexed once per file change, which takes about 0.1 s.
- **Evidence:** computed only for the visible queue page and for the open case, then cached.
- **Batched writes:** a case action writes the alert-management file once, plus one audit row (per-alert audit rows only for cases of 200 alerts or fewer).
- **Online enrichment:** runs in one background thread with rate limits. Request threads never wait for it, and internal names and private IPs are never sent out.

## 5. Using it

```bash
python3 dashboard/server.py --port 9000                       # real mode (pipeline runs on log changes)
python3 dashboard/server.py --no-initial-run --port 9000      # real mode, show the current results first
python3 dashboard/server.py --demo --port 9000                # demo data
```

Open `http://127.0.0.1:9000/triage` and work through these steps:

1. Pick who you are in **Acting as** (Tier 1 = SOC Analyst 1 or 2).
2. Open the top case (`j`) and **Claim** it (`c`).
3. Read Evidence, Checklist and ML. Tick the two manual checks.
4. Either **Close** it (`x`) with a classification and comment, or **Escalate** it (`e`); the escalation form is pre-filled.
5. For a High case closed as a false positive, switch to **Senior SOC Analyst** and use **Approvals** to approve or reject.
6. At the end of the shift, open **Shift handover**, download the Markdown, and acknowledge it.

**Configuration** lives in `dashboard/data/response_integrations.json` and is read live:

```json
"triage": {"internal_zones": ["lab.local"], "resolvers": ["10.0.0.53"], "default_group": "source",
           "tranco_path": "dashboard/data/tranco.csv", "tranco_top_n": 100000},
"enrichment": {"virustotal": {"enabled": false, "api_key": null, "ttl_hours": 24},
               "abuseipdb":  {"enabled": false, "api_key": null, "ttl_hours": 24}}
```

- **Tranco:** download the list manually from tranco-list.eu and save it as `dashboard/data/tranco.csv`. The format is `rank,domain`, and only the first `tranco_top_n` rows are loaded.
- **API keys:** they are never shown by the dashboard (`***`).

## 6. Verification

- **Automated:** `python3 -m pytest tests/test_dashboard_soc.py tests/test_dashboard_triage.py -q` → 43 passed (TESTING_REPORT 5c lists the cases).
- **Real alert file** (`--no-initial-run`, fresh data folder):
  - 3 cases in host + detection-type mode, 1,949 in host + domain mode; queue responses took 0.4–0.7 s.
  - The ML case shows encodings, NXDOMAIN, volume and ML agreement as present, and TXT/NULL and long labels as absent. The data is 8,154 A-record queries with labels of at most 44 characters.
  - Claim → checklist → close as `fp_model_logic` gave a 202 pending request. Tier 1 approval was refused with 403. Tier 2 approval closed all 200 member alerts with the verdict and approver recorded.
- **Not done:** the browser click-through. Chrome on Windows could not reach the WSL server in this session.

## 7. Limits and next steps

- **Lab data:** every lab domain is internal and every query is type A. Several checks therefore show "absent" or "no data", and Tranco / VirusTotal add nothing for `*.lab.local`. These checks are meant for real or public traffic.
- **"Why it fired":** the panel compares the case against the client's own baseline. It is context, not model attribution (no SHAP).
- **No login:** before any shared deployment, add authentication so the guardrails become real controls.
- **Next:**
  1. Browser click-through (record it in TESTING_REPORT 5c).
  2. A Tier 1 run on a fresh Kali capture with the `runs/v3_iforest` model.
  3. Collect verdicts and measure the false-positive rate per rule.
  4. Consider SHAP values for the Random Forest to replace the baseline-deviation panel.
