# Final Decision — Capstone Extension Plan

**Project:** DNS Traffic Anomaly Detection Using Hybrid ML Fusion (CADT, 2025–2026)
**Date:** 2026-10-14
**Scope of this file:** decisions on the four extension ideas (attack capture, Technitium→Wazuh/ELK, real-time automation, Telegram human-in-the-loop), merged with the earlier Improvement Blueprint.
**Revision 2:** added §7 (additional recommendations from Claude) and wired them into the roadmap, metrics and threat model.
**Status:** research-backed design. Items marked *(verify)* depend on your installed versions: test them in the lab with `wazuh-logtest` / a dry run before relying on them.

---

## 1. Decision summary

| # | Your idea | Verdict | Final form |
|---|-----------|---------|------------|
| 0 | *(from blueprint)* Trustworthy ML results | **Do first, non-negotiable** | Ground-truth labels, campaign splits, label-shuffle test, ablations |
| 1 | Upgrade attacks + capture them as JSON (with location) | **Adopt, with changes** | Two separate records: an *attacker-side manifest* (ground truth) and *defender-side telemetry* (what detectors see). Never mix them. |
| 2 | Technitium → Wazuh / ELK | **Adopt: use both, with distinct jobs** | ELK = visibility and hunting (already built). Wazuh = detection, alerting, case flow. |
| 3 | Real-time SIEM-style automation | **Adopt as "near-real-time"** | Streaming window aggregator + scorer daemon; measured detection latency |
| 4 | Telegram bot with human approval | **Adopt: strongest demo feature** | Separate approval gateway; allowlisted approvers; one-time callbacks; fail-closed; expiring blocks |
| + | Claude's additional ideas (§7) | **Adopt the MVP-tagged ones** | Dry-run mode, kill switch, evidence cards, feedback buttons, canary domains, ATT&CK coverage table, replay test, resolver hardening |

**Three corrections to the ideas as written** (details in §3):

1. The sample JSON is a **web login brute-force** event. That is a different detection domain from DNS. Keep DNS as the core of the capstone and use the web events as a *second telemetry source* that proves the SIEM pipeline. Don't build ML for it; Wazuh frequency rules are enough.
2. Your Phone Store logs in through **Firebase Auth**, so a brute-force attack would never hit your Nginx. You need a small lab login endpoint (e.g. `/api/v1/auth/login`) as the target.
3. In the sample, `action_taken: "blocked_ip"` is a **defender** field. It must not be written by the attack tool or visible to the model as a feature.

---

## 2. Final architecture

```
                         ATTACKER SIDE (lab only, isolated)
  attack.c · iodine/dnscat2/dns2tcp · hydra → lab login endpoint
        │  writes ──► attack_manifest.jsonl   (ground truth: campaign_id, tool, profile,
        │                                       start/end, source host, zone/location)
        │             ▲ NEVER read by detectors; used only for labels + evaluation
        ▼
┌──────────────────────────── DEFENDER SIDE ─────────────────────────────┐
│ Technitium (DNS logs) ──┐                                              │
│ Nginx / lab login (JSON)┼─► Filebeat ─► Logstash ─► Elasticsearch/Kibana│  visibility
│                         │                                              │
│                         └─► Normalizer (ECS fields) ─► Window aggregator│
│                               (client × registered domain × 1/5/15 min)│
│                                        │                               │
│                    rules · robust stats · Path A · Path B · beaconing   │
│                                        ▼                               │
│                    Fusion (agreement severity) + calibration + allowlist│
│                                        ▼                               │
│                    dns_ml_alerts.jsonl (NDJSON, ECS-style)              │
└────────────────────────────────────────┬───────────────────────────────┘
                                         ▼
        Wazuh agent (localfile json) ─► Wazuh manager (custom rules, frequency rules)
                                         ▼
                 integratord custom-telegram  ──►  Telegram: notification (one-way)
                                         ▼
                 Approval Gateway (separate service, long-polling bot)
                    PENDING ─► human taps Approve/Reject ─► APPROVED ─► EXECUTED
                                         ▼
                 Responder: Technitium block API (least-privilege token, auto-expiry)
                            · optional Wazuh active response (web lab only)
                                         ▼
                 Audit log ─► analyst verdict ─► labeled data ─► next model (shadow first)
```

---

## 3. Idea 1 — Upgraded attacks and capture

### 3.1 Why two separate records

| Record | Who writes it | Who may read it | Purpose |
|--------|---------------|-----------------|---------|
| **Attack manifest** | The attack tool/wrapper | Training-label builder and evaluator only | Ground truth: this window really was an attack |
| **Defender telemetry** | DNS server, Nginx, normalizer | Detectors, SIEM | What a real SOC would actually see |

If the detector can see the manifest (or fields derived from it), the evaluation is circular again. This is the same leakage the blueprint flags as G1–G3.

### 3.2 Attack manifest (one line per run)

```json
{
  "campaign_id": "C-2026-10-14-007",
  "attack_family": "dns_tunneling",
  "tool": "dnscat2",
  "profile": "low_and_slow",
  "start": "2026-10-14T22:00:00Z",
  "end": "2026-10-14T22:30:00Z",
  "source_host": "attacker-02",
  "source_ip": "192.168.18.52",
  "location": {"zone": "lab-attacker-vlan", "site": "CADT-lab", "geo": null},
  "target": {"service": "technitium-dns", "ip": "192.168.18.143", "domain": "lab.local"},
  "operator": "student-a",
  "split": "test"
}
```

Rules:

- **Rotate source hosts and IPs**; at least one campaign comes from a host never used in training.
- `split` is assigned **per campaign**, never per row.
- **"Location" in a lab:** use `zone`/`site`/`asset` (e.g. VLAN, room, host role). That is what a real SOC uses for private addresses. GeoIP only makes sense for public IPs, so if you want a map in Kibana, use a GeoLite2 database for the demo and check its licence terms *(verify)*. Simulated "foreign" geo values should be marked `"simulated": true` so nobody mistakes them for real attribution.

### 3.3 Defender telemetry for web brute force (adapted from your sample)

Keep your structure, but change three things: drop the defender-only fields from attacker output, use ECS-style names so Elastic/Wazuh need no custom mapping, and name the log source honestly.

```json
{
  "@timestamp": "2026-10-14T22:15:31.402Z",
  "log_source": "nginx_access",
  "event": {"kind": "event", "category": "authentication", "outcome": "failure"},
  "source": {"ip": "192.168.18.52", "port": 49212},
  "destination": {"ip": "192.168.18.143", "port": 443},
  "http": {"request": {"method": "POST"}, "response": {"status_code": 401}},
  "url": {"path": "/api/v1/auth/login"},
  "user_agent": {"original": "Mozilla/5.0 (Hydra/BruteForce)"},
  "user": {"name": "admin"},
  "host": {"name": "lab-web-01"}
}
```

Notes:

- `log_source` is `nginx_access` unless you actually deploy a WAF (ModSecurity + OWASP CRS, or Coraza) *(verify)*. Claiming "web_application_firewall" without one is a credibility risk at the defense.
- **Never record or log passwords.** `user.name` is enough.
- **User-Agent and username are attacker-controlled.** Don't use "Hydra" in the UA as the detection (any attacker changes it). Detect on behavior: failures per source per window, many usernames per source, one username from many sources (spraying).
- Defender decisions (`action_taken`, `blocked_ip`) are written **later**, by the responder, into the audit log, not into the original event.

### 3.4 Attack upgrades (priority order)

| Priority | Upgrade | Why |
|----------|---------|-----|
| P1 | Real tunnels: iodine, dnscat2, dns2tcp with light, heavy, low-and-slow profiles and TXT/NULL/CNAME variants | Your project claims tunneling detection but `attack.c` only floods |
| P1 | Per-run manifest written automatically by a wrapper script | Makes ground-truth labels free |
| P2 | Beaconing script (fixed and jittered interval) | Gives Path B a non-flood test |
| P2 | Lab login endpoint + Hydra/custom script | Feeds the web telemetry pipeline |
| P3 | Evasion profiles: length/entropy matching, slow rate, distribution across several IPs | Honest robustness test |

Ethics: run only in the isolated lab, with permission, and state it in the paper.

---

## 4. Idea 2 — Technitium → Wazuh and ELK

### 4.1 Decision: one stack for visibility, one for detection

You already have Technitium → Filebeat → Logstash → Elasticsearch/Kibana working. Don't throw it away.

| Layer | Tool | Job |
|-------|------|-----|
| Visibility / hunting | **ELK (existing)** | Raw DNS and web logs, Kibana dashboards (top domains, NXDOMAIN rate, unique subdomains per domain, alerts overlay) |
| Detection / alerting | **Wazuh** | Ingest your engine's NDJSON alerts, custom rules, frequency rules for web brute force, notifications, optional active response |

Resource note: running ELK and Wazuh (manager + indexer + dashboard) together is memory-heavy. If the lab VM is small, give Wazuh its own VM, or keep only Kibana for dashboards and drop extra ELK components.

### 4.2 What goes where

- **Raw Technitium lines → ELK only.** Reuse your existing grok pattern. Don't write Wazuh decoders for raw DNS text; it's extra work with no benefit.
- **Your engine's normalized NDJSON alerts → Wazuh** (`localfile`, `log_format` json). Decoded events only become alerts if a custom rule matches them, and the rule level must clear the alert threshold.
- **Web auth events (Nginx JSON) → both**: ELK for dashboards, Wazuh for frequency rules.

### 4.3 Wazuh rules (starting point, test with `wazuh-logtest`)

```xml
<group name="dns_ml,dns,">
  <rule id="100900" level="7">
    <decoded_as>json</decoded_as>
    <field name="source">dns_ml_engine</field>
    <description>DNS ML engine: $(rule_name) client=$(client_ip) domain=$(domain)</description>
  </rule>
  <rule id="100901" level="12">
    <if_sid>100900</if_sid>
    <field name="severity">^High$</field>
    <description>DNS ML HIGH: $(rule_name) client=$(client_ip) domain=$(domain) score=$(ml_score)</description>
    <mitre><id>T1572</id></mitre>
  </rule>
</group>

<group name="web,authentication_failures,">
  <rule id="100910" level="3">
    <decoded_as>json</decoded_as>
    <field name="log_source">nginx_access</field>
    <field name="http.response.status_code">^401$</field>
    <description>Lab login failure</description>
  </rule>
  <!-- 5 failures from the same source in 60 s -->
  <rule id="100911" level="10" frequency="5" timeframe="60">
    <if_matched_sid>100910</if_matched_sid>
    <same_field>source.ip</same_field>
    <description>Web brute force: repeated login failures from same source</description>
    <mitre><id>T1110</id></mitre>
  </rule>
</group>
```

Field-name handling for nested JSON, `same_field`, and rule IDs differ by Wazuh version, so verify each rule with `wazuh-logtest` before restarting the manager *(verify)*. Pick IDs in the custom range (100000+) that you don't already use.

### 4.4 Dashboards to build (visible, defense-friendly)

1. DNS overview: queries/min, NXDOMAIN ratio, top clients, top registered domains.
2. Tunneling view: unique subdomains per registered domain, TXT/NULL share, label entropy.
3. Alert timeline coloured by severity, with the attack manifest windows overlaid (**evaluation dashboard only**, kept out of detector inputs).
4. Web login failures per source and per minute.
5. SOC health: alerts/day, approval latency, pending approvals.

---

## 5. Idea 3 — Near-real-time automation

### 5.1 Be precise about "real time"

Your current flow is batch (`Run_Pipeline.sh`). For the capstone, say **near-real-time**: events are windowed, and an alert fires within a measured delay after a window closes. That's honest, defensible, and measurable. True per-packet inline detection is a different project.

### 5.2 Design

1. **Tailer**: follows the Technitium log (and the Nginx JSON log), handles rotation and restarts without duplicating events (store offset).
2. **Normalizer**: Technitium/Nginx lines → ECS-style dict. Malformed lines are counted and dropped, never crash the loop.
3. **Window aggregator**: sliding windows per (client, registered domain) at 1 / 5 / 15 min; features from the blueprint (unique names, TXT/NULL ratio, NX ratio, label length/entropy, inter-arrival regularity).
4. **Scorer**: rules + robust stats (median/MAD or EWMA) + Path A/B on window features. Models loaded once, hash-verified.
5. **Fusion**: agreement-based severity. Both ML paths or ML + rule agreement → High; single signal → Medium/Low. Allowlist (your own domains, popular domains) always wins.
6. **Emitter**: append NDJSON, de-duplicate per (client, domain, rule) with a cooldown so one attack doesn't produce 500 alerts.
7. **Runs as a `systemd` service** (or a Compose service) with a health endpoint/heartbeat; a missing heartbeat is itself an alert.

Don't introduce Kafka/Flink for this scale. A single-process Python loop with bounded memory is enough for a lab and easier to explain.

### 5.3 Service-level targets (measure and report them)

| Metric | Suggested target (tune to your lab) |
|--------|-------------------------------------|
| Detection latency (first malicious query → alert in Wazuh) | ≤ 2 × window length |
| Alert → Telegram notification | ≤ 10 s |
| Engine CPU/memory | Bounded, reported |
| False positives/day on a benign-only day | Set a target before the test, then report the result |

---

## 6. Idea 4 — Telegram with human-in-the-loop approval

### 6.1 Two components with different jobs

| Component | Direction | Purpose |
|-----------|-----------|---------|
| **Notifier**: Wazuh `integratord` custom script (`custom-telegram`) | Wazuh → Telegram (one-way) | Sends alert text. Script name must start with `custom-`, referenced in an `<integration>` block with a `level` filter and JSON alert format; the script receives the alert file path. |
| **Approval gateway**: standalone service | Telegram ↔ gateway ↔ responder | Sends inline-keyboard buttons, receives taps, runs the approved action |

Keep them separate. The notifier only talks; the gateway can act, so it is the component to harden.

### 6.2 Use long polling, not a public webhook

The gateway calls Telegram outbound (`getUpdates`), so the lab needs no inbound port or public URL. Request only the update types you use: `allowed_updates = ["callback_query"]` (plus `message` if you add commands). Always call `answerCallbackQuery` after a tap so the client stops showing a spinner.

### 6.3 Approval state machine

```
PENDING ──approve──► APPROVED ──execute ok──► EXECUTED ──expiry──► REVERTED
   │                     └──execute fail──► FAILED
   ├──reject───► REJECTED
   └──timeout──► EXPIRED   (fail-closed: nothing happens)
```

Each transition is written to the audit log with timestamp, approver Telegram user ID, alert ID, model version and action.

### 6.4 Message design

```
🚨 DNS TUNNELING — HIGH   (score 0.91, 2 detectors agree)
Client:  10.0.0.23   (zone: lab-clients)
Domain:  tunnel[.]example      ← defanged
Evidence: 398 unique names / 5 min · TXT 92% · entropy 4.7
Proposed action: block domain tunnel[.]example for 24 h
Expires: 10 min · ID: a7f3c2

[ ✅ Approve block ]  [ ❌ Reject ]  [ 🔍 More detail ]
```

- `callback_data` carries only a **short random nonce** plus a verb (Telegram limits callback data to 64 bytes). The alert and the exact action are stored server-side under that nonce. The tap can never choose *what* gets blocked, it only approves a pre-built, pre-validated action.
- Defang domains (`tunnel[.]example`) and **escape/strip markup** before sending. DNS names, usernames and user-agents are attacker-controlled text and can contain formatting characters. Truncate long values.
- Never include passwords, tokens or full payloads.

### 6.5 Security rules for the gateway (non-negotiable)

1. **Authorize by Telegram user ID, not chat ID.** Check `callback_query.from.id` against an allowlist of approvers. Ignore everything else silently. Use a private chat or a locked-down group.
2. **One-time nonces.** After a decision, the nonce is dead. Replayed or double-tapped callbacks do nothing.
3. **Expiry and fail-closed.** Unanswered requests expire; expiry means no action.
4. **Only allow-listed actions** (enum): `request_block_domain`, `add_to_watchlist`, `isolate_host_review`. Anything else is rejected by code.
5. **Validate before executing:** domain syntax, not on the allowlist (own domains, root domains, critical SaaS), not already blocked, rate limit on approvals per hour.
6. **Tier by impact:** domain block → one approver. Host isolation, or a block on a broad parent domain → two approvers or "review only" (ticket, no automatic effect).
7. **Secrets:** bot token and Technitium token in `/etc/dns-ml/secrets.env`, `chmod 600`, owned by the service user, never in CLI args, Compose files or git. If the token leaks, revoke it via BotFather.
8. **Assume Telegram is not a confidential channel for bots.** Redact or avoid internal details beyond what a lab needs; in a real deployment, hold sensitive context behind an internal link.
9. **Notification hygiene:** de-duplicate, rate-limit, and send a digest for Low/Medium. Alert fatigue defeats human-in-the-loop.

### 6.6 Responder: Technitium blocking

- Endpoint to add a blocked zone takes a `domain` and needs a session token with **Blocked: Modify** permission. Create a **dedicated API user** limited to that section, not an admin token.
- **Path discrepancy to check:** sources show both `/api/blocked/add` and `/api/zones/blocked/add`, and older names like `/api/blockZone` are marked obsolete. Confirm the exact path on your installed version in its API docs or Swagger *(verify)*.
- The documented call uses **GET with the token in the query string**, so the token can leak into logs and proxies. Keep it on `localhost`/an internal network, don't log full URLs, and prefer a POST variant if your version supports it *(verify)*.
- **Blocked zones don't expire by themselves.** The gateway must schedule the unblock (store `expires_at`, run a reaper job, log the revert).
- Always check the allowlist first, then add the block, then verify with a test query (`NXDOMAIN`/blocked response) and report back in the Telegram thread.

### 6.7 Wazuh active response: where it fits

Wazuh active response can run a script on an alert, and **stateful** responses revert after a `<timeout>`. For the web brute-force demo it's a valid mechanism (a frequency rule, then `firewall-drop` with a short timeout).

Decision for the capstone:

- **DNS-related blocks: HITL only** (via the gateway).
- **Web brute-force: HITL by default.** If you want to demo automation too, enable `firewall-drop` only for the lab login endpoint, with a short timeout (minutes), a frequency threshold (e.g. ≥5 failures in 60 s), and an allowlist that includes the gateway, analyst and DNS server. Label it clearly as the *deterministic, reversible, low-impact* exception.

### 6.8 Don't block the wrong thing

- **Spoofed sources:** for amplification and reflection-style attacks the source IP is often forged. Blocking it can cut off an innocent host. Prefer domain-level controls or rate limiting.
- **Tunneling:** block the **domain**, then investigate the **host**. Host isolation is a human decision.
- **Self-lockout:** the allowlist must contain the DNS server, gateway, analyst workstation and the Telegram/API endpoints the system depends on.

---

## 7. Additional ideas (Claude's recommendations)

These come from my own review of the design, not from your four ideas. Each one is small, fits the existing architecture, and either makes a claim more defensible or makes the human-in-the-loop safer. **MVP** means I recommend it inside Phases 0–5; **Optional** means do it only if time remains.

| ID | Idea | Why it matters | Effort | Phase | Tag |
|----|------|----------------|--------|-------|-----|
| A1 | Dry-run ("would-block") mode + kill switch | Proves the response loop is safe before it can hurt anything | S | 5 | **MVP** |
| A2 | Verdict buttons that create labels | Turns every alert into training data and fixes circular labels over time | S | 5 | **MVP** |
| A3 | Canary (honey) domains | Near-zero false-positive detection that needs no ML | S | 3 | **MVP** |
| A4 | Post-block follow-up (and optional sinkhole) | Finds hosts that are still calling a blocked domain | S–M | 5 / 9 | MVP-lite |
| A5 | ATT&CK coverage table (purple-team matrix) | Gives an honest, checkable coverage claim, including gaps | S | 3 | **MVP** |
| A6 | Detection-as-code + replay test | Stops silent regressions; one config file, one expected-alerts file | S–M | 4 | MVP-lite |
| A7 | Per-host risk score (risk-based alerting) | Fewer, better alerts; one Telegram case per host | M | 9 | Optional |
| A8 | Evidence card in every approval request | Human approval is only as good as the information shown | S | 5 | **MVP** |
| A9 | Auto-generated incident report | Ready-made figures and timelines for the paper and the demo | S | 9 | Optional |
| A10 | Resolver hardening before detection | Prevention is cheaper than detection, and gives a measurable before/after | S | 1 | **MVP** |
| A11 | Lab hygiene: NTP, privacy, chaos tests | Wrong clocks silently corrupt labels and latency numbers | S | 0 / 4 | **MVP** |
| A12 | Scripted demo with a fallback | A defense is a live demo; plan for it to fail once | S | 9 | **MVP** |

### A1. Dry-run mode and kill switch

- Run the **entire** approval flow for the first one to two weeks of testing, but make the responder log `"would_block": "tunnel.example"` instead of calling Technitium.
- Approvers still tap Approve/Reject; afterwards each "would have blocked" is marked correct or wrong. This gives you the **wrong-action rate** before any real enforcement exists.
- Turn enforcement on only when the wrong-action rate is under a threshold you set in advance (write it down before testing).
- Kill switch: approvers can send `/pause`, `/resume` and `/status` to the bot; a global flag in the secrets/config file does the same from the host.
- **Circuit breaker:** if more than N approved blocks happen per hour, or any block hits a parent domain, the gateway auto-pauses and notifies. A runaway loop then stops itself.

### A2. Verdict buttons that create labels

After an action (or after a notification you decide to ignore), offer a second row of buttons:

```
[ ✔ True positive ]  [ ✖ False positive ]  [ ? Unsure ]
reason (for FP): cdn_telemetry · av_lookup · test_traffic · misconfig · other
```

- Verdicts append to `feedback.jsonl` with alert ID, approver ID, model version and reason code.
- They feed a **candidate** training set, never an automatic retrain. Promotion still goes through shadow mode and manual approval.
- Repeated false positives for the same registered domain become an **allowlist suggestion**, which a human must approve.
- Poisoning guard: only allowlisted approvers can submit verdicts, one verdict per alert per approver, and a sample of verdicts is re-audited.

### A3. Canary (honey) domains

- Add a few records to your `lab.local` zone that **no legitimate client or web page ever uses**, with plausible names such as `vpn-backup.lab.local` or `hr-db.lab.local`.
- Any query for them is an alert: reconnaissance, malware enumerating names, or a curious insider. Rule: `qname in canary_list` and `severity = High`.
- It needs no training data, is easy to explain, and makes a strong live demo ("watch this scan trip the canary").
- Caveats: security scanners and some resolvers prefetch or enumerate names, so tag the source (attack run vs real) and keep the canaries out of the Phone Store pages and public docs.

### A4. Post-block follow-up (and optional sinkhole)

- **Minimum:** after a domain is blocked, count how many clients keep querying it. Those clients are the likely infected or tunneling hosts. Send them to a "host review" queue (still human-decided).
- **Optional:** if your Technitium version supports a custom blocking response, point blocked names to a lab sinkhole host that only logs requests *(verify)*. You then get a list of affected hosts with timestamps instead of bare NXDOMAIN.
- This also fixes a quiet flaw in "block the domain": it ends the symptom but tells you nothing about which machine was talking.

### A5. ATT&CK coverage table (purple-team matrix)

Create one table that links every attack campaign to a technique, an expected detector and the observed result:

| Technique | Campaign family | Expected detector | Detected? | Latency | Notes |
|-----------|-----------------|-------------------|-----------|---------|-------|
| T1572 Protocol Tunneling | dnscat2 / iodine | Path A + window rules | measured | measured | |
| T1568 Dynamic Resolution | DGA-style generator | Path B + NXDOMAIN ratio | measured | measured | |
| T1048 Exfil Over Alt Protocol | dns2tcp heavy | volume + record-type mix | measured | measured | |
| T1110 Brute Force | Hydra on lab login | Wazuh rule 100911 | measured | measured | |
| T1071.004 DNS C2 / beaconing | beacon script | regularity detector | measured | measured | |
| Encrypted DNS (DoH) | browser/curl to DoH resolver | **none yet** | no | n/a | listed as a known gap |

- Showing a **known gap** honestly (DoH) is stronger at a defense than claiming full coverage.
- Optional: export the table as an ATT&CK Navigator layer for a heat-map slide *(verify the layer format version you use)*.

### A6. Detection-as-code and replay test

Minimal repo layout:

```
detections/
  config.yaml            # thresholds, weights, windows, allowlist, canary list (one versioned file)
replays/
  tunnel_light.jsonl     # small input log
  tunnel_light.expected.json   # alerts that MUST appear (rule, severity, domain)
  benign_day.jsonl
  benign_day.expected.json     # expected: zero High alerts
tests/
  test_replay.py         # runs engine on each replay, compares to expected
```

- Every alert carries `config_version` (hash of `config.yaml`) and `model_version`, so any alert can be reproduced later.
- Run the replay test before every demo and every threshold change. If the alert set changes, you see it immediately instead of discovering it live.

### A7. Per-host risk score (optional)

Combine all signals per host instead of alerting on each one:

```
risk(host) = Σ  weight(signal) × confidence × exp(-Δt / τ)
```

- Signals: DNS ML alert, tunneling window rule, canary hit, web brute-force source, repeated NXDOMAIN spikes.
- Decay (`τ` of a few hours) lets old noise fade. Telegram receives **one case per host** when risk crosses a threshold, with the contributing signals listed.
- Several Low alerts on one machine then escalate, which is how real attacks usually appear.

### A8. Evidence card in every approval request

Show the approver *why*, not just *what*:

- Top 3 contributing features as **observed vs baseline**, e.g. `unique names / 5 min: 398 (this client's median: 6)`.
- Which detectors agreed, and the calibrated score.
- A **deep link** to a pre-filtered Kibana view (client + domain + time range).
- First-seen time of the domain and whether it is in the popularity allowlist.
- **Approval fatigue check:** occasionally inject a clearly benign synthetic request into the queue. If someone approves it, flag it and review the process. Also require a reject reason code so rejecting is as deliberate as approving.

### A9. Auto-generated incident report (optional)

After each approved action, generate a one-page markdown file: timeline (first malicious query, alert, notification, approval, block, revert), evidence card, approver, model and config version, and outcome. These files double as figures for the paper and as proof of the audit trail.

### A10. Resolver hardening before detection

Do these cheap preventive controls first, then measure detection on top. Check each setting name in your Technitium version *(verify)*:

- Restrict query types you don't need (NULL, ANY) or limit their response size.
- Per-client rate limiting and response rate limiting.
- No open recursion: only lab subnets may query.
- Block or redirect DoH to known resolvers at the egress firewall (also narrows the DoH gap).
- Run the attack suite **before and after** hardening and report both. "Hardening cut attack volume by X% and detection still caught the rest" is a clear result.

### A11. Lab hygiene

- **Time sync:** all hosts (DNS server, attacker VMs, Wazuh, gateway) use NTP. Clock skew shifts attack windows, corrupts labels and breaks latency measurements without any visible error.
- **Privacy:** DNS logs reveal browsing behavior. Keep retention short, and pseudonymize client IPs (stable hash) in screenshots, datasets you share and the paper. Say this in the ethics section.
- **Chaos tests:** stop Filebeat, the Wazuh agent or the engine on purpose and confirm the heartbeat or "no data" alert fires. Detection that silently stops is worse than none.

### A12. Scripted demo with a fallback

| Step | Action | Shows |
|------|--------|-------|
| 1 | Start on a quiet Kibana dashboard | Baseline |
| 2 | Trip a canary domain | Instant, explainable detection (A3) |
| 3 | Launch a light dnscat2 run from the unseen attacker host | Domain-window detection |
| 4 | Telegram message arrives with evidence card | Real-time alerting (A8) |
| 5 | Approve; show the block, the test query, the expiry | Human-in-the-loop (A1 off for the demo) |
| 6 | Show a non-approver tap being ignored | Safety (§6.5) |
| 7 | Show the coverage table with its known gap | Honesty (A5) |

- Fixed random seeds and a one-command reset script so the demo repeats exactly.
- Keep a **pre-recorded screen capture** of the same run as a fallback if the network or a service fails.

---

## 8. Threat model of the pipeline itself

| Threat | Example | Mitigation |
|--------|---------|------------|
| Log injection | Attacker puts JSON or markup in username/UA/qname | Parse structured fields only; escape on output; never `eval`; strict schema |
| Alert flooding | Attacker triggers thousands of alerts to bury a real one or spam Telegram | Cooldown/dedup, per-entity grouping, digest messages, rate limit |
| Approval hijack | Stolen bot token, or someone else in the chat taps | User-ID allowlist, one-time nonces, token in 600-perm file, revoke on suspicion |
| Callback tampering/replay | Forged or repeated `callback_data` | Opaque nonce, server-side action store, state machine |
| Wrong-target block | Allowlisted/critical domain or spoofed IP | Allowlist wins, validation, human review, expiry |
| Model poisoning | Attacker shapes traffic that later becomes training data | Candidate model → frozen test → shadow mode → manual promotion; rollback |
| Model supply chain | Tampered pickle | SHA256 check against the registry (ideally signed) before load |
| Pipeline blind spot | DoH/DoT bypasses DNS logs | Detect/redirect DoH at egress; document as a limitation if not covered |
| Silent failure | Engine or Wazuh agent stops | Heartbeat alert; "no data" alert; chaos tests (A11) |
| Approval fatigue / rubber-stamping | Approver taps Approve on everything | Evidence card, required reject reasons, injected benign test requests, digest for Low/Medium (A8) |
| Runaway automation | Bug or attack causes many blocks | Circuit breaker, `/pause` kill switch, dry-run first (A1) |
| Privacy leak | Client IPs and browsing visible in reports/screenshots | Pseudonymize, short retention, state it in the ethics section (A11) |

---

## 9. Final roadmap

Do the phases in order. **If time runs short, everything below the cut line becomes "future work."**

| Phase | Work | Effort | Acceptance test |
|-------|------|--------|-----------------|
| **0. Foundation** | Attack wrapper writes the manifest; ground-truth labels; remove IP/port and rule-overlap features; campaign/time splits; label-shuffle test; NTP on all hosts (A11) | L | Shuffle test ≈ chance; manifest exists for every run |
| **1. Real attacks** | iodine/dnscat2 profiles; beaconing script; lab login endpoint + brute-force script; resolver hardening baseline, measured before/after (A10) | M | Each family produces labeled campaigns from ≥2 source hosts |
| **2. Window detection** | Domain-level windows; robust stats; agreement-based severity; calibrated scores | M | Benign-only day within false-positive target; held-out campaign/attack-type results reported |
| **3. Visibility + SIEM** | Technitium/Nginx → ELK dashboards; NDJSON → Wazuh with rules from §4.3; canary domains (A3); ATT&CK coverage table (A5) | M | Replay a known attack: alert visible in Wazuh and Kibana with correct fields and MITRE tag |
| **4. Near-real-time engine** | Tailer + aggregator + scorer as a service; heartbeat; config file + replay test (A6) | M | Measured latency table (§5.3); survives log rotation and restart without duplicates |
| **5. Telegram HITL** | Notifier + approval gateway + Technitium responder with expiry + audit log; evidence card (A8); dry-run mode, kill switch, circuit breaker (A1); verdict buttons (A2); post-block follow-up (A4) | M | Approve works end-to-end; reject/timeout does nothing; replay and non-approver taps are ignored; block auto-reverts; dry-run logs "would block" with no change; `/pause` stops all actions |
| ─ ─ ─ ─ ─ **MVP CUT LINE** ─ ─ ─ ─ ─ | | | |
| 6. Hardening | Model hash/signature, shadow-mode promotion, DoH visibility, CI replay tests | M | Tampered model refused at load |
| 7. Optional LLM triage | Read-only, schema-bound summarizer (see blueprint §6) | M–L | Prompt-injection test passes: output stays in schema, no actions |
| 8. Cortex/TheHive/MISP | Analyzer wrapper, case creation, IOC push | M | Analyst can score a domain from a case |
| 9. Optional polish | Per-host risk score (A7), auto incident reports (A9), sinkhole (A4), scripted demo + fallback (A12; do the demo script even if the rest is cut) | S–M | Demo runs from one command; fallback recording exists |

Minimum credible capstone = **Phases 0–5**. Phase 0 is the one that makes every later number believable.

---

## 10. Metrics to report

| Metric | Why |
|--------|-----|
| PR-AUC, precision@top-N alerts | Better than accuracy for imbalanced data |
| Recall per attack family, including a held-out family | Shows generalization |
| False positives/day on benign-only data | Analyst burden |
| Time-to-detect and alert → Telegram latency | Real-time claim |
| Approval latency (notification → decision) and % expired | Human-in-the-loop usability |
| Wrong-action rate (blocks later reverted as incorrect), measured first in dry-run | Safety of the response loop |
| Canary hit rate and false positives (A3) | High-fidelity detection baseline |
| ATT&CK techniques covered / known gaps (A5) | Honest coverage claim |
| Approver verdicts per alert and time-to-verdict (A2) | Label supply and human workload |
| Score calibration (reliability curve) | Makes scores usable for triage |
| Engine CPU/memory under attack load | Feasibility |

Report **before vs after**: original pipeline (rule-derived labels, random split) versus the fixed one. The drop in headline F1, with an explanation, is itself a strong result.

---

## 11. Defense talking points

1. We assumed our own results could be wrong, and tested for it (label-shuffle, held-out campaign, ablations).
2. Detection works on **behavior over windows**, not single suspicious strings.
3. Ground truth and defender telemetry are **separated** so evaluation is honest.
4. The response loop is **human-approved, least-privilege, expiring and audited**; failure modes fail closed.
5. We treated the SOC pipeline as a target too (injection, flooding, token theft, replay).
6. Safety was measured before enforcement (dry-run) and can be stopped instantly (kill switch, circuit breaker).
7. Known limits are documented: lab scale, DoH/DoT blind spot, practitioner thresholds that need local tuning.

---

## 12. Open items to verify before building

- Technitium: exact block/allow API paths and permission names for your version; whether a POST form for blocking exists; log format and any built-in log export app.
- Wazuh: nested-field matching and `same_field` behavior for your version; `integratord` argument handling for your custom script; whether your agent can read the mounted Technitium/Nginx log paths (permissions).
- Telegram: bot privacy settings, group vs private chat, rate limits for your alert volume.
- Datasets/licences: GeoLite2 terms if you use GeoIP; public DNS exfiltration dataset licences.
- WAF: decide whether to add ModSecurity/Coraza; if not, label the source `nginx_access`.

---

## 13. Sources consulted

- Wazuh documentation: custom active response scripts; stateful vs stateless responses and the `<timeout>` option; blocking SSH brute force with active response; custom rules and `logtest`.
- Wazuh community threads: frequency-based custom rules (`frequency`/`timeframe`) layered on top of a base rule before triggering `firewall-drop`; `custom-` naming and `<integration>` block for Telegram.
- Wazuh Telegram integration guides (custom wrapper script plus Python script, tested by passing an alert JSON file).
- Telegram Bot API usage in client-library docs: `callback_query` updates, `allowed_updates`, and acknowledging callbacks with `answerCallbackQuery`.
- Technitium DNS Server API references (community client/MCP docs): blocked-zone add/list/import, **Blocked: Modify** permission, token via `login`/`createToken`, obsolete path names.
- Earlier blueprint references: Arp et al. *Dos and Don'ts of ML in Computer Security*; CIC-Bell-DNS-EXF-2021; BCCC-CIC-Bell-DNS-2024; OWASP LLM01 Prompt Injection.

Several of these are community or third-party summaries rather than vendor reference pages. Confirm anything you depend on against the official docs for your installed versions.