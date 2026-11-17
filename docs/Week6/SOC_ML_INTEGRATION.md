# Connecting the ML detector to SOC tools

**DNS Traffic Anomaly Detection · 2026-11-17**

This document explains how the project's ML model reaches the SOC tools: the existing ELK stack in
`infra/technitium-elk`, any syslog-based SIEM (FortiSIEM, Wazuh, Splunk, QRadar) and SOAR tools. It
also explains how analyst verdicts go back to the model as training labels.

---

## 1. Data flow

```
Technitium DNS ──PushLogger / log files──► data/raw/*.log
                                             │
         dashboard/server.py runs the 4 pipeline steps on every change
                                             ▼
  features.extractor ─► fusion.bridge (Path A RF + Path B + LR fusion) ─► detection.engine ─► monitoring
                          ml_score_A / ml_score_B /                        rules 1–6, MITRE    PSI drift,
                          ml_combined_score / ml_confidence                tags                retrain flag
                                             │
                              week4_unified_alerts.json
                                             ▼
                     SOC dashboard (triage, verdicts, metrics)
                       │                 │                    │
           exporters.py: Elasticsearch   syslog CEF          webhook
                       ▼                 ▼                    ▼
                Kibana / Elastic   FortiSIEM, Wazuh,       SOAR, chat
                   Security        Splunk, QRadar          bridges
                                             │
                verdicts ─► /api/feedback/export ─► data/feedback/labels_*.csv ─► next retraining (manual)
```

Before this change the ML alerts stopped at the dashboard. Filebeat shipped only the **raw DNS logs**
into Elasticsearch (`technitium-dns-*`), so Kibana never saw a single ML detection.

## 2. What each alert carries

Every exported alert is one ECS document. The same fields appear in CEF and the webhook payload.

| Field | Source |
|---|---|
| `@timestamp` | DNS query time (`query_time`), so the document date is stable across pipeline runs |
| `event.id` | alert fingerprint `fp` (stable; also the Elasticsearch `_id`) |
| `event.severity` | Low 21 / Medium 47 / High 73 / Critical 99 |
| `rule.name`, `rule.ruleset` | detection engine rule and its source |
| `source.ip`, `dns.question.name`, `dns.question.registered_domain` | client and queried name |
| `threat.tactic.name`, `threat.technique.id` | MITRE ATT&CK tags from the engine |
| `dns_ml.score_a`, `score_b`, `combined`, `confidence`, `threat_score`, `fusion_method` | ML bridge output |
| `dns_ml.model_version` | hash of the deployed thresholds and training metadata (`/api/model`) |
| `soc.status`, `assigned_to`, `escalated`, `verdict` | analyst workflow from the dashboard |
| `tags` | `dns-tunnel-ml`, plus `demo` for synthetic demo alerts |

## 3. Elasticsearch and Kibana (existing `infra/technitium-elk` stack)

1. Start the stack: `cd infra/technitium-elk && docker compose up -d elasticsearch kibana`.
2. Enable the exporter in `dashboard/data/response_integrations.json`:
   ```json
   "elasticsearch": {"configured": true, "endpoint": "http://127.0.0.1:9200",
                     "index_prefix": "dns-ml-alerts", "api_key": null, "install_template": true}
   ```
   The file is re-read on every export, so no restart is needed.
3. The dashboard exports after every pipeline run and about 2 s after any analyst action. On first use
   it installs `infra/technitium-elk/kibana/dns-ml-alerts-template.json`, so `source.ip` is mapped as
   an IP, the scores as floats and the ATT&CK fields as keywords.
4. Check it: `curl -s 'http://127.0.0.1:9200/dns-ml-alerts-*/_count'`. Run the pipeline again and the
   count must not change: documents are overwritten by `_id = fp`, not duplicated.
5. Create the Kibana data view (once):
   ```bash
   curl -s -X POST http://127.0.0.1:5601/api/data_views/data_view -H 'kbn-xsrf: true' \
     -H 'Content-Type: application/json' \
     -d '{"data_view":{"title":"dns-ml-alerts-*","name":"DNS ML alerts","timeFieldName":"@timestamp"}}'
   ```
   Useful Discover / Lens views: `dns_ml.confidence : "HIGH" and soc.status : "Open"`; a breakdown by
   `threat.technique.id`; a join with `technitium-dns-*` on `source.ip` to see the raw queries behind
   an alert.

Past alerts (for example a Kali training run) can be pushed without the dashboard:
`python dashboard/exporters.py --alerts data/processed/week4_unified_alerts.json --target elasticsearch`.
`--print ecs` or `--print cef` shows the first three documents without sending anything.

**Security note:** the compose file runs Elasticsearch with `xpack.security.enabled=false`. Keep port
9200 on localhost. With security on, create an API key and set `api_key`; it is never shown by the
dashboard (`***`).

## 4. Syslog CEF (FortiSIEM, Wazuh, Splunk, QRadar, Graylog)

```json
"syslog_cef": {"configured": true, "host": "127.0.0.1", "port": 514, "proto": "udp"}
```

Each alert is one RFC 3164 syslog line (facility local4, severity from the alert) carrying CEF:

```
<163>Nov 17 20:31:02 host CEF:0|Capstone|DNSTunnelML|1.0|dnsml-1a2b3c4d|DNS Tunneling Detection|8|
  rt=… src=10.0.0.5 externalId=<fp> cat=CommandAndControl msg=… cs1Label=dnsQuery cs1=a1.evil.com
  cs2Label=mitreTechniques cs2=T1572 cs3Label=mlConfidence cs3=HIGH cs4Label=socStatus cs4=Open
  cfp1Label=mlCombinedScore cfp1=0.93 …
```

- **Wazuh:** add a `<remote><connection>syslog</connection><port>514</port><allowed-ips>…</allowed-ips></remote>`
  block to `ossec.conf`. The CEF decoder then exposes the extension keys for rules.
- **FortiSIEM / QRadar / Splunk:** add a CEF syslog source pointing at this host.

CEF cannot overwrite an earlier event, so an alert is re-sent only when its content changes (status,
verdict or scores). The dedupe state is kept in `dashboard/data/export_state.json`.

## 5. Webhook (SOAR, chat bridges)

```json
"webhook": {"configured": true, "url": "https://soar.example/hooks/dns-ml", "secret": "<shared secret>"}
```

The exporter POSTs `{"source":"capstone-dns-ml","count":n,"alerts":[<ECS docs>]}` in batches of up to
100. With `secret` set it adds `X-Signature-SHA256: hex(HMAC-SHA256(secret, body))`, so the receiver
can reject forged calls. Only `http` and `https` URLs are accepted. The URL can be changed only by
editing the file, never through the API, so a browser cannot redirect alerts elsewhere.

## 6. Feedback loop: analyst verdicts → training labels

1. In the Alerts drawer (Investigation tab), or as a bulk action, the analyst records a verdict:
   true positive, false positive, benign positive or duplicate, with an optional reason.
2. `GET /api/feedback/export?format=csv` (or `python scripts/export_feedback_labels.py`) produces one
   row per judged alert: its ML scores, `model_version` and `label` (1 attack, 0 benign, empty
   = duplicate).
3. Review the file, then add the rows you trust to the labelled data before the next
   `scripts/train_models.sh` run. False positives at high ML confidence are the most useful
   rows: they are exactly where the threshold drift in V3_EVALUATION_RESULTS.md shows up.
4. After retraining, `model_version` changes. The SOC Performance row and the feedback export show
   whether the false-positive rate dropped for the new version.

Retraining is deliberately **not** automatic. Analyst labels can be wrong, and a poisoned label set
would silently weaken the detector. A human reviews the export first.

## 7. Model visibility in the dashboard

| Where | What |
|---|---|
| Alerts drawer → ML tab | Path A, Path B and fusion scores against the deployed thresholds; confidence tier; model version; drift |
| Alerts drawer → Playbook tab | triage steps chosen by rule type and ML confidence (guidance only) |
| Pipeline Health | deployed model summary, max-PSI trend per run, exporter status and last errors |
| SOC Overview | MTTD / MTTA / MTTR, ack-SLA breaches, false-positive rate, ATT&CK tactic × technique heatmap |

## 8. Limits

- `models/` still holds the **autoencoder** Path B. `/api/model` reports it as such until
  `runs/v3_iforest` is promoted (waiting on mentor approval).
- MTTD here is pipeline latency (alert time − DNS query time), not attacker dwell time.
- Registered domain = last two labels; there is no public-suffix list, so `co.uk`-style names group
  too broadly.
- There is no login. The dashboard is meant for `127.0.0.1`. With `--host 0.0.0.0` it prints a warning,
  and every client name must be allowed with `--allow-host`.
