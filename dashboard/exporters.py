#!/usr/bin/env python3
"""
Push the ML pipeline's alerts to external SOC tools. Standard library only.

Targets (all off by default; enable in dashboard/data/response_integrations.json):
  elasticsearch  _bulk into <index_prefix>-YYYY.MM.dd, ECS field names, document _id = alert fp,
                 so re-running the pipeline or changing an alert's status overwrites, never duplicates.
                 Kibana / Elastic Security read it directly (infra/technitium-elk).
  syslog_cef     ArcSight CEF over syslog UDP/TCP: FortiSIEM, Wazuh, Splunk, QRadar, Graylog.
  webhook        JSON POST (optionally HMAC-SHA256 signed) for SOAR tools or chat bridges.

CEF and webhook receivers cannot overwrite, so each target only receives alerts whose exported
content changed since the last successful send (state kept in dashboard/data/export_state.json).

One-shot CLI (pushes an alerts file produced by the detection engine):
    python dashboard/exporters.py --alerts data/processed/week4_unified_alerts.json --target elasticsearch
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DEFAULTS = {
    "elasticsearch": {"configured": False, "endpoint": "http://127.0.0.1:9200",
                      "index_prefix": "dns-ml-alerts", "api_key": None, "install_template": True},
    "syslog_cef": {"configured": False, "host": "127.0.0.1", "port": 514, "proto": "udp"},
    "webhook": {"configured": False, "url": None, "secret": None},
}
SECRET_KEYS = ("api_key", "secret")
TARGETS = tuple(DEFAULTS)
SEV_NUM = {"Low": 21, "Medium": 47, "High": 73, "Critical": 99}      # ECS event.severity
CEF_SEV = {"Low": 3, "Medium": 5, "High": 8, "Critical": 10}
SYSLOG_SEV = {"Low": 5, "Medium": 4, "High": 3, "Critical": 2}       # notice / warning / error / critical
SYSLOG_FACILITY = 20                                                  # local4
HTTP_TIMEOUT = 10
BULK_CHUNK = 500
WEBHOOK_CHUNK = 100
STATE_CAP = 50000
TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "infra" / "technitium-elk" / "kibana" / "dns-ml-alerts-template.json"


# ──────────────────────────────────────────────────────────────
# Document building
# ──────────────────────────────────────────────────────────────
def _to_utc_iso(value):
    if value in (None, ""):
        return None
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()          # naive engine timestamps are local time
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _num(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f and f not in (float("inf"), float("-inf")) else None


def _valid_ip(v):
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return None


def _registered_domain(domain):
    labels = [l for l in str(domain or "").lower().rstrip(".").split(".") if l]
    return ".".join(labels[-2:]) if len(labels) >= 2 else None


def to_ecs(alert, fp, mgmt=None, model_version=None):
    """Map one detection-engine alert (+ analyst management record) to an ECS document."""
    d = alert.get("details") or {}
    mgmt = mgmt or {}
    sev = alert.get("severity") or "Medium"
    event_time = _to_utc_iso(alert.get("query_time")) or _to_utc_iso(alert.get("timestamp"))
    domain = alert.get("domain")
    if str(domain or "").strip().lower() in ("", "n/a", "unknown", "multiple", "none"):
        domain = None    # engine placeholders for aggregate rules (e.g. NXDOMAIN bursts)
    doc = {
        "@timestamp": event_time or datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "event": {"kind": "alert", "category": ["network", "intrusion_detection"], "type": ["info"],
                  "id": fp, "severity": SEV_NUM.get(sev, 47), "dataset": "dns_ml.alerts", "module": "dns_ml",
                  "created": _to_utc_iso(alert.get("timestamp"))},
        "rule": {"name": alert.get("rule_name"), "ruleset": alert.get("rule_source"),
                 "description": str(alert.get("description") or "")[:1024] or None},
        "dns": {"question": {"name": domain, "type": d.get("query_type"),
                             "registered_domain": _registered_domain(domain)}},
        "threat": {"framework": "MITRE ATT&CK",
                   "tactic": {"name": list(alert.get("mitre_tactics") or [])},
                   "technique": {"id": list(alert.get("mitre_techniques") or [])}},
        "dns_ml": {"severity_label": sev, "score_a": _num(d.get("ml_score_A")), "score_b": _num(d.get("ml_score_B")),
                   "combined": _num(d.get("ml_combined_score")), "threat_score": _num(d.get("ml_threat_score")),
                   "label": d.get("ml_combined_label"), "confidence": d.get("ml_confidence"),
                   "fusion_method": d.get("fusion_method"), "model_version": model_version,
                   "investigation_priority": alert.get("investigation_priority"), "demo": bool(d.get("demo"))},
        "soc": {"status": mgmt.get("status") or "Open", "assigned_to": mgmt.get("assigned_to"),
                "escalated": bool(mgmt.get("escalated")), "verdict": mgmt.get("verdict"),
                "verdict_reason": mgmt.get("verdict_reason"), "updated_at": mgmt.get("updated_at")},
        "observer": {"product": "Capstone DNS ML detector", "type": "ids"},
        "tags": ["dns-tunnel-ml"] + (["demo"] if d.get("demo") else []),
    }
    ip = _valid_ip(alert.get("client_ip"))
    if ip:
        doc["source"] = {"ip": ip}
    elif alert.get("client_ip"):
        doc["dns_ml"]["client"] = str(alert.get("client_ip"))
    return doc


def _digest(doc):
    stable = {k: v for k, v in doc.items() if k != "event"}
    stable["sev"] = doc["event"]["severity"]
    return hashlib.sha1(json.dumps(stable, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def index_name(prefix, doc):
    day = (doc.get("@timestamp") or "")[:10].replace("-", ".") or datetime.now(timezone.utc).strftime("%Y.%m.%d")
    return f"{prefix}-{day}"


# ──────────────────────────────────────────────────────────────
# CEF
# ──────────────────────────────────────────────────────────────
def _cef_header(s):
    return str(s if s is not None else "").replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_value(s):
    return (str(s).replace("\\", "\\\\").replace("=", "\\=")
            .replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n"))


def to_cef(doc):
    sev = doc["dns_ml"]["severity_label"]
    rule = doc["rule"]["name"] or "unknown"
    sig = "dnsml-" + hashlib.sha1(rule.encode("utf-8")).hexdigest()[:8]
    ext = []

    def add(key, val):
        if val is not None and val != "" and val != []:
            ext.append(f"{key}={_cef_value(val)}")

    ts = _to_utc_iso(doc["@timestamp"])
    if ts:
        add("rt", int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000))
    add("src", (doc.get("source") or {}).get("ip"))
    add("externalId", doc["event"]["id"])
    add("cat", ",".join(doc["threat"]["tactic"]["name"]))
    add("msg", (doc["rule"]["description"] or "")[:512])
    pairs = (("cs1", "dnsQuery", doc["dns"]["question"]["name"]),
             ("cs2", "mitreTechniques", ",".join(doc["threat"]["technique"]["id"])),
             ("cs3", "mlConfidence", doc["dns_ml"]["confidence"]),
             ("cs4", "socStatus", doc["soc"]["status"]),
             ("cs5", "analystVerdict", doc["soc"]["verdict"]),
             ("cs6", "modelVersion", doc["dns_ml"]["model_version"]),
             ("cfp1", "mlCombinedScore", doc["dns_ml"]["combined"]),
             ("cfp2", "mlScoreA", doc["dns_ml"]["score_a"]),
             ("cfp3", "mlScoreB", doc["dns_ml"]["score_b"]))
    for key, label, val in pairs:
        if val is not None and val != "":
            add(key + "Label", label)
            add(key, round(val, 4) if isinstance(val, float) else val)
    return (f"CEF:0|Capstone|DNSTunnelML|1.0|{_cef_header(sig)}|{_cef_header(rule)}|"
            f"{CEF_SEV.get(sev, 5)}|" + " ".join(ext))


def syslog_frame(cef, sev_label, hostname=None):
    pri = SYSLOG_FACILITY * 8 + SYSLOG_SEV.get(sev_label, 4)
    now = datetime.now()
    stamp = f"{now.strftime('%b')} {now.day:>2} {now.strftime('%H:%M:%S')}"   # RFC 3164: day space-padded
    host = (hostname or socket.gethostname() or "capstone").split(".")[0].replace(" ", "-")
    return f"<{pri}>{stamp} {host} {cef}"


# ──────────────────────────────────────────────────────────────
# Senders: each returns (sent_fps, error_or_None)
# ──────────────────────────────────────────────────────────────
def _http(url, data, headers, method="POST"):
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:  # noqa: S310 (scheme validated by caller)
        return r.status, r.read()


def _check_http_url(url):
    p = urlparse(str(url or ""))
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError(f"endpoint must be an http(s) URL, got {url!r}")
    return url.rstrip("/")


def es_install_template(cfg):
    base = _check_http_url(cfg.get("endpoint"))
    try:
        tpl = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    prefix = cfg.get("index_prefix") or "dns-ml-alerts"
    tpl["index_patterns"] = [f"{prefix}-*"]
    headers = {"Content-Type": "application/json"}
    if cfg.get("api_key"):
        headers["Authorization"] = "ApiKey " + cfg["api_key"]
    _http(f"{base}/_index_template/{prefix}", json.dumps(tpl).encode("utf-8"), headers, method="PUT")
    return True


def send_elasticsearch(cfg, items):
    base = _check_http_url(cfg.get("endpoint"))
    prefix = cfg.get("index_prefix") or "dns-ml-alerts"
    headers = {"Content-Type": "application/x-ndjson"}
    if cfg.get("api_key"):
        headers["Authorization"] = "ApiKey " + cfg["api_key"]
    sent, errors = [], []
    for i in range(0, len(items), BULK_CHUNK):
        chunk = items[i:i + BULK_CHUNK]
        lines = []
        for fp, doc in chunk:
            lines.append(json.dumps({"index": {"_index": index_name(prefix, doc), "_id": fp}}))
            lines.append(json.dumps(doc, default=str))
        try:
            _, raw = _http(f"{base}/_bulk", ("\n".join(lines) + "\n").encode("utf-8"), headers)
            resp = json.loads(raw.decode("utf-8") or "{}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            errors.append(f"_bulk failed: {e}")
            continue
        for (fp, _), item in zip(chunk, resp.get("items") or []):
            res = item.get("index") or {}
            if res.get("error"):
                err = res["error"]
                errors.append(f"{fp}: {err.get('type') if isinstance(err, dict) else err}")
            else:
                sent.append(fp)
    return sent, ("; ".join(errors[:5]) + (f" (+{len(errors) - 5} more)" if len(errors) > 5 else "")) if errors else None


def send_syslog_cef(cfg, items):
    host, port = str(cfg.get("host") or "127.0.0.1"), int(cfg.get("port") or 514)
    proto = str(cfg.get("proto") or "udp").lower()
    if proto not in ("udp", "tcp"):
        raise ValueError("proto must be udp or tcp")
    frames = [(fp, syslog_frame(to_cef(doc), doc["dns_ml"]["severity_label"]).encode("utf-8")) for fp, doc in items]
    sent = []
    try:
        if proto == "udp":
            with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as s:
                for fp, f in frames:
                    s.sendto(f[:8192], (host, port))
                    sent.append(fp)
        else:
            with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as s:
                for fp, f in frames:
                    s.sendall(f.replace(b"\n", b" ") + b"\n")
                    sent.append(fp)
    except OSError as e:
        return sent, f"syslog {proto}://{host}:{port}: {e}"
    return sent, None


def send_webhook(cfg, items):
    url = _check_http_url(cfg.get("url"))
    sent, errors = [], []
    for i in range(0, len(items), WEBHOOK_CHUNK):
        chunk = items[i:i + WEBHOOK_CHUNK]
        body = json.dumps({"source": "capstone-dns-ml", "sent_at": datetime.now(timezone.utc).isoformat(),
                           "count": len(chunk), "alerts": [doc for _, doc in chunk]}, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "capstone-dns-ml-exporter/1.0"}
        if cfg.get("secret"):
            headers["X-Signature-SHA256"] = hmac.new(str(cfg["secret"]).encode("utf-8"), body, hashlib.sha256).hexdigest()
        try:
            _http(url, body, headers)
            sent.extend(fp for fp, _ in chunk)
        except (urllib.error.URLError, OSError, ValueError) as e:
            errors.append(str(e))
    return sent, "; ".join(errors[:3]) if errors else None


SENDERS = {"elasticsearch": send_elasticsearch, "syslog_cef": send_syslog_cef, "webhook": send_webhook}


# ──────────────────────────────────────────────────────────────
# Config + background manager
# ──────────────────────────────────────────────────────────────
def merged_config(raw_records):
    raw_records = raw_records if isinstance(raw_records, dict) else {}
    out = {}
    for name, defaults in DEFAULTS.items():
        user = raw_records.get(name) if isinstance(raw_records.get(name), dict) else {}
        out[name] = {**defaults, **user}
        out[name]["configured"] = bool(out[name].get("configured"))
    return out


def redact(config):
    return {name: {k: ("***" if k in SECRET_KEYS and v else v) for k, v in cfg.items()} for name, cfg in config.items()}


class ExportManager:
    """Debounced background exporter. trigger() is cheap and safe to call from request threads."""

    def __init__(self, load_config, build_items, state_path, debounce=2.0, on_change=None):
        self._load_config = load_config      # () -> merged config dict
        self._build_items = build_items      # () -> [(fp, ecs_doc), ...]
        self._on_change = on_change          # called after an export attempt (e.g. bump UI state)
        self._state_path = Path(state_path)
        self._debounce = debounce
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._status = {n: {"configured": False, "last_attempt": None, "last_success": None,
                            "last_error": None, "sent_total": 0, "last_batch": 0, "pending": 0} for n in TARGETS}
        self._sent = self._load_state()
        self._template_done = False
        self._thread = None

    def _load_state(self):
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            return {n: dict(data.get(n) or {}) for n in TARGETS}
        except (OSError, ValueError):
            return {n: {} for n in TARGETS}

    def _save_state(self):
        tmp = self._state_path.with_suffix(".tmp")
        try:
            for n in TARGETS:
                if len(self._sent[n]) > STATE_CAP:
                    self._sent[n] = dict(list(self._sent[n].items())[-STATE_CAP:])
            tmp.write_text(json.dumps(self._sent), encoding="utf-8")
            os.replace(tmp, self._state_path)
        except OSError:
            pass

    def status(self):
        try:
            cfg = self._load_config()
        except Exception:
            cfg = {}
        with self._lock:
            out = {n: dict(s) for n, s in self._status.items()}
        for n in out:
            out[n]["configured"] = bool((cfg.get(n) or {}).get("configured"))
        return out

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="soc-exporter", daemon=True)
            self._thread.start()

    def trigger(self):
        self._event.set()

    def _loop(self):
        while True:
            self._event.wait()
            time.sleep(self._debounce)       # coalesce a burst of alert actions into one export
            self._event.clear()
            try:
                self.run_once()
            except Exception as e:  # never let the exporter thread die
                sys.stderr.write(f"[exporter] {e}\n")

    def run_once(self, only=None):
        cfg = self._load_config()
        active = [n for n in TARGETS if cfg[n]["configured"] and (only is None or n in only)]
        if not active:
            return {}
        items = self._build_items()
        results = {}
        for name in active:
            now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            todo = []
            for fp, doc in items:
                dg = _digest(doc)
                if self._sent[name].get(fp) != dg:
                    todo.append((fp, doc, dg))
            err = None
            sent = []
            if todo:
                try:
                    if name == "elasticsearch" and cfg[name].get("install_template") and not self._template_done:
                        try:
                            self._template_done = es_install_template(cfg[name])
                        except (urllib.error.URLError, OSError, ValueError) as e:
                            err = f"index template: {e}"
                    sent, send_err = SENDERS[name](cfg[name], [(fp, doc) for fp, doc, _ in todo])
                    err = send_err or err
                except (ValueError, OSError) as e:
                    err = str(e)
                digests = {fp: dg for fp, _, dg in todo}
                for fp in sent:
                    self._sent[name][fp] = digests[fp]
            with self._lock:
                st = self._status[name]
                st["last_attempt"] = now
                st["last_batch"] = len(sent)
                st["sent_total"] += len(sent)
                st["pending"] = len(todo) - len(sent)
                st["last_error"] = err
                if not err:
                    st["last_success"] = now
            results[name] = {"sent": len(sent), "pending": len(todo) - len(sent), "error": err}
        self._save_state()
        if self._on_change and any(r["sent"] or r["error"] for r in results.values()):
            self._on_change()
        return results


# ──────────────────────────────────────────────────────────────
# CLI: one-shot export of an alerts file
# ──────────────────────────────────────────────────────────────
def _cli():
    here = Path(__file__).resolve().parent
    p = argparse.ArgumentParser(description="Export detection-engine alerts to SOC tools")
    p.add_argument("--alerts", default=str(here.parent / "data" / "processed" / "week4_unified_alerts.json"))
    p.add_argument("--config", default=str(here / "data" / "response_integrations.json"))
    p.add_argument("--target", choices=TARGETS, action="append",
                   help="limit to these targets (default: every target with configured=true)")
    p.add_argument("--print", dest="print_only", choices=("ecs", "cef"),
                   help="print the first 3 documents instead of sending")
    args = p.parse_args()

    sys.path.insert(0, str(here))
    from server import fp_hex  # same fingerprint as the dashboard uses

    alerts = (json.loads(Path(args.alerts).read_text(encoding="utf-8")) or {}).get("alerts", [])
    try:
        raw = json.loads(Path(args.config).read_text(encoding="utf-8")).get("records", {})
    except (OSError, ValueError):
        raw = {}
    cfg = merged_config(raw)
    items = [(fp_hex(a), to_ecs(a, fp_hex(a))) for a in alerts]
    if args.print_only:
        for fp, doc in items[:3]:
            print(json.dumps(doc, indent=2, default=str) if args.print_only == "ecs" else to_cef(doc))
        return
    if args.target:
        for t in args.target:
            cfg[t]["configured"] = True
    mgr = ExportManager(lambda: cfg, lambda: items, here / "data" / "export_state_cli.json", debounce=0)
    res = mgr.run_once(only=args.target)
    if not res:
        sys.exit("No target enabled. Set configured=true in the config file or pass --target.")
    for name, r in res.items():
        print(f"{name}: sent {r['sent']}, pending {r['pending']}" + (f", error: {r['error']}" if r["error"] else ""))


if __name__ == "__main__":
    _cli()
