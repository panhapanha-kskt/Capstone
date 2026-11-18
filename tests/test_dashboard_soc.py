"""Dashboard SOC hardening, workflow, ML-info and exporter tests (stdlib server on a random port)."""

import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = tempfile.mkdtemp(prefix="soc_dash_test_")
os.environ["SOC_DASHBOARD_DATA_DIR"] = _DATA_DIR      # must be set before server is imported
sys.path.insert(0, str(ROOT / "dashboard"))

import exporters  # noqa: E402
import server  # noqa: E402

JSON_HDRS = {"Content-Type": "application/json", "X-SOC-Request": "1"}


def _alert(rule, ip, domain, minutes_ago=1, sev="High", **details):
    t = datetime.now() - timedelta(minutes=minutes_ago)
    return {"alert_id": rule + ip + domain, "timestamp": t.isoformat(), "query_time": (t - timedelta(seconds=2)).isoformat(),
            "rule_name": rule, "rule_source": "test", "severity": sev, "client_ip": ip, "domain": domain,
            "description": f"{rule} for {domain}", "mitre_tactics": ["CommandAndControl"],
            "mitre_techniques": ["T1572"], "details": details}


ALERTS = [
    _alert("DNS Tunneling Detection", "10.0.0.5", "a1.evil-tunnel.com", 1, ml_score_A=0.97, ml_combined_score=0.93,
           ml_confidence="HIGH"),
    _alert("ML Model Attack Detection", "10.0.0.5", "b2.evil-tunnel.com", 2, ml_score_A=0.9),
    _alert("Excessive NXDOMAIN DNS Queries", "10.0.0.9", "x.lab.local", 3, sev="Medium"),
]


@pytest.fixture(scope="module")
def base():
    with server.STATE.lock:
        server.STATE.mode = "demo"
        server.STATE.status = "idle"
        server.STATE.alerts_data = {"alerts": ALERTS, "total_alerts": len(ALERTS),
                                    "alerts_by_severity": {"High": 2, "Medium": 1}}
        server.STATE.bump()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    data = None if body is None else (body if isinstance(body, (bytes, str)) else json.dumps(body))
    c.request(method, path, body=data, headers=headers or {})
    r = c.getresponse()
    raw = r.read()
    c.close()
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else None
    except ValueError:
        parsed = raw.decode("utf-8", "replace")
    return r.status, dict(r.getheaders()), parsed


def fp_of(i):
    return server.fp_hex(ALERTS[i])


# ── security ───────────────────────────────────────────────────
def test_post_requires_json_content_type(base):
    code, _, body = req(base, "POST", "/api/run", "x", {"Content-Type": "text/plain", "X-SOC-Request": "1"})
    assert code == 415


def test_post_requires_custom_header(base):
    code, _, body = req(base, "POST", "/api/run", {}, {"Content-Type": "application/json"})
    assert code == 403 and "X-SOC-Request" in body["error"]


def test_cross_origin_post_rejected(base):
    code, _, _ = req(base, "POST", f"/api/alerts/{fp_of(0)}/acknowledge", {"actor": "analyst-1"},
                     {**JSON_HDRS, "Origin": "http://evil.test"})
    assert code == 403
    code, _, _ = req(base, "POST", f"/api/alerts/{fp_of(0)}/acknowledge", {"actor": "analyst-1"},
                     {**JSON_HDRS, "Sec-Fetch-Site": "cross-site"})
    assert code == 403


def test_dns_rebinding_host_rejected(base):
    code, _, _ = req(base, "GET", "/api/state", headers={"Host": f"attacker.example:{base}"})
    assert code == 403


def test_security_headers_and_csp_nonce(base):
    code, headers, page = req(base, "GET", "/alerts")
    assert code == 200
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    csp = headers["Content-Security-Policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    tags = re.findall(r"<script[^>]*>", page)
    assert tags and all(f'nonce="{nonce}"' in t for t in tags)
    assert "cdnjs" not in page          # React/htm are vendored, so CSP can stay 'self'
    _, headers2, _ = req(base, "GET", "/alerts")
    assert headers2["Content-Security-Policy"] != csp     # fresh nonce per response


def test_run_is_audited_and_rate_limited(base):
    server._RUN_GATE["last"] = 0.0
    code, _, _ = req(base, "POST", "/api/run", {"actor": "analyst-2"}, JSON_HDRS)
    assert code == 200
    code, headers, _ = req(base, "POST", "/api/run", {"actor": "analyst-2"}, JSON_HDRS)
    assert code == 429 and int(headers["Retry-After"]) >= 1
    audit = server.STORE.audit(limit=20)
    assert any(r["action"] == "PIPELINE_RUN_REQUESTED" and r["actor"] == "analyst-2" for r in audit)


def test_unknown_actor_not_trusted(base):
    code, _, body = req(base, "POST", f"/api/alerts/{fp_of(2)}/notes",
                        {"actor": "<img src=x onerror=alert(1)>", "text": "hello"}, JSON_HDRS)
    assert code == 200 and body["record"]["notes"][-1]["author"] == "unknown-analyst"


def test_incidents_endpoint_redacts_secrets(base, monkeypatch):
    cfg = server.STORE._cache["config"]["records"]
    monkeypatch.setitem(cfg, "webhook", {"configured": False, "url": "http://x", "secret": "s3cret"})
    _, _, body = req(base, "GET", "/api/incidents")
    assert body["integrations"]["webhook"]["secret"] == "***"


# ── lifecycle + workflow ───────────────────────────────────────
def test_state_is_superset_and_etag(base):
    code, headers, s = req(base, "GET", "/api/state")
    for k in ("version", "feed", "totals", "pipeline", "health", "models", "sources", "monitoring"):
        assert k in s
    assert {"fp", "management", "details", "suppressed"} <= set(s["feed"][0])
    assert "model_version" in s and "integrations" in s
    code, _, _ = req(base, "GET", "/api/state", headers={"If-None-Match": headers["ETag"]})
    assert code == 304


def test_closed_alert_transitions(base):
    fp = fp_of(1)
    assert req(base, "POST", f"/api/alerts/{fp}/status", {"actor": "analyst-1", "status": "Closed"}, JSON_HDRS)[0] == 200
    code, _, body = req(base, "POST", f"/api/alerts/{fp}/status", {"actor": "analyst-1", "status": "Investigating"}, JSON_HDRS)
    assert code == 409 and body["allowed"] == ["Open"]
    code, _, _ = req(base, "POST", f"/api/alerts/{fp}/acknowledge", {"actor": "analyst-1"}, JSON_HDRS)
    assert code == 409
    assert req(base, "POST", f"/api/alerts/{fp}/status", {"actor": "analyst-1", "status": "Open"}, JSON_HDRS)[0] == 200


def test_verdict_and_metrics(base):
    fp = fp_of(0)
    assert req(base, "POST", f"/api/alerts/{fp}/acknowledge", {"actor": "analyst-1"}, JSON_HDRS)[0] == 200
    assert req(base, "POST", f"/api/alerts/{fp}/verdict", {"actor": "analyst-1", "verdict": "maybe"}, JSON_HDRS)[0] == 400
    code, _, body = req(base, "POST", f"/api/alerts/{fp}/verdict",
                        {"actor": "senior-1", "verdict": "true_positive", "reason": "=HYPERLINK(\"x\")"}, JSON_HDRS)
    assert code == 200 and body["record"]["verdict"] == "true_positive"
    assert any(r["action"] == "VERDICT_SET" for r in server.STORE.audit(alert_fp=fp))
    _, _, m = req(base, "GET", "/api/metrics?hours=24")
    assert m["mtta_seconds"]["n"] >= 1 and m["mttd_seconds"]["n"] == 3
    assert m["verdicts"].get("true_positive") == 1
    assert m["attack_matrix"]["CommandAndControl"]["T1572"] == 3


def test_feedback_export_labels_and_csv_injection(base):
    _, _, data = req(base, "GET", "/api/feedback/export")
    row = next(r for r in data["records"] if r["fp"] == fp_of(0))
    assert row["label"] == 1 and row["ml_score_A"] == 0.97 and row["model_version"]
    _, headers, csv_text = req(base, "GET", "/api/feedback/export?format=csv")
    assert headers["Content-Type"].startswith("text/csv")
    assert "'=HYPERLINK" in csv_text


def test_related_alerts(base):
    _, _, rel = req(base, "GET", f"/api/alerts/{fp_of(0)}/related?window=3600")
    assert rel["total"] == 1 and rel["records"][0]["fp"] == fp_of(1)
    assert set(rel["records"][0]["reasons"]) == {"same client IP", "same registered domain"}


def test_suppression_hides_only_in_ui(base):
    future = (datetime.now() + timedelta(days=1)).isoformat()
    code, _, body = req(base, "POST", "/api/suppressions",
                        {"actor": "senior-1", "field": "domain", "value": "lab.local", "reason": "lab zone", "until": future},
                        JSON_HDRS)
    assert code == 200
    sid = body["record"]["id"]
    _, _, visible = req(base, "GET", "/api/alerts?include_suppressed=0")
    assert fp_of(2) not in [f["fp"] for f in visible["records"]]
    _, _, allr = req(base, "GET", "/api/alerts")
    assert next(f for f in allr["records"] if f["fp"] == fp_of(2))["suppressed"] == sid
    assert req(base, "POST", "/api/suppressions", {"field": "domain", "value": "x.com", "reason": "r",
                                                  "until": "2001-01-01T00:00:00Z"}, JSON_HDRS)[0] == 400
    assert req(base, "POST", "/api/suppressions", {"field": "domain", "value": "x.com"}, JSON_HDRS)[0] == 400
    assert req(base, "POST", f"/api/suppressions/{sid}/delete", {"actor": "senior-1"}, JSON_HDRS)[0] == 200


def test_handover_markdown(base):
    code, headers, text = req(base, "GET", "/api/reports/handover?format=md&hours=8")
    assert code == 200 and headers["Content-Type"].startswith("text/markdown")
    assert text.startswith("# SOC shift handover") and "## Open incidents" in text


# ── model info ─────────────────────────────────────────────────
def _models_dir(tmp_path, suffix, declared=None):
    (tmp_path / "dns_threshold.json").write_text(json.dumps({"threshold": 0.5, "features": ["a"] * 3}))
    thr = {"threshold": 0.49, "method": "percentile_99"}
    if declared:
        thr["model_type"] = declared
    (tmp_path / "dns_trafficformer_threshold.json").write_text(json.dumps(thr))
    (tmp_path / f"dns_trafficformer{suffix}").write_bytes(b"x")
    return tmp_path


def test_model_info_detects_path_b_type(tmp_path):
    (tmp_path / "a").mkdir()
    info = server.model_info(_models_dir(tmp_path / "a", "_iforest.pkl"))
    assert info["path_b"]["model_type"] == "IsolationForest" and info["model_version"]
    (tmp_path / "b").mkdir()
    assert server.model_info(_models_dir(tmp_path / "b", ".h5"))["path_b"]["model_type"] == "Transformer autoencoder"
    (tmp_path / "c").mkdir()
    assert server.model_info(_models_dir(tmp_path / "c", ".h5", "iforest"))["path_b"]["model_type"] == "IsolationForest"


# ── exporters ──────────────────────────────────────────────────
def test_to_ecs_fields():
    doc = exporters.to_ecs(ALERTS[0], "abc123", {"status": "Escalated", "verdict": "true_positive"}, "v1")
    assert doc["event"]["kind"] == "alert" and doc["event"]["id"] == "abc123"
    assert doc["source"]["ip"] == "10.0.0.5" and doc["dns"]["question"]["registered_domain"] == "evil-tunnel.com"
    assert doc["threat"]["technique"]["id"] == ["T1572"] and doc["dns_ml"]["score_a"] == 0.97
    assert doc["soc"]["verdict"] == "true_positive" and doc["@timestamp"].endswith("Z")
    bad = exporters.to_ecs({**ALERTS[0], "client_ip": "multiple"}, "x")
    assert "source" not in bad and bad["dns_ml"]["client"] == "multiple"


def test_cef_escaping():
    a = {**ALERTS[0], "rule_name": "a|b", "description": "x=1\nline2\\"}
    cef = exporters.to_cef(exporters.to_ecs(a, "fp1"))
    assert cef.startswith("CEF:0|Capstone|DNSTunnelML|1.0|")
    assert "|a\\|b|8|" in cef
    assert "msg=x\\=1\\nline2\\\\" in cef and "\n" not in cef


class _FakeES(BaseHTTPRequestHandler):
    bodies = []

    def log_message(self, *a):
        pass

    def do_PUT(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        self._ok(b'{"acknowledged":true}')

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        _FakeES.bodies.append((self.path, dict(self.headers), body))
        if self.path == "/_bulk":
            lines = [json.loads(l) for l in body.strip().split("\n")]
            items = []
            for meta in lines[0::2]:
                bad = meta["index"]["_id"] == "reject-me"
                items.append({"index": {"_id": meta["index"]["_id"], "status": 400 if bad else 201,
                                        **({"error": {"type": "mapper_parsing_exception"}} if bad else {})}})
            self._ok(json.dumps({"errors": any("error" in i["index"] for i in items), "items": items}).encode())
        else:
            self._ok(b"{}")

    def _ok(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture()
def fake_http():
    _FakeES.bodies = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FakeES)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _manager(tmp_path, cfg, items):
    full = exporters.merged_config(cfg)
    return exporters.ExportManager(lambda: full, lambda: items, tmp_path / "state.json", debounce=0)


def test_elasticsearch_bulk_idempotent(tmp_path, fake_http):
    items = [(server.fp_hex(a), exporters.to_ecs(a, server.fp_hex(a))) for a in ALERTS]
    mgr = _manager(tmp_path, {"elasticsearch": {"configured": True, "endpoint": fake_http}}, items)
    res = mgr.run_once()
    assert res["elasticsearch"] == {"sent": 3, "pending": 0, "error": None}
    path, headers, body = [b for b in _FakeES.bodies if b[0] == "/_bulk"][0]
    metas = [json.loads(l) for l in body.strip().split("\n")[0::2]]
    assert [m["index"]["_id"] for m in metas] == [fp for fp, _ in items]
    assert all(m["index"]["_index"].startswith("dns-ml-alerts-") for m in metas)
    assert headers["Content-Type"] == "application/x-ndjson"
    assert mgr.run_once()["elasticsearch"]["sent"] == 0          # unchanged docs are not re-sent
    reloaded = _manager(tmp_path, {"elasticsearch": {"configured": True, "endpoint": fake_http}}, items)
    assert reloaded.run_once()["elasticsearch"]["sent"] == 0     # dedupe state survives a restart


def test_elasticsearch_item_errors_reported(tmp_path, fake_http):
    items = [("reject-me", exporters.to_ecs(ALERTS[0], "reject-me")), ("ok-1", exporters.to_ecs(ALERTS[1], "ok-1"))]
    res = _manager(tmp_path, {"elasticsearch": {"configured": True, "endpoint": fake_http}}, items).run_once()
    assert res["elasticsearch"]["sent"] == 1 and res["elasticsearch"]["pending"] == 1
    assert "mapper_parsing_exception" in res["elasticsearch"]["error"]


def test_webhook_signed(tmp_path, fake_http):
    items = [("f1", exporters.to_ecs(ALERTS[0], "f1"))]
    res = _manager(tmp_path, {"webhook": {"configured": True, "url": fake_http + "/hook", "secret": "k"}}, items).run_once()
    assert res["webhook"]["sent"] == 1
    path, headers, body = _FakeES.bodies[-1]
    assert path == "/hook" and json.loads(body)["count"] == 1
    lower = {k.lower(): v for k, v in headers.items()}      # urllib re-cases header names
    assert lower["x-signature-sha256"] == hmac.new(b"k", body.encode(), hashlib.sha256).hexdigest()


def test_syslog_cef_udp(tmp_path):
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(5)
    items = [("f1", exporters.to_ecs(ALERTS[0], "f1"))]
    res = _manager(tmp_path, {"syslog_cef": {"configured": True, "host": "127.0.0.1",
                                             "port": rx.getsockname()[1], "proto": "udp"}}, items).run_once()
    data = rx.recv(9000).decode()
    rx.close()
    assert res["syslog_cef"]["sent"] == 1
    assert re.match(r"^<163>\w{3} [ \d]\d \d\d:\d\d:\d\d \S+ CEF:0\|", data)   # local4.error for High
    assert "cs1=a1.evil-tunnel.com" in data and "externalId=f1" in data


def test_unreachable_target_does_not_raise(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                  # nothing listens here now
    items = [("f1", exporters.to_ecs(ALERTS[0], "f1"))]
    mgr = _manager(tmp_path, {"elasticsearch": {"configured": True, "endpoint": f"http://127.0.0.1:{port}",
                                                "install_template": False}}, items)
    res = mgr.run_once()
    assert res["elasticsearch"]["sent"] == 0 and res["elasticsearch"]["error"]
    assert mgr.status()["elasticsearch"]["last_error"]


def test_bad_endpoint_scheme_rejected(tmp_path):
    items = [("f1", exporters.to_ecs(ALERTS[0], "f1"))]
    res = _manager(tmp_path, {"webhook": {"configured": True, "url": "file:///etc/passwd"}}, items).run_once()
    assert res["webhook"]["sent"] == 0 and "http(s)" in res["webhook"]["error"]


def test_training_console_requests_pass_the_guard():
    host = {"Host": "127.0.0.1:9000"}
    multipart = {**host, "Content-Type": "multipart/form-data; boundary=x", "X-Admin-Token": "t"}
    assert server.check_request("POST", multipart, "/training/api/datasets") is None
    assert server.check_request("POST", {**host, "X-Admin-Token": "t"}, "/training/api/models/rollback") is None
    assert server.check_request("POST", {**host, "Content-Type": "application/json"}, "/training/api/train")[0] == 403
    assert server.check_request("POST", {**multipart, "Origin": "http://evil.test"}, "/training/api/datasets")[0] == 403
    assert server.check_request("POST", {**host, "Content-Type": "text/plain", "X-Admin-Token": "t"},
                                "/training/api/train")[0] == 415
    # streamed dataset upload: raw body, still needs the admin token and same-origin
    raw = {**host, "Content-Type": "application/octet-stream", "X-Admin-Token": "t"}
    assert server.check_request("POST", raw, "/training/api/datasets/upload") is None
    assert server.check_request("POST", {**host, "Content-Type": "application/octet-stream"},
                                "/training/api/datasets/upload")[0] == 403
    assert server.check_request("POST", {**raw, "Sec-Fetch-Site": "cross-site"}, "/training/api/datasets/upload")[0] == 403
    # the exemption is only for the training proxy
    assert server.check_request("POST", multipart, "/api/run")[0] == 415
    assert server.check_request("POST", raw, "/api/run")[0] == 415
    assert server.check_request("POST", {**host, "Content-Type": "application/json", "X-Admin-Token": "t"},
                                "/api/run")[0] == 403
