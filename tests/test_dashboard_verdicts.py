"""Verdict fixes from AUDIT_training_label_unlabel_2026-11-18.md §6: F1 (unknown alerts), F2 (clear verdict),
F4 (same-value no-op), F5 (no records from rejected requests), F8 (--demo sets the training API to demo mode).
F3 (in-flight guard) is front-end only; F4 is its server-side backstop."""

import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("SOC_DASHBOARD_DATA_DIR", tempfile.mkdtemp(prefix="soc_dash_test_"))
sys.path.insert(0, str(ROOT / "dashboard"))

import server  # noqa: E402

H = {"Content-Type": "application/json", "X-SOC-Request": "1"}
BASE_TIME = datetime.now() - timedelta(minutes=1)


def _alert(rule, ip, domain, sev="Medium", minutes_ago=0):
    t = BASE_TIME - timedelta(minutes=minutes_ago)
    return {"alert_id": f"verdicts|{rule}|{ip}|{domain}", "timestamp": t.isoformat(),
            "query_time": (t - timedelta(seconds=2)).isoformat(), "rule_name": rule, "rule_source": "test",
            "severity": sev, "client_ip": ip, "domain": domain, "description": f"{rule} for {domain}",
            "mitre_tactics": ["CommandAndControl"], "mitre_techniques": ["T1071.004"], "details": {}}


ALERTS = [_alert("Verdict Test Rule", "10.9.9.%d" % i, f"v{i}.verdict-test.example", minutes_ago=i) for i in range(6)]
UNKNOWN = "deadbeefdeadbeef00"


@pytest.fixture(scope="module")
def base():
    with server.STATE.lock:
        old = (server.STATE.mode, server.STATE.alerts_data)
        server.STATE.mode = "demo"
        server.STATE.alerts_data = {"alerts": ALERTS, "total_alerts": len(ALERTS),
                                    "alerts_by_severity": {"Medium": len(ALERTS)}}
        server.STATE.bump()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    with server.STATE.lock:
        server.STATE.mode, server.STATE.alerts_data = old
        server.STATE.bump()


def post(port, path, body):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", path, body=json.dumps(body), headers=H)
    r = c.getresponse()
    raw = r.read()
    c.close()
    return r.status, (json.loads(raw) if raw else None)


def fp(i):
    return server.fp_hex(ALERTS[i])


def audit(fp_, action=None):
    rows = server.STORE.audit(alert_fp=fp_, limit=500)
    return [r for r in rows if action is None or r["action"] == action]


def file_records():
    path = server.STORE_FILES["alerts"]
    return json.loads(Path(path).read_text(encoding="utf-8"))["records"] if Path(path).exists() else {}


# ── F1: unknown alerts ─────────────────────────────────────────
def test_f1_verdict_on_unknown_alert_is_404_and_writes_nothing(base):
    code, body = post(base, f"/api/alerts/{UNKNOWN}/verdict", {"actor": "analyst-1", "verdict": "true_positive"})
    assert code == 404 and body["error"] == "unknown alert"
    assert server.STORE.get_alert_mgmt(UNKNOWN) is None
    assert UNKNOWN not in file_records()
    assert audit(UNKNOWN) == []


def test_f1_bulk_reports_unknown_items_and_still_applies_known(base):
    code, body = post(base, "/api/alerts/bulk",
                      {"actor": "analyst-1", "action": "acknowledge", "fps": [UNKNOWN, "not-hex!", fp(0)]})
    assert code == 200 and body["total"] == 3 and body["succeeded"] == 1
    by_fp = {r["fp"]: r for r in body["results"]}
    assert by_fp[UNKNOWN]["code"] == 404 and by_fp["not-hex!"]["code"] == 404 and by_fp[fp(0)]["ok"]
    assert server.STORE.get_alert_mgmt(UNKNOWN) is None


def test_f1_alert_that_left_the_feed_can_still_be_updated(base):
    gone = _alert("Aged Out Rule", "10.9.8.1", "old.verdict-test.example", minutes_ago=30)
    gfp = server.fp_hex(gone)
    with server.STATE.lock:
        server.STATE.alerts_data["alerts"].append(gone)
    assert post(base, f"/api/alerts/{gfp}/acknowledge", {"actor": "analyst-1"})[0] == 200
    with server.STATE.lock:
        server.STATE.alerts_data["alerts"].remove(gone)
    assert post(base, f"/api/alerts/{gfp}/notes", {"actor": "analyst-1", "text": "still investigating"})[0] == 200


# ── F5: rejected requests leave no record ──────────────────────
def test_f5_rejected_request_creates_no_record(base):
    f = fp(1)
    assert server.STORE.get_alert_mgmt(f) is None
    assert post(base, f"/api/alerts/{f}/verdict", {"actor": "analyst-1", "verdict": None})[0] == 400
    assert server.STORE.get_alert_mgmt(f) is None
    assert post(base, f"/api/alerts/{fp(2)}/acknowledge", {"actor": "analyst-1"})[0] == 200   # forces a file write
    assert f not in file_records()


def test_f5_bulk_with_only_invalid_items_does_not_touch_the_file(base):
    path = Path(server.STORE_FILES["alerts"])
    before = path.stat().st_mtime_ns if path.exists() else None
    n_audit = len(server.STORE.audit(limit=10000))
    code, body = post(base, "/api/alerts/bulk",
                      {"actor": "analyst-1", "action": "verdict", "payload": {"verdict": "maybe"}, "fps": [fp(3)]})
    assert code == 200 and body["failed"] == 1
    assert server.STORE.get_alert_mgmt(fp(3)) is None
    assert (path.stat().st_mtime_ns if path.exists() else None) == before
    assert len(server.STORE.audit(limit=10000)) == n_audit


# ── F4: same verdict twice is a no-op ──────────────────────────
def test_f4_same_verdict_twice_is_one_audit_entry(base):
    f = fp(4)
    body = {"actor": "analyst-1", "verdict": "benign_positive", "reason": "CDN"}
    code, first = post(base, f"/api/alerts/{f}/verdict", body)
    assert code == 200 and not first.get("unchanged")
    at = first["record"]["verdict_at"]
    code, second = post(base, f"/api/alerts/{f}/verdict", body)
    assert code == 200 and second["unchanged"] is True and second["record"]["verdict_at"] == at
    assert len(audit(f, "VERDICT_SET")) == 1
    # a different reason is a real change
    code, third = post(base, f"/api/alerts/{f}/verdict", dict(body, reason="CDN edge node"))
    assert code == 200 and not third.get("unchanged") and len(audit(f, "VERDICT_SET")) == 2


# ── F2: clear verdict ──────────────────────────────────────────
def test_f2_clear_verdict_removes_it_from_the_export_and_is_audited(base):
    f = fp(5)
    assert post(base, f"/api/alerts/{f}/verdict", {"actor": "analyst-1", "verdict": "true_positive"})[0] == 200
    assert any(r["fp"] == f for r in server.feedback_rows())
    code, body = post(base, f"/api/alerts/{f}/clearverdict", {"actor": "analyst-1", "reason": "wrong alert"})
    assert code == 200
    rec = body["record"]
    assert rec["verdict"] is None and rec["verdict_by"] is None and rec["verdict_at"] is None
    rows = audit(f, "VERDICT_CLEARED")
    assert len(rows) == 1 and rows[0]["old_value"] == "true_positive" and rows[0]["new_value"] is None
    assert not any(r["fp"] == f for r in server.feedback_rows())
    assert file_records()[f]["verdict"] is None                       # persisted
    # clearing again: nothing to clear
    assert post(base, f"/api/alerts/{f}/clearverdict", {"actor": "analyst-1"})[0] == 409


def test_f2_tier1_cannot_clear_another_analysts_verdict(base):
    f = fp(2)
    assert post(base, f"/api/alerts/{f}/verdict", {"actor": "analyst-1", "verdict": "undetermined"})[0] == 200
    code, body = post(base, f"/api/alerts/{f}/clearverdict", {"actor": "analyst-2"})
    assert code == 403 and body["required_tier"] == 2
    assert post(base, f"/api/alerts/{f}/clearverdict", {"actor": "senior-1"})[0] == 200


def test_f2_unknown_actor_cannot_clear(base):
    f = fp(0)
    assert post(base, f"/api/alerts/{f}/verdict", {"actor": "analyst-1", "verdict": "undetermined"})[0] == 200
    assert post(base, f"/api/alerts/{f}/clearverdict", {"actor": "unknown-person"})[0] == 403


def test_f2_bulk_clear_verdict(base):
    for i in (1, 3):
        assert post(base, f"/api/alerts/{fp(i)}/verdict", {"actor": "senior-1", "verdict": "duplicate"})[0] == 200
    code, body = post(base, "/api/alerts/bulk",
                      {"actor": "senior-1", "action": "clearverdict", "fps": [fp(1), fp(3), UNKNOWN]})
    assert code == 200 and body["succeeded"] == 2 and body["failed"] == 1
    assert server.STORE.get_alert_mgmt(fp(1))["verdict"] is None
    assert server.STORE.get_alert_mgmt(fp(3))["verdict"] is None


def test_f2_require_verdict_blocks_clearing_on_closed_alert(base, monkeypatch):
    f = fp(4)
    monkeypatch.setitem(server.WORKFLOW, "require_verdict", True)
    assert post(base, f"/api/alerts/{f}/status", {"actor": "analyst-1", "status": "Closed"})[0] == 200
    assert post(base, f"/api/alerts/{f}/clearverdict", {"actor": "senior-1"})[0] == 409
    assert server.STORE.get_alert_mgmt(f)["verdict"] == "benign_positive"


# ── F8: --demo puts the training console in demo mode ──────────
def test_f8_demo_flag_sets_training_mode_before_import():
    src = (ROOT / "dashboard" / "server.py").read_text(encoding="utf-8")
    demo_at = src.index('os.environ["TRAINGUI_MODE"] = "demo"')
    assert demo_at < src.index("= start_training_api()", src.index("if args.demo:"))
    # and the training settings really switch the production folder away from <repo>/models
    code = ("import sys; sys.path.insert(0, %r); from core import settings as S; "
            "print(S.MODE, S.PRODUCTION)") % str(ROOT / "dashboard" / "training-gui")
    env = dict(os.environ, TRAINGUI_MODE="demo")
    env.pop("PRODUCTION_DIR", None)
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True).stdout.split()
    assert out[0] == "demo"
    assert Path(out[1]).resolve() != (ROOT / "models").resolve()
