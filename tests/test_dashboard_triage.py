"""Tier 1 triage workbench: grouping, evidence/checklist, guardrails, four-eyes, batch writes, enrichment."""

import http.client
import json
import os
import re
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("SOC_DASHBOARD_DATA_DIR", tempfile.mkdtemp(prefix="soc_dash_test_"))
sys.path.insert(0, str(ROOT / "dashboard"))

import evidence  # noqa: E402
import server  # noqa: E402

H = {"Content-Type": "application/json", "X-SOC-Request": "1"}
LONG = "a" * 52


BASE_TIME = datetime.now() - timedelta(minutes=1)   # fixed per run: fingerprints include query_time


def _alert(rule, ip, domain, sev="High", minutes_ago=0, desc=None, **details):
    t = BASE_TIME - timedelta(minutes=minutes_ago)
    return {"alert_id": f"{rule}|{ip}|{domain}", "timestamp": t.isoformat(), "query_time": (t - timedelta(seconds=3)).isoformat(),
            "rule_name": rule, "rule_source": "test", "severity": sev, "client_ip": ip, "domain": domain,
            "description": desc or f"{rule} for {domain}", "mitre_tactics": ["CommandAndControl"],
            "mitre_techniques": ["T1071.004"], "details": details}


def make_alerts():
    return [
        _alert("ML Model Attack Detection", "10.1.1.5", f"{LONG}.t.evil-tunnel.com", ml_score_A=0.97,
               ml_score_B=1.4, ml_combined_score=0.95, ml_confidence="HIGH", attack_signature="ENCODING"),
        _alert("ML Model Attack Detection", "10.1.1.5", "mzxw6ytboi.t.evil-tunnel.com", ml_combined_score=0.91),
        _alert("ML Model Attack Detection", "10.1.1.5", "gezdgnbvgy.t.evil-tunnel.com", sev="Medium", ml_combined_score=0.8),
        _alert("Z-score Statistical Detection - entropy", "10.1.1.5", "api.dev.lab.local", sev="Medium",
               desc="Statistical anomaly: entropy Z-score = 2.12 (value: 3.9414, baseline mean: 3.03)"),
        _alert("Z-score Statistical Detection - query_length", "10.1.1.5", "web.dev.lab.local", sev="Medium",
               desc="Statistical anomaly: query_length Z-score = 4.50 (value: 80.0, baseline mean: 16.47)"),
        _alert("DNS Tunneling Detection", "172.18.0.1", "q1.other-bad.net", sev="High"),
        _alert("Excessive NXDOMAIN DNS Queries", "10.1.1.5", "N/A", sev="Medium"),
    ]


def make_features(path):
    base = datetime.now() - timedelta(minutes=3)
    rows = []
    for i in range(30):
        dom = f"{LONG}.t.evil-tunnel.com" if i == 0 else f"n{i:02d}mzxw6ytb.t.evil-tunnel.com"
        rows.append({"timestamp": (base + timedelta(seconds=i)).isoformat(timespec="seconds"), "client_ip": "10.1.1.5",
                     "domain": dom, "query_type": "NULL" if i < 4 else "A", "response_code": "NoError",
                     "query_length": len(dom), "entropy": 4.2, "subdomain_depth": 3, "longest_label": len(dom.split(".")[0]),
                     "digit_ratio": 0.2, "query_rate": 0.5, "first_label_length": len(dom.split(".")[0]),
                     "encoding_type": "base32_suspicious" if i % 2 else "None", "is_high_entropy": i % 3 == 0,
                     "is_random_subdomain": False, "ml_label_A": 1, "ml_label_B": 1, "ml_score_A": 0.9})
    for i in range(12):
        rows.append({"timestamp": (base + timedelta(seconds=40 + i)).isoformat(timespec="seconds"), "client_ip": "10.1.1.5",
                     "domain": f"host{i}.dev.lab.local", "query_type": "A", "response_code": "NxDomain",
                     "query_length": 18, "entropy": 2.5, "subdomain_depth": 2, "longest_label": 6, "digit_ratio": 0.0,
                     "query_rate": 0.1, "first_label_length": 5, "encoding_type": "None", "is_high_entropy": False,
                     "is_random_subdomain": False, "ml_label_A": 0, "ml_label_B": 0})
    rows.append({"timestamp": base.isoformat(timespec="seconds"), "client_ip": "10.1.1.5", "domain": "api.dev.lab.local",
                 "query_type": "A", "response_code": "NoError", "query_length": 17})
    rows.append({"timestamp": base.isoformat(timespec="seconds"), "client_ip": "10.1.1.5", "domain": "web.dev.lab.local",
                 "query_type": "A", "response_code": "NoError", "query_length": 17})
    path.write_text(json.dumps(rows), encoding="utf-8")


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    feat = tmp_path_factory.mktemp("feat") / "week3_features_with_ml.json"
    make_features(feat)
    old_features, old_mode = server.FEATURES, server.STATE.mode
    server.FEATURES = evidence.FeatureIndex(feat)
    with server.STATE.lock:
        server.STATE.mode = "live"
        server.STATE.status = "idle"
        server.STATE.alerts_data = {"alerts": make_alerts(), "total_alerts": 7}
        server.STATE.bump()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield {"port": srv.server_address[1], "features": feat}
    srv.shutdown()
    server.FEATURES = old_features
    server.STATE.mode = old_mode


def req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    c.request(method, path, body=None if body is None else json.dumps(body), headers=headers or {})
    r = c.getresponse()
    raw = r.read()
    c.close()
    try:
        data = json.loads(raw.decode()) if raw else None
    except ValueError:
        data = raw.decode("utf-8", "replace")
    return r.status, dict(r.getheaders()), data


def queue(env, group="entity", actor="analyst-1", **kw):
    qs = "&".join(f"{k}={v}" for k, v in dict(group=group, actor=actor, status="", **kw).items())
    return req(env["port"], "GET", "/api/triage/queue?" + qs)[2]


def case_by_label(env, label, group="entity"):
    return next(c for c in queue(env, group)["cases"] if c["label"] == label)


def post(env, path, body):
    return req(env["port"], "POST", path, body, H)


# ── pure functions ─────────────────────────────────────────────
def test_case_apex_internal_zones():
    assert evidence.case_apex("x.y.evil.com") == "evil.com"
    assert evidence.case_apex("a.b.dev.lab.local", ["lab.local"]) == "dev.lab.local"
    assert evidence.case_apex("q.corp.internal") == "q.corp.internal"
    assert evidence.rule_family("Z-score Statistical Detection - entropy") == "zscore"
    assert evidence.rule_family("ML High Threat Score") == "ml"


def test_parse_zscore():
    z = evidence.parse_zscore("Statistical anomaly: entropy Z-score = 2.12 (value: 3.9414, baseline mean: 3.03)")
    assert z == {"feature": "entropy", "z": 2.12, "value": 3.9414, "baseline_mean": 3.03}
    assert evidence.parse_zscore("no score here") is None


def test_ip_flags():
    assert evidence.ip_flags("172.18.0.1")["shared"] and "docker-gateway" in evidence.ip_flags("172.18.0.1")["flags"]
    assert evidence.ip_flags("127.0.0.1")["shared"]
    assert not evidence.ip_flags("10.1.1.5")["shared"]
    assert evidence.ip_flags("10.0.0.53", resolvers=["10.0.0.53"])["shared"]


def test_feature_index_reloads_on_change(tmp_path):
    p = tmp_path / "f.json"
    p.write_text(json.dumps([{"client_ip": "1.1.1.1", "domain": "a.com"}]))
    fi = evidence.FeatureIndex(p)
    assert fi.get()["rows"] == 1
    assert fi.get() is fi.get()                       # cached while unchanged
    time.sleep(0.01)
    p.write_text(json.dumps([{"client_ip": "1.1.1.1", "domain": "a.com"}] * 3))
    os.utime(p, (time.time() + 5, time.time() + 5))
    assert fi.get()["rows"] == 3


# ── queue + grouping ───────────────────────────────────────────
def test_grouping_modes_and_priority(env):
    ent = queue(env, "entity")
    labels = {c["label"]: c for c in ent["cases"]}
    assert set(labels) == {"evil-tunnel.com", "dev.lab.local", "other-bad.net", "nxdomain"}
    assert labels["evil-tunnel.com"]["members"] == 3 and labels["evil-tunnel.com"]["priority"] == "High"
    assert labels["dev.lab.local"]["priority"] == "Medium"
    src = queue(env, "source")
    assert {c["label"] for c in src["cases"]} == {"ML model detections", "Statistical (Z-score) anomalies",
                                                  "Rule-based detections", "NXDOMAIN bursts"}
    assert src["counts"]["alerts"] == 7
    assert ent["cases"][0]["priority"] == "High"        # sorted by priority first


def test_queue_etag(env):
    _, headers, _ = req(env["port"], "GET", "/api/triage/queue?group=source&actor=analyst-1")
    code, _, _ = req(env["port"], "GET", "/api/triage/queue?group=source&actor=analyst-1",
                     headers={"If-None-Match": headers["ETag"]})
    assert code == 304


def test_first_seen_survives_rerun(env):
    c = case_by_label(env, "dev.lab.local")
    first = c["first_seen_at"]
    rerun = make_alerts()
    for a in rerun:      # a pipeline re-run stamps new alert times; fp ignores them
        a["timestamp"] = datetime.now().isoformat()
    with server.STATE.lock:
        server.STATE.alerts_data = {"alerts": rerun, "total_alerts": len(rerun)}
        server.STATE.bump()
    assert case_by_label(env, "dev.lab.local")["first_seen_at"] == first


# ── evidence + checklist ───────────────────────────────────────
def test_case_evidence_and_checklist(env):
    k = case_by_label(env, "evil-tunnel.com")["key"]
    _, _, v = req(env["port"], "GET", f"/api/triage/case/{k}?actor=analyst-1")
    auto = {i["id"]: i["auto"]["result"] for i in v["checklist"] if i["auto"]}
    assert auto["long_labels"] is True and auto["rare_qtypes"] is True and auto["encoding"] is True
    assert auto["volume"] is True and auto["ml_agree"] is True and auto["src_shared"] is False
    assert auto["popular"] is None              # Tranco list not installed
    assert v["evidence"]["query_types"]["NULL"] == 4
    assert v["suggestion"]["action"] == "escalate"
    assert v["ml"]["score_a"]["max"] == 0.97 and v["ml"]["top_deviations"]
    assert {"claim", "close", "escalate", "fp_needs_approval"} <= set(v["allowed_actions"])
    k2 = case_by_label(env, "other-bad.net")["key"]
    _, _, v2 = req(env["port"], "GET", f"/api/triage/case/{k2}?actor=analyst-1")
    assert v2["source"]["shared"] and v2["source"]["warning"]
    k3 = case_by_label(env, "dev.lab.local")["key"]
    _, _, v3 = req(env["port"], "GET", f"/api/triage/case/{k3}?actor=analyst-1")
    assert v3["evidence"]["zscores"]["max"]["z"] == 4.5


# ── workflow + guardrails ──────────────────────────────────────
def test_claim_fans_out_and_conflicts(env):
    k = case_by_label(env, "evil-tunnel.com")["key"]
    code, _, body = post(env, f"/api/triage/case/{k}/claim", {"actor": "analyst-1"})
    assert code == 200 and body["members"]["ok"] == 3
    mgmt = server.STORE.all_alert_mgmt()
    fps = [server.fp_hex(a) for a in make_alerts()[:3]]
    assert all(mgmt[fp]["assigned_to"] == "analyst-1" and mgmt[fp]["status"] == "Investigating" for fp in fps)
    assert post(env, f"/api/triage/case/{k}/claim", {"actor": "analyst-2"})[0] == 409
    assert post(env, f"/api/triage/case/{k}/claim", {"actor": "analyst-2", "force": True})[0] == 403
    assert post(env, f"/api/triage/case/{k}/claim", {"actor": "senior-1", "force": True})[0] == 200
    assert post(env, f"/api/triage/case/{k}/release", {"actor": "senior-1", "next_step": "back to L1"})[0] == 200
    assert post(env, f"/api/triage/case/{k}/claim", {"actor": "analyst-1"})[0] == 200


def test_claimed_case_declares_one_linked_incident(env):
    k = case_by_label(env, "other-bad.net")["key"]
    body = {"actor": "analyst-1", "title": "Suspected DNS tunnel from shared source",
            "severity": "High", "reason": "Suspicious DNS activity needs incident response review"}
    assert post(env, f"/api/triage/case/{k}/declare", body)[0] == 409
    assert post(env, f"/api/triage/case/{k}/claim", {"actor": "analyst-1"})[0] == 200
    assert case_by_label(env, "other-bad.net")["status"] == "Investigating"
    assert post(env, f"/api/triage/case/{k}/declare", dict(body, actor="analyst-2"))[0] == 409
    assert post(env, f"/api/triage/case/{k}/declare", dict(body, reason="short"))[0] == 400
    code, _, created = post(env, f"/api/triage/case/{k}/declare", body)
    assert code == 201
    incident = created["record"]
    assert incident["source_case_key"] == k and incident["created_by"] == "analyst-1"
    assert incident["status"] == "Investigating"
    assert incident["source_alert_count"] == 1 and incident["alert_fps"]
    assert incident["declaration_reason"] == body["reason"]
    assert incident["triage_snapshot"]["evidence"] and incident["triage_snapshot"]["history"]
    _, _, view = req(env["port"], "GET", f"/api/triage/case/{k}?actor=analyst-1")
    assert view["case"]["incident_id"] == incident["id"]
    assert "declare" not in view["allowed_actions"]
    code, _, again = post(env, f"/api/triage/case/{k}/declare", body)
    assert code == 200 and again["already_declared"] and again["record"]["id"] == incident["id"]
    _, _, read = req(env["port"], "GET", f"/api/incidents/{incident['id']}")
    assert read["record"]["source_case_key"] == k


def test_manual_incident_uses_reason_without_placeholder_alert(env):
    body = {"actor": "analyst-1", "alert_fps": [], "title": "Reported suspicious host activity",
            "severity": "Medium", "reason": "User reported activity that meets incident criteria"}
    assert post(env, "/api/incidents", dict(body, reason="short"))[0] == 400
    code, _, created = post(env, "/api/incidents", body)
    assert code == 200
    incident = created["record"]
    assert incident["source_type"] == "manual" and incident["alert_fps"] == []
    assert incident["declaration_reason"] == body["reason"]


def test_four_eyes_close_on_high(env):
    k = case_by_label(env, "evil-tunnel.com")["key"]
    high_fp = server.fp_hex(make_alerts()[0])
    medium_fp = server.fp_hex(make_alerts()[3])
    high_status = server.STORE.get_alert_mgmt(high_fp)["status"]
    medium_record = server.STORE.get_alert_mgmt(medium_fp)
    medium_status = medium_record["status"] if medium_record else "Open"
    assert post(env, f"/api/alerts/{high_fp}/status",
                {"actor": "analyst-1", "status": "Closed"})[0] == 409
    assert post(env, f"/api/alerts/{high_fp}/verdict",
                {"actor": "senior-1", "verdict": "fp_model_logic"})[0] == 200
    assert post(env, f"/api/alerts/{high_fp}/status",
                {"actor": "analyst-1", "status": "Closed"})[0] == 403
    assert post(env, "/api/alerts/bulk", {"actor": "analyst-1", "action": "close",
                                           "fps": [high_fp]})[2]["failed"] == 1
    assert server.STORE.get_alert_mgmt(high_fp)["status"] == high_status
    body = {"actor": "analyst-1", "classification": "fp_model_logic", "comment": "known lab load test traffic"}
    code, _, r = post(env, f"/api/triage/case/{k}/close", body)
    assert code == 400 and {m["id"] for m in r["missing"]} == {"m_host_review", "m_owner"}
    for item in ("m_host_review", "m_owner"):
        assert post(env, f"/api/triage/case/{k}/checklist", {"actor": "analyst-1", "item_id": item, "checked": True})[0] == 200
    assert post(env, f"/api/alerts/{high_fp}/status",
                {"actor": "analyst-1", "status": "Closed"})[0] == 403
    assert post(env, f"/api/alerts/{medium_fp}/verdict",
                {"actor": "analyst-1", "verdict": "true_positive"})[0] == 200
    code, _, bulk = post(env, "/api/alerts/bulk", {"actor": "senior-1", "action": "close",
                                                  "fps": [high_fp, medium_fp]})
    assert code == 200 and bulk["succeeded"] == 0 and bulk["failed"] == 2
    assert server.STORE.get_alert_mgmt(high_fp)["status"] == high_status
    assert server.STORE.get_alert_mgmt(medium_fp)["status"] == medium_status
    assert post(env, f"/api/triage/case/{k}/close", dict(body, comment="short"))[0] == 400
    code, _, r = post(env, f"/api/triage/case/{k}/close", body)
    assert code == 202 and r["pending_approval"]
    rid = r["close_request"]["id"]
    assert case_by_label(env, "evil-tunnel.com")["status"] == "PendingApproval"
    assert post(env, f"/api/triage/requests/{rid}/approve", {"actor": "analyst-2"})[0] == 403   # Tier 1
    code, _, r = post(env, f"/api/triage/requests/{rid}/approve", {"actor": "senior-1", "note": "agreed"})
    assert code == 200 and r["closed"] and r["members"]["ok"] == 3
    mgmt = server.STORE.all_alert_mgmt()
    fps = [server.fp_hex(a) for a in make_alerts()[:3]]
    assert all(mgmt[fp]["status"] == "Closed" and mgmt[fp]["verdict"] == "fp_model_logic"
               and mgmt[fp]["verdict_approved_by"] == "senior-1" for fp in fps)
    assert case_by_label(env, "evil-tunnel.com")["status"] == "Closed"
    assert post(env, f"/api/triage/requests/{rid}/approve", {"actor": "ir-lead"})[0] == 409


def test_requester_cannot_approve_own_request(env):
    k = case_by_label(env, "other-bad.net")["key"]
    for item in ("m_host_review", "m_owner"):
        post(env, f"/api/triage/case/{k}/checklist", {"actor": "senior-1", "item_id": item, "checked": True})
    # Tier 2 closes High FP directly (no request needed)
    code, _, r = post(env, f"/api/triage/case/{k}/close",
                      {"actor": "senior-1", "classification": "fp_bad_data", "comment": "duplicated test capture"})
    assert code == 200 and r["closed"]


def test_tier1_closes_medium_fp_directly_and_escalation(env):
    k = case_by_label(env, "dev.lab.local")["key"]
    code, _, r = post(env, f"/api/triage/case/{k}/escalate", {"actor": "analyst-1", "summary": "x"})
    assert code == 400                         # checklist first
    for item in ("m_host_review", "m_owner"):
        post(env, f"/api/triage/case/{k}/checklist", {"actor": "analyst-1", "item_id": item, "checked": True})
    code, _, r = post(env, f"/api/triage/case/{k}/escalate", {"actor": "analyst-1", "summary": "two z-score outliers"})
    assert code == 400 and "evidence" in r["error"]
    full = {"actor": "analyst-1", "summary": "two z-score outliers", "evidence": "query_length z=4.5",
            "checks_done": ["checklist reviewed"], "hypothesis": "possible exfil", "recommended_action": "check host"}
    code, _, r = post(env, f"/api/triage/case/{k}/escalate", full)
    assert code == 200 and r["escalation"]["checks_done"] == "- checklist reviewed"
    c = case_by_label(env, "dev.lab.local")
    assert c["status"] == "Escalated" and c["owner"] is None and c["next_step"].startswith("Tier 2")
    _, _, v = req(env["port"], "GET", f"/api/triage/case/{k}?actor=analyst-1")
    assert "close" not in v["allowed_actions"] and v["escalations"]
    assert post(env, f"/api/triage/case/{k}/close", {"actor": "analyst-1", "classification": "undetermined",
                                                     "comment": "not enough data to decide"})[0] == 403
    code, _, r = post(env, f"/api/triage/case/{k}/close", {"actor": "senior-1", "classification": "true_positive",
                                                           "comment": "confirmed with host owner"})
    assert code == 200


def test_tier1_medium_fp_close_without_approval(env):
    k = case_by_label(env, "nxdomain")["key"]
    for item in ("m_host_review", "m_owner"):
        post(env, f"/api/triage/case/{k}/checklist", {"actor": "analyst-2", "item_id": item, "checked": True})
    code, _, r = post(env, f"/api/triage/case/{k}/close",
                      {"actor": "analyst-2", "classification": "fp_model_logic", "comment": "resolver retries, benign"})
    assert code == 200 and r["closed"]


def test_history_and_my_shift(env):
    k = case_by_label(env, "evil-tunnel.com")["key"]
    _, _, v = req(env["port"], "GET", f"/api/triage/case/{k}?actor=senior-1")
    actions = {h["action"] for h in v["history"]}
    assert {"CASE_CLAIM", "CASE_CLOSE_REQUESTED", "CASE_CLOSE_APPROVED"} <= actions
    _, _, me = req(env["port"], "GET", "/api/triage/me?actor=analyst-1")
    assert me["claimed"] >= 2 and me["close_requested"] == 1 and me["escalated"] == 1 and me["tier"] == 1
    assert me["mtta_seconds"]["n"] >= 1


def test_handover_ack(env):
    _, _, h = req(env["port"], "GET", "/api/triage/handover?hours=8")
    assert "open_cases" in h and "pending_close_requests" in h
    assert post(env, "/api/triage/handover/ack", {"actor": "analyst-2", "note": "taking over"})[0] == 200
    _, _, h = req(env["port"], "GET", "/api/triage/handover?hours=8")
    assert h["last_ack"]["actor"] == "analyst-2"
    assert post(env, "/api/triage/handover/ack", {"actor": "nobody"})[0] == 403


def test_legacy_routes_guardrails(env):
    hi = server.fp_hex(make_alerts()[5])
    with server.STORE.lock:          # reopen the alert the earlier test closed
        rec = server.STORE._cache["alerts"]["records"][hi]
        rec["status"], rec["closed_by"] = "Open", None
    assert post(env, f"/api/alerts/{hi}/verdict", {"actor": "analyst-1", "verdict": "fp_bad_data"})[0] == 403
    assert post(env, f"/api/alerts/{hi}/verdict",
                 {"actor": "analyst-1", "verdict": "fp_bad_data", "_approved_by": "senior-1"})[0] == 403   # stripped
    code, _, r = post(env, "/api/alerts/bulk", {"actor": "analyst-1", "action": "verdict", "fps": [hi],
                                                "payload": {"verdict": "fp_model_logic", "_approved_by": "x"}})
    assert code == 200 and r["failed"] == 1 and r["results"][0]["code"] == 403
    assert post(env, f"/api/alerts/{hi}/verdict", {"actor": "senior-1", "verdict": "false_positive"})[0] == 200
    assert server.VERDICT_TO_LABEL["false_positive"] == 0 and server.VERDICT_TO_LABEL["undetermined"] is None
    assert post(env, f"/api/alerts/{hi}/status", {"actor": "analyst-1", "status": "Closed"})[0] == 403
    assert post(env, f"/api/alerts/{hi}/status", {"actor": "senior-1", "status": "Closed"})[0] == 200
    assert post(env, f"/api/alerts/{hi}/status", {"actor": "analyst-2", "status": "Open"})[0] == 403
    assert post(env, f"/api/alerts/{hi}/status", {"actor": "senior-1", "status": "Open"})[0] == 200
    assert post(env, "/api/suppressions", {"actor": "analyst-1", "field": "domain", "value": "x.com",
                                           "reason": "noise"})[0] == 403
    assert post(env, "/api/suppressions", {"field": "domain", "value": "x.com"})[0] == 400   # validated first
    m = server.compute_metrics(24)
    assert m["false_positive_rate"] is not None and m["verdicts_by_rule"]


def test_batch_write_once_and_audit_capped(env, monkeypatch):
    writes = []
    real = server.Store._atomic_write
    monkeypatch.setattr(server.Store, "_atomic_write",
                        staticmethod(lambda path, data: (writes.append(Path(path).name), real(path, data))))
    before = len(server.STORE.audit(limit=100000))
    fps = [f"{i:016x}" for i in range(500)]
    res = server.STORE.apply_case_action(fps, [("note", {"text": "bulk"})], "senior-1", "c-000000000000")
    assert res["ok"] == 500 and writes.count("alert_management.json") == 1 and writes.count("audit_log.json") == 1
    assert len(server.STORE.audit(limit=100000)) - before == 1        # one CASE_ row, no per-alert rows


def test_enrichment_offline_and_online_gating(env, monkeypatch):
    _, _, d = req(env["port"], "GET", "/api/enrich/domain/a.b.lab.local")
    assert d["offline"]["internal"] and d["online"]["status"] == "disabled"
    cfg = {"virustotal": {"enabled": True, "api_key": "k", "ttl_hours": 1}, "abuseipdb": {"enabled": True, "api_key": "k"}}
    enr = evidence.OnlineEnricher(lambda: cfg, lambda k: None, lambda k, v: None, lambda: ["lab.local"])
    called = []
    monkeypatch.setattr(evidence.OnlineEnricher, "_fetch", staticmethod(lambda *a, **k: called.append(a) or {}))
    assert enr.lookup("domain", "x.lab.local")["status"] == "not_sent"
    assert enr.lookup("ip", "192.168.1.5")["status"] == "not_sent"
    t = time.time()
    assert enr.lookup("domain", "example.org")["status"] == "pending"      # queued, worker not started
    assert time.time() - t < 0.5 and not called
    assert req(env["port"], "GET", "/api/enrich/ip/not-an-ip")[0] == 400
    _, _, integ = req(env["port"], "GET", "/api/integrations")
    assert "enrichment" in integ


def test_triage_page_has_csp_nonce(env):
    code, headers, page = req(env["port"], "GET", "/triage")
    nonce = re.search(r"'nonce-([^']+)'", headers["Content-Security-Policy"]).group(1)
    tags = re.findall(r"<script[^>]*>", page)
    assert code == 200 and tags and all(f'nonce="{nonce}"' in t for t in tags)
    assert " on" not in "".join(re.findall(r"<[^>]+>", page)).replace(" one", "")   # no inline handlers
