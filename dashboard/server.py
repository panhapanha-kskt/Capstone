#!/usr/bin/env python3
"""
Live dashboard server for DNS Traffic Anomaly Detection.

What it does
  1. Watches the Technitium log folder for new or changed *.log files.
  2. When something changes, re-runs the same pipeline as scripts/run_pipeline.sh:
       extractor -> ML bridge -> detection engine -> monitoring
  3. Serves the newest results as JSON (/api/state) and the page (/).

It only reads and runs your existing modules. It changes none of them.
The integrated training console uses FastAPI and Uvicorn from the project requirements.

Run it where the pipeline already works (needs TensorFlow for the ML bridge):

    python dashboard/server.py
    python dashboard/server.py --watch infra/technitium-elk/data/dns_logs
    python dashboard/server.py --demo          # fake alerts, no models needed

Then open http://127.0.0.1:8000
"""

import argparse
import hashlib
import http.client
import ipaddress
import json
import mimetypes
import os
import random
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import evidence  # noqa: E402  (dashboard/evidence.py, stdlib only)
import exporters  # noqa: E402  (dashboard/exporters.py, stdlib only)
DATA = ROOT / "data" / "processed"
RAW = ROOT / "data" / "raw"
MODELS = ROOT / "models"
TRAINING_GUI = HERE / "training-gui"
TRAINING_API_PORT = None
TRAINING_PROXY_TIMEOUT = 3600   # seconds per socket operation; big dataset uploads take a while

WEEK3 = DATA / "week3_features_all.json"
WEEK3_ML = DATA / "week3_features_with_ml.json"
ALERTS = DATA / "week4_unified_alerts.json"
MONITOR = DATA / "monitoring_report.json"
METADATA = MODELS / "training_metadata.json"

PATH_B_MODEL = "dns_trafficformer"
HISTORY_LIMIT = 120
FEED_LIMIT = 150


# ──────────────────────────────────────────────────────────────
# Pipeline steps (same commands as scripts/run_pipeline.sh)
# ──────────────────────────────────────────────────────────────
def pipeline_steps(zscore):
    py = sys.executable
    # Path B saves <name>.keras (autoencoder) or <name>_iforest.pkl (Isolation Forest); runs from
    # before Week 3 saved <name>.h5. path_b_predict picks the right one from the threshold file.
    path_b_ready = (
        any((MODELS / f"{PATH_B_MODEL}{suffix}").exists() for suffix in (".keras", ".h5", "_iforest.pkl"))
        and all((MODELS / n).exists() for n in (f"{PATH_B_MODEL}_threshold.json", f"{PATH_B_MODEL}_norm.json"))
    )
    bridge = [py, "-m", "dns_detect.fusion.bridge",
              "--week3", str(WEEK3), "--output", str(WEEK3_ML),
              "--weight-a", "0.6", "--weight-b", "0.4"]
    bridge += ["--path-b-model", PATH_B_MODEL] if path_b_ready else ["--no-path-b"]
    return [
        ("Extract features", [py, "-m", "dns_detect.features.extractor"], True),
        ("Score with ML models", bridge, True),
        ("Run detection rules", [py, "-m", "dns_detect.detection.engine",
                                 "--input", str(WEEK3_ML), "--output", str(ALERTS),
                                 "--zscore", str(zscore), "--csv"], True),
        ("Check drift", [py, "-m", "dns_detect.monitoring.monitor",
                         "--live", str(WEEK3_ML), "--alerts", str(ALERTS),
                         "--output", str(MONITOR)], False),  # informational, never fatal
    ]


# ──────────────────────────────────────────────────────────────
# Shared state
# ──────────────────────────────────────────────────────────────
class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.mode = "live"
        self.watch_dir = str(RAW)
        self.status = "starting"        # starting | idle | running | error
        self.step = ""
        self.error = ""
        self.started_at = time.time()
        self.last_run_at = None
        self.last_duration = None
        self.runs = 0
        self.history = []               # one point per pipeline run
        self.first_seen = {}            # alert fingerprint -> epoch first seen
        self.baseline_loaded = False
        self.alerts_mtime = None
        self.alerts_data = None
        self.version = 0
        self.poll_interval = 3.0  # reflects --interval, set from main()

    def bump(self):
        self.version += 1


STATE = State()


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def fingerprint(a):
    # alert_id is a fresh uuid on every engine run, so identify an alert by what it says
    return "|".join(str(a.get(k, "")) for k in ("rule_name", "client_ip", "domain", "query_time")) \
        + "|" + str(a.get("description", ""))[:90]


def fp_hex(a):
    """Short stable hex id derived from fingerprint(). Used as the durable alert key
    for management records so it survives fresh pipeline-run UUIDs."""
    return hashlib.sha1(fingerprint(a).encode("utf-8")).hexdigest()[:16]


def _finite(obj):
    """NaN / ±inf → None so the browser can JSON.parse the state (Python's json writes bare NaN).
    The bridge leaves Path B scores empty for records without a window, and the detection
    engine copies them into alert details as float('nan')."""
    if isinstance(obj, float):
        return obj if obj == obj and obj not in (float("inf"), float("-inf")) else None
    if isinstance(obj, dict):
        return {k: _finite(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_finite(v) for v in obj]
    return obj


# ──────────────────────────────────────────────────────────────
# Persistent store (alert management, use-case prefs, incidents, audit)
# ──────────────────────────────────────────────────────────────
STORE_DIR = Path(os.environ.get("SOC_DASHBOARD_DATA_DIR") or (HERE / "data"))
STORE_FILES = {
    "alerts":   STORE_DIR / "alert_management.json",
    "usecases": STORE_DIR / "usecase_preferences.json",
    "incidents": STORE_DIR / "incident_records.json",
    "audit":    STORE_DIR / "audit_log.json",
    "analysts": STORE_DIR / "analysts.json",
    "config":   STORE_DIR / "response_integrations.json",
    "suppressions": STORE_DIR / "suppressions.json",
    "triage": STORE_DIR / "triage_cases.json",
    "enrich_cache": STORE_DIR / "enrichment_cache.json",
}
SCHEMA_VERSIONS = {k: 1 for k in STORE_FILES}
# MIGRATIONS[key][from_version] = fn(data) -> data at from_version + 1
MIGRATIONS = {}
TRIAGE_DEFAULT = {"cases": {}, "escalations": {}, "close_requests": {}, "handover_acks": []}
SCHEMA_VERSION = 1

VALID_STATUSES = ("Open", "Acknowledged", "Investigating", "Escalated", "Resolved", "Closed")
# Reopen = Resolved/Closed → Open
ALLOWED_TRANSITIONS = {
    "Open":          {"Acknowledged", "Investigating", "Escalated", "Closed"},
    "Acknowledged":  {"Investigating", "Escalated", "Resolved", "Closed"},
    "Investigating": {"Escalated", "Resolved", "Closed"},
    "Escalated":     {"Investigating", "Resolved", "Closed"},
    "Resolved":      {"Closed", "Open"},    # Open = Reopen
    "Closed":        {"Open"},               # Open = Reopen
}
VALID_BULK_ACTIONS = ("acknowledge", "assign", "status", "escalate", "close", "verdict")
VALID_RESPONSE_ACTIONS = (
    "watchlist_ip", "mark_domain", "create_investigation_report",
    "export_evidence", "firewall_block_request", "endpoint_isolation_request",
)
NOTE_MAX_BYTES = 4096
# Analyst disposition. These become training labels via /api/feedback/export.
VALID_VERDICTS = ("true_positive", "benign_positive", "fp_model_logic", "fp_bad_data", "duplicate",
                  "undetermined", "false_positive")   # false_positive = legacy (before 2026-11-18)
FP_VERDICTS = frozenset({"false_positive", "fp_model_logic", "fp_bad_data"})
HIGH_SEVERITIES = ("High", "Critical")
CASE_PER_ALERT_AUDIT_MAX = 200
# Time to close-or-escalate targets (Tier 1 triage clock), separate from the ack clock above.
TRIAGE_SLA_SECONDS = {"Critical": 15 * 60, "High": 3600, "Medium": 4 * 3600, "Low": 8 * 3600}
VALID_SUPPRESSION_FIELDS = ("domain", "client_ip", "rule")
WORKFLOW = {"require_verdict": False}
# Time-to-acknowledge targets per severity (seconds); typical tiered SOC SLAs.
ACK_SLA_SECONDS = {"Critical": 15 * 60, "High": 15 * 60, "Medium": 60 * 60, "Low": 4 * 3600}

# Minimum analyst tier per write. Workflow control only: there is no login, so the actor is self-declared.
PERMISSIONS = {
    "note": 0, "acknowledge": 1, "assign": 1, "status": 1, "escalate": 1, "verdict": 1,
    "claim": 1, "release": 1, "checklist": 1, "case_close": 1, "case_escalate": 1, "handover_ack": 1,
    "incident_create": 1, "bulk": 1,
    "approve": 2, "suppress": 2, "incident_action": 2, "usecase_pref": 2, "force_claim": 2,
}


def role_tier(role):
    m = re.search(r"\d", str(role or ""))
    return int(m.group(0)) if m else 0

DEFAULT_ANALYSTS = [
    {"id": "analyst-1", "name": "SOC Analyst 1", "role": "Tier 1"},
    {"id": "analyst-2", "name": "SOC Analyst 2", "role": "Tier 1"},
    {"id": "senior-1",  "name": "Senior SOC Analyst", "role": "Tier 2"},
    {"id": "ir-lead",   "name": "Incident Response Lead", "role": "Tier 3"},
]


def _iso_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Store:
    """Thread-safe JSON store with atomic writes and .bak recovery.

    Each file follows: {"schema_version": 1, "records": <dict|list>}.
    """
    def __init__(self):
        self.lock = threading.Lock()
        STORE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(STORE_DIR, 0o700)
        except OSError:
            pass
        self._cache = {}
        for key, path in STORE_FILES.items():
            self._cache[key] = self._migrate(key, self._load(path, default_records=self._default_records(key)))
        for k, v in TRIAGE_DEFAULT.items():
            self._cache["triage"]["records"].setdefault(k, type(v)())
        # seed analysts file if absent
        if not STORE_FILES["analysts"].exists():
            self._cache["analysts"] = {"schema_version": SCHEMA_VERSION, "records": DEFAULT_ANALYSTS}
            self._atomic_write(STORE_FILES["analysts"], self._cache["analysts"])
        # seed empty integrations config if absent (never auto-populated with creds)
        if not STORE_FILES["config"].exists():
            self._cache["config"] = {"schema_version": SCHEMA_VERSION, "records": {
                "fortigate":   {"configured": False, "endpoint": None},
                "fortiedr":    {"configured": False, "endpoint": None},
                "fortisoar":   {"configured": False, "endpoint": None},
                "servicenow":  {"configured": False, "endpoint": None},
                **{k: dict(v) for k, v in exporters.DEFAULTS.items()},
            }}
            self._atomic_write(STORE_FILES["config"], self._cache["config"])

    @staticmethod
    def _default_records(key):
        if key in ("audit",):
            return []
        if key == "triage":
            return {k: type(v)() for k, v in TRIAGE_DEFAULT.items()}
        return {}

    @staticmethod
    def _migrate(key, data):
        target = SCHEMA_VERSIONS.get(key, SCHEMA_VERSION)
        v = int(data.get("schema_version") or 1)
        while v < target:
            data = MIGRATIONS[key][v](data)
            v += 1
            data["schema_version"] = v
        return data

    def _load(self, path, default_records):
        if not path.exists():
            return {"schema_version": SCHEMA_VERSION, "records": default_records}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or "records" not in data:
                raise ValueError("missing records wrapper")
            return data
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"[store] {path.name} unreadable ({exc}); trying .bak\n")
            bak = path.with_suffix(path.suffix + ".bak")
            if bak.exists():
                try:
                    with open(bak, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    pass
            try:
                path.rename(path.with_suffix(path.suffix + f".corrupt-{int(time.time())}"))
            except OSError:
                pass
            return {"schema_version": SCHEMA_VERSION, "records": default_records}

    @staticmethod
    def _atomic_write(path, data):
        tmp = path.with_suffix(path.suffix + ".tmp")
        bak = path.with_suffix(path.suffix + ".bak")
        payload = json.dumps(data, ensure_ascii=False, indent=2, default=str).encode("utf-8")
        with open(tmp, "wb") as f:
            f.write(payload)
            f.flush()
            try:
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        if path.exists():
            try:
                shutil.copy2(path, bak)
            except OSError:
                pass
        os.replace(tmp, path)

    # ── alert management ────────────────────────────────────────
    def get_alert_mgmt(self, fp):
        with self.lock:
            return self._cache["alerts"]["records"].get(fp)

    def all_alert_mgmt(self):
        with self.lock:
            return dict(self._cache["alerts"]["records"])

    def _put_alert_mgmt(self, fp, record):
        self._cache["alerts"]["records"][fp] = record
        self._atomic_write(STORE_FILES["alerts"], self._cache["alerts"])

    def ensure_alert_record(self, fp, seed_from_alert=None):
        rec = self._cache["alerts"]["records"].get(fp)
        if rec is not None:
            return rec
        now = _iso_now()
        rec = {
            "fp": fp,
            "status": "Open",
            "assigned_to": None,
            "escalated": False,
            "acknowledged_at": None,
            "assigned_at": None,
            "resolved_at": None,
            "closed_at": None,
            "verdict": None,
            "verdict_reason": None,
            "verdict_by": None,
            "verdict_at": None,
            "notes": [],
            "updated_at": now,
            "created_at": now,
            "last_seen_alert_id": (seed_from_alert or {}).get("alert_id"),
            "rule_name": (seed_from_alert or {}).get("rule_name"),
            "severity": (seed_from_alert or {}).get("severity"),
        }
        self._cache["alerts"]["records"][fp] = rec
        return rec

    def _tier_locked(self, actor):
        for a in self._cache["analysts"]["records"]:
            if a.get("id") == actor:
                return role_tier(a.get("role"))
        return 0

    def _apply_one_locked(self, fp, action, payload, actor, alert_hint, now):
        """Mutate one alert record in the cache (caller holds self.lock and persists).
        Returns (http_status, body_dict, audit_entries)."""
        rec = self.ensure_alert_record(fp, seed_from_alert=alert_hint)
        old_status = rec["status"]
        audit_entries = []
        tier = self._tier_locked(actor)
        severity = rec.get("severity") or (alert_hint or {}).get("severity")

        if action == "acknowledge":
            if rec["status"] in ("Resolved", "Closed"):
                return 409, {"error": f"cannot acknowledge a {rec['status']} alert; reopen it first"}, []
            if rec["status"] == "Open":
                rec["status"] = "Acknowledged"
            rec["acknowledged_at"] = rec["acknowledged_at"] or now
            audit_entries.append(("ACKNOWLEDGED", old_status, rec["status"]))

        elif action == "assign":
            new_analyst = payload.get("analyst_id")
            if new_analyst is not None:
                if not any(a["id"] == new_analyst for a in self._cache["analysts"]["records"]):
                    return 400, {"error": f"unknown analyst {new_analyst}"}, []
            old_assignee = rec["assigned_to"]
            rec["assigned_to"] = new_analyst
            rec["assigned_at"] = now if new_analyst else None
            audit_entries.append(("ASSIGNED", old_assignee, new_analyst))

        elif action == "status":
            new_status = payload.get("status")
            if new_status not in VALID_STATUSES:
                return 400, {"error": f"status must be one of {VALID_STATUSES}"}, []
            if new_status not in ALLOWED_TRANSITIONS.get(old_status, set()) and new_status != old_status:
                return 409, {
                    "error": f"invalid transition {old_status} → {new_status}",
                    "allowed": sorted(ALLOWED_TRANSITIONS.get(old_status, set())),
                }, []
            reopening = new_status == "Open" and old_status in ("Resolved", "Closed")
            if reopening and tier < 2 and rec.get("closed_by") != actor:
                return 403, {"error": "only Tier 2+ or the analyst who closed it can reopen this alert",
                             "required_tier": 2}, []
            if (WORKFLOW["require_verdict"] and new_status in ("Resolved", "Closed")
                    and new_status != old_status and not rec.get("verdict")):
                return 409, {"error": "set a verdict before resolving or closing this alert",
                             "verdicts": list(VALID_VERDICTS)}, []
            rec["status"] = new_status
            if new_status == "Resolved":
                rec["resolved_at"] = now
                rec["closed_by"] = actor
            elif new_status == "Closed":
                rec["closed_at"] = now
                rec["closed_by"] = actor
            elif reopening:
                # reopen: clear resolved/closed stamps, keep history in audit
                rec["resolved_at"] = None
                rec["closed_at"] = None
                rec["closed_by"] = None
            audit_entries.append(("STATUS_CHANGED", old_status, new_status))

        elif action == "escalate":
            if rec["status"] == "Closed":
                return 409, {"error": "cannot escalate a Closed alert"}, []
            rec["escalated"] = True
            if rec["status"] != "Escalated":
                rec["status"] = "Escalated"
            audit_entries.append(("ESCALATED", old_status, rec["status"]))

        elif action == "note":
            text = (payload.get("text") or "").strip()
            if not text:
                return 400, {"error": "note text required"}, []
            if len(text.encode("utf-8")) > NOTE_MAX_BYTES:
                return 400, {"error": f"note exceeds {NOTE_MAX_BYTES} bytes"}, []
            note = {"id": str(uuid.uuid4()), "text": text, "author": actor, "ts": now}
            rec["notes"].append(note)
            audit_entries.append(("NOTE_ADDED", None, note["id"]))

        elif action == "verdict":
            verdict = payload.get("verdict")
            if verdict not in VALID_VERDICTS:
                return 400, {"error": f"verdict must be one of {VALID_VERDICTS}"}, []
            reason = payload.get("reason")
            if reason is not None and (not isinstance(reason, str)
                                       or len(reason.encode("utf-8")) > NOTE_MAX_BYTES):
                return 400, {"error": f"reason must be a string up to {NOTE_MAX_BYTES} bytes"}, []
            if (verdict in FP_VERDICTS and severity in HIGH_SEVERITIES and tier < 2
                    and not payload.get("_approved_by")):
                return 403, {"error": "Tier 1 cannot mark a High/Critical alert as a false positive; "
                                      "request closure from the Triage page for Tier 2 approval",
                             "required_tier": 2}, []
            old_verdict = rec.get("verdict")
            rec["verdict"] = verdict
            rec["verdict_reason"] = (reason or "").strip() or None
            rec["verdict_by"] = actor
            rec["verdict_at"] = now
            if payload.get("_approved_by"):
                rec["verdict_approved_by"] = payload["_approved_by"]
            audit_entries.append(("VERDICT_SET", old_verdict, verdict))

        else:
            return 400, {"error": f"unknown action {action}"}, []

        rec["updated_at"] = now
        if payload.get("_case_key"):
            rec["case_key"] = payload["_case_key"]
        if alert_hint:
            rec["last_seen_alert_id"] = alert_hint.get("alert_id") or rec.get("last_seen_alert_id")
        return 200, {"ok": True, "record": rec}, audit_entries

    def apply_alert_action(self, fp, action, payload, actor, alert_hint=None):
        """Apply a validated management action to one alert. Returns (http_status, body_dict).

        action ∈ {status, assign, acknowledge, escalate, note, verdict}."""
        with self.lock:
            code, body, audit_entries = self._apply_one_locked(fp, action, payload, actor, alert_hint, _iso_now())
            if code != 200:
                return code, body
            self._atomic_write(STORE_FILES["alerts"], self._cache["alerts"])
            for act, old, new in audit_entries:
                self._append_audit(alert_fp=fp, action=act, old=old, new=new, actor=actor,
                                   note=payload.get("reason") if action != "note" else payload.get("text"),
                                   flush=False)
            self._flush_audit()
            STATE.bump()  # tell pollers something changed
            return code, body

    def apply_case_action(self, fps, steps, actor, case_key, hints=None, audit_note=None, audit_action=None):
        """Apply a sequence of (action, payload) steps to every alert in a case with ONE file write
        and one CASE_* audit row (per-alert rows only for small cases). A step that is invalid for a
        member (e.g. acknowledge on an already Closed alert) is skipped for that member, not fatal.
        Returns {"ok": n, "failed": [{"fp", "code", "error"}]}."""
        hints = hints or {}
        now = _iso_now()
        ok, failed = 0, []
        per_alert = len(fps) <= CASE_PER_ALERT_AUDIT_MAX
        with self.lock:
            for fp in fps:
                member_ok = True
                for action, payload in steps:
                    p = dict(payload or {})
                    if case_key:
                        p["_case_key"] = case_key
                    code, body, entries = self._apply_one_locked(fp, action, p, actor, hints.get(fp), now)
                    if code != 200:
                        if code == 403:          # a guardrail is never "skipped"; surface it
                            member_ok = False
                        failed.append({"fp": fp, "action": action, "code": code, "error": body.get("error")})
                        continue
                    if per_alert:
                        for act, old, new in entries:
                            self._append_audit(alert_fp=fp, action=act, old=old, new=new, actor=actor,
                                               note=p.get("reason") if action != "note" else p.get("text"),
                                               flush=False)
                ok += 1 if member_ok else 0
            self._atomic_write(STORE_FILES["alerts"], self._cache["alerts"])
            self._append_audit(action=audit_action or ("CASE_" + "_".join(a.upper() for a, _ in steps)),
                               actor=actor,
                               new={"case_key": case_key, "members": len(fps), "ok": ok, "failed": len(failed)},
                               note=audit_note, flush=False)
            self._flush_audit()
            STATE.bump()
        return {"ok": ok, "failed": failed}

    # ── analysts ────────────────────────────────────────────────
    def analysts(self):
        with self.lock:
            return list(self._cache["analysts"]["records"])

    # ── audit ───────────────────────────────────────────────────
    def _flush_audit(self):
        self._atomic_write(STORE_FILES["audit"], self._cache["audit"])

    def _append_audit(self, action, actor, alert_fp=None, incident_id=None, old=None, new=None, note=None,
                      flush=True):
        entry = {
            "event_id": str(uuid.uuid4()),
            "timestamp": _iso_now(),
            "action": action,
            "actor": actor,
            "alert_fp": alert_fp,
            "incident_id": incident_id,
            "old_value": old,
            "new_value": new,
            "note": note,
            "authenticated": False,
        }
        self._cache["audit"]["records"].append(entry)
        # cap in-memory audit at 10 000 entries (keep newest)
        if len(self._cache["audit"]["records"]) > 10000:
            self._cache["audit"]["records"] = self._cache["audit"]["records"][-10000:]
        if flush:
            self._flush_audit()

    def audit(self, alert_fp=None, incident_id=None, limit=200):
        with self.lock:
            rows = list(self._cache["audit"]["records"])
        if alert_fp:
            rows = [r for r in rows if r.get("alert_fp") == alert_fp]
        if incident_id:
            rows = [r for r in rows if r.get("incident_id") == incident_id]
        return rows[-limit:][::-1]  # newest first

    # ── use-case prefs ──────────────────────────────────────────
    def get_usecase_prefs(self):
        with self.lock:
            return dict(self._cache["usecases"]["records"])

    def set_usecase_pref(self, rule_name, visibility=None, excluded=None, note=None, actor="system"):
        if not rule_name or not isinstance(rule_name, str):
            return 400, {"error": "rule_name required"}
        with self.lock:
            now = _iso_now()
            rec = self._cache["usecases"]["records"].get(rule_name) or {
                "rule_name": rule_name,
                "visibility": True,
                "excluded": False,
                "note": "",
                "updated_at": now,
                "updated_by": actor,
            }
            if visibility is not None:
                rec["visibility"] = bool(visibility)
            if excluded is not None:
                rec["excluded"] = bool(excluded)
            if note is not None:
                if not isinstance(note, str) or len(note.encode("utf-8")) > NOTE_MAX_BYTES:
                    return 400, {"error": "note invalid or too large"}
                rec["note"] = note
            rec["updated_at"] = now
            rec["updated_by"] = actor
            self._cache["usecases"]["records"][rule_name] = rec
            self._atomic_write(STORE_FILES["usecases"], self._cache["usecases"])
            self._append_audit(action="USECASE_PREF_CHANGED", actor=actor,
                               old=None, new=rec, note=f"rule={rule_name}")
            STATE.bump()
            return 200, {"ok": True, "record": rec}

    # ── incidents ───────────────────────────────────────────────
    def incidents(self):
        with self.lock:
            return list(self._cache["incidents"]["records"].values())

    def incident(self, incident_id):
        with self.lock:
            return self._cache["incidents"]["records"].get(incident_id)

    def create_incident(self, alert_fps, title, severity, actor):
        if not isinstance(alert_fps, list) or not alert_fps:
            return 400, {"error": "alert_fps required"}
        if not title or not isinstance(title, str):
            return 400, {"error": "title required"}
        severity = severity if severity in ("Low", "Medium", "High", "Critical") else "Medium"
        incident_id = "inc-" + uuid.uuid4().hex[:10]
        now = _iso_now()
        rec = {
            "id": incident_id,
            "title": title[:240],
            "severity": severity,
            "status": "Open",
            "alert_fps": list(alert_fps)[:200],
            "created_at": now,
            "created_by": actor,
            "updated_at": now,
            "actions": [],
        }
        with self.lock:
            self._cache["incidents"]["records"][incident_id] = rec
            self._atomic_write(STORE_FILES["incidents"], self._cache["incidents"])
            self._append_audit(action="INCIDENT_CREATED", actor=actor,
                               incident_id=incident_id, new=rec)
            STATE.bump()
        return 200, {"ok": True, "record": rec}

    def record_incident_action(self, incident_id, action, payload, actor):
        if action not in VALID_RESPONSE_ACTIONS:
            return 400, {"error": f"action must be one of {VALID_RESPONSE_ACTIONS}"}
        with self.lock:
            rec = self._cache["incidents"]["records"].get(incident_id)
            if not rec:
                return 404, {"error": "incident not found"}
            config = self._cache["config"]["records"]
            # map action → integration key for status resolution
            integration_map = {
                "firewall_block_request": "fortigate",
                "endpoint_isolation_request": "fortiedr",
            }
            integ_key = integration_map.get(action)
            if integ_key and not config.get(integ_key, {}).get("configured"):
                status = "NOT_CONFIGURED"
            else:
                status = "SIMULATED"   # project phase: never EXECUTED
            action_entry = {
                "action_id": str(uuid.uuid4()),
                "action": action,
                "payload": payload or {},
                "status": status,
                "actor": actor,
                "ts": _iso_now(),
            }
            rec["actions"].append(action_entry)
            rec["updated_at"] = action_entry["ts"]
            self._atomic_write(STORE_FILES["incidents"], self._cache["incidents"])
            self._append_audit(action="INCIDENT_ACTION_" + status,
                               actor=actor, incident_id=incident_id,
                               new={"action": action, "status": status})
            STATE.bump()
        return 200, {"ok": True, "status": status, "action": action_entry}

    def integrations(self):
        with self.lock:
            return dict(self._cache["config"]["records"])

    # ── triage cases (Tier 1 workbench) ──────────────────────────
    def triage_snapshot(self):
        with self.lock:
            r = self._cache["triage"]["records"]
            return {"cases": dict(r["cases"]), "escalations": dict(r["escalations"]),
                    "close_requests": dict(r["close_requests"]), "handover_acks": list(r["handover_acks"])}

    def triage_touch(self, keys_modes):
        """Persist first_seen_at for cases seen for the first time (one write, only if any are new)."""
        now = _iso_now()
        with self.lock:
            cases = self._cache["triage"]["records"]["cases"]
            new = [(k, m) for k, m in keys_modes if k not in cases]
            for k, m in new:
                cases[k] = {"first_seen_at": now, "mode": m, "claimed_by": None, "claimed_at": None,
                            "checklist": {}, "next_step": None, "escalation_ids": [], "close_request_id": None,
                            "closed_at": None}
            if new:
                self._atomic_write(STORE_FILES["triage"], self._cache["triage"])
            return {k: dict(cases[k]) for k, _ in keys_modes}

    def triage_update(self, fn, audit=None):
        """Run fn(records) under the lock, persist once, optionally append one audit row
        (audit = dict of _append_audit kwargs). fn may return (code, body) to abort without writing."""
        with self.lock:
            res = fn(self._cache["triage"]["records"])
            if isinstance(res, tuple) and res and isinstance(res[0], int) and res[0] >= 400:
                return res
            self._atomic_write(STORE_FILES["triage"], self._cache["triage"])
            if audit:
                self._append_audit(**audit)
            STATE.bump()
            return res

    # ── enrichment cache ─────────────────────────────────────────
    def enrich_get(self, key):
        with self.lock:
            return self._cache["enrich_cache"]["records"].get(key)

    def enrich_put(self, key, value):
        with self.lock:
            recs = self._cache["enrich_cache"]["records"]
            recs[key] = value
            if len(recs) > 5000:
                for k in sorted(recs, key=lambda k: recs[k].get("fetched_at", 0))[:len(recs) - 5000]:
                    recs.pop(k, None)
            self._atomic_write(STORE_FILES["enrich_cache"], self._cache["enrich_cache"])

    # ── suppressions (UI triage only; detection rules are never changed) ──
    def suppressions(self, active_only=False):
        with self.lock:
            rows = list(self._cache["suppressions"]["records"].values())
        if active_only:
            now = time.time()
            rows = [r for r in rows if not r.get("until") or (_parse_ts(r["until"]) or 0) > now]
        return rows

    def add_suppression(self, field, value, until, reason, actor, check=None):
        if field not in VALID_SUPPRESSION_FIELDS:
            return 400, {"error": f"field must be one of {VALID_SUPPRESSION_FIELDS}"}
        if not isinstance(value, str) or not value.strip() or len(value) > 255:
            return 400, {"error": "value required (max 255 chars)"}
        if not isinstance(reason, str) or not reason.strip():
            return 400, {"error": "reason required: say why this is a known false positive"}
        if len(reason.encode("utf-8")) > NOTE_MAX_BYTES:
            return 400, {"error": f"reason exceeds {NOTE_MAX_BYTES} bytes"}
        if until is not None:
            if not isinstance(until, str) or _parse_ts(until) is None:
                return 400, {"error": "until must be an ISO-8601 timestamp or null"}
            if _parse_ts(until) <= time.time():
                return 400, {"error": "until must be in the future"}
        denied = check() if check else None      # validate first, then authorize
        if denied:
            return denied
        sid = "sup-" + uuid.uuid4().hex[:10]
        rec = {"id": sid, "field": field, "value": value.strip().lower().rstrip("."),
               "until": until, "reason": reason.strip(), "created_by": actor, "created_at": _iso_now()}
        with self.lock:
            self._cache["suppressions"]["records"][sid] = rec
            self._atomic_write(STORE_FILES["suppressions"], self._cache["suppressions"])
            self._append_audit(action="SUPPRESSION_ADDED", actor=actor, new=rec, note=rec["reason"])
            STATE.bump()
        return 200, {"ok": True, "record": rec}

    def remove_suppression(self, sid, actor):
        with self.lock:
            rec = self._cache["suppressions"]["records"].pop(sid, None)
            if rec is None:
                return 404, {"error": "suppression not found"}
            self._atomic_write(STORE_FILES["suppressions"], self._cache["suppressions"])
            self._append_audit(action="SUPPRESSION_REMOVED", actor=actor, old=rec)
            STATE.bump()
        return 200, {"ok": True}


def _parse_ts(value):
    """ISO-8601 (with or without Z / offset; naive = local time) or epoch → epoch seconds, else None."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value).strip().replace("Z", "+00:00")).timestamp()
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return None


def suppression_for(alert, suppressions):
    """Id of the first active suppression matching this alert, else None."""
    dom = str(alert.get("domain") or "").lower().rstrip(".")
    ip = str(alert.get("client_ip") or "")
    rule = str(alert.get("rule_name") or "")
    for s in suppressions:
        v = s.get("value") or ""
        if s["field"] == "domain" and dom and (dom == v or dom.endswith("." + v)):
            return s["id"]
        if s["field"] == "client_ip" and ip == v:
            return s["id"]
        if s["field"] == "rule" and rule.lower() == v:
            return s["id"]
    return None


STORE = Store()


# ──────────────────────────────────────────────────────────────
# SOC-tool exporters (Elasticsearch / syslog CEF / webhook)
# ──────────────────────────────────────────────────────────────
def _export_config():
    # re-read the file so an edited config takes effect without a restart
    raw = read_json(STORE_FILES["config"]) or {}
    return exporters.merged_config(raw.get("records") if isinstance(raw, dict) else {})


SECRET_FIELD_NAMES = ("api_key", "secret", "token", "password")


def redact_deep(obj):
    """Copy of obj with every secret-looking field replaced by *** (any depth)."""
    if isinstance(obj, dict):
        return {k: ("***" if k in SECRET_FIELD_NAMES and v else redact_deep(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_deep(v) for v in obj]
    return obj


def _redacted_config():
    return exporters.redact(_export_config())


def _export_items():
    mgmt_all = STORE.all_alert_mgmt()
    version = model_info().get("model_version")
    items = []
    for a in _live_alerts():
        fp = fp_hex(a)
        items.append((fp, exporters.to_ecs(a, fp, mgmt_all.get(fp), version)))
    return items


EXPORTS = exporters.ExportManager(_export_config, _export_items, STORE_DIR / "export_state.json",
                                  on_change=lambda: STATE.bump())


def export_status():
    return EXPORTS.status()


def load_alerts(force=False):
    """Reload the alert file when it changed. Marks alerts never seen before."""
    try:
        mtime = ALERTS.stat().st_mtime
    except OSError:
        return
    if not force and mtime == STATE.alerts_mtime:
        return
    data = read_json(ALERTS)
    if not data:
        return
    now = time.time()
    with STATE.lock:
        first_run = not STATE.baseline_loaded
        for a in data.get("alerts", []):
            fp = fingerprint(a)
            if fp not in STATE.first_seen:
                # alerts present at startup are the baseline, not "new"
                STATE.first_seen[fp] = 0 if first_run else now
            a["_first_seen"] = STATE.first_seen[fp]
        STATE.baseline_loaded = True
        STATE.alerts_mtime = mtime
        STATE.alerts_data = data
        STATE.bump()


def _max_psi(monitoring):
    vals = [m.get("psi") for m in ((monitoring or {}).get("drift") or {}).values()
            if isinstance(m, dict) and isinstance(m.get("psi"), (int, float))]
    return round(max(vals), 4) if vals else None


def record_history():
    d = STATE.alerts_data or {}
    sev = d.get("alerts_by_severity", {})
    monitoring = None if STATE.mode == "demo" else read_json(MONITOR)
    STATE.history.append({
        "t": time.time(),
        "total": d.get("total_alerts", 0),
        "high": sev.get("High", 0),
        "medium": sev.get("Medium", 0),
        "queries": d.get("total_queries_analyzed", 0),
        "max_psi": _max_psi(monitoring),
        "retrain_recommended": (monitoring or {}).get("retrain_recommended"),
    })
    del STATE.history[:-HISTORY_LIMIT]


# ──────────────────────────────────────────────────────────────
# Model information (what produced the ML scores on each alert)
# ──────────────────────────────────────────────────────────────
_MODEL_CACHE = {"sig": None, "info": None}


def _path_b_type(models_dir, name, thr):
    declared = (thr or {}).get("model_type")
    if declared:
        return {"iforest": "IsolationForest", "trafficformer": "Transformer autoencoder"}.get(declared, declared)
    if (models_dir / f"{name}_iforest.pkl").exists():
        return "IsolationForest"
    if any((models_dir / f"{name}{s}").exists() for s in (".keras", ".h5")):
        return "Transformer autoencoder"
    return None


def model_info(models_dir=None):
    """Summary of the deployed models, read from the JSON files training writes. Cached by mtime."""
    models_dir = Path(models_dir or MODELS)
    names = ("dns_threshold.json", f"{PATH_B_MODEL}_threshold.json", "fusion_lr.json",
             "training_metadata.json", "training_provenance.json", "evaluation_metrics.json")
    sig = []
    for n in names:
        try:
            sig.append((n, (models_dir / n).stat().st_mtime))
        except OSError:
            sig.append((n, None))
    sig = tuple(sig) + (str(models_dir),)
    if _MODEL_CACHE["sig"] == sig and _MODEL_CACHE["info"] is not None:
        info = dict(_MODEL_CACHE["info"])
    else:
        thr_a = read_json(models_dir / "dns_threshold.json") or {}
        thr_b = read_json(models_dir / f"{PATH_B_MODEL}_threshold.json") or {}
        fusion = read_json(models_dir / "fusion_lr.json") or {}
        meta = read_json(models_dir / "training_metadata.json") or {}
        prov = read_json(models_dir / "training_provenance.json") or {}
        evalm = read_json(models_dir / "evaluation_metrics.json") or {}
        ident = json.dumps({"a": thr_a, "b": thr_b, "f": fusion, "trained": meta.get("last_trained"),
                            "n": meta.get("total_samples")}, sort_keys=True, default=str)
        info = {
            "models_dir": str(models_dir),
            "model_version": hashlib.sha256(ident.encode("utf-8")).hexdigest()[:12] if (thr_a or meta) else None,
            "path_a": {"model_type": "RandomForest", "threshold": thr_a.get("threshold"),
                       "decision": thr_a.get("decision"), "fpr_budget": thr_a.get("fpr_budget"),
                       "n_features": len(thr_a.get("features") or []) or None,
                       "val_recall": thr_a.get("val_recall"), "val_fpr": thr_a.get("val_fpr"),
                       "dataset_version": (thr_a.get("dataset_version") or "")[:16] or None,
                       "split": thr_a.get("split")},
            "path_b": {"model_type": _path_b_type(models_dir, PATH_B_MODEL, thr_b),
                       "threshold": thr_b.get("threshold"), "threshold_method": thr_b.get("method"),
                       "window_size": thr_b.get("window_size")},
            "fusion": {"method": "logistic_regression" if fusion else None,
                       "threshold": fusion.get("threshold"), "fpr_budget": fusion.get("fpr_budget"),
                       "inputs": fusion.get("inputs"), "coefficients": fusion.get("coefficients")},
            "training": {k: meta.get(k) for k in ("last_trained", "total_samples", "attack_samples",
                                                  "benign_samples", "attack_types_seen", "retrain_mode")},
            "provenance": {k: prov.get(k) for k in ("merged_at", "total_records")},
            "evaluation_available": bool(evalm),
        }
        _MODEL_CACHE.update(sig=sig, info=dict(info))
    monitoring = read_json(MONITOR) if STATE.mode != "demo" else None
    info["drift"] = {"max_psi": _max_psi(monitoring),
                     "retrain_recommended": (monitoring or {}).get("retrain_recommended"),
                     "reasons": (monitoring or {}).get("reasons") or [],
                     "trained_on": (monitoring or {}).get("trained_on")}
    info["mode"] = STATE.mode
    if STATE.mode == "demo":
        info["note"] = "Demo mode: alert ML scores are synthetic; this block still describes the files in models/."
    return info


# ──────────────────────────────────────────────────────────────
# Analyst feedback → training labels
# ──────────────────────────────────────────────────────────────
FEEDBACK_FIELDS = ("fp", "label", "verdict", "verdict_reason", "verdict_by", "verdict_at", "status",
                   "rule", "severity", "client_ip", "domain", "alert_time", "query_time",
                   "ml_score_A", "ml_score_B", "ml_combined_score", "ml_confidence", "ml_threat_score",
                   "model_version", "in_live_feed", "demo")
VERDICT_TO_LABEL = {"true_positive": 1, "false_positive": 0, "fp_model_logic": 0, "fp_bad_data": 0,
                    "benign_positive": 0, "duplicate": None, "undetermined": None}


def feedback_rows():
    """One row per alert an analyst gave a verdict. label: 1 = attack, 0 = benign, None = not usable."""
    mgmt_all = STORE.all_alert_mgmt()
    live = {fp_hex(a): a for a in _live_alerts()}
    version = model_info().get("model_version")
    rows = []
    for fp, rec in mgmt_all.items():
        if not rec.get("verdict"):
            continue
        a = live.get(fp) or {}
        d = a.get("details") or {}
        rows.append({
            "fp": fp, "label": VERDICT_TO_LABEL.get(rec["verdict"]), "verdict": rec["verdict"],
            "verdict_reason": rec.get("verdict_reason"), "verdict_by": rec.get("verdict_by"),
            "verdict_at": rec.get("verdict_at"), "status": rec.get("status"),
            "rule": a.get("rule_name") or rec.get("rule_name"), "severity": a.get("severity") or rec.get("severity"),
            "client_ip": a.get("client_ip"), "domain": a.get("domain"),
            "alert_time": a.get("timestamp"), "query_time": a.get("query_time"),
            "ml_score_A": d.get("ml_score_A"), "ml_score_B": d.get("ml_score_B"),
            "ml_combined_score": d.get("ml_combined_score"), "ml_confidence": d.get("ml_confidence"),
            "ml_threat_score": d.get("ml_threat_score"),
            "model_version": version, "in_live_feed": bool(a), "demo": bool(d.get("demo")),
        })
    rows.sort(key=lambda r: r.get("verdict_at") or "")
    return _finite(rows)


def feedback_csv(rows):
    import csv
    import io
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FEEDBACK_FIELDS, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        # neutralise spreadsheet formula injection in free-text cells
        w.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v)
                    for k, v in r.items()})
    return buf.getvalue()


# ──────────────────────────────────────────────────────────────
# Running the pipeline
# ──────────────────────────────────────────────────────────────
def sync_logs(watch_dir):
    """The extractor reads data/raw. Copy new or changed logs there (what run_all.sh does)."""
    src = Path(watch_dir)
    if src.resolve() == RAW.resolve():
        return
    RAW.mkdir(parents=True, exist_ok=True)
    for f in src.glob("*.log"):
        dst = RAW / f.name
        try:
            s, d = f.stat(), (dst.stat() if dst.exists() else None)
            if d is None or s.st_size != d.st_size or s.st_mtime > d.st_mtime:
                shutil.copy2(f, dst)
        except OSError:
            pass


def run_custom(cmd):
    return subprocess.run(cmd, shell=True, cwd=ROOT, capture_output=True, text=True, timeout=900)


def run_pipeline(zscore, custom_cmd):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    DATA.mkdir(parents=True, exist_ok=True)

    with STATE.lock:
        STATE.status, STATE.error, STATE.step = "running", "", "Copy logs"
        STATE.bump()
    t0 = time.time()
    try:
        sync_logs(STATE.watch_dir)
        if custom_cmd:
            with STATE.lock:
                STATE.step = "Custom command"
                STATE.bump()
            r = run_custom(custom_cmd)
            if r.returncode != 0:
                raise RuntimeError("custom command failed:\n" + tail(r.stdout + r.stderr))
        else:
            for name, cmd, fatal in pipeline_steps(zscore):
                with STATE.lock:
                    STATE.step = name
                    STATE.bump()
                r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                                   text=True, timeout=900, encoding="utf-8", errors="replace")
                if r.returncode != 0 and fatal:
                    raise RuntimeError(f"{name} failed:\n" + tail(r.stdout + r.stderr))
        load_alerts(force=True)
        with STATE.lock:
            STATE.status, STATE.step = "idle", ""
            STATE.last_run_at, STATE.last_duration = time.time(), time.time() - t0
            STATE.runs += 1
            record_history()
            STATE.bump()
        EXPORTS.trigger()
    except Exception as e:  # keep the watcher alive, show the reason on the page
        with STATE.lock:
            STATE.status, STATE.step, STATE.error = "error", "", str(e)[-1500:]
            STATE.last_run_at, STATE.last_duration = time.time(), time.time() - t0
            STATE.bump()


def tail(text, n=25):
    return "\n".join(text.strip().splitlines()[-n:])


def log_signature(watch_dir):
    sig = []
    for f in sorted(Path(watch_dir).glob("*.log")):
        try:
            s = f.stat()
            sig.append((f.name, s.st_size, int(s.st_mtime)))
        except OSError:
            pass
    return tuple(sig)


def watch_loop(args):
    # last_run_sig is the log state the newest results were built from.
    # None means "never ran", so the first pass runs the pipeline once.
    prev_sig = log_signature(STATE.watch_dir)
    last_run_sig = prev_sig if args.no_initial_run else None
    last_change = time.time()
    if args.no_initial_run:
        with STATE.lock:
            STATE.status = "idle"
            STATE.bump()
    while True:
        sig = log_signature(STATE.watch_dir)
        if sig != prev_sig:
            prev_sig, last_change = sig, time.time()
        # run once the log has been quiet for `debounce` seconds, so a burst becomes one run
        if sig != last_run_sig and time.time() - last_change >= args.debounce:
            run_pipeline(args.zscore, args.pipeline_cmd)
            last_run_sig = sig     # lines added during the run make sig differ again: one more run
        time.sleep(args.interval)


# ──────────────────────────────────────────────────────────────
# Demo mode: invented alerts so the page can be seen without models
# ──────────────────────────────────────────────────────────────
DEMO_RULES = [
    ("Excessive NXDOMAIN DNS Queries", "Microsoft Sentinel ASIM DNS Solution", ["CommandAndControl"], ["T1568", "T1008"]),
    ("DNS Tunneling Detection", "Project Requirement", ["Exfiltration"], ["T1572", "T1048"]),
    ("Deep Subdomain Detection", "Project Requirement", ["CommandAndControl"], ["T1572"]),
    ("ML Model Attack Detection", "ML Bridge (Path A + Path B)", ["CommandAndControl", "Exfiltration"], ["T1572", "T1568", "T1048"]),
    ("ML High Threat Score", "ML Bridge (combined threat score)", ["CommandAndControl", "Exfiltration"], ["T1572", "T1568"]),
    ("Z-score Statistical Detection - query_length", "NetSleuthXplorer + Microsoft Sentinel", ["Discovery", "CommandAndControl"], ["T1046", "T1568"]),
]
DEMO_CLIENTS = ["192.168.197.135", "192.168.223.132", "10.0.0.14", "172.18.0.2"]
DEMO_DOMAINS = ["x7k2.dns2tcp-key.com", "aGVsbG8gd29ybGQ.daumel.xyz", "apa-www.lab.local",
                "q9z1v8.exfil.example", "a.b.c.d.e.f.lab.local", "mail-ng.lab.local"]


def demo_loop(args):
    rng = random.Random(7)
    alerts = []
    queries = 0
    with STATE.lock:
        STATE.status = "idle"
        STATE.bump()

    def demo_details(sev):
        # synthetic scores shaped like the bridge's output, flagged demo=True everywhere they surface
        a = round(rng.uniform(0.82, 0.999) if sev == "High" else rng.uniform(0.45, 0.85), 4)
        has_b = rng.random() > 0.15
        b = round(rng.uniform(0.5, 3.0), 4) if has_b else None
        comb = round(min(0.9999, 0.55 * a + (0.35 if has_b and b > 1 else 0.1) + rng.uniform(-0.05, 0.05)), 4)
        conf = "HIGH" if comb >= 0.9 else "MEDIUM" if comb >= 0.7 else "LOW"
        return {"demo": True, "ml_score_A": a, "ml_score_B": b, "has_score_B": int(has_b),
                "ml_combined_score": comb, "ml_combined_label": int(comb >= 0.4875),
                "ml_confidence": conf, "ml_threat_score": round(comb * 100, 1),
                "fusion_method": "demo", "query_type": rng.choice(["TXT", "A", "CNAME", "NULL"])}

    def make():
        name, src, tac, tech = rng.choice(DEMO_RULES)
        sev = rng.choices(["High", "Medium"], [0.45, 0.55])[0]
        dom = rng.choice(DEMO_DOMAINS)
        return {
            "alert_id": str(uuid.uuid4()), "timestamp": datetime.now().isoformat(),
            "rule_name": name, "rule_source": src, "severity": sev,
            "client_ip": rng.choice(DEMO_CLIENTS), "domain": dom,
            "details": demo_details(sev), "description": f"Demo alert for {dom} ({rng.randint(1, 999)})",
            "mitre_tactics": tac, "mitre_techniques": tech,
            "investigation_priority": "High" if sev == "High" else "Normal",
            "query_time": datetime.now().isoformat(timespec="seconds"),
        }

    for _ in range(14):
        alerts.append(make())
    queries = 3200
    first = True
    while True:
        if not first:
            queries += rng.randint(40, 160)
            for _ in range(rng.choice([0, 1, 1, 2, 3])):
                alerts.append(make())
        now = time.time()
        with STATE.lock:
            for a in alerts:
                fp = fingerprint(a)
                if fp not in STATE.first_seen:
                    STATE.first_seen[fp] = 0 if first else now
                a["_first_seen"] = STATE.first_seen[fp]
            sev = Counter(a["severity"] for a in alerts)
            STATE.alerts_data = {
                "generated": datetime.now().isoformat(), "total_queries_analyzed": queries,
                "total_alerts": len(alerts), "ml_rules_active": True,
                "alerts_by_rule": dict(Counter(a["rule_name"] for a in alerts)),
                "alerts_by_severity": dict(sev), "alerts": alerts,
            }
            STATE.runs += 1
            STATE.last_run_at, STATE.last_duration = now, 0.4
            record_history()
            STATE.baseline_loaded = True
            STATE.bump()
        EXPORTS.trigger()
        first = False
        time.sleep(max(args.interval, 2.5))


# ──────────────────────────────────────────────────────────────
# API
# ──────────────────────────────────────────────────────────────
def _collection_sources(alerts):
    """Honest 'collection source' signal: unique source_file values seen in alerts
    (from pipeline details) + current data/raw directory listing.
    No invented device inventory."""
    seen = Counter()
    for a in alerts:
        details = a.get("details") or {}
        sf = details.get("source_file")
        if sf:
            seen[sf] += 1
    sources = []
    for name, count in seen.most_common():
        sources.append({"name": name, "event_count": count, "kind": "pipeline-source_file"})
    try:
        for f in sorted(RAW.glob("*.log")):
            try:
                st = f.stat()
                sources.append({
                    "name": f.name,
                    "event_count": seen.get(f.name, 0),
                    "size_bytes": st.st_size,
                    "mtime": st.st_mtime,
                    "kind": "raw-log-file",
                })
            except OSError:
                pass
    except OSError:
        pass
    return sources


def _health_band(pipeline_status, alerts_age, monitoring, has_alerts_file, interval):
    """Transparent rules for health band. Never claims Healthy just because HTTP is up."""
    reasons = []
    if not has_alerts_file:
        return "Unknown", ["No alerts file produced yet"]
    if pipeline_status == "error":
        return "Critical", ["Pipeline reported an error on its last run"]
    if alerts_age is not None and alerts_age > (10 * max(interval, 1.0)):
        reasons.append(f"Alerts file is {int(alerts_age)}s old (>10× poll interval)")
    if monitoring:
        if monitoring.get("retrain_recommended"):
            reasons.append("Monitoring report recommends retraining")
        drift = (monitoring.get("drift") or {})
        for feat, meta in drift.items():
            if isinstance(meta, dict) and meta.get("band") in ("major", "high"):
                reasons.append(f"Drift {meta.get('band')} on {feat} (PSI={meta.get('psi')})")
    if reasons:
        return "Warning", reasons
    return "Healthy", ["Pipeline idle and alerts file is fresh"]


def build_state():
    mgmt_all = STORE.all_alert_mgmt()
    active_sup = STORE.suppressions(active_only=True)
    model_version = model_info().get("model_version")
    integrations_status = export_status()
    with STATE.lock:
        d = STATE.alerts_data or {}
        alerts = list(d.get("alerts", []))
        now = time.time()
        alerts.sort(key=lambda a: (a.get("_first_seen", 0), a.get("timestamp", "")), reverse=True)
        feed = []
        for a in alerts[:FEED_LIMIT]:
            fs = a.get("_first_seen", 0)
            fp = fp_hex(a)
            mgmt = mgmt_all.get(fp)
            feed.append({
                "id": a.get("alert_id"), "fp": fp, "time": a.get("timestamp"), "rule": a.get("rule_name"),
                "source": a.get("rule_source"),
                "severity": a.get("severity"), "client": a.get("client_ip"), "domain": a.get("domain"),
                "description": a.get("description"), "tactics": a.get("mitre_tactics", []),
                "techniques": a.get("mitre_techniques", []),
                "details": a.get("details") or {},
                "query_time": a.get("query_time"),
                "investigation_priority": a.get("investigation_priority"),
                "is_new": bool(fs) and now - fs < 45,
                "management": mgmt,  # None when no record yet
                "suppressed": suppression_for(a, active_sup),
            })
        ips = Counter(a.get("client_ip") for a in alerts if a.get("client_ip") not in (None, "multiple", "unknown"))
        doms = Counter(a.get("domain") for a in alerts if a.get("domain") not in (None, "N/A", "unknown"))
        techs = Counter(t for a in alerts for t in a.get("mitre_techniques", []))
        meta = read_json(METADATA) or {}
        monitoring = read_json(MONITOR)
        try:
            alerts_mtime = ALERTS.stat().st_mtime
            alerts_age = now - alerts_mtime
            has_alerts_file = True
        except OSError:
            alerts_mtime = None
            alerts_age = None
            has_alerts_file = bool(STATE.alerts_data)  # demo mode synthesises in-memory
        # In demo mode we build alerts in memory with no file; treat as fresh
        if STATE.mode == "demo":
            has_alerts_file = bool(STATE.alerts_data)
            alerts_age = 0 if has_alerts_file else None
        band, band_reasons = _health_band(STATE.status, alerts_age, monitoring,
                                          has_alerts_file, STATE.poll_interval)
        sources = _collection_sources(alerts)

        return {
            "version": STATE.version,
            "now": now,
            "mode": STATE.mode,
            "watch_dir": STATE.watch_dir,
            "pipeline": {
                "status": STATE.status, "step": STATE.step, "error": STATE.error,
                "last_run_at": STATE.last_run_at, "last_duration": STATE.last_duration, "runs": STATE.runs,
            },
            "totals": {
                "alerts": d.get("total_alerts", 0),
                "queries": d.get("total_queries_analyzed", 0),
                "by_severity": d.get("alerts_by_severity", {}),
                "by_rule": d.get("alerts_by_rule", {}),
                "ml_active": d.get("ml_rules_active"),
                "generated": d.get("generated"),
                "new_alerts": sum(1 for f in feed if f["is_new"]),
            },
            "top_clients": ips.most_common(6),
            "top_domains": doms.most_common(6),
            "top_techniques": techs.most_common(6),
            "feed": feed,
            "history": STATE.history[-HISTORY_LIMIT:],
            "monitoring": monitoring,
            "models": {k: meta.get(k) for k in ("last_trained", "total_samples", "attack_samples", "benign_samples")},
            "model_version": model_version,
            "integrations": integrations_status,
            "sources": sources,
            "health": {
                "band": band,
                "reasons": band_reasons,
                "pipeline_status": STATE.status,
                "pipeline_last_run_at": STATE.last_run_at,
                "pipeline_last_duration": STATE.last_duration,
                "pipeline_runs": STATE.runs,
                "pipeline_error": STATE.error,
                "alerts_file_mtime": alerts_mtime,
                "alerts_file_age_seconds": alerts_age,
                "has_alerts_file": has_alerts_file,
                "retrain_recommended": (monitoring or {}).get("retrain_recommended") if monitoring else None,
            },
        }


# ──────────────────────────────────────────────────────────────
# Request helpers / routing for management APIs
# ──────────────────────────────────────────────────────────────
MAX_BODY_BYTES = 64 * 1024   # 64 KiB per POST
PAGE_ROUTES = {
    "/": "index.html", "/index.html": "index.html",
    "/soc": "soc.html", "/soc.html": "soc.html",
    "/usecases": "usecases.html", "/usecases.html": "usecases.html",
    "/alerts": "alerts.html", "/alerts.html": "alerts.html",
    "/events": "events.html", "/events.html": "events.html",
    "/devices": "devices.html", "/devices.html": "devices.html",
    "/health": "health.html", "/health.html": "health.html",
    "/incidents": "incidents.html", "/incidents.html": "incidents.html",
    "/triage": "triage.html", "/triage.html": "triage.html",
}

ALERT_FP_RE = re.compile(r"^/api/alerts/([0-9a-f]{8,32})(/[a-z]+)?$")
EVENT_FP_RE = re.compile(r"^/api/events/([0-9a-f]{8,32})$")
INCIDENT_RE = re.compile(r"^/api/incidents/(inc-[0-9a-f]{6,12})(/action)?$")
SUPPRESSION_RE = re.compile(r"^/api/suppressions/(sup-[0-9a-f]{10})/delete$")


def _qfloat(query, key, default, lo, hi):
    try:
        v = float((query.get(key) or [default])[0])
    except (TypeError, ValueError):
        return default
    if v != v:
        return default
    return max(lo, min(hi, v))


def _json_body(req):
    """Read JSON POST body with a size cap. Returns (ok, value|error_dict)."""
    length = req.headers.get("Content-Length")
    if length is None:
        return False, {"error": "Content-Length required"}
    try:
        n = int(length)
    except ValueError:
        return False, {"error": "Content-Length invalid"}
    if n < 0 or n > MAX_BODY_BYTES:
        return False, {"error": f"body must be 0..{MAX_BODY_BYTES} bytes"}
    if n == 0:
        return True, {}
    raw = req.rfile.read(n)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        return False, {"error": f"invalid JSON: {e}"}
    if not isinstance(value, dict):
        return False, {"error": "body must be a JSON object"}
    # keys starting with "_" are internal (e.g. _approved_by set by the four-eyes flow); never from clients
    return True, {k: v for k, v in value.items() if not str(k).startswith("_")}


def _actor(body, default="unknown-analyst"):
    # No login on this localhost tool: only accept actor ids that exist in analysts.json so the
    # audit trail cannot be filled with arbitrary names.
    actor = body.get("actor") if isinstance(body, dict) else None
    if not isinstance(actor, str) or not actor.strip():
        return default
    actor = actor.strip()[:80]
    if not any(a.get("id") == actor for a in STORE.analysts()):
        return default
    return actor


def actor_tier(actor):
    for a in STORE.analysts():
        if a.get("id") == actor:
            return role_tier(a.get("role"))
    return 0


def authorize(actor, perm):
    """None when allowed, else (403, body). Tier comes from the actor's role in analysts.json."""
    need = PERMISSIONS.get(perm, 2)
    have = actor_tier(actor)
    if have >= need:
        return None
    return 403, {"error": f"'{perm}' needs Tier {need}+ (you are acting as {actor}, Tier {have})",
                 "required_tier": need, "actor_tier": have,
                 "note": "Tier guardrails are a workflow control; this dashboard has no login."}


# ──────────────────────────────────────────────────────────────
# Request security (CSRF / DNS-rebinding / headers)
# ──────────────────────────────────────────────────────────────
SECURITY = {
    "allowed_hosts": {"127.0.0.1", "localhost", "::1"},
    "csp_report_only": False,
    "run_min_gap": 10.0,
}
_RUN_GATE = {"last": 0.0, "lock": threading.Lock()}

CSP_TEMPLATE = ("default-src 'self'; script-src 'self' 'nonce-{nonce}'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
BASE_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
)
_SCRIPT_TAG_RE = re.compile(rb"<script(?=[\s>])", re.IGNORECASE)


def _host_name(host_header):
    if not host_header:
        return None
    try:
        return urlparse("//" + host_header.strip()).hostname
    except ValueError:
        return None


def is_training_api(path):
    return path == "/training/api" or path.startswith("/training/api/")


def check_request(method, headers, path=""):
    """Returns None when the request may proceed, else (http_status, error_message)."""
    host = headers.get("Host") or ""
    if _host_name(host) not in SECURITY["allowed_hosts"]:
        return 403, "Host header not allowed"
    if method != "POST":
        return None
    training = is_training_api(path)
    ctype = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
    # the training console uploads datasets (multipart) and sends body-less POSTs (cancel, rollback)
    allowed = ("application/json", "multipart/form-data", "") if training else ("application/json",)
    if ctype not in allowed:
        return 415, "Content-Type must be application/json"
    origin = headers.get("Origin")
    if origin is not None and origin not in (f"http://{host}", f"https://{host}"):
        return 403, "cross-origin request rejected"
    site = headers.get("Sec-Fetch-Site")
    if site is not None and site not in ("same-origin", "none"):
        return 403, "cross-site request rejected"
    if training:
        # its own custom X-Admin-Token header forces a CORS preflight just like X-SOC-Request;
        # the training API then checks the token value itself
        if not headers.get("X-Admin-Token"):
            return 403, "X-Admin-Token header required"
        return None
    if headers.get("X-SOC-Request") != "1":
        return 403, "X-SOC-Request: 1 header required"
    return None


def inject_nonce(html_bytes, nonce):
    return _SCRIPT_TAG_RE.sub(b'<script nonce="' + nonce.encode("ascii") + b'"', html_bytes)


def run_gate_allows(now=None):
    now = time.time() if now is None else now
    with _RUN_GATE["lock"]:
        wait = SECURITY["run_min_gap"] - (now - _RUN_GATE["last"])
        if wait > 0:
            return False, wait
        _RUN_GATE["last"] = now
        return True, 0.0


def _find_alert_by_fp(fp):
    """Locate a live alert dict by its fp_hex in the current alerts_data."""
    with STATE.lock:
        d = STATE.alerts_data or {}
        for a in d.get("alerts", []):
            if fp_hex(a) == fp:
                return a
    return None


def _match_event(a, q):
    """Substring filters for /api/events."""
    def has(field, key):
        v = q.get(key)
        if not v:
            return True
        want = v[0].lower()
        got = str(a.get(field, "") or "").lower()
        return want in got
    if q.get("severity") and (a.get("severity") not in q.get("severity")):
        return False
    if q.get("source") and (a.get("rule_source") not in q.get("source")):
        return False
    if not (has("domain", "domain") and has("client_ip", "ip")
            and has("rule_name", "rule")):
        return False
    if q.get("technique"):
        want = q["technique"][0].lower()
        techs = [str(t).lower() for t in (a.get("mitre_techniques") or [])]
        if not any(want in t for t in techs):
            return False
    if q.get("q"):
        hay = " ".join(str(a.get(k, "") or "") for k in (
            "rule_name", "rule_source", "client_ip", "domain", "description")).lower()
        det = str(a.get("details") or "").lower()
        if q["q"][0].lower() not in hay + " " + det:
            return False
    # Time filtering: from/to as ISO or epoch seconds
    for bound_key, cmp in (("from", lambda x, b: x >= b), ("to", lambda x, b: x <= b)):
        if q.get(bound_key):
            try:
                b = float(q[bound_key][0])
            except ValueError:
                try:
                    b = datetime.fromisoformat(q[bound_key][0].replace("Z", "+00:00")).timestamp()
                except Exception:
                    continue
            ts = a.get("timestamp") or ""
            try:
                x = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                continue
            if not cmp(x, b):
                return False
    return True


def _derive_devices():
    """Honest client-IP + collection-source summary. NOT a device inventory."""
    with STATE.lock:
        alerts = list((STATE.alerts_data or {}).get("alerts", []))
    now = time.time()
    by_ip = {}
    for a in alerts:
        ip = a.get("client_ip")
        if not ip or ip in ("multiple", "unknown"):
            continue
        rec = by_ip.setdefault(ip, {
            "ip": ip, "event_count": 0, "domains": set(),
            "first_seen": None, "last_seen": None,
            "severity": {"High": 0, "Medium": 0, "Low": 0},
            "enriched_dns": None, "enriched_reputation": None,
        })
        rec["event_count"] += 1
        if a.get("domain"):
            rec["domains"].add(a["domain"])
        ts = a.get("timestamp") or ""
        try:
            epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            epoch = a.get("_first_seen") or now
        if rec["first_seen"] is None or epoch < rec["first_seen"]:
            rec["first_seen"] = epoch
        if rec["last_seen"] is None or epoch > rec["last_seen"]:
            rec["last_seen"] = epoch
        sev = a.get("severity")
        if sev in rec["severity"]:
            rec["severity"][sev] += 1
        details = a.get("details") or {}
        if details.get("enriched_dns"):
            rec["enriched_dns"] = details["enriched_dns"]
        if details.get("enriched_reputation"):
            rec["enriched_reputation"] = details["enriched_reputation"]
    out = []
    interval = STATE.poll_interval or 3.0
    for rec in by_ip.values():
        rec["domain_count"] = len(rec["domains"])
        rec.pop("domains", None)
        age = now - (rec["last_seen"] or now)
        if age <= interval * 5:
            rec["status"] = "Active"
        elif age <= interval * 20:
            rec["status"] = "Quiet"
        else:
            rec["status"] = "Unknown"
        out.append(rec)
    out.sort(key=lambda r: r["event_count"], reverse=True)
    return out


OPEN_STATUSES = ("Open", "Acknowledged", "Investigating", "Escalated")


def _stats(values):
    vals = sorted(v for v in values if v is not None and v >= 0)
    if not vals:
        return {"n": 0, "mean": None, "median": None, "p90": None}
    n = len(vals)
    mid = vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2
    return {"n": n, "mean": round(sum(vals) / n, 1), "median": round(mid, 1),
            "p90": round(vals[min(n - 1, int(round(0.9 * (n - 1))))], 1)}


def _live_alerts():
    with STATE.lock:
        return list((STATE.alerts_data or {}).get("alerts", []))


def compute_metrics(hours=24.0):
    """SOC KPIs over alerts detected in the last `hours`.
    MTTD = alert time − DNS query time (pipeline latency); MTTA/MTTR = analyst ack/resolve − alert time.
    Alerts no analyst has touched count as Open."""
    now = time.time()
    cutoff = now - hours * 3600
    mgmt_all = STORE.all_alert_mgmt()
    analysts = {a["id"]: a for a in STORE.analysts()}
    active_sup = STORE.suppressions(active_only=True)
    ttd, tta, ttr = [], [], []
    open_by_sev, status_counts, verdicts = Counter(), Counter(), Counter()
    matrix = {}
    workload = {aid: {"analyst": aid, "name": a.get("name"), "open": 0, "total": 0} for aid, a in analysts.items()}
    sla_breached = 0
    in_window = 0
    suppressed = 0
    escalated = dispositioned = 0
    by_rule = {}
    for a in _live_alerts():
        t_alert = _parse_ts(a.get("timestamp"))
        if t_alert is not None and t_alert < cutoff:
            continue
        in_window += 1
        fp = fp_hex(a)
        rec = mgmt_all.get(fp) or {}
        status = rec.get("status") or "Open"
        sev = a.get("severity") or "Medium"
        status_counts[status] += 1
        if suppression_for(a, active_sup):
            suppressed += 1
        if status in OPEN_STATUSES:
            open_by_sev[sev] += 1
        t_query = _parse_ts(a.get("query_time"))
        if t_alert is not None and t_query is not None:
            ttd.append(t_alert - t_query)
        t_ack = _parse_ts(rec.get("acknowledged_at"))
        t_done = _parse_ts(rec.get("resolved_at")) or _parse_ts(rec.get("closed_at"))
        if t_alert is not None:
            if t_ack is not None:
                tta.append(t_ack - t_alert)
            if t_done is not None:
                ttr.append(t_done - t_alert)
            target = ACK_SLA_SECONDS.get(sev, ACK_SLA_SECONDS["Medium"])
            # acknowledged late, or still unacknowledged and open past the target
            waited = t_ack if t_ack is not None else (now if status in OPEN_STATUSES else None)
            if waited is not None and waited - t_alert > target:
                sla_breached += 1
        if rec.get("verdict"):
            verdicts[rec["verdict"]] += 1
            by_rule.setdefault(a.get("rule_name") or "?", Counter())[rec["verdict"]] += 1
        if rec.get("escalated") or status == "Escalated":
            escalated += 1
        if rec.get("escalated") or rec.get("verdict") or status in ("Resolved", "Closed"):
            dispositioned += 1
        who = rec.get("assigned_to")
        if who:
            w = workload.setdefault(who, {"analyst": who, "name": None, "open": 0, "total": 0})
            w["total"] += 1
            if status in OPEN_STATUSES:
                w["open"] += 1
        for tac in a.get("mitre_tactics") or ["Unmapped"]:
            row = matrix.setdefault(tac, {})
            for tech in a.get("mitre_techniques") or ["—"]:
                row[tech] = row.get(tech, 0) + 1
    judged = sum(verdicts.values())
    fp_n = sum(n for v, n in verdicts.items() if v in FP_VERDICTS)
    rule_rows = []
    for rule, c in by_rule.items():
        tot = sum(c.values())
        rule_rows.append({"rule": rule, "judged": tot, "false_positive": sum(n for v, n in c.items() if v in FP_VERDICTS),
                          "true_positive": c.get("true_positive", 0),
                          "fp_rate": round(sum(n for v, n in c.items() if v in FP_VERDICTS) / tot, 4)})
    rule_rows.sort(key=lambda r: (-r["false_positive"], r["rule"]))
    pending = sum(1 for r in STORE.triage_snapshot()["close_requests"].values() if r.get("status") == "pending")
    return {
        "window_hours": hours,
        "generated_at": _iso_now(),
        "alerts_in_window": in_window,
        "suppressed_in_window": suppressed,
        "mttd_seconds": _stats(ttd),
        "mtta_seconds": _stats(tta),
        "mttr_seconds": _stats(ttr),
        "ack_sla_seconds": ACK_SLA_SECONDS,
        "ack_sla_breached": sla_breached,
        "open_by_severity": dict(open_by_sev),
        "status_counts": dict(status_counts),
        "verdicts": dict(verdicts),
        "false_positive_rate": (round(fp_n / judged, 4) if judged else None),
        "verdicts_by_rule": rule_rows,
        "escalated": escalated,
        "escalation_rate": (round(escalated / dispositioned, 4) if dispositioned else None),
        "pending_close_approvals": pending,
        "workload": sorted(workload.values(), key=lambda w: (-w["open"], w["analyst"])),
        "attack_matrix": matrix,
        "notes": ("MTTD is pipeline latency (alert time minus DNS query time), not attacker dwell time. "
                  "Untouched alerts count as Open."),
    }


def _registered_domain(domain):
    # approximation (no public-suffix list): last two labels
    labels = [l for l in str(domain or "").lower().rstrip(".").split(".") if l]
    return ".".join(labels[-2:]) if len(labels) >= 2 else None


def related_alerts(fp, window=900.0, limit=50):
    alerts = _live_alerts()
    base = next((a for a in alerts if fp_hex(a) == fp), None)
    if base is None:
        return None
    t0 = _parse_ts(base.get("timestamp"))
    ip = base.get("client_ip")
    ip = None if ip in (None, "multiple", "unknown") else ip
    reg = _registered_domain(base.get("domain"))
    out = []
    for a in alerts:
        afp = fp_hex(a)
        if afp == fp:
            continue
        reasons = []
        if ip and a.get("client_ip") == ip:
            reasons.append("same client IP")
        if reg and _registered_domain(a.get("domain")) == reg:
            reasons.append("same registered domain")
        if not reasons:
            continue
        t = _parse_ts(a.get("timestamp"))
        dt = None if (t is None or t0 is None) else t - t0
        if dt is not None and abs(dt) > window:
            continue
        out.append({"fp": afp, "rule": a.get("rule_name"), "severity": a.get("severity"),
                    "client": a.get("client_ip"), "domain": a.get("domain"), "time": a.get("timestamp"),
                    "delta_seconds": None if dt is None else round(dt, 1), "reasons": reasons})
    out.sort(key=lambda r: abs(r["delta_seconds"]) if r["delta_seconds"] is not None else float("inf"))
    return {"fp": fp, "window_seconds": window, "client_ip": ip, "registered_domain": reg,
            "records": out[:limit], "total": len(out),
            "note": "Registered domain = last two labels (no public-suffix list), so treat it as an approximation."}


def handover_report(hours=8.0):
    now = time.time()
    cutoff = now - hours * 3600
    audit = [r for r in STORE.audit(limit=10000) if (_parse_ts(r.get("timestamp")) or 0) >= cutoff]
    mgmt_all = STORE.all_alert_mgmt()
    alerts = {fp_hex(a): a for a in _live_alerts()}
    escalated, unassigned_high = [], []
    for fp, a in alerts.items():
        rec = mgmt_all.get(fp) or {}
        status = rec.get("status") or "Open"
        if status not in OPEN_STATUSES:
            continue
        row = {"fp": fp, "rule": a.get("rule_name"), "severity": a.get("severity"),
               "client": a.get("client_ip"), "domain": a.get("domain"), "status": status,
               "assigned_to": rec.get("assigned_to")}
        if status == "Escalated" or rec.get("escalated"):
            escalated.append(row)
        elif a.get("severity") in ("High", "Critical") and not rec.get("assigned_to"):
            unassigned_high.append(row)
    open_incidents = [{"id": i["id"], "title": i["title"], "severity": i["severity"], "status": i["status"]}
                      for i in STORE.incidents() if i.get("status") != "Closed"]
    return {
        "window_hours": hours,
        "generated_at": _iso_now(),
        "pipeline": {"status": STATE.status, "runs": STATE.runs, "error": STATE.error or None},
        "activity": {"by_action": dict(Counter(r["action"] for r in audit)),
                     "by_actor": dict(Counter(r["actor"] for r in audit))},
        "escalated_open": escalated[:100],
        "unassigned_high_open": unassigned_high[:100],
        "open_incidents": open_incidents,
        "metrics": compute_metrics(hours),
    }


def handover_markdown(rep):
    def md(s):
        if isinstance(s, dict):
            s = ", ".join(f"{k} {v}" for k, v in sorted(s.items())) or "none"
        return str(s if s is not None else "—").replace("|", "\\|").replace("\n", " ")
    m = rep["metrics"]
    lines = [f"# SOC shift handover ({md(rep['generated_at'])}, last {rep['window_hours']:g} h)", "",
             f"- Pipeline: {md(rep['pipeline']['status'])}, {rep['pipeline']['runs']} runs"
             + (f", last error: {md(rep['pipeline']['error'])}" if rep["pipeline"]["error"] else ""),
             f"- Alerts in window: {m['alerts_in_window']} (suppressed {m['suppressed_in_window']}); "
             f"open by severity: {md(m['open_by_severity'])}",
             f"- MTTA median: {md(m['mtta_seconds']['median'])} s; MTTR median: {md(m['mttr_seconds']['median'])} s; "
             f"ack-SLA breaches: {m['ack_sla_breached']}",
             f"- Verdicts: {md(m['verdicts'])}", "",
             "## Escalated, still open", ""]
    rows = rep["escalated_open"] or []
    lines += (["| fp | severity | rule | client | domain | assigned |", "|---|---|---|---|---|---|"]
              + [f"| {r['fp'][:8]} | {md(r['severity'])} | {md(r['rule'])} | {md(r['client'])} | {md(r['domain'])} | {md(r['assigned_to'])} |" for r in rows]
              if rows else ["None."])
    lines += ["", "## High severity, open and unassigned", ""]
    rows = rep["unassigned_high_open"] or []
    lines += (["| fp | rule | client | domain |", "|---|---|---|---|"]
              + [f"| {r['fp'][:8]} | {md(r['rule'])} | {md(r['client'])} | {md(r['domain'])} |" for r in rows]
              if rows else ["None."])
    lines += ["", "## Open incidents", ""]
    lines += ([f"- {md(i['id'])} [{md(i['severity'])}] {md(i['title'])} ({md(i['status'])})" for i in rep["open_incidents"]]
              or ["None."])
    lines += ["", "## Analyst activity", ""]
    lines += ([f"- {md(k)}: {v}" for k, v in sorted(rep["activity"]["by_action"].items())] or ["No actions recorded."])
    return "\n".join(lines) + "\n"


# ──────────────────────────────────────────────────────────────
# Tier 1 triage workbench: cases = groups of alerts (see dashboard/evidence.py)
# ──────────────────────────────────────────────────────────────
TRIAGE_DEFAULTS = {"internal_zones": ["lab.local"], "resolvers": [], "default_group": "source",
                   "tranco_path": str(HERE / "data" / "tranco.csv"), "tranco_top_n": 100000}
ENRICH_DEFAULTS = {"virustotal": {"enabled": False, "api_key": None, "ttl_hours": 24, "min_interval_seconds": 15},
                   "abuseipdb": {"enabled": False, "api_key": None, "ttl_hours": 24, "min_interval_seconds": 2}}
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
STATUS_RANK = {"Open": 0, "Acknowledged": 1, "Investigating": 2, "Escalated": 3, "Resolved": 4, "Closed": 5}
CLOSE_CLASSES = ("true_positive", "benign_positive", "fp_model_logic", "fp_bad_data", "duplicate", "undetermined")
ESCALATION_FIELDS = ("summary", "evidence", "checks_done", "hypothesis", "recommended_action")
REQUIRED_MANUAL = tuple(c[0] for c in evidence.CHECKLIST if c[3])
TRIAGE_CASE_RE = re.compile(r"^/api/triage/case/(c-[0-9a-f]{12})(/[a-z]+)?$")
TRIAGE_REQ_RE = re.compile(r"^/api/triage/requests/(cr-[0-9a-f]{10})/(approve|reject)$")
ENRICH_RE = re.compile(r"^/api/enrich/(domain|ip)/([A-Za-z0-9._:\-]{1,253})$")


def _config_records():
    raw = read_json(STORE_FILES["config"]) or {}
    return raw.get("records") if isinstance(raw, dict) and isinstance(raw.get("records"), dict) else {}


def triage_config():
    user = _config_records().get("triage")
    return {**TRIAGE_DEFAULTS, **(user if isinstance(user, dict) else {})}


def enrichment_config():
    user = _config_records().get("enrichment")
    user = user if isinstance(user, dict) else {}
    return {k: {**v, **(user.get(k) if isinstance(user.get(k), dict) else {})} for k, v in ENRICH_DEFAULTS.items()}


FEATURES = evidence.FeatureIndex(WEEK3_ML)
_TRANCO = {"obj": None}
_CASE_CACHE = {"sig": None, "cases": None, "lock": threading.Lock()}
_EVIDENCE_CACHE = {}
_EVIDENCE_LOCK = threading.Lock()


def tranco():
    cfg = triage_config()
    t = _TRANCO["obj"]
    if t is None or str(t.path) != str(cfg["tranco_path"]) or t.top_n != int(cfg["tranco_top_n"]):
        t = _TRANCO["obj"] = evidence.Tranco(cfg["tranco_path"], cfg["tranco_top_n"])
    return t


ENRICHER = evidence.OnlineEnricher(enrichment_config, STORE.enrich_get, STORE.enrich_put,
                                   lambda: triage_config()["internal_zones"])


def _feature_snapshot():
    return None if STATE.mode == "demo" else FEATURES.get()


def triage_cases(mode):
    """{key: case} for the live alerts, cached per (alert data identity, mode, zones)."""
    zones = tuple(triage_config()["internal_zones"])
    with STATE.lock:
        data = STATE.alerts_data or {}
        alerts = list(data.get("alerts", []))
        sig = (id(data), len(alerts), STATE.alerts_mtime, mode, zones)
    with _CASE_CACHE["lock"]:
        if _CASE_CACHE["sig"] == sig:
            return _CASE_CACHE["cases"]
        cases = evidence.group_alerts([(a, fp_hex(a)) for a in alerts], mode, zones)
        _CASE_CACHE.update(sig=sig, cases=cases)
        return cases


def find_case(key):
    for mode in ("source", "entity"):
        c = triage_cases(mode).get(key)
        if c:
            return c
    return None


def _member_status(mgmt_all, fp):
    return (mgmt_all.get(fp) or {}).get("status") or "Open"


def case_summary(case, mgmt_all, trec, requests, now):
    statuses = [_member_status(mgmt_all, fp) for _, fp in case["items"]]
    open_items = [(a, fp) for (a, fp), st in zip(case["items"], statuses) if st in OPEN_STATUSES]
    req = requests.get(trec.get("close_request_id") or "") if trec.get("close_request_id") else None
    if req and req.get("status") == "pending":
        status = "PendingApproval"
    elif any(st == "Escalated" for st in statuses):
        status = "Escalated"
    elif not open_items:
        status = "Closed"
    else:
        status = min((st for st in statuses if st in OPEN_STATUSES), key=lambda s: STATUS_RANK[s])
    pool = [a for a, _ in open_items] or [a for a, _ in case["items"]]
    priority = max((a.get("severity") or "Medium" for a in pool), key=lambda s: SEV_RANK.get(s, 0))
    ml = [x for x in (_finite_num((a.get("details") or {}).get("ml_combined_score")) for a in pool) if x is not None]
    start = max(_parse_ts(trec.get("first_seen_at")) or now, _parse_ts(trec.get("closed_at")) or 0)
    claimed = _parse_ts(trec.get("claimed_at"))
    ack_target = ACK_SLA_SECONDS.get(priority, ACK_SLA_SECONDS["Medium"])
    tri_target = TRIAGE_SLA_SECONDS.get(priority, TRIAGE_SLA_SECONDS["Medium"])
    done = status in ("Closed", "Escalated", "PendingApproval")
    ack_due, tri_due = start + ack_target, start + tri_target
    # ack clock stops at the claim; triage clock stops at close / escalate / close request
    ack_breached = (claimed > ack_due) if claimed is not None else (not done and now > ack_due)
    tri_breached = (not done) and now > tri_due
    return {
        "key": case["key"], "mode": case["mode"], "client": case["client"], "group": case["group"],
        "label": case["label"], "rules": sorted({a.get("rule_name") for a, _ in case["items"]}),
        "priority": priority, "members": len(case["items"]), "open_members": len(open_items),
        "status": status, "owner": trec.get("claimed_by"), "claimed_at": trec.get("claimed_at"),
        "first_seen_at": trec.get("first_seen_at"), "sla_start": start,
        "ack_due": ack_due, "triage_due": tri_due, "ack_met": claimed is not None and claimed <= ack_due,
        "ack_breached": ack_breached, "triage_breached": tri_breached,
        "ml_max": round(max(ml), 4) if ml else None,
        "next_step": trec.get("next_step"),
        "pending_close": ({"id": req["id"], "classification": req["classification"],
                           "requested_by": req["requested_by"]} if req and req.get("status") == "pending" else None),
        "source_flags": evidence.ip_flags(case["client"], triage_config()["resolvers"]),
        "checklist_manual": {k: bool((trec.get("checklist") or {}).get(k, {}).get("checked")) for k in REQUIRED_MANUAL},
    }


def _finite_num(v):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if x == x and x not in (float("inf"), float("-inf")) else None


def case_detail_evidence(case):
    """Evidence + checklist + ML for one case; cached per (case, members, feature-file load)."""
    snap = _feature_snapshot()
    cfg = triage_config()
    sig = (case["key"], len(case["items"]), (snap or {}).get("loaded_at"), tuple(cfg["internal_zones"]),
           tuple(cfg["resolvers"]), STATE.mode)
    with _EVIDENCE_LOCK:
        hit = _EVIDENCE_CACHE.get(case["key"])
        if hit and hit[0] == sig:
            return hit[1]
    rows = evidence.case_rows(snap, case, cfg["internal_zones"])
    ev = evidence.case_evidence(case, rows, demo=STATE.mode == "demo")
    ipf = evidence.ip_flags(case["client"], cfg["resolvers"])
    tr = tranco()
    tr_ok = tr.available()
    apexes = Counter(evidence.case_apex(a.get("domain"), cfg["internal_zones"])
                     for a, _ in case["items"] if evidence.has_domain(a.get("domain")))
    top_apex = apexes.most_common(1)[0][0] if apexes else None
    tr_hit = tr.rank(top_apex) if (tr_ok and top_apex) else None
    rep = None
    if top_apex:
        look = ENRICHER.lookup("domain", top_apex)
        if look.get("status") == "ok":
            rep = {"result": look.get("result"), "detail": look.get("detail")}
        elif look.get("status") in ("pending", "not_sent", "error"):
            rep = {"result": None, "detail": f"{look['provider']}: {look['status']}"
                                             + (f" ({look.get('detail')})" if look.get("detail") else "")}
    auto = evidence.auto_checklist(case, ev, rows, ipf, tr_hit, tr_ok, rep)
    mi = model_info()
    ml = evidence.ml_panel(case, rows, snap, thresholds={"path_a": mi["path_a"].get("threshold"),
                                                          "fusion": mi["fusion"].get("threshold")},
                           demo=STATE.mode == "demo")
    sug = evidence.suggestion(auto, ml)
    pivots = {"top_domains": [{"apex": k, "alerts": v} for k, v in apexes.most_common(8)]}
    if snap and case["mode"] == "entity" and case["group"] not in ("nxdomain", "(no domain)"):
        hosts = Counter()
        apex = case["group"]
        for (ip, dom), rs in snap["by_pair"].items():
            if dom == apex or dom.endswith("." + apex):
                hosts[ip] += len(rs)
        pivots["domain_hosts"] = [{"client": ip, "queries": n} for ip, n in hosts.most_common(20)]
    out = {"evidence": ev, "auto": auto, "ml": ml, "suggestion": sug, "ip": ipf, "pivots": pivots,
           "tranco_available": tr_ok, "top_apex": top_apex}
    with _EVIDENCE_LOCK:
        _EVIDENCE_CACHE[case["key"]] = (sig, out)
        if len(_EVIDENCE_CACHE) > 3000:
            _EVIDENCE_CACHE.clear()
    return out


def _checklist_view(auto, trec):
    manual = trec.get("checklist") or {}
    items, done = [], 0
    for cid, label, kind, required in evidence.CHECKLIST:
        a = auto.get(cid) or {}
        m = manual.get(cid) or {}
        complete = bool(m.get("checked")) or (kind != "manual" and a.get("result") is not None)
        done += 1 if complete else 0
        items.append({"id": cid, "label": label, "kind": kind, "required": required,
                      "auto": None if kind == "manual" else {"result": a.get("result"), "detail": a.get("detail")},
                      "checked": bool(m.get("checked")), "by": m.get("by"), "at": m.get("at"), "note": m.get("note")})
    return items, done, len(evidence.CHECKLIST)


def triage_queue(mode, actor=None, mine=False, status=None, severity=None, q=None, offset=0, limit=100):
    cases = triage_cases(mode)
    trecs = STORE.triage_touch([(k, mode) for k in cases])
    snap = STORE.triage_snapshot()
    mgmt_all = STORE.all_alert_mgmt()
    now = time.time()
    rows = [case_summary(c, mgmt_all, trecs.get(k) or {}, snap["close_requests"], now) for k, c in cases.items()]
    counts = {"total": len(rows),
              "by_status": dict(Counter(r["status"] for r in rows)),
              "by_severity": dict(Counter(r["priority"] for r in rows if r["status"] not in ("Closed",))),
              "mine": sum(1 for r in rows if actor and r["owner"] == actor and r["status"] not in ("Closed",)),
              "unassigned": sum(1 for r in rows if not r["owner"] and r["status"] in ("Open", "Acknowledged", "Investigating")),
              "sla_breached": sum(1 for r in rows if r["triage_breached"] or (r["ack_breached"] and not r["owner"])),
              "pending_approval": sum(1 for r in rows if r["status"] == "PendingApproval"),
              "alerts": sum(r["members"] for r in rows)}
    if mine and actor:
        rows = [r for r in rows if r["owner"] == actor]
    if status == "open":
        rows = [r for r in rows if r["status"] not in ("Closed",)]
    elif status:
        rows = [r for r in rows if r["status"] == status]
    if severity:
        rows = [r for r in rows if r["priority"] == severity]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in (r["client"] + " " + str(r["group"]) + " " + r["label"] + " " +
                                          " ".join(str(x) for x in r["rules"])).lower()]
    closed_last = lambda r: 1 if r["status"] == "Closed" else 0
    rows.sort(key=lambda r: (closed_last(r), -SEV_RANK.get(r["priority"], 0), r["triage_due"], -r["members"]))
    page = rows[offset:offset + limit]
    for r in page:   # checklist progress only for the visible page (evidence is computed lazily)
        det = case_detail_evidence(cases[r["key"]])
        _, done, total = _checklist_view(det["auto"], trecs.get(r["key"]) or {})
        r["checklist_done"], r["checklist_total"] = done, total
        r["suggestion"] = det["suggestion"]["action"]
    return {"now": now, "group": mode, "counts": counts, "total": len(rows), "offset": offset, "limit": limit,
            "cases": page, "sla": {"ack_seconds": ACK_SLA_SECONDS, "triage_seconds": TRIAGE_SLA_SECONDS},
            "mode": STATE.mode}


def allowed_actions(summary, actor):
    tier = actor_tier(actor)
    st = summary["status"]
    closed = st == "Closed"
    pending = summary["pending_close"]
    owner = summary["owner"]
    l2 = st == "Escalated"      # escalated cases belong to Tier 2+
    acts = {
        "claim": tier >= (2 if l2 else 1) and not closed and (owner is None or (owner != actor and tier >= 2)),
        "release": not closed and owner is not None and (owner == actor or tier >= 2),
        "checklist": tier >= 1 and not closed,
        "close": tier >= (2 if l2 else 1) and not closed and not pending,
        "escalate": tier >= 1 and st not in ("Closed", "Escalated") and not pending,
        "approve": tier >= 2 and bool(pending) and pending["requested_by"] != actor,
        "fp_needs_approval": tier < 2 and summary["priority"] in HIGH_SEVERITIES,
        "suppress": tier >= 2,
    }
    return [k for k, v in acts.items() if v]


def triage_case_view(key, actor=None, offset=0, limit=50):
    case = find_case(key)
    if not case:
        return None
    trecs = STORE.triage_touch([(key, case["mode"])])
    trec = trecs[key]
    snap = STORE.triage_snapshot()
    mgmt_all = STORE.all_alert_mgmt()
    summary = case_summary(case, mgmt_all, trec, snap["close_requests"], time.time())
    det = case_detail_evidence(case)
    checklist, done, total = _checklist_view(det["auto"], trec)
    summary["checklist_done"], summary["checklist_total"] = done, total
    members = []
    items = sorted(case["items"], key=lambda it: (-SEV_RANK.get(it[0].get("severity"), 0), str(it[0].get("domain"))))
    for a, fp in items[offset:offset + limit]:
        m = mgmt_all.get(fp) or {}
        d = a.get("details") or {}
        members.append({"fp": fp, "rule": a.get("rule_name"), "severity": a.get("severity"),
                        "domain": a.get("domain"), "query_time": a.get("query_time"),
                        "status": m.get("status") or "Open", "verdict": m.get("verdict"),
                        "ml_combined_score": _finite_num(d.get("ml_combined_score")),
                        "description": str(a.get("description") or "")[:240]})
    host_cases = []
    for other in triage_cases(case["mode"]).values():
        if other["client"] == case["client"] and other["key"] != key:
            host_cases.append({"key": other["key"], "label": other["label"], "members": len(other["items"])})
    pivots = dict(det["pivots"], host_cases=sorted(host_cases, key=lambda x: -x["members"])[:20])
    esc = [snap["escalations"][e] for e in trec.get("escalation_ids") or [] if e in snap["escalations"]]
    req = snap["close_requests"].get(trec.get("close_request_id") or "")
    history = [r for r in STORE.audit(limit=10000)
               if isinstance(r.get("new_value"), dict) and r["new_value"].get("case_key") == key][:100]
    return {"case": summary, "members": members, "members_total": len(case["items"]),
            "evidence": det["evidence"], "checklist": checklist, "ml": det["ml"], "suggestion": det["suggestion"],
            "source": det["ip"], "pivots": pivots, "escalations": esc, "close_request": req,
            "history": history, "allowed_actions": allowed_actions(summary, actor),
            "actor": actor, "actor_tier": actor_tier(actor) if actor else None,
            "close_classes": CLOSE_CLASSES, "escalation_fields": ESCALATION_FIELDS,
            "tranco_available": det["tranco_available"], "top_apex": det["top_apex"],
            "guardrail_note": "Tier guardrails are a workflow control; this dashboard has no login."}


def _open_fps(case):
    mgmt_all = STORE.all_alert_mgmt()
    return [fp for _, fp in case["items"] if _member_status(mgmt_all, fp) in OPEN_STATUSES]


def _hints(case):
    return {fp: a for a, fp in case["items"]}


def _text(body, key, max_bytes=NOTE_MAX_BYTES, min_len=1):
    v = body.get(key)
    if isinstance(v, list):
        v = "\n".join(f"- {str(x).strip()}" for x in v if str(x).strip())
    if not isinstance(v, str) or len(v.strip()) < min_len:
        return None, f"{key} is required" + (f" (at least {min_len} characters)" if min_len > 1 else "")
    if len(v.encode("utf-8")) > max_bytes:
        return None, f"{key} exceeds {max_bytes} bytes"
    return v.strip(), None


def triage_action(key, action, body):
    """POST /api/triage/case/{key}/{action}. Returns (http_status, body)."""
    case = find_case(key)
    if not case:
        return 404, {"error": "case not found (alerts may have aged out)"}
    actor = _actor(body)
    STORE.triage_touch([(key, case["mode"])])
    snap = STORE.triage_snapshot()
    trec = snap["cases"][key]
    summary = case_summary(case, STORE.all_alert_mgmt(), trec, snap["close_requests"], time.time())
    open_fps = _open_fps(case)

    if action == "claim":
        denied = authorize(actor, "claim")
        if denied:
            return denied
        owner = trec.get("claimed_by")
        if owner and owner != actor:
            if not body.get("force"):
                return 409, {"error": f"already claimed by {owner}", "owner": owner}
            denied = authorize(actor, "force_claim")
            if denied:
                return denied
        if summary["status"] == "Closed":
            return 409, {"error": "case is closed"}
        if summary["status"] == "Escalated" and actor_tier(actor) < 2:
            return 403, {"error": "escalated cases are worked by Tier 2+", "required_tier": 2}
        res = STORE.apply_case_action(open_fps, [("acknowledge", {}), ("assign", {"analyst_id": actor})], actor, key,
                                      hints=_hints(case), audit_action="CASE_CLAIM")
        now = _iso_now()

        def upd(r):
            c = r["cases"][key]
            c["claimed_by"], c["claimed_at"] = actor, c.get("claimed_at") if c.get("claimed_by") == actor else now
        STORE.triage_update(upd)
        EXPORTS.trigger()
        return 200, {"ok": True, "claimed_by": actor, "members": res}

    if action == "release":
        owner = trec.get("claimed_by")
        if not owner:
            return 409, {"error": "case is not claimed"}
        if owner != actor:
            denied = authorize(actor, "force_claim")
            if denied:
                return denied
        next_step, _ = _text(body, "next_step")
        res = STORE.apply_case_action(open_fps, [("assign", {"analyst_id": None})], actor, key,
                                      hints=_hints(case), audit_action="CASE_RELEASE", audit_note=next_step)

        def upd(r):
            c = r["cases"][key]
            c["claimed_by"], c["claimed_at"] = None, None
            if next_step:
                c["next_step"] = next_step
        STORE.triage_update(upd)
        return 200, {"ok": True, "members": res}

    if action == "checklist":
        denied = authorize(actor, "checklist")
        if denied:
            return denied
        item = body.get("item_id")
        if item not in {c[0] for c in evidence.CHECKLIST}:
            return 400, {"error": "unknown checklist item"}
        note = body.get("note")
        if note is not None and (not isinstance(note, str) or len(note.encode("utf-8")) > NOTE_MAX_BYTES):
            return 400, {"error": "note invalid or too large"}
        entry = {"checked": bool(body.get("checked")), "by": actor, "at": _iso_now(), "note": (note or "").strip() or None}

        def upd(r):
            r["cases"][key].setdefault("checklist", {})[item] = entry
        STORE.triage_update(upd, audit={"action": "CASE_CHECKLIST", "actor": actor,
                                        "new": {"case_key": key, "item": item, "checked": entry["checked"]},
                                        "note": entry["note"]})
        return 200, {"ok": True, "item": item, "entry": entry}

    if action in ("close", "escalate"):
        denied = authorize(actor, "case_close" if action == "close" else "case_escalate")
        if denied:
            return denied
        if summary["status"] == "Closed":
            return 409, {"error": "case is already closed"}
        if summary["pending_close"]:
            return 409, {"error": "a close request is waiting for Tier 2 approval"}
        if summary["status"] == "Escalated" and actor_tier(actor) < 2:
            return 403, {"error": "escalated cases are worked by Tier 2+", "required_tier": 2}
        missing = [k for k in REQUIRED_MANUAL if not ((trec.get("checklist") or {}).get(k) or {}).get("checked")]
        if missing:
            labels = {c[0]: c[1] for c in evidence.CHECKLIST}
            return 400, {"error": "complete the required checklist items first",
                         "missing": [{"id": m, "label": labels[m]} for m in missing]}

    if action == "close":
        cls = body.get("classification")
        if cls not in CLOSE_CLASSES:
            return 400, {"error": f"classification must be one of {CLOSE_CLASSES}"}
        comment, err = _text(body, "comment", min_len=10)
        if err:
            return 400, {"error": err}
        if cls in FP_VERDICTS and summary["priority"] in HIGH_SEVERITIES and actor_tier(actor) < 2:
            rid = "cr-" + uuid.uuid4().hex[:10]
            req = {"id": rid, "case_key": key, "classification": cls, "comment": comment,
                   "requested_by": actor, "requested_at": _iso_now(), "status": "pending",
                   "member_fps": open_fps, "decided_by": None, "decided_at": None, "decision_note": None,
                   "priority": summary["priority"], "label": case["label"], "client": case["client"]}

            def upd(r):
                r["close_requests"][rid] = req
                r["cases"][key]["close_request_id"] = rid
            STORE.triage_update(upd, audit={"action": "CASE_CLOSE_REQUESTED", "actor": actor,
                                            "new": {"case_key": key, "request_id": rid, "classification": cls,
                                                    "members": len(open_fps)}, "note": comment})
            return 202, {"ok": True, "pending_approval": True, "close_request": req,
                         "message": "High/Critical false-positive closures need a Tier 2 approval (four-eyes)."}
        return _close_case(key, case, open_fps, cls, comment, actor)

    if action == "escalate":
        fields = {}
        for f in ESCALATION_FIELDS:
            val, err = _text(body, f, min_len=3)
            if err:
                return 400, {"error": err, "required": list(ESCALATION_FIELDS)}
            fields[f] = val
        eid = "esc-" + uuid.uuid4().hex[:10]
        rec = dict(fields, id=eid, case_key=key, actor=actor, ts=_iso_now(), member_fps=open_fps,
                   priority=summary["priority"], label=case["label"], client=case["client"])
        res = STORE.apply_case_action(open_fps, [("escalate", {"reason": f"case {key} escalation {eid}"})],
                                      actor, key, hints=_hints(case), audit_action="CASE_ESCALATE",
                                      audit_note=fields["summary"][:500])

        def upd(r):
            r["escalations"][eid] = rec
            c = r["cases"][key]
            c.setdefault("escalation_ids", []).append(eid)
            c["claimed_by"], c["claimed_at"] = None, None     # back in the queue for Tier 2
            c["next_step"] = "Tier 2: " + fields["recommended_action"][:200]
        STORE.triage_update(upd)
        EXPORTS.trigger()
        return 200, {"ok": True, "escalation": rec, "members": res}

    return 404, {"error": "unknown action"}


def _close_case(key, case, fps, cls, comment, actor, approved_by=None, request_id=None):
    payload = {"verdict": cls, "reason": comment}
    if approved_by:
        payload["_approved_by"] = approved_by
    res = STORE.apply_case_action(fps, [("verdict", payload), ("status", {"status": "Closed"})], actor, key,
                                  hints=_hints(case), audit_note=comment,
                                  audit_action="CASE_CLOSE_APPROVED" if approved_by else "CASE_CLOSE")
    now = _iso_now()

    def upd(r):
        c = r["cases"][key]
        c["closed_at"], c["closed_by"], c["classification"] = now, actor, cls
        c["claimed_by"], c["claimed_at"] = None, None
        c["close_request_id"] = None
        if request_id and request_id in r["close_requests"]:
            r["close_requests"][request_id].update(status="approved", decided_by=approved_by, decided_at=now)
    STORE.triage_update(upd)
    EXPORTS.trigger()
    return 200, {"ok": True, "closed": True, "classification": cls, "members": res}


def triage_decide(rid, decision, body):
    actor = _actor(body)
    denied = authorize(actor, "approve")
    if denied:
        return denied
    snap = STORE.triage_snapshot()
    req = snap["close_requests"].get(rid)
    if not req:
        return 404, {"error": "close request not found"}
    if req["status"] != "pending":
        return 409, {"error": f"request already {req['status']}"}
    if req["requested_by"] == actor:
        return 403, {"error": "four-eyes: the requester cannot approve their own close request"}
    note = body.get("note") if isinstance(body.get("note"), str) else None
    case = find_case(req["case_key"])
    if decision == "approve":
        if not case:
            return 409, {"error": "the case is no longer in the live feed"}
        mgmt_all = STORE.all_alert_mgmt()
        fps = [fp for fp in req["member_fps"] if _member_status(mgmt_all, fp) in OPEN_STATUSES]
        code, resp = _close_case(req["case_key"], case, fps, req["classification"],
                                 req["comment"] + (f"\n[approved by {actor}: {note}]" if note else f"\n[approved by {actor}]"),
                                 actor, approved_by=actor, request_id=rid)
        return code, dict(resp, request_id=rid, decision="approved")
    now = _iso_now()

    def upd(r):
        r["close_requests"][rid].update(status="rejected", decided_by=actor, decided_at=now, decision_note=note)
        c = r["cases"].get(req["case_key"])
        if c and c.get("close_request_id") == rid:
            c["close_request_id"] = None
    STORE.triage_update(upd, audit={"action": "CASE_CLOSE_REJECTED", "actor": actor,
                                    "new": {"case_key": req["case_key"], "request_id": rid}, "note": note})
    return 200, {"ok": True, "request_id": rid, "decision": "rejected"}


def triage_requests(status="pending"):
    reqs = list(STORE.triage_snapshot()["close_requests"].values())
    if status:
        reqs = [r for r in reqs if r.get("status") == status]
    return sorted(reqs, key=lambda r: r.get("requested_at") or "", reverse=True)


def triage_me(actor, hours=8.0):
    cutoff = time.time() - hours * 3600
    rows = [r for r in STORE.audit(limit=10000)
            if r.get("actor") == actor and (_parse_ts(r.get("timestamp")) or 0) >= cutoff]
    acts = Counter(r["action"] for r in rows)
    snap = STORE.triage_snapshot()
    ttas = []
    for r in rows:
        if r["action"] == "CASE_CLAIM":
            k = (r.get("new_value") or {}).get("case_key")
            c = snap["cases"].get(k) or {}
            t0, t1 = _parse_ts(c.get("first_seen_at")), _parse_ts(r.get("timestamp"))
            if t0 and t1 and t1 >= t0:
                ttas.append(t1 - t0)
    owned = [k for k, c in snap["cases"].items() if c.get("claimed_by") == actor]
    return {"actor": actor, "tier": actor_tier(actor), "window_hours": hours,
            "claimed": acts.get("CASE_CLAIM", 0),
            "closed": acts.get("CASE_CLOSE", 0) + acts.get("CASE_CLOSE_APPROVED", 0),
            "close_requested": acts.get("CASE_CLOSE_REQUESTED", 0),
            "escalated": acts.get("CASE_ESCALATE", 0),
            "approved": acts.get("CASE_CLOSE_APPROVED", 0), "rejected": acts.get("CASE_CLOSE_REJECTED", 0),
            "alert_actions": sum(v for k, v in acts.items() if not k.startswith("CASE_")),
            "mtta_seconds": _stats(ttas), "open_owned": len(owned)}


def triage_handover(hours=8.0):
    rep = handover_report(hours)
    mode = triage_config()["default_group"]
    q = triage_queue(mode if mode in ("source", "entity") else "source", status="open", limit=200)
    rep["open_cases"] = [{"key": c["key"], "label": c["label"], "client": c["client"], "priority": c["priority"],
                          "status": c["status"], "owner": c["owner"], "next_step": c["next_step"],
                          "members": c["members"], "triage_breached": c["triage_breached"]} for c in q["cases"]]
    rep["pending_close_requests"] = triage_requests("pending")[:50]
    acks = STORE.triage_snapshot()["handover_acks"]
    rep["last_ack"] = acks[-1] if acks else None
    return rep


def triage_handover_ack(body):
    actor = _actor(body)
    denied = authorize(actor, "handover_ack")
    if denied:
        return denied
    note = body.get("note") if isinstance(body.get("note"), str) else ""
    if len(note.encode("utf-8")) > NOTE_MAX_BYTES:
        return 400, {"error": "note too large"}
    entry = {"actor": actor, "ts": _iso_now(), "note": note.strip() or None,
             "report_generated_at": body.get("report_generated_at") if isinstance(body.get("report_generated_at"), str) else None}

    def upd(r):
        r["handover_acks"].append(entry)
        del r["handover_acks"][:-200]
    STORE.triage_update(upd, audit={"action": "HANDOVER_ACKNOWLEDGED", "actor": actor, "new": entry})
    return 200, {"ok": True, "ack": entry}


def enrich(kind, value):
    cfg = triage_config()
    if kind == "domain":
        value = value.lower().rstrip(".")
        tr = tranco()
        ok = tr.available()
        return {"kind": kind, "value": value,
                "offline": {"internal": evidence.is_internal(value, cfg["internal_zones"]),
                            "apex": evidence.case_apex(value, cfg["internal_zones"]),
                            "tranco": tr.rank(value) if ok else None, "tranco_available": ok},
                "online": ENRICHER.lookup("domain", value)}
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return {"kind": kind, "value": value, "offline": evidence.ip_flags(value, cfg["resolvers"]),
            "online": ENRICHER.lookup("ip", value)}


def _safe_static(rel):
    """Resolve a /static/... request safely to a file inside HERE/static."""
    base = (HERE / "static").resolve()
    target = (base / rel.lstrip("/\\")).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        return None
    if not target.is_file():
        return None
    return target


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _security_headers(self):
        for k, v in BASE_SECURITY_HEADERS:
            self.send_header(k, v)

    def send(self, code, body, ctype, extra_headers=()):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, raw):
        nonce = secrets.token_urlsafe(16)
        csp_name = ("Content-Security-Policy-Report-Only" if SECURITY["csp_report_only"]
                    else "Content-Security-Policy")
        self.send(200, inject_nonce(raw, nonce), "text/html; charset=utf-8",
                  extra_headers=((csp_name, CSP_TEMPLATE.format(nonce=nonce)),))

    def _guarded(self, method):
        bad = check_request(method, self.headers, urlparse(self.path).path)
        if bad is None:
            return True
        code, msg = bad
        if method == "POST":
            # drain the body so the connection is left in a sane state
            try:
                n = min(int(self.headers.get("Content-Length") or 0), MAX_BODY_BYTES)
                if n > 0:
                    self.rfile.read(n)
            except ValueError:
                pass
        self.send_json(code, {"error": msg})
        return False

    def send_json(self, code, obj):
        body = json.dumps(_finite(obj), default=str, allow_nan=False).encode("utf-8")
        self.send(code, body, "application/json; charset=utf-8")

    def send_405(self, allow):
        self.send_response(405)
        self.send_header("Allow", allow)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()

    def proxy_training_api(self):
        if TRAINING_API_PORT is None:
            self.send_json(503, {"detail": "Training API is not available"})
            return

        parsed = urlparse(self.path)
        target = parsed.path[len("/training"):] or "/"
        if parsed.query:
            target += "?" + parsed.query
        length_header = self.headers.get("Content-Length")
        if length_header is None and self.headers.get("Transfer-Encoding"):
            self.send_json(411, {"detail": "Content-Length is required"})
            return
        try:
            remaining = int(length_header or 0)
        except ValueError:
            self.send_json(400, {"detail": "Invalid Content-Length"})
            return
        if remaining < 0:
            self.send_json(400, {"detail": "Invalid Content-Length"})
            return

        connection = http.client.HTTPConnection("127.0.0.1", TRAINING_API_PORT, timeout=TRAINING_PROXY_TIMEOUT)
        try:
            connection.putrequest(self.command, target, skip_accept_encoding=True)
            hop_by_hop = {
                "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                "te", "trailer", "transfer-encoding", "upgrade",
            }
            for name, value in self.headers.items():
                if name.lower() != "host" and name.lower() not in hop_by_hop:
                    connection.putheader(name, value)
            connection.endheaders()
            while remaining:
                chunk = self.rfile.read(min(1024 * 1024, remaining))
                if not chunk:
                    # The browser cancelled or lost the upload: nobody is left to answer.
                    self.close_connection = True
                    return
                try:
                    connection.send(chunk)
                except OSError:
                    # The training API answered early (e.g. rejected the upload) and closed its side.
                    # Stop forwarding and relay its answer below.
                    self.close_connection = True
                    break
                remaining -= len(chunk)

            response = connection.getresponse()
            body = response.read()
            self._send_quietly(response.status, body, response.getheader("Content-Type", "application/json"))
        except (OSError, http.client.HTTPException) as exc:
            self._send_quietly(502, json.dumps({"detail": f"Training API request failed: {exc}"}).encode(),
                               "application/json; charset=utf-8")
        finally:
            connection.close()

    def _send_quietly(self, code, body, ctype):
        """Send a response, but don't print a traceback if the browser has already gone away."""
        try:
            self.send(code, body, ctype)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    # ── GET ────────────────────────────────────────────────────
    def do_GET(self):
        if not self._guarded("GET"):
            return
        url = urlparse(self.path)
        path = url.path
        query = parse_qs(url.query) if url.query else {}

        if path in ("/training", "/training/"):
            try:
                page = (TRAINING_GUI / "api" / "static" / "index.html").read_bytes()
            except OSError:
                self.send(500, b"Training console page not found", "text/plain")
                return
            self.send(200, page, "text/html; charset=utf-8")
            return

        if path == "/training/api" or path.startswith("/training/api/"):
            self.proxy_training_api()
            return

        # HTML pages
        if path in PAGE_ROUTES:
            page = PAGE_ROUTES[path]
            try:
                self.send_html((HERE / page).read_bytes())
            except OSError:
                self.send(500, f"dashboard/{page} not found".encode(), "text/plain")
            return

        # Static assets
        if path.startswith("/static/"):
            target = _safe_static(path[len("/static/"):])
            if not target:
                self.send(404, b"not found", "text/plain")
                return
            ctype, _ = mimetypes.guess_type(str(target))
            if ctype is None:
                ctype = "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
                ctype += "; charset=utf-8"
            self.send(200, target.read_bytes(), ctype)
            return

        if path == "/api/state":
            # version changes on every data/management change; the 30 s bucket lets time-derived
            # fields (is_new, alert-file age in the health band) refresh even when nothing was written
            etag = f'"v{STATE.version}-{int(time.time() // 30)}"'
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "no-cache")
                self._security_headers()
                self.end_headers()
                return
            body = json.dumps(_finite(build_state()), default=str, allow_nan=False).encode("utf-8")
            self.send(200, body, "application/json; charset=utf-8", extra_headers=(("ETag", etag),))
            return

        if path == "/api/analysts":
            self.send_json(200, {"records": STORE.analysts(), "authenticated": False})
            return

        if path == "/api/alerts":
            self.send_json(200, self._list_alerts(query))
            return

        m = ALERT_FP_RE.match(path)
        if m:
            fp, sub = m.group(1), m.group(2)
            if sub == "/related":
                rel = related_alerts(fp, window=_qfloat(query, "window", 900.0, 1.0, 7 * 86400.0))
                if rel is None:
                    self.send_json(404, {"error": "alert not in the current feed", "fp": fp})
                else:
                    self.send_json(200, rel)
                return
            if sub:
                self.send(404, b"not found", "text/plain")
                return
            self.send_json(200, self._one_alert(fp))
            return

        if path == "/api/metrics":
            self.send_json(200, compute_metrics(_qfloat(query, "hours", 24.0, 0.25, 24 * 90.0)))
            return

        if path == "/api/reports/handover":
            rep = handover_report(_qfloat(query, "hours", 8.0, 0.25, 24 * 14.0))
            if (query.get("format") or ["json"])[0] == "md":
                self.send(200, handover_markdown(rep), "text/markdown; charset=utf-8",
                          extra_headers=(("Content-Disposition",
                                          'attachment; filename="soc_handover.md"'),))
            else:
                self.send_json(200, rep)
            return

        if path.startswith("/api/triage/") or path.startswith("/api/enrich/"):
            self._triage_get(path, query)
            return

        if path == "/api/model":
            self.send_json(200, model_info())
            return

        if path == "/api/feedback/export":
            rows = feedback_rows()
            fmt = (query.get("format") or ["json"])[0]
            if fmt == "csv":
                self.send(200, feedback_csv(rows), "text/csv; charset=utf-8",
                          extra_headers=(("Content-Disposition", 'attachment; filename="feedback_labels.csv"'),))
            elif fmt == "ndjson":
                body = "".join(json.dumps(r, default=str) + "\n" for r in rows)
                self.send(200, body, "application/x-ndjson; charset=utf-8",
                          extra_headers=(("Content-Disposition", 'attachment; filename="feedback_labels.ndjson"'),))
            else:
                self.send_json(200, {"records": rows, "total": len(rows),
                                     "labels": {"1": "attack (true_positive)",
                                                "0": "benign (false_positive / benign_positive)",
                                                "null": "duplicate: not used for training"}})
            return

        if path == "/api/integrations":
            self.send_json(200, {"status": export_status(), "config": _redacted_config(),
                                 "triage": triage_config(), "enrichment": redact_deep(enrichment_config())})
            return

        if path == "/api/suppressions":
            self.send_json(200, {"records": STORE.suppressions(),
                                 "note": "Suppressions hide alerts in this UI only; detection rules still fire."})
            return

        if path == "/api/events":
            self.send_json(200, self._list_events(query))
            return

        m = EVENT_FP_RE.match(path)
        if m:
            fp = m.group(1)
            self.send_json(200, self._one_event(fp))
            return

        if path == "/api/devices":
            self.send_json(200, {
                "clients": _derive_devices(),
                "sources": _collection_sources(list((STATE.alerts_data or {}).get("alerts", []))),
                "disclaimer": (
                    "This project does not ship a device-agent inventory. "
                    "Hostname/OS/last-seen are not available from DNS logs alone. "
                    "Fields below are derived from DNS query client IPs and pipeline source_file only."
                ),
            })
            return

        if path == "/api/health":
            s = build_state()
            self.send_json(200, {"health": s["health"], "monitoring": s["monitoring"],
                                 "pipeline": s["pipeline"], "history": s["history"][-30:],
                                 "mode": s["mode"], "watch_dir": s["watch_dir"]})
            return

        if path == "/api/usecases":
            self.send_json(200, {
                "preferences": STORE.get_usecase_prefs(),
                "note": ("Dashboard Visibility toggles affect only this UI. "
                         "They do not disable detection rules in the pipeline."),
            })
            return

        if path == "/api/incidents":
            self.send_json(200, {"records": STORE.incidents(),
                                 "integrations": redact_deep(
                                     {k: v for k, v in STORE.integrations().items() if isinstance(v, dict)})})
            return

        m = INCIDENT_RE.match(path)
        if m and not m.group(2):
            inc = STORE.incident(m.group(1))
            if not inc:
                self.send_json(404, {"error": "incident not found"})
                return
            self.send_json(200, {"record": inc})
            return

        if path == "/api/audit":
            limit = 200
            try:
                if query.get("limit"):
                    limit = max(1, min(1000, int(query["limit"][0])))
            except ValueError:
                pass
            fp = query.get("alert_fp", [None])[0]
            inc = query.get("incident_id", [None])[0]
            self.send_json(200, {"records": STORE.audit(alert_fp=fp, incident_id=inc, limit=limit),
                                 "authenticated": False})
            return

        if path == "/api/run":
            self.send_405("POST")
            return

        self.send(404, b"not found", "text/plain")

    # ── POST ───────────────────────────────────────────────────
    def do_POST(self):
        if not self._guarded("POST"):
            return
        url = urlparse(self.path)
        path = url.path

        if path == "/training/api" or path.startswith("/training/api/"):
            self.proxy_training_api()
            return

        if path == "/api/run":
            self._run_request()
            return

        m = ALERT_FP_RE.match(path)
        if m:
            fp, action_path = m.group(1), m.group(2)
            if not action_path:
                self.send_405("POST")
                return
            action = action_path.lstrip("/")
            self._alert_action(fp, action)
            return

        if path == "/api/alerts/bulk":
            self._alerts_bulk()
            return

        if path == "/api/usecases/preferences":
            self._usecase_pref()
            return

        if path.startswith("/api/triage/"):
            self._triage_post(path)
            return

        if path == "/api/incidents":
            self._create_incident()
            return

        if path == "/api/suppressions":
            ok, body = _json_body(self)
            if not ok:
                self.send_json(400, body)
                return
            actor = _actor(body)
            code, resp = STORE.add_suppression(body.get("field"), body.get("value"), body.get("until"),
                                               body.get("reason"), actor,
                                               check=lambda: authorize(actor, "suppress"))
            self.send_json(code, resp)
            return

        m = SUPPRESSION_RE.match(path)
        if m:
            ok, body = _json_body(self)
            if not ok:
                self.send_json(400, body)
                return
            actor = _actor(body)
            denied = authorize(actor, "suppress")
            code, resp = denied if denied else STORE.remove_suppression(m.group(1), actor)
            self.send_json(code, resp)
            return

        m = INCIDENT_RE.match(path)
        if m and m.group(2) == "/action":
            self._incident_action(m.group(1))
            return

        self.send(404, b"not found", "text/plain")

    # ── Tier 1 triage ──────────────────────────────────────────
    def _triage_get(self, path, query):
        qs = lambda k, d=None: (query.get(k) or [d])[0]
        actor = qs("actor")
        if actor and not any(a.get("id") == actor for a in STORE.analysts()):
            actor = "unknown-analyst"
        try:
            offset = max(0, int(qs("offset", "0")))
            limit = max(1, min(500, int(qs("limit", "100"))))
        except ValueError:
            offset, limit = 0, 100
        if path == "/api/triage/queue":
            group = qs("group") or triage_config()["default_group"]
            if group not in ("source", "entity"):
                self.send_json(400, {"error": "group must be source or entity"})
                return
            etag = (f'"t{STATE.version}-{int(time.time() // 30)}-{group}-{actor}-{qs("mine")}-{qs("status")}-'
                    f'{qs("severity")}-{hashlib.sha1(str(qs("q")).encode()).hexdigest()[:6]}-{offset}-{limit}"')
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self._security_headers()
                self.end_headers()
                return
            body = triage_queue(group, actor=actor, mine=qs("mine") in ("1", "true"), status=qs("status"),
                                severity=qs("severity"), q=qs("q"), offset=offset, limit=limit)
            self.send(200, json.dumps(_finite(body), default=str, allow_nan=False),
                      "application/json; charset=utf-8", extra_headers=(("ETag", etag),))
            return
        m = TRIAGE_CASE_RE.match(path)
        if m and not m.group(2):
            view = triage_case_view(m.group(1), actor=actor, offset=offset, limit=min(limit, 200))
            if view is None:
                self.send_json(404, {"error": "case not found (alerts may have aged out)"})
            else:
                self.send_json(200, view)
            return
        if path == "/api/triage/requests":
            self.send_json(200, {"records": triage_requests(qs("status", "pending") or None)})
            return
        if path == "/api/triage/me":
            if not actor:
                self.send_json(400, {"error": "actor query parameter required"})
                return
            self.send_json(200, triage_me(actor, _qfloat(query, "hours", 8.0, 0.25, 24 * 7.0)))
            return
        if path == "/api/triage/handover":
            self.send_json(200, triage_handover(_qfloat(query, "hours", 8.0, 0.25, 24 * 14.0)))
            return
        m = ENRICH_RE.match(path)
        if m:
            res = enrich(m.group(1), m.group(2))
            if res is None:
                self.send_json(400, {"error": "invalid IP address"})
            else:
                self.send_json(200, res)
            return
        self.send(404, b"not found", "text/plain")

    def _triage_post(self, path):
        ok, body = _json_body(self)
        if not ok:
            self.send_json(400, body)
            return
        m = TRIAGE_CASE_RE.match(path)
        if m and m.group(2):
            code, resp = triage_action(m.group(1), m.group(2).lstrip("/"), body)
        elif TRIAGE_REQ_RE.match(path):
            m = TRIAGE_REQ_RE.match(path)
            code, resp = triage_decide(m.group(1), m.group(2), body)
        elif path == "/api/triage/handover/ack":
            code, resp = triage_handover_ack(body)
        else:
            code, resp = 404, {"error": "not found"}
        self.send_json(code, resp)

    # ── per-endpoint helpers ───────────────────────────────────
    def _run_request(self):
        ok, body = _json_body(self)
        if not ok:
            self.send_json(400, body)
            return
        allowed, wait = run_gate_allows()
        if not allowed:
            self.send(429, json.dumps({"error": "a run was requested recently",
                                       "retry_after_seconds": round(wait, 1)}),
                      "application/json; charset=utf-8",
                      extra_headers=(("Retry-After", str(max(1, int(wait + 0.999)))),))
            return
        actor = _actor(body)
        with STORE.lock:
            STORE._append_audit(action="PIPELINE_RUN_REQUESTED", actor=actor,
                                new={"mode": STATE.mode})
        RUN_REQUESTS.set()
        self.send_json(200, {"ok": True})

    def _list_alerts(self, query):
        s = build_state()
        feed = s["feed"]
        who = (query.get("assigned_to") or [None])[0]
        if who:
            feed = [f for f in feed if (f.get("management") or {}).get("assigned_to") == who]
        if (query.get("include_suppressed") or ["1"])[0] in ("0", "false", "no"):
            feed = [f for f in feed if not f.get("suppressed")]
        sort = (query.get("sort") or [None])[0]
        if sort == "severity":
            rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            feed = sorted(feed, key=lambda f: (rank.get(f.get("severity"), 4), -(_parse_ts(f.get("time")) or 0)))
        elif sort == "age":
            feed = sorted(feed, key=lambda f: _parse_ts(f.get("time")) or 0)
        return {"records": feed, "total": len(feed), "feed_limit": FEED_LIMIT,
                "generated": s["totals"].get("generated"), "mode": s["mode"]}

    def _one_alert(self, fp):
        a = _find_alert_by_fp(fp)
        mgmt = STORE.get_alert_mgmt(fp)
        audit = STORE.audit(alert_fp=fp, limit=200)
        if a is None and mgmt is None:
            return {"error": "alert not found", "fp": fp}
        return {
            "fp": fp,
            "alert": (None if a is None else {
                "id": a.get("alert_id"), "time": a.get("timestamp"),
                "rule": a.get("rule_name"), "source": a.get("rule_source"),
                "severity": a.get("severity"), "client": a.get("client_ip"),
                "domain": a.get("domain"), "description": a.get("description"),
                "tactics": a.get("mitre_tactics", []), "techniques": a.get("mitre_techniques", []),
                "details": a.get("details") or {},
                "query_time": a.get("query_time"),
                "investigation_priority": a.get("investigation_priority"),
            }),
            "management": mgmt,
            "audit": audit,
            "note": "alert may be absent if it has aged out of the feed; management record persists.",
        }

    def _list_events(self, query):
        # events are the same alerts but exposed with full details and filters
        with STATE.lock:
            alerts = list((STATE.alerts_data or {}).get("alerts", []))
        filtered = [a for a in alerts if _match_event(a, query)]
        try:
            limit = max(1, min(500, int((query.get("limit") or ["100"])[0])))
            offset = max(0, int((query.get("offset") or ["0"])[0]))
        except ValueError:
            limit, offset = 100, 0
        slice_ = filtered[offset:offset + limit]
        records = []
        for a in slice_:
            d = a.get("details") or {}
            records.append({
                "fp": fp_hex(a),
                "alert_id": a.get("alert_id"),
                "timestamp": a.get("timestamp"),
                "client_ip": a.get("client_ip"),
                "domain": a.get("domain"),
                "query_type": d.get("query_type"),
                "rule": a.get("rule_name"),
                "source": a.get("rule_source"),
                "severity": a.get("severity"),
                "tactics": a.get("mitre_tactics", []),
                "techniques": a.get("mitre_techniques", []),
                "anomaly_score": d.get("zscore"),
                "ml_combined_score": d.get("ml_combined_score"),
                "ml_threat_score": d.get("ml_threat_score"),
                "ml_score_A": d.get("ml_score_A"),
                "ml_score_B": d.get("ml_score_B"),
                "reason": (d.get("reasons") or [None])[0] or a.get("description"),
                "source_file": d.get("source_file"),
                "details": d,
            })
        return {"records": records, "total": len(filtered), "offset": offset, "limit": limit}

    def _one_event(self, fp):
        a = _find_alert_by_fp(fp)
        if a is None:
            return {"error": "event not found", "fp": fp}
        return {
            "fp": fp,
            "event": a,
            "management": STORE.get_alert_mgmt(fp),
            "audit": STORE.audit(alert_fp=fp, limit=50),
        }

    def _alert_action(self, fp, action):
        ok, body = _json_body(self)
        if not ok:
            self.send_json(400, body)
            return
        actor = _actor(body)
        alert_hint = _find_alert_by_fp(fp) or {}
        if action not in ("acknowledge", "assign", "status", "escalate", "notes", "verdict"):
            self.send_json(404, {"error": "unknown action"})
            return
        action_internal = "note" if action == "notes" else action
        denied = authorize(actor, action_internal)
        if denied:
            self.send_json(*denied)
            return
        code, resp = STORE.apply_alert_action(fp, action_internal, body, actor,
                                              alert_hint=alert_hint or None)
        if code == 200:
            EXPORTS.trigger()   # status / verdict changes update the exported documents
        self.send_json(code, resp)

    def _alerts_bulk(self):
        ok, body = _json_body(self)
        if not ok:
            self.send_json(400, body)
            return
        fps = body.get("fps")
        action = body.get("action")
        payload = body.get("payload") or {}
        actor = _actor(body)
        if not isinstance(fps, list) or not fps:
            self.send_json(400, {"error": "fps list required"})
            return
        if action not in VALID_BULK_ACTIONS:
            self.send_json(400, {"error": f"action must be one of {VALID_BULK_ACTIONS}"})
            return
        action_map = {"acknowledge": "acknowledge", "assign": "assign",
                      "status": "status", "escalate": "escalate", "close": "status",
                      "verdict": "verdict"}
        internal = action_map[action]
        denied = authorize(actor, "bulk") or authorize(actor, internal)
        if denied:
            self.send_json(*denied)
            return
        p = {k: v for k, v in (payload if isinstance(payload, dict) else {}).items() if not str(k).startswith("_")}
        if action == "close":
            p["status"] = "Closed"
        fps = [f for f in fps[:200] if isinstance(f, str)]
        live = {fp_hex(a): a for a in _live_alerts()}
        res = STORE.apply_case_action(fps, [(internal, p)], actor, None,
                                      hints={fp: live.get(fp) for fp in fps},
                                      audit_note=p.get("reason"), audit_action="BULK_" + action.upper())
        errors = {f["fp"]: f for f in res["failed"]}
        results = [{"fp": fp, "code": errors[fp]["code"] if fp in errors else 200, "ok": fp not in errors,
                    "error": errors[fp]["error"] if fp in errors else None} for fp in fps]
        EXPORTS.trigger()
        self.send_json(200, {
            "total": len(results),
            "succeeded": sum(1 for r in results if r["ok"]),
            "failed": sum(1 for r in results if not r["ok"]),
            "results": results,
        })

    def _usecase_pref(self):
        ok, body = _json_body(self)
        if not ok:
            self.send_json(400, body)
            return
        actor = _actor(body)
        denied = authorize(actor, "usecase_pref")
        if denied:
            self.send_json(*denied)
            return
        code, resp = STORE.set_usecase_pref(
            rule_name=body.get("rule_name"),
            visibility=body.get("visibility"),
            excluded=body.get("excluded"),
            note=body.get("note"),
            actor=actor,
        )
        self.send_json(code, resp)

    def _create_incident(self):
        ok, body = _json_body(self)
        if not ok:
            self.send_json(400, body)
            return
        actor = _actor(body)
        denied = authorize(actor, "incident_create")
        if denied:
            self.send_json(*denied)
            return
        code, resp = STORE.create_incident(
            alert_fps=body.get("alert_fps") or [],
            title=body.get("title") or "",
            severity=body.get("severity") or "Medium",
            actor=actor,
        )
        self.send_json(code, resp)

    def _incident_action(self, incident_id):
        ok, body = _json_body(self)
        if not ok:
            self.send_json(400, body)
            return
        actor = _actor(body)
        denied = authorize(actor, "incident_action")
        if denied:
            self.send_json(*denied)
            return
        code, resp = STORE.record_incident_action(
            incident_id=incident_id,
            action=body.get("action"),
            payload=body.get("payload") or {},
            actor=actor,
        )
        self.send_json(code, resp)


RUN_REQUESTS = threading.Event()


def start_training_api():
    """Run the training API privately; the dashboard proxies it on its own port."""
    try:
        import uvicorn

        sys.path.insert(0, str(TRAINING_GUI))
        try:
            from api.main import app as training_app
        finally:
            sys.path.remove(str(TRAINING_GUI))
    except ImportError as exc:
        raise RuntimeError(
            "Training console dependencies are missing. Install requirements.txt from the project root."
        ) from exc

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen(128)
    server_socket.setblocking(False)
    port = server_socket.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(
        training_app, host="127.0.0.1", port=port, log_level="error", access_log=False
    ))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [server_socket]}, daemon=True)
    thread.start()

    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=2)
        server_socket.close()
        raise RuntimeError("Training API failed to start; check its dependencies and configuration.")
    return server, thread, server_socket, port


def manual_run_loop(args):
    """The 'Run now' button."""
    while True:
        RUN_REQUESTS.wait()
        RUN_REQUESTS.clear()
        if STATE.status != "running" and not args.demo:
            run_pipeline(args.zscore, args.pipeline_cmd)


def main():
    global TRAINING_API_PORT

    p = argparse.ArgumentParser(description="Live DNS detection dashboard")
    p.add_argument("--watch", default=str(RAW), help="folder with Technitium *.log files (default: data/raw)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--interval", type=float, default=3.0, help="seconds between checks for new log lines")
    p.add_argument("--debounce", type=float, default=5.0, help="wait this long after the last change before running")
    p.add_argument("--zscore", type=float, default=2.0)
    p.add_argument("--no-initial-run", action="store_true", help="show existing results first; run only on change")
    p.add_argument("--pipeline-cmd", default=None, help="replace the built-in pipeline with this shell command (testing)")
    p.add_argument("--demo", action="store_true", help="invented alerts, no models or logs needed")
    p.add_argument("--allow-host", action="append", default=[],
                   help="extra Host header name to accept (repeatable); needed when --host is not loopback")
    p.add_argument("--csp-report-only", action="store_true",
                   help="send CSP as Report-Only (debugging); default enforces it")
    p.add_argument("--require-verdict", action="store_true",
                   help="refuse Resolved/Closed until the analyst records a TP/FP verdict")
    args = p.parse_args()

    WORKFLOW["require_verdict"] = args.require_verdict
    SECURITY["csp_report_only"] = args.csp_report_only
    SECURITY["allowed_hosts"].update(h.strip().lower() for h in args.allow_host if h.strip())
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        if args.host not in ("0.0.0.0", "::"):
            SECURITY["allowed_hosts"].add(args.host.lower())
        sys.stderr.write(
            "WARNING: binding to a non-loopback address. This dashboard has no login; anyone who can "
            "reach this port can change alert state. Use --allow-host for each name clients will use.\n")

    STATE.watch_dir = str(Path(args.watch).resolve())
    STATE.poll_interval = args.interval
    if args.host not in ("127.0.0.1", "localhost", "::1") and os.getenv("ADMIN_TOKEN", "admin") in ("", "admin", "change-me"):
        sys.exit("Set a non-default ADMIN_TOKEN before exposing the dashboard beyond localhost.")
    if args.demo:
        STATE.mode = "demo"
    else:
        if not Path(STATE.watch_dir).is_dir():
            sys.exit(f"Watch folder not found: {STATE.watch_dir}")
        load_alerts(force=True)          # show the last results straight away
        if STATE.alerts_data:
            with STATE.lock:
                record_history()

    try:
        training_server, training_thread, training_socket, TRAINING_API_PORT = start_training_api()
    except RuntimeError as exc:
        sys.exit(str(exc))

    threading.Thread(target=demo_loop if args.demo else watch_loop, args=(args,), daemon=True).start()
    threading.Thread(target=manual_run_loop, args=(args,), daemon=True).start()
    EXPORTS.start()
    ENRICHER.start()

    try:
        srv = ThreadingHTTPServer((args.host, args.port), Handler)
        print(f"Dashboard: http://{args.host}:{args.port}   ({'demo data' if args.demo else 'watching ' + STATE.watch_dir})")
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        if "srv" in locals():
            srv.server_close()
        training_server.should_exit = True
        training_thread.join(timeout=5)
        training_socket.close()


if __name__ == "__main__":
    main()
