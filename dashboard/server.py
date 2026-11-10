#!/usr/bin/env python3
"""
Live dashboard server for DNS Traffic Anomaly Detection.

What it does
  1. Watches the Technitium log folder for new or changed *.log files.
  2. When something changes, re-runs the same pipeline as scripts/run_pipeline.sh:
       extractor -> ML bridge -> detection engine -> monitoring
  3. Serves the newest results as JSON (/api/state) and the page (/).

It only reads and runs your existing modules. It changes none of them.
Standard library only, so there is nothing extra to install.

Run it where the pipeline already works (needs TensorFlow for the ML bridge):

    python dashboard/server.py
    python dashboard/server.py --watch infra/technitium-elk/data/dns_logs
    python dashboard/server.py --demo          # fake alerts, no models needed

Then open http://127.0.0.1:8000
"""

import argparse
import hashlib
import json
import mimetypes
import os
import random
import re
import shlex
import shutil
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
DATA = ROOT / "data" / "processed"
RAW = ROOT / "data" / "raw"
MODELS = ROOT / "models"

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
    # Path B saves <name>.keras; runs from before Week 3 saved <name>.h5 (path_b_predict loads either).
    path_b_ready = (
        any((MODELS / f"{PATH_B_MODEL}{ext}").exists() for ext in (".keras", ".h5"))
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
STORE_DIR = HERE / "data"
STORE_FILES = {
    "alerts":   STORE_DIR / "alert_management.json",
    "usecases": STORE_DIR / "usecase_preferences.json",
    "incidents": STORE_DIR / "incident_records.json",
    "audit":    STORE_DIR / "audit_log.json",
    "analysts": STORE_DIR / "analysts.json",
    "config":   STORE_DIR / "response_integrations.json",
}
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
VALID_BULK_ACTIONS = ("acknowledge", "assign", "status", "escalate", "close")
VALID_RESPONSE_ACTIONS = (
    "watchlist_ip", "mark_domain", "create_investigation_report",
    "export_evidence", "firewall_block_request", "endpoint_isolation_request",
)
NOTE_MAX_BYTES = 4096

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
            self._cache[key] = self._load(path, default_records=self._default_records(key))
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
            }}
            self._atomic_write(STORE_FILES["config"], self._cache["config"])

    @staticmethod
    def _default_records(key):
        if key in ("audit",):
            return []
        return {}

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
            "notes": [],
            "updated_at": now,
            "created_at": now,
            "last_seen_alert_id": (seed_from_alert or {}).get("alert_id"),
            "rule_name": (seed_from_alert or {}).get("rule_name"),
            "severity": (seed_from_alert or {}).get("severity"),
        }
        self._cache["alerts"]["records"][fp] = rec
        return rec

    def apply_alert_action(self, fp, action, payload, actor, alert_hint=None):
        """Apply a validated management action. Returns (http_status, body_dict).

        action ∈ {status, assign, acknowledge, escalate, note}."""
        with self.lock:
            rec = self.ensure_alert_record(fp, seed_from_alert=alert_hint)
            now = _iso_now()
            old_status = rec["status"]
            audit_entries = []

            if action == "acknowledge":
                if rec["status"] not in ALLOWED_TRANSITIONS and rec["status"] != "Open":
                    return 409, {"error": f"cannot acknowledge from {rec['status']}"}
                if rec["status"] == "Open":
                    rec["status"] = "Acknowledged"
                rec["acknowledged_at"] = rec["acknowledged_at"] or now
                audit_entries.append(("ACKNOWLEDGED", old_status, rec["status"]))

            elif action == "assign":
                new_analyst = payload.get("analyst_id")
                if new_analyst is not None:
                    if not any(a["id"] == new_analyst for a in self._cache["analysts"]["records"]):
                        return 400, {"error": f"unknown analyst {new_analyst}"}
                old_assignee = rec["assigned_to"]
                rec["assigned_to"] = new_analyst
                rec["assigned_at"] = now if new_analyst else None
                audit_entries.append(("ASSIGNED", old_assignee, new_analyst))

            elif action == "status":
                new_status = payload.get("status")
                if new_status not in VALID_STATUSES:
                    return 400, {"error": f"status must be one of {VALID_STATUSES}"}
                if new_status not in ALLOWED_TRANSITIONS.get(old_status, set()) and new_status != old_status:
                    return 409, {
                        "error": f"invalid transition {old_status} → {new_status}",
                        "allowed": sorted(ALLOWED_TRANSITIONS.get(old_status, set())),
                    }
                rec["status"] = new_status
                if new_status == "Resolved":
                    rec["resolved_at"] = now
                elif new_status == "Closed":
                    rec["closed_at"] = now
                elif new_status == "Open" and old_status in ("Resolved", "Closed"):
                    # reopen: clear resolved/closed stamps, keep history in audit
                    rec["resolved_at"] = None
                    rec["closed_at"] = None
                audit_entries.append(("STATUS_CHANGED", old_status, new_status))

            elif action == "escalate":
                if rec["status"] == "Closed":
                    return 409, {"error": "cannot escalate a Closed alert"}
                rec["escalated"] = True
                if rec["status"] != "Escalated":
                    rec["status"] = "Escalated"
                audit_entries.append(("ESCALATED", old_status, rec["status"]))

            elif action == "note":
                text = (payload.get("text") or "").strip()
                if not text:
                    return 400, {"error": "note text required"}
                if len(text.encode("utf-8")) > NOTE_MAX_BYTES:
                    return 400, {"error": f"note exceeds {NOTE_MAX_BYTES} bytes"}
                note = {
                    "id": str(uuid.uuid4()),
                    "text": text,
                    "author": actor,
                    "ts": now,
                }
                rec["notes"].append(note)
                audit_entries.append(("NOTE_ADDED", None, note["id"]))

            else:
                return 400, {"error": f"unknown action {action}"}

            rec["updated_at"] = now
            if alert_hint:
                rec["last_seen_alert_id"] = alert_hint.get("alert_id") or rec.get("last_seen_alert_id")
            self._put_alert_mgmt(fp, rec)
            for act, old, new in audit_entries:
                self._append_audit(alert_fp=fp, action=act, old=old, new=new, actor=actor,
                                   note=payload.get("reason") if action != "note" else payload.get("text"))

            STATE.bump()  # tell pollers something changed
            return 200, {"ok": True, "record": rec}

    # ── analysts ────────────────────────────────────────────────
    def analysts(self):
        with self.lock:
            return list(self._cache["analysts"]["records"])

    # ── audit ───────────────────────────────────────────────────
    def _append_audit(self, action, actor, alert_fp=None, incident_id=None, old=None, new=None, note=None):
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
        self._atomic_write(STORE_FILES["audit"], self._cache["audit"])

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


STORE = Store()


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


def record_history():
    d = STATE.alerts_data or {}
    sev = d.get("alerts_by_severity", {})
    STATE.history.append({
        "t": time.time(),
        "total": d.get("total_alerts", 0),
        "high": sev.get("High", 0),
        "medium": sev.get("Medium", 0),
        "queries": d.get("total_queries_analyzed", 0),
    })
    del STATE.history[:-HISTORY_LIMIT]


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

    def make():
        name, src, tac, tech = rng.choice(DEMO_RULES)
        sev = rng.choices(["High", "Medium"], [0.45, 0.55])[0]
        dom = rng.choice(DEMO_DOMAINS)
        return {
            "alert_id": str(uuid.uuid4()), "timestamp": datetime.now().isoformat(),
            "rule_name": name, "rule_source": src, "severity": sev,
            "client_ip": rng.choice(DEMO_CLIENTS), "domain": dom,
            "details": {}, "description": f"Demo alert for {dom} ({rng.randint(1, 999)})",
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
}

ALERT_FP_RE = re.compile(r"^/api/alerts/([0-9a-f]{8,32})(/[a-z]+)?$")
EVENT_FP_RE = re.compile(r"^/api/events/([0-9a-f]{8,32})$")
INCIDENT_RE = re.compile(r"^/api/incidents/(inc-[0-9a-f]{6,12})(/action)?$")


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
    return True, value


def _actor(body, default="unknown-analyst"):
    actor = body.get("actor") if isinstance(body, dict) else None
    if not isinstance(actor, str) or not actor.strip():
        return default
    return actor.strip()[:80]


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

    def send(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, code, obj):
        body = json.dumps(_finite(obj), default=str, allow_nan=False).encode("utf-8")
        self.send(code, body, "application/json; charset=utf-8")

    def send_405(self, allow):
        self.send_response(405)
        self.send_header("Allow", allow)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    # ── GET ────────────────────────────────────────────────────
    def do_GET(self):
        url = urlparse(self.path)
        path = url.path
        query = parse_qs(url.query) if url.query else {}

        # HTML pages
        if path in PAGE_ROUTES:
            page = PAGE_ROUTES[path]
            try:
                self.send(200, (HERE / page).read_bytes(), "text/html; charset=utf-8")
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
            self.send_json(200, build_state())
            return

        if path == "/api/analysts":
            self.send_json(200, {"records": STORE.analysts(), "authenticated": False})
            return

        if path == "/api/alerts":
            self.send_json(200, self._list_alerts(query))
            return

        m = ALERT_FP_RE.match(path)
        if m:
            fp = m.group(1)
            self.send_json(200, self._one_alert(fp))
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
                                 "integrations": STORE.integrations()})
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
        url = urlparse(self.path)
        path = url.path

        if path == "/api/run":
            RUN_REQUESTS.set()
            self.send_json(200, {"ok": True})
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

        if path == "/api/incidents":
            self._create_incident()
            return

        m = INCIDENT_RE.match(path)
        if m and m.group(2) == "/action":
            self._incident_action(m.group(1))
            return

        self.send(404, b"not found", "text/plain")

    # ── per-endpoint helpers ───────────────────────────────────
    def _list_alerts(self, query):
        s = build_state()
        feed = s["feed"]
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
        if action not in ("acknowledge", "assign", "status", "escalate", "notes"):
            self.send_json(404, {"error": "unknown action"})
            return
        action_internal = "note" if action == "notes" else action
        code, resp = STORE.apply_alert_action(fp, action_internal, body, actor,
                                              alert_hint=alert_hint or None)
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
        results = []
        action_map = {"acknowledge": "acknowledge", "assign": "assign",
                      "status": "status", "escalate": "escalate", "close": "status"}
        p = dict(payload)
        if action == "close":
            p["status"] = "Closed"
        internal = action_map[action]
        for fp in fps[:200]:
            alert_hint = _find_alert_by_fp(fp) or {}
            code, resp = STORE.apply_alert_action(fp, internal, p, actor,
                                                  alert_hint=alert_hint or None)
            results.append({"fp": fp, "code": code, "ok": code == 200,
                            "error": resp.get("error") if code != 200 else None})
        STORE._append_audit(action="BULK_" + action.upper(), actor=actor,
                            new={"count": len(fps), "action": action, "payload": payload})
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
        code, resp = STORE.create_incident(
            alert_fps=body.get("alert_fps") or [],
            title=body.get("title") or "",
            severity=body.get("severity") or "Medium",
            actor=_actor(body),
        )
        self.send_json(code, resp)

    def _incident_action(self, incident_id):
        ok, body = _json_body(self)
        if not ok:
            self.send_json(400, body)
            return
        code, resp = STORE.record_incident_action(
            incident_id=incident_id,
            action=body.get("action"),
            payload=body.get("payload") or {},
            actor=_actor(body),
        )
        self.send_json(code, resp)


RUN_REQUESTS = threading.Event()


def manual_run_loop(args):
    """The 'Run now' button."""
    while True:
        RUN_REQUESTS.wait()
        RUN_REQUESTS.clear()
        if STATE.status != "running" and not args.demo:
            run_pipeline(args.zscore, args.pipeline_cmd)


def main():
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
    args = p.parse_args()

    STATE.watch_dir = str(Path(args.watch).resolve())
    STATE.poll_interval = args.interval
    if args.demo:
        STATE.mode = "demo"
    else:
        if not Path(STATE.watch_dir).is_dir():
            sys.exit(f"Watch folder not found: {STATE.watch_dir}")
        load_alerts(force=True)          # show the last results straight away
        if STATE.alerts_data:
            with STATE.lock:
                record_history()

    threading.Thread(target=demo_loop if args.demo else watch_loop, args=(args,), daemon=True).start()
    threading.Thread(target=manual_run_loop, args=(args,), daemon=True).start()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Dashboard: http://{args.host}:{args.port}   ({'demo data' if args.demo else 'watching ' + STATE.watch_dir})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
