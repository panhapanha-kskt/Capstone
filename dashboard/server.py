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
import json
import os
import random
import shlex
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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
def build_state():
    with STATE.lock:
        d = STATE.alerts_data or {}
        alerts = list(d.get("alerts", []))
        now = time.time()
        alerts.sort(key=lambda a: (a.get("_first_seen", 0), a.get("timestamp", "")), reverse=True)
        feed = []
        for a in alerts[:FEED_LIMIT]:
            fs = a.get("_first_seen", 0)
            feed.append({
                "id": a.get("alert_id"), "time": a.get("timestamp"), "rule": a.get("rule_name"),
                "severity": a.get("severity"), "client": a.get("client_ip"), "domain": a.get("domain"),
                "description": a.get("description"), "tactics": a.get("mitre_tactics", []),
                "techniques": a.get("mitre_techniques", []),
                "is_new": bool(fs) and now - fs < 45,
            })
        ips = Counter(a.get("client_ip") for a in alerts if a.get("client_ip") not in (None, "multiple", "unknown"))
        doms = Counter(a.get("domain") for a in alerts if a.get("domain") not in (None, "N/A", "unknown"))
        techs = Counter(t for a in alerts for t in a.get("mitre_techniques", []))
        meta = read_json(METADATA) or {}
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
            "monitoring": read_json(MONITOR),
            "models": {k: meta.get(k) for k in ("last_trained", "total_samples", "attack_samples", "benign_samples")},
        }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            try:
                self.send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            except OSError:
                self.send(500, b"dashboard/index.html not found", "text/plain")
        elif path == "/api/state":
            self.send(200, json.dumps(_finite(build_state()), default=str, allow_nan=False).encode(),
                      "application/json")
        elif path == "/api/run":
            self.send(405, b"POST to /api/run", "text/plain")
        else:
            self.send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path.split("?")[0] == "/api/run":
            RUN_REQUESTS.set()
            self.send(200, b'{"ok":true}', "application/json")
        else:
            self.send(404, b"not found", "text/plain")


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
