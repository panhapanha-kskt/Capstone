#!/usr/bin/env python3
"""
technitium_push_listener.py — real-time receiver for the PushLogger Technitium DNS App.

Technitium polling (copying its log files every few seconds) can miss or merge queries under
heavy concurrent load. infra/technitium-apps/PushLogger/ is a DNS App installed directly into
Technitium that calls out to this listener the instant each query is answered (IDnsQueryLogger -
no interval, no batching). This process must stay running for that to have anywhere to land:
it's a plain HTTP server, not a one-shot script.

Each push is appended to data/raw/<date>.log in Technitium's own native log line format, so
dns_detect.features.extractor.parse_technitium_log_line and the rest of the pipeline need no
changes, and dashboard/server.py (watching data/raw by default) picks up the new line like any
other log write.

Run alongside dashboard/server.py (different port). Normally started for you by
scripts/setup_pushlogger.sh, but can be run directly:

    python3 scripts/technitium_push_listener.py --host 172.20.0.1 --port 8787

--host must be an interface the Technitium container can reach (its docker bridge gateway, e.g.
172.20.0.1 - find yours with `ip addr show`, the br-... interface - not 127.0.0.1). Point the
PushLogger app's "pushUrl" config at http://<that host>:<port>/push.

Auth: a shared secret the PushLogger app config must send back as "token" on every push. Reads
TECHNITIUM_PUSH_TOKEN from the environment or .env, falling back to TECHNITIUM_API_KEY so you
don't need a second secret unless you want one.
"""

import argparse
import json
import os
import re
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
_WRITE_LOCK = threading.Lock()


def _load_dotenv():
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv()
PUSH_TOKEN = os.environ.get("TECHNITIUM_PUSH_TOKEN") or os.environ.get("TECHNITIUM_API_KEY")


def format_log_line(payload):
    """Build the exact line Technitium itself writes, so the extractor parses it unchanged."""
    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, str) or not _TS_RE.match(timestamp):
        return None, "timestamp must be 'YYYY-MM-DD HH:MM:SS'"
    date_str = timestamp[:10]
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return None, "timestamp date is invalid"

    client_ip = str(payload.get("clientIp") or "unknown")
    client_port = payload.get("clientPort") or 0
    protocol = str(payload.get("protocol") or "UDP")
    qname = str(payload.get("qname") or "")
    qtype = str(payload.get("qtype") or "unknown")
    qclass = str(payload.get("qclass") or "IN")
    rcode = str(payload.get("rcode") or "unknown")
    answers = payload.get("answers") or []
    if not isinstance(answers, list):
        return None, "answers must be a list"

    line = (
        f"[{timestamp} Local] [{client_ip}:{client_port}] [{protocol}] "
        f"QNAME: {qname}; QTYPE: {qtype}; QCLASS: {qclass}; RCODE: {rcode}; "
        f"ANSWER: [{', '.join(str(a) for a in answers)}]\n"
    )
    return (date_str, line), None


def append_entry(payload):
    result, err = format_log_line(payload)
    if err:
        return False, err
    date_str, line = result
    RAW.mkdir(parents=True, exist_ok=True)
    target = RAW / f"{date_str}.log"
    with _WRITE_LOCK:
        with open(target, "a", encoding="utf-8") as f:
            f.write(line)
    return True, None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # one line per DNS query is too noisy for the default access log

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.rstrip("/") != "/push":
            self._send(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "invalid JSON"})
            return

        if not PUSH_TOKEN or payload.get("token") != PUSH_TOKEN:
            self._send(403, {"error": "invalid or missing token"})
            return

        ok, err = append_entry(payload)
        if not ok:
            self._send(400, {"error": err})
            return
        self._send(200, {"ok": True})

    def do_GET(self):
        if self.path.rstrip("/") == "/healthz":
            self._send(200, {"ok": True})
            return
        self._send(404, {"error": "not found"})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="0.0.0.0",
                    help="interface to bind (default: all interfaces, for portability)")
    p.add_argument("--port", type=int, default=8787)
    args = p.parse_args()

    if not PUSH_TOKEN:
        print("WARNING: no TECHNITIUM_PUSH_TOKEN or TECHNITIUM_API_KEY set - every push will be "
              "rejected with 403. Set one in .env.")

    RAW.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Listening on http://{args.host}:{args.port}/push -> {RAW}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
