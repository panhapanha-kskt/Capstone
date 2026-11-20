#!/usr/bin/env python3
"""Supervisor for one soc service, plus the helpers scripts/soc.sh calls. Linux/WSL, no root.

    python3 scripts/soc_supervisor.py detector     # supervise push listener + dashboard/server.py
    python3 scripts/soc_supervisor.py learner      # supervise scripts/learner.py
    python3 scripts/soc_supervisor.py status       # what `soc.sh status` prints (exit 0 all running, 3 not)
    python3 scripts/soc_supervisor.py env          # shell variables for soc.sh
    python3 scripts/soc_supervisor.py wait-healthy --timeout 30 detector learner
    python3 scripts/soc_supervisor.py strays [detector|learner]   # leftover processes (exit 1 if any)
    python3 scripts/soc_supervisor.py kill-groups  [detector|learner]

One supervisor per service, so a crash in one can never restart the other. Each supervisor:
  - holds runs/soc/<svc>.supervisor.lock (flock) for its whole life → a second start is refused;
  - starts each child in its own process group (start_new_session) and stops it with
    SIGTERM to the group → stop_timeout_s → SIGKILL to the group (no orphaned pipeline steps);
  - restarts a child that exits or fails its health check, after min(base·2^(n-1), max) seconds;
    n goes back to 0 once the child has been healthy for reset_after_healthy_s;
  - health: dashboard /api/health, listener /healthz, learner = fresh runs/soc/learner.heartbeat;
  - copies each child's output to logs/soc/<child>.log, rotated by size (10 MB x 5 by default);
  - writes runs/soc/state/<child>.json (pid, pgid, uptime, restarts, last exit, backoff, health).
Settings: config/soc.yaml (or $SOC_CONFIG); see src/dns_detect/soc/config.py for env overrides.
"""
import argparse
import contextlib
import datetime
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from dns_detect.soc import config as soc_config  # noqa: E402
from dns_detect.soc import triggers as T  # noqa: E402

SERVICES = ("detector", "learner")
STRAY_PATTERNS = {
    "detector": ("technitium_push_listener.py", "dashboard/server.py", "soc_supervisor.py detector"),
    "learner": ("scripts/learner.py", "train_models.sh", "run_candidate_seeds.sh", "train_new_data.sh",
                "soc_supervisor.py learner"),
}


# ── small helpers ─────────────────────────────────────────────────────────────
def backoff_delay(n, base, cap):
    """Delay before restart number n (1, 2, 3, ...): base, 2·base, 4·base, ... capped at cap."""
    if n <= 0:
        return 0.0
    return float(min(base * (2 ** (n - 1)), cap))


def proc_stat(pid):
    """(state, pgid) of a process, or None."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    rest = raw[raw.rindex(")") + 2:].split()
    return rest[0], int(rest[2])


def proc_cmdline(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def proc_cwd(pid):
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return None


def proc_soc_config(pid):
    """The config file a process runs with (SOC_CONFIG in its environment, else config/soc.yaml), or None
    if its environment can't be read. Used so that a soc started with another config (a test, a demo
    config) is not reported as a stray of this one."""
    try:
        env = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
    except OSError:
        return None
    for item in env:
        if item.startswith(b"SOC_CONFIG=") and len(item) > 11:
            return os.path.realpath(item[11:].decode("utf-8", "replace"))
    return os.path.realpath(ROOT / "config" / "soc.yaml")


def alive(pid):
    st = proc_stat(pid) if pid else None
    return bool(st) and st[0] not in ("Z", "X")


def group_pids(pgid):
    """Live (non-zombie) processes in a process group."""
    out = []
    if not pgid:
        return out
    for d in Path("/proc").glob("[0-9]*"):
        st = proc_stat(d.name)
        if st and st[1] == pgid and st[0] not in ("Z", "X"):
            out.append(int(d.name))
    return out


def stop_group(pgid, timeout, proc=None, say=None):
    """SIGTERM the whole group, wait up to timeout, then SIGKILL what is left. True if nothing is left."""
    if not pgid or not group_pids(pgid):
        if proc is not None:
            with contextlib.suppress(Exception):
                proc.wait(timeout=1)
        return True
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGTERM)
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None:
            proc.poll()                      # reap the direct child so it does not linger as a zombie
        if not group_pids(pgid):
            return True
        time.sleep(0.1)
    if say:
        say(f"group {pgid} did not stop within {timeout:.0f}s: SIGKILL")
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)
    end = time.time() + 5
    while time.time() < end:
        if proc is not None:
            proc.poll()
        if not group_pids(pgid):
            return True
        time.sleep(0.05)
    return not group_pids(pgid)


def lock_busy(path):
    if fcntl is None or not Path(path).exists():
        return False
    with open(path, "a") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(f, fcntl.LOCK_UN)
    return False


def url_hostport(url):
    u = urllib.parse.urlparse(url)
    return u.hostname or "127.0.0.1", u.port or (443 if u.scheme == "https" else 80)


def port_open(url, timeout=1.0):
    try:
        with socket.create_connection(url_hostport(url), timeout=timeout):
            return True
    except OSError:
        return False


def http_ok(url, timeout):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "soc-supervisor"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (local health URL)
            return 200 <= r.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.replace(tmp, path)
    except OSError:
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


class RotatingLog:
    """Append bytes to a file; when it would pass max_bytes, shift file → .1 → ... → .<backups>."""

    def __init__(self, path, max_bytes, backups):
        self.path, self.max_bytes, self.backups = Path(path), int(max_bytes), int(backups)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.f = open(self.path, "ab")

    def _rotate(self):
        self.f.close()
        for i in range(self.backups - 1, 0, -1):
            src = self.path.with_name(f"{self.path.name}.{i}")
            if src.exists():
                with contextlib.suppress(OSError):
                    os.replace(src, self.path.with_name(f"{self.path.name}.{i + 1}"))
        if self.backups > 0:
            with contextlib.suppress(OSError):
                os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))
        else:
            with contextlib.suppress(OSError):
                self.path.unlink()
        self.f = open(self.path, "ab")

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        with self.lock:
            if self.max_bytes > 0 and self.f.tell() + len(data) > self.max_bytes and self.f.tell() > 0:
                self._rotate()
            self.f.write(data)
            self.f.flush()

    def close(self):
        with self.lock:
            with contextlib.suppress(Exception):
                self.f.close()


def child_env(cfg):
    env = dict(os.environ)
    bindir = os.path.dirname(cfg["_python"])
    if bindir:
        env["PATH"] = bindir + os.pathsep + env.get("PATH", "")
        if (Path(bindir).parent / "pyvenv.cfg").is_file():
            env["VIRTUAL_ENV"] = str(Path(bindir).parent)
    env["PYTHONUNBUFFERED"] = "1"
    if cfg.get("_config_file"):
        env["SOC_CONFIG"] = cfg["_config_file"]
    return env


def marker_of(argv):
    """The token that identifies a child in /proc/<pid>/cmdline (its script, else its program)."""
    for a in argv[1:]:
        if a.endswith((".py", ".sh")):
            return Path(a).name
    return Path(argv[0]).name if argv else ""


# ── supervisor ────────────────────────────────────────────────────────────────
class Child:
    def __init__(self, sup, name, argv, health_url, nice):
        self.sup, self.name, self.argv, self.health_url, self.nice = sup, name, argv, health_url, nice
        self.proc = None
        self.pgid = None
        self.started_at = None
        self.restarts = 0
        self.backoff_n = 0
        self.next_start = 0.0
        self.last_exit = None
        self.healthy_since = None
        self.health = None
        self.fails = 0
        self.last_check = 0.0
        self.state = "starting"
        self.note = None
        self.state_file = sup.sd / "state" / f"{name}.json"
        self.log = RotatingLog(sup.ld / f"{name}.log", sup.rot["max_bytes"], sup.rot["backups"])
        self.pump = None

    def check_health(self):
        if self.name == "learner":
            hb = self.sup.sd / "learner.heartbeat"
            try:
                age = time.time() - hb.stat().st_mtime
            except OSError:
                return False
            return age < float(self.sup.cfg["learner"]["heartbeat_stale_s"])
        if self.health_url:
            return http_ok(self.health_url, float(self.sup.cfg["health"]["timeout_s"]))
        return True

    def start(self, now):
        if self.health_url and port_open(self.health_url):
            self.note = f"port {url_hostport(self.health_url)[1]} in use by a process not managed by soc"
            self.sup.say(f"{self.name}: {self.note}; not started")
            self.schedule_restart(now, None, count=False)
            self.state = "port_in_use"
            self.save()
            return
        argv = (["nice", "-n", str(self.nice)] if self.nice > 0 else []) + self.argv
        if self.name == "learner":
            with contextlib.suppress(OSError):
                (self.sup.sd / "learner.heartbeat").unlink()
        try:
            self.proc = subprocess.Popen(argv, cwd=ROOT, env=self.sup.env, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as e:
            self.sup.say(f"{self.name}: cannot start {shlex.join(argv)}: {e}")
            self.schedule_restart(now, None)
            return
        self.pgid = self.proc.pid
        self.started_at = now
        self.healthy_since = None
        self.health = None
        self.fails = 0
        self.last_check = now
        self.state = "running"
        self.note = None
        self.log.write(f"\n===== {datetime.datetime.now():%Y-%m-%d %H:%M:%S} start pid {self.proc.pid}: "
                       f"{shlex.join(argv)}\n")
        self.pump = threading.Thread(target=self._pump, args=(self.proc,), daemon=True)
        self.pump.start()
        self.sup.say(f"{self.name}: started pid {self.proc.pid} (restart #{self.restarts})")
        self.save()

    def _pump(self, proc):
        for line in iter(proc.stdout.readline, b""):
            self.log.write(line)
        with contextlib.suppress(Exception):
            proc.stdout.close()

    def schedule_restart(self, now, rc, count=True):
        if count:
            self.restarts += 1
        self.backoff_n += 1
        bo = self.sup.cfg["restart_backoff"]
        delay = backoff_delay(self.backoff_n, float(bo["base_s"]), float(bo["max_s"]))
        self.next_start = now + delay
        self.state = "backoff"
        return delay

    def exited(self, now, rc, why="exited"):
        stop_group(self.pgid, float(self.sup.stop_timeout), self.proc, self.sup.say)   # leftovers in its group
        self.last_exit = rc
        self.proc = None
        delay = self.schedule_restart(now, rc)
        self.sup.say(f"{self.name}: {why} (exit {rc}); restart #{self.restarts} in {delay:g}s")
        self.save()

    def tick(self, now):
        if self.proc is None:
            if not self.sup.stopping and now >= self.next_start:
                self.start(now)
            return
        rc = self.proc.poll()
        if rc is not None:
            self.exited(now, rc)
            return
        h = self.sup.cfg["health"]
        if now - self.last_check >= float(h["interval_s"]):
            self.last_check = now
            ok = self.check_health()
            in_grace = now - self.started_at < float(h["startup_grace_s"])
            self.health = ok
            if ok:
                self.fails = 0
                if self.healthy_since is None:
                    self.healthy_since = now
            elif not in_grace:
                self.fails += 1
                self.healthy_since = None
                if self.fails >= int(h["fail_threshold"]):
                    self.sup.say(f"{self.name}: health check failed {self.fails}x; restarting")
                    stop_group(self.pgid, float(self.sup.stop_timeout), self.proc, self.sup.say)
                    self.exited(now, self.proc.poll() if self.proc else None, "unhealthy")
                    return
            self.save()
        if self.healthy_since is not None and self.backoff_n and \
                now - self.healthy_since >= float(self.sup.cfg["restart_backoff"]["reset_after_healthy_s"]):
            self.backoff_n = 0
            self.save()

    def stop(self):
        if self.proc is not None:
            stop_group(self.pgid, float(self.sup.stop_timeout), self.proc, self.sup.say)
            with contextlib.suppress(Exception):
                self.last_exit = self.proc.wait(timeout=2)
        self.proc = None
        self.state = "stopped"
        self.save()
        if self.pump is not None:
            self.pump.join(timeout=2)
        self.log.close()

    def save(self):
        write_json(self.state_file, {
            "name": self.name, "service": self.sup.svc, "state": self.state, "note": self.note,
            "pid": self.proc.pid if self.proc else None, "pgid": self.pgid,
            "started_at": self.started_at, "restarts": self.restarts, "last_exit": self.last_exit,
            "backoff_n": self.backoff_n, "next_start_at": self.next_start if self.state == "backoff" else None,
            "health": self.health, "health_url": self.health_url, "healthy_since": self.healthy_since,
            "cmd": self.argv, "marker": marker_of(self.argv), "supervisor_pid": os.getpid(),
            "updated_at": time.time()})


class Supervisor:
    def __init__(self, cfg, svc, foreground=False):
        self.cfg, self.svc, self.foreground = cfg, svc, foreground
        self.sd = soc_config.state_dir(cfg)
        self.ld = soc_config.log_dir(cfg)
        self.rot = cfg["log_rotate"]
        self.stop_timeout = (cfg["learner"] if svc == "learner" else cfg["detector"])["stop_timeout_s"]
        self.stopping = False
        self.env = child_env(cfg)
        self.sd.mkdir(parents=True, exist_ok=True)
        (self.sd / "state").mkdir(exist_ok=True)
        self.ld.mkdir(parents=True, exist_ok=True)
        self.slog = RotatingLog(self.ld / f"supervisor-{svc}.log", self.rot["max_bytes"], self.rot["backups"])
        self.children = []

    def say(self, msg):
        line = f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {self.svc}: {msg}\n"
        self.slog.write(line)
        if self.foreground:
            sys.stderr.write(line)

    def kill_stale(self):
        """Groups recorded by an earlier supervisor that was SIGKILLed: stop them if they are still ours."""
        for f in (self.sd / "state").glob("*.json"):
            st = read_json(f)
            if not st or st.get("service") != self.svc or not st.get("pgid"):
                continue
            pids = group_pids(st["pgid"])
            if pids and any(st.get("marker", "") in proc_cmdline(p) for p in pids):
                self.say(f"stopping leftover group {st['pgid']} of {st.get('name')} from an earlier supervisor")
                stop_group(st["pgid"], float(self.stop_timeout), None, self.say)

    def run(self):
        if fcntl is None:
            print("soc_supervisor.py needs Linux/WSL", file=sys.stderr)
            return 1
        lockf = open(self.sd / f"{self.svc}.supervisor.lock", "a")
        try:
            fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pid = (self.sd / f"{self.svc}.supervisor.pid")
            print(f"{self.svc} supervisor already running (pid {pid.read_text().strip() if pid.exists() else '?'})")
            return 3
        (self.sd / f"{self.svc}.supervisor.pid").write_text(str(os.getpid()))

        def on_term(signum, frame):
            self.stopping = True
        signal.signal(signal.SIGTERM, on_term)
        signal.signal(signal.SIGINT, on_term)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

        self.say(f"supervisor pid {os.getpid()} starting; python {self.cfg['_python']} "
                 f"({self.cfg['_python_source']}); config {self.cfg.get('_config_file') or 'defaults'}")
        self.kill_stale()
        for name, argv, url, nice in soc_config.children(self.cfg, self.svc):
            self.children.append(Child(self, name, argv, url, nice))
        last_save = 0.0
        while not self.stopping:
            now = time.time()
            for c in self.children:
                try:
                    c.tick(now)
                except Exception as e:  # a bug for one child must not take down the other
                    self.say(f"{c.name}: supervisor error {type(e).__name__}: {e}")
            if now - last_save > 5:
                for c in self.children:
                    c.save()
                last_save = now
            time.sleep(0.2)
        self.shutdown()
        with contextlib.suppress(OSError):
            (self.sd / f"{self.svc}.supervisor.pid").unlink()
        fcntl.flock(lockf, fcntl.LOCK_UN)
        lockf.close()
        return 0

    def shutdown(self):
        if self.svc == "learner":
            grace = float(self.cfg["learner"]["promote_grace_s"])
            runs_dir = soc_config.rpath(self.cfg["paths"]["runs_dir"])
            end = time.time() + grace
            if lock_busy(runs_dir / ".promote.lock"):
                self.say(f"a promote is running (runs/.promote.lock); waiting up to {grace:g}s before stopping")
                while time.time() < end and lock_busy(runs_dir / ".promote.lock"):
                    time.sleep(1)
        self.say("stopping children")
        for c in self.children:
            c.stop()
        self.say("stopped")
        self.slog.close()


# ── status and helpers for soc.sh ────────────────────────────────────────────
def fmt_age(sec):
    if sec is None:
        return "-"
    sec = int(max(0, sec))
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    return (f"{d}d" if d else "") + (f"{h}h" if h or d else "") + f"{m}m{s:02d}s"


def supervisor_pid(sd, svc):
    p = Path(sd) / f"{svc}.supervisor.pid"
    try:
        pid = int(p.read_text().strip())
    except (OSError, ValueError):
        return None
    return pid if alive(pid) and "soc_supervisor.py" in proc_cmdline(pid) else None


def supervisor_running(sd, svc):
    return lock_busy(Path(sd) / f"{svc}.supervisor.lock")


def child_states(cfg, svc):
    sd = soc_config.state_dir(cfg)
    out = []
    for name, argv, url, nice in soc_config.children(cfg, svc):
        st = read_json(sd / "state" / f"{name}.json") or {"name": name, "state": "stopped"}
        if not supervisor_running(sd, svc):
            st = dict(st, state="stopped", pid=None)
        elif st.get("state") == "running" and not alive(st.get("pid")):
            st = dict(st, state="exited")
        out.append(st)
    return out


def read_log_rows(path):
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    rows = []
    for line in lines:
        with contextlib.suppress(ValueError):
            row = json.loads(line)
            if isinstance(row, dict):
                rows.append(row)
    return rows


def _file_matches(path, want):
    """'ok', 'eol' (same content, only CRLF/LF differs, e.g. a JSON file rewritten on Windows) or 'diff'."""
    if not isinstance(want, str):
        return "ok"
    if T.sha256_file(path) == want:
        return "ok"
    import hashlib
    data = Path(path).read_bytes()
    if hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest() == want:
        return "eol"
    return "diff"


def live_model(models_dir):
    """(description, verdict) from models/PROMOTED.json, else a sha256 over the model files.
    verdict: True (all listed files match), "eol" (match apart from line endings), False, None (no list)."""
    models_dir = Path(models_dir)
    prom = read_json(models_dir / "PROMOTED.json")
    if isinstance(prom, dict):
        name = prom.get("source_run") or prom.get("name") or prom.get("run") or prom.get("source") \
            or prom.get("label") or "?"
        files = prom.get("files") or prom.get("sha256") or {}
        if isinstance(files, list):
            files = {str(i.get("file") or i.get("path") or i.get("name")): i.get("sha256")
                     for i in files if isinstance(i, dict)}
        verdict = None
        if isinstance(files, dict) and files:
            results = []
            for fn, want in files.items():
                want = want.get("sha256") if isinstance(want, dict) else want
                p = models_dir / fn
                results.append(_file_matches(p, want) if p.is_file() else "diff")
            verdict = False if "diff" in results else ("eol" if "eol" in results else True)
        when = prom.get("promoted_at") or prom.get("time") or ""
        return f"{name} {when}".strip(), verdict
    sys.path.insert(0, str(ROOT / "scripts"))
    import learner as L  # stdlib-only module; reuse its models/ hash
    h = L.hash_models(models_dir)
    return (f"(no models/PROMOTED.json) sha256 of models/ files: {h[:16]}…" if h else "no models/ folder"), None


def status(cfg):
    sd = soc_config.state_dir(cfg)
    now = time.time()
    all_ok = True
    print(f"soc status  ({datetime.datetime.now():%Y-%m-%d %H:%M:%S})   repo {ROOT}")
    print(f"python: {cfg['_python']} ({cfg['_python_source']})   config: {cfg.get('_config_file') or 'defaults'}")
    print(f"{'SERVICE':9} {'CHILD':10} {'STATE':12} {'PID':>7} {'UPTIME':>10} {'RESTARTS':>8} {'LAST EXIT':>9}  HEALTH")
    for svc in SERVICES:
        sup = supervisor_pid(sd, svc)
        running = supervisor_running(sd, svc)
        print(f"{svc:9} {'supervisor':10} {'running' if running else 'stopped':12} {sup or '-':>7}")
        for st in child_states(cfg, svc):
            state = st.get("state", "stopped")
            if state != "running":
                all_ok = False
            up = now - st["started_at"] if state == "running" and st.get("started_at") else None
            if state == "backoff" and st.get("next_start_at"):
                state = f"backoff {max(0, st['next_start_at'] - now):.0f}s"
            health = {True: "ok", False: "FAIL", None: "-"}[st.get("health")]
            print(f"{'':9} {st.get('name', '?'):10} {state:12} {st.get('pid') or '-':>7} {fmt_age(up):>10} "
                  f"{st.get('restarts', 0):>8} {'-' if st.get('last_exit') is None else st.get('last_exit'):>9}  {health}"
                  + (f"  ({st['note']})" if st.get("note") else ""))
        if not running:
            all_ok = False

    runs_dir = soc_config.rpath(cfg["paths"]["runs_dir"])
    rows = read_log_rows(runs_dir / "promotion_log.jsonl")
    lst = read_json(sd / "learner_state.json") or {}
    learner_rows = [r for r in rows if r.get("source") == "learner"]
    pb_rows = [r for r in rows if "source" not in r]
    print()
    seen = lst.get("last_trigger_seen")
    print("last trigger seen: " + (f"{seen.get('trigger')} at {seen.get('time')}" if seen else "none"))
    if learner_rows:
        r = learner_rows[-1]
        print(f"last learner decision: {r.get('time')} {r.get('event')} {r.get('decision') or ''} "
              f"trigger={r.get('trigger')} run={r.get('run')} {r.get('reason') or ''}".rstrip())
    else:
        print("last learner decision: none")
    if pb_rows:
        r = pb_rows[-1]
        print(f"last gate result: {r.get('time')} {r.get('name')} gate={r.get('gate')} -> {r.get('decision')}")
    else:
        print("last gate result: none")
    desc, ok = live_model(soc_config.rpath(cfg["paths"]["models_dir"]))
    print(f"live model: {desc}" + {True: "  (sha256 verified)", False: "  (sha256 MISMATCH vs PROMOTED.json)",
                                    "eol": "  (sha256 verified; some JSON files differ only in CRLF/LF line endings)",
                                    None: ""}[ok])

    pending, cmd = None, None
    for i, r in enumerate(pb_rows):
        if str(r.get("decision", "")).startswith("ready"):
            later = [x for x in pb_rows[i + 1:] if x.get("name") == r.get("name") and x.get("promoted")]
            pending = None if later else r
    lr = lst.get("last_ready") or {}
    if lr.get("run"):
        promoted = [x for x in pb_rows if x.get("name") == lr["run"] and x.get("promoted")]
        if not promoted and (pending is None or pending.get("name") == lr["run"]):
            last = [x for x in pb_rows if x.get("name") == lr["run"]]
            pending = pending or (last[-1] if last else {"name": lr["run"], "time": lr.get("time")})
            cmd = lr.get("command")
    if pending:
        print(f"ready to promote: {pending.get('name')} ({pending.get('time')}; chosen {pending.get('chosen')})")
        if cmd:
            print(f"  promote (gate + smoke test + rollback): {cmd}")
        if pending.get("chosen"):
            print(f"  or by hand: bash scripts/promote_model.sh {pending.get('chosen')}")
    else:
        print("ready to promote: none")
    pp = lst.get("pending_promote")
    if pp:
        print(f"promote retry pending: {pp.get('run')} attempt {pp.get('attempts')}/"
              f"{cfg['promote_retry']['max_attempts']}")
    cu = lst.get("cooldown_until")
    print("learner cooldown: " + (f"{fmt_age(cu - now)} left" if cu and cu > now else "none"))
    lr = lst.get("last_run") or {}
    if lr.get("run"):
        print(f"last run: {lr.get('run')} outcome={lr.get('outcome')} exit={lr.get('exit')}")
    turl = cfg["detector"].get("technitium_url")
    if turl:
        print(f"technitium ({turl}): {'reachable' if port_open(turl, 0.5) else 'not reachable'} (not managed by soc)")
    return 0 if all_ok else 3


def shell_env(cfg):
    vals = {
        "SOC_STATE_DIR": str(soc_config.state_dir(cfg)), "SOC_LOG_DIR": str(soc_config.log_dir(cfg)),
        "SOC_PY": cfg["_python"], "SOC_PY_SOURCE": cfg["_python_source"],
        "SOC_CONFIG_FILE": cfg.get("_config_file") or "",
        "SOC_DET_STOP": str(int(float(cfg["detector"]["stop_timeout_s"]))),
        "SOC_LRN_STOP": str(int(float(cfg["learner"]["stop_timeout_s"]))),
        "SOC_PROMOTE_GRACE": str(int(float(cfg["learner"]["promote_grace_s"]))),
        "SOC_STARTUP_GRACE": str(int(float(cfg["health"]["startup_grace_s"]))),
    }
    return "\n".join(f"{k}={shlex.quote(v)}" for k, v in vals.items())


def wait_healthy(cfg, services, timeout):
    """0 when every child of the services is running and healthy (or has no health check), else 2."""
    end = time.time() + timeout
    while True:
        ok = True
        for svc in services:
            if not supervisor_running(soc_config.state_dir(cfg), svc):
                ok = False
            for st in child_states(cfg, svc):
                if st.get("state") != "running":
                    ok = False
                elif st.get("health_url") and st.get("health") is not True:
                    ok = ok and http_ok(st["health_url"], 2.0)
        if ok:
            return 0
        if time.time() >= end:
            return 2
        time.sleep(0.5)


def strays(cfg, services):
    """Processes that should be gone after `down`: recorded child groups, plus soc-pattern processes whose
    working directory is this repo. [(pid, cmdline)]"""
    sd = soc_config.state_dir(cfg)
    found = {}
    for f in (sd / "state").glob("*.json"):
        st = read_json(f)
        if st and st.get("service") in services and st.get("pgid"):
            for p in group_pids(st["pgid"]):
                found[p] = proc_cmdline(p)
    me = {os.getpid(), os.getppid()}
    ours = proc_soc_config("self")
    root = str(ROOT.resolve())
    pats = [p for s in services for p in STRAY_PATTERNS[s]]
    for d in Path("/proc").glob("[0-9]*"):
        pid = int(d.name)
        if pid in me or not alive(pid):
            continue
        cmd = proc_cmdline(pid)
        if any(p in cmd for p in pats) and proc_cwd(pid) == root and "soc_supervisor.py strays" not in cmd \
                and proc_soc_config(pid) in (ours, None):
            found[pid] = cmd
    return sorted(found.items())


def kill_groups(cfg, services):
    sd = soc_config.state_dir(cfg)
    for f in (sd / "state").glob("*.json"):
        st = read_json(f)
        if not (st and st.get("service") in services and st.get("pgid")):
            continue
        pids = group_pids(st["pgid"])
        # Only a group that still runs OUR command (marker in a member's cmdline): after a reboot the
        # recorded pgid may belong to an unrelated process.
        if pids and st.get("marker") and any(st["marker"] in proc_cmdline(p) for p in pids):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(st["pgid"], signal.SIGKILL)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["detector", "learner", "status", "env", "wait-healthy", "strays",
                                        "kill-groups"])
    ap.add_argument("services", nargs="*", help="for wait-healthy / strays / kill-groups (default: both)")
    ap.add_argument("--foreground", action="store_true", help="also print the supervisor log to stderr")
    ap.add_argument("--timeout", type=float, default=30.0)
    a = ap.parse_intermixed_args(argv)   # "wait-healthy --timeout 5 detector" on Python 3.10 too
    cfg = soc_config.load()
    svcs = [s for s in a.services if s in SERVICES] or list(SERVICES)
    if a.command in SERVICES:
        return Supervisor(cfg, a.command, a.foreground).run()
    if a.command == "status":
        return status(cfg)
    if a.command == "env":
        print(shell_env(cfg))
        return 0
    if a.command == "wait-healthy":
        return wait_healthy(cfg, svcs, a.timeout)
    if a.command == "strays":
        found = strays(cfg, svcs)
        for pid, cmd in found:
            print(f"{pid} {cmd}")
        return 1 if found else 0
    if a.command == "kill-groups":
        kill_groups(cfg, svcs)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
