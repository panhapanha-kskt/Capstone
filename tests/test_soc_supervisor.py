"""scripts/soc_supervisor.py with short-lived stub children (sleep / tiny Python scripts).

Every test uses its own SOC_CONFIG in tmp_path (state and logs there too) and kills whatever it started.
"""
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SUP = ROOT / "scripts" / "soc_supervisor.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


S = _load("soc_supervisor_mod", SUP)

# a child that starts a grandchild (writes its pid) and then sleeps; optional: ignore SIGTERM / crash
CHILD = r'''import os, signal, subprocess, sys, time
mode = sys.argv[1]
out = sys.argv[2]
if mode == "ignore_term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
if mode == "crash":
    print("crashing", flush=True)
    time.sleep(0.05)
    sys.exit(7)
g = subprocess.Popen(["sleep", "300"])
with open(out, "a") as f:
    f.write("%d %d\n" % (os.getpid(), g.pid))
print("child up", os.getpid(), flush=True)
beat = sys.argv[3] if len(sys.argv) > 3 else None
while True:
    if beat:
        open(beat, "w").write(str(time.time()))
    time.sleep(0.1)
'''


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Env:
    def __init__(self, tmp):
        self.tmp = tmp
        self.child = tmp / "child.py"
        self.child.write_text(CHILD)
        self.procs = []

    def config(self, listener="sleep", dashboard="sleep", listener_url=None, dashboard_url=None, **over):
        py = sys.executable
        cfg = {
            "state_dir": str(self.tmp / "soc"), "log_dir": str(self.tmp / "logs"),
            "paths": {"runs_dir": str(self.tmp / "runs"), "models_dir": str(self.tmp / "models")},
            "detector": {"listener": {"cmd": [py, str(self.child), listener, str(self.tmp / "listener.pids")],
                                      "health_url": listener_url},
                         "dashboard": {"cmd": [py, str(self.child), dashboard, str(self.tmp / "dashboard.pids")],
                                       "health_url": dashboard_url},
                         "stop_timeout_s": 1, "technitium_url": None},
            "learner": {"cmd": [py, str(self.child), "sleep", str(self.tmp / "learner.pids"),
                                str(self.tmp / "soc" / "learner.heartbeat")],
                        "stop_timeout_s": 1, "promote_grace_s": 1, "heartbeat_stale_s": 3600},
            "health": {"interval_s": 0.2, "timeout_s": 0.5, "startup_grace_s": 0, "fail_threshold": 2},
            "restart_backoff": {"base_s": 0.2, "max_s": 1.6, "reset_after_healthy_s": 60},
            "log_rotate": {"max_bytes": 100000, "backups": 2},
        }
        for k, v in over.items():
            cfg[k] = v
        path = self.tmp / "soc.yaml"
        path.write_text(json.dumps(cfg))                     # JSON is valid YAML
        self.env = {**os.environ, "SOC_CONFIG": str(path), "SOC_PYTHON": sys.executable}
        for k in ("SOC_LISTENER_CMD", "SOC_DETECTOR_CMD", "SOC_LEARNER_CMD"):
            self.env.pop(k, None)
        return path

    def start(self, svc="detector"):
        p = subprocess.Popen([sys.executable, str(SUP), svc, "--foreground"], env=self.env, cwd=ROOT,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        self.procs.append(p)
        return p

    def state(self, name):
        try:
            return json.loads((self.tmp / "soc" / "state" / f"{name}.json").read_text())
        except (OSError, ValueError):
            return {}

    def pids(self, name):
        f = self.tmp / f"{name}.pids"
        if not f.exists():
            return []
        return [tuple(map(int, line.split())) for line in f.read_text().splitlines() if line.strip()]

    def wait(self, cond, timeout=10.0):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.05)
        return False

    def suplog(self, svc="detector"):
        p = self.tmp / "logs" / f"supervisor-{svc}.log"
        return p.read_text() if p.exists() else ""

    def cleanup(self):
        for p in self.procs:
            if p.poll() is None:
                with pytest_suppress():
                    os.killpg(p.pid, signal.SIGTERM)
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
        for f in (self.tmp / "soc" / "state").glob("*.json") if (self.tmp / "soc" / "state").exists() else []:
            st = json.loads(f.read_text())
            if st.get("pgid"):
                with pytest_suppress():
                    os.killpg(st["pgid"], signal.SIGKILL)
        for name in ("listener", "dashboard", "learner"):
            for pids in self.pids(name):
                for pid in pids:
                    with pytest_suppress():
                        os.kill(pid, signal.SIGKILL)


class pytest_suppress:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return exc[0] is not None and issubclass(exc[0], (ProcessLookupError, PermissionError, OSError))


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.cleanup()


def gone(pid):
    return not S.alive(pid)


def test_backoff_delays():
    assert [S.backoff_delay(n, 2, 300) for n in range(1, 11)] == [2, 4, 8, 16, 32, 64, 128, 256, 300, 300]
    assert S.backoff_delay(0, 2, 300) == 0


def test_rotating_log(tmp_path):
    log = S.RotatingLog(tmp_path / "x.log", 100, 2)
    for i in range(50):
        log.write(f"line {i:04d}\n")
    log.close()
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == ["x.log", "x.log.1", "x.log.2"]
    assert all(p.stat().st_size <= 100 for p in tmp_path.iterdir())


def test_sigterm_stops_children_and_grandchildren(env):
    env.config()
    sup = env.start()
    assert env.wait(lambda: env.pids("listener") and env.pids("dashboard"))
    (lc, lg), (dc, dg) = env.pids("listener")[0], env.pids("dashboard")[0]
    os.kill(sup.pid, signal.SIGTERM)
    assert sup.wait(timeout=10) == 0
    assert all(gone(p) for p in (lc, lg, dc, dg))
    assert env.state("listener")["state"] == "stopped"
    assert (env.tmp / "logs" / "listener.log").read_text().count("child up") == 1


def test_term_ignoring_child_is_killed_after_timeout(env):
    env.config(listener="ignore_term")
    sup = env.start()
    assert env.wait(lambda: env.pids("listener"))
    lc, lg = env.pids("listener")[0]
    t0 = time.time()
    os.kill(sup.pid, signal.SIGTERM)
    assert sup.wait(timeout=15) == 0
    assert gone(lc) and gone(lg) and time.time() - t0 >= 1.0
    assert "SIGKILL" in env.suplog()


def test_crashing_child_restarts_with_backoff_and_sibling_is_untouched(env):
    env.config(listener="crash")
    sup = env.start()
    assert env.wait(lambda: env.pids("dashboard"))
    dash_pid = env.state("dashboard").get("pid")
    assert env.wait(lambda: env.state("listener").get("restarts", 0) >= 4, timeout=15)
    log = env.suplog()
    for d in ("0.2s", "0.4s", "0.8s", "1.6s"):
        assert f"in {d}" in log
    st = env.state("dashboard")
    assert st["pid"] == dash_pid and st["restarts"] == 0 and len(env.pids("dashboard")) == 1
    os.kill(sup.pid, signal.SIGTERM)
    sup.wait(timeout=10)


def test_failed_health_checks_restart_only_that_child(env):
    env.config(listener_url=f"http://127.0.0.1:{free_port()}/healthz")   # nothing answers there
    sup = env.start()
    assert env.wait(lambda: env.state("listener").get("restarts", 0) >= 1, timeout=10)
    assert "health check failed" in env.suplog()
    first = env.pids("listener")[0]
    assert gone(first[0]) and gone(first[1])                          # the old group is fully gone
    assert env.state("dashboard")["restarts"] == 0
    os.kill(sup.pid, signal.SIGTERM)
    sup.wait(timeout=10)


def test_healthy_http_child_and_port_in_use(env, tmp_path):
    port = free_port()
    srv = socket.socket()
    srv.bind(("127.0.0.1", port))
    srv.listen(5)                                                      # someone else owns the port
    try:
        env.config(dashboard_url=f"http://127.0.0.1:{port}/api/health")
        sup = env.start()
        assert env.wait(lambda: env.state("dashboard").get("state") in ("port_in_use", "backoff")
                        and "not managed by soc" in env.suplog(), timeout=10)
        assert env.pids("dashboard") == []                             # not started
        assert env.wait(lambda: env.state("listener").get("state") == "running")
    finally:
        srv.close()
    os.kill(sup.pid, signal.SIGTERM)
    sup.wait(timeout=10)


def test_second_supervisor_is_refused(env):
    env.config()
    sup = env.start("learner")
    assert env.wait(lambda: env.pids("learner"))
    second = env.start("learner")
    out = second.communicate(timeout=10)[0].decode()
    assert second.returncode == 3 and "already running" in out
    assert len(env.pids("learner")) == 1
    os.kill(sup.pid, signal.SIGTERM)
    assert sup.wait(timeout=10) == 0


def test_leftover_group_of_a_killed_supervisor_is_stopped_on_next_start(env):
    env.config()
    sup = env.start("learner")
    assert env.wait(lambda: env.pids("learner"))
    lc, lg = env.pids("learner")[0]
    os.kill(sup.pid, signal.SIGKILL)                                   # supervisor dies, child survives
    sup.wait(timeout=5)
    assert not gone(lc)
    sup2 = env.start("learner")
    assert env.wait(lambda: gone(lc) and gone(lg), timeout=10)
    assert env.wait(lambda: len(env.pids("learner")) == 2)
    os.kill(sup2.pid, signal.SIGTERM)
    assert sup2.wait(timeout=10) == 0


def test_learner_child_restarts_but_detector_does_not(env):
    env.config()
    det, lrn = env.start("detector"), env.start("learner")
    assert env.wait(lambda: env.pids("learner") and env.pids("dashboard") and env.pids("listener"))
    dash = env.state("dashboard")["pid"]
    lc, lg = env.pids("learner")[0]
    os.kill(lc, signal.SIGKILL)                                        # kill -9 the learner mid-run
    assert env.wait(lambda: env.state("learner").get("restarts") == 1 and len(env.pids("learner")) == 2)
    assert gone(lg)                                                    # its grandchild (training) is gone too
    assert env.state("dashboard")["pid"] == dash and env.state("dashboard")["restarts"] == 0
    for p in (det, lrn):
        os.kill(p.pid, signal.SIGTERM)
        assert p.wait(timeout=10) == 0


def test_status_with_nothing_running(env):
    env.config()
    r = subprocess.run([sys.executable, str(SUP), "status"], env=env.env, cwd=ROOT, capture_output=True,
                       text=True, timeout=30)
    assert r.returncode == 3
    for text in ("detector", "learner", "listener", "dashboard", "stopped", "last trigger seen",
                 "last gate result", "live model", "ready to promote"):
        assert text in r.stdout, text


def test_live_model_hash_check(tmp_path):
    import hashlib
    (tmp_path / "a.json").write_bytes(b'{"x": 1}\r\n')           # rewritten on Windows: CRLF only
    (tmp_path / "m.pkl").write_bytes(b"model")
    files = {"a.json": hashlib.sha256(b'{"x": 1}\n').hexdigest(), "m.pkl": hashlib.sha256(b"model").hexdigest()}
    (tmp_path / "PROMOTED.json").write_text(json.dumps({"source_run": "runs/v3", "promoted_at": "t", "files": files}))
    assert S.live_model(tmp_path) == ("runs/v3 t", "eol")
    (tmp_path / "a.json").write_bytes(b'{"x": 1}\n')
    assert S.live_model(tmp_path)[1] is True
    (tmp_path / "m.pkl").write_bytes(b"other")
    assert S.live_model(tmp_path)[1] is False
