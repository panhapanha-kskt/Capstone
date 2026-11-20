"""scripts/soc.sh end to end with stub services (SOC_CONFIG in tmp_path; nothing real is started)."""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SOC = ROOT / "scripts" / "soc.sh"

STUB = r'''import os, subprocess, sys, time
g = subprocess.Popen(["sleep", "300"])
with open(sys.argv[1], "a") as f:
    f.write("%d %d\n" % (os.getpid(), g.pid))
print("stub up", flush=True)
beat = sys.argv[2] if len(sys.argv) > 2 else None
while True:
    if beat:
        open(beat, "w").write(str(time.time()))
    time.sleep(0.2)
'''


class Soc:
    def __init__(self, tmp):
        self.tmp = tmp
        (tmp / "stub_service.py").write_text(STUB)
        py, stub = sys.executable, str(tmp / "stub_service.py")
        (tmp / "runs").mkdir()
        (tmp / "models").mkdir()
        cfg = {
            "python": sys.executable,
            "state_dir": str(tmp / "soc"), "log_dir": str(tmp / "logs"),
            "paths": {"runs_dir": str(tmp / "runs"), "models_dir": str(tmp / "models")},
            "detector": {"listener": {"cmd": [py, stub, str(tmp / "listener.pids")], "health_url": None},
                         "dashboard": {"cmd": [py, stub, str(tmp / "dashboard.pids")], "health_url": None},
                         "stop_timeout_s": 2, "technitium_url": None},
            "learner": {"cmd": [py, stub, str(tmp / "learner.pids"), str(tmp / "soc" / "learner.heartbeat")],
                        "stop_timeout_s": 2, "promote_grace_s": 1},
            "health": {"interval_s": 0.5, "timeout_s": 1, "startup_grace_s": 30, "fail_threshold": 3},
            "restart_backoff": {"base_s": 0.2, "max_s": 1, "reset_after_healthy_s": 5},
        }
        self.cfg = tmp / "soc.yaml"
        self.cfg.write_text(json.dumps(cfg))
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("SOC_") and k not in ("AUTO_PROMOTE",)}
        self.env.update(SOC_CONFIG=str(self.cfg), SOC_UP_WAIT_S="10", SOC_PYTHON=sys.executable)

    def run(self, *args, timeout=60):
        return subprocess.run(["bash", str(SOC), *args], env=self.env, cwd=self.tmp, capture_output=True,
                              text=True, timeout=timeout)

    def pids(self, name):
        f = self.tmp / f"{name}.pids"
        return [tuple(map(int, x.split())) for x in f.read_text().splitlines()] if f.exists() else []

    def sup_pid(self, svc):
        return int((self.tmp / "soc" / f"{svc}.supervisor.pid").read_text())

    def state(self, name):
        return json.loads((self.tmp / "soc" / "state" / f"{name}.json").read_text())

    def all_pids(self):
        return [p for n in ("listener", "dashboard", "learner") for pair in self.pids(n) for p in pair]

    def cleanup(self):
        self.run("down", timeout=90)
        for pid in self.all_pids():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass


def alive(pid):
    try:
        st = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return st[st.rindex(")") + 2] not in "ZX"


@pytest.fixture
def soc(tmp_path):
    s = Soc(tmp_path)
    yield s
    s.cleanup()


def test_help_and_unknown_command():
    r = subprocess.run(["bash", str(SOC), "--help"], capture_output=True, text=True)
    assert r.returncode == 0 and "soc.sh up" in r.stdout
    r = subprocess.run(["bash", str(SOC), "bogus"], capture_output=True, text=True)
    assert r.returncode == 1


def test_status_when_nothing_runs(soc):
    r = soc.run("status")
    assert r.returncode == 3, r.stdout + r.stderr
    assert r.stdout.count("stopped") >= 5                       # 2 supervisors + 3 children
    for text in ("last trigger seen", "last gate result", "live model", "ready to promote"):
        assert text in r.stdout


def test_up_is_idempotent_status_down_leaves_no_strays(soc):
    r = soc.run("up")
    assert r.returncode == 0, r.stdout + r.stderr
    assert soc.run("up").returncode == 0                        # second up: starts nothing
    r2 = soc.run("up")
    assert r2.stdout.count("already running") == 2, r2.stdout
    sup = {s: soc.sup_pid(s) for s in ("detector", "learner")}
    assert all(len(soc.pids(n)) == 1 for n in ("listener", "dashboard", "learner"))
    st = soc.run("status")
    assert st.returncode == 0, st.stdout
    for text in ("supervisor", "running", str(soc.state("dashboard")["pid"]), "UPTIME", "RESTARTS"):
        assert text in st.stdout
    r = soc.run("down", timeout=90)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not any(alive(p) for p in soc.all_pids() + list(sup.values()))
    assert soc.run("status").returncode == 3
    assert soc.run("down").returncode == 0                      # down when nothing runs


def test_restart_learner_keeps_the_detector(soc):
    assert soc.run("up").returncode == 0
    det_sup, dash = soc.sup_pid("detector"), soc.state("dashboard")["pid"]
    old_learner = soc.pids("learner")[0]
    r = soc.run("restart", "learner", timeout=90)
    assert r.returncode == 0, r.stdout + r.stderr
    assert soc.sup_pid("detector") == det_sup and soc.state("dashboard")["pid"] == dash
    assert not alive(old_learner[0]) and not alive(old_learner[1])
    assert len(soc.pids("learner")) == 2


def test_auto_promote_reaches_the_learner_only_when_asked(soc):
    soc.env["SOC_AUTO_PROMOTE"] = "1"                          # stray value in the user's shell: ignored
    assert soc.run("up", "learner").returncode == 0
    pid = soc.state("learner")["pid"]
    env = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
    assert b"SOC_AUTO_PROMOTE=1" not in env
    assert soc.run("restart", "--auto-promote", "learner", timeout=90).returncode == 0
    pid = soc.state("learner")["pid"]
    assert b"SOC_AUTO_PROMOTE=1" in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")


def test_down_cleans_up_after_a_killed_supervisor(soc):
    assert soc.run("up", "detector").returncode == 0
    os.kill(soc.sup_pid("detector"), signal.SIGKILL)            # supervisor gone, children left behind
    time.sleep(0.3)
    assert any(alive(p) for p in soc.all_pids())
    r = soc.run("down", timeout=90)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not any(alive(p) for p in soc.all_pids())


def test_logs_and_status_show_pending_ready_to_promote(soc):
    row = {"time": "2026-11-20T10:00:00+00:00", "name": "soc_captures_x", "gate": "PASS", "promoted": False,
           "chosen": "runs/soc_captures_x_s42", "decision": "ready, waiting for approval"}
    (soc.tmp / "runs" / "promotion_log.jsonl").write_text(json.dumps(row) + "\n")
    (soc.tmp / "soc").mkdir(exist_ok=True)
    (soc.tmp / "soc" / "learner_state.json").write_text(json.dumps({"last_ready": {
        "run": "soc_captures_x", "command": 'python3 scripts/part_b.py --name soc_captures_x --seeds "42 43 44" '
                                           '--auto-promote'}}))
    st = soc.run("status")
    assert "ready to promote: soc_captures_x" in st.stdout
    assert "part_b.py --name soc_captures_x" in st.stdout and "promote_model.sh runs/soc_captures_x_s42" in st.stdout
    assert soc.run("up", "detector").returncode == 0
    time.sleep(0.5)
    lg = soc.run("logs", "detector")
    assert lg.returncode == 0 and "stub up" in lg.stdout
