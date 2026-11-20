"""scripts/part_b.py holds runs/.pipeline.lock EXCLUSIVELY through promote → smoke test → rollback.

Closes the gap between "is detection running?" and promote_model.sh: while part_b swaps models/, a
detection run (run_pipeline.sh / the dashboard take the lock shared) has to wait; and part_b refuses while
detection holds it shared or a detection heartbeat is fresh. Stubs only; nothing is trained or promoted.
"""
import fcntl
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PART_B = ROOT / "scripts" / "part_b.py"

GATE = """import json, sys
a = sys.argv
out = a[a.index("--out") + 1]
runs = a[a.index("--runs") + 1:a.index("--out")]
seeds = [{"run": r, "seed": int(r.rsplit("_s", 1)[1]), "candidate": {"false_alarms": 1}} for r in runs]
json.dump({"seeds": seeds, "passed": True}, open(out, "w"))
"""
# Each stub tries to take the detection lock the way run_pipeline.sh does (shared), without waiting,
# and records whether it was blocked. It runs while part_b is inside promote / smoke / rollback.
PROBE = """import fcntl, os, sys, time
step = sys.argv[1]
runs = os.environ["FAKE_RUNS"]
open(os.path.join(runs, "in_" + step), "w").write("1")
time.sleep(float(os.environ.get("FAKE_HOLD", "0")))
with open(os.path.join(runs, ".pipeline.lock"), "a") as f:
    try:
        fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)
        res = "free"
    except BlockingIOError:
        res = "blocked"
open(os.path.join(runs, "probe_" + step), "w").write(res)
sys.exit(int(os.environ.get("FAKE_RC_" + step.upper(), "0")))
"""


@pytest.fixture
def lab(tmp_path):
    runs, models = tmp_path / "runs", tmp_path / "models"
    runs.mkdir()
    models.mkdir()
    (models / "model.txt").write_text("live")
    (tmp_path / "gate.py").write_text(GATE)
    (tmp_path / "probe.py").write_text(PROBE)
    probe = f"{sys.executable} {tmp_path / 'probe.py'}"
    env = {**os.environ, "FAKE_RUNS": str(runs),
           "PART_B_GATE": f"{sys.executable} {tmp_path / 'gate.py'}",
           "PART_B_PROMOTE": f"{probe} promote", "PART_B_SMOKE": f"{probe} smoke",
           "PART_B_ROLLBACK": f"{probe} rollback"}
    return {"runs": runs, "models": models, "env": env}


def argv(lab):
    return [sys.executable, str(PART_B), "--name", "cand", "--seeds", "42 43 44", "--runs-dir", str(lab["runs"]),
            "--models-dir", str(lab["models"]), "--auto-promote"]


def probe(lab, step):
    return (lab["runs"] / f"probe_{step}").read_text()


def test_detection_cannot_start_during_promote_and_smoke(lab):
    r = subprocess.run(argv(lab), env=lab["env"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert probe(lab, "promote") == "blocked" and probe(lab, "smoke") == "blocked"
    with open(lab["runs"] / ".pipeline.lock", "a") as f:     # released when part_b is done
        fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)


def test_lock_is_held_through_rollback_too(lab):
    env = dict(lab["env"], FAKE_RC_SMOKE="1")
    r = subprocess.run(argv(lab), env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 2, r.stdout + r.stderr
    assert probe(lab, "rollback") == "blocked"
    assert json.loads((lab["runs"] / "promotion_log.jsonl").read_text().splitlines()[-1])["decision"] == \
        "smoke test failed, rolled back"


def test_shared_lock_taken_while_part_b_promotes_has_to_wait(lab):
    env = dict(lab["env"], FAKE_HOLD="1.5")
    p = subprocess.Popen(argv(lab), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        end = time.time() + 30
        while not (lab["runs"] / "in_promote").exists() and time.time() < end:
            time.sleep(0.02)
        with open(lab["runs"] / ".pipeline.lock", "a") as f:
            with pytest.raises(BlockingIOError):
                fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)  # what run_pipeline.sh would hit
            t0 = time.time()
            fcntl.flock(f, fcntl.LOCK_SH)                      # blocking: waits for part_b
            assert p.poll() is not None or time.time() - t0 > 0.5
    finally:
        p.wait(timeout=60)
    assert p.returncode == 0


def test_part_b_refuses_while_detection_holds_the_lock_shared(lab):
    with open(lab["runs"] / ".pipeline.lock", "a") as held:
        fcntl.flock(held, fcntl.LOCK_SH)
        r = subprocess.run(argv(lab), env=lab["env"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 3 and "run_pipeline.sh is running" in r.stdout
    assert not (lab["runs"] / "in_promote").exists()
    row = json.loads((lab["runs"] / "promotion_log.jsonl").read_text().splitlines()[-1])
    assert row["decision"] == "not promoted: run_pipeline.sh is running"


def test_part_b_refuses_while_a_detection_heartbeat_is_fresh(lab):
    rd = lab["runs"] / ".pipeline.readers"
    rd.mkdir()
    (rd / "winhost-123-abc").write_text(str(time.time()))      # e.g. a Windows-hosted dashboard
    r = subprocess.run(argv(lab), env=lab["env"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 3 and not (lab["runs"] / "in_promote").exists()
    with open(lab["runs"] / ".pipeline.lock", "a") as f:     # the refused attempt left nothing locked
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
