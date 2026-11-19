"""Task 9: Part B automation (scripts/part_b.py) with stub commands. Nothing is trained or promoted for real."""
import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PART_B = ROOT / "scripts" / "part_b.py"
FA = {"42": 13, "43": 16, "44": 2}          # false alarms per seed → median 13 → seed 42 is chosen

GATE = """import json, os, sys
a = sys.argv
out = a[a.index("--out") + 1]
runs = a[a.index("--runs") + 1:a.index("--out")]
fa = json.loads(os.environ["FAKE_FA"])
seeds = [{"run": r, "seed": int(r.rsplit("_s", 1)[1]), "candidate": {"false_alarms": fa[r.rsplit("_s", 1)[1]]}} for r in runs]
ok = os.environ["FAKE_GATE"] == "pass"
json.dump({"seeds": seeds, "passed": ok}, open(out, "w"))
sys.exit(0 if ok else 1)
"""
PROMOTE = """import os, sys, pathlib
m = pathlib.Path(os.environ["FAKE_MODELS"])
arch = m / "archive" / "before_cand_x"
arch.mkdir(parents=True, exist_ok=True)
(arch / "model.txt").write_text((m / "model.txt").read_text())
(m / "model.txt").write_text("promoted " + sys.argv[1])
"""
SMOKE = """import os, sys
sys.exit(0 if os.environ["FAKE_SMOKE"] == "pass" else 1)
"""


@pytest.fixture
def lab(tmp_path):
    runs, models = tmp_path / "runs", tmp_path / "models"
    runs.mkdir()
    models.mkdir()
    (models / "model.txt").write_text("live")
    for name, body in (("gate", GATE), ("promote", PROMOTE), ("smoke", SMOKE)):
        (tmp_path / f"{name}.py").write_text(body)
    env = {**os.environ, "FAKE_FA": json.dumps(FA), "FAKE_MODELS": str(models),
           "PART_B_GATE": f"{sys.executable} {tmp_path / 'gate.py'}",
           "PART_B_PROMOTE": f"{sys.executable} {tmp_path / 'promote.py'}",
           "PART_B_SMOKE": f"{sys.executable} {tmp_path / 'smoke.py'}"}
    return {"runs": runs, "models": models, "env": env}


def run_b(lab, gate, smoke="pass", auto=False):
    env = dict(lab["env"], FAKE_GATE=gate, FAKE_SMOKE=smoke)
    args = [sys.executable, str(PART_B), "--name", "cand", "--seeds", "42 43 44",
            "--runs-dir", str(lab["runs"]), "--models-dir", str(lab["models"])] + (["--auto-promote"] if auto else [])
    return subprocess.run(args, env=env, capture_output=True, text=True)


def last_log(lab):
    return json.loads((lab["runs"] / "promotion_log.jsonl").read_text().splitlines()[-1])


def test_gate_fail_keeps_models(lab):
    r = run_b(lab, "fail", auto=True)
    assert r.returncode == 1, r.stdout + r.stderr
    assert (lab["models"] / "model.txt").read_text() == "live"
    row = last_log(lab)
    assert row["gate"] == "FAIL" and row["promoted"] is False and "time" in row


def test_gate_pass_without_flag_only_reports_ready(lab):
    r = run_b(lab, "pass")
    assert r.returncode == 10, r.stdout + r.stderr
    assert "cand_s42" in r.stdout                                   # median seed, not the luckiest (44)
    assert (lab["models"] / "model.txt").read_text() == "live"
    assert last_log(lab)["decision"].startswith("ready")


def test_gate_pass_with_flag_promotes_median_seed(lab):
    r = run_b(lab, "pass", auto=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (lab["models"] / "model.txt").read_text().endswith("cand_s42")
    row = last_log(lab)
    assert row["promoted"] is True and row["chosen"].endswith("cand_s42")


def test_smoke_failure_rolls_back(lab):
    r = run_b(lab, "pass", smoke="fail", auto=True)                # real rollback_model.sh, MODELS_DIR=tmp
    assert r.returncode == 2, r.stdout + r.stderr
    assert (lab["models"] / "model.txt").read_text() == "live"
    assert any(p.name.startswith("rolledback_") for p in (lab["models"] / "archive").iterdir())
    assert last_log(lab)["decision"] == "smoke test failed, rolled back"


def test_run_all_retrain_never_trains_into_models():
    src = (ROOT / "scripts" / "run_all.sh").read_text(encoding="utf-8")
    assert "run_candidate_seeds.sh" in src and "run_part_b" in src
    assert 'train_models.sh" --retrain' not in src                 # the old auto-retrain into models/ is gone
    retrain = src[src.index('elif [[ "$RETRAIN_GIVEN" == true ]]'):src.index('stage "TRAIN (steps 1–11)')]
    assert "run_part_b" in retrain and "train_models.sh" not in retrain
    seeds = (ROOT / "scripts" / "run_candidate_seeds.sh").read_text(encoding="utf-8")
    assert "|| true" not in seeds and "part_b.py" in seeds
    assert 'DNS_DETECT_MODELS_DIR="$out"' in seeds                 # every seed trains into its own runs/ folder


def test_second_run_is_refused_while_locked(lab):
    with open(lab["runs"] / ".promote.lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        r = run_b(lab, "pass", auto=True)
    assert r.returncode == 3 and "another Part B run" in r.stdout
    assert (lab["models"] / "model.txt").read_text() == "live"


# ── a retrain learns from at least the live model's data ───────
def _fake_project(tmp_path, provenance_files):
    proj = tmp_path / "proj"
    (proj / "scripts").mkdir(parents=True)
    (proj / "models").mkdir()
    src = (ROOT / "scripts" / "run_candidate_seeds.sh").read_text(encoding="utf-8")
    (proj / "scripts" / "run_candidate_seeds.sh").write_text(src)
    (proj / "models" / "split_manifest.json").write_text("{}")
    (proj / "models" / "training_provenance.json").write_text(
        json.dumps({"source_files": [{"path": p} for p in provenance_files]}))
    return proj


def test_retrain_refuses_when_live_training_files_are_missing(tmp_path):
    proj = _fake_project(tmp_path, ["data/a.json", "data/missing.json"])
    (proj / "data").mkdir()
    (proj / "data" / "a.json").write_text("[]")
    env = {k: v for k, v in os.environ.items() if k not in ("FILES", "SPLIT", "RUN_NAME")}
    r = subprocess.run(["bash", str(proj / "scripts" / "run_candidate_seeds.sh")], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 4, r.stdout + r.stderr
    assert "data/missing.json" in r.stderr and "Nothing was trained" in r.stderr
    assert not (proj / "runs").exists()                              # nothing written


def test_retrain_defaults_to_live_data_and_split():
    seeds = (ROOT / "scripts" / "run_candidate_seeds.sh").read_text(encoding="utf-8")
    assert 'LIVE_PROV="models/training_provenance.json"' in seeds
    assert 'SPLIT="models/split_manifest.json"' in seeds


def test_no_unsafe_retrain_advice_left():
    for rel in ("scripts/run_pipeline.sh", "scripts/pipeline_awareness_check.sh",
                "src/dns_detect/monitoring/monitor.py", "scripts/run_all.sh"):
        assert "train_models.sh --retrain" not in (ROOT / rel).read_text(encoding="utf-8"), rel


def test_promote_waits_while_detection_is_running(lab):
    with open(lab["runs"] / ".pipeline.lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_SH)                              # what run_pipeline.sh holds
        r = run_b(lab, "pass", auto=True)
    assert r.returncode == 3 and "run_pipeline.sh is running" in r.stdout
    assert (lab["models"] / "model.txt").read_text() == "live"
    assert run_b(lab, "pass", auto=True).returncode == 0              # once it has finished
