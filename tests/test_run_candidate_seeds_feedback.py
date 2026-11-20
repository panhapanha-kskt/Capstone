"""scripts/run_candidate_seeds.sh FEEDBACK pass-through (learner trigger (c)).

Unset → every seed's train_models.sh call is exactly what it was before; set → each seed also gets
--feedback <file>. train_models.sh and part_b.py are stubs in a throwaway copy of the project.
"""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TRAIN_STUB = """#!/usr/bin/env bash
printf '%s\\x1f' "$@" >> "$CALLS"; printf '\\n' >> "$CALLS"
mkdir -p "$DNS_DETECT_MODELS_DIR"
"""
PART_B_STUB = "import sys; print('part_b', sys.argv[1:]); sys.exit(10)\n"


def project(tmp_path):
    proj = tmp_path / "proj"
    (proj / "scripts").mkdir(parents=True)
    (proj / "data").mkdir()
    (proj / "scripts" / "run_candidate_seeds.sh").write_bytes((ROOT / "scripts" / "run_candidate_seeds.sh").read_bytes())
    (proj / "scripts" / "train_models.sh").write_text(TRAIN_STUB)
    (proj / "scripts" / "part_b.py").write_text(PART_B_STUB)
    (proj / "data" / "a.json").write_text("[]")
    (proj / "data" / "b.json").write_text("[]")
    (proj / "split.json").write_text("{}")
    return proj


def run(proj, **extra):
    env = {k: v for k, v in os.environ.items() if k not in ("FEEDBACK", "AUTO_PROMOTE", "FILES", "SPLIT")}
    env.update(RUN_NAME="t", SEEDS="42 43", SPLIT="split.json", FILES="data/a.json data/b.json",
               CALLS=str(proj / "calls.txt"), **extra)
    r = subprocess.run(["bash", "scripts/run_candidate_seeds.sh"], cwd=proj, env=env, capture_output=True,
                       text=True, timeout=60)
    calls = [line.rstrip("\x1f").split("\x1f") for line in (proj / "calls.txt").read_text().splitlines()]
    return r, calls


def expected(seed):
    return ["--seed", seed, "--n-days", "20", "--path-b-model", "iforest", "--force-retrain",
            "--split-manifest", "runs/t_split.json", "--files", "data/a.json", "data/b.json"]


def test_without_feedback_the_command_is_unchanged(tmp_path):
    r, calls = run(project(tmp_path))
    assert r.returncode == 10, r.stdout + r.stderr
    assert calls == [expected("42"), expected("43")]


def test_feedback_is_passed_to_every_seed(tmp_path):
    r, calls = run(project(tmp_path), FEEDBACK="data/feedback/verdict_labels.json")
    assert r.returncode == 10, r.stdout + r.stderr
    assert calls == [expected(s) + ["--feedback", "data/feedback/verdict_labels.json"] for s in ("42", "43")]


def test_empty_feedback_counts_as_unset(tmp_path):
    r, calls = run(project(tmp_path), FEEDBACK="")
    assert calls == [expected("42"), expected("43")]
    assert json.dumps(calls).count("--feedback") == 0
