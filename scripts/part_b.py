#!/usr/bin/env python3
"""Part B of the pipeline: gate → (optional) promote → smoke test → rollback if the smoke test fails.

    python3 scripts/part_b.py --name labelled_v3_iforest --seeds "42 43 44"                  # stop at "ready"
    python3 scripts/part_b.py --name labelled_v3_iforest --seeds "42 43 44" --auto-promote   # promote on PASS
    python3 scripts/part_b.py --name console_v7 --run R1 --run R2 --run R3 --auto-promote    # explicit folders

Exit codes: 0 promoted · 10 gate PASS, waiting for you to promote · 1 gate FAIL (models/ untouched)
            2 promoted but the smoke test failed, rolled back · 3 another promote is running, or an error.
Tests swap the real commands for stubs with PART_B_GATE / PART_B_PROMOTE / PART_B_SMOKE / PART_B_ROLLBACK.
"""
import argparse
import datetime
try:
    import fcntl  # POSIX only
except ImportError:  # Windows: the training console runs this script through bash/WSL instead
    fcntl = None
import json
import os
import shlex
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
sys.path.insert(0, str(ROOT / "src" / "dns_detect" / "utils"))
import pipeline_lock  # noqa: E402  (stdlib only; shared with the dashboard, audit H1)


def command(env_name, default):
    v = os.environ.get(env_name)
    return shlex.split(v) if v else default


def pick_seed(report):
    """The seed whose false alarms are closest to the median: typical, not the luckiest."""
    seeds = [s for s in report.get("seeds", []) if isinstance(s.get("candidate"), dict)]
    if not seeds:
        raise ValueError("gate report has no scored seeds")
    med = statistics.median(s["candidate"]["false_alarms"] for s in seeds)
    best = min(seeds, key=lambda s: (abs(s["candidate"]["false_alarms"] - med),
                                     s["candidate"]["false_alarms"], s.get("seed") or 0))
    return best, med


def git_commit():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                              text=True, check=True).stdout.strip()
    except Exception:
        return None


def log(runs_dir, **row):
    row = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "git_commit": git_commit(), **row}
    with open(runs_dir / "promotion_log.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def pipeline_running(runs_dir):
    """True if detection is running right now (run_pipeline.sh's flock, or the dashboard's
    heartbeat in runs/.pipeline.readers/). Don't swap models under it."""
    return pipeline_lock.pipeline_running(runs_dir)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--name", required=True, help="run name: folders are <runs-dir>/<name>_s<seed>")
    ap.add_argument("--seeds", help='e.g. "42 43 44"  (or give the folders with --run)')
    ap.add_argument("--run", action="append", default=[],
                    help="explicit run folder, one per seed (repeat); used instead of --seeds")
    ap.add_argument("--auto-promote", action="store_true", help="promote on PASS (you agree in advance)")
    ap.add_argument("--runs-dir", default=str(ROOT / "runs"))
    ap.add_argument("--models-dir", default=str(ROOT / "models"))
    a = ap.parse_args(argv)
    runs_dir, models_dir = Path(a.runs_dir), Path(a.models_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)
    if a.run:
        runs = [str(Path(x)) for x in a.run]
    elif a.seeds:
        runs = [str(runs_dir / f"{a.name}_s{s}") for s in a.seeds.split()]
    else:
        ap.error("give --seeds or at least one --run")
    report_path = runs_dir / f"{a.name}_gate.json"

    # Lock: two runs can never promote at the same time (released automatically when the process ends).
    lock = open(runs_dir / ".promote.lock", "w")
    if fcntl is None:
        print("✗ part_b.py needs a POSIX system (Linux/WSL) for its promote lock")
        return 3
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("✗ another Part B run is promoting right now; try again when it finishes")
        return 3

    # Use the gate result instead of ignoring it.
    gate = subprocess.run(command("PART_B_GATE", [PY, str(ROOT / "scripts/compare_models.py")])
                          + ["--runs", *runs, "--out", str(report_path)], cwd=ROOT)
    if gate.returncode != 0:
        log(runs_dir, name=a.name, runs=runs, gate="FAIL", promoted=False, decision="kept current models")
        print(f"✗ gate FAIL: models/ unchanged. Report: {report_path}")
        return 1

    report = json.loads(report_path.read_text(encoding="utf-8"))
    seed, med = pick_seed(report)
    run = seed["run"]
    why = f"seed {seed.get('seed')}: {seed['candidate']['false_alarms']} false alarms (median {med})"
    if not a.auto_promote:
        log(runs_dir, name=a.name, runs=runs, gate="PASS", promoted=False, chosen=run, why=why,
            decision="ready, waiting for approval")
        print(f"✓ gate PASS. Ready: bash scripts/promote_model.sh {run}   ({why})")
        return 10

    if pipeline_running(runs_dir):
        log(runs_dir, name=a.name, gate="PASS", promoted=False, chosen=run, why=why,
            decision="not promoted: run_pipeline.sh is running")
        print("✗ run_pipeline.sh is running; not swapping models under it. Promote later with:\n"
              f"  bash scripts/promote_model.sh {run}")
        return 3

    # Promote (promote_model.sh runs the schema check and archives the old models first).
    if subprocess.run(command("PART_B_PROMOTE", ["bash", str(ROOT / "scripts/promote_model.sh")])
                      + [run, f"before_{a.name}"], cwd=ROOT).returncode != 0:
        log(runs_dir, name=a.name, gate="PASS", promoted=False, chosen=run,
            decision="promote failed, models/ unchanged")
        print("✗ promote failed; promote_model.sh changes nothing when it fails")
        return 3

    # Seed folders keep merged_features_labeled.json (not merged_labeled.json), so pass it to the smoke test.
    data = Path(run) / "merged_features_labeled.json"
    smoke = command("PART_B_SMOKE", [PY, str(ROOT / "scripts/smoke_models.py")]) + \
        ["--models", str(models_dir), "--reference", run] + (["--data", str(data)] if data.is_file() else [])
    if subprocess.run(smoke, cwd=ROOT).returncode != 0:
        # Smoke test failed → put the previous models back.
        subprocess.run(command("PART_B_ROLLBACK", ["bash", str(ROOT / "scripts/rollback_model.sh")]),
                       cwd=ROOT, env={**os.environ, "MODELS_DIR": str(models_dir)})
        log(runs_dir, name=a.name, gate="PASS", promoted=False, chosen=run, why=why,
            decision="smoke test failed, rolled back")
        print("✗ smoke test failed after promote: rolled back to the previous models")
        return 2

    log(runs_dir, name=a.name, gate="PASS", promoted=True, chosen=run, why=why, decision="promoted")
    print(f"✓ promoted {run} ({why})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
