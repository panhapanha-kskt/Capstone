#!/usr/bin/env python3
"""
run_record.py — Write run_record.json beside a run's models: everything needed to reproduce it.

    python3 scripts/run_record.py --out runs/x [--provenance runs/x/training_provenance.json]
        [--split runs/x/split_manifest.json] [--seed 42] [--copy-merged data/processed/merged_features_labeled.json]

Recorded:
  git        commit, branch, and whether tracked files had uncommitted changes
  python     interpreter version and `pip freeze`
  inputs     sha256 + size of every source file listed in the provenance file
  split      sha256 of the split manifest
  seed       the training seed
  merged     sha256 of the merged labelled data; with --copy-merged the file itself is copied
             into the run folder (data/processed is rewritten by every run)

Never fails the training run: anything that cannot be read is recorded as null with a reason.
"""

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def sha256_file(path, chunk: int = 1 << 20):
    """sha256 hex digest of a file, or None if it cannot be read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


def _cmd(args, cwd=None):
    try:
        r = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=120)
        return r.stdout.strip() if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def git_info(root=PROJECT_ROOT) -> dict:
    commit = _cmd(["git", "rev-parse", "HEAD"], cwd=root)
    if commit is None:
        return {"commit": None, "reason": "not a git checkout or git not installed"}
    # Tracked files only: data/processed is rewritten by every run and would always look dirty.
    status = _cmd(["git", "status", "--porcelain", "--untracked-files=no", "--", ".",
                   ":(exclude)data/processed"], cwd=root)
    return {"commit": commit, "branch": _cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root),
            "uncommitted_changes": bool(status) if status is not None else None,
            "changed_files": status.splitlines()[:50] if status else []}


def pip_freeze() -> list:
    out = _cmd([sys.executable, "-m", "pip", "freeze", "--all"])
    return out.splitlines() if out else []


def input_files(provenance) -> list:
    """sha256 of every source file in training_provenance.json (merge step)."""
    try:
        prov = json.loads(Path(provenance).read_text())
    except (OSError, ValueError, TypeError):
        return []
    files = []
    for entry in prov.get("source_files", []):
        p = entry.get("path") if isinstance(entry, dict) else str(entry)
        if not p:
            continue
        path = Path(p)
        files.append({"path": p, "records": entry.get("records") if isinstance(entry, dict) else None,
                      "bytes": path.stat().st_size if path.is_file() else None,
                      "sha256": sha256_file(path) if path.is_file() else None})
    return files


def build_record(out, provenance=None, split=None, seed=None, merged=None) -> dict:
    return {
        "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_dir": str(out),
        "git": git_info(),
        "python": {"version": platform.python_version(), "executable": sys.executable,
                   "platform": platform.platform()},
        "pip_freeze": pip_freeze(),
        "seed": seed,
        "split_manifest": {"path": str(split), "sha256": sha256_file(split)} if split else None,
        "inputs": input_files(provenance) if provenance else [],
        "merged_labeled": {"path": str(merged), "sha256": sha256_file(merged)} if merged else None,
    }


def write_record(out, provenance=None, split=None, seed=None, merged=None, copy_merged=False,
                 feedback_report=None) -> Path:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    rec = build_record(out, provenance, split, seed, merged)
    # Analyst verdicts used by this run (train_models.sh --feedback): counts, drops, input hash.
    rec["analyst_feedback"] = (json.loads(Path(feedback_report).read_text(encoding="utf-8"))
                               if feedback_report and Path(feedback_report).is_file() else None)
    if copy_merged and merged and Path(merged).is_file():
        dst = out / Path(merged).name
        shutil.copy2(merged, dst)
        rec["merged_labeled"]["copied_to"] = str(dst)
    path = out / "run_record.json"
    path.write_text(json.dumps(rec, indent=2))
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description="Record what produced a training run.")
    ap.add_argument("--out", required=True, help="run folder (the models directory of this run)")
    ap.add_argument("--provenance", help="training_provenance.json (default: <out>/training_provenance.json)")
    ap.add_argument("--split", help="split manifest used for this run")
    ap.add_argument("--seed", type=int)
    ap.add_argument("--merged", help="merged labelled data used for training")
    ap.add_argument("--copy-merged", action="store_true", help="also copy --merged into the run folder")
    ap.add_argument("--feedback-report", help="feedback_report.json from train_models.sh --feedback")
    a = ap.parse_args(argv)
    prov = a.provenance or str(Path(a.out) / "training_provenance.json")
    path = write_record(a.out, prov, a.split, a.seed, a.merged, a.copy_merged, a.feedback_report)
    rec = json.loads(path.read_text())
    g = rec["git"]
    print(f"  Run record -> {path}  (commit {str(g.get('commit'))[:10]}"
          f"{', uncommitted changes' if g.get('uncommitted_changes') else ''}; "
          f"{len(rec['inputs'])} input file(s); {len(rec['pip_freeze'])} packages"
          f"{'; merged data copied' if (rec.get('merged_labeled') or {}).get('copied_to') else ''})")


if __name__ == "__main__":
    main()
