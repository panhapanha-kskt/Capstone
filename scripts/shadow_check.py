#!/usr/bin/env python3
"""Shadow check: score a candidate model on the traffic the detector most recently processed, WITHOUT
alerting, and compare it with the live model's scores on the same rows. Runs after the gate PASSes and
before promote_model.sh (scripts/part_b.py --shadow). It never writes to models/ or to data/.

    python3 scripts/shadow_check.py --candidate runs/<name>_s43 [--name <name>]
    python3 scripts/shadow_check.py --candidate runs/x --live-ml data/processed/week3_features_with_ml.json \
        --features data/processed/week3_features_all.json --out runs/x_shadow.json

Why: the gate judges the candidate on frozen TEST rows; the shadow check judges it on CURRENT traffic,
the way Google's MLOps guide asks for an online validation (canary / A/B) before a model serves live
traffic. A candidate that would suddenly alert on 3x more of today's traffic, or disagree with the live
model on most rows, is held back even though its test metrics passed.

Checks (thresholds from config/soc.yaml `shadow:` or the flags; defaults below):
  flag rate     candidate rows with ml_combined_label == 1 must be <= live rate * (1 + max_rate_increase)
                + max_new_flags_abs (absolute allowance for tiny live rates)
  agreement     share of rows where candidate and live labels agree >= min_agreement
  min rows      at least min_rows scored rows, else exit 4 (not enough live traffic: no verdict)
Exit codes: 0 pass · 1 fail (models/ unchanged) · 4 no live data / too few rows · 3 error.
Env PART_B_SHADOW lets scripts/part_b.py substitute a stub in tests.
"""
import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULTS = {"max_rate_increase": 0.5, "max_new_flags_abs": 20, "min_agreement": 0.95, "min_rows": 200}


def load_records(path):
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    return d.get("records", d) if isinstance(d, dict) else d


def thresholds(args):
    t = dict(DEFAULTS)
    cfg = ROOT / "config" / "soc.yaml"
    if cfg.is_file():
        try:
            import yaml
            sh = (yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}).get("shadow") or {}
            t.update({k: sh[k] for k in DEFAULTS if k in sh})
        except Exception as e:  # config problems must not crash the check: use defaults, say so
            print(f"! could not read shadow thresholds from {cfg}: {e}; using defaults")
    for k in DEFAULTS:
        v = getattr(args, k, None)
        if v is not None:
            t[k] = v
    return t


def path_b_arg(candidate):
    c = Path(candidate)
    if any((c / f"dns_trafficformer{s}").exists() for s in ("_iforest.pkl", ".keras", ".h5")) \
            and (c / "dns_trafficformer_threshold.json").exists():
        return ["--path-b-model", "dns_trafficformer"]
    return ["--no-path-b"]


def score_candidate(candidate, features, out_json):
    """Run the normal ML bridge with the candidate's folder as the model dir; output goes to out_json only."""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src") + os.pathsep + os.environ.get("PYTHONPATH", ""),
           "DNS_DETECT_MODELS_DIR": str(Path(candidate).resolve())}
    cmd = [sys.executable, "-m", "dns_detect.fusion.bridge", "--week3", str(features), "--output", str(out_json),
           "--model-dir", str(Path(candidate).resolve())] + path_b_arg(candidate)
    r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-12:])
        raise RuntimeError(f"bridge failed on the candidate (exit {r.returncode}):\n{tail}")


def compare(live, cand):
    by_id = {}
    for r in live:
        rid = r.get("row_id")
        if rid is not None:
            by_id[rid] = r
    pairs = []
    for i, c in enumerate(cand):
        rid = c.get("row_id", i)
        l = by_id.get(rid) if by_id else (live[i] if i < len(live) else None)
        if l is not None:
            pairs.append((int(l.get("ml_combined_label") or 0), int(c.get("ml_combined_label") or 0)))
    n = len(pairs)
    live_flags = sum(l for l, _ in pairs)
    cand_flags = sum(c for _, c in pairs)
    agree = sum(1 for l, c in pairs if l == c)
    return {"rows": n, "live_flags": live_flags, "candidate_flags": cand_flags,
            "live_rate": live_flags / n if n else None, "candidate_rate": cand_flags / n if n else None,
            "agreement": agree / n if n else None,
            "new_flags": sum(1 for l, c in pairs if c == 1 and l == 0),
            "dropped_flags": sum(1 for l, c in pairs if c == 0 and l == 1)}


def verdict(stats, t):
    checks = []
    n = stats["rows"]
    if n < int(t["min_rows"]):
        return None, [{"check": "rows", "ok": False, "detail": f"{n} scored rows; need >= {t['min_rows']}"}]
    allowed = stats["live_flags"] * (1 + float(t["max_rate_increase"])) + int(t["max_new_flags_abs"])
    checks.append({"check": "flag rate", "ok": stats["candidate_flags"] <= allowed,
                   "detail": f"candidate flags {stats['candidate_flags']} vs live {stats['live_flags']}; "
                             f"allowed <= {allowed:.0f} (live x {1 + float(t['max_rate_increase']):.2f} + {t['max_new_flags_abs']})"})
    checks.append({"check": "agreement", "ok": stats["agreement"] >= float(t["min_agreement"]),
                   "detail": f"{stats['agreement']:.4f} of rows agree; need >= {t['min_agreement']}"})
    return all(c["ok"] for c in checks), checks


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--candidate", required=True, help="run folder of the candidate (a seed folder)")
    ap.add_argument("--name", help="report name: runs/<name>_shadow.json (default: candidate folder name)")
    ap.add_argument("--features", default=str(ROOT / "data/processed/week3_features_all.json"))
    ap.add_argument("--live-ml", default=str(ROOT / "data/processed/week3_features_with_ml.json"),
                    help="the live model's scores on the same traffic (written by the detector)")
    ap.add_argument("--out", help="report path (default runs/<name>_shadow.json)")
    for k in DEFAULTS:
        ap.add_argument(f"--{k.replace('_', '-')}", dest=k, type=float, default=None)
    a = ap.parse_args(argv)
    name = a.name or Path(a.candidate).name
    out = Path(a.out) if a.out else ROOT / "runs" / f"{name}_shadow.json"
    t = thresholds(a)
    report = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "candidate": str(a.candidate), "features": str(a.features), "live_ml": str(a.live_ml),
              "thresholds": t, "passed": None, "checks": [], "stats": None}

    def finish(code, msg):
        report["exit"] = code
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(msg + f"  (report: {out})")
        return code

    if not (Path(a.features).is_file() and Path(a.live_ml).is_file()):
        return finish(4, "✗ shadow: no live traffic to score (run detection first); no verdict")
    tmp = Path(tempfile.mkdtemp(prefix="shadow_", dir=str(out.parent)))
    try:
        try:
            score_candidate(a.candidate, a.features, tmp / "candidate_with_ml.json")
        except RuntimeError as e:
            report["error"] = str(e)
            return finish(3, f"✗ shadow: {e}")
        stats = compare(load_records(a.live_ml), load_records(tmp / "candidate_with_ml.json"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    report["stats"] = stats
    ok, checks = verdict(stats, t)
    report["checks"] = checks
    for c in checks:
        print(f"   {'✓' if c['ok'] else '✗'} {c['check']}: {c['detail']}")
    if ok is None:
        return finish(4, "✗ shadow: too little live traffic for a verdict")
    report["passed"] = ok
    return finish(0 if ok else 1, "✓ shadow check PASS: candidate behaves like the live model on current traffic"
                  if ok else "✗ shadow check FAIL: candidate behaves differently on current traffic; models/ unchanged")


if __name__ == "__main__":
    sys.exit(main())
