#!/usr/bin/env python3
"""
compare_models.py — Pass/fail gate for a candidate model, against config/success_criteria.yaml.

    python3 scripts/compare_models.py --runs runs/c_s42 runs/c_s43 runs/c_s44 [--out report.json]

Each --runs folder is one seed of the candidate (a DNS_DETECT_MODELS_DIR of train_models.sh,
or a training-console run's model/ folder). For every seed, on that run's own frozen test rows:
  candidate   the judged detector (fusion or Path A) from evaluation_metrics.json
  current     the live models/ Path A, scored on the same rows (read only; never written)
  rules       dns_detect.models.baselines, thresholds fitted on the train rows only
Then the criteria are checked on the mean ± sd over seeds (or on every seed where stated).

Needs each run's split_manifest.json and merged_features_labeled.json (copied into the run
folder by scripts/run_record.py). Without them the current-model and rule checks are skipped
and reported as not run — the gate then fails, it does not guess.
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_CRITERIA = ROOT / "config" / "success_criteria.yaml"


# ─────────────────────────── loading ───────────────────────────

def read_json(p):
    try:
        return json.loads(Path(p).read_text())
    except (OSError, ValueError):
        return None


def load_criteria(path=DEFAULT_CRITERIA) -> dict:
    import yaml
    crit = yaml.safe_load(Path(path).read_text()) or {}
    if crit.get("fpr_budget") is None:
        crit["fpr_budget"] = _settings_budget()
    return crit


def _settings_budget() -> float:
    try:
        import yaml
        s = yaml.safe_load((ROOT / "config" / "settings.yaml").read_text())
        return float(s["training"]["path_a_max_fpr"])
    except Exception:
        return 0.001


def detector_block(ev: dict, detector: str):
    """Test metrics of the judged detector in an evaluation_metrics.json, normalised."""
    from dns_detect.models.thresholds import rate_interval
    if detector == "fusion":
        t = ((ev or {}).get("fusion") or {}).get("test") or {}
        b = t.get("learned_lr")
        if not b:
            return None
        return {"recall": b["recall"], "fpr": b["fpr"], "false_alarms": b["false_alarms"],
                "benign": b["benign"], "attack": b.get("attack"), "f1": b["f1"],
                "precision": b["precision"], "budget_check": b.get("budget_check")}
    pa = (ev or {}).get("path_a")
    if not pa:
        return None
    sup = pa.get("test_support") or {}
    ben = sup.get("benign")
    return {"recall": pa["recall"], "fpr": pa["fpr"], "false_alarms": pa["false_alarms"],
            "benign": ben, "attack": sup.get("attack"), "f1": pa["f1"], "precision": pa["precision"],
            "budget_check": pa.get("budget_check")}


def load_run(run, detector: str) -> dict:
    run = Path(run)
    ev = read_json(run / "evaluation_metrics.json")
    meta = read_json(run / "training_metadata.json") or {}
    rec = read_json(run / "run_record.json") or {}
    pa = (ev or {}).get("path_a") or {}
    twin = pa.get("test_without_train_twin") or {}
    return {
        "run": str(run),
        "seed": meta.get("seed", rec.get("seed")),
        "split_sha256": meta.get("split_sha256") or (rec.get("split_manifest") or {}).get("sha256"),
        "git_commit": (rec.get("git") or {}).get("commit"),
        "candidate": detector_block(ev, detector),
        "twin_free": {"rows": twin.get("rows"),
                      "recall": (twin.get("metrics") or {}).get("recall"),
                      "false_alarms": (twin.get("metrics") or {}).get("false_alarms")} if twin else None,
    }


def test_frame(run):
    """(df, y, train_idx, test_idx) for a run, from its copied data and split, or None."""
    run = Path(run)
    data = run / "merged_features_labeled.json"
    split = run / "split_manifest.json"
    if not data.is_file() or not split.is_file():
        return None
    import pandas as pd
    from dns_detect.parsing.dns_parser import load_as_dataframe
    from dns_detect.models.splits import load_manifest_indices
    df = load_as_dataframe(str(data))
    lab = pd.to_numeric(df.get("label"), errors="coerce")
    df = df[lab.notna()].reset_index(drop=True)
    df["label"] = pd.to_numeric(df["label"]).astype(int)
    tr, _val, te, _missing, _m = load_manifest_indices(str(split), df)
    return df, df["label"].to_numpy(), tr, te


# ─────────────────────────── scoring ───────────────────────────

def rule_results(df, y, tr, te) -> dict:
    from dns_detect.models.baselines import fit_all_baselines
    from dns_detect.models.thresholds import rates
    rules = fit_all_baselines(df.iloc[tr], y[tr])
    test = df.iloc[te]
    return {name: rates(y[te], np.asarray(r.predict(test)).astype(int)) for name, r in rules.items()}


def score_current(models_dir, df_test) -> np.ndarray:
    """Hard Path A labels from another models folder, in a child process (read only)."""
    with tempfile.TemporaryDirectory() as tmp:
        rows, out = Path(tmp) / "rows.json", Path(tmp) / "preds.npy"
        df_test.to_json(rows, orient="records")
        env = {**os.environ, "DNS_DETECT_MODELS_DIR": str(models_dir), "PYTHONPATH": str(ROOT / "src")}
        r = subprocess.run([sys.executable, __file__, "--_score-path-a", str(rows), str(out)],
                           env=env, capture_output=True, text=True)
        if r.returncode != 0 or not out.exists():
            raise RuntimeError((r.stderr or r.stdout).strip().splitlines()[-1] if (r.stderr or r.stdout)
                               else "scoring failed")
        return np.load(out)


def _score_child(rows, out):
    from dns_detect.parsing.dns_parser import load_as_dataframe
    from dns_detect.models.path_a import score_frame
    _scores, preds, _thr, _dec = score_frame(load_as_dataframe(rows))
    np.save(out, np.asarray(preds).astype(int))


# ─────────────────────────── gate ───────────────────────────

def mean_sd(values):
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return None
    return {"mean": statistics.fmean(vals), "sd": statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "n": len(vals), "values": vals}


def check(name, passed, detail):
    return {"criterion": name, "passed": passed, "detail": detail}


def evaluate(crit: dict, seeds: list) -> dict:
    """seeds: per-seed dicts from load_run(), plus optional 'current' and 'rules' rate blocks."""
    budget = float(crit["fpr_budget"])
    checks = []
    cands = [s["candidate"] for s in seeds]

    n_ok = sum(c is not None for c in cands)
    checks.append(check("seeds", n_ok >= int(crit.get("min_seeds", 3)),
                        f"{n_ok} seed(s) with {crit.get('detector', 'fusion')} test metrics; "
                        f"need >= {crit.get('min_seeds', 3)}"))
    if crit.get("same_split", True):
        shas = {s.get("split_sha256") for s in seeds}
        checks.append(check("same split", len(shas) == 1 and None not in shas,
                            f"split sha256 values: {sorted(str(x)[:12] for x in shas)}"))
    agg = {k: mean_sd([c[k] for c in cands if c]) for k in ("recall", "fpr", "false_alarms", "f1", "precision")}
    if n_ok == 0:
        return {"criteria": crit, "seeds": seeds, "aggregate": agg, "checks": checks, "passed": False}

    rmin = float(crit.get("recall_min", 0.0))
    worst = min(c["recall"] for c in cands if c)
    checks.append(check("recall floor (every seed)", worst >= rmin, f"lowest recall {worst:.4f}; floor {rmin}"))

    if crit.get("require_point_fpr_within_budget", True):
        m = agg["fpr"]["mean"]
        checks.append(check("FPR within budget (mean)", m <= budget, f"mean test FPR {m:.4%}; budget {budget:.3%}"))
    if crit.get("require_upper_bound_within_budget", False):
        ups = [(c.get("budget_check") or {}).get("upper") for c in cands if c]
        ok = all(u is not None and u <= budget for u in ups)
        checks.append(check("FPR 95% upper bound within budget (every seed)", ok,
                            "upper bounds " + ", ".join("n/a" if u is None else f"{u:.3%}" for u in ups)))

    cur = [s.get("current") for s in seeds]
    if all(isinstance(c, dict) for c in cur):
        tol = float(crit.get("current_recall_tolerance", 0.0))
        cr, kr = statistics.fmean(c["recall"] for c in cur), agg["recall"]["mean"]
        checks.append(check("recall vs current model (mean)", kr >= cr - tol,
                            f"candidate {kr:.4f} vs current {cr:.4f} (tolerance {tol})"))
        if crit.get("current_false_alarms_not_higher", True):
            cf, kf = statistics.fmean(c["false_alarms"] for c in cur), agg["false_alarms"]["mean"]
            checks.append(check("false alarms vs current model (mean)", kf <= cf,
                                f"candidate {kf:.2f} vs current {cf:.2f} on the same test rows"))
    else:
        reasons = sorted({c for c in cur if isinstance(c, str)}) or ["not run"]
        checks.append(check("versus current model", False, "could not score: " + "; ".join(reasons)))

    if crit.get("beat_rule_baselines", True):
        rules = [s.get("rules") for s in seeds]
        if all(isinstance(r, dict) and r for r in rules):
            lost = []
            for s, r in zip(seeds, rules):
                for name, b in r.items():
                    if s["candidate"] and s["candidate"]["f1"] <= b["f1"]:
                        lost.append(f"seed {s.get('seed')}: {name} F1 {b['f1']:.4f} >= {s['candidate']['f1']:.4f}")
            best = max(b["f1"] for r in rules for b in r.values())
            checks.append(check("beats every rule baseline (F1, every seed)", not lost,
                                "; ".join(lost) if lost else f"best rule F1 {best:.4f}"))
        else:
            checks.append(check("beats every rule baseline", False, "rules not scored (missing data or split)"))

    if crit.get("twin_free_recall_min") is not None:
        tf = [(s.get("twin_free") or {}).get("recall") for s in seeds]
        ok = all(v is not None and v >= float(crit["twin_free_recall_min"]) for v in tf)
        checks.append(check("recall without train twins (every seed)", ok, f"values {tf}"))

    return {"criteria": crit, "seeds": seeds, "aggregate": agg, "checks": checks,
            "passed": all(c["passed"] for c in checks)}


def gather(runs, crit) -> list:
    seeds = []
    for run in runs:
        s = load_run(run, crit.get("detector", "fusion"))
        frame = None
        try:
            frame = test_frame(run)
        except Exception as e:
            s["current"] = s["rules"] = f"{Path(run).name}: test rows not loaded ({e})"
        if frame is None and "rules" not in s:
            s["current"] = s["rules"] = (f"{Path(run).name}: no merged_features_labeled.json or "
                                         "split_manifest.json in the run folder")
        if frame is not None:
            df, y, tr, te = frame
            from dns_detect.models.thresholds import rates
            try:
                s["rules"] = rule_results(df, y, tr, te)
            except Exception as e:
                s["rules"] = f"rules failed: {e}"
            cur = ROOT / crit.get("current_models_dir", "models")
            try:
                s["current"] = rates(y[te], score_current(cur, df.iloc[te]))
            except Exception as e:
                s["current"] = f"current model ({cur}) not scored: {e}"
        seeds.append(s)
    return seeds


def _fmt(a, pct=False):
    if not a:
        return "n/a"
    return (f"{a['mean']:.4%} ± {a['sd']:.4%}" if pct else f"{a['mean']:.4f} ± {a['sd']:.4f}")


def print_report(rep: dict):
    print(f"Detector: {rep['criteria'].get('detector', 'fusion')}   budget {float(rep['criteria']['fpr_budget']):.3%}")
    print(f"{'seed':>6} {'recall':>8} {'FPR':>9} {'FA':>5} {'benign':>7} {'F1':>7}   current FA   best rule F1")
    for s in rep["seeds"]:
        c = s["candidate"] or {}
        cur = s.get("current")
        rules = s.get("rules")
        best = max((b["f1"] for b in rules.values()), default=None) if isinstance(rules, dict) else None
        print(f"{str(s.get('seed')):>6} {c.get('recall', float('nan')):8.4f} {c.get('fpr') or 0:9.4%} "
              f"{c.get('false_alarms', '-'):>5} {str(c.get('benign', '-')):>7} {c.get('f1', float('nan')):7.4f}   "
              f"{cur['false_alarms'] if isinstance(cur, dict) else 'n/a':>10}   "
              f"{'n/a' if best is None else f'{best:.4f}':>12}")
    a = rep["aggregate"]
    print(f"mean ± sd: recall {_fmt(a['recall'])} · FPR {_fmt(a['fpr'], True)} · F1 {_fmt(a['f1'])}")
    for c in rep["checks"]:
        print(f"  [{'PASS' if c['passed'] else 'FAIL'}] {c['criterion']}: {c['detail']}")
    print("GATE:", "PASS" if rep["passed"] else "FAIL")


def main(argv=None):
    if argv is None and len(sys.argv) > 1 and sys.argv[1] == "--_score-path-a":
        return _score_child(sys.argv[2], sys.argv[3])
    ap = argparse.ArgumentParser(description="Pass/fail gate for a candidate model over several seeds.")
    ap.add_argument("--runs", nargs="+", required=True, help="run folders, one per seed")
    ap.add_argument("--criteria", default=str(DEFAULT_CRITERIA))
    ap.add_argument("--detector", choices=["fusion", "path_a"], help="override criteria 'detector'")
    ap.add_argument("--out", help="write the full report as JSON")
    a = ap.parse_args(argv)
    crit = load_criteria(a.criteria)
    if a.detector:
        crit["detector"] = a.detector
    rep = evaluate(crit, gather(a.runs, crit))
    print_report(rep)
    if a.out:
        Path(a.out).write_text(json.dumps(rep, indent=2, default=str))
        print(f"report → {a.out}")
    return 0 if rep["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
