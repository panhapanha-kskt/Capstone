#!/usr/bin/env python3
"""
evaluate_detectors.py — Every detector of one or more runs, with error ranges (T9).

    python3 scripts/evaluate_detectors.py --runs runs/labelled_v3_iforest_s42 runs/..._s43 runs/..._s44 \
        [--group domain|time] [--block-minutes 60] [--n-boot 1000] [--out report.json] [--md report.md]

For each run (a models folder with its split_manifest.json and training data):
  scores the run's frozen TEST rows with Path A, Path B and the fusion (the same scoring
  train_fusion.py uses), plus the record-type rule baseline (TXT/KEY/NULL, no fitting);
  then dns_detect.models.uncertainty.evaluate_detector gives each one point metrics,
  exact 95 % intervals (Clopper-Pearson; Wilson for FPR) and a 95 % cluster bootstrap
  resampled by parent domain (default) or by time block.
Across runs it reports the seed spread (mean, sd, min, max) next to the bootstrap intervals.

Nothing is written to the run folders; scores are cached in runs/_eval_cache/.
Path A needs TensorFlow importable (path_a.py imports keras), as in training.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
CACHE = ROOT / "runs" / "_eval_cache"
DETECTORS = ("fusion", "path_a", "path_b", "rule_record_type")
DATA_NAMES = ("merged_features_labeled.json", "merged_labeled.json")


def find_data(run: Path):
    for n in DATA_NAMES:
        if (run / n).is_file():
            return run / n
    return None


# ───────────────────────── child: scoring with one models folder ─────────────────────────

def _child(data, split, out):
    sys.path.insert(0, str(ROOT / "scripts"))
    from train_fusion import score_dataset
    from dns_detect.models.splits import load_manifest_indices
    from dns_detect.models.baselines import record_type_rule
    from dns_detect.fusion import stacker
    df = score_dataset(data, "dns_trafficformer", missing_b_as_nan=False)
    _tr, _val, te, _miss, _m = load_manifest_indices(split, df)
    te = te[df["label"].iloc[te].notna().to_numpy()]
    t = df.iloc[te]
    loaded = stacker.load()
    if loaded is None:
        raise SystemExit("no fusion model (fusion_lr.pkl) in this folder")
    f_prob, f_lab = stacker.predict(t, *loaded)
    rule = record_type_rule(t).astype(int)
    # Plain unicode arrays (pandas 3 strings become object arrays, which np.load refuses).
    ts = (np.asarray(t["timestamp"].astype(str).tolist(), dtype=str) if "timestamp" in t.columns
          else np.array(["na"] * len(t), dtype=str))
    np.savez_compressed(
        out, y=t["label"].astype(int).to_numpy(),
        a_score=t["ml_score_A"].to_numpy(float), a_label=t["ml_label_A"].to_numpy(int),
        b_score=np.nan_to_num(t["ml_score_B"].to_numpy(float)), b_label=t["ml_label_B"].to_numpy(int),
        b_covered=t["covered_B"].to_numpy(bool),
        f_score=f_prob, f_label=f_lab, rule_label=rule,
        domain=np.asarray(t["parent_domain"].astype(str).tolist(), dtype=str), timestamp=ts)


def cache_key(data: Path, split: Path, run: Path) -> str:
    """Changes when the data, the split or the model files change (v2: unicode string arrays)."""
    parts = [str(p.resolve()) + str(p.stat().st_mtime_ns)
             for p in (data, split, run / "fusion_lr.pkl", run / "dns_tunnel_rf.pkl")]
    return hashlib.sha256(("v2|" + "|".join(parts)).encode()).hexdigest()[:16]


def scores_for(run: Path, data: Path, split: Path, refresh=False) -> dict:
    key = cache_key(data, split, run)
    CACHE.mkdir(parents=True, exist_ok=True)
    out = CACHE / f"{run.name}_{key}.npz"
    if refresh or not out.exists():
        env = {**os.environ, "DNS_DETECT_MODELS_DIR": str(run.resolve()), "PYTHONPATH": str(ROOT / "src")}
        print(f"• scoring {run} …", flush=True)
        r = subprocess.run([sys.executable, __file__, "--_child", str(data), str(split), str(out)], env=env)
        if r.returncode != 0 or not out.exists():
            raise SystemExit(f"scoring failed for {run}")
    z = np.load(out, allow_pickle=False)
    return {k: z[k] for k in z.files}


# ───────────────────────── parent: metrics and report ─────────────────────────

def detector_inputs(s: dict) -> dict:
    return {
        "fusion": (s["f_score"], s["f_label"]),
        "path_a": (s["a_score"], s["a_label"]),
        "path_b": (s["b_score"], s["b_label"]),
        "rule_record_type": (s["rule_label"].astype(float), s["rule_label"]),
    }


def evaluate_run(s: dict, group: str, block_minutes: int, n_boot: int, seed: int) -> dict:
    from dns_detect.models.uncertainty import evaluate_detector, time_blocks
    groups = s["domain"] if group == "domain" else time_blocks(s["timestamp"], block_minutes)
    res = {name: evaluate_detector(s["y"], sc, lab, groups, n_boot=n_boot, seed=seed)
           for name, (sc, lab) in detector_inputs(s).items()}
    res["path_b"]["coverage"] = float(np.mean(s["b_covered"]))
    return res


SPREAD_KEYS = ("false_alarms", "fpr", "recall", "precision", "f1", "pr_auc", "roc_auc", "recall_at_fpr_0.001")


def summarise(per_run: dict) -> dict:
    from dns_detect.models.uncertainty import seed_spread
    return {det: {k: seed_spread([r[det]["point"].get(k) for r in per_run.values()]) for k in SPREAD_KEYS}
            for det in DETECTORS}


def _pct(v):
    return "n/a" if v is None else f"{v:.2%}"


def _ci(c):
    return "n/a" if not c else f"[{c[0]:.2%}, {c[1]:.2%}]"


def markdown(rep: dict) -> str:
    lines = [f"Grouping for the bootstrap: **{rep['group']}**, {rep['n_boot']} resamples, 95% intervals. "
             "Exact = Clopper-Pearson (Wilson in brackets for FPR). Recall@FPR 0.1% is descriptive.", ""]
    for run, res in rep["runs"].items():
        lines += [f"**{run}**", "",
                  "| Detector | Recall (exact / bootstrap) | False alarms | FPR | FPR exact (Wilson) | FPR bootstrap "
                  "| Precision | F1 | PR-AUC | ROC-AUC | Recall@FPR 0.1% |",
                  "|---|---|---|---|---|---|---|---|---|---|---|"]
        for det in DETECTORS:
            r = res[det]; p, e, b = r["point"], r["exact"], r["bootstrap"] or {}
            extra = f" (covers {r['coverage']:.0%})" if "coverage" in r else ""
            lines.append(
                f"| {det}{extra} | {_pct(p['recall'])} {_ci(e['recall_clopper_pearson'])} / {_ci(b.get('recall'))} "
                f"| {p['false_alarms']}/{p['benign']} | {_pct(p['fpr'])} | {_ci(e['fpr_clopper_pearson'])} "
                f"({_ci(e['fpr_wilson'])}) | {_ci(b.get('fpr'))} | {p['precision']:.4f} | {p['f1']:.4f} "
                f"| {p['pr_auc'] if p['pr_auc'] is None else round(p['pr_auc'], 4)} "
                f"| {p['roc_auc'] if p['roc_auc'] is None else round(p['roc_auc'], 4)} "
                f"| {_pct(p.get('recall_at_fpr_0.001'))} |")
        lines.append("")
    if len(rep["runs"]) > 1:
        lines += ["**Seed spread** (training randomness; mean ± sd, min–max over runs)", "",
                  "| Detector | False alarms | FPR | Recall | F1 | PR-AUC |", "|---|---|---|---|---|---|"]
        for det in DETECTORS:
            sp = rep["seed_spread"][det]

            def f(k, pct=False):
                v = sp.get(k)
                if not v:
                    return "n/a"
                if pct:
                    return f"{v['mean']:.2%} ± {v['sd']:.2%} ({v['min']:.2%}–{v['max']:.2%})"
                return f"{v['mean']:.4g} ± {v['sd']:.3g} ({v['min']:.4g}–{v['max']:.4g})"
            lines.append(f"| {det} | {f('false_alarms')} | {f('fpr', True)} | {f('recall', True)} "
                         f"| {f('f1')} | {f('pr_auc')} |")
    return "\n".join(lines)


def main(argv=None):
    if len(sys.argv) > 1 and sys.argv[1] == "--_child" and argv is None:
        return _child(*sys.argv[2:5])
    ap = argparse.ArgumentParser(description="All detectors with error ranges, over one or more runs.")
    ap.add_argument("--runs", nargs="+", required=True)
    ap.add_argument("--group", choices=("domain", "time"), default="domain")
    ap.add_argument("--block-minutes", type=int, default=60)
    ap.add_argument("--n-boot", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=0, help="bootstrap seed")
    ap.add_argument("--refresh", action="store_true", help="re-score instead of using the cache")
    ap.add_argument("--out", help="JSON report")
    ap.add_argument("--md", help="Markdown tables")
    a = ap.parse_args(argv)

    per_run = {}
    for r in a.runs:
        run = Path(r)
        data, split = find_data(run), run / "split_manifest.json"
        if data is None or not split.is_file():
            raise SystemExit(f"{run}: needs split_manifest.json and {' or '.join(DATA_NAMES)}")
        s = scores_for(run, data, split, a.refresh)
        per_run[run.name] = evaluate_run(s, a.group, a.block_minutes, a.n_boot, a.seed)
    rep = {"group": a.group, "block_minutes": a.block_minutes if a.group == "time" else None,
           "n_boot": a.n_boot, "runs": per_run,
           "seed_spread": summarise(per_run) if len(per_run) > 1 else None}
    md = markdown(rep)
    print(md)
    if a.out:
        Path(a.out).write_text(json.dumps(rep, indent=2))
        print(f"\nreport → {a.out}")
    if a.md:
        Path(a.md).write_text(md + "\n")
        print(f"tables → {a.md}")


if __name__ == "__main__":
    sys.exit(main())
