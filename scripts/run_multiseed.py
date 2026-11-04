#!/usr/bin/env python3
"""
run_multiseed.py — Train Path A, Path B and the fusion with several seeds; report mean ± sd.

TEST_REPORT §5 limitation 4: the trained models were run once (seed 42), so it was unknown how
much the numbers move with another seed. Each seed trains into its own folder
(DNS_DETECT_MODELS_DIR=<out-root>/seed<N>), so models/ is never touched.

--manifest may contain "{seed}" to use a different split per seed (e.g. capture_group_seed{seed}).
With a fixed manifest (e.g. time_seed42.json: the time split holds the same rows for every seed)
only the model seed changes: tree sampling, validation halves, autoencoder init and noise.

Usage:
  python3 scripts/run_multiseed.py --data data/processed/week4/merged_week4.json \
      --manifest data/processed/week4/splits/time_seed42_cic.json --seeds 42 43 44 45 46
  python3 scripts/run_multiseed.py ... --skip-path-b      # Path A only (minutes, not hours)
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]

METRICS = ("recall", "fpr", "false_alarms", "pr_auc")


def _run(cmd, env, log):
    with open(log, "a", encoding="utf-8") as f:
        f.write(f"\n$ {' '.join(cmd)}\n")
        f.flush()
        r = subprocess.run(cmd, cwd=ROOT, env=env, stdout=f, stderr=subprocess.STDOUT)
    if r.returncode:
        sys.exit(f"[error] failed (exit {r.returncode}): {' '.join(cmd)} — see {log}")


def check_labels(args):
    """Refuse heuristic / weak_behavioral labels before any seed trains (see ingest/labeling.py)."""
    sys.path.insert(0, str(ROOT / "src"))
    from dns_detect.ingest.labeling import validate_training_labels
    return validate_training_labels(json.loads(Path(args.data).read_text()),
                                    allow_untrusted=args.allow_heuristic_labels, context="run_multiseed")


def train_seed(seed, args):
    out = Path(args.out_root) / f"seed{seed}"
    out.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "DNS_DETECT_MODELS_DIR": str(out.resolve()), "PYTHONPATH": str(ROOT / "src")}
    manifest = args.manifest.format(seed=seed)
    log = out / "train.log"
    py = sys.executable
    print(f"[*] seed {seed}: training → {out}  (log: {log})", flush=True)
    _run([py, "-m", "dns_detect.models.path_a", "--train", args.data, "--split-manifest", manifest,
          "--no-transformer", "--seed", str(seed)], env, log)
    if not args.skip_path_b:
        data = Path(args.data)
        _run([py, "-m", "dns_detect.models.path_b_train", "--filename", data.name,
              "--data_dir", str(data.parent), "--n_days", "20", "--save_name", "dns_trafficformer",
              "--split-manifest", manifest, "--seed", str(seed)], env, log)
        fusion = [py, "scripts/train_fusion.py", "--labeled", args.data, "--split-manifest", manifest]
        if args.allow_heuristic_labels:
            fusion.append("--allow-heuristic-labels")
        _run(fusion, env, log)
    return json.loads((out / "evaluation_metrics.json").read_text())


def collect(m):
    row = {}
    for name, block in (("path_a", m.get("path_a")), ("path_b", m.get("path_b"))):
        for k in METRICS:
            if block and block.get(k) is not None:
                row[f"{name}.{k}"] = float(block[k])
    for name, block in (m.get("fusion", {}).get("test") or {}).items():
        for k in METRICS:
            if block.get(k) is not None:
                row[f"fusion_{name}.{k}"] = float(block[k])
    return row


def main():
    ap = argparse.ArgumentParser(description="Repeat training over seeds and report mean ± sd.")
    ap.add_argument("--data", required=True, help="labeled training file")
    ap.add_argument("--manifest", required=True, help="split manifest; may contain {seed}")
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44, 45, 46])
    ap.add_argument("--out-root", default="models_multiseed")
    ap.add_argument("--skip-path-b", action="store_true", help="Path A only (no Path B, no fusion)")
    ap.add_argument("--out", default=None, help="summary JSON (default: <out-root>/summary.json)")
    ap.add_argument("--allow-heuristic-labels", action="store_true",
                    help="EXPERIMENTAL: train even if some labels are heuristic / weak_behavioral")
    args = ap.parse_args()
    print(f"[*] label provenance: {check_labels(args)['by_source']}")

    per_seed = {s: collect(train_seed(s, args)) for s in args.seeds}
    keys = sorted({k for r in per_seed.values() for k in r})
    summary = {}
    print(f"\n{'metric':34s} {'mean':>10s} {'sd':>10s} {'min':>10s} {'max':>10s}")
    for k in keys:
        v = np.array([per_seed[s][k] for s in args.seeds if k in per_seed[s]])
        summary[k] = {"mean": float(v.mean()), "sd": float(v.std(ddof=1)) if len(v) > 1 else 0.0,
                      "min": float(v.min()), "max": float(v.max()), "n": int(len(v))}
        print(f"{k:34s} {v.mean():10.4f} {summary[k]['sd']:10.4f} {v.min():10.4f} {v.max():10.4f}")
    out = args.out or str(Path(args.out_root) / "summary.json")
    Path(out).write_text(json.dumps({"data": args.data, "manifest": args.manifest, "seeds": args.seeds,
                                     "per_seed": per_seed, "summary": summary}, indent=2))
    print(f"\n[+] summary → {out}")


if __name__ == "__main__":
    main()
