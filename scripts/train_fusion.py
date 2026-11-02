#!/usr/bin/env python3
"""
train_fusion.py — Learned fusion of Path A + Path B + rules (ML_IMPROVEMENT_GUIDE Step 7).

Prerequisite: Path A and Path B trained on the SAME split manifest, so that the manifest's
validation and test rows were never used to fit either model:

    python -m dns_detect.models.path_a --train data/processed/merged_features_labeled.json \
        --split-manifest data/processed/splits/time_seed42.json
    python -m dns_detect.models.path_b_train --filename merged_features_labeled.json \
        --data_dir data/processed --n_days 20 --save_name dns_trafficformer \
        --split-manifest data/processed/splits/time_seed42.json

Then:
    python scripts/train_fusion.py --labeled data/processed/merged_features_labeled.json \
        --split-manifest data/processed/splits/time_seed42.json

The logistic regression and its false-alarm-budget threshold are fitted on validation rows;
the test rows are used once, to compare Path A alone, Path B alone, the OR rule and the
learned fusion at their own thresholds. Enable it with `ensemble.fusion: lr` in settings.yaml.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.parsing.dns_parser import load_as_dataframe  # noqa: E402
from dns_detect.models.path_a import score_frame, _training_setting  # noqa: E402
from dns_detect.models.path_b_predict import score_records  # noqa: E402
from dns_detect.models.splits import load_manifest_indices  # noqa: E402
from dns_detect.models.thresholds import rates  # noqa: E402
from dns_detect.fusion import stacker  # noqa: E402


def _by_family(y, pred, fam):
    return {str(f): float(pred[(y == 1) & (fam == f)].mean())
            for f in sorted(set(fam[y == 1]))}


def main():
    ap = argparse.ArgumentParser(description="Train the logistic-regression fusion of Path A + Path B + rules")
    ap.add_argument("--labeled", required=True, help="labeled JSON both paths were trained from")
    ap.add_argument("--split-manifest", required=True, help="the manifest both paths were trained with")
    ap.add_argument("--path-b-model", default="dns_trafficformer")
    args = ap.parse_args()

    df = load_as_dataframe(args.labeled)
    # Path B scores follow the file's record order, so they are attached before any filtering.
    score_b, label_b, covered, _ = score_records(args.labeled, args.path_b_model)
    df["ml_score_B"], df["ml_label_B"] = score_b, label_b
    df["ml_score_A"], df["ml_label_A"], _, _ = score_frame(df)

    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    tr, val, te, missing, manifest = load_manifest_indices(args.split_manifest, df)
    val = val[df["label"].iloc[val].notna().to_numpy()]
    te = te[df["label"].iloc[te].notna().to_numpy()]
    y = df["label"].fillna(0).astype(int).to_numpy()
    fam = (df["attack_family"].fillna("benign").astype(str).to_numpy()
           if "attack_family" in df.columns else np.where(y == 1, "attack", "benign"))
    print(f"[*] manifest {os.path.basename(args.split_manifest)} → val={len(val)}  test={len(te)}  "
          f"(Path B covers {covered[te].mean():.0%} of test rows)")

    max_fpr = float(_training_setting("path_a_max_fpr", 0.001))
    lr, meta = stacker.fit(df.iloc[val], y[val], max_fpr)
    lr_prob, lr_label = stacker.predict(df.iloc[te], lr, meta)
    print(f"[*] fusion weights: {meta['coefficients']}  intercept={meta['intercept']:.3f}  "
          f"threshold={meta['threshold']:.4f}")

    yt, ft = y[te], fam[te]
    a = df["ml_label_A"].to_numpy()[te]
    b = df["ml_label_B"].to_numpy()[te]
    candidates = {"path_a": a, "path_b": b, "or_rule": ((a == 1) | (b == 1)).astype(int), "learned_lr": lr_label}
    results = {}
    print(f"\n   {'detector':12s} {'recall':>8s} {'FPR':>8s} {'false alarms':>13s} {'precision':>10s}")
    for name, pred in candidates.items():
        r = rates(yt, pred)
        r["recall_by_family"] = _by_family(yt, pred, ft)
        results[name] = r
        print(f"   {name:12s} {r['recall']:8.3f} {r['fpr']:8.4f} {r['false_alarms']:>8d}/{r['benign']:<5d} "
              f"{r['precision']:10.3f}")

    stacker.save(lr, {**meta, "split": os.path.basename(args.split_manifest), "test_rows": int(len(te))})
    metrics_path = ROOT / "models" / "evaluation_metrics.json"
    try:
        allm = json.loads(metrics_path.read_text())
    except Exception:
        allm = {}
    allm["fusion"] = {"split": os.path.basename(args.split_manifest), "test_rows": int(len(te)),
                      "fpr_budget": max_fpr, "model": meta, "test": results}
    metrics_path.write_text(json.dumps(allm, indent=2))
    print(f"\n[+] Saved {stacker.MODEL_FUSION} and metrics → {metrics_path} (key: fusion)")
    print("    Enable with `ensemble.fusion: lr` in config/settings.yaml.")


if __name__ == "__main__":
    main()
