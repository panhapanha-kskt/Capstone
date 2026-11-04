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
    # V1 (default, unchanged behaviour) → models/fusion_lr.{pkl,json}
    python scripts/train_fusion.py --labeled data/processed/merged_features_labeled.json \
        --split-manifest data/processed/splits/time_seed42.json

    # V2 → models/fusion_lr_v2.{pkl,json} + models/fusion_fallback_quantiles.json (V1 untouched)
    python scripts/train_fusion.py --version 2 --labeled ... --split-manifest ...

    # Confidence-tier sidecar for the existing V1 model (models/fusion_lr_tiers.json); no training
    python scripts/train_fusion.py --tiers-for-v1 --labeled ... --split-manifest ...

The fusion model and its false-alarm-budget threshold are fitted on validation rows only;
the test rows are used once, to compare Path A alone, Path B alone, the OR rule and the learned
fusion at their own thresholds. Enable V1 with `ensemble.fusion: lr`, V2 with `lr_v2`.

Labels: training refuses rows whose label_source is not independent ground truth (heuristic /
weak_behavioral) unless --allow-heuristic-labels is given (ingest/labeling.validate_training_labels).
"""

import argparse
import json
import logging
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
from dns_detect.ingest.labeling import parent_domain, validate_training_labels  # noqa: E402
from dns_detect.utils.dataset_hash import dataset_hash  # noqa: E402
from dns_detect.utils.paths import MODELS_DIR, PROJECT_ROOT  # noqa: E402

FALLBACK_QUANTILES = MODELS_DIR / "fusion_fallback_quantiles.json"
V1_TIERS = MODELS_DIR / "fusion_lr_tiers.json"


def _by_family(y, pred, fam):
    return {str(f): float(pred[(y == 1) & (fam == f)].mean())
            for f in sorted(set(fam[y == 1]))}


def score_dataset(labeled: str, path_b_model: str, missing_b_as_nan: bool) -> pd.DataFrame:
    """Labeled frame with ml_score_A/B and labels attached. Path B coverage kept as covered_B."""
    df = load_as_dataframe(labeled)
    # Path B scores follow the file's record order, so they are attached before any filtering.
    score_b, label_b, covered, _ = score_records(labeled, path_b_model)
    df["covered_B"] = covered
    df["ml_score_B"] = np.where(covered, score_b, np.nan) if missing_b_as_nan else score_b
    df["ml_label_B"] = label_b
    df["ml_score_A"], df["ml_label_A"], _, _ = score_frame(df)
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    if "parent_domain" not in df.columns:
        df["parent_domain"] = df["domain"].astype(str).map(parent_domain)
    return df


def main():
    ap = argparse.ArgumentParser(description="Train the logistic-regression fusion of Path A + Path B + rules")
    ap.add_argument("--labeled", required=True, help="labeled JSON both paths were trained from")
    ap.add_argument("--split-manifest", required=True, help="the manifest both paths were trained with")
    ap.add_argument("--path-b-model", default="dns_trafficformer")
    ap.add_argument("--version", type=int, choices=(1, 2), default=1,
                    help="1 = original fusion (default, models/fusion_lr.*); 2 = fusion V2 (models/fusion_lr_v2.*)")
    ap.add_argument("--delta", type=float, default=0.05, help="V2: Neyman-Pearson confidence parameter")
    ap.add_argument("--seed", type=int, default=42, help="V2: seed for the grouped fit/calibration split and CV")
    ap.add_argument("--class-weight", choices=("none", "balanced"), default="none", help="V2 only")
    ap.add_argument("--tiers-for-v1", action="store_true",
                    help="write models/fusion_lr_tiers.json for the existing V1 model and exit (no training)")
    ap.add_argument("--allow-heuristic-labels", action="store_true",
                    help="EXPERIMENTAL: train even if some labels are heuristic / weak_behavioral")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="   [%(levelname)s] %(message)s")

    df = score_dataset(args.labeled, args.path_b_model, missing_b_as_nan=(args.version == 2 or args.tiers_for_v1))
    tr, val, te, missing, manifest = load_manifest_indices(args.split_manifest, df)
    val = val[df["label"].iloc[val].notna().to_numpy()]
    te = te[df["label"].iloc[te].notna().to_numpy()]
    label_check = validate_training_labels(df.iloc[val], allow_untrusted=args.allow_heuristic_labels,
                                           context="fusion training (validation rows)")
    y = df["label"].fillna(0).astype(int).to_numpy()
    fam = (df["attack_family"].fillna("benign").astype(str).to_numpy()
           if "attack_family" in df.columns else np.where(y == 1, "attack", "benign"))
    print(f"[*] manifest {os.path.basename(args.split_manifest)} → val={len(val)}  test={len(te)}  "
          f"(Path B covers {df['covered_B'].to_numpy()[te].mean():.0%} of test rows)")
    max_fpr = float(_training_setting("path_a_max_fpr", 0.001))

    if args.tiers_for_v1:
        loaded = stacker.load_versioned(1)
        if loaded is None:
            sys.exit("[!] no V1 fusion model (models/fusion_lr.pkl) to describe")
        v1_df = df.iloc[val].assign(ml_score_B=df["ml_score_B"].iloc[val].fillna(0.0))
        score, _ = stacker.predict(v1_df, *loaded)
        benign = score[y[val] == 0]
        tiers = stacker.tier_boundaries(benign, float(loaded[1]["threshold"]))
        out = {**tiers, "tier_source": "v1_in_sample_val", "threshold_rule": ">=",
               "note": "V1 was fitted on these validation rows, so its benign quantiles are in-sample.",
               "split": os.path.basename(args.split_manifest)}
        V1_TIERS.write_text(json.dumps(out, indent=2))
        print(f"[+] V1 tier boundaries → {V1_TIERS}: {out}")
        return

    if args.version == 1:
        lr, meta = stacker.fit(df.iloc[val], y[val], max_fpr)
        lr_prob, lr_label = stacker.predict(df.iloc[te], lr, meta)
    else:
        groups = df["parent_domain"].astype(str).to_numpy()
        ds = dataset_hash([args.labeled], stacker.FUSION_INPUTS_V2, root=str(PROJECT_ROOT))
        lr, meta, diag = stacker.fit_v2(
            df.iloc[val], y[val], groups[val], max_fpr, delta=args.delta, seed=args.seed,
            class_weight=None if args.class_weight == "none" else "balanced",
            extra_meta={"split": os.path.basename(args.split_manifest), "dataset_sha256": ds,
                        "label_provenance": label_check})
        lr_prob, lr_label = stacker.predict_versioned(df.iloc[te], lr, meta)
        print(f"[*] threshold method: {meta['threshold_method']}  "
              f"(benign calibration rows {meta['n_cal_benign']}, NP needs {meta['n_required_for_np']})")
        print(f"[*] OOF calibration: Brier={meta['oof_calibration']['brier']:.4g}  "
              f"ECE={meta['oof_calibration']['ece']:.4g}  ({meta['cv']['method']}, groups=parent_domain)")
    print(f"[*] fusion weights: {meta['coefficients']}  intercept={meta['intercept']:.3f}  "
          f"threshold={meta['threshold']:.6g}")

    yt, ft = y[te], fam[te]
    a = df["ml_label_A"].to_numpy()[te]
    b = df["ml_label_B"].to_numpy()[te]
    name = "learned_lr" if args.version == 1 else "learned_lr_v2"
    candidates = {"path_a": a, "path_b": b, "or_rule": ((a == 1) | (b == 1)).astype(int), name: lr_label}
    results = {}
    print(f"\n   {'detector':14s} {'recall':>8s} {'FPR':>8s} {'false alarms':>13s} {'precision':>10s}")
    for n, pred in candidates.items():
        r = rates(yt, pred)
        r["recall_by_family"] = _by_family(yt, pred, ft)
        results[n] = r
        print(f"   {n:14s} {r['recall']:8.3f} {r['fpr']:8.4f} {r['false_alarms']:>8d}/{r['benign']:<5d} "
              f"{r['precision']:10.3f}")

    metrics_path = MODELS_DIR / "evaluation_metrics.json"
    try:
        allm = json.loads(metrics_path.read_text())
    except Exception:
        allm = {}
    if args.version == 1:
        stacker.save(lr, {**meta, "split": os.path.basename(args.split_manifest), "test_rows": int(len(te))})
        allm["fusion"] = {"split": os.path.basename(args.split_manifest), "test_rows": int(len(te)),
                          "fpr_budget": max_fpr, "model": meta, "test": results}
        saved = stacker.MODEL_FUSION
    else:
        meta["test_rows"] = int(len(te))
        stacker.save_v2(lr, meta)
        # Frozen benign validation score distributions for the bridge's development-mode OR
        # fallback (empirical benign quantile normalisation). Validation rows only.
        vb = val[y[val] == 0]
        sa = np.sort(df["ml_score_A"].to_numpy()[vb].astype(float))
        sb = df["ml_score_B"].to_numpy()[vb].astype(float)
        sb = np.sort(sb[~np.isnan(sb)])
        FALLBACK_QUANTILES.write_text(json.dumps({
            "source": "validation benign rows", "split": os.path.basename(args.split_manifest),
            "path_a_benign_sorted": sa.tolist(), "path_b_benign_sorted": sb.tolist()}))
        allm["fusion_v2"] = {"split": os.path.basename(args.split_manifest), "test_rows": int(len(te)),
                             "fpr_budget": max_fpr, "model": meta, "test": results,
                             "alignment": diag["alignment"],
                             "oof_reliability": diag["oof_calibration"].get("reliability")}
        saved = stacker.MODEL_FUSION_V2
    metrics_path.write_text(json.dumps(allm, indent=2))
    print(f"\n[+] Saved {saved} and metrics → {metrics_path} (key: {'fusion' if args.version == 1 else 'fusion_v2'})")
    print(f"    Enable with `ensemble.fusion: {'lr' if args.version == 1 else 'lr_v2'}` in config/settings.yaml.")


if __name__ == "__main__":
    main()
