#!/usr/bin/env python3
"""
eval_bridge.py — Read-only end-to-end evaluation of the bridge's decision methods.

Compares, on the SAME rows (the split manifest's test rows, trusted labels only):
  1. OR gate                    ml_combined_label_or (per-path labels)
  2. legacy max-blend           max(A, 0.6·A + 0.4·B) >= Path A's threshold (the old *_thr column)
  3. existing LR fusion (V1)    models/fusion_lr.*
  4. improved LR fusion (V2)    models/fusion_lr_v2.*
all through bridge.merge_ml_scores (the production code path, detection allowlist included).
Per-split / per-seed numbers for the learned methods come from scripts/eval_fusion.py
(outputs/fusion_eval/results.json), which refits them on rows Path A/B never saw.

Ablations: Path A removed (production must refuse, development must mark every row degraded),
Path B removed (every Path B score NaN), plus an optional CLI check that the bridge process
exits non-zero in production when the Path A model file is absent (--cli-ablation).

Nothing in models/ or data/ is written. Output: outputs/bridge_eval/results.json.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from dns_detect.fusion import bridge, stacker  # noqa: E402
from dns_detect.ingest.labeling import validate_training_labels  # noqa: E402
from dns_detect.models.path_a import _training_setting, load_threshold  # noqa: E402
from dns_detect.models.splits import load_manifest_indices  # noqa: E402
from eval_fusion import metric_block  # noqa: E402


def frame_for_bridge(df: pd.DataFrame) -> pd.DataFrame:
    """Scored rows in the shape merge_ml_scores receives from run_bridge."""
    f = df.copy()
    f["ml_label_A"] = pd.to_numeric(f["ml_label_A"], errors="coerce")
    return f


def merge(f: pd.DataFrame, fusion: str, mode: str = "production", allowlist=None):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        out = bridge.merge_ml_scores(f, f["ml_score_B"], f["ml_label_B"],
                                     covered_b=f["has_score_B"].to_numpy(dtype=bool),
                                     mode=mode, fusion=fusion, allowlist=allowlist)
    return bridge.ensure_week4_compatible(out)


def method_metrics(y, out: pd.DataFrame, label_col: str, score_col: str, brier_ok: bool) -> dict:
    m = metric_block(y, out[label_col].to_numpy(int), out[score_col].fillna(0.0).to_numpy(float), brier_ok)
    m.pop("pr_curve", None)
    m["records_per_tier"] = out["ml_confidence"].value_counts().to_dict()
    m["non_lr_share"] = float((out["fusion_method"] != "lr").mean())
    m["degraded_records"] = int((out["fusion_method"] == "degraded").sum())
    return m


def silently_benign(out: pd.DataFrame) -> int:
    """Rows without a Path A score that look like ordinary benign output."""
    no_a = out["ml_score_A"].isna()
    return int((no_a & ((out["ml_confidence"] == "CLEAN") | (out["ml_combined_verdict"] == "ml_benign")
                        | (out["fusion_method"] != "degraded"))).sum())


def cli_ablation(labeled: str) -> dict:
    """Bridge process with the Path A model removed (temp models dir): production must fail."""
    tmp = Path(tempfile.mkdtemp(prefix="bridge_ablation_"))
    try:
        for f in (ROOT / "models").iterdir():
            if f.is_file() and f.name not in ("dns_tunnel_rf.pkl",):
                shutil.copy2(f, tmp / f.name)
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "DNS_DETECT_MODELS_DIR": str(tmp),
               "PYTHONIOENCODING": "utf-8", "TF_CPP_MIN_LOG_LEVEL": "3"}
        base = [sys.executable, "-m", "dns_detect.fusion.bridge", "--week3", labeled, "--no-path-b"]
        prod = subprocess.run(base + ["--output", str(tmp / "prod.json")], env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=900)
        dev = subprocess.run(base + ["--output", str(tmp / "dev.json"), "--dev", "--allow-missing-path-a"],
                             env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                             timeout=900)
        res = {"production_exit_code": prod.returncode,
               "production_error": (prod.stderr.strip().splitlines() or [""])[-1][:300],
               "production_wrote_output": (tmp / "prod.json").exists(),
               "development_exit_code": dev.returncode}
        if (tmp / "dev.json").exists():
            d = pd.DataFrame(json.loads((tmp / "dev.json").read_text()))
            res.update({"development_rows": int(len(d)),
                        "development_degraded": int((d["fusion_method"] == "degraded").sum()),
                        "development_silently_benign": silently_benign(d)})
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Read-only bridge evaluation: OR vs legacy blend vs LR V1 vs LR V2")
    ap.add_argument("--labeled", required=True)
    ap.add_argument("--split-manifest", required=True)
    ap.add_argument("--path-b-model", default="dns_trafficformer")
    ap.add_argument("--cache", default="outputs/fusion_eval/scored.pkl")
    ap.add_argument("--fusion-results", default="outputs/fusion_eval/results.json")
    ap.add_argument("--cli-ablation", action="store_true", help="also run the bridge CLI with Path A removed")
    ap.add_argument("--out", default="outputs/bridge_eval/results.json")
    args = ap.parse_args()

    if args.cache and os.path.exists(args.cache):
        df = pd.read_pickle(args.cache)
    else:
        from train_fusion import score_dataset
        df = score_dataset(args.labeled, args.path_b_model, missing_b_as_nan=True)
    df["has_score_B"] = df["ml_score_B"].notna().astype(int)
    _, _, te, _, _ = load_manifest_indices(args.split_manifest, df)
    te = te[df["label"].iloc[te].notna().to_numpy()]
    T = frame_for_bridge(df.iloc[te].reset_index(drop=True))
    y = T["label"].astype(int).to_numpy()
    labels = validate_training_labels(T, allow_untrusted=True, context="evaluation labels")
    allow = bridge.load_detection_allowlist()
    fpr_budget = float(_training_setting("path_a_max_fpr", 0.001))
    print(f"[*] test rows: {len(T)} ({int(y.sum())} attack / {int((y == 0).sum())} benign); "
          f"label sources {labels['by_source']}; Path B coverage {T['has_score_B'].mean():.1%}")

    runs = {}
    # The detection allowlist is applied to EVERY method's decision, so the comparison is like-for-like.
    allowed = bridge.allowlisted(T["domain"] if "domain" in T.columns else pd.Series([""] * len(T)), allow)
    out_or = merge(T, "or", allowlist=allow)
    runs["or_gate"] = method_metrics(y, out_or.assign(lab=out_or["ml_combined_label_or"] * ~allowed), "lab",
                                     "ml_combined_score_legacy", brier_ok=False)
    runs["or_gate_no_allowlist"] = method_metrics(y, out_or.assign(lab=out_or["ml_combined_label_or"]), "lab",
                                                  "ml_combined_score_legacy", brier_ok=False)
    thr_a = float(load_threshold())
    legacy = out_or.assign(lab=((out_or["ml_combined_score_legacy"] >= thr_a) & ~allowed).astype(int))
    runs["legacy_max_blend"] = method_metrics(y, legacy, "lab", "ml_combined_score_legacy", brier_ok=False)
    runs["legacy_max_blend"]["threshold"] = thr_a
    outs = {"or": out_or}
    for name, fusion in (("lr_v1", "lr"), ("lr_v2", "lr_v2")):
        try:
            o = merge(T, fusion, allowlist=allow)
        except bridge.ModelUnavailableError as e:
            runs[name] = {"status": f"unavailable: {e}"}
            continue
        outs[name] = o
        runs[name] = method_metrics(y, o, "ml_combined_label", "ml_combined_score", brier_ok=True)
        runs[name]["tier_source"] = o["confidence_method"].iloc[0]
        runs[name]["benign_share_by_tier"] = {
            t: {"benign": int(((o["ml_confidence"] == t) & (y == 0)).sum()),
                "per_10k_benign": float(1e4 * ((o["ml_confidence"] == t) & (y == 0)).sum() / max(1, (y == 0).sum()))}
            for t in ("HIGH", "MEDIUM", "LOW", "CLEAN", "UNSCORED")}

    print(f"\n   {'method':18s} {'recall':>7s} {'FPR':>8s} {'alarms/10k':>11s} {'precision':>10s} {'F1':>6s} {'PR-AUC':>7s}")
    for k, m in runs.items():
        if "recall" in m:
            print(f"   {k:18s} {m['recall']:7.3f} {m['fpr']:8.4f} {m['alarms_per_10k_benign']:11.1f} "
                  f"{m['precision']:10.3f} {m['f1']:6.3f} {m['pr_auc'] if m['pr_auc'] is None else round(m['pr_auc'], 4)}")
        else:
            print(f"   {k:18s} {m['status']}")

    # ── ablations (merge_ml_scores, the production code path) ──
    abl = {}
    noA = T.assign(ml_score_A=np.nan, ml_label_A=np.nan)
    try:
        merge(noA, "lr", mode="production", allowlist=allow)
        abl["path_a_removed_production"] = "DID NOT RAISE"
    except bridge.ModelUnavailableError as e:
        abl["path_a_removed_production"] = f"raised ModelUnavailableError: {str(e)[:120]}"
    d = merge(noA, "lr", mode="development", allowlist=allow)
    abl["path_a_removed_development"] = {"rows": int(len(d)), "degraded": int((d["fusion_method"] == "degraded").sum()),
                                         "silently_benign": silently_benign(d),
                                         "tiers": d["ml_confidence"].value_counts().to_dict()}
    noB = T.assign(ml_score_B=np.nan, ml_label_B=np.nan, has_score_B=0)
    b = merge(noB, "lr", allowlist=allow)
    abl["path_b_removed"] = {"rows": int(len(b)), "path_b_nan": int(b["ml_score_B"].isna().sum()),
                             **{k: v for k, v in method_metrics(y, b, "ml_combined_label", "ml_combined_score", True).items()
                                if k in ("recall", "fpr", "alarms_per_10k_benign", "false_alarms")}}
    if args.cli_ablation:
        print("\n[*] CLI ablation (bridge process, Path A model removed) …")
        abl["cli_path_a_removed"] = cli_ablation(args.labeled)

    # ── reproducibility ──
    again = merge(T, "lr", allowlist=allow)
    reproducible = bool(outs.get("lr_v1") is not None and again["ml_combined_score"].equals(outs["lr_v1"]["ml_combined_score"]))

    # ── data integrity on the full labeled file ──
    integrity = {"rows": int(len(df)), "path_b_uncovered": int(df["ml_score_B"].isna().sum()),
                 "path_a_missing": int(df["ml_score_A"].isna().sum()),
                 "label_sources_all_rows": validate_training_labels(df, allow_untrusted=True,
                                                                    context="all rows")["by_source"]}

    fusion_eval = None
    if os.path.exists(args.fusion_results):
        fr = json.loads(Path(args.fusion_results).read_text())
        fusion_eval = {"summary": fr.get("summary"), "gate": fr.get("gate")}

    v1 = runs.get("lr_v1", {})
    orr = runs["or_gate"]
    failure_ok = (abl["path_a_removed_production"].startswith("raised")
                  and abl["path_a_removed_development"]["degraded"] == len(T)
                  and abl["path_a_removed_development"]["silently_benign"] == 0
                  and abl["path_b_removed"]["path_b_nan"] == len(T)
                  and (not args.cli_ablation or (abl["cli_path_a_removed"]["production_exit_code"] != 0
                                                 and not abl["cli_path_a_removed"]["production_wrote_output"])))
    gate = {
        "1_lr_alarms_per_10k_below_or": {"lr_v1": v1.get("alarms_per_10k_benign"), "or": orr["alarms_per_10k_benign"],
                                         "pass": v1.get("alarms_per_10k_benign", 1e9) < orr["alarms_per_10k_benign"]},
        "2_recall_within_0.02_of_or": {"lr_v1": v1.get("recall"), "or": orr["recall"],
                                       "pass": v1.get("recall", 0) >= orr["recall"] - 0.02},
        "3_independent_labels": {"untrusted_rows": labels["untrusted"], "pass": labels["untrusted"] == 0},
        "4_reproducible": {"pass": reproducible},
        "5_failure_behaviour": {"pass": bool(failure_ok)},
        "6_stacker_v2_gate": {"pass": bool(fusion_eval and fusion_eval["gate"] and fusion_eval["gate"]["accepted"])},
    }
    decision = {
        "learned_fusion_v1_as_default": all(gate[k]["pass"] for k in list(gate)[:5]),
        "promote_v2": all(g["pass"] for g in gate.values()),
    }
    result = {"rows": int(len(T)), "attack": int(y.sum()), "benign": int((y == 0).sum()), "fpr_budget": fpr_budget,
              "label_provenance": labels, "path_b_coverage": float(T["has_score_B"].mean()),
              "methods": runs, "ablations": abl, "reproducible": reproducible, "integrity": integrity,
              "fusion_eval": fusion_eval, "gate": gate, "decision": decision}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2, default=float))
    print("\n[*] ablations:", json.dumps(abl, indent=1, default=str))
    print("\n[*] gate:")
    for k, g in gate.items():
        print(f"   {'PASS' if g['pass'] else 'FAIL'}  {k}")
    print(f"[*] decision: {decision}  → {args.out}")


if __name__ == "__main__":
    main()
