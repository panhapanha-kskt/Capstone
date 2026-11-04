#!/usr/bin/env python3
"""
eval_fusion.py — Read-only comparison of Path A, Path B, the OR rule, fusion V1 and fusion V2.

Leakage control. Path A and Path B were trained once, on the train rows of one manifest
(default time_seed42). Only that manifest's validation + test rows — never seen by either base
model — form the evaluation POOL. The pool is re-split with the project's own split definitions
(models/splits.build_indices: capture_group, parent_domain_group, time) for each seed; inside
each run the fusion models are fitted on the run's train+val part and scored once on its test
part. Thresholds are never tuned on a test part. The reference run "manifest" is the original
split (fusion fitted on validation, scored on test).

Nothing is written to models/ or data/. Results go to outputs/fusion_eval/.

    python scripts/eval_fusion.py --labeled data/processed/merged_features_labeled.json \
        --split-manifest data/processed/splits/time_seed42.json
    python scripts/eval_fusion.py ... --cache outputs/fusion_eval/scored.pkl   # reuse base-model scores
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from sklearn.metrics import average_precision_score, precision_recall_curve  # noqa: E402

from dns_detect.fusion import stacker  # noqa: E402
from dns_detect.models import splits as splits_mod  # noqa: E402
from dns_detect.models.path_a import _training_setting  # noqa: E402
from dns_detect.models.splits import load_manifest_indices  # noqa: E402
from dns_detect.models.thresholds import rates  # noqa: E402

STRATEGIES = ("capture_group", "parent_domain_group", "time")
SEEDS = (42, 43, 44, 45, 46)
METHODS = ("path_a", "path_b", "or_rule", "fusion_v1", "fusion_v2", "fusion_v2_balanced")


def wilson(k: int, n: int, z: float = 1.959964) -> list:
    """95% Wilson score interval for a proportion k/n."""
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def metric_block(y, label, score, brier_ok: bool) -> dict:
    y = np.asarray(y).astype(int)
    label = np.asarray(label).astype(int)
    r = rates(y, label)
    tp = int(((label == 1) & (y == 1)).sum()); fn = int(((label == 0) & (y == 1)).sum())
    tn = int(((label == 0) & (y == 0)).sum()); fp = r["false_alarms"]
    out = {**r, "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
           "fpr_ci95": wilson(fp, r["benign"]), "recall_ci95": wilson(tp, r["attack"]),
           "alarms_per_10k_benign": 1e4 * fp / r["benign"] if r["benign"] else None}
    s = np.asarray(score, dtype=float)
    if len(np.unique(y)) == 2 and np.all(np.isfinite(s)):
        out["pr_auc"] = float(average_precision_score(y, s))
        p, rc, _ = precision_recall_curve(y, s)
        keep = np.unique(np.linspace(0, len(p) - 1, min(len(p), 100)).astype(int))
        out["pr_curve"] = {"precision": p[keep].round(5).tolist(), "recall": rc[keep].round(5).tolist()}
    else:
        out["pr_auc"] = None
    out["brier"] = float(np.mean((s - y) ** 2)) if brier_ok and np.all(np.isfinite(s)) else None
    return out


def vif(X: np.ndarray, names) -> dict:
    """Variance inflation factor per column (columns with no variance are reported as None)."""
    out = {}
    for j, n in enumerate(names):
        xj = X[:, j]
        if np.std(xj) == 0:
            out[n] = None
            continue
        others = np.delete(X, j, axis=1)
        others = others[:, np.std(others, axis=0) > 0]
        A = np.column_stack([np.ones(len(xj)), others])
        coef, *_ = np.linalg.lstsq(A, xj, rcond=None)
        resid = xj - A @ coef
        r2 = 1 - resid.var() / xj.var()
        out[n] = float(1 / max(1e-12, 1 - r2))
    return out


def run_once(df: pd.DataFrame, fit_idx: np.ndarray, test_idx: np.ndarray, seed: int, max_fpr: float,
             delta: float) -> dict:
    y = df["label"].astype(int).to_numpy()
    groups = df["parent_domain"].astype(str).to_numpy()
    yf, yt = y[fit_idx], y[test_idx]
    if len(np.unique(yf)) < 2 or len(np.unique(yt)) < 2:
        return {"status": "n/a", "reason": "a part has a single class",
                "fit_classes": np.bincount(yf, minlength=2).tolist(),
                "test_classes": np.bincount(yt, minlength=2).tolist()}
    te = df.iloc[test_idx]
    a_s, a_l = te["ml_score_A"].to_numpy(float), te["ml_label_A"].to_numpy(int)
    b_raw = te["ml_score_B"].to_numpy(float)
    b_l = np.where(np.isnan(b_raw), 0, te["ml_label_B"].to_numpy(int))      # no window → no alarm
    b_s = np.nan_to_num(b_raw, nan=0.0)
    or_l = ((a_l == 1) | (b_l == 1)).astype(int)
    or_s = np.maximum(a_s, 0.6 * a_s + 0.4 * b_s)        # legacy blend, only to rank for PR-AUC

    res = {"status": "ok", "n_fit": int(len(fit_idx)), "n_test": int(len(test_idx)),
           "test_base_rate": float(yt.mean()), "test_benign": int((yt == 0).sum()),
           "test_attack": int((yt == 1).sum()),
           "path_b_coverage_test": float((~np.isnan(b_raw)).mean()), "methods": {}}
    res["methods"]["path_a"] = metric_block(yt, a_l, a_s, brier_ok=True)
    res["methods"]["path_b"] = metric_block(yt, b_l, b_s, brier_ok=False)   # sigmoid(z) is not a probability
    res["methods"]["or_rule"] = metric_block(yt, or_l, or_s, brier_ok=False)

    # V1 — its own legacy semantics: missing Path B is 0.
    fit_v1 = df.iloc[fit_idx].assign(ml_score_B=df["ml_score_B"].iloc[fit_idx].fillna(0.0))
    v1, m1 = stacker.fit(fit_v1, yf, max_fpr)
    p1, l1 = stacker.predict(te.assign(ml_score_B=b_s), v1, m1)
    res["methods"]["fusion_v1"] = {**metric_block(yt, l1, p1, brier_ok=True),
                                   "coefficients": m1["coefficients"], "threshold": m1["threshold"]}

    for name, cw in (("fusion_v2", None), ("fusion_v2_balanced", "balanced")):
        v2, m2, diag = stacker.fit_v2(df.iloc[fit_idx], yf, groups[fit_idx], max_fpr, delta=delta,
                                      seed=seed, class_weight=cw)
        p2, l2 = stacker.predict_versioned(te, v2, m2)
        res["methods"][name] = {**metric_block(yt, l2, p2, brier_ok=True),
                                "coefficients": m2["coefficients"], "threshold": m2["threshold"],
                                "threshold_method": m2["threshold_method"],
                                "n_cal_benign": m2["n_cal_benign"], "oof": m2["oof_calibration"],
                                "test_reliability": stacker.calibration_report(yt, p2)["reliability"]}
        if cw is None:
            X = stacker.fusion_inputs_v2(df.iloc[fit_idx], m2)
            with np.errstate(invalid="ignore", divide="ignore"):
                corr = np.corrcoef(X, rowvar=False)
            res["v2_collinearity"] = {
                "inputs": stacker.FUSION_INPUTS_V2,
                "corr": np.where(np.isfinite(corr), corr, np.nan).round(4).tolist(),
                "vif": vif(X, stacker.FUSION_INPUTS_V2),
                "input_std_fit": dict(zip(stacker.FUSION_INPUTS_V2, X.std(axis=0).round(6).tolist())),
                "alignment": diag["alignment"]}
    return res


def gate(runs: list, max_fpr: float, compat_ok: bool) -> dict:
    ok = [r for r in runs if r["result"]["status"] == "ok"]
    n, n_all = len(ok), len(runs)
    M = lambda r, m: r["result"]["methods"][m]  # noqa: E731
    fpr_ok = sum(1 for r in ok if M(r, "fusion_v2")["fpr"] <= max_fpr)
    rec_ok = sum(1 for r in ok if M(r, "fusion_v2")["recall"] >= M(r, "fusion_v1")["recall"] - 0.01)
    pr_ok = sum(1 for r in ok if (M(r, "fusion_v2")["pr_auc"] or 0) >
                max(M(r, "path_a")["pr_auc"] or 0, M(r, "path_b")["pr_auc"] or 0))
    alarm_ok = sum(1 for r in ok if M(r, "fusion_v2")["alarms_per_10k_benign"] <
                   M(r, "or_rule")["alarms_per_10k_benign"])
    brier_ok = sum(1 for r in ok if M(r, "fusion_v2")["brier"] < M(r, "fusion_v1")["brier"])

    def mean(m, k):
        v = [M(r, m)[k] for r in ok if M(r, m).get(k) is not None]
        return float(np.mean(v)) if v else None

    crit = {
        "1_fpr_budget_met_in_95pct_runs": {"k": fpr_ok, "n": n, "pass": n > 0 and fpr_ok / n >= 0.95},
        "2_recall_not_below_v1_by_0.01": {"k": rec_ok, "n": n, "pass": n > 0 and rec_ok == n,
                                          "mean_v2": mean("fusion_v2", "recall"), "mean_v1": mean("fusion_v1", "recall")},
        "3_pr_auc_beats_best_single_path": {"k": pr_ok, "n": n, "pass": n > 0 and pr_ok / n >= 0.5,
                                            "mean_v2": mean("fusion_v2", "pr_auc"),
                                            "mean_a": mean("path_a", "pr_auc"), "mean_b": mean("path_b", "pr_auc")},
        "4_alarms_per_10k_below_or": {"k": alarm_ok, "n": n, "pass": n > 0 and alarm_ok / n >= 0.5,
                                      "mean_v2": mean("fusion_v2", "alarms_per_10k_benign"),
                                      "mean_or": mean("or_rule", "alarms_per_10k_benign")},
        "5_brier_below_v1": {"k": brier_ok, "n": n, "pass": n > 0 and brier_ok / n >= 0.5,
                             "mean_v2": mean("fusion_v2", "brier"), "mean_v1": mean("fusion_v1", "brier")},
        "6_backward_compatibility": {"pass": bool(compat_ok)},
    }
    return {"runs_total": n_all, "runs_evaluable": n,
            "runs_duplicate": sum(1 for r in runs if r["result"]["status"] == "duplicate"),
            "runs_na": sum(1 for r in runs if r["result"]["status"] == "n/a"), "criteria": crit,
            "accepted": all(c["pass"] for c in crit.values()),
            "note": "Criteria 3-5 use a majority of runs; 1 needs >=95%; 2 needs every run. "
                    "k/n are exact counts, not a statistical guarantee."}


def compat_check(df: pd.DataFrame) -> dict:
    """V1 still loads and predicts identically through load_versioned; V2 metadata validates."""
    out = {}
    v1 = stacker.load_versioned(1)
    if v1 is not None:
        sample = df.head(500).assign(ml_score_B=df["ml_score_B"].head(500).fillna(0.0))
        p_old, l_old = stacker.predict(sample, *v1)
        p_new, l_new = stacker.predict_versioned(sample, *v1)
        out["v1_identical"] = bool(np.array_equal(p_old, p_new) and np.array_equal(l_old, l_new))
    else:
        out["v1_identical"] = None
    v2 = stacker.load_versioned(2)
    out["v2_schema_valid"] = v2 is not None
    out["ok"] = out["v1_identical"] is not False and out["v2_schema_valid"]
    return out


def summarise(runs: list) -> dict:
    out = {}
    for strat in sorted({r["strategy"] for r in runs}):
        rs = [r for r in runs if r["strategy"] == strat and r["result"]["status"] == "ok"]
        block = {"runs": len(rs), "split_methods": sorted({r["split_method"] for r in runs if r["strategy"] == strat})}
        for m in METHODS:
            for k in ("recall", "fpr", "precision", "f1", "pr_auc", "brier", "alarms_per_10k_benign"):
                v = [r["result"]["methods"][m][k] for r in rs if r["result"]["methods"][m].get(k) is not None]
                if v:
                    block[f"{m}.{k}"] = {"mean": float(np.mean(v)), "sd": float(np.std(v, ddof=1)) if len(v) > 1 else 0.0}
        for m in ("fusion_v1", "fusion_v2"):
            co = pd.DataFrame([r["result"]["methods"][m]["coefficients"] for r in rs])
            if len(co):
                block[f"{m}.coefficients"] = {c: {"mean": float(co[c].mean()), "sd": float(co[c].std(ddof=1)) if len(co) > 1 else 0.0,
                                                  "share_negative": float((co[c] < 0).mean())} for c in co.columns}
        out[strat] = block
    return out


def main():
    ap = argparse.ArgumentParser(description="Read-only evaluation of Path A/B, OR, fusion V1 and V2")
    ap.add_argument("--labeled", required=True)
    ap.add_argument("--split-manifest", required=True, help="manifest Path A and Path B were trained with")
    ap.add_argument("--path-b-model", default="dns_trafficformer")
    ap.add_argument("--cache", default=None, help="pickle of scored rows to reuse (written if missing)")
    ap.add_argument("--strategies", nargs="+", default=list(STRATEGIES))
    ap.add_argument("--seeds", type=int, nargs="+", default=list(SEEDS))
    ap.add_argument("--delta", type=float, default=0.05)
    ap.add_argument("--out", default="outputs/fusion_eval/results.json")
    args = ap.parse_args()
    logging.basicConfig(level=logging.ERROR)

    if args.cache and os.path.exists(args.cache):
        df = pd.read_pickle(args.cache)
    else:
        from train_fusion import score_dataset
        df = score_dataset(args.labeled, args.path_b_model, missing_b_as_nan=True)
        if args.cache:
            os.makedirs(os.path.dirname(args.cache) or ".", exist_ok=True)
            df.to_pickle(args.cache)
    tr, val, te, _, _ = load_manifest_indices(args.split_manifest, df)
    pool = np.sort(np.r_[val, te])
    pool = pool[df["label"].iloc[pool].notna().to_numpy()]
    P = df.iloc[pool].reset_index(drop=True)
    P["label"] = P["label"].astype(int)
    ref_fit = np.flatnonzero(np.isin(pool, val))
    ref_test = np.flatnonzero(np.isin(pool, te))
    max_fpr = float(_training_setting("path_a_max_fpr", 0.001))
    y = P["label"].to_numpy()
    print(f"[*] pool = val+test of {os.path.basename(args.split_manifest)}: {len(P)} rows "
          f"({int(y.sum())} attack / {int((y == 0).sum())} benign); Path A/B never trained on these rows")

    runs = [{"strategy": "manifest", "seed": 42, "split_method": "original manifest (val → test)",
             "result": run_once(P, ref_fit, ref_test, 42, max_fpr, args.delta)}]
    print("   reference (fusion fitted on validation, scored on the manifest's test rows):")
    for m, b in runs[0]["result"]["methods"].items():
        print(f"     {m:20s} recall={b['recall']:.3f} FPR={b['fpr']:.4f} ({b['false_alarms']}/{b['benign']}) "
              f"alarms/10k={b['alarms_per_10k_benign']:.1f} PR-AUC={b['pr_auc'] if b['pr_auc'] is None else round(b['pr_auc'], 4)}"
              f" Brier={b['brier'] if b['brier'] is None else round(b['brier'], 5)}")
    seen = {}
    for strat in args.strategies:
        for seed in args.seeds:
            tr_i, va_i, te_i, method = splits_mod.build_indices(P, y, strat, seed=seed)
            fit_i = np.sort(np.r_[tr_i, va_i]).astype(int)
            te_i = np.sort(te_i).astype(int)
            key = (fit_i.tobytes(), te_i.tobytes(), seed)   # seed also drives V2's fit/cal split
            if key in seen:
                # A grouped strategy that fell back to the same random row split as an earlier run:
                # identical rows → identical numbers. Kept for the record, excluded from the gate.
                runs.append({"strategy": strat, "seed": seed, "split_method": method,
                             "result": {"status": "duplicate", "same_rows_as": seen[key]}})
                print(f"   {strat:20s} seed {seed} [{method}]  duplicate of {seen[key]} — not counted")
                continue
            seen[key] = f"{strat}/seed{seed}"
            runs.append({"strategy": strat, "seed": seed, "split_method": method,
                         "result": run_once(P, fit_i, te_i, seed, max_fpr, args.delta)})
            r = runs[-1]["result"]
            if r["status"] == "ok":
                m = r["methods"]
                print(f"   {strat:20s} seed {seed} [{method}]  FPR A={m['path_a']['fpr']:.4f} "
                      f"OR={m['or_rule']['fpr']:.4f} V1={m['fusion_v1']['fpr']:.4f} V2={m['fusion_v2']['fpr']:.4f}  "
                      f"recall V1={m['fusion_v1']['recall']:.3f} V2={m['fusion_v2']['recall']:.3f}")
            else:
                print(f"   {strat:20s} seed {seed} [{method}]  n/a: {r['reason']}")

    compat = compat_check(df)
    resampled = [r for r in runs if r["strategy"] != "manifest"]
    result = {"pool": {"rows": int(len(P)), "attack": int(y.sum()), "benign": int((y == 0).sum()),
                       "base_rate": float(y.mean()), "manifest": os.path.basename(args.split_manifest),
                       "attack_parent_domains": sorted(P.loc[P.label == 1, "parent_domain"].astype(str).unique()),
                       "benign_parent_domains": int(P.loc[P.label == 0, "parent_domain"].nunique()),
                       "path_b_coverage": float(P["ml_score_B"].notna().mean())},
              "fpr_budget": max_fpr, "delta": args.delta, "compat": compat,
              "reference_run": runs[0], "summary": summarise(resampled),
              "gate": gate(resampled, max_fpr, compat["ok"]), "runs": runs}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2, default=float))
    g = result["gate"]
    print(f"\n[*] gate over {g['runs_evaluable']}/{g['runs_total']} evaluable runs:")
    for k, c in g["criteria"].items():
        extra = f"{c['k']}/{c['n']}" if "k" in c else ""
        print(f"   {'PASS' if c['pass'] else 'FAIL'}  {k}  {extra}")
    print(f"[*] V2 {'ACCEPTED' if g['accepted'] else 'NOT accepted'} for promotion → {args.out}")


if __name__ == "__main__":
    main()
