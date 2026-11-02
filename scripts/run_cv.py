#!/usr/bin/env python3
"""
run_cv.py — Need-Improve.md N13 driver.

Loads the labeled training set and, for every (strategy, seed) in
`config/settings.yaml :: evaluation`, writes a split manifest and evaluates the
rule baselines plus (optionally) the trained Path A model on each split's test rows.
Reports mean ± sd across seeds.

The script is deliberately thin — it never retrains Path A per seed (that is Path A's
job); it loads the existing production RF/GBT if available and scores them on each split's
test rows. For the headline "unseen-tool" column (N1), it also runs the leave-one-family-out
strategy, which uses a *retrained* RandomForest per held-out family (quick, independent of
the production model) so the headline number is independent of the current training split.

Usage:
    python scripts/run_cv.py \
        --labeled data/raw/merged_features_labeled.json \
        --strategies exact_copy capture_group parent_domain_group time lofo \
        --seeds 42 43 44 45 46 \
        --out models/evaluation_metrics.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from statistics import mean, pstdev

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.parsing.dns_parser import (  # noqa: E402
    load_as_dataframe, FEATURES_8, PATH_A_BASE_FEATURES, PATH_A_FEATURES, PATH_A_FEATURES_ALL,
)
from dns_detect.features.aggregates import (  # noqa: E402
    FEATURES_AGG, BigramModel, add_window_features, domain_series, epoch_seconds,
)
from dns_detect.models import splits as splits_mod  # noqa: E402
from dns_detect.models import baselines as baselines_mod  # noqa: E402
from dns_detect.models.thresholds import rates, threshold_for_fpr  # noqa: E402
from dns_detect.utils.dataset_hash import dataset_hash  # noqa: E402

# Feature sets for the unseen-tool (LOFO) ablation — each guide step adds to the one before.
LOFO_FEATURE_SETS = {
    "base8": list(FEATURES_8),                               # Week-2 model inputs
    "step2": list(PATH_A_BASE_FEATURES),                     # − answer_count
    "behaviour_only": [f for f in FEATURES_AGG if f in PATH_A_FEATURES],
    "step3": list(PATH_A_FEATURES),                          # per-query + behaviour (config exclusions applied)
    "step3_plus_rr_shortcut": list(PATH_A_FEATURES_ALL),     # + tunnel_rr_share_5m, to measure the shortcut
}

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (
        average_precision_score, f1_score, precision_score, recall_score, roc_auc_score,
    )
    SKLEARN_OK = True
except Exception:
    SKLEARN_OK = False


def _metric_block(y_true: np.ndarray, scores: np.ndarray, preds: np.ndarray) -> dict:
    """`scores` drive the threshold-free metrics; `preds` (the detector's own decision) drive F1/P/R."""
    y_true = np.asarray(y_true).astype(int)
    scores = np.asarray(scores, dtype=float)
    preds = np.asarray(preds).astype(int)
    try:
        pr = float(average_precision_score(y_true, scores))
    except Exception:
        pr = None
    try:
        roc = float(roc_auc_score(y_true, scores))
    except Exception:
        roc = None
    fp = int(((preds == 1) & (y_true == 0)).sum())
    n_ben = int((y_true == 0).sum())
    return {
        "fpr": fp / n_ben if n_ben else None,
        "f1": float(f1_score(y_true, preds, zero_division=0)),
        "precision": float(precision_score(y_true, preds, zero_division=0)),
        "recall": float(recall_score(y_true, preds, zero_division=0)),
        "pr_auc": pr,
        "pr_auc_baseline": float((y_true == 1).mean()),
        "roc_auc": roc,
        "support": {"benign": int((y_true == 0).sum()), "attack": int((y_true == 1).sum())},
    }


def _features_matrix(df: pd.DataFrame, features) -> np.ndarray:
    return df[list(features)].apply(pd.to_numeric, errors="coerce").fillna(0.0).to_numpy(dtype=float)


def _run_lofo(df: pd.DataFrame, y: np.ndarray, family: str, features=None,
              benign_val: float = 0.1, benign_test: float = 0.2, max_fpr: float = 0.001) -> dict:
    """
    Unseen-tool test, scored the way the model is deployed.

    Train on benign + every attack family except `family`. Benign rows are cut by time into
    train (oldest 70 %), validation (next 10 %) and test (latest 20 %). The alarm threshold is
    the false-alarm-budget threshold on the validation benign rows (`max_fpr`, as in Path A),
    so every feature set is compared at the same false-alarm rate, not at an arbitrary 0.5.
    Test = held-out family + test benign → recall on the unseen tool and FPR on unseen benign.
    The bigram model is refitted on each fold's training benign rows only.
    """
    if not SKLEARN_OK:
        return {"error": "sklearn not available"}
    features = list(features or FEATURES_8)
    tr_idx, _val, te_idx, _m = splits_mod._lofo_split(df, y, family)
    ben = tr_idx[y[tr_idx] == 0]
    t = epoch_seconds(df["timestamp"].iloc[ben]) if "timestamp" in df.columns else np.arange(len(ben), dtype=float)
    ben = ben[np.argsort(np.nan_to_num(t, nan=-np.inf), kind="stable")]
    n_te, n_val = int(len(ben) * benign_test), int(len(ben) * benign_val)
    ben_te, ben_val = ben[len(ben) - n_te:], ben[len(ben) - n_te - n_val:len(ben) - n_te]
    tr_idx = np.setdiff1d(tr_idx, np.concatenate([ben_te, ben_val]))
    te_idx = np.concatenate([te_idx, ben_te])

    work = df
    if "bigram_logprob" in features:
        bigram = BigramModel().fit(domain_series(df.iloc[tr_idx][y[tr_idx] == 0]))
        work = df.copy()
        work["bigram_logprob"] = bigram.score_many(domain_series(df))
    X = _features_matrix(work, features)
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1)
    rf.fit(X[tr_idx], y[tr_idx])
    thr = threshold_for_fpr(np.zeros(len(ben_val)), rf.predict_proba(X[ben_val])[:, 1], max_fpr)
    scores = rf.predict_proba(X[te_idx])[:, 1]
    y_te = y[te_idx]
    block = {**rates(y_te, (scores >= thr).astype(int)), "threshold": thr,
             "at_0.5": rates(y_te, (scores >= 0.5).astype(int))}
    if len(np.unique(y_te)) == 2:
        block["pr_auc"] = float(average_precision_score(y_te, scores))
    return block


def _evaluate_split(df: pd.DataFrame, y: np.ndarray, strategy: str, seed: int,
                    splits_dir: str, dataset_version: str | None, held_out_family: str | None = None):
    row_ids = splits_mod.stable_row_ids(df)
    tr_idx, val_idx, te_idx, method = splits_mod.build_indices(
        df, y, strategy, seed=seed, held_out_family=held_out_family,
    )
    mpath = splits_mod.manifest_path(strategy, seed, splits_dir, held_out_family=held_out_family)
    splits_mod.write_manifest(mpath, strategy, seed, row_ids, tr_idx, val_idx, te_idx,
                              dataset_version=dataset_version,
                              notes=f"method={method}; held_out_family={held_out_family or '-'}")

    # Fit baselines on train, score on test.
    y_train = y[tr_idx]
    df_train = df.iloc[tr_idx]
    df_test = df.iloc[te_idx]
    y_test = y[te_idx]

    results = {"manifest": mpath, "method": method}
    if len(y_test) == 0 or len(np.unique(y_test)) < 2:
        # LOFO test blocks are single-class by construction; evaluate using recall only.
        for name, det in baselines_mod.fit_all_baselines(df_train, y_train).items():
            preds = det.predict(df_test).astype(int)
            results[name] = {"recall": float(preds.mean()) if len(preds) else None,
                             "support": {"attack": int(len(y_test))}}
        return results

    for name, det in baselines_mod.fit_all_baselines(df_train, y_train).items():
        block = _metric_block(y_test, det.score(df_test), det.predict(df_test))
        block["threshold"] = det.threshold
        results[name] = block
    return results


def _aggregate(seed_results: list[dict], baseline_name: str, metric: str) -> dict:
    vals = [r[baseline_name].get(metric) for r in seed_results if baseline_name in r and r[baseline_name].get(metric) is not None]
    if not vals:
        return {"mean": None, "sd": None, "n": 0}
    return {"mean": float(mean(vals)), "sd": float(pstdev(vals)) if len(vals) > 1 else 0.0, "n": len(vals)}


def main():
    ap = argparse.ArgumentParser(description="Need-Improve.md N13 — 5-seed CV + baselines + unseen-tool headline")
    ap.add_argument("--labeled", required=True, nargs="+",
                    help="one or more labeled features JSONs (output of Step 8, or raw single-class files like "
                         "data/processed/labeled_{tunnels,benign}.json which will be concatenated)")
    ap.add_argument("--strategies", nargs="+", default=["exact_copy", "capture_group", "parent_domain_group", "time", "lofo"])
    ap.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44, 45, 46])
    ap.add_argument("--lofo-feature-sets", nargs="+", default=list(LOFO_FEATURE_SETS),
                    choices=list(LOFO_FEATURE_SETS),
                    help="feature sets compared in the unseen-tool (lofo) test")
    ap.add_argument("--splits-dir", default="data/processed/splits")
    # Separate file: models/evaluation_metrics.json belongs to path_a.py / path_b_train.py.
    ap.add_argument("--out", default="models/cv_metrics.json")
    args = ap.parse_args()
    if os.path.basename(args.out) == "evaluation_metrics.json":
        ap.error("--out must not be evaluation_metrics.json (it holds the Path A / Path B training metrics)")

    dfs = []
    for p in args.labeled:
        d = load_as_dataframe(p)
        # Preserve metadata the base loader strips (source_file, parent_domain, timestamp,
        # client_ip, attack_family, query_type) by re-reading the raw records.
        try:
            with open(p, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, list) and len(raw) == len(d):
                extras = pd.DataFrame(raw)
                for col in ("source_file", "parent_domain", "timestamp", "client_ip",
                            "attack_family", "query_type", "label", "label_source",
                            "domain"):
                    if col in extras.columns and col not in d.columns:
                        d[col] = extras[col].values
        except Exception as _e:
            print(f"[warn] couldn't attach extras from {p}: {_e}")
        d["_source_path"] = p
        dfs.append(d)
    df = pd.concat(dfs, ignore_index=True)

    # label column, forgiving of mixed types
    df["label"] = pd.to_numeric(df.get("label"), errors="coerce")
    df = df[df["label"].notna()].copy()
    df["label"] = df["label"].astype(int)
    y = df["label"].to_numpy()

    dv = dataset_hash(list(args.labeled), FEATURES_8)
    print(f"[*] dataset_version = {dv[:16]}...  rows={len(df)}  attack_share={float((y==1).mean()):.3f}  "
          f"inputs={len(args.labeled)}")

    all_results: dict = {"dataset_version": dv, "labeled_paths": list(args.labeled), "by_strategy": {}}

    for strategy in args.strategies:
        print(f"\n== strategy: {strategy} ==")
        if strategy == "lofo":
            # One run per (feature set, held-out family); deterministic, so no seed loop.
            fams = sorted({str(f) for f in df.get("attack_family", pd.Series([], dtype=str)).unique()
                           if str(f) not in ("benign", "nan", "")})
            wdf = add_window_features(df)  # label-free, past-only; shared by all feature sets
            lofo: dict = {}
            print(f"   {'feature set':24s} " + "  ".join(f"{f:>16s}" for f in fams) + "   recall mean / min   FPR")
            for set_name in args.lofo_feature_sets:
                feats = LOFO_FEATURE_SETS[set_name]
                per_family = {}
                for fam in fams:
                    try:
                        per_family[fam] = _run_lofo(wdf, y, fam, feats)
                    except Exception as e:
                        per_family[fam] = {"error": str(e)}
                recs = [v["recall"] for v in per_family.values() if isinstance(v.get("recall"), (int, float))]
                fprs = [v["fpr"] for v in per_family.values() if isinstance(v.get("fpr"), (int, float))]
                head = {"unseen_tool_recall_mean": float(mean(recs)) if recs else None,
                        "unseen_tool_recall_min": min(recs) if recs else None,
                        "benign_fpr_mean": float(mean(fprs)) if fprs else None,
                        "families": len(recs), "features": feats}
                lofo[set_name] = {"per_family": per_family, "headline": head}
                cells = "  ".join(f"{per_family[f].get('recall', float('nan')):16.3f}" for f in fams)
                if recs:
                    print(f"   {set_name:24s} {cells}   {head['unseen_tool_recall_mean']:.3f} / "
                          f"{head['unseen_tool_recall_min']:.3f}      {head['benign_fpr_mean']:.4f}")
            all_results["by_strategy"]["lofo"] = lofo
            continue

        seed_results = []
        for seed in args.seeds:
            try:
                res = _evaluate_split(df, y, strategy, seed, args.splits_dir, dv)
            except Exception as e:
                res = {"error": str(e)}
                print(f"   seed {seed}: ERROR {e}")
            seed_results.append(res)
        methods = sorted({r.get("method", "error") for r in seed_results})
        all_results["by_strategy"][strategy] = {"per_seed": seed_results, "methods": methods}
        print(f"   split method: {', '.join(methods)}")
        if any("fallback" in m for m in methods):
            # The grouped split could not keep both classes in every split, so it fell back to
            # random rows: this strategy's numbers are NOT group-separated. Report, don't hide.
            print("   ! grouped split impossible on this data (too few groups per class) — "
                  "fell back to random rows; numbers below are not group-separated")
        detectors = set()
        for r in seed_results:
            detectors.update(k for k in r if isinstance(r.get(k), dict) and "f1" in r[k])
        agg: dict = {}
        for det in detectors:
            agg[det] = {m: _aggregate(seed_results, det, m)
                        for m in ("f1", "pr_auc", "precision", "recall", "fpr", "threshold")}
        all_results["by_strategy"][strategy]["aggregate"] = agg
        for det, metrics in sorted(agg.items(), key=lambda kv: (kv[1]["f1"]["mean"] or -1), reverse=True):
            f1, pr, fpr = metrics["f1"], metrics["pr_auc"], metrics["fpr"]
            if f1["mean"] is None:
                continue
            pr_s = f"{pr['mean']:.3f}" if pr["mean"] is not None else "  -  "
            fpr_s = f"{fpr['mean']:.4f}" if fpr["mean"] is not None else "-"
            print(f"   {det:24s} F1={f1['mean']:.3f} ± {f1['sd']:.3f}   PR-AUC={pr_s}   FPR={fpr_s}")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n[+] Full results → {args.out}")


if __name__ == "__main__":
    main()
