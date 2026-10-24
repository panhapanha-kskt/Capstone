#!/usr/bin/env python3
"""
verify_models.py — Independent checks that the ML results mean what we claim.

A near-perfect score is a reason to look harder, not a result. This script answers:
  1. Shortcut     — can a SINGLE feature already separate the classes?
  2. Duplicates   — does the random-split score drop when no domain may appear in both
                    train and test (duplicate / near-duplicate leakage)?
  3. Generalize   — leave-one-attack-family-out: does it catch a tunneling TOOL it never saw?
  4. Shuffle      — with permuted labels, does performance collapse to chance (no pipeline leak)?
  5. Hold-out     — (optional) the SAVED production models (Path A + Path B) on unseen data.

Checks 1–4 train throwaway in-memory models. Saved model files are only ever READ (check 5),
never written. Results → models/verification_report.json.

Usage:
  python3 scripts/verify_models.py
  python3 scripts/verify_models.py --holdout data/processed/holdout_benign.json data/processed/holdout_tunnels.json
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from dns_detect.parsing.dns_parser import load_as_dataframe, FEATURES_8  # noqa: E402

from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier  # noqa: E402
from sklearn.tree import DecisionTreeClassifier  # noqa: E402
from sklearn.model_selection import (  # noqa: E402
    StratifiedKFold, cross_val_predict, train_test_split, GroupShuffleSplit,
)
from sklearn.metrics import (  # noqa: E402
    average_precision_score, roc_auc_score, f1_score, precision_score, recall_score,
)

SEED = 42
VERDICTS = []   # (status, check, message)


def verdict(status, check, msg):
    VERDICTS.append((status, check, msg))
    icon = {"PASS": "✅", "WARN": "⚠ ", "INFO": "ℹ "}[status]
    print(f"   {icon} {status}: {msg}")


# ─────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────

def tree_pair_scores(X_tr, y_tr, X_te):
    """Mirror production Path A: soft-vote of RF + HistGradientBoosting."""
    rf = RandomForestClassifier(n_estimators=100, class_weight="balanced",
                                random_state=SEED, n_jobs=-1).fit(X_tr, y_tr)
    gbt = HistGradientBoostingClassifier(max_iter=200, class_weight="balanced",
                                         random_state=SEED).fit(X_tr, y_tr)
    return 0.5 * (rf.predict_proba(X_te)[:, 1] + gbt.predict_proba(X_te)[:, 1])


def metric_block(y, scores, threshold=0.5):
    y = np.asarray(y)
    preds = (np.asarray(scores) >= threshold).astype(int)
    out = {
        "n": int(len(y)),
        "prevalence": round(float(y.mean()), 4) if len(y) else None,
        "precision": round(float(precision_score(y, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y, preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y, preds, zero_division=0)), 4),
    }
    if len(np.unique(y)) > 1:
        out["pr_auc"] = round(float(average_precision_score(y, scores)), 4)
        out["roc_auc"] = round(float(roc_auc_score(y, scores)), 4)
    return out


def load_df(paths):
    frames = []
    for p in paths:
        d = load_as_dataframe(p)
        if "label" not in d.columns:
            sys.exit(f"[error] {p} has no 'label' column — use a labeled file")
        frames.append(d)
    df = pd.concat(frames, ignore_index=True)
    for col in FEATURES_8:
        if col not in df.columns:
            df[col] = 0
    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
    if "attack_family" not in df.columns:
        df["attack_family"] = np.where(df["label"] == 1, "attack", "benign")
    df["attack_family"] = df["attack_family"].astype(str)
    df["domain"] = df.get("domain", pd.Series([""] * len(df))).astype(str)
    return df


# ─────────────────────────────────────────────
# checks
# ─────────────────────────────────────────────

def check_data(df):
    print("\n── 0. Data sanity ─────────────────────────────────────────────")
    y = df["label"].to_numpy()
    fams = df.loc[df["label"] == 1, "attack_family"].value_counts().to_dict()
    dup_domains = int(df.duplicated("domain").sum())
    dup_rows = int(df.duplicated(FEATURES_8).sum())
    # identical feature vectors carrying BOTH labels = unavoidable error / label noise
    g = df.groupby(FEATURES_8)["label"].nunique()
    conflicting = int((g > 1).sum())
    print(f"   rows={len(df)}  benign={int((y == 0).sum())}  attack={int((y == 1).sum())}  families={fams}")
    print(f"   duplicate domains={dup_domains}  duplicate feature rows={dup_rows}  "
          f"feature vectors with BOTH labels={conflicting}")
    if conflicting:
        verdict("INFO", "data", f"{conflicting} identical feature vectors appear with both labels "
                                "(sets a ceiling below 100%)")
    return {"rows": len(df), "benign": int((y == 0).sum()), "attack": int((y == 1).sum()),
            "families": fams, "duplicate_domains": dup_domains,
            "duplicate_feature_rows": dup_rows, "conflicting_vectors": conflicting}


def check_shortcuts(df):
    print("\n── 1. Single-feature shortcut test (depth-2 tree, 5-fold CV) ──")
    y = df["label"].to_numpy()
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    res = {}
    for f in FEATURES_8:
        x = df[[f]].to_numpy(dtype=float)
        if np.nanstd(x) == 0:
            res[f] = {"roc_auc": None, "note": "constant"}
            print(f"   {f:<18} constant — no signal")
            continue
        p = cross_val_predict(DecisionTreeClassifier(max_depth=2, random_state=SEED),
                              x, y, cv=skf, method="predict_proba")[:, 1]
        auc = float(roc_auc_score(y, p))
        res[f] = {"roc_auc": round(auc, 4)}
        print(f"   {f:<18} ROC-AUC alone = {auc:.4f}")
    best_f = max((k for k in res if res[k]["roc_auc"] is not None),
                 key=lambda k: res[k]["roc_auc"])
    best = res[best_f]["roc_auc"]
    if best >= 0.99:
        verdict("WARN", "shortcut", f"'{best_f}' ALONE separates the classes (AUC {best:.3f}). "
                "The task is easy on this data — report it; the 1.00 is not model sophistication.")
    else:
        verdict("PASS", "shortcut", f"no single feature is sufficient (best: '{best_f}' AUC {best:.3f})")
    return res


def check_importance(df):
    print("\n── 1b. Random Forest feature importance ───────────────────────")
    rf = RandomForestClassifier(n_estimators=100, class_weight="balanced",
                                random_state=SEED, n_jobs=-1)
    rf.fit(df[FEATURES_8].to_numpy(dtype=float), df["label"].to_numpy())
    imp = sorted(zip(FEATURES_8, rf.feature_importances_), key=lambda t: -t[1])
    for f, v in imp:
        print(f"   {f:<18} {v:.3f}")
    return {f: round(float(v), 4) for f, v in imp}


def check_duplicates(df):
    print("\n── 2. Random split vs domain-grouped split (duplicate leakage) ─")
    X = df[FEATURES_8].to_numpy(dtype=float)
    y = df["label"].to_numpy()
    Xa, Xb, ya, yb = train_test_split(X, y, test_size=0.3, random_state=SEED, stratify=y)
    rand = metric_block(yb, tree_pair_scores(Xa, ya, Xb))
    gss = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=SEED)
    tr, te = next(gss.split(X, y, groups=df["domain"].to_numpy()))
    grp = metric_block(y[te], tree_pair_scores(X[tr], y[tr], X[te]))
    print(f"   random split   : F1={rand['f1']}  PR-AUC={rand.get('pr_auc')}")
    print(f"   grouped split  : F1={grp['f1']}  PR-AUC={grp.get('pr_auc')}  "
          f"(no domain in both train and test)")
    gap = rand["f1"] - grp["f1"]
    if gap > 0.02:
        verdict("WARN", "duplicates", f"F1 drops {gap:.3f} when duplicates can't leak — report the "
                                      "grouped-split number, not the random-split one")
    else:
        verdict("PASS", "duplicates", f"score holds without duplicate leakage (F1 gap {gap:+.3f})")
    return {"random_split": rand, "grouped_split": grp}


def check_lofo(df):
    print("\n── 3. Leave-one-attack-family-out (unseen tunneling tool) ─────")
    fams = sorted(df.loc[df["label"] == 1, "attack_family"].unique())
    if len(fams) < 2:
        verdict("INFO", "lofo", "only one attack family — can't test generalization to an unseen tool")
        return {}
    ben = df[df["label"] == 0]
    ben_tr, ben_te = train_test_split(ben, test_size=0.3, random_state=SEED)
    out = {}
    for f in fams:
        train = pd.concat([ben_tr, df[(df["label"] == 1) & (df["attack_family"] != f)]])
        test = pd.concat([ben_te, df[(df["label"] == 1) & (df["attack_family"] == f)]])
        s = tree_pair_scores(train[FEATURES_8].to_numpy(dtype=float), train["label"].to_numpy(),
                             test[FEATURES_8].to_numpy(dtype=float))
        m = metric_block(test["label"].to_numpy(), s)
        out[f] = m
        print(f"   held out '{f}': recall on unseen tool={m['recall']}  F1={m['f1']}  "
              f"PR-AUC={m.get('pr_auc')}")
        if m["recall"] < 0.8:
            verdict("WARN", "lofo", f"only {m['recall']:.2f} recall on '{f}' when it was never "
                                    "seen in training — the model partly memorizes tool patterns")
        else:
            verdict("PASS", "lofo", f"catches unseen '{f}' (recall {m['recall']:.2f})")
    return out


def check_shuffle(df):
    print("\n── 4. Label-shuffle test (permuted labels, 5-fold CV) ─────────")
    X = df[FEATURES_8].to_numpy(dtype=float)
    y = np.random.default_rng(SEED).permutation(df["label"].to_numpy())
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    rf = RandomForestClassifier(n_estimators=100, class_weight="balanced",
                                random_state=SEED, n_jobs=-1)
    p = cross_val_predict(rf, X, y, cv=skf, method="predict_proba")[:, 1]
    m = metric_block(y, p)
    print(f"   shuffled PR-AUC={m.get('pr_auc')}  vs prevalence={m['prevalence']}  "
          f"ROC-AUC={m.get('roc_auc')}")
    if m.get("pr_auc") is not None and m["pr_auc"] <= m["prevalence"] + 0.05:
        verdict("PASS", "shuffle", "performance collapses to chance with shuffled labels — "
                                   "no pipeline leakage (note: does not test label circularity)")
    else:
        verdict("WARN", "shuffle", "model still scores above chance on SHUFFLED labels — "
                                   "something leaks; investigate before trusting results")
    return m


def check_holdout(df_train, paths):
    print("\n── 5. Hold-out: SAVED production models on unseen queries ─────")
    ho = load_df(paths)
    seen = set(df_train["domain"])
    before = len(ho)
    ho = ho[~ho["domain"].isin(seen)].reset_index(drop=True)
    print(f"   hold-out rows: {before} → {len(ho)} after removing domains seen in training")
    if ho.empty or ho["label"].nunique() < 2:
        verdict("INFO", "holdout", "hold-out needs both classes after de-duplication — skipped")
        return {}
    out = {}

    # Path A — exactly the production scoring path
    from dns_detect.models.path_a import load_path_a_models, tree_ensemble_scores
    rf, gbt, scaler, thr, decision = load_path_a_models()
    s = tree_ensemble_scores(rf, gbt, scaler.transform(ho[FEATURES_8].to_numpy(dtype=float)), decision)
    m = metric_block(ho["label"].to_numpy(), s, thr)
    fam_rec = {}
    for fam in sorted(ho.loc[ho["label"] == 1, "attack_family"].unique()):
        mask = (ho["label"] == 1) & (ho["attack_family"] == fam)
        fam_rec[fam] = round(float((s[mask.to_numpy()] >= thr).mean()), 4)
    m["recall_by_family"] = fam_rec
    out["path_a"] = m
    print(f"   Path A ({decision}, thr={thr:.3f}): P={m['precision']} R={m['recall']} "
          f"F1={m['f1']} PR-AUC={m.get('pr_auc')}  per-family recall={fam_rec}")
    verdict("PASS" if m["f1"] >= 0.9 else "WARN", "holdout_a",
            f"saved Path A on unseen queries: F1={m['f1']}")

    # Path B — production per-client windowed scoring
    try:
        from dns_detect.models.path_b_predict import score_records
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            json.dump(ho.to_dict(orient="records"), tmp, default=str)
            tmp_path = tmp.name
        sb, ab, cov, _ = score_records(tmp_path, "dns_trafficformer")
        os.unlink(tmp_path)
        yb = ho["label"].to_numpy()[cov]
        if cov.sum() and len(np.unique(yb)) > 1:
            mb = metric_block(yb, sb[cov], 0.5)
            mb["anomaly_flag_f1"] = round(float(f1_score(yb, ab[cov], zero_division=0)), 4)
            mb["records_scored"] = int(cov.sum())
            out["path_b"] = mb
            print(f"   Path B: scored {int(cov.sum())}/{len(ho)} records  "
                  f"PR-AUC={mb.get('pr_auc')}  anomaly-flag F1={mb['anomaly_flag_f1']}")
        else:
            verdict("INFO", "holdout_b", "Path B scored too few records / one class "
                                         "(needs ≥ window-size queries per client)")
    except Exception as e:  # Path B is optional for the verdict
        verdict("INFO", "holdout_b", f"Path B hold-out skipped: {e}")
    return out


def main():
    ap = argparse.ArgumentParser(description="Verify the DNS ML results (checks 1–5).")
    ap.add_argument("--data", default=str(PROJECT_ROOT / "data/processed/merged_features_labeled.json"),
                    help="labeled training set (default: the one train_models.sh just used)")
    ap.add_argument("--holdout", nargs="+", default=None,
                    help="labeled hold-out JSON file(s) for the saved-model test (check 5)")
    ap.add_argument("--output", default=str(PROJECT_ROOT / "models/verification_report.json"))
    args = ap.parse_args()

    print("=" * 70)
    print("MODEL VERIFICATION — does the score mean what we claim?")
    print("=" * 70)
    df = load_df([args.data])
    if df["label"].nunique() < 2:
        sys.exit("[error] training data has a single class — nothing to verify")

    report = {"data_file": args.data}
    report["data"] = check_data(df)
    report["shortcuts"] = check_shortcuts(df)
    report["rf_importance"] = check_importance(df)
    report["duplicates"] = check_duplicates(df)
    report["leave_one_family_out"] = check_lofo(df)
    report["label_shuffle"] = check_shuffle(df)
    if args.holdout:
        report["holdout"] = check_holdout(df, args.holdout)

    report["verdicts"] = [{"status": s, "check": c, "message": m} for s, c, m in VERDICTS]
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for s, c, m in VERDICTS:
        print(f"  [{s}] {c}: {m}")
    print(f"\n✅ Report saved → {args.output}")


if __name__ == "__main__":
    main()
