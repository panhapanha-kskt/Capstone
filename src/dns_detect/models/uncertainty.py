"""
uncertainty.py — Detector metrics with error ranges (T9).

One function, `evaluate_detector`, gives every detector (Path A, Path B, fusion, rule
baselines) the same report:

  point        recall, FPR, precision, F1, PR-AUC, ROC-AUC, recall at FPR = 0.1 %,
               false alarms, counts
  exact        95 % Clopper-Pearson intervals for FPR and recall (thresholds.rate_interval,
               the method Path A and the fusion already report) and a Wilson interval for FPR
  bootstrap    95 % percentile intervals from a stratified CLUSTER bootstrap: whole groups
               (parent domains or time blocks) are resampled, benign and attack groups
               separately, so near-duplicate queries of one domain move together instead of
               being counted as independent evidence

`seed_spread` summarises one metric over several training seeds (mean, sd, min, max).
Seed spread and bootstrap intervals measure different things: the first is training
randomness, the second is how much the test rows themselves could vary. Report both.

Recall at FPR = 0.1 % is DESCRIPTIVE: it picks the best cut-off on the rows being reported,
so it is an upper bound on what a threshold chosen elsewhere could reach, never an
operating point.
"""

from __future__ import annotations

import math

import numpy as np

from dns_detect.models.thresholds import rate_interval

DEFAULT_N_BOOT = 1000
DEFAULT_CONFIDENCE = 0.95
DEFAULT_RECALL_AT_FPR = 0.001


def wilson_interval(k: int, n: int, confidence: float = DEFAULT_CONFIDENCE):
    """Wilson score interval [low, high] for k events in n trials (None when n == 0)."""
    from scipy.stats import norm
    k, n = int(k), int(n)
    if n <= 0:
        return None
    z = float(norm.ppf(1 - (1 - confidence) / 2))
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    low = 0.0 if k == 0 else max(0.0, mid - half)      # exact ends: no floating-point dust
    high = 1.0 if k == n else min(1.0, mid + half)
    return [low, high]


def recall_at_fpr(y, scores, max_fpr: float = DEFAULT_RECALL_AT_FPR):
    """Highest recall reachable with an alarm rule `score >= t` whose FPR on these rows is
    <= max_fpr. Descriptive only (the cut-off is chosen on the same rows)."""
    y = np.asarray(y).astype(int)
    s = np.asarray(scores, dtype=float)
    ben, att = s[y == 0], s[y == 1]
    if len(att) == 0:
        return None
    if len(ben) == 0:
        return 1.0
    k = int(math.floor(max_fpr * len(ben)))           # false alarms allowed
    ben_sorted = np.sort(ben)[::-1]
    # t must be above the (k+1)-th highest benign score
    bar = ben_sorted[k] if k < len(ben_sorted) else -np.inf
    return float((att > bar).mean())


def _safe_auc(fn, y, s):
    try:
        if len(np.unique(y)) < 2:
            return None
        return float(fn(y, s))
    except ValueError:
        return None


def point_metrics(y, scores, preds, max_fpr: float = DEFAULT_RECALL_AT_FPR) -> dict:
    from sklearn.metrics import average_precision_score, roc_auc_score
    y = np.asarray(y).astype(int)
    p = np.asarray(preds).astype(int)
    s = np.asarray(scores, dtype=float)
    tp = int(((p == 1) & (y == 1)).sum())
    fp = int(((p == 1) & (y == 0)).sum())
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / pos if pos else None
    f1 = (2 * prec * rec / (prec + rec)) if rec and prec + rec else 0.0
    return {
        "recall": rec, "fpr": fp / neg if neg else None, "precision": prec, "f1": f1,
        "pr_auc": _safe_auc(average_precision_score, y, s),
        "roc_auc": _safe_auc(roc_auc_score, y, s),
        f"recall_at_fpr_{max_fpr:g}": recall_at_fpr(y, s, max_fpr),
        "false_alarms": fp, "true_positives": tp, "benign": neg, "attack": pos,
    }


def _group_index(groups, y):
    """{class: [index arrays, one per group]} — a group goes to the class most of its rows have."""
    groups = np.asarray(groups).astype(str)
    order = np.argsort(groups, kind="stable")
    g_sorted = groups[order]
    cuts = np.flatnonzero(g_sorted[1:] != g_sorted[:-1]) + 1
    parts = np.split(order, cuts)
    out = {0: [], 1: []}
    for idx in parts:
        out[int(round(float(y[idx].mean())))].append(idx)
    return out


def cluster_bootstrap(y, scores, preds, groups, n_boot: int = DEFAULT_N_BOOT, seed: int = 0,
                      confidence: float = DEFAULT_CONFIDENCE,
                      max_fpr: float = DEFAULT_RECALL_AT_FPR) -> dict:
    """Percentile intervals for every point metric, resampling whole groups within each class."""
    y = np.asarray(y).astype(int)
    s = np.asarray(scores, dtype=float)
    p = np.asarray(preds).astype(int)
    parts = _group_index(groups, y)
    rng = np.random.default_rng(seed)
    draws: dict = {}
    for _ in range(int(n_boot)):
        idx = []
        for cls in (0, 1):
            g = parts[cls]
            if g:
                pick = rng.integers(0, len(g), size=len(g))
                idx.extend(g[i] for i in pick)
        idx = np.concatenate(idx) if idx else np.array([], dtype=int)
        m = point_metrics(y[idx], s[idx], p[idx], max_fpr)
        for k, v in m.items():
            if v is not None and k not in ("benign", "attack", "true_positives"):
                draws.setdefault(k, []).append(v)
    lo, hi = (1 - confidence) / 2 * 100, (1 + confidence) / 2 * 100
    return {k: [float(np.percentile(v, lo)), float(np.percentile(v, hi))] for k, v in draws.items()}


def evaluate_detector(y, scores, preds, groups=None, n_boot: int = DEFAULT_N_BOOT, seed: int = 0,
                      confidence: float = DEFAULT_CONFIDENCE,
                      max_fpr: float = DEFAULT_RECALL_AT_FPR) -> dict:
    """Point metrics + exact intervals + cluster-bootstrap intervals for one detector."""
    pt = point_metrics(y, scores, preds, max_fpr)
    out = {
        "point": pt,
        "exact": {
            "fpr_clopper_pearson": rate_interval(pt["false_alarms"], pt["benign"], confidence),
            "fpr_wilson": wilson_interval(pt["false_alarms"], pt["benign"], confidence),
            "recall_clopper_pearson": rate_interval(pt["true_positives"], pt["attack"], confidence),
        },
        "bootstrap": None, "n_groups": None, "n_boot": int(n_boot), "confidence": confidence,
    }
    if groups is not None and n_boot > 0:
        parts = _group_index(groups, np.asarray(y).astype(int))
        out["n_groups"] = {"benign": len(parts[0]), "attack": len(parts[1])}
        out["bootstrap"] = cluster_bootstrap(y, scores, preds, groups, n_boot, seed, confidence, max_fpr)
    return out


def seed_spread(values) -> dict | None:
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return None
    return {"mean": float(np.mean(vals)), "sd": float(np.std(vals, ddof=1)) if len(vals) > 1 else 0.0,
            "min": float(np.min(vals)), "max": float(np.max(vals)), "n": len(vals)}


def time_blocks(timestamps, minutes: int = 60) -> np.ndarray:
    """Group label per row: the start of its `minutes`-long block (rows without a time → 'na')."""
    import pandas as pd
    ts = pd.to_datetime(pd.Series(timestamps), errors="coerce", utc=True)
    block = ts.dt.floor(f"{int(minutes)}min")
    return block.astype(str).where(ts.notna(), "na").to_numpy()
