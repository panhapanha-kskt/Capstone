"""thresholds.py — Alarm thresholds chosen from a false-alarm budget (ML_IMPROVEMENT_GUIDE Steps 2 and 7)."""

import numpy as np


def threshold_for_fpr(y_true, scores, max_fpr: float) -> float:
    """
    Alarm threshold t (alarm when score >= t) whose false-alarm rate on these rows is <= max_fpr.

    With n benign rows, k = floor(max_fpr · n) false alarms are allowed, so t must sit above
    b = the (k+1)-th highest benign score. Any t in (b, a] keeps every attack scoring >= a,
    where a is the lowest attack score above b. Taking the middle of that gap instead of the
    point just above b leaves margin for unseen benign traffic: calibrated tree scores on
    separable validation data are exactly 0 or 1, and "just above 0" turns any new benign
    query with a non-zero score into an alarm. With no attack rows above b, t = just above b.
    A result above the highest possible score means the budget cannot be met on this data.
    """
    y = np.asarray(y_true).astype(int)
    s = np.asarray(scores, dtype=float)
    ben = np.sort(s[y == 0])
    if len(ben) == 0:
        return 0.5
    k = int(np.floor(max_fpr * len(ben)))
    if k >= len(ben):
        return float(ben[0])
    b = ben[len(ben) - 1 - k]
    above = s[(y == 1) & (s > b)]
    if len(above):
        return float((b + above.min()) / 2.0)
    return float(np.nextafter(b, np.inf))


def rates(y_true, preds) -> dict:
    """Recall, false-positive rate, precision and counts for hard predictions."""
    y = np.asarray(y_true).astype(int)
    p = np.asarray(preds).astype(int)
    tp = int(((p == 1) & (y == 1)).sum())
    fp = int(((p == 1) & (y == 0)).sum())
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / pos if pos else 0.0
    return {
        "recall": rec,
        "fpr": fp / neg if neg else None,
        "precision": prec,
        "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
        "false_alarms": fp,
        "benign": neg,
        "attack": pos,
    }
