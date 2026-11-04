"""thresholds.py — Alarm thresholds chosen from a false-alarm budget (ML_IMPROVEMENT_GUIDE Steps 2 and 7).

threshold_for_fpr  empirical: meets the budget on the rows it is given (alarm when score >= t).
np_threshold       Neyman-Pearson umbrella algorithm (Tong, Feng & Li 2018): with probability
                   >= 1 - delta over the draw of the benign calibration rows, the population
                   false-alarm rate is <= alpha (alarm when score > t, strictly).
"""

import math

import numpy as np


class InsufficientCalibrationError(ValueError):
    """Too few benign calibration rows for the requested (alpha, delta) guarantee."""

    def __init__(self, n: int, n_required: int, alpha: float, delta: float):
        self.n, self.n_required, self.alpha, self.delta = n, n_required, alpha, delta
        super().__init__(
            f"Neyman-Pearson threshold needs at least {n_required} benign calibration rows for "
            f"alpha={alpha}, delta={delta}; got {n}. No FPR guarantee can be given on this data.")


def _check_unit(name: str, v: float) -> float:
    v = float(v)
    if not (0.0 < v < 1.0) or math.isnan(v):
        raise ValueError(f"{name} must lie strictly between 0 and 1, got {v}")
    return v


def np_violation_bound(n: int, k: int, alpha: float) -> float:
    """
    Upper bound on P(FPR > alpha) when the threshold is the k-th smallest of n benign scores
    (1-indexed) and the alarm rule is `score > threshold`:

        P(FPR > alpha) <= sum_{j=k}^{n} C(n, j) (1 - alpha)^j alpha^(n - j)

    (Tong, Feng & Li 2018, Proposition 1). The right side is P(Binomial(n, 1 - alpha) >= k):
    the k-th order statistic exceeds the (1 - alpha) benign quantile only if at least k of the
    n draws fall below that quantile. Summed in log space so n in the tens of thousands is safe.
    """
    if not 1 <= k <= n:
        raise ValueError(f"need 1 <= k <= n, got k={k}, n={n}")
    la, l1a = math.log(alpha), math.log1p(-alpha)
    lgn = math.lgamma(n + 1)
    terms = [lgn - math.lgamma(j + 1) - math.lgamma(n - j + 1) + j * l1a + (n - j) * la
             for j in range(k, n + 1)]
    m = max(terms)
    return float(min(1.0, math.exp(m) * sum(math.exp(t - m) for t in terms)))


def np_min_samples(alpha: float, delta: float = 0.05) -> int:
    """
    Smallest n for which any order statistic meets the guarantee. The weakest requirement is
    k = n (threshold = the largest benign score), whose bound is (1 - alpha)^n, so
    n >= ln(delta) / ln(1 - alpha). For alpha = 0.001, delta = 0.05 this is 2995.
    """
    alpha, delta = _check_unit("alpha", alpha), _check_unit("delta", delta)
    n = math.ceil(math.log(delta) / math.log1p(-alpha))
    while (1 - alpha) ** n > delta:      # guard against floating-point rounding at the boundary
        n += 1
    while n > 1 and (1 - alpha) ** (n - 1) <= delta:
        n -= 1
    return int(n)


def np_threshold(benign_scores, alpha: float, delta: float = 0.05) -> dict:
    """
    Neyman-Pearson umbrella threshold (Tong, Feng & Li 2018, Algorithm 1).

    Sort the n benign calibration scores ascending, s_(1) <= ... <= s_(n), and pick the smallest
    k with np_violation_bound(n, k, alpha) <= delta. Alarm when score > s_(k) (strict).

    Guarantee: P(population FPR > alpha) <= delta over the draw of the calibration rows,
    provided (i) the calibration rows were NOT used to fit the scorer, (ii) they are exchangeable
    with deployment benign traffic, and (iii) scores are continuous. Ties only lower the realised
    FPR under the strict rule, so the bound still holds with ties. It says nothing about a shift
    between calibration and deployment traffic.

    Returns {"threshold", "k", "n", "bound", "alpha", "delta", "rule": ">"}.
    Raises InsufficientCalibrationError when n < np_min_samples(alpha, delta).
    """
    alpha, delta = _check_unit("alpha", alpha), _check_unit("delta", delta)
    s = np.asarray(benign_scores, dtype=float).ravel()
    if s.size == 0:
        raise ValueError("np_threshold needs at least one benign score")
    if not np.all(np.isfinite(s)):
        raise ValueError("np_threshold: benign scores must be finite")
    n = int(s.size)
    n_req = np_min_samples(alpha, delta)
    if n < n_req:
        raise InsufficientCalibrationError(n, n_req, alpha, delta)
    s = np.sort(s)
    # The bound decreases as k grows, so binary-search the smallest k that meets delta.
    lo, hi = 1, n
    while lo < hi:
        mid = (lo + hi) // 2
        if np_violation_bound(n, mid, alpha) <= delta:
            hi = mid
        else:
            lo = mid + 1
    k = lo
    return {"threshold": float(s[k - 1]), "k": int(k), "n": n,
            "bound": np_violation_bound(n, k, alpha), "alpha": alpha, "delta": delta, "rule": ">"}


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
