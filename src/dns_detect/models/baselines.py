"""
baselines.py — Rule-based detectors (Need-Improve.md N4).

The Week-2 reference check shows a one-line record-type rule reaching F1 1.000 on the
current labeled set. Reporting that number alongside the ML models — and alongside two
literature-standard numeric thresholds — makes "did ML earn its place?" (Arp et al. P6)
answerable on every split.

Each detector exposes:
    predict(df) -> np.ndarray[bool]       # hard labels
    score(df)   -> np.ndarray[float]      # monotone score for PR-AUC

`fit_threshold` picks the threshold on *train only* — never pick it on the test set
(Arp et al. P3/P5). `literature_entropy_rule` freezes t = 4.0 (Nadler et al. 2019) so
the plan's "entropy > 4.0 from the literature" row is reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np
import pandas as pd

TUNNEL_RECORD_TYPES = {"TXT", "KEY", "NULL", "CNAME", "MX", "SRV", "PRIVATE", "65399", "10"}


def record_type_rule(df: pd.DataFrame, types: Iterable[str] = ("TXT", "KEY", "NULL")) -> np.ndarray:
    """True when `query_type` is in `types` (upper-cased, missing → '')."""
    types_up = {t.upper() for t in types}
    if "query_type" not in df.columns:
        return np.zeros(len(df), dtype=bool)
    col = df["query_type"].astype(str).str.upper().fillna("")
    return col.isin(types_up).to_numpy()


def record_type_score(df: pd.DataFrame, types: Iterable[str] = ("TXT", "KEY", "NULL")) -> np.ndarray:
    return record_type_rule(df, types).astype(float)


@dataclass
class ThresholdRule:
    """One-sided `column > threshold` rule with a train-only threshold fitter."""

    column: str
    threshold: float
    name: str

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        if self.column not in df.columns:
            return np.zeros(len(df), dtype=bool)
        return (pd.to_numeric(df[self.column], errors="coerce").fillna(-np.inf) > self.threshold).to_numpy()

    def score(self, df: pd.DataFrame) -> np.ndarray:
        """Raw value as a monotone score for PR-AUC."""
        if self.column not in df.columns:
            return np.zeros(len(df), dtype=float)
        return pd.to_numeric(df[self.column], errors="coerce").fillna(0.0).to_numpy(dtype=float)


def fit_threshold(
    y_train: np.ndarray,
    values_train: np.ndarray,
    objective: str = "f1",
    grid: int = 101,
) -> float:
    """
    Pick `t` maximising the objective on train only. Rule is `value > t`.
    Grid of `grid` points between min and max; ties → smaller t (more alarms).
    """
    y = np.asarray(y_train).astype(int)
    v = np.asarray(values_train, dtype=float)
    if len(v) == 0:
        return 0.0
    lo, hi = float(np.min(v)), float(np.max(v))
    if lo == hi:
        return lo
    pos = int(y.sum())
    candidates = np.linspace(lo, hi, grid)
    best_t, best_score = float(candidates[0]), -1.0
    for t in candidates:
        pred = (v > t).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        fn = pos - tp
        if objective == "f1":
            denom = 2 * tp + fp + fn
            s = (2 * tp) / denom if denom else 0.0
        elif objective == "recall":
            s = tp / pos if pos else 0.0
        else:
            raise ValueError(f"unknown objective {objective!r}")
        if s > best_score:
            best_t, best_score = float(t), s
    return best_t


def entropy_threshold(threshold: float) -> ThresholdRule:
    return ThresholdRule("query_entropy", threshold, f"entropy>{threshold:g}")


def length_threshold(threshold: float) -> ThresholdRule:
    return ThresholdRule("query_length", threshold, f"length>{threshold:g}")


def literature_entropy_rule() -> ThresholdRule:
    """Nadler et al. 2019: entropy > 4.0 as a DNS-tunneling flag."""
    return entropy_threshold(4.0)


class _RecordTypeDetector:
    name = "record_type_in_{TXT,KEY,NULL}"
    threshold = None

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        return record_type_rule(df)

    def score(self, df: pd.DataFrame) -> np.ndarray:
        return record_type_score(df)


def fit_all_baselines(df_train: pd.DataFrame, y_train: np.ndarray) -> dict:
    """
    Train-fit the default baselines. Returns {stable_name: detector}; each detector has
    `.predict(df)`, `.score(df)` and `.threshold`. Names are stable across seeds so
    per-seed results can be aggregated; the fitted threshold lives on the detector.
    """
    ent_vals = pd.to_numeric(df_train.get("query_entropy", 0), errors="coerce").fillna(0.0).to_numpy()
    len_vals = pd.to_numeric(df_train.get("query_length", 0), errors="coerce").fillna(0.0).to_numpy()
    return {
        "record_type": _RecordTypeDetector(),
        "entropy_train_fit": entropy_threshold(fit_threshold(y_train, ent_vals)),
        "entropy_4.0_literature": literature_entropy_rule(),
        "length_train_fit": length_threshold(fit_threshold(y_train, len_vals)),
    }
