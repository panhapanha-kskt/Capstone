"""
stacker.py — Learned fusion of Path A, Path B and the per-query rules (ML_IMPROVEMENT_GUIDE Step 7).

The OR rule fires whenever either path fires, so the false alarms of both paths add up.
A logistic regression learns from the validation split how much to trust each signal:

    P(attack) = σ( w₀ + w₁·score_A + w₂·score_B + w₃·has_score_B + w₄·rule_hits )

`has_score_B` tells the model when Path B had no window to judge (a client's first queries),
so a missing score is not read as "benign". The alarm threshold is chosen from the same
false-alarm budget as Path A. Rule thresholds come from config/settings.yaml (detection).
"""

import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

from dns_detect.models.thresholds import threshold_for_fpr
from dns_detect.utils.paths import MODELS_DIR

FUSION_INPUTS = ["ml_score_A", "ml_score_B", "has_score_B", "rule_hits"]
MODEL_FUSION = os.path.join(str(MODELS_DIR), "fusion_lr.pkl")
META_FUSION = os.path.join(str(MODELS_DIR), "fusion_lr.json")


def _detection_setting(name, default):
    try:
        from dns_detect.config import settings
        v = getattr(settings.detection, name, None)
        return default if v is None else v
    except Exception:
        return default


def _col(df: pd.DataFrame, *names) -> pd.Series:
    for n in names:
        if n in df.columns:
            return pd.to_numeric(df[n], errors="coerce").fillna(0.0)
    return pd.Series(np.zeros(len(df)), index=df.index)


def fusion_inputs(df: pd.DataFrame) -> np.ndarray:
    """Matrix of FUSION_INPUTS for each record (R3 tunneling + R4 deep-subdomain rule hits)."""
    a = _col(df, "ml_score_A")
    b = _col(df, "ml_score_B")
    length = _col(df, "query_length")
    ent = _col(df, "entropy", "query_entropy")
    depth = _col(df, "subdomain_depth", "subdomain_count")
    r3 = (length > float(_detection_setting("tunneling_length_threshold", 100))) & \
         (ent > float(_detection_setting("tunneling_entropy_threshold", 4.0)))
    r4 = depth > float(_detection_setting("subdomain_depth_threshold", 5))
    return np.column_stack([a, b, (b > 0).astype(float), r3.astype(float) + r4.astype(float)])


def fit(df_val: pd.DataFrame, y_val: np.ndarray, max_fpr: float):
    X = fusion_inputs(df_val)
    lr = LogisticRegression(class_weight="balanced", max_iter=1000).fit(X, y_val)
    thr = threshold_for_fpr(y_val, lr.predict_proba(X)[:, 1], max_fpr)
    meta = {"inputs": FUSION_INPUTS, "threshold": thr, "fpr_budget": max_fpr,
            "coefficients": dict(zip(FUSION_INPUTS, map(float, lr.coef_[0]))),
            "intercept": float(lr.intercept_[0])}
    return lr, meta


def save(lr, meta: dict) -> None:
    joblib.dump(lr, MODEL_FUSION)
    with open(META_FUSION, "w") as f:
        json.dump(meta, f, indent=2)


def load():
    """(model, meta) or None when no fusion model has been trained."""
    if not (os.path.exists(MODEL_FUSION) and os.path.exists(META_FUSION)):
        return None
    with open(META_FUSION) as f:
        return joblib.load(MODEL_FUSION), json.load(f)


def predict(df: pd.DataFrame, lr, meta: dict):
    prob = lr.predict_proba(fusion_inputs(df))[:, 1]
    return prob, (prob >= float(meta["threshold"])).astype(int)
