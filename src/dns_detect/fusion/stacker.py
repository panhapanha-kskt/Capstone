"""
stacker.py — Learned fusion of Path A, Path B and the per-query rules (ML_IMPROVEMENT_GUIDE Step 7).

The OR rule fires whenever either path fires, so the false alarms of both paths add up.
A logistic regression learns from the validation split how much to trust each signal:

    P(attack) = σ( w₀ + w₁·score_A + w₂·score_B + w₃·has_score_B + w₄·rule_hits )

`has_score_B` tells the model when Path B had no window to judge (a client's first queries),
so a missing score is not read as "benign". The alarm threshold is chosen from the same
false-alarm budget as Path A. Rule thresholds come from config/settings.yaml (detection).

V1 (above, `fusion_inputs` / `fit` / `predict`, models/fusion_lr.{pkl,json}) is kept unchanged.

V2 (`fusion_inputs_v2` / `fit_v2` / `predict_versioned`, models/fusion_lr_v2.{pkl,json}):
  inputs  logit_A      logit(clip(ml_score_A, EPS, 1-EPS))   Path A is a calibrated probability
          score_B      standardised logit(ml_score_B)          Path B is sigmoid(z) of the
                                                               reconstruction error, so its logit
                                                               is that z; 0 when missing
          has_score_B  1 when ml_score_B is present (NaN = no window), taken BEFORE any filling
          r3_tunnel    query_length > L and entropy > H        (rule R3)
          r4_deep      subdomain_depth > D                     (rule R4)
  frozen  rule thresholds and Path B scaling are saved in the metadata and used at inference;
          settings.yaml is read only at training time.
  fitting class_weight=None; the model is fitted on a "fit" part of the validation rows and the
          alarm threshold is set on a disjoint, benign-only "calibration" part (grouped by parent
          domain). The deployed model is that same fitted model — no refit — so the threshold
          belongs to the model that uses it. Grouped out-of-fold scores are kept for diagnostics.
  alarm   fusion_score > threshold (strict); Neyman-Pearson when the calibration part is large
          enough, otherwise the empirical budget (recorded as threshold_method).
The V2 output is called fusion_score: it is not a calibrated attack probability unless the
saved calibration diagnostics say so.
"""

import json
import logging
import os
import platform
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

from dns_detect.models.thresholds import (
    InsufficientCalibrationError, np_min_samples, np_threshold, threshold_for_fpr,
)
from dns_detect.utils.paths import MODELS_DIR

log = logging.getLogger(__name__)

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


# ═════════════════════════════════════════════════════════════════════════════
# V2
# ═════════════════════════════════════════════════════════════════════════════

MODEL_VERSION_V2 = 2
SUPPORTED_VERSIONS = (1, 2)
FUSION_INPUTS_V2 = ["logit_A", "score_B", "has_score_B", "r3_tunnel", "r4_deep"]
EPS = 1e-6
MODEL_FUSION_V2 = os.path.join(str(MODELS_DIR), "fusion_lr_v2.pkl")
META_FUSION_V2 = os.path.join(str(MODELS_DIR), "fusion_lr_v2.json")

# Column aliases: bridge output uses Week-3 names, the parsed frame uses model names.
_ALIASES = {
    "query_length": ("query_length",),
    "entropy": ("entropy", "query_entropy"),
    "subdomain_depth": ("subdomain_depth", "subdomain_count"),
}
RULE_DEFAULTS = {"tunneling_length_threshold": 100.0, "tunneling_entropy_threshold": 4.0,
                 "subdomain_depth_threshold": 5.0}
REQUIRED_META_V2 = ("model_version", "feature_schema", "rule_thresholds", "transform",
                    "score_B_scaling", "coefficients", "intercept", "threshold",
                    "threshold_rule", "threshold_method", "fpr_budget", "delta")


class FusionSchemaError(ValueError):
    """A fusion artefact whose metadata is missing, malformed or of an unknown version."""


def _logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(np.asarray(p, dtype=float), EPS, 1.0 - EPS)
    return np.log(p) - np.log1p(-p)


def current_rule_thresholds() -> dict:
    """Rule thresholds from settings.yaml (detection) — read at TRAINING time only."""
    return {k: float(_detection_setting(k, v)) for k, v in RULE_DEFAULTS.items()}


def _numeric(df: pd.DataFrame, name: str, *, allow_nan: bool) -> pd.Series:
    """
    The column `name` (or one of its aliases) as floats. Raises KeyError when absent and
    ValueError on values that are not numbers, are infinite, or are NaN where NaN is not allowed.
    Nothing is silently filled.
    """
    col = next((c for c in _ALIASES.get(name, (name,)) if c in df.columns), None)
    if col is None:
        raise KeyError(f"fusion input column {name!r} is missing "
                       f"(looked for {list(_ALIASES.get(name, (name,)))})")
    raw = df[col]
    s = pd.to_numeric(raw, errors="coerce").astype(float)
    bad_text = s.isna() & raw.notna()
    if bad_text.any():
        rows = list(np.flatnonzero(bad_text.to_numpy())[:10])
        raise ValueError(f"column {col!r} has non-numeric values at rows {rows}")
    if np.isinf(s.to_numpy()).any():
        rows = list(np.flatnonzero(np.isinf(s.to_numpy()))[:10])
        raise ValueError(f"column {col!r} has infinite values at rows {rows}")
    if not allow_nan and s.isna().any():
        rows = list(np.flatnonzero(s.isna().to_numpy())[:10])
        raise ValueError(f"column {col!r} has missing values at rows {rows}")
    return s


def score_b_logits(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """(logit of ml_score_B with NaN where missing, presence mask). Missing = NaN in the raw column."""
    if "ml_score_B" not in df.columns:
        n = len(df)
        return np.full(n, np.nan), np.zeros(n, dtype=bool)
    b = _numeric(df, "ml_score_B", allow_nan=True).to_numpy()
    present = ~np.isnan(b)
    z = np.full(len(b), np.nan)
    z[present] = _logit(b[present])
    return z, present


def build_spec(df_train: pd.DataFrame, rule_thresholds: dict | None = None) -> dict:
    """Frozen input specification from the TRAINING rows: rule thresholds + Path B scaling."""
    z, present = score_b_logits(df_train)
    zp = z[present]
    mu = float(zp.mean()) if zp.size else 0.0
    sd = float(zp.std()) if zp.size > 1 else 1.0
    return {"rule_thresholds": dict(rule_thresholds or current_rule_thresholds()),
            "transform": {"score_A": "logit", "score_B": "logit_standardised", "eps": EPS},
            "score_B_scaling": {"mean": mu, "std": sd if sd > 0 else 1.0, "n_present": int(zp.size)}}


def fusion_inputs_v2(df: pd.DataFrame, spec: dict) -> np.ndarray:
    """
    Matrix of FUSION_INPUTS_V2. `spec` is the frozen specification (build_spec / model metadata).
    ml_score_A is required and must be complete; ml_score_B may be NaN (no Path B window);
    the rule columns are required.
    """
    a = _numeric(df, "ml_score_A", allow_nan=False).to_numpy()
    z, present = score_b_logits(df)
    sc = spec["score_B_scaling"]
    score_b = np.where(present, (np.nan_to_num(z) - float(sc["mean"])) / float(sc["std"]), 0.0)
    rt = spec["rule_thresholds"]
    length = _numeric(df, "query_length", allow_nan=False).to_numpy()
    ent = _numeric(df, "entropy", allow_nan=False).to_numpy()
    depth = _numeric(df, "subdomain_depth", allow_nan=False).to_numpy()
    r3 = (length > float(rt["tunneling_length_threshold"])) & (ent > float(rt["tunneling_entropy_threshold"]))
    r4 = depth > float(rt["subdomain_depth_threshold"])
    return np.column_stack([_logit(a), score_b, present.astype(float), r3.astype(float), r4.astype(float)])


def _new_lr(class_weight=None, seed: int = 42) -> LogisticRegression:
    return LogisticRegression(class_weight=class_weight, max_iter=5000, random_state=seed)


# ── Splits ────────────────────────────────────────────────────────────────────

def fit_cal_split(y: np.ndarray, groups: np.ndarray, seed: int = 42, cal_share: float = 0.5):
    """
    Grouped (fit, calibration) cut of the validation rows. Calibration is benign-only: a
    Neyman-Pearson / FPR-budget threshold needs only benign scores, and every attack row is
    needed to fit the model. Groups (parent domains) that contain any attack go to `fit`;
    benign groups are shuffled and assigned to `cal` until ~cal_share of the benign rows are there.
    """
    y = np.asarray(y).astype(int)
    groups = np.asarray(groups).astype(str)
    attack_groups = set(groups[y == 1])
    benign_groups = sorted(set(groups) - attack_groups)
    rng = np.random.default_rng(seed)
    rng.shuffle(benign_groups)
    n_benign_target = cal_share * int((y == 0).sum())
    cal_groups, n = set(), 0
    sizes = pd.Series(groups).value_counts()
    for g in benign_groups:
        if n >= n_benign_target:
            break
        cal_groups.add(g)
        n += int(sizes[g])
    cal = np.flatnonzero(np.isin(groups, list(cal_groups)))
    fit = np.flatnonzero(~np.isin(groups, list(cal_groups)))
    if len(np.unique(y[fit])) < 2:
        raise ValueError("fit part needs both classes")
    return fit, cal


def oof_folds(y: np.ndarray, groups: np.ndarray, n_splits: int = 5, seed: int = 42):
    """
    Grouped K-fold indices (StratifiedGroupKFold, the class-balancing variant of GroupKFold).
    Falls back to plain GroupKFold if the stratified variant cannot be built. Asserts that no
    group is on both sides of a fold. Returns (folds, method).
    """
    from sklearn.model_selection import GroupKFold, StratifiedGroupKFold
    y = np.asarray(y).astype(int)
    groups = np.asarray(groups).astype(str)
    k = min(n_splits, len(np.unique(groups)))
    try:
        folds = list(StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=seed).split(y, y, groups))
        method = f"StratifiedGroupKFold(n_splits={k})"
    except ValueError as e:
        log.warning("StratifiedGroupKFold failed (%s) — using GroupKFold", e)
        folds = list(GroupKFold(n_splits=k).split(y, y, groups))
        method = f"GroupKFold(n_splits={k})"
    for tr, te in folds:
        overlap = set(groups[tr]) & set(groups[te])
        if overlap:
            raise AssertionError(f"group leakage across a fold: {sorted(overlap)[:5]}")
    return folds, method


def oof_scores(df: pd.DataFrame, y: np.ndarray, groups: np.ndarray, n_splits: int = 5,
               seed: int = 42, class_weight=None, rule_thresholds: dict | None = None) -> dict:
    """
    Grouped out-of-fold fusion scores: each fold builds its own spec (Path B scaling) from its
    training part, fits, and scores the held-out part. Every row gets exactly one score.
    Folds whose training part has one class are reported and their rows stay NaN.
    """
    y = np.asarray(y).astype(int)
    folds, method = oof_folds(y, groups, n_splits, seed)
    oof = np.full(len(y), np.nan)
    hits = np.zeros(len(y), dtype=int)
    coefs, skipped = [], []
    for i, (tr, te) in enumerate(folds):
        hits[te] += 1
        if len(np.unique(y[tr])) < 2:
            skipped.append(i)
            continue
        spec = build_spec(df.iloc[tr], rule_thresholds)
        lr = _new_lr(class_weight, seed).fit(fusion_inputs_v2(df.iloc[tr], spec), y[tr])
        oof[te] = lr.predict_proba(fusion_inputs_v2(df.iloc[te], spec))[:, 1]
        coefs.append(dict(zip(FUSION_INPUTS_V2, map(float, lr.coef_[0]))))
    if not np.all(hits == 1):
        raise AssertionError("out-of-fold split did not score every row exactly once")
    return {"oof": oof, "method": method, "n_folds": len(folds), "skipped_folds": skipped,
            "fold_coefficients": coefs}


# ── Calibration diagnostics ──────────────────────────────────────────────────

def calibration_report(y, p, n_bins: int = 10) -> dict:
    """Brier score, 10-bin reliability table and expected calibration error (equal-width bins)."""
    y = np.asarray(y).astype(int)
    p = np.asarray(p, dtype=float)
    ok = ~np.isnan(p)
    y, p = y[ok], p[ok]
    if len(y) == 0:
        return {"n": 0}
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1], right=False), 0, n_bins - 1)
    table, ece = [], 0.0
    for b in range(n_bins):
        m = idx == b
        if not m.any():
            table.append({"bin": [float(edges[b]), float(edges[b + 1])], "n": 0})
            continue
        conf, acc = float(p[m].mean()), float(y[m].mean())
        ece += m.mean() * abs(conf - acc)
        table.append({"bin": [float(edges[b]), float(edges[b + 1])], "n": int(m.sum()),
                      "mean_score": conf, "attack_share": acc})
    return {"n": int(len(y)), "brier": float(np.mean((p - y) ** 2)), "ece": float(ece),
            "base_rate": float(y.mean()), "reliability": table}


def tier_boundaries(benign_scores, threshold: float, min_rows_q99: int = 100) -> dict:
    """
    Confidence-tier cut points from benign scores of the deployed model on rows it was not
    fitted on: LOW from the benign q90, MEDIUM from q99, HIGH from the alarm threshold.
    Kept monotone (q90 <= q99 <= threshold); with fewer than `min_rows_q99` rows q99 is not
    estimable and MEDIUM collapses into LOW.
    """
    s = np.asarray(benign_scores, dtype=float)
    s = s[np.isfinite(s)]
    thr = float(threshold)
    if s.size == 0:
        return {"q90": thr, "q99": thr, "high": thr, "n_benign": 0, "note": "no benign scores"}
    q90 = float(np.quantile(s, 0.90))
    q99 = float(np.quantile(s, 0.99)) if s.size >= min_rows_q99 else thr
    q90, q99 = min(q90, thr), min(max(q99, q90), thr)
    return {"q90": q90, "q99": q99, "high": thr, "n_benign": int(s.size),
            "note": "" if s.size >= min_rows_q99 else f"q99 not estimable from {s.size} rows"}


# ── Training ──────────────────────────────────────────────────────────────────

def _versions() -> dict:
    import sklearn
    return {"python": platform.python_version(), "numpy": np.__version__,
            "pandas": pd.__version__, "scikit_learn": sklearn.__version__}


def choose_threshold(cal_benign_scores, max_fpr: float, delta: float = 0.05,
                     attack_scores=None) -> dict:
    """
    Neyman-Pearson threshold when the benign calibration rows suffice; otherwise the project's
    empirical budget rule `threshold_for_fpr` (no guarantee), with a warning. Alarm rule is
    `score > threshold` either way.

    Fallback: threshold_for_fpr places t midway between b (the (k+1)-th highest benign score)
    and the lowest attack score above b, leaving margin for unseen benign traffic (see its
    docstring). The calibration part is benign-only, so `attack_scores` (the deployed model's
    scores on the fit part's attacks — in-sample) supply the upper edge of the gap. Without
    attack scores t sits just above b. Either way, the strict rule `score > t'` with
    t' = nextafter(t, -inf) gives exactly threshold_for_fpr's `score >= t` decision.
    """
    s = np.asarray(cal_benign_scores, dtype=float)
    try:
        r = np_threshold(s, max_fpr, delta)
        return {"threshold": r["threshold"], "threshold_method": "neyman_pearson",
                "np_k": r["k"], "np_bound": r["bound"], "n_cal_benign": r["n"],
                "n_required_for_np": np_min_samples(max_fpr, delta)}
    except InsufficientCalibrationError as e:
        log.warning("%s Falling back to the empirical FPR budget (no guarantee).", e)
        att = np.asarray(attack_scores if attack_scores is not None else [], dtype=float)
        y = np.r_[np.zeros(len(s)), np.ones(len(att))]
        t = threshold_for_fpr(y, np.r_[s, att], max_fpr)
        return {"threshold": float(np.nextafter(t, -np.inf)),
                "threshold_method": "empirical_fallback" + ("_gap_midpoint" if len(att) else ""),
                "n_cal_benign": int(len(s)), "n_required_for_np": e.n_required,
                "benign_quantile_edge": float(np.sort(s)[len(s) - 1 - min(len(s) - 1, int(np.floor(max_fpr * len(s))))])
                if len(s) else None}


def fit_v2(df_val: pd.DataFrame, y_val: np.ndarray, groups: np.ndarray, max_fpr: float,
           delta: float = 0.05, seed: int = 42, class_weight=None, n_splits: int = 5,
           rule_thresholds: dict | None = None, extra_meta: dict | None = None):
    """
    Train fusion V2 on the validation rows. Returns (model, meta, diagnostics).

    1. grouped benign-only calibration part (fit_cal_split);
    2. spec (rule thresholds + Path B scaling) and logistic regression from the fit part;
    3. threshold from the calibration part's benign scores (choose_threshold);
    4. tier boundaries from the same calibration scores;
    5. grouped out-of-fold scores over all validation rows, for calibration diagnostics.
    """
    y_val = np.asarray(y_val).astype(int)
    groups = np.asarray(groups).astype(str)
    rule_thresholds = dict(rule_thresholds or current_rule_thresholds())
    fit_idx, cal_idx = fit_cal_split(y_val, groups, seed)
    df_fit, df_cal = df_val.iloc[fit_idx], df_val.iloc[cal_idx]
    spec = build_spec(df_fit, rule_thresholds)
    lr = _new_lr(class_weight, seed).fit(fusion_inputs_v2(df_fit, spec), y_val[fit_idx])
    cal_scores = lr.predict_proba(fusion_inputs_v2(df_cal, spec))[:, 1]
    fit_attack_scores = lr.predict_proba(fusion_inputs_v2(df_fit[y_val[fit_idx] == 1], spec))[:, 1]
    thr = choose_threshold(cal_scores, max_fpr, delta, attack_scores=fit_attack_scores)

    oof = oof_scores(df_val, y_val, groups, n_splits, seed, class_weight, rule_thresholds)
    cal_diag = calibration_report(y_val, oof["oof"])
    oof_benign = oof["oof"][(y_val == 0) & ~np.isnan(oof["oof"])]
    qs = [0.5, 0.9, 0.99, 0.999]
    alignment = {"quantiles": qs,
                 "oof_benign": [float(np.quantile(oof_benign, q)) for q in qs] if oof_benign.size else [],
                 "cal_benign_deployed_model": [float(np.quantile(cal_scores, q)) for q in qs]
                 if cal_scores.size else []}
    # Out-of-fold ECE on validation rows is necessary, not sufficient, for calling the score a
    # probability (deployment prevalence and drift differ) — so the output is always named
    # fusion_score; the flag only records what the validation diagnostics showed.
    oof_ece_small = bool(cal_diag.get("ece", 1.0) <= 0.05)

    meta = {
        "model_version": MODEL_VERSION_V2,
        "feature_schema": list(FUSION_INPUTS_V2),
        **spec,
        "coefficients": dict(zip(FUSION_INPUTS_V2, map(float, lr.coef_[0]))),
        "intercept": float(lr.intercept_[0]),
        **thr,
        "threshold_rule": ">",
        "fpr_budget": float(max_fpr),
        "delta": float(delta),
        "class_weight": class_weight,
        "score_name": "fusion_score",
        "oof_ece_below_0_05": oof_ece_small,
        "tier_boundaries": tier_boundaries(cal_scores, thr["threshold"]),
        "tier_source": "calibration_part_benign",
        "rows": {"validation": int(len(y_val)), "fit": int(len(fit_idx)), "calibration": int(len(cal_idx)),
                 "attack": int((y_val == 1).sum()), "benign": int((y_val == 0).sum()),
                 "fit_attack": int((y_val[fit_idx] == 1).sum()), "fit_benign": int((y_val[fit_idx] == 0).sum()),
                 "cal_benign": int((y_val[cal_idx] == 0).sum())},
        "class_prior_validation": float(y_val.mean()),
        "cv": {"method": oof["method"], "n_folds": oof["n_folds"], "group": "parent_domain",
               "skipped_folds": oof["skipped_folds"], "seed": int(seed)},
        "oof_calibration": {k: v for k, v in cal_diag.items() if k != "reliability"},
        "random_seed": int(seed),
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "versions": _versions(),
        **(extra_meta or {}),
    }
    diagnostics = {"oof": oof, "oof_calibration": cal_diag, "alignment": alignment,
                   "fit_idx": fit_idx, "cal_idx": cal_idx, "cal_scores": cal_scores}
    validate_meta_v2(meta)
    return lr, meta, diagnostics


# ── Artefacts ─────────────────────────────────────────────────────────────────

def validate_meta_v2(meta: dict) -> None:
    missing = [k for k in REQUIRED_META_V2 if k not in meta]
    if missing:
        raise FusionSchemaError(f"fusion V2 metadata is missing {missing}")
    if list(meta["feature_schema"]) != FUSION_INPUTS_V2:
        raise FusionSchemaError(f"fusion V2 feature schema {meta['feature_schema']} != {FUSION_INPUTS_V2}")
    if meta["threshold_rule"] != ">":
        raise FusionSchemaError(f"unsupported threshold rule {meta['threshold_rule']!r}")
    for k in RULE_DEFAULTS:
        if k not in meta["rule_thresholds"]:
            raise FusionSchemaError(f"rule threshold {k!r} missing from metadata")
    sc = meta["score_B_scaling"]
    if not ({"mean", "std"} <= set(sc)) or not float(sc["std"]) > 0:
        raise FusionSchemaError("score_B_scaling needs mean and a positive std")


def meta_version(meta: dict) -> int:
    v = meta.get("model_version", 1)       # V1 files predate the field
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise FusionSchemaError(f"model_version {v!r} is not an integer")
    if v not in SUPPORTED_VERSIONS:
        raise FusionSchemaError(f"unknown fusion model_version {v}; supported: {SUPPORTED_VERSIONS}")
    return v


def save_v2(lr, meta: dict, model_path: str | None = None, meta_path: str | None = None) -> None:
    """Write the V2 artefact. Never touches the V1 files."""
    validate_meta_v2(meta)
    model_path, meta_path = model_path or MODEL_FUSION_V2, meta_path or META_FUSION_V2
    if os.path.abspath(model_path) == os.path.abspath(MODEL_FUSION):
        raise ValueError("refusing to overwrite the V1 fusion artefact")
    joblib.dump(lr, model_path)
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)


def load_versioned(version: int | None = None):
    """
    (model, meta) for the requested version, or None if that artefact does not exist.
    version=None → V2 when present, else V1. Malformed metadata raises FusionSchemaError.
    """
    candidates = {1: (MODEL_FUSION, META_FUSION), 2: (MODEL_FUSION_V2, META_FUSION_V2)}
    if version is not None and int(version) not in SUPPORTED_VERSIONS:
        raise FusionSchemaError(f"unknown fusion model_version {version}; supported: {SUPPORTED_VERSIONS}")
    order = [int(version)] if version is not None else [2, 1]
    for v in order:
        mp, jp = candidates[v]
        if not (os.path.exists(mp) and os.path.exists(jp)):
            continue
        with open(jp) as f:
            meta = json.load(f)
        found = meta_version(meta)
        if found != v:
            raise FusionSchemaError(f"{jp} declares model_version {found}, expected {v}")
        if v == 1:
            for k in ("inputs", "threshold"):
                if k not in meta:
                    raise FusionSchemaError(f"fusion V1 metadata is missing {k!r}")
            if list(meta["inputs"]) != FUSION_INPUTS:
                raise FusionSchemaError(f"fusion V1 inputs {meta['inputs']} != {FUSION_INPUTS}")
        else:
            validate_meta_v2(meta)
        return joblib.load(mp), meta
    return None


def predict_versioned(df: pd.DataFrame, model, meta: dict):
    """(score, label) with the input builder and alarm rule of the artefact's own version."""
    if meta_version(meta) == 1:
        return predict(df, model, meta)
    validate_meta_v2(meta)
    score = model.predict_proba(fusion_inputs_v2(df, meta))[:, 1]
    return score, (score > float(meta["threshold"])).astype(int)
