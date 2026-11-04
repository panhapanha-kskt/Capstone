#!/usr/bin/env python3
"""
bridge.py — Week 3 features → ML scores (Path A + Path B) → one fused decision → Week 4.
DNS Traffic Anomaly Detection System.

Flow (python -m dns_detect.fusion.bridge --week3 ... --output ...):
  1. Load the Week-3 records once; every record gets row_id = its position in the file.
     Required FEATURES_8 inputs are checked on the RAW records (the parser would zero-fill).
  2. Path A (RF + GBT soft-vote, path_a.score_frame) → ml_score_A / ml_label_A.
     Missing Path A model: production raises ModelUnavailableError; development with
     --allow-missing-path-a marks every record "degraded" (NaN score, never benign by default).
  3. Path B (Trafficformer, path_b_predict.score_records, per-client windows) → ml_score_B.
     Only the LAST record of each window gets a score; the rest are NaN with has_score_B = 0.
     Path B's API is positional, so its output is checked against the bridge's rows
     (length + client_ip order) before it is attached by row_id.
  4. Fusion — one decision path (ensemble.fusion):
       lr      learned logistic regression, V1 (models/fusion_lr.*)          fusion_method = lr
       lr_v2   learned logistic regression, V2 (models/fusion_lr_v2.*)       fusion_method = lr
       or      explicit legacy OR of the per-path labels                     fusion_method = or_fallback
     Missing learned model: production raises; development falls back to the OR rule
     (fusion_method = or_fallback) with a benign-quantile score. Comparison columns are always
     written: ml_combined_label_or, ml_combined_score_legacy (max(A, wA·A + wB·B)).
  5. Confidence tiers from benign alarm volume (HIGH = alarm; MEDIUM ≥ benign q99; LOW ≥ q90;
     CLEAN below; UNSCORED when there is no score) — boundaries come from the fusion artefact.
  6. Detection allowlist suppresses alarms (score kept for audit; threat score zeroed).
  7. ml_threat_score = ml_combined_score (one score for Week 4); the old hand-weighted formula
     stays as ml_threat_score_legacy. attack_count / attack_signature pass through unchanged.
  8. Output JSON (missing values are null, never NaN) + <output>.meta.json run summary.

Modes: ensemble.bridge_mode in settings.yaml (production by default) or --dev on the CLI.

Usage:
  python -m dns_detect.fusion.bridge --week3 data/week3_features_all.json \\
      --output data/week3_features_with_ml.json --path-b-model dns_trafficformer
  python -m dns_detect.fusion.bridge ... --no-path-b              # Path B off (scores all NaN)
  python -m dns_detect.fusion.bridge ... --dev --allow-missing-path-a   # development only
  python -m dns_detect.fusion.bridge --week3 ... --label-only --output labeled.json
      # keeps trusted labels; --allow-heuristic-labels adds attack_count >= 1 labels (experimental)
"""

import argparse
import json
import logging
import math
import os
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

from dns_detect.parsing.dns_parser import (
    FEATURES_8, _load_json_records, load_as_dataframe, load_multifeature_with_meta,
)
from dns_detect.models.path_a import score_frame, MODEL_RF, MODEL_SCALER
from dns_detect.fusion import stacker
from dns_detect.ingest.labeling import TRUSTED_SOURCES, load_allowlist
from dns_detect.utils.paths import PROJECT_ROOT, MODELS_DIR

log = logging.getLogger(__name__)

FALLBACK_QUANTILES = os.path.join(str(MODELS_DIR), "fusion_fallback_quantiles.json")
V1_TIERS = os.path.join(str(MODELS_DIR), "fusion_lr_tiers.json")
LEGACY_TIER_CUTS = {"HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.3}
FUSION_METHODS = ("lr", "or_fallback", "degraded")
WEEK4_COLUMNS = ("ml_combined_score", "ml_combined_label", "ml_confidence", "ml_threat_score")


class ModelUnavailableError(RuntimeError):
    """A model the bridge needs is missing and the mode does not allow running without it."""


class AlignmentError(RuntimeError):
    """Scores could not be matched to records one-to-one."""


class MissingFeaturesError(ValueError):
    """Required model inputs are absent from the Week-3 records."""


# ─────────────────────────────────────────────
# SETTINGS
# ─────────────────────────────────────────────

def _ensemble_setting(name, default):
    try:
        from dns_detect.config import settings
        v = getattr(settings.ensemble, name, None)
        return default if v is None else v
    except Exception:
        return default


def _fusion_mode() -> str:
    mode = str(_ensemble_setting("fusion", "or") or "or").lower()
    if mode not in ("or", "lr", "lr_v2"):
        raise ValueError(f"ensemble.fusion must be one of or / lr / lr_v2, got {mode!r}")
    return mode


def _bridge_mode() -> str:
    mode = str(_ensemble_setting("bridge_mode", "production") or "production").lower()
    if mode not in ("production", "development"):
        raise ValueError(f"ensemble.bridge_mode must be production or development, got {mode!r}")
    return mode


# ─────────────────────────────────────────────
# LABELS (--label-only)
# ─────────────────────────────────────────────

ATTACK_TYPE_MAP = {
    "NORMAL":           0,
    "NXDOMAIN_FLOOD":   1,
    "RANDOM_SUBDOMAIN": 2,
    "AMPLIFICATION":    3,
    "CACHE_POISONING":  4,
    "HIGH_ENTROPY":     5,
    "ENCODING":         6,
}
# Primary type when a record carries several Week-3 flags: most severe first, independent of
# the order the names appear in attack_signature. Integrity and exfiltration indicators outrank
# volumetric ones.
ATTACK_TYPE_PRIORITY = ("CACHE_POISONING", "ENCODING", "HIGH_ENTROPY", "RANDOM_SUBDOMAIN",
                        "NXDOMAIN_FLOOD", "AMPLIFICATION")


def attack_types(signature) -> list:
    """Known attack type names in a Week-3 attack_signature (comma separated), deduplicated."""
    names = [p.strip().upper() for p in str(signature or "").split(",")]
    return sorted({n for n in names if n in ATTACK_TYPE_MAP and n != "NORMAL"})


def primary_attack_type(signature) -> str:
    present = set(attack_types(signature))
    return next((t for t in ATTACK_TYPE_PRIORITY if t in present), "NORMAL")


def generate_labels_from_week3(records: list, allow_heuristic: bool = False) -> list:
    """
    Training labels for Week-3 records.

    Trusted labels already present (label 0/1 with label_source in TRUSTED_SOURCES, or no
    source = "file") are kept. Records whose label is untrusted or missing are NOT labeled from
    attack_count unless allow_heuristic=True: attack_count is the Week-3 rule count, so training on
    it teaches the models the rules' own false alarms. Heuristic labels are tagged
    label_source = "heuristic", which the training guard (ingest/labeling.validate_training_labels)
    rejects by default. Also adds attack_type_id (priority order, not signature order) and
    multi-hot attack_type_<NAME> columns.
    """
    labeled, counts, need = [], {}, 0
    for rec in records:
        r = dict(rec)
        has_label = "label" in rec and rec["label"] in (0, 1, "0", "1", 0.0, 1.0)
        src = rec.get("label_source") if isinstance(rec.get("label_source"), str) and rec.get("label_source") else "file"
        if has_label and src in TRUSTED_SOURCES:
            r["label"], r["label_source"] = int(float(rec["label"])), src
        else:
            need += 1
            if allow_heuristic:
                r["label"] = 1 if int(r.get("attack_count", 0) or 0) >= 1 else 0
                r["label_source"] = "heuristic"
        if "label" in r and r.get("label_source"):
            counts[r["label_source"]] = counts.get(r["label_source"], 0) + 1
        types = attack_types(r.get("attack_signature"))
        r["attack_type_id"] = ATTACK_TYPE_MAP[primary_attack_type(r.get("attack_signature"))]
        for t in ATTACK_TYPE_PRIORITY:
            r[f"attack_type_{t}"] = int(t in types)
        labeled.append(r)

    if need and not allow_heuristic:
        raise ValueError(
            f"{need} of {len(records)} records have no trusted label. Label them from an attack "
            f"manifest (scripts/label_from_manifest.py / ingest/labeling.py), or pass "
            f"--allow-heuristic-labels to use attack_count >= 1 (experimental, tagged 'heuristic').")
    total = len(labeled)
    print(f"   Labels by source: {counts}")
    if counts.get("heuristic"):
        h = counts["heuristic"]
        warnings.warn(f"{h} of {total} labels ({100 * h / max(total, 1):.2f}%) are heuristic "
                      f"(attack_count >= 1). They are NOT ground truth; training refuses them by default.")
    return labeled


# ─────────────────────────────────────────────
# RECORDS, FEATURES, ALIGNMENT
# ─────────────────────────────────────────────

# Raw Week-3 columns from which week3_frame_to_features builds each FEATURES_8 input.
FEATURE_SOURCES = {
    "query_length":      ("query_length",),
    "query_entropy":     ("query_entropy", "entropy"),
    "has_digits":        ("has_digits", "domain"),
    "answer_count":      ("answer_count", "answer_size"),
    "subdomain_count":   ("subdomain_count", "subdomain_depth"),
    "longest_label":     ("longest_label", "first_label_length", "domain"),
    "digit_ratio":       ("digit_ratio", "numeric_ratio"),
    "unique_char_ratio": ("unique_char_ratio", "domain"),
}


def check_features(raw: pd.DataFrame) -> dict:
    """
    {"missing_columns": [...], "rows_missing": {feature: n_rows}} — computed on the RAW records,
    before the parser's zero-fill. A feature is missing when none of its source columns exists;
    a row is missing a feature when every source column is null on that row.
    """
    missing_cols, rows_missing, row_mask = [], {}, np.zeros(len(raw), dtype=bool)
    for feat, sources in FEATURE_SOURCES.items():
        present = [c for c in sources if c in raw.columns]
        if not present:
            missing_cols.append(feat)
            continue
        null_all = raw[present].isna().all(axis=1).to_numpy()
        if null_all.any():
            rows_missing[feat] = int(null_all.sum())
            row_mask |= null_all
    return {"missing_columns": missing_cols, "rows_missing": rows_missing, "row_mask": row_mask}


def join_on_row_id(base: pd.DataFrame, other: pd.DataFrame, name: str) -> pd.DataFrame:
    """One-to-one left join on row_id that raises instead of guessing."""
    for frame, label in ((base, "records"), (other, name)):
        if "row_id" not in frame.columns:
            raise AlignmentError(f"{label} has no row_id column")
        if frame["row_id"].isna().any():
            raise AlignmentError(f"{label} has {int(frame['row_id'].isna().sum())} missing row_id(s)")
        dup = frame["row_id"].duplicated()
        if dup.any():
            raise AlignmentError(f"{label} has duplicate row_id(s): {frame.loc[dup, 'row_id'].head().tolist()}")
    unmatched = set(other["row_id"]) - set(base["row_id"])
    if unmatched:
        raise AlignmentError(f"{name} has {len(unmatched)} row_id(s) not in the records: {sorted(unmatched)[:5]}")
    absent = set(base["row_id"]) - set(other["row_id"])
    if absent:
        raise AlignmentError(f"{name} is missing {len(absent)} record(s): {sorted(absent)[:5]}")
    clash = [c for c in other.columns if c != "row_id" and c in base.columns]
    out = base.drop(columns=clash).merge(other, on="row_id", how="left", validate="one_to_one", sort=False)
    return out


# ─────────────────────────────────────────────
# PATH A
# ─────────────────────────────────────────────

def run_path_a(week3_json_path: str = None, df: pd.DataFrame = None) -> pd.DataFrame:
    """
    Path A (RF + Gradient Boosting soft-vote) scores. The Transformer is a reported baseline only.
    Returns a frame with row_id, ml_score_A, ml_label_A, ml_verdict_A. Raises
    ModelUnavailableError when a model file is missing.
    """
    print("\n── Path A: RF + Gradient Boosting (8-feature tree ensemble) ──")
    missing = [m for m in (MODEL_RF, MODEL_SCALER) if not os.path.exists(m)]
    if missing:
        raise ModelUnavailableError(
            f"Path A model not found: {', '.join(missing)}\n"
            f"Train it first: python -m dns_detect.models.path_a --train <labeled_data>")
    if df is None:
        df = load_as_dataframe(week3_json_path)
        df["row_id"] = np.arange(len(df))
    # Same feature code path as training: per-query + window features + bigram score.
    scores, preds, threshold, decision = score_frame(df)
    print(f"   Decision: {decision}  |  threshold: {threshold:.4f}")
    out = pd.DataFrame({"row_id": df["row_id"].to_numpy(), "ml_score_A": np.asarray(scores, dtype=float),
                        "ml_label_A": np.asarray(preds, dtype=float)})
    out["ml_verdict_A"] = np.where(out["ml_label_A"] == 1, "ATTACK", "benign")
    a_attacks = int((out["ml_label_A"] == 1).sum())
    print(f"   Path A results: {a_attacks} attack  |  {len(out) - a_attacks} benign")
    return out


def degraded_path_a(row_ids) -> pd.DataFrame:
    """Path A unavailable (development only): NaN scores, verdict SKIP — never 'benign'."""
    n = len(row_ids)
    return pd.DataFrame({"row_id": np.asarray(row_ids), "ml_score_A": np.full(n, np.nan),
                         "ml_label_A": np.full(n, np.nan), "ml_verdict_A": ["SKIP"] * n})


# ─────────────────────────────────────────────
# PATH B
# ─────────────────────────────────────────────

def run_path_b(week3_json_path: str, save_name: str, model_dir: str = None):
    """
    Path B (multi-feature Trafficformer). Windows are built per client in time order; each
    window's score lands on its LAST record. Returns (ml_score_B, ml_label_B, covered) as
    Series aligned to the JSON's record order; records without a window are NaN (not 0).
    """
    from dns_detect.models.path_b_predict import score_records   # TensorFlow is loaded only here
    if model_dir is None:
        model_dir = str(MODELS_DIR)
    print("\n── Path B: Trafficformer (multi-feature, per-client sequences) ─")
    scores, anomalies, covered, _thr = score_records(week3_json_path, save_name, model_dir)
    covered = np.asarray(covered, dtype=bool)
    n_total = len(scores)
    b_attacks = int(np.asarray(anomalies)[covered].sum())
    print(f"   Path B results: {b_attacks} anomalies  |  {int(covered.sum()) - b_attacks} normal  "
          f"({int(covered.sum())}/{n_total} records scored; the rest have no window yet)")
    if covered.any():
        print(f"   Score range: {scores[covered].min():.4f} – {scores[covered].max():.4f}")
    return (pd.Series(np.where(covered, scores, np.nan), name="ml_score_B"),
            pd.Series(np.where(covered, anomalies, np.nan).astype(float), name="ml_label_B"),
            pd.Series(covered, name="has_score_B"))


def check_path_b_alignment(week3_json_path: str, df: pd.DataFrame, n_scores: int) -> None:
    """Path B scores are positional: confirm they cover the same records in the same order."""
    if n_scores != len(df):
        raise AlignmentError(f"Path B returned {n_scores} scores for {len(df)} records")
    _, _, client_ip, _ = load_multifeature_with_meta(week3_json_path)
    if len(client_ip) != len(df):
        raise AlignmentError(f"Path B loader read {len(client_ip)} records, the bridge {len(df)}")
    if "client_ip" in df.columns:
        mine = df["client_ip"].astype(str).to_numpy()
        bad = np.flatnonzero(mine != np.asarray(client_ip).astype(str))
        if bad.size:
            raise AlignmentError(f"Path B record order differs from the bridge at rows {bad[:5].tolist()}")


# ─────────────────────────────────────────────
# FALLBACK SCORE AND CONFIDENCE TIERS
# ─────────────────────────────────────────────

def load_fallback_quantiles(path: str = None):
    """Frozen benign validation score distributions (train_fusion.py --version 2), or None."""
    path = path or FALLBACK_QUANTILES
    if not os.path.exists(path):
        return None
    with open(path) as f:
        q = json.load(f)
    return {"a": np.asarray(q.get("path_a_benign_sorted", []), dtype=float),
            "b": np.asarray(q.get("path_b_benign_sorted", []), dtype=float)}


def benign_quantile(benign_sorted: np.ndarray, scores) -> np.ndarray:
    """
    Empirical benign quantile: share of benign validation scores <= score, in [0, 1].
    Scores above the observed range map to 1, below to 0. NaN stays NaN. An empty
    distribution gives NaN (no calibration available).
    """
    s = np.asarray(scores, dtype=float)
    out = np.full(s.shape, np.nan)
    if benign_sorted is None or len(benign_sorted) == 0:
        return out
    ok = ~np.isnan(s)
    out[ok] = np.searchsorted(benign_sorted, s[ok], side="right") / len(benign_sorted)
    return out


def assign_tiers(score, alarm, cuts: dict) -> np.ndarray:
    """
    HIGH = the fused alarm; MEDIUM = score >= benign q99; LOW = score >= benign q90; CLEAN below;
    UNSCORED when the score is missing. Cut points are made monotone (q90 <= q99).
    """
    s = np.asarray(score, dtype=float)
    alarm = np.asarray(alarm).astype(bool)
    q90 = float(cuts["q90"])
    q99 = max(float(cuts["q99"]), q90)
    tier = np.where(s >= q99, "MEDIUM", np.where(s >= q90, "LOW", "CLEAN")).astype(object)
    tier[alarm] = "HIGH"
    tier[np.isnan(s)] = "UNSCORED"
    return tier


def legacy_tiers(score) -> np.ndarray:
    s = np.asarray(score, dtype=float)
    t = np.where(s >= 0.8, "HIGH", np.where(s >= 0.5, "MEDIUM", np.where(s >= 0.3, "LOW", "CLEAN"))).astype(object)
    t[np.isnan(s)] = "UNSCORED"
    return t


# ─────────────────────────────────────────────
# ALLOWLIST
# ─────────────────────────────────────────────

def load_detection_allowlist() -> set:
    """Suffixes from detection.allowlist_path (config/detect_allowlist.txt); empty if unset."""
    try:
        from dns_detect.config import settings
        path = getattr(settings.detection, "allowlist_path", None)
    except Exception:
        path = None
    if not path:
        return set()
    p = Path(path)
    return load_allowlist(str(p if p.is_absolute() else PROJECT_ROOT / p))


def allowlisted(domains: pd.Series, allowlist: set) -> np.ndarray:
    """True where the domain is an allowlisted suffix or under one, matched per DNS label."""
    def hit(d):
        labels = str(d).lower().rstrip(".").split(".")
        return any(".".join(labels[i:]) in allowlist for i in range(len(labels)))
    if not allowlist:
        return np.zeros(len(domains), dtype=bool)
    return domains.map(hit).to_numpy(dtype=bool)


# ─────────────────────────────────────────────
# MERGE AND FUSE
# ─────────────────────────────────────────────

def _load_learned(fusion: str):
    """(model, meta, tier_cuts, tier_source) for lr / lr_v2, or None when the artefact is missing."""
    loaded = stacker.load_versioned(2 if fusion == "lr_v2" else 1)
    if loaded is None:
        return None
    model, meta = loaded
    if stacker.meta_version(meta) == 2:
        return model, meta, meta["tier_boundaries"], meta.get("tier_source", "v2_metadata")
    if os.path.exists(V1_TIERS):
        with open(V1_TIERS) as f:
            t = json.load(f)
        return model, meta, t, t.get("tier_source", "v1_sidecar")
    return model, meta, None, "legacy_fixed"


def merge_ml_scores(df_path_a: pd.DataFrame,
                    score_b: pd.Series,
                    label_b: pd.Series,
                    weight_a: float = 0.6,
                    weight_b: float = 0.4,
                    decision_threshold: float = None,
                    allowlist: set = None,
                    covered_b=None,
                    mode: str = None,
                    fusion: str = None) -> pd.DataFrame:
    """
    Attach Path B (positionally aligned to df_path_a), fuse, tier, and apply the allowlist.

    covered_b  Path B coverage mask; None = "present wherever score_b is not NaN" (callers that
               pass 0-filled scores keep their old behaviour).
    mode       production | development (default: ensemble.bridge_mode).
    fusion     lr | lr_v2 | or (default: ensemble.fusion).
    weight_a/b only shape ml_combined_score_legacy (comparison column).
    decision_threshold  accepted for backward compatibility; no longer used (the old
               ml_combined_label_thr compared the blend with Path A's own threshold).
    """
    mode = (mode or _bridge_mode()).lower()
    fusion = (fusion or _fusion_mode()).lower()
    df = df_path_a.copy()
    sb = pd.to_numeric(pd.Series(np.asarray(score_b), index=df.index), errors="coerce")
    lb = pd.to_numeric(pd.Series(np.asarray(label_b), index=df.index), errors="coerce")
    cov = (sb.notna().to_numpy() if covered_b is None else np.asarray(covered_b, dtype=bool))
    if len(sb) != len(df) or len(cov) != len(df):
        raise AlignmentError(f"Path B has {len(sb)} scores / {len(cov)} coverage flags for {len(df)} records")
    df["ml_score_B"] = sb.where(cov)
    df["ml_label_B"] = lb.where(cov)
    df["has_score_B"] = cov.astype(int)
    if "ml_score_A" not in df.columns:
        raise KeyError("ml_score_A is required (run Path A or mark the records degraded)")
    a = pd.to_numeric(df["ml_score_A"], errors="coerce")
    has_a = a.notna().to_numpy()

    # ── comparison columns (always present) ──
    a0, b0 = a.fillna(0.0), df["ml_score_B"].fillna(0.0)
    df["ml_combined_score_legacy"] = np.maximum(a0, weight_a * a0 + weight_b * b0)
    la = (pd.to_numeric(df.get("ml_label_A", pd.Series(0, index=df.index)), errors="coerce") == 1).to_numpy()
    lbb = (df["ml_label_B"] == 1).to_numpy()
    or_label = (la | lbb).astype(int)
    df["ml_combined_label_or"] = or_label

    score = np.full(len(df), np.nan)
    label = np.zeros(len(df), dtype=int)
    method = np.where(has_a, "lr", "degraded").astype(object)
    status = np.where(has_a, "ok", "degraded").astype(object)
    tier_cuts, tier_source, threshold = None, None, None

    learned = _load_learned(fusion) if fusion in ("lr", "lr_v2") else None
    if fusion in ("lr", "lr_v2") and learned is None:
        msg = (f"ensemble.fusion is {fusion!r} but the fusion model "
               f"({'models/fusion_lr_v2.pkl' if fusion == 'lr_v2' else 'models/fusion_lr.pkl'}) is missing")
        if mode == "production":
            raise ModelUnavailableError(msg + " — train it (scripts/train_fusion.py) or run with --dev")
        warnings.warn(msg + " — DEVELOPMENT MODE: using the OR rule (fusion_method=or_fallback)")

    if learned is not None:
        model, meta, tier_cuts, tier_source = learned
        threshold = float(meta["threshold"])
        rows = np.flatnonzero(has_a)
        if rows.size:
            sub = df.iloc[rows]
            if stacker.meta_version(meta) == 1:
                sub = sub.assign(ml_score_B=sub["ml_score_B"].fillna(0.0))   # V1's own input semantics
            s, l = stacker.predict_versioned(sub, model, meta)
            score[rows], label[rows] = s, l
        print(f"   Fusion: logistic regression V{stacker.meta_version(meta)} (threshold {threshold:.4f}) — "
              f"{int(label.sum())} attack vs {int(or_label[has_a].sum())} with the OR rule")
    else:
        # OR rule: configured explicitly (fusion: or) or development fallback.
        q = load_fallback_quantiles()
        method[has_a] = "or_fallback"
        status[has_a] = "or_configured" if fusion == "or" else "fallback"
        label[has_a] = or_label[has_a]
        if q is not None:
            qa = benign_quantile(q["a"], a.to_numpy())
            qb = benign_quantile(q["b"], df["ml_score_B"].to_numpy())
            score = np.where(np.isnan(qb), qa, np.fmax(qa, qb))
            tier_cuts, tier_source = {"q90": 0.90, "q99": 0.99}, "benign_quantile_scale"
        else:
            tier_source = "none (no fallback quantiles: models/fusion_fallback_quantiles.json)"
        score[~has_a] = np.nan
        if fusion != "or":
            print("   [warn] fusion model missing — OR rule used (development mode)")

    if (~has_a).any():
        msg = f"{int((~has_a).sum())} record(s) have no Path A score (degraded)"
        if mode == "production":
            raise ModelUnavailableError(msg + " — production mode refuses to emit unscored records")
        warnings.warn(msg + " — they are marked fusion_method=degraded, ml_confidence=UNSCORED")

    df["ml_combined_score"] = score
    df["ml_combined_label"] = label
    df["fusion_method"] = method
    df["fusion_status"] = status
    if tier_cuts is not None:
        df["ml_confidence"] = assign_tiers(score, label == 1, tier_cuts)
        df["confidence_method"] = tier_source
    else:
        df["ml_confidence"] = legacy_tiers(score)
        df["confidence_method"] = "legacy_fixed"
    df.attrs["fusion"] = {"fusion": fusion, "mode": mode, "threshold": threshold,
                          "tier_cuts": tier_cuts, "tier_source": tier_source}

    # Detection allowlist: known CDN / telemetry names never raise an alarm. The score stays,
    # so suppressed rows can still be audited.
    if allowlist is None:
        allowlist = load_detection_allowlist()
    domains = df["domain"] if "domain" in df.columns else pd.Series([""] * len(df), index=df.index)
    suppressed = allowlisted(domains, allowlist) & (df["ml_combined_label"].to_numpy() == 1)
    df["suppressed_by_allowlist"] = suppressed
    df.loc[suppressed, "ml_combined_label"] = 0
    if suppressed.any():
        print(f"   Allowlist: {int(suppressed.sum())} alarm(s) suppressed (score kept)")

    df["ml_combined_verdict"] = np.where(df["fusion_method"] == "degraded", "ml_unscored",
                                         np.where(df["ml_combined_label"] == 1, "ML_ATTACK", "ml_benign"))
    return df


# ─────────────────────────────────────────────
# WEEK 4 COMPATIBILITY
# ─────────────────────────────────────────────

def ensure_week4_compatible(df: pd.DataFrame) -> pd.DataFrame:
    """
    Columns Week 4 (detection/engine.py) reads. Does NOT modify existing Week-3 columns.
    ml_threat_score = ml_combined_score (one score), zeroed where the allowlist suppressed the
    alarm so Week 4 Rule 6 cannot re-raise it. The old formula is kept as ml_threat_score_legacy.
    """
    for w4_col, ml_col in {"entropy": "query_entropy", "subdomain_depth": "subdomain_count"}.items():
        if w4_col not in df.columns and ml_col in df.columns:
            df[w4_col] = df[ml_col]
    a0 = pd.to_numeric(df.get("ml_score_A", pd.Series(0.0, index=df.index)), errors="coerce").fillna(0)
    b0 = pd.to_numeric(df.get("ml_score_B", pd.Series(0.0, index=df.index)), errors="coerce").fillna(0)
    if "attack_count" in df.columns:
        rule = pd.to_numeric(df["attack_count"], errors="coerce").fillna(0).clip(0, 6) / 6.0
        df["ml_threat_score_legacy"] = 0.4 * rule + 0.35 * a0 + 0.25 * b0
    else:
        df["ml_threat_score_legacy"] = df.get("ml_combined_score_legacy", pd.Series(0.0, index=df.index))
    threat = pd.to_numeric(df.get("ml_combined_score", pd.Series(np.nan, index=df.index)), errors="coerce")
    if "suppressed_by_allowlist" in df.columns:
        threat = threat.where(~df["suppressed_by_allowlist"].astype(bool), 0.0)
    df["ml_threat_score"] = threat
    return df


def check_week4_contract(df: pd.DataFrame) -> None:
    missing = [c for c in WEEK4_COLUMNS if c not in df.columns]
    if missing:
        raise AlignmentError(f"bridge output lacks Week-4 columns {missing}")


def _json_safe(records: list) -> list:
    """NaN / ±inf → None (null in JSON); numpy scalars → Python."""
    out = []
    for r in records:
        clean = {}
        for k, v in r.items():
            if isinstance(v, (np.floating, float)):
                v = None if not math.isfinite(float(v)) else float(v)
            elif isinstance(v, np.integer):
                v = int(v)
            elif isinstance(v, np.bool_):
                v = bool(v)
            clean[k] = v
        out.append(clean)
    return out


def tier_summary(df: pd.DataFrame, fpr_budget: float = None) -> dict:
    """Records per tier and the benign rows per 10,000 the tier definition implies."""
    total = len(df)
    budget = fpr_budget if fpr_budget is not None else 0.001
    expected = {"HIGH": budget, "MEDIUM": max(0.0, 0.01 - budget), "LOW": 0.09, "CLEAN": 0.90, "UNSCORED": None}
    out = {}
    for t in ("HIGH", "MEDIUM", "LOW", "CLEAN", "UNSCORED"):
        n = int((df["ml_confidence"] == t).sum())
        e = expected[t] if df["confidence_method"].iloc[0] != "legacy_fixed" else None
        out[t] = {"records": n, "share": n / total if total else 0.0,
                  "expected_benign_per_10k": None if e is None else round(1e4 * e, 1)}
    return out


# ─────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────

def run_bridge(week3_path: str, output_path: str,
               path_b_model: str = None,
               model_dir: str = None,
               weight_a: float = 0.6,
               weight_b: float = 0.4,
               label_only: bool = False,
               no_path_b: bool = False,
               mode: str = None,
               allow_missing_path_a: bool = False,
               fill_missing_features: bool = False,
               allow_heuristic_labels: bool = False):

    mode = (mode or _bridge_mode()).lower()
    print("\n" + "=" * 70)
    print("ML BRIDGE — Connecting Week 3 → ML Models → Week 4")
    print("=" * 70)
    print(f"Input  : {week3_path}")
    print(f"Output : {output_path}")
    print(f"Mode   : {mode}  |  fusion: {_fusion_mode()}")

    records = _load_json_records(week3_path)
    print(f"\n[*] Loaded {len(records)} Week 3 records")
    out_dir = os.path.dirname(output_path) or "."

    if label_only:
        print("\n[*] LABEL ONLY MODE — trusted labels kept; heuristic labels only with --allow-heuristic-labels")
        labeled = generate_labels_from_week3(records, allow_heuristic=allow_heuristic_labels)
        os.makedirs(out_dir, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(labeled, f, indent=2, default=str)
        print(f"\n✅ Labeled data saved → {output_path}")
        return

    if (allow_missing_path_a or fill_missing_features) and mode != "development":
        raise ValueError("--allow-missing-path-a / --fill-missing-features need development mode (--dev)")

    raw = pd.DataFrame(records)
    feat = check_features(raw)
    if feat["missing_columns"] and not fill_missing_features:
        raise MissingFeaturesError(
            f"Week-3 records lack model inputs {feat['missing_columns']} (looked for "
            f"{ {f: FEATURE_SOURCES[f] for f in feat['missing_columns']} }). Re-run feature extraction, "
            f"or use --dev --fill-missing-features to zero-fill them (experimental).")
    if feat["rows_missing"] and not fill_missing_features:
        raise MissingFeaturesError(f"some records have null model inputs {feat['rows_missing']}; "
                                   f"use --dev --fill-missing-features to zero-fill them (experimental).")

    df = load_as_dataframe(week3_path)
    if len(df) != len(records):
        raise AlignmentError(f"parser returned {len(df)} rows for {len(records)} records")
    df["row_id"] = np.arange(len(df))
    if fill_missing_features:
        df["features_filled"] = feat["row_mask"] | bool(feat["missing_columns"])
        if df["features_filled"].any():
            warnings.warn(f"zero-filled features: columns {feat['missing_columns']}, rows {feat['rows_missing']}")

    # Path A
    try:
        pa = run_path_a(df=df)
    except ModelUnavailableError as e:
        if not allow_missing_path_a:
            raise
        warnings.warn(f"{e}\nDEVELOPMENT MODE: every record is marked degraded (no Path A score).")
        pa = degraded_path_a(df["row_id"])
    df = join_on_row_id(df, pa, "Path A scores")

    # Path B
    covered = np.zeros(len(df), dtype=bool)
    score_b = pd.Series(np.full(len(df), np.nan), name="ml_score_B")
    label_b = pd.Series(np.full(len(df), np.nan), name="ml_label_B")
    path_b_status = "disabled (--no-path-b)" if no_path_b else "disabled (--path-b-model not given)"
    if not no_path_b and path_b_model:
        try:
            score_b, label_b, cov = run_path_b(week3_path, path_b_model, model_dir)
            check_path_b_alignment(week3_path, df, len(score_b))
            covered = cov.to_numpy()
            path_b_status = "ok"
        except FileNotFoundError as e:
            # Path B is optional by design (warm-up windows, no model yet): scores stay NaN.
            print(f"\n⚠ Path B unavailable: {e} — Path B scores are left empty (NaN), not 0")
            path_b_status = f"model missing: {e}"
    else:
        print(f"\n[*] Path B {path_b_status} — scores left empty (NaN)")
    pb = pd.DataFrame({"row_id": df["row_id"].to_numpy(), "ml_score_B": score_b.to_numpy(),
                       "ml_label_B": label_b.to_numpy(), "has_score_B": covered})
    df = join_on_row_id(df, pb, "Path B scores")

    print("\n── Merging ML scores ──────────────────────────────────────────")
    df = merge_ml_scores(df, df["ml_score_B"], df["ml_label_B"], weight_a, weight_b,
                         covered_b=df["has_score_B"].to_numpy(dtype=bool), mode=mode)
    df = ensure_week4_compatible(df)
    fusion_info = df.attrs.get("fusion", {})

    # Preserve every original Week-3 column, joined by row_id (never by position).
    week3_df = raw.copy()
    week3_df["row_id"] = np.arange(len(week3_df))
    extra = [c for c in week3_df.columns if c not in df.columns]
    if extra:
        df = join_on_row_id(df, week3_df[["row_id"] + extra], "Week-3 columns")
    df = df.sort_values("row_id", kind="stable").reset_index(drop=True)
    check_week4_contract(df)

    total = len(df)
    fpr_budget = None
    try:
        from dns_detect.models.path_a import _training_setting
        fpr_budget = float(_training_setting("path_a_max_fpr", 0.001))
    except Exception:
        pass
    tiers = tier_summary(df, fpr_budget)
    summary = {
        "records": total, "mode": mode, "fusion": fusion_info.get("fusion"),
        "fusion_threshold": fusion_info.get("threshold"), "tier_source": fusion_info.get("tier_source"),
        "fusion_method": df["fusion_method"].value_counts().to_dict(),
        "fusion_status": df["fusion_status"].value_counts().to_dict(),
        "path_b": path_b_status, "path_b_covered": int(df["has_score_B"].sum()),
        "path_b_missing": int(total - df["has_score_B"].sum()),
        "path_a_missing": int(df["ml_score_A"].isna().sum()),
        "alarms": int(df["ml_combined_label"].sum()), "alarms_or_rule": int(df["ml_combined_label_or"].sum()),
        "suppressed_by_allowlist": int(df["suppressed_by_allowlist"].sum()),
        "features_filled": {"columns": feat["missing_columns"], "rows": feat["rows_missing"]}
        if fill_missing_features else None,
        "tiers": tiers,
    }
    print("\n── Bridge Summary ─────────────────────────────────────────────")
    print(f"   Total records      : {total}")
    print(f"   Fusion method      : {summary['fusion_method']}")
    print(f"   ML attacks flagged : {summary['alarms']} ({summary['alarms'] / max(total, 1) * 100:.1f}%)  "
          f"| OR rule would flag {summary['alarms_or_rule']}")
    print(f"   Path B scored      : {summary['path_b_covered']}/{total}  | Path A missing: {summary['path_a_missing']}")
    print(f"   Confidence tiers ({df['confidence_method'].iloc[0] if total else '-'}):")
    for t, v in tiers.items():
        exp = "" if v["expected_benign_per_10k"] is None else f"  (benign traffic: ~{v['expected_benign_per_10k']}/10k by design)"
        print(f"     {t:9s}: {v['records']:7d}  {100 * v['share']:5.1f}%{exp}")
    print("   Tiers are alarm-volume bands from benign validation scores, not attack probabilities.")

    os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(_json_safe(df.to_dict(orient="records")), f, indent=2, default=str, allow_nan=False)
    with open(output_path + ".meta.json", "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"\n✅ Bridge output saved → {output_path}  (run summary: {output_path}.meta.json)")
    print(f"   Next step: python -m dns_detect.detection.engine --input {output_path}")
    return summary


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="bridge.py — Week 3 features → ML scores → one fused decision → Week 4",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Workflow:
  1. Labels: python scripts/label_from_manifest.py ...   (or ingest/labeling.py via train_models.sh)
  2. Train Path A / Path B / fusion: ./scripts/train_models.sh; python scripts/train_fusion.py ...
  3. Bridge:  python -m dns_detect.fusion.bridge --week3 data/week3_features_all.json \\
                 --output data/week3_features_with_ml.json --path-b-model dns_trafficformer
  4. Week 4:  python -m dns_detect.detection.engine --input data/week3_features_with_ml.json
        """)
    parser.add_argument("--week3", type=str, required=True)
    parser.add_argument("--output", type=str, required=True)
    parser.add_argument("--path-b-model", type=str, default=None)
    parser.add_argument("--model-dir", type=str, default=None)
    parser.add_argument("--weight-a", type=float, default=None,
                        help="DEPRECATED: only shapes ml_combined_score_legacy (default 0.6)")
    parser.add_argument("--weight-b", type=float, default=None,
                        help="DEPRECATED: only shapes ml_combined_score_legacy (default 0.4)")
    parser.add_argument("--label-only", action="store_true")
    parser.add_argument("--allow-heuristic-labels", action="store_true",
                        help="--label-only: label untrusted rows from attack_count >= 1 (tagged 'heuristic')")
    parser.add_argument("--no-path-b", action="store_true")
    parser.add_argument("--dev", action="store_true",
                        help="development mode (overrides ensemble.bridge_mode): OR fallback when the "
                             "fusion model is missing, and the two options below")
    parser.add_argument("--allow-missing-path-a", action="store_true",
                        help="--dev only: run without Path A; every record is marked degraded")
    parser.add_argument("--fill-missing-features", action="store_true",
                        help="--dev only: zero-fill missing model inputs and record which")
    args = parser.parse_args()
    if args.weight_a is not None or args.weight_b is not None:
        warnings.warn("--weight-a/--weight-b no longer control the fusion decision; they only shape "
                      "the ml_combined_score_legacy comparison column", DeprecationWarning, stacklevel=1)
        print("   [deprecated] --weight-a/--weight-b only affect ml_combined_score_legacy")

    run_bridge(
        week3_path=args.week3,
        output_path=args.output,
        path_b_model=args.path_b_model,
        model_dir=args.model_dir,
        weight_a=0.6 if args.weight_a is None else args.weight_a,
        weight_b=0.4 if args.weight_b is None else args.weight_b,
        label_only=args.label_only,
        no_path_b=args.no_path_b,
        mode="development" if args.dev else None,
        allow_missing_path_a=args.allow_missing_path_a,
        fill_missing_features=args.fill_missing_features,
        allow_heuristic_labels=args.allow_heuristic_labels,
    )


if __name__ == "__main__":
    warnings.simplefilter("always", DeprecationWarning)
    main()
