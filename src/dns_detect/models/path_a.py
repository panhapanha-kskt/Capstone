#!/usr/bin/env python3
"""
path_a.py — Path A: per-query tree ensemble (RF + HistGradientBoosting)
DNS Tunnel Detector — ML layer

Design:
  - Inputs = PATH_A_FEATURES: 7 per-query features (FEATURES_8 without answer_count, which
    only encodes the capture source) + behaviour features over a past-only 5-minute window
    + a benign character-bigram score (features/aggregates.py).
  - Split before any fitting; scaler, bigram model, calibration and threshold never see test.
  - Validation is cut in two grouped halves: one calibrates the tree scores (isotonic), the
    other chooses RF-only vs RF+GBT and the alarm threshold.
  - Threshold = the lowest score whose false-alarm rate on validation benign rows stays within
    training.path_a_max_fpr (a false-alarm budget), not the F1-optimal point at 54 % prevalence.
  - The Transformer is trained + reported as a baseline only, never in the decision.

Usage:
  python -m dns_detect.models.path_a --train merged_features_labeled.json [--split-manifest m.json]
  python -m dns_detect.models.path_a --infer week3_features_all.json [--output-json out.json]
"""

import os
import json
import argparse
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    classification_report, roc_auc_score, average_precision_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
from tensorflow import keras
from tensorflow.keras import layers

from dns_detect.parsing.dns_parser import (
    load_as_dataframe, FEATURES_8, PATH_A_FEATURES, feature_vector_key,
)
from dns_detect.features.aggregates import (
    BigramModel, WINDOW_SECONDS, add_aggregate_features, domain_series,
)
from dns_detect.models.splits import (
    grouped_split, overlap_share, partition_conflicting_groups, load_manifest_indices,
)
from dns_detect.models.thresholds import threshold_for_fpr
from dns_detect.utils.dataset_hash import dataset_hash
from dns_detect.utils.paths import PROJECT_ROOT

SEQUENCE_LENGTH = 10
_MODELS_DIR = str(PROJECT_ROOT / "models")
MODEL_RF   = os.path.join(_MODELS_DIR, "dns_tunnel_rf.pkl")
MODEL_GBT  = os.path.join(_MODELS_DIR, "dns_tunnel_gbt.pkl")
MODEL_TF   = os.path.join(_MODELS_DIR, "dns_tunnel_transformer.keras")  # baseline only (not in decision)
MODEL_SCALER = os.path.join(_MODELS_DIR, "dns_scaler.pkl")
MODEL_THRESHOLD = os.path.join(_MODELS_DIR, "dns_threshold.json")
MODEL_BIGRAM = os.path.join(_MODELS_DIR, "bigram_table.json")


def _training_setting(name: str, default):
    try:
        from dns_detect.config import settings
        v = getattr(settings.training, name, None)
        return default if v is None else v
    except Exception:
        return default


# ─────────────────────────────────────────────
# TRANSFORMER ARCHITECTURE (baseline only)
# ─────────────────────────────────────────────

def transformer_encoder(inputs, head_size, num_heads, ff_dim, dropout=0.0):
    x = layers.LayerNormalization(epsilon=1e-6)(inputs)
    x = layers.MultiHeadAttention(
        key_dim=head_size, num_heads=num_heads, dropout=dropout
    )(x, x)
    x = layers.Dropout(dropout)(x)
    res = x + inputs

    x = layers.LayerNormalization(epsilon=1e-6)(res)
    x = layers.Conv1D(filters=ff_dim, kernel_size=1, activation="relu")(x)
    x = layers.Dropout(dropout)(x)
    x = layers.Conv1D(filters=inputs.shape[-1], kernel_size=1)(x)
    return x + res


def build_transformer(input_shape, head_size=32, num_heads=2, ff_dim=64,
                      num_transformer_blocks=2, mlp_units=None,
                      dropout=0.1, mlp_dropout=0.1):
    """Binary classification transformer. Output: sigmoid → P(attack)."""
    if mlp_units is None:
        mlp_units = [64]

    inputs = keras.Input(shape=input_shape)
    x = inputs
    for _ in range(num_transformer_blocks):
        x = transformer_encoder(x, head_size, num_heads, ff_dim, dropout)

    x = layers.GlobalAveragePooling1D(data_format="channels_last")(x)
    for dim in mlp_units:
        x = layers.Dense(dim, activation="relu")(x)
        x = layers.Dropout(mlp_dropout)(x)

    outputs = layers.Dense(1, activation="sigmoid")(x)
    return keras.Model(inputs, outputs)


def build_sequences(X: np.ndarray, y: np.ndarray, seq_len: int):
    Xs, ys = [], []
    for i in range(len(X) - seq_len + 1):
        Xs.append(X[i: i + seq_len])
        ys.append(y[i + seq_len - 1])
    return np.array(Xs), np.array(ys)


def build_sequences_unlabeled(X: np.ndarray, seq_len: int) -> np.ndarray:
    return np.array([X[i: i + seq_len] for i in range(len(X) - seq_len + 1)])


# ─────────────────────────────────────────────
# THRESHOLD + CALIBRATION
# ─────────────────────────────────────────────

def calibrate(model, X_cal: np.ndarray, y_cal: np.ndarray):
    """Isotonic calibration of an already-fitted classifier on held-out rows (sigmoid if few rows)."""
    if len(np.unique(y_cal)) < 2:
        print("   [warn] calibration half has one class — scores left uncalibrated")
        return model
    from sklearn.calibration import CalibratedClassifierCV
    method = "isotonic" if len(y_cal) >= 200 else "sigmoid"
    try:
        from sklearn.frozen import FrozenEstimator
        cal = CalibratedClassifierCV(FrozenEstimator(model), method=method)
    except ImportError:  # scikit-learn < 1.6
        cal = CalibratedClassifierCV(model, method=method, cv="prefit")
    return cal.fit(X_cal, y_cal)


def _split_validation(val_idx: np.ndarray, groups: np.ndarray, y: np.ndarray, seed: int = 42):
    """Grouped 50/50 cut of the validation rows: (calibration half, threshold half)."""
    if len(val_idx) >= 20:
        gss = GroupShuffleSplit(n_splits=10, test_size=0.5, random_state=seed)
        for a, b in gss.split(val_idx, y[val_idx], groups[val_idx]):
            cal, thr = val_idx[a], val_idx[b]
            if len(np.unique(y[cal])) == 2 and len(np.unique(y[thr])) == 2:
                return cal, thr
    print("   [warn] validation too small to halve — calibration and threshold share it")
    return val_idx, val_idx


# ─────────────────────────────────────────────
# FEATURES (one code path for training and inference)
# ─────────────────────────────────────────────

def build_feature_frame(df: pd.DataFrame, features, bigram=None) -> pd.DataFrame:
    """Add whatever behaviour features `features` needs and zero-fill any still missing."""
    df = add_aggregate_features(df, bigram, window_seconds=WINDOW_SECONDS, features=features)
    for col in features:
        if col not in df.columns:
            df[col] = 0
    return df


def feature_matrix(df: pd.DataFrame, features) -> np.ndarray:
    return df[list(features)].apply(pd.to_numeric, errors="coerce").fillna(0.0).to_numpy(dtype=float)


def load_path_a_meta() -> dict:
    """Feature list + bigram model the saved Path A was trained with (old models: FEATURES_8)."""
    meta = {"features": list(FEATURES_8), "bigram": None}
    if os.path.exists(MODEL_THRESHOLD):
        with open(MODEL_THRESHOLD) as f:
            meta["features"] = list(json.load(f).get("features", FEATURES_8))
    if "bigram_logprob" in meta["features"]:
        if not os.path.exists(MODEL_BIGRAM):
            raise FileNotFoundError(f"{MODEL_BIGRAM} missing — retrain Path A")
        meta["bigram"] = BigramModel.load(MODEL_BIGRAM)
    return meta


# ─────────────────────────────────────────────
# LEARNERS
# ─────────────────────────────────────────────

def train_random_forest(X_train, y_train, X_val, y_val):
    print("\n── Random Forest ──────────────────────────────────────────────")
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    print("   validation report (uncalibrated):")
    print(classification_report(y_val, rf.predict(X_val), target_names=["benign", "attack"], zero_division=0))
    return rf


def train_gradient_boosting(X_train, y_train, X_val, y_val):
    """Second tree learner; relies on features differently from RF (two-opinion ensemble)."""
    print("\n── Gradient Boosting (HistGradientBoosting) ────────────────────")
    gbt = HistGradientBoostingClassifier(
        learning_rate=0.1, max_iter=300, early_stopping=True, validation_fraction=0.15,
        class_weight="balanced", random_state=42,
    )
    gbt.fit(X_train, y_train)
    print("   validation report (uncalibrated):")
    print(classification_report(y_val, gbt.predict(X_val), target_names=["benign", "attack"], zero_division=0))
    return gbt


def tree_ensemble_scores(rf_model, gbt_model, X_flat, decision="rf_gbt"):
    """Path A score = mean P(attack) of the two (calibrated) trees, or RF alone for 'rf_only'."""
    rf_probs = rf_model.predict_proba(X_flat)[:, 1]
    if decision == "rf_only" or gbt_model is None:
        return rf_probs
    gbt_probs = gbt_model.predict_proba(X_flat)[:, 1]
    return 0.5 * (rf_probs + gbt_probs)


def load_path_a_models():
    """Load Path A production models + threshold + decision for inference."""
    rf_model = joblib.load(MODEL_RF)
    gbt_model = joblib.load(MODEL_GBT) if os.path.exists(MODEL_GBT) else None
    scaler = joblib.load(MODEL_SCALER)
    threshold, decision = load_threshold_and_decision()
    return rf_model, gbt_model, scaler, threshold, decision


def score_frame(df: pd.DataFrame):
    """Score a records DataFrame with the saved Path A. Returns (scores, preds, threshold, decision)."""
    rf_model, gbt_model, scaler, threshold, decision = load_path_a_models()
    meta = load_path_a_meta()
    feats = build_feature_frame(df, meta["features"], meta["bigram"])
    X = scaler.transform(feature_matrix(feats, meta["features"]))
    scores = tree_ensemble_scores(rf_model, gbt_model, X, decision)
    return scores, (scores >= threshold).astype(int), threshold, decision


def train_transformer(X_seq_train, y_seq_train, X_seq_test, y_seq_test):
    print("\n── Transformer (Binary Classifier, baseline only) ────────────")
    model = build_transformer(
        input_shape=(SEQUENCE_LENGTH, X_seq_train.shape[2]),
        head_size=32, num_heads=2, ff_dim=64,
        num_transformer_blocks=2, mlp_units=[64],
        dropout=0.1, mlp_dropout=0.1,
    )
    model.compile(optimizer="adam", loss="binary_crossentropy",
                  metrics=["accuracy", keras.metrics.AUC(name="auc")])
    model.fit(
        X_seq_train, y_seq_train,
        validation_data=(X_seq_test, y_seq_test),
        epochs=30, batch_size=32,
        callbacks=[keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True,
                                                 monitor="val_auc", mode="max")],
        verbose=0,
    )
    model.save(MODEL_TF)
    print(f"Saved → {MODEL_TF}")
    return model


# ─────────────────────────────────────────────
# ENSEMBLE INFERENCE (legacy RF + Transformer API, kept for callers)
# ─────────────────────────────────────────────

def _ensemble_scores(rf_model, tf_model, X_flat, X_seq, rf_weight=0.5, tf_weight=0.5):
    rf_probs = rf_model.predict_proba(X_flat)[:, 1]
    tf_probs = tf_model.predict(X_seq, verbose=0).flatten()
    pad = len(rf_probs) - len(tf_probs)
    return np.concatenate([rf_probs[:pad], rf_weight * rf_probs[pad:] + tf_weight * tf_probs])


def ensemble_predict(rf_model, tf_model, X_flat, X_seq, threshold=0.5, rf_weight=0.5, tf_weight=0.5):
    combined = _ensemble_scores(rf_model, tf_model, X_flat, X_seq, rf_weight, tf_weight)
    return (combined >= threshold).astype(int), combined


def load_threshold() -> float:
    """Load calibrated threshold from disk, default 0.5 if not found."""
    if os.path.exists(MODEL_THRESHOLD):
        with open(MODEL_THRESHOLD) as f:
            return float(json.load(f).get("threshold", 0.5))
    return 0.5


def load_threshold_and_decision():
    """Load (threshold, decision) where decision ∈ {'rf_gbt','rf_only'}."""
    if os.path.exists(MODEL_THRESHOLD):
        with open(MODEL_THRESHOLD) as f:
            data = json.load(f)
        return float(data.get("threshold", 0.5)), str(data.get("decision", "rf_gbt"))
    return 0.5, "rf_gbt"


# ─────────────────────────────────────────────
# METRICS
# ─────────────────────────────────────────────

def _metric_block(y_true, scores, threshold):
    """Threshold-dependent + threshold-free metrics for a score vector."""
    from sklearn.metrics import precision_score, recall_score, f1_score
    y_true = np.asarray(y_true)
    preds = (np.asarray(scores) >= threshold).astype(int)
    n_ben = int((y_true == 0).sum())
    try:
        roc = float(roc_auc_score(y_true, scores))
    except Exception:
        roc = None
    try:
        pr = float(average_precision_score(y_true, scores))
    except Exception:
        pr = None
    return {
        "precision": float(precision_score(y_true, preds, zero_division=0)),
        "recall":    float(recall_score(y_true, preds, zero_division=0)),
        "f1":        float(f1_score(y_true, preds, zero_division=0)),
        "fpr":       float(((preds == 1) & (y_true == 0)).sum() / n_ben) if n_ben else None,
        "false_alarms": int(((preds == 1) & (y_true == 0)).sum()),
        "pr_auc":    pr,
        "pr_auc_baseline": float((y_true == 1).mean()) if len(y_true) else None,
        "roc_auc":   roc,
        "threshold": float(threshold),
    }


def _recall_by_family(y_true, preds, families):
    """Per-attack-family recall (families aligned to rows)."""
    if families is None:
        return {}
    out = {}
    fams = np.asarray(families)
    for fam in sorted(set(fams[y_true == 1])):
        mask = (y_true == 1) & (fams == fam)
        n = int(mask.sum())
        if n:
            out[str(fam)] = {"recall": float(preds[mask].mean()), "support": n}
    return out


def _model_vector_key(df: pd.DataFrame, features) -> np.ndarray:
    vals = df[list(features)].apply(pd.to_numeric, errors="coerce").fillna(0).astype(float).round(6)
    return vals.astype(str).agg("|".join, axis=1).to_numpy()


# ─────────────────────────────────────────────
# FULL TRAINING PIPELINE
# ─────────────────────────────────────────────

def run_training(input_path: str, rf_weight=0.5, tf_weight=0.5, shuffle_labels=False,
                 split_manifest: str = None, with_transformer: bool = True):
    print(f"\n[*] Loading training data: {input_path}")
    df = load_as_dataframe(input_path)
    for col in FEATURES_8:
        if col not in df.columns:
            df[col] = 0
    if "label" not in df.columns:
        raise ValueError(
            "Training data must have a 'label' column (0=benign, 1=attack). "
            "Run Step 8 labeling first: python -m dns_detect.ingest.labeling --input … --output …"
        )

    # Rows without a label (abstained in Step 8) can't be used for supervised training.
    unlabeled = pd.to_numeric(df["label"], errors="coerce").isna()
    if unlabeled.any():
        print(f"[*] Dropped {int(unlabeled.sum())} row(s) without a label")
        df = df[~unlabeled].reset_index(drop=True)
    df["label"] = pd.to_numeric(df["label"]).astype(int)
    y = df["label"].to_numpy()
    print(f"[*] Dataset: {len(df)} records  |  Benign: {(y == 0).sum()}  |  Attack: {(y == 1).sum()}")
    if len(np.unique(y)) < 2:
        # Checked before ANY artifact is written, so a bad dataset never half-overwrites models.
        raise SystemExit(f"[error] Training data has a single class (label={int(y[0])}). "
                         f"Path A needs benign and attack rows. No model files were changed.")

    features = list(PATH_A_FEATURES)
    max_fpr = float(_training_setting("path_a_max_fpr", 0.001))
    print(f"[*] Path A features ({len(features)}): {', '.join(features)}")
    print(f"[*] False-alarm budget: {max_fpr:.3%} of benign validation rows")

    # Window features use no labels and only past traffic, so computing them before the
    # split is what live detection does too. The bigram model needs training data → later.
    df = build_feature_frame(df, [f for f in features if f != "bigram_logprob"])

    fam = df["attack_family"].astype(str).to_numpy() if "attack_family" in df.columns \
        else np.array(["?"] * len(df))
    trusted = (~df["label_source"].isin(["weak_behavioral"])).to_numpy() if "label_source" in df.columns \
        else np.ones(len(df), dtype=bool)

    # ── STEP 1: SPLIT BEFORE ANY FITTING ──────────────────────────
    # Exact copies of the per-query vector stay on one side (exact-copy leakage, N2).
    groups = feature_vector_key(df).to_numpy()
    # Conflicts are judged on what the model sees (minus the bigram score, a function of
    # the name). They are kept out of training and saved as an error-analysis set (N8).
    keep, conflict_mask, n_conflicts = partition_conflicting_groups(
        y, _model_vector_key(df, [f for f in features if f != "bigram_logprob"]))
    if n_conflicts:
        print(f"[*] {int(conflict_mask.sum())} rows in {n_conflicts} model vector(s) carry both labels "
              f"→ error-analysis set, not trained on")
        try:
            out = os.path.normpath(os.path.join(_MODELS_DIR, "..", "data", "processed", "conflicts.json"))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            df.loc[conflict_mask].to_json(out, orient="records")
            print(f"    saved → {out}")
        except Exception as e:
            print(f"    [warn] could not persist conflict partition: {e}")

    if split_manifest:
        tr_idx, val_idx, te_idx, missing, manifest = load_manifest_indices(split_manifest, df)
        # Conflicts never train or calibrate; the shared test rows stay exactly as listed.
        tr_idx, val_idx = tr_idx[keep[tr_idx]], val_idx[keep[val_idx]]
        split_method = f"manifest:{os.path.basename(split_manifest)}"
        if len(missing):
            print(f"[*] {len(missing)} row(s) are not in the manifest and are left out")
        if len(val_idx) == 0:
            raise SystemExit("[error] manifest has no validation rows — Path A needs them for calibration")
    else:
        kept = np.where(keep)[0]
        tr_r, val_r, te_r, split_method = grouped_split(y[kept], groups[kept], seed=42)
        tr_idx, val_idx, te_idx = kept[tr_r], kept[val_r], kept[te_r]
    test_twin_share = overlap_share(groups, tr_idx, te_idx)
    print(f"[*] Split ({split_method}) → train={len(tr_idx)}  val={len(val_idx)}  test={len(te_idx)}  "
          f"| test rows with an exact twin in train: {test_twin_share:.1%}")

    # ── STEP 2: FIT EVERYTHING DATA-DEPENDENT ON TRAIN ONLY ───────
    bigram = None
    if "bigram_logprob" in features:
        bigram = BigramModel().fit(domain_series(df.iloc[tr_idx][y[tr_idx] == 0]))
        df["bigram_logprob"] = bigram.score_many(domain_series(df))
    X_all = feature_matrix(df, features)
    scaler = StandardScaler().fit(X_all[tr_idx])
    X_train, X_val, X_test = (scaler.transform(X_all[i]) for i in (tr_idx, val_idx, te_idx))
    y_train, y_val, y_test = y[tr_idx], y[val_idx], y[te_idx]
    fam_test, trusted_test = fam[te_idx], trusted[te_idx]

    rf_raw = train_random_forest(X_train, y_train, X_val, y_val)
    gbt_raw = train_gradient_boosting(X_train, y_train, X_val, y_val)

    transformer_block = None
    if with_transformer:
        X_seq_tr, y_seq_tr = build_sequences(X_train, y_train, SEQUENCE_LENGTH)
        X_seq_val, y_seq_val = build_sequences(X_val, y_val, SEQUENCE_LENGTH)
        X_seq_te, y_seq_te = build_sequences(X_test, y_test, SEQUENCE_LENGTH)
        tf_model = train_transformer(X_seq_tr, y_seq_tr, X_seq_val, y_seq_val)
        try:
            transformer_block = _metric_block(y_seq_te, tf_model.predict(X_seq_te, verbose=0).flatten(), 0.5)
        except Exception:
            transformer_block = None

    # ── STEP 3: CALIBRATE, GATE AND SET THE THRESHOLD ON VALIDATION ─
    print("\n── Calibration + decision gate (validation only) ─────────────")
    cal_rel, thr_rel = _split_validation(np.arange(len(val_idx)), groups[val_idx], y_val)
    rf_model = calibrate(rf_raw, X_val[cal_rel], y_val[cal_rel])
    gbt_model = calibrate(gbt_raw, X_val[cal_rel], y_val[cal_rel])
    print(f"   calibration rows={len(cal_rel)}  threshold rows={len(thr_rel)}")

    candidates = {}
    for decision in ("rf_only", "rf_gbt"):
        s = tree_ensemble_scores(rf_model, gbt_model, X_val[thr_rel], decision)
        thr = threshold_for_fpr(y_val[thr_rel], s, max_fpr)
        candidates[decision] = {"threshold": thr, **_metric_block(y_val[thr_rel], s, thr)}
        print(f"   {decision:8s} threshold={thr:.4f}  val recall={candidates[decision]['recall']:.4f}  "
              f"val FPR={candidates[decision]['fpr']:.4%}  val PR-AUC={candidates[decision]['pr_auc']}")
    # Higher recall at the same budget wins; on a tie the simpler RF-only model is kept.
    decision = "rf_gbt" if candidates["rf_gbt"]["recall"] > candidates["rf_only"]["recall"] else "rf_only"
    threshold = candidates[decision]["threshold"]
    if threshold > 1.0:
        print("   [warn] no threshold meets the false-alarm budget on validation — Path A will never alarm. "
              "Raise training.path_a_max_fpr or add validation data.")
    print(f"[*] Decision gate (validation) → '{decision}'  threshold={threshold:.4f}")

    dv = dataset_hash([input_path], features)
    joblib.dump(rf_model, MODEL_RF)
    joblib.dump(gbt_model, MODEL_GBT)
    joblib.dump(scaler, MODEL_SCALER)
    if bigram is not None:
        bigram.save(MODEL_BIGRAM)
    with open(MODEL_THRESHOLD, "w") as f:
        json.dump({
            "threshold": threshold, "decision": decision, "features": features,
            "fpr_budget": max_fpr, "calibrated": True, "window_seconds": WINDOW_SECONDS,
            "val_recall": candidates[decision]["recall"], "val_fpr": candidates[decision]["fpr"],
            "dataset_version": dv, "split": split_method,
        }, f, indent=2)
    print(f"Saved → {MODEL_RF}, {MODEL_GBT}, {MODEL_SCALER}, {MODEL_THRESHOLD}"
          + (f", {MODEL_BIGRAM}" if bigram is not None else ""))

    # ── STEP 4: HELD-OUT TEST REPORT (first and only use of test) ──
    print("\n── Final Path A evaluation (held-out test set) ───────────────")
    chosen_scores = tree_ensemble_scores(rf_model, gbt_model, X_test, decision)
    chosen = _metric_block(y_test, chosen_scores, threshold)
    preds = (chosen_scores >= threshold).astype(int)
    print(classification_report(y_test, preds, target_names=["benign", "attack"], zero_division=0))
    print(f"PR-AUC: {chosen['pr_auc']}  (baseline={chosen['pr_auc_baseline']:.3f})  | ROC-AUC: {chosen['roc_auc']}  "
          f"| false alarms: {chosen['false_alarms']} / {int((y_test == 0).sum())} benign")
    recall_by_family = _recall_by_family(y_test, preds, fam_test if "attack_family" in df.columns else None)
    for k, v in recall_by_family.items():
        print(f"  - {k}: recall={v['recall']:.3f}  (n={v['support']})")

    trusted_block = None
    n_trusted = int(trusted_test.sum())
    if n_trusted and len(np.unique(y_test[trusted_test])) == 2:
        trusted_block = _metric_block(y_test[trusted_test], chosen_scores[trusted_test], threshold)
        print(f"Trusted-label test rows: {n_trusted}/{len(y_test)}  →  F1={trusted_block['f1']:.4f}")

    shuffle_block = None
    if shuffle_labels:
        print("\n── Label-shuffle check (train on permuted labels) ────────────")
        y_shuf = np.random.default_rng(42).permutation(y_train)
        rf_s = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                      random_state=42, n_jobs=-1).fit(X_train, y_shuf)
        shuffle_block = _metric_block(y_test, rf_s.predict_proba(X_test)[:, 1], 0.5)
        print(f"   Shuffled PR-AUC={shuffle_block['pr_auc']} (baseline≈{shuffle_block['pr_auc_baseline']:.3f})")

    metrics_path = os.path.join(_MODELS_DIR, "evaluation_metrics.json")
    try:
        with open(metrics_path) as f:
            all_metrics = json.load(f)
    except Exception:
        all_metrics = {}
    all_metrics["path_a"] = {
        **chosen,
        "decision": decision,
        "features": features,
        "fpr_budget": max_fpr,
        "calibrated": True,
        "validation_candidates": candidates,     # the gate's inputs — validation only
        "transformer_baseline": transformer_block,
        "shuffle_labels": shuffle_block,
        "recall_by_family": recall_by_family,
        "seed": 42,
        "split": split_method,
        "dataset_version": dv,
        "split_sizes": {"train": int(len(tr_idx)), "val": int(len(val_idx)), "test": int(len(te_idx))},
        "test_rows_with_twin_in_train": test_twin_share,
        "conflicting_vectors": int(n_conflicts),
        "test_support": {"benign": int((y_test == 0).sum()), "attack": int((y_test == 1).sum())},
        "test_trusted_labels": trusted_block,
        "test_trusted_rows": n_trusted,
    }
    with open(metrics_path, "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"[+] Metrics saved → {metrics_path}  (key: path_a)")
    print("\n✅ Path A training complete.")


# ─────────────────────────────────────────────
# INFERENCE PIPELINE
# ─────────────────────────────────────────────

def run_inference(input_path: str, rf_weight=0.5, tf_weight=0.5, output_json: str = None):
    """Score any supported file with the saved Path A; writes CSV and optionally enriched JSON."""
    print("[*] Loading models...")
    df = load_as_dataframe(input_path)
    scores, preds, threshold, decision = score_frame(df)
    print(f"[*] Path A decision: {decision}  |  threshold: {threshold:.4f}")

    result_df = df.copy().reset_index(drop=True)
    result_df["ml_score_A"] = scores
    result_df["ml_label_A"] = preds
    result_df["ml_verdict_A"] = result_df["ml_label_A"].map({1: "ATTACK", 0: "benign"})

    out_csv = f"{Path(input_path).stem}_model_results.csv"
    result_df.to_csv(out_csv, index=False)
    print(f"\n[+] CSV saved → {out_csv}")
    print(f"    Total analyzed : {len(preds)}")
    print(f"    Attack detected: {preds.sum()}")
    print(f"    Benign         : {(preds == 0).sum()}")

    if output_json:
        with open(output_json, "w") as f:
            json.dump(result_df.to_dict(orient="records"), f, indent=2, default=str)
        print(f"[+] Enriched JSON saved → {output_json}")
    return result_df


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DNS Tunnel Detector — Path A: calibrated RF + HistGBT on per-query + behaviour features",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--train", metavar="FILE", help="Labeled file to train on")
    parser.add_argument("--infer", metavar="FILE", help="File to run inference on")
    parser.add_argument("--output-json", metavar="FILE", help="Save inference results as JSON")
    parser.add_argument("--split-manifest", metavar="FILE", default=None,
                        help="Use this shared split (data/processed/splits/*.json) instead of a new one")
    parser.add_argument("--no-transformer", action="store_true",
                        help="Skip the Transformer baseline (faster experiments)")
    parser.add_argument("--rf-weight", type=float, default=0.5, help="(kept for CLI compat)")
    parser.add_argument("--tf-weight", type=float, default=0.5, help="(deprecated)")
    parser.add_argument("--shuffle-labels", action="store_true",
                        help="Also run a label-shuffle/permutation leakage check")
    args = parser.parse_args()

    if args.train:
        run_training(args.train, args.rf_weight, args.tf_weight, shuffle_labels=args.shuffle_labels,
                     split_manifest=args.split_manifest, with_transformer=not args.no_transformer)
    if args.infer:
        run_inference(args.infer, args.rf_weight, args.tf_weight, args.output_json)
    if not args.train and not args.infer:
        parser.print_help()


if __name__ == "__main__":
    main()
