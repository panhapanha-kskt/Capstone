#!/usr/bin/env python3
"""
model.py — Path A: RF + Transformer Ensemble (8-feature classification)
DNS Tunnel Detector — Week 5 ML Layer

Fixes from original:
  - Uses shared dns_parser.py (no duplicated parsers)
  - Transformer is a TRUE BINARY CLASSIFIER (sigmoid + binary_crossentropy)
  - Stratified train/test split to ensure attack samples in both sets
  - Threshold calibration via precision-recall curve
  - Scaler saved/loaded alongside models
  - Inference returns week3-compatible enriched JSON for ml_bridge.py

Usage:
  python model.py --train week3_features_all.json
  python model.py --infer week3_features_all.json
  python model.py --train dns_labeled.csv
  python model.py --infer capture.pcap --rf-weight 0.4 --tf-weight 0.6
"""

import os
import json
import math
import argparse
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from collections import Counter
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, precision_recall_curve, roc_auc_score,
    average_precision_score,
)
from sklearn.preprocessing import StandardScaler
from tensorflow import keras
from tensorflow.keras import layers

# Import shared parser
from dns_detect.parsing.dns_parser import load_as_dataframe, FEATURES_8
from dns_detect.utils.paths import PROJECT_ROOT

SEQUENCE_LENGTH = 10
_MODELS_DIR = str(PROJECT_ROOT / "models")
MODEL_RF   = os.path.join(_MODELS_DIR, "dns_tunnel_rf.pkl")
MODEL_GBT  = os.path.join(_MODELS_DIR, "dns_tunnel_gbt.pkl")      # Path A 2nd learner (research-backed)
MODEL_TF   = os.path.join(_MODELS_DIR, "dns_tunnel_transformer.keras")  # baseline only (not in decision)
MODEL_SCALER = os.path.join(_MODELS_DIR, "dns_scaler.pkl")
MODEL_THRESHOLD = os.path.join(_MODELS_DIR, "dns_threshold.json")


# ─────────────────────────────────────────────
# TRANSFORMER ARCHITECTURE (binary classifier)
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
    """
    Binary classification transformer.
    Output: sigmoid → probability of being tunneling/attack traffic.
    """
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

    # sigmoid for binary classification (NOT regression)
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
# THRESHOLD CALIBRATION
# ─────────────────────────────────────────────

def calibrate_threshold(y_true: np.ndarray, y_scores: np.ndarray) -> float:
    """
    Find optimal classification threshold using F1 from precision-recall curve.
    Returns the threshold that maximises F1 on the validation set.
    """
    precision, recall, thresholds = precision_recall_curve(y_true, y_scores)
    # F1 = 2 * P * R / (P + R), avoid divide-by-zero
    f1_scores = np.where(
        (precision + recall) > 0,
        2 * precision * recall / (precision + recall),
        0.0
    )
    best_idx = np.argmax(f1_scores[:-1])  # thresholds is 1 shorter
    best_threshold = float(thresholds[best_idx])
    best_f1 = float(f1_scores[best_idx])
    print(f"   Calibrated threshold: {best_threshold:.4f}  (F1={best_f1:.4f})")
    return best_threshold


# ─────────────────────────────────────────────
# TRAINING
# ─────────────────────────────────────────────

def train_random_forest(X_train, y_train, X_test, y_test):
    print("\n── Random Forest ──────────────────────────────────────────────")
    rf = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",   # handles imbalanced attack/normal ratio
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    print(classification_report(y_test, rf.predict(X_test),
                                 target_names=["benign", "attack"]))
    joblib.dump(rf, MODEL_RF)
    print(f"Saved → {MODEL_RF}")
    return rf


def train_gradient_boosting(X_train, y_train, X_test, y_test):
    """
    Second tree learner for the Path A ensemble.

    Gradient boosting typically edges out RF on NIDS tabular data and relies on a
    different (more concentrated) subset of features, so soft-voting it with the RF
    is a genuine 'two-opinion' tabular ensemble (see docs/ML_IMPROVEMENTS.md).
    HistGradientBoostingClassifier is sklearn-native (no extra dependency).
    """
    print("\n── Gradient Boosting (HistGradientBoosting) ────────────────────")
    gbt = HistGradientBoostingClassifier(
        learning_rate=0.1,
        max_iter=300,
        early_stopping=True,
        validation_fraction=0.15,
        class_weight="balanced",   # handle attack/benign imbalance
        random_state=42,
    )
    gbt.fit(X_train, y_train)
    print(classification_report(y_test, gbt.predict(X_test),
                                target_names=["benign", "attack"]))
    joblib.dump(gbt, MODEL_GBT)
    print(f"Saved → {MODEL_GBT}")
    return gbt


def tree_ensemble_scores(rf_model, gbt_model, X_flat, decision="rf_gbt"):
    """
    Path A production score = soft-vote of the two tree learners (mean P(attack)),
    or RF alone when the decision gate picked 'rf_only'. Aligned to X_flat length.
    """
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


def train_transformer(X_seq_train, y_seq_train, X_seq_test, y_seq_test):
    print("\n── Transformer (Binary Classifier) ───────────────────────────")
    model = build_transformer(
        input_shape=(SEQUENCE_LENGTH, X_seq_train.shape[2]),
        head_size=32, num_heads=2, ff_dim=64,
        num_transformer_blocks=2, mlp_units=[64],
        dropout=0.1, mlp_dropout=0.1,
    )
    # Binary cross-entropy — correct loss for classification
    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.AUC(name="auc")]
    )
    model.summary()

    model.fit(
        X_seq_train, y_seq_train,
        validation_data=(X_seq_test, y_seq_test),
        epochs=30,
        batch_size=32,
        callbacks=[
            keras.callbacks.EarlyStopping(
                patience=5, restore_best_weights=True, monitor="val_auc", mode="max"
            )
        ],
        verbose=1
    )
    loss, acc, auc = model.evaluate(X_seq_test, y_seq_test, verbose=0)
    print(f"Test accuracy: {acc:.4f}  |  Test loss: {loss:.4f}  |  Test AUC: {auc:.4f}")
    model.save(MODEL_TF)
    print(f"Saved → {MODEL_TF}")
    return model


# ─────────────────────────────────────────────
# ENSEMBLE INFERENCE
# ─────────────────────────────────────────────

def _ensemble_scores(rf_model, tf_model, X_flat, X_seq,
                     rf_weight=0.5, tf_weight=0.5):
    """
    Weighted ensemble probability per sample, aligned to X_flat length.
    The first `pad` samples (which have no full sequence window) fall
    back to the RF score alone.
    """
    rf_probs = rf_model.predict_proba(X_flat)[:, 1]
    tf_probs = tf_model.predict(X_seq, verbose=0).flatten()
    pad = len(rf_probs) - len(tf_probs)
    return np.concatenate([
        rf_probs[:pad],
        rf_weight * rf_probs[pad:] + tf_weight * tf_probs
    ])


def ensemble_predict(rf_model, tf_model, X_flat, X_seq,
                     threshold=0.5, rf_weight=0.5, tf_weight=0.5):
    """
    Weighted ensemble of RF + Transformer probabilities.
    Both models output P(attack). Combined score >= threshold → attack.
    """
    combined = _ensemble_scores(rf_model, tf_model, X_flat, X_seq,
                                rf_weight, tf_weight)
    predictions = (combined >= threshold).astype(int)
    return predictions, combined


def load_threshold() -> float:
    """Load calibrated threshold from disk, default 0.5 if not found."""
    if os.path.exists(MODEL_THRESHOLD):
        with open(MODEL_THRESHOLD) as f:
            data = json.load(f)
        return float(data.get("threshold", 0.5))
    return 0.5


def load_threshold_and_decision():
    """Load (threshold, decision) where decision ∈ {'rf_gbt','rf_only'}."""
    if os.path.exists(MODEL_THRESHOLD):
        with open(MODEL_THRESHOLD) as f:
            data = json.load(f)
        return float(data.get("threshold", 0.5)), str(data.get("decision", "rf_gbt"))
    return 0.5, "rf_gbt"


# ─────────────────────────────────────────────
# FULL TRAINING PIPELINE
# ─────────────────────────────────────────────

def _metric_block(y_true, scores, threshold):
    """Threshold-dependent + threshold-free metrics for a score vector."""
    from sklearn.metrics import precision_score, recall_score, f1_score
    preds = (scores >= threshold).astype(int)
    prevalence = float((y_true == 1).mean())
    try:
        roc = float(roc_auc_score(y_true, scores))
    except Exception:
        roc = None
    try:
        pr = float(average_precision_score(y_true, scores))  # PR-AUC
    except Exception:
        pr = None
    return {
        "precision": float(precision_score(y_true, preds, zero_division=0)),
        "recall":    float(recall_score(y_true, preds, zero_division=0)),
        "f1":        float(f1_score(y_true, preds, zero_division=0)),
        "pr_auc":    pr,                 # PRIMARY for imbalanced data (Saito & Rehmsmeier)
        "pr_auc_baseline": prevalence,   # random PR-AUC = class prevalence
        "roc_auc":   roc,                # secondary
        "threshold": float(threshold),
    }


def _recall_by_family(y_true, preds, families):
    """Per-attack-family recall on the test set (families aligned to rows)."""
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


def run_training(input_path: str, rf_weight=0.5, tf_weight=0.5, shuffle_labels=False):
    print(f"\n[*] Loading training data: {input_path}")
    df = load_as_dataframe(input_path)

    # Fill any missing feature columns
    for col in FEATURES_8:
        if col not in df.columns:
            df[col] = 0

    if "label" not in df.columns:
        raise ValueError(
            "Training data must have a 'label' column (0=benign, 1=attack). "
            "For Week 3 data, run ml_bridge.py first to generate labels from attack_count."
        )

    print(f"[*] Dataset: {len(df)} records  |  "
          f"Benign: {(df['label']==0).sum()}  |  "
          f"Attack: {(df['label']==1).sum()}")

    X = df[FEATURES_8].values
    y = df["label"].values
    # attack_family (from ground-truth manifest labeling) for per-family recall
    fam = df["attack_family"].values if "attack_family" in df.columns else np.array(["?"] * len(df))

    # ── STEP 1: SPLIT BEFORE SCALING (prevents data leakage) ──────
    # 3-way stratified split: 70% train / 15% validation / 15% test.
    X_train_raw, X_tmp_raw, y_train, y_tmp, _fam_tr, fam_tmp = train_test_split(
        X, y, fam, test_size=0.30, random_state=42, stratify=y
    )
    X_val_raw, X_test_raw, y_val, y_test, _fam_val, fam_test = train_test_split(
        X_tmp_raw, y_tmp, fam_tmp, test_size=0.50, random_state=42, stratify=y_tmp
    )
    print(f"[*] Split → train={len(X_train_raw)}  val={len(X_val_raw)}  test={len(X_test_raw)}")

    # ── STEP 2: FIT SCALER ON TRAINING DATA ONLY ──────────────────
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_val   = scaler.transform(X_val_raw)
    X_test  = scaler.transform(X_test_raw)
    joblib.dump(scaler, MODEL_SCALER)
    print(f"Saved → {MODEL_SCALER}  (fit on training data only)")

    # ── STEP 3: TRAIN PRODUCTION LEARNERS (two trees) ─────────────
    # Research: trees beat deep nets on small tabular data; RF + gradient
    # boosting rely on features differently → a real two-opinion ensemble.
    rf_model  = train_random_forest(X_train, y_train, X_test, y_test)
    gbt_model = train_gradient_boosting(X_train, y_train, X_test, y_test)

    # ── STEP 4: TRANSFORMER (BASELINE ONLY — excluded from decision) ──
    # Kept + reported for the paper ("explored, underperformed on tabular data").
    X_seq_tr, y_seq_tr   = build_sequences(X_train, y_train, SEQUENCE_LENGTH)
    X_seq_val, y_seq_val = build_sequences(X_val, y_val, SEQUENCE_LENGTH)
    X_seq_te, y_seq_te   = build_sequences(X_test, y_test, SEQUENCE_LENGTH)
    tf_model = train_transformer(X_seq_tr, y_seq_tr, X_seq_val, y_seq_val)

    # ── STEP 5: CALIBRATE + GATE (RF-only vs RF+GBT) ──────────────
    # Calibrate each candidate's threshold on validation, then keep the
    # combo ONLY if it beats RF-alone on the held-out test (plan's gate).
    print("\n── Calibrating thresholds (validation set) ───────────────────")
    val_rf  = tree_ensemble_scores(rf_model, None, X_val, "rf_only")
    thr_rf  = calibrate_threshold(y_val, val_rf)
    val_cmb = tree_ensemble_scores(rf_model, gbt_model, X_val, "rf_gbt")
    thr_cmb = calibrate_threshold(y_val, val_cmb)

    test_rf  = tree_ensemble_scores(rf_model, None, X_test, "rf_only")
    test_cmb = tree_ensemble_scores(rf_model, gbt_model, X_test, "rf_gbt")
    block_rf  = _metric_block(y_test, test_rf, thr_rf)
    block_cmb = _metric_block(y_test, test_cmb, thr_cmb)

    if block_cmb["f1"] >= block_rf["f1"]:
        decision, threshold, chosen, chosen_scores = "rf_gbt", thr_cmb, block_cmb, test_cmb
    else:
        decision, threshold, chosen, chosen_scores = "rf_only", thr_rf, block_rf, test_rf
    print(f"\n[*] Decision gate → '{decision}' "
          f"(RF+GBT F1={block_cmb['f1']:.4f} vs RF-only F1={block_rf['f1']:.4f})")

    with open(MODEL_THRESHOLD, "w") as f:
        json.dump({"threshold": threshold, "decision": decision}, f)
    print(f"Saved → {MODEL_THRESHOLD}  (decision: {decision})")

    # ── STEP 6: HELD-OUT TEST REPORT (the numbers for the paper) ──
    print("\n── Final Path A Evaluation (held-out test set) ───────────────")
    preds = (chosen_scores >= threshold).astype(int)
    print(classification_report(y_test, preds, target_names=["benign", "attack"]))
    print(f"PR-AUC (primary): {chosen['pr_auc']}  (baseline={chosen['pr_auc_baseline']:.3f})  "
          f"| ROC-AUC: {chosen['roc_auc']}")
    recall_by_family = _recall_by_family(y_test, preds, fam_test)
    if recall_by_family:
        print("Per-attack-family recall:")
        for k, v in recall_by_family.items():
            print(f"  - {k}: recall={v['recall']:.3f}  (n={v['support']})")

    # Transformer baseline metrics (not used in the decision)
    try:
        tf_scores = tf_model.predict(X_seq_te, verbose=0).flatten()
        tf_block = _metric_block(y_seq_te, tf_scores, 0.5)
    except Exception:
        tf_block = None

    # ── STEP 7: OPTIONAL LABEL-SHUFFLE / PERMUTATION CHECK ────────
    # Honest note: this catches PIPELINE leakage/overfitting, NOT circular
    # labeling (labels-from-features is a real dependency). See docs/ML_IMPROVEMENTS.md.
    shuffle_block = None
    if shuffle_labels:
        print("\n── Label-shuffle check (train on permuted labels) ────────────")
        rng = np.random.default_rng(42)
        y_shuf = rng.permutation(y_train)
        rf_s = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                      random_state=42, n_jobs=-1).fit(X_train, y_shuf)
        gbt_s = HistGradientBoostingClassifier(max_iter=300, class_weight="balanced",
                                               random_state=42).fit(X_train, y_shuf)
        s_scores = tree_ensemble_scores(rf_s, gbt_s, X_test, decision)
        shuffle_block = _metric_block(y_test, s_scores, 0.5)
        print(f"   Shuffled PR-AUC={shuffle_block['pr_auc']} (baseline≈{shuffle_block['pr_auc_baseline']:.3f}), "
              f"ROC-AUC={shuffle_block['roc_auc']} → should collapse toward chance if leak-free")

    # ── PERSIST METRICS (single source of truth for the paper) ────
    metrics_path = os.path.join(_MODELS_DIR, "evaluation_metrics.json")
    try:
        with open(metrics_path) as f:
            all_metrics = json.load(f)
    except Exception:
        all_metrics = {}
    all_metrics["path_a"] = {
        **chosen,                        # chosen decision's metrics (precision/recall/f1/pr_auc/roc_auc/threshold)
        "decision": decision,
        "candidates": {"rf_only": block_rf, "rf_gbt": block_cmb},
        "transformer_baseline": tf_block,   # reported, NOT in the decision
        "shuffle_labels": shuffle_block,
        "recall_by_family": recall_by_family,
        "seed": 42,
        "split_sizes": {"train": int(len(X_train)), "val": int(len(X_val)), "test": int(len(X_test))},
        "test_support": {"benign": int((y_test == 0).sum()), "attack": int((y_test == 1).sum())},
    }
    with open(metrics_path, "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"[+] Metrics saved → {metrics_path}  (key: path_a)")

    print("\n✅ Training complete. Artifacts saved:")
    print(f"   {MODEL_RF}  |  {MODEL_GBT}  |  {MODEL_TF} (baseline)  |  {MODEL_SCALER}  |  {MODEL_THRESHOLD}")


# ─────────────────────────────────────────────
# INFERENCE PIPELINE
# ─────────────────────────────────────────────

def run_inference(input_path: str, rf_weight=0.5, tf_weight=0.5,
                  output_json: str = None):
    """
    Load any supported file, run ensemble inference.
    Saves results to CSV and optionally enriched JSON (for ml_bridge.py).
    """
    print(f"[*] Loading models...")
    rf_model, gbt_model, scaler, threshold, decision = load_path_a_models()
    print(f"[*] Path A decision: {decision}  |  threshold: {threshold:.4f}")

    df = load_as_dataframe(input_path)
    for col in FEATURES_8:
        if col not in df.columns:
            df[col] = 0

    X_scaled = scaler.transform(df[FEATURES_8].values)

    scores = tree_ensemble_scores(rf_model, gbt_model, X_scaled, decision)
    preds  = (scores >= threshold).astype(int)

    result_df = df.copy().reset_index(drop=True)
    result_df["ml_score_A"]   = scores
    result_df["ml_label_A"]   = preds
    result_df["ml_verdict_A"] = result_df["ml_label_A"].map({1: "ATTACK", 0: "benign"})

    # Save CSV
    stem     = Path(input_path).stem
    out_csv  = f"{stem}_model_results.csv"
    result_df.to_csv(out_csv, index=False)
    print(f"\n[+] CSV saved → {out_csv}")
    print(f"    Total analyzed : {len(preds)}")
    print(f"    Attack detected: {preds.sum()}")
    print(f"    Benign         : {(preds == 0).sum()}")

    # Save enriched JSON for ml_bridge.py consumption
    if output_json:
        records = result_df.to_dict(orient="records")
        with open(output_json, "w") as f:
            json.dump(records, f, indent=2, default=str)
        print(f"[+] Enriched JSON saved → {output_json}")

    return result_df


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DNS Tunnel Detector — Path A: RF + Transformer Ensemble (8 features)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Train on Week 3 labeled JSON (after running ml_bridge.py --label-only)
  python model.py --train week3_features_labeled.json

  # Train on classic labeled CSV
  python model.py --train dns_labeled.csv

  # Infer on Week 3 features
  python model.py --infer week3_features_all.json --output-json week3_with_ml_A.json

  # Infer on PCAP
  python model.py --infer capture.pcap

  # Infer with custom ensemble weights
  python model.py --infer traffic.json --rf-weight 0.4 --tf-weight 0.6
        """
    )
    parser.add_argument("--train",      metavar="FILE",  help="Labeled file to train both models")
    parser.add_argument("--infer",      metavar="FILE",  help="File to run inference on")
    parser.add_argument("--output-json",metavar="FILE",  help="Save inference results as JSON (for ml_bridge.py)")
    parser.add_argument("--rf-weight",  type=float, default=0.5, help="(kept for CLI compat; RF+GBT soft-vote is 50/50)")
    parser.add_argument("--tf-weight",  type=float, default=0.5, help="(deprecated; Transformer is a baseline, not in the decision)")
    parser.add_argument("--shuffle-labels", action="store_true",
                        help="Also run a label-shuffle/permutation leakage check (Tier 3)")
    args = parser.parse_args()

    if args.train:
        run_training(args.train, args.rf_weight, args.tf_weight,
                     shuffle_labels=args.shuffle_labels)

    if args.infer:
        run_inference(args.infer, args.rf_weight, args.tf_weight, args.output_json)

    if not args.train and not args.infer:
        parser.print_help()


if __name__ == "__main__":
    main()
