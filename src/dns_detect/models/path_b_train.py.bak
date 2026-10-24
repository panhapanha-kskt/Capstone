#!/usr/bin/env python3
"""
train.py — Path B: Trafficformer (multi-feature, per-client sequence autoencoder)
DNS Anomaly Detector — Week 5 ML Layer

Design (research-backed — see docs/ML_IMPROVEMENTS.md):
  - Input is a MULTI-FEATURE vector per query (PATH_B_FEATURES), not just query
    length (Kitsune reconstructs multi-dimensional vectors; Nadler's tunneling
    features combine length, entropy and label structure).
  - Windows are built WITHIN each client's time-ordered stream, so a window is a
    real temporal sequence and never mixes hosts.
  - Trained on BENIGN windows only (the autoencoder learns "normal").
  - Anomaly threshold = 99th PERCENTILE of benign-validation reconstruction error
    (robust to skewed error distributions); mean + k·σ kept as a fallback method.

Usage:
  python -m dns_detect.models.path_b_train --filename merged_features_labeled.json \
      --n_days 20 --save_name dns_trafficformer --data_dir data/processed
"""

import os

os.environ["CUDA_DEVICE_ORDER"]    = "PCI_BUS_ID"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"

import json
import argparse
import numpy as np
import tensorflow as tf
from pathlib import Path

from dns_detect.parsing.dns_parser import load_multifeature_with_meta, PATH_B_FEATURES
from dns_detect.models.path_a import transformer_encoder
from dns_detect.models.path_b_predict import (
    build_client_windows, normalize_features, compute_reconstruction_errors,
)
from dns_detect.utils.paths import PROJECT_ROOT


def _default_percentile() -> float:
    """Threshold percentile from config/settings.yaml (training.path_b_threshold_percentile)."""
    try:
        from dns_detect.config import settings
        return float(getattr(settings.training, "path_b_threshold_percentile", 99.0))
    except Exception:
        return 99.0


# ─────────────────────────────────────────────
# MODEL ARCHITECTURE
# ─────────────────────────────────────────────

def build_trafficformer(input_shape, head_size=64, num_heads=3,
                         ff_dim=3, num_transformer_blocks=3,
                         mlp_units=None, mlp_dropout=0.4, dropout=0.25):
    """
    Trafficformer: sequence reconstruction model over (window, F) inputs.
    Output has the same shape as the input; loss = MSE on the reconstruction.
    High reconstruction error = traffic unlike learned-normal = anomaly.
    """
    if mlp_units is None:
        mlp_units = [64]

    from tensorflow.keras import layers, Input, Model

    inputs = Input(shape=input_shape)  # (window_size, F)
    x = inputs
    for _ in range(num_transformer_blocks):
        x = transformer_encoder(x, head_size, num_heads, ff_dim, dropout)

    for dim in mlp_units:
        x = layers.Dense(dim, activation="relu")(x)
        x = layers.Dropout(mlp_dropout)(x)

    n_features = input_shape[-1]
    outputs = layers.Dense(n_features, activation="linear")(x)   # (window_size, F)
    return Model(inputs, outputs, name="trafficformer_reconstruction")


# ─────────────────────────────────────────────
# THRESHOLD + METRICS
# ─────────────────────────────────────────────

def compute_threshold(errors: np.ndarray, method: str = "percentile",
                      percentile: float = 99.0, multiplier: float = 2.5):
    """
    Anomaly threshold from benign-validation reconstruction errors.
      percentile (default): the p-th percentile of benign error — robust to skew.
      mean_std (fallback) : mean + multiplier·std (assumes ~normal errors).
    """
    mean, std = float(np.mean(errors)), float(np.std(errors))
    if method == "mean_std":
        thr = mean + multiplier * std
        label = f"mean_std_{multiplier}"
    else:
        thr = float(np.percentile(errors, percentile))
        label = f"percentile_{percentile:g}"
    print(f"   Error stats → mean={mean:.4f}  std={std:.4f}")
    print(f"   Anomaly threshold: {thr:.4f}  ({label})")
    return thr, label, mean, std


def save_metrics_block(key: str, block: dict):
    """Merge a metrics block into models/evaluation_metrics.json."""
    metrics_path = os.path.join(str(PROJECT_ROOT / "models"), "evaluation_metrics.json")
    try:
        with open(metrics_path) as f:
            all_metrics = json.load(f)
    except Exception:
        all_metrics = {}
    all_metrics[key] = block
    with open(metrics_path, "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"[+] Metrics saved → {metrics_path}  (key: {key})")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Trafficformer Trainer (Path B — multi-feature, per-client sequence autoencoder)",
    )
    parser.add_argument("--filename",   type=str, required=True,
                        help="Labeled features JSON (records with timestamp + client_ip)")
    parser.add_argument("--n_days",     type=int, required=True,
                        help="Window size (records per window)")
    parser.add_argument("--save_name",  type=str, required=True,
                        help="Model save name (saved to models/<save_name>.h5)")
    parser.add_argument("--data_dir",   type=str, default="data",
                        help="Data directory (default: data/)")
    parser.add_argument("--threshold-method", choices=["percentile", "mean_std"],
                        default="percentile", help="Anomaly threshold method (default: percentile)")
    parser.add_argument("--percentile", type=float, default=_default_percentile(),
                        help="Benign-error percentile for the threshold (default: 99)")
    parser.add_argument("--multiplier", type=float, default=2.5,
                        help="k for the mean+k·std fallback method (default: 2.5)")
    args = parser.parse_args()

    DATA_PATH = Path(args.data_dir) / args.filename
    SAVE_NAME = args.save_name
    N_DAYS    = args.n_days

    X, labels, client_ip, order = load_multifeature_with_meta(str(DATA_PATH))
    F = X.shape[1]
    print(f"[*] Loaded {len(X)} records × {F} features from {DATA_PATH}  "
          f"(attacks={int((labels == 1).sum())}, benign={int((labels == 0).sum())}, "
          f"clients={len(set(client_ip))})")
    print(f"[*] Path B features: {', '.join(PATH_B_FEATURES)}")

    # ── CHRONOLOGICAL 3-WAY SPLIT (by time, before normalization) ──
    # Sort globally by time, split 70/15/15 by position; windows are then built
    # per client INSIDE each split, so none crosses a split or host boundary.
    t_order = np.argsort(order, kind="stable")
    X, labels, client_ip, order = X[t_order], labels[t_order], client_ip[t_order], order[t_order]
    n = len(X)
    tr_end, val_end = int(n * 0.70), int(n * 0.85)
    splits = {
        "train": slice(0, tr_end),
        "val":   slice(tr_end, val_end),
        "test":  slice(val_end, n),
    }
    print(f"[*] Chronological split → train={tr_end}  val={val_end - tr_end}  test={n - val_end}")

    # Per-feature normalization from TRAIN rows only
    X_tr = X[splits["train"]]
    f_min = X_tr.min(axis=0)
    f_rng = X_tr.max(axis=0) - f_min
    f_rng = np.where(f_rng > 0, f_rng, 1.0)
    norm = {"min": f_min.astype(np.float32), "range": f_rng.astype(np.float32)}
    Xn = normalize_features(X, norm)

    _models_dir = str(PROJECT_ROOT / "models")
    os.makedirs(_models_dir, exist_ok=True)
    norm_path = os.path.join(_models_dir, f"{SAVE_NAME}_norm.json")
    with open(norm_path, "w") as f:
        json.dump({"features": PATH_B_FEATURES,
                   "min": norm["min"].tolist(),
                   "range": norm["range"].tolist()}, f, indent=2)
    print(f"[*] Per-feature normalization saved → {norm_path}  (train-derived)")

    win = {}
    for name, sl in splits.items():
        win[name] = build_client_windows(Xn[sl], client_ip[sl], order[sl], N_DAYS, labels[sl])
    x_train, _, yw_train = win["train"]
    x_valid, _, yw_valid = win["val"]
    x_test,  _, yw_test  = win["test"]
    print(f"[*] Per-client windows → train={len(x_train)}  val={len(x_valid)}  test={len(x_test)}")
    if len(x_train) == 0 or len(x_valid) == 0:
        raise SystemExit("[!] Not enough per-client records to build windows "
                         f"(window={N_DAYS}). Add more traffic or lower --n_days.")

    # ── BENIGN-ONLY TRAINING (autoencoder learns "normal") ────────
    MIN_BENIGN = 10
    x_train_ben = x_train[yw_train == 0]
    x_valid_ben = x_valid[yw_valid == 0]
    if len(x_train_ben) < MIN_BENIGN:
        print(f"[!] Only {len(x_train_ben)} benign train windows — falling back to ALL "
              f"train windows (capture benign-only traffic to fix this)")
        x_train_ben = x_train
    else:
        print(f"[*] Benign-only training windows: {len(x_train_ben)} "
              f"(dropped {len(x_train) - len(x_train_ben)} attack windows)")
    if len(x_valid_ben) < MIN_BENIGN:
        print(f"[!] Only {len(x_valid_ben)} benign val windows — calibrating threshold "
              f"on ALL val windows (threshold less trustworthy)")
        x_valid_ben = x_valid

    model = build_trafficformer(
        input_shape=[N_DAYS, F],
        head_size=64, num_heads=3, ff_dim=3,
        num_transformer_blocks=3,
        mlp_units=[64], mlp_dropout=0.4, dropout=0.25,
    )
    model.compile(loss="mean_squared_error",
                  optimizer=tf.keras.optimizers.Adam(learning_rate=1e-4))
    model.summary()

    early_stop = tf.keras.callbacks.EarlyStopping(
        monitor="val_loss", patience=10, restore_best_weights=True
    )
    checkpoint = tf.keras.callbacks.ModelCheckpoint(
        os.path.join(_models_dir, f"{SAVE_NAME}.h5"),
        monitor="val_loss", verbose=1, save_best_only=True, mode="min",
    )
    model.fit(
        x_train_ben, x_train_ben,   # reconstruction: target = input
        epochs=200, batch_size=32,
        validation_data=(x_valid_ben, x_valid_ben),
        callbacks=[early_stop, checkpoint],
    )
    print(f"\n[+] Model saved → {_models_dir}/{SAVE_NAME}.h5")

    # ── THRESHOLD ON BENIGN VALIDATION ERRORS ─────────────────────
    print("\n── Calibrating Anomaly Threshold (benign val) ────────────────")
    val_errors = compute_reconstruction_errors(model, x_valid_ben)
    threshold, method, err_mean, err_std = compute_threshold(
        val_errors, args.threshold_method, args.percentile, args.multiplier
    )
    threshold_path = os.path.join(_models_dir, f"{SAVE_NAME}_threshold.json")
    with open(threshold_path, "w") as f:
        json.dump({
            "threshold":   threshold,
            "method":      method,
            "window_size": N_DAYS,
            "n_features":  F,
            "error_mean":  err_mean,
            "error_std":   err_std,
        }, f, indent=2)
    print(f"[+] Threshold saved → {threshold_path}")

    # ── FINAL EVALUATION ON HELD-OUT MIXED TEST SET ───────────────
    print("\n── Final Evaluation (held-out test set) ──────────────────────")
    if len(x_test) > 0 and len(np.unique(yw_test)) > 1:
        from sklearn.metrics import (
            precision_score, recall_score, f1_score, roc_auc_score,
            average_precision_score, classification_report,
        )
        test_errors = compute_reconstruction_errors(model, x_test)
        test_pred   = (test_errors > threshold).astype(int)
        print(classification_report(yw_test, test_pred, target_names=["benign", "attack"],
                                    zero_division=0))
        try:
            roc_auc = float(roc_auc_score(yw_test, test_errors))
        except Exception:
            roc_auc = None
        try:
            pr_auc = float(average_precision_score(yw_test, test_errors))
        except Exception:
            pr_auc = None
        prevalence = float((yw_test == 1).mean())
        print(f"Path B PR-AUC (primary): {pr_auc}  (baseline={prevalence:.3f})  | ROC-AUC: {roc_auc}")

        save_metrics_block("path_b", {
            "precision": float(precision_score(yw_test, test_pred, zero_division=0)),
            "recall":    float(recall_score(yw_test, test_pred, zero_division=0)),
            "f1":        float(f1_score(yw_test, test_pred, zero_division=0)),
            "pr_auc":    pr_auc,
            "pr_auc_baseline": prevalence,
            "roc_auc":   roc_auc,
            "threshold": threshold,
            "threshold_method": method,
            "window_size": N_DAYS,
            "features":  PATH_B_FEATURES,
            "split_sizes": {
                "train_windows": int(len(x_train)),
                "val_windows":   int(len(x_valid)),
                "test_windows":  int(len(x_test)),
                "benign_train_windows": int(len(x_train_ben)),
            },
            "test_support": {
                "benign": int((yw_test == 0).sum()),
                "attack": int((yw_test == 1).sum()),
            },
        })
    else:
        print("[!] Test set has a single class (or is empty) — classification metrics "
              "skipped. Need mixed benign+attack data for meaningful Path B metrics.")

    print("\n✅ Training complete.")
    print("   Detects anomalies via RECONSTRUCTION ERROR on multi-feature, per-client windows.")
