#!/usr/bin/env python3
"""
train.py — Path B: Trafficformer (query-length time-series)
DNS Anomaly Detector — Week 5 ML Layer

KEY FIX from original:
  - Original trained a REGRESSION model (MSE loss, predicting next length)
    but predict.py used int(pred) as a binary label → conceptual mismatch.
  - This version is now a proper SEQUENCE ANOMALY DETECTOR:
      * Trains an autoencoder-style reconstruction model (still MSE on sequences)
      * Anomaly score = reconstruction error (high error = anomaly)
      * predict.py compares reconstruction error to a calibrated threshold
      * No more int(0.0003) → 0 and int(0.9) → 0 being treated the same
  - Uses shared dns_parser.py — no duplicated parsers

Usage:
  python Train.py --filename week3_features_all.json --n_days 20 --save_name dns_trafficformer
  python Train.py --filename example.traff --n_days 20 --save_name my_model
  python Train.py --filename capture.pcap  --n_days 20 --save_name pcap_model
"""

import os

os.environ["CUDA_DEVICE_ORDER"]    = "PCI_BUS_ID"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"

import json
import argparse
import numpy as np
import tensorflow as tf
from pathlib import Path

from dns_detect.parsing.dns_parser import load_values_and_labels
from dns_detect.models.path_a import transformer_encoder
from dns_detect.utils.paths import PROJECT_ROOT


# ─────────────────────────────────────────────
# MODEL ARCHITECTURE
# ─────────────────────────────────────────────

def build_trafficformer(input_shape, head_size=64, num_heads=3,
                         ff_dim=3, num_transformer_blocks=3,
                         mlp_units=None, mlp_dropout=0.4, dropout=0.25):
    """
    Trafficformer: sequence reconstruction model.

    Architecture:
      Input  → Transformer blocks → Dense reconstruction of input sequence
    Loss:
      Mean Squared Error on the RECONSTRUCTED sequence.

    Anomaly detection logic (in Predict.py):
      reconstruction_error = MSE(original_window, reconstructed_window)
      If error > threshold → ANOMALY (potential tunneling)

    This is correct: the model learns what NORMAL traffic looks like.
    Unusual traffic (tunneling) will have HIGH reconstruction error.
    """
    if mlp_units is None:
        mlp_units = [64]

    from tensorflow.keras import layers, Input, Model

    inputs = Input(shape=input_shape)  # (window_size, 1)
    x = inputs

    for _ in range(num_transformer_blocks):
        x = transformer_encoder(x, head_size, num_heads, ff_dim, dropout)

    # MLP head
    for dim in mlp_units:
        x = layers.Dense(dim, activation="relu")(x)
        x = layers.Dropout(mlp_dropout)(x)

    # Reconstruction output: same shape as input
    outputs = layers.Dense(1, activation="linear")(x)   # (window_size, 1)

    return Model(inputs, outputs, name="trafficformer_reconstruction")


# ─────────────────────────────────────────────
# DATASET BUILDER
# ─────────────────────────────────────────────

def make_dataset(data: np.ndarray, window_size: int = 20):
    """
    Build overlapping windows from the time series.
    Input → target is the SAME window (reconstruction task).
    Both X and y are the same window — model learns to reconstruct normal traffic.
    """
    windows = []
    for i in range(len(data) - window_size + 1):
        windows.append(data[i: i + window_size])
    windows = np.array(windows, dtype=np.float32)
    X = windows.reshape(-1, window_size, 1)
    y = X.copy()  # reconstruction: target = input
    return X, y


def compute_threshold_from_errors(errors: np.ndarray,
                                   multiplier: float = 2.5) -> float:
    """
    Compute anomaly threshold from reconstruction errors on normal traffic.
    threshold = mean + multiplier * std
    multiplier=2.5 means ~99% of normal traffic is below the threshold.
    """
    mean = float(np.mean(errors))
    std  = float(np.std(errors))
    threshold = mean + multiplier * std
    print(f"   Error stats → mean={mean:.4f}  std={std:.4f}")
    print(f"   Anomaly threshold: {threshold:.4f}  (mean + {multiplier}×std)")
    return threshold


def make_labeled_windows(values: np.ndarray, labels: np.ndarray,
                         window_size: int):
    """
    Build overlapping reconstruction windows plus a per-window label.
    A window is labelled attack (1) if ANY point inside it is an attack,
    else benign (0). Returns (X, y_window) where X has shape
    (n_windows, window_size, 1).
    """
    X, y_win = [], []
    for i in range(len(values) - window_size + 1):
        X.append(values[i: i + window_size])
        y_win.append(int(labels[i: i + window_size].max()) if window_size else 0)
    X = np.array(X, dtype=np.float32).reshape(-1, window_size, 1)
    y_win = np.array(y_win, dtype=int)
    return X, y_win


def save_metrics_block(key: str, block: dict):
    """Merge a metrics block into models/evaluation_metrics.json."""
    metrics_path = os.path.join(str(PROJECT_ROOT / "models"),
                                "evaluation_metrics.json")
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
        description="Trafficformer Trainer (Path B — sequence reconstruction anomaly detector)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python Train.py --filename week3_features_all.json --n_days 20 --save_name dns_trafficformer
  python Train.py --filename example.traff  --n_days 20 --save_name my_model
  python Train.py --filename capture.pcap   --n_days 20 --save_name pcap_model
  python Train.py --filename dns.log        --n_days 20 --save_name zeek_model
  python Train.py --filename traffic.json   --n_days 20 --save_name json_model
        """
    )
    parser.add_argument("--filename",   type=str, default="example.traff",
                        help="Input file (.traff / .pcap / .json / .log)")
    parser.add_argument("--n_days",     type=int, required=True,
                        help="Window size (timesteps)")
    parser.add_argument("--save_name",  type=str, required=True,
                        help="Model save name (saved to models/<save_name>.h5)")
    parser.add_argument("--data_dir",   type=str, default="data",
                        help="Data directory (default: data/)")
    parser.add_argument("--multiplier", type=float, default=2.5,
                        help="Threshold = mean + multiplier*std (default: 2.5)")
    args = parser.parse_args()

    DATA_PATH = Path(args.data_dir) / args.filename
    SAVE_NAME = args.save_name
    N_DAYS    = args.n_days

    # Load values AND aligned labels (labels drive benign-only training
    # and the final test metrics).
    data, labels = load_values_and_labels(str(DATA_PATH))
    print(f"[*] Loaded {len(data)} data points from {DATA_PATH}  "
          f"(attacks={int((labels == 1).sum())}, benign={int((labels == 0).sum())})")

    # ── CHRONOLOGICAL 3-WAY SPLIT BEFORE NORMALIZATION ────────────
    # This is a time series, so split by time (70% train / 15% val /
    # 15% test) rather than shuffling. Normalization params come from the
    # TRAIN portion only — the model must not peek at later ranges, or
    # reconstruction error on them is optimistically low.
    n          = len(data)
    tr_end     = int(n * 0.70)
    val_end    = int(n * 0.85)
    train_raw  = data[:tr_end].astype(np.float32)
    valid_raw  = data[tr_end:val_end].astype(np.float32)
    test_raw   = data[val_end:].astype(np.float32)
    train_lab  = labels[:tr_end]
    valid_lab  = labels[tr_end:val_end]
    test_lab   = labels[val_end:]
    print(f"[*] Chronological split → train={len(train_raw)}  "
          f"val={len(valid_raw)}  test={len(test_raw)}")

    data_min   = float(train_raw.min())
    data_max   = float(train_raw.max())
    data_range = data_max - data_min if data_max > data_min else 1.0

    train_norm = (train_raw - data_min) / data_range
    valid_norm = (valid_raw - data_min) / data_range
    test_norm  = (test_raw  - data_min) / data_range

    # Save normalization params alongside model (train-derived)
    _models_dir = str(PROJECT_ROOT / "models")
    os.makedirs(_models_dir, exist_ok=True)
    norm_path = os.path.join(_models_dir, f"{SAVE_NAME}_norm.json")
    with open(norm_path, "w") as f:
        json.dump({"min": data_min, "max": data_max, "range": data_range}, f)
    print(f"[*] Normalization params saved → {norm_path}  (train-derived)")

    # Build labelled reconstruction windows within each split (no window
    # crosses a split boundary).
    x_train, yw_train = make_labeled_windows(train_norm, train_lab, N_DAYS)
    x_valid, yw_valid = make_labeled_windows(valid_norm, valid_lab, N_DAYS)
    x_test,  yw_test  = make_labeled_windows(test_norm,  test_lab,  N_DAYS)
    print(f"[*] Windows → train={len(x_train)}  val={len(x_valid)}  test={len(x_test)}")

    # ── BENIGN-ONLY TRAINING (autoencoder best practice) ──────────
    # The autoencoder should learn what NORMAL traffic looks like, so it
    # trains on benign windows only. Falls back to all windows if a split
    # has too few benign samples (tiny lab datasets).
    MIN_BENIGN = 10
    x_train_ben = x_train[yw_train == 0]
    x_valid_ben = x_valid[yw_valid == 0]
    if len(x_train_ben) < MIN_BENIGN:
        print(f"[!] Only {len(x_train_ben)} benign train windows — "
              f"falling back to ALL train windows")
        x_train_ben = x_train
    else:
        print(f"[*] Benign-only training windows: {len(x_train_ben)} "
              f"(dropped {len(x_train) - len(x_train_ben)} attack windows)")
    if len(x_valid_ben) < MIN_BENIGN:
        print(f"[!] Only {len(x_valid_ben)} benign val windows — "
              f"calibrating threshold on ALL val windows")
        x_valid_ben = x_valid

    # Build and compile the reconstruction model
    model = build_trafficformer(
        input_shape=[N_DAYS, 1],
        head_size=64, num_heads=3, ff_dim=3,
        num_transformer_blocks=3,
        mlp_units=[64], mlp_dropout=0.4, dropout=0.25,
    )
    model.compile(
        loss="mean_squared_error",
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-4),
    )
    model.summary()

    early_stop = tf.keras.callbacks.EarlyStopping(
        monitor="val_loss", patience=10, restore_best_weights=True
    )
    checkpoint = tf.keras.callbacks.ModelCheckpoint(
        os.path.join(_models_dir, f"{SAVE_NAME}.h5"),
        monitor="val_loss", verbose=1, save_best_only=True, mode="min",
    )

    history = model.fit(
        x_train_ben, x_train_ben,   # reconstruction: target = input
        epochs=200,
        batch_size=32,
        validation_data=(x_valid_ben, x_valid_ben),
        callbacks=[early_stop, checkpoint],
    )
    print(f"\n[+] Model saved → {_models_dir}/{SAVE_NAME}.h5")

    # Calibrate anomaly threshold on benign val reconstruction errors
    print("\n── Calibrating Anomaly Threshold (benign val) ────────────────")
    val_recon  = model.predict(x_valid_ben, verbose=0)
    val_errors = np.mean(np.square(x_valid_ben - val_recon), axis=(1, 2))
    threshold  = compute_threshold_from_errors(val_errors, multiplier=args.multiplier)

    threshold_path = os.path.join(_models_dir, f"{SAVE_NAME}_threshold.json")
    with open(threshold_path, "w") as f:
        json.dump({
            "threshold":   threshold,
            "multiplier":  args.multiplier,
            "window_size": N_DAYS,
            "error_mean":  float(np.mean(val_errors)),
            "error_std":   float(np.std(val_errors)),
        }, f, indent=2)
    print(f"[+] Threshold saved → {threshold_path}")

    # ── FINAL EVALUATION ON HELD-OUT MIXED TEST SET ───────────────
    # These are the unbiased numbers for the paper: the test split
    # influenced neither training nor threshold calibration.
    print("\n── Final Evaluation (held-out test set) ──────────────────────")
    if len(x_test) > 0 and len(np.unique(yw_test)) > 1:
        from sklearn.metrics import (
            precision_score, recall_score, f1_score, roc_auc_score,
            classification_report,
        )
        test_recon  = model.predict(x_test, verbose=0)
        test_errors = np.mean(np.square(x_test - test_recon), axis=(1, 2))
        test_pred   = (test_errors > threshold).astype(int)

        print(classification_report(
            yw_test, test_pred, target_names=["benign", "attack"],
            zero_division=0,
        ))
        try:
            roc_auc = float(roc_auc_score(yw_test, test_errors))
            print(f"Path B ROC-AUC: {roc_auc:.4f}")
        except Exception:
            roc_auc = None

        save_metrics_block("path_b", {
            "precision": float(precision_score(yw_test, test_pred, zero_division=0)),
            "recall":    float(recall_score(yw_test, test_pred, zero_division=0)),
            "f1":        float(f1_score(yw_test, test_pred, zero_division=0)),
            "roc_auc":   roc_auc,
            "threshold": threshold,
            "multiplier": args.multiplier,
            "window_size": N_DAYS,
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
        print("[!] Test set has a single class (or is empty) — "
              "classification metrics skipped. Need mixed benign+attack "
              "data for meaningful Path B test metrics.")

    print("\n✅ Training complete.")
    print("   This model detects anomalies via RECONSTRUCTION ERROR.")
    print("   High error = unusual traffic pattern = potential DNS tunnel/attack.")
    print(f"\n   Next step: python Predict.py --filename <input> --save_name {SAVE_NAME}")
