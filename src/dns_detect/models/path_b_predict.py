#!/usr/bin/env python3
"""
predict.py — Path B: Trafficformer Inference (multi-feature, per-client sequences)
DNS Anomaly Detector — Week 5 ML Layer

How it scores:
  - Each record is a multi-feature vector (PATH_B_FEATURES: length, entropy,
    subdomain count, digit ratio, longest label) — not a single scalar.
  - Records are grouped by client_ip and sorted by time, then cut into sliding
    windows that never cross a host boundary (a window is a real sequence).
  - reconstruction_error = MSE(window, reconstructed_window); error > threshold
    → ANOMALY. The threshold is the 99th percentile of benign-validation error
    (saved at train time), not mean+kσ.
  - ml_score_B = sigmoid of the error's z-score (0–1) for fusion with Path A.

Usage:
  python -m dns_detect.models.path_b_predict --filename week3_features_all.json --save_name dns_trafficformer
"""

import os
os.environ["CUDA_DEVICE_ORDER"]    = "PCI_BUS_ID"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"

import json
import argparse
import numpy as np
import pandas as pd
import tensorflow as tf
from pathlib import Path

from dns_detect.parsing.dns_parser import load_multifeature_with_meta, PATH_B_FEATURES
from dns_detect.utils.paths import PROJECT_ROOT


# ─────────────────────────────────────────────
# HELPERS (shared with path_b_train.py and fusion/bridge.py)
# ─────────────────────────────────────────────

def load_model_artifacts(save_name: str, model_dir: str = None):
    """
    Load model + threshold + normalization params.
    Returns (model, threshold, window_size, error_mean, error_std, norm, features).
    `norm` is {"min": [...F], "range": [...F]} (per-feature).
    """
    if model_dir is None:
        model_dir = str(PROJECT_ROOT / "models")
    threshold_path = os.path.join(model_dir, f"{save_name}_threshold.json")
    norm_path      = os.path.join(model_dir, f"{save_name}_norm.json")

    # Training saves .h5; .keras is also accepted so either format loads.
    candidates = [os.path.join(model_dir, f"{save_name}{ext}")
                  for ext in (".h5", ".keras")]
    model_path = next((p for p in candidates if os.path.exists(p)), None)
    if model_path is None:
        raise FileNotFoundError(
            f"Model not found: tried {' and '.join(candidates)}"
        )

    print(f"[*] Loading model: {model_path}")
    model = tf.keras.models.load_model(model_path, compile=False)

    if os.path.exists(threshold_path):
        with open(threshold_path) as f:
            td = json.load(f)
        threshold   = float(td["threshold"])
        window_size = int(td.get("window_size", 20))
        error_mean  = float(td.get("error_mean", 0.0))
        error_std   = float(td.get("error_std", 1.0))
        print(f"[*] Loaded anomaly threshold: {threshold:.6f}  "
              f"(method: {td.get('method', 'unknown')})")
    else:
        print("[!] No threshold file found — using fallback threshold=0.01")
        threshold, window_size, error_mean, error_std = 0.01, 20, 0.0, 1.0

    features = list(PATH_B_FEATURES)
    if os.path.exists(norm_path):
        with open(norm_path) as f:
            nd = json.load(f)
        features = nd.get("features", features)
        mins, ranges = nd["min"], nd["range"]
        # Back-compat: old single-feature artifacts stored scalars.
        if not isinstance(mins, list):
            mins, ranges = [mins], [ranges]
        norm = {"min": np.asarray(mins, dtype=np.float32),
                "range": np.asarray(ranges, dtype=np.float32)}
    else:
        print("[!] No normalization file found — using raw values (may reduce accuracy)")
        norm = {"min": np.zeros(len(features), dtype=np.float32),
                "range": np.ones(len(features), dtype=np.float32)}

    return model, threshold, window_size, error_mean, error_std, norm, features


def normalize_features(X: np.ndarray, norm: dict) -> np.ndarray:
    """Per-feature min-range scaling with train-derived params."""
    rng = np.where(norm["range"] > 0, norm["range"], 1.0)
    return ((X - norm["min"]) / rng).astype(np.float32)


def build_client_windows(X: np.ndarray, client_ip: np.ndarray, order: np.ndarray,
                         window_size: int, labels: np.ndarray = None):
    """
    Sliding windows built WITHIN each client's time-ordered stream.

    Returns:
      windows  : (n_windows, window_size, F)
      last_idx : (n_windows,) original row index of each window's last record
      y_win    : (n_windows,) 1 if any record in the window is attack (or None)
    No window crosses a host boundary. Clients with fewer than `window_size`
    records produce no windows (their records get no Path B score).
    """
    F = X.shape[1] if X.ndim == 2 else 1
    windows, last_idx, y_win = [], [], []
    for cip in pd.unique(client_ip):
        idx = np.where(client_ip == cip)[0]
        idx = idx[np.argsort(order[idx], kind="stable")]
        for i in range(len(idx) - window_size + 1):
            w = idx[i: i + window_size]
            windows.append(X[w])
            last_idx.append(w[-1])
            if labels is not None:
                y_win.append(int(labels[w].max()))
    if windows:
        windows = np.asarray(windows, dtype=np.float32).reshape(-1, window_size, F)
    else:
        windows = np.zeros((0, window_size, F), dtype=np.float32)
    return (windows, np.asarray(last_idx, dtype=int),
            np.asarray(y_win, dtype=int) if labels is not None else None)


def compute_reconstruction_errors(model, X_windows: np.ndarray) -> np.ndarray:
    """Per-window MSE reconstruction error. Shape: (N,)."""
    if len(X_windows) == 0:
        return np.zeros(0, dtype=np.float32)
    reconstructed = model.predict(X_windows, verbose=0)
    return np.mean(np.square(X_windows - reconstructed), axis=(1, 2))


def normalize_scores(errors: np.ndarray, error_mean: float,
                     error_std: float) -> np.ndarray:
    """Map reconstruction errors to (0,1) via a z-score sigmoid → ml_score_B."""
    if error_std == 0:
        return np.zeros_like(errors)
    z = (errors - error_mean) / error_std
    return 1.0 / (1.0 + np.exp(-z))


def score_records(path: str, save_name: str, model_dir: str = None):
    """
    Score every record in `path` with Path B.
    Returns (scores[n], anomalies[n], covered[n]) aligned to the file's record
    order. Each window's score is assigned to its LAST record; records not at
    the end of any window keep score 0 / not-anomalous (covered=False).
    """
    model, threshold, window_size, error_mean, error_std, norm, features = \
        load_model_artifacts(save_name, model_dir)
    X, _labels, client_ip, order = load_multifeature_with_meta(path, features)
    Xn = normalize_features(X, norm)

    windows, last_idx, _ = build_client_windows(Xn, client_ip, order, window_size)
    errors = compute_reconstruction_errors(model, windows)
    scores = normalize_scores(errors, error_mean, error_std)
    anomalies = (errors > threshold).astype(int)

    n = len(X)
    out_scores = np.zeros(n, dtype=float)
    out_anom = np.zeros(n, dtype=int)
    covered = np.zeros(n, dtype=bool)
    out_scores[last_idx] = scores
    out_anom[last_idx] = anomalies
    covered[last_idx] = True
    return out_scores, out_anom, covered, threshold


# ─────────────────────────────────────────────
# REUSABLE PREDICTION FUNCTION
# ─────────────────────────────────────────────

def get_predict(DATA_PATH: str, SAVE_NAME: str,
                data_dir: str = None, model_dir: str = None) -> dict:
    """Summary stats + per-record results (used by callers wanting a dict)."""
    if data_dir is None:
        data_dir = str(PROJECT_ROOT / "data")
    full_path = (Path(DATA_PATH) if Path(DATA_PATH).is_absolute()
                 else Path(data_dir) / DATA_PATH)
    scores, anomalies, covered, threshold = score_records(str(full_path), SAVE_NAME, model_dir)
    n_cov = int(covered.sum())
    return {
        "num_records":   int(len(scores)),
        "num_windows":   n_cov,
        "num_anomalies": int(anomalies.sum()),
        "anomaly_rate":  float(anomalies[covered].mean()) if n_cov else 0.0,
        "threshold":     threshold,
        "scores":        scores.tolist(),
        "anomalies":     anomalies.tolist(),
    }


# ─────────────────────────────────────────────
# CLI MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Trafficformer Predictor (Path B — multi-feature reconstruction anomaly detection)",
    )
    parser.add_argument("--filename",  type=str, required=True,
                        help="Week-3 features JSON to score")
    parser.add_argument("--save_name", type=str, required=True,
                        help="Model name (loaded from models/<save_name>.h5)")
    parser.add_argument("--data_dir",  type=str, default="data",
                        help="Data directory (default: data/)")
    parser.add_argument("--model_dir", type=str, default=None,
                        help="Model directory (default: PROJECT_ROOT/models/)")
    parser.add_argument("--output",    type=str, default=None,
                        help="Save per-record results to this CSV file")
    args = parser.parse_args()

    full_path = Path(args.filename) if Path(args.filename).is_absolute() \
        else Path(args.data_dir) / args.filename
    scores, anomalies, covered, threshold = score_records(str(full_path), args.save_name, args.model_dir)

    n_cov = int(covered.sum())
    print("\n=======MODEL OUTPUT (Path B — Trafficformer)=================")
    print(f"File analyzed     : {full_path}")
    print(f"Records / windows : {len(scores)} / {n_cov}")
    print(f"Anomaly threshold : {threshold:.6f}")
    print(f"Anomalies detected: {int(anomalies.sum())}")
    if n_cov:
        print(f"ml_score_B range  : {scores[covered].min():.4f} – {scores[covered].max():.4f}")
    print("=============================================================\n")

    if args.output:
        pd.DataFrame({
            "ml_score_B": scores,
            "is_anomaly": anomalies,
            "scored":     covered,
            "verdict_B":  ["ANOMALY" if a else "normal" for a in anomalies],
        }).to_csv(args.output, index=False)
        print(f"[+] Per-record results saved → {args.output}")
