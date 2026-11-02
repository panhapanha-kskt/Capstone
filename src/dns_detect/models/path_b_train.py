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
                         mlp_units=None, mlp_dropout=0.4, dropout=0.25,
                         latent_dim=8, noise_std=0.05):
    """
    Trafficformer: denoising sequence autoencoder over (window, F) inputs.

    Encoder blocks keep residual connections, so without a bottleneck the network can learn
    to pass any window straight through and reconstruct attacks as well as benign traffic.
    Two changes force it to learn what normal traffic looks like instead:
      • bottleneck — the whole window is squeezed into `latent_dim` numbers before decoding;
      • input noise — GaussianNoise (training only) makes copying the input useless.
    Loss = MSE between the clean window and its reconstruction.
    """
    if mlp_units is None:
        mlp_units = [64]

    from tensorflow.keras import layers, Input, Model

    window, n_features = int(input_shape[0]), int(input_shape[-1])
    inputs = Input(shape=input_shape)  # (window_size, F)
    x = layers.GaussianNoise(noise_std)(inputs) if noise_std > 0 else inputs
    for _ in range(num_transformer_blocks):
        x = transformer_encoder(x, head_size, num_heads, ff_dim, dropout)

    # latent_dim=0 rebuilds the earlier architecture (no bottleneck) so old weights still load.
    if latent_dim:
        x = layers.Flatten()(x)
        z = layers.Dense(latent_dim, name="bottleneck")(x)
        x = layers.Dense(window * 16, activation="relu")(z)
        x = layers.Reshape((window, 16))(x)
    for dim in mlp_units:
        x = layers.Dense(dim, activation="relu")(x)
        x = layers.Dropout(mlp_dropout)(x)

    outputs = layers.Dense(n_features, activation="linear")(x)   # (window_size, F)
    return Model(inputs, outputs, name="trafficformer_reconstruction")


def _family_recall(y_win, pred, fam_win) -> dict:
    """Recall per attack family over windows. Path B never sees attacks, so each is unseen-tool recall."""
    out = {}
    for f in sorted(set(fam_win[y_win == 1])):
        m = (y_win == 1) & (fam_win == f)
        out[str(f)] = {"recall": float(pred[m].mean()), "support": int(m.sum())}
    return out


def _window_families(fam_sub, last_idx, y_win):
    fw = np.asarray(fam_sub, dtype=object)[last_idx] if len(last_idx) else np.array([], dtype=object)
    return np.where((y_win == 1) & (fw == "benign"), "mixed", fw)


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
                        help="Model save name (saved to models/<save_name>.keras)")
    parser.add_argument("--data_dir",   type=str, default="data",
                        help="Data directory (default: data/)")
    parser.add_argument("--threshold-method", choices=["percentile", "mean_std"],
                        default="percentile", help="Anomaly threshold method (default: percentile)")
    parser.add_argument("--percentile", type=float, default=_default_percentile(),
                        help="Benign-error percentile for the threshold (default: 99)")
    parser.add_argument("--multiplier", type=float, default=2.5,
                        help="k for the mean+k·std fallback method (default: 2.5)")
    parser.add_argument("--split-manifest", default=None,
                        help="Shared split (data/processed/splits/*.json); use a 'time' manifest for Path B")
    parser.add_argument("--latent-dim", type=int, default=8, help="Bottleneck size (default: 8)")
    parser.add_argument("--epochs", type=int, default=200)
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

    # ── STRATIFIED-CHRONOLOGICAL 3-WAY SPLIT (per class, before normalization) ──
    # Why not a global time cut: on this project the attack captures (2019/2024)
    # all predate the benign capture (2026), so sorting by time globally and
    # taking 70/15/15 drops every attack into train and leaves val/test with no
    # positives — Path B can't be evaluated. Instead, sort within each class by
    # time and cut 70/15/15 per class, then concatenate. Each split now carries
    # both classes while still respecting chronology inside each class.
    import pandas as pd
    from dns_detect.parsing.dns_parser import _load_json_records
    from dns_detect.models.splits import load_manifest_indices
    rec_df = pd.DataFrame(_load_json_records(str(DATA_PATH)))
    fam = (rec_df["attack_family"].fillna("benign").astype(str).to_numpy()
           if "attack_family" in rec_df.columns else np.where(labels == 1, "attack", "benign"))
    fam = np.where(labels == 0, "benign", fam)

    tr_mask  = np.zeros(len(X), dtype=bool)
    val_mask = np.zeros(len(X), dtype=bool)
    te_mask  = np.zeros(len(X), dtype=bool)
    split_name = "per_class_chronological_70_15_15"
    if args.split_manifest:
        tr_i, val_i, te_i, missing, manifest = load_manifest_indices(args.split_manifest, rec_df)
        tr_mask[tr_i], val_mask[val_i], te_mask[te_i] = True, True, True
        split_name = f"manifest:{os.path.basename(args.split_manifest)}"
        if manifest.get("strategy") != "time":
            print(f"[!] Manifest strategy is '{manifest.get('strategy')}', not 'time': windows of 20 "
                  f"queries will join queries that were not consecutive. Prefer a time manifest.")
        if len(missing):
            print(f"[*] {len(missing)} record(s) not in the manifest are left out")
    else:
        for cls in np.unique(labels):
            cls_idx = np.where(labels == cls)[0]
            cls_idx = cls_idx[np.argsort(order[cls_idx], kind="stable")]
            k = len(cls_idx)
            tr_c, val_c = int(k * 0.70), int(k * 0.85)
            tr_mask[cls_idx[:tr_c]]        = True
            val_mask[cls_idx[tr_c:val_c]]  = True
            te_mask[cls_idx[val_c:]]       = True
    splits = {"train": tr_mask, "val": val_mask, "test": te_mask}
    print(f"[*] Stratified-chronological split → "
          f"train(ben={int((labels[tr_mask]==0).sum())},atk={int((labels[tr_mask]==1).sum())})  "
          f"val(ben={int((labels[val_mask]==0).sum())},atk={int((labels[val_mask]==1).sum())})  "
          f"test(ben={int((labels[te_mask]==0).sum())},atk={int((labels[te_mask]==1).sum())})")

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
        json.dump({"features": list(PATH_B_FEATURES),
                   "min": norm["min"].tolist(),
                   "range": norm["range"].tolist()}, f, indent=2)
    print(f"[*] Per-feature normalization saved → {norm_path}  (train-derived)")

    win = {}
    for name, sl in splits.items():
        win[name] = build_client_windows(Xn[sl], client_ip[sl], order[sl], N_DAYS, labels[sl])
    x_train, _, yw_train = win["train"]
    x_valid, _, yw_valid = win["val"]
    x_test, last_test, yw_test = win["test"]
    fam_test_win = _window_families(fam[te_mask], last_test, yw_test)
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
        latent_dim=args.latent_dim,
    )
    model.compile(loss="mean_squared_error",
                  optimizer=tf.keras.optimizers.Adam(learning_rate=1e-4))
    model.summary()

    early_stop = tf.keras.callbacks.EarlyStopping(
        monitor="val_loss", patience=10, restore_best_weights=True
    )
    checkpoint = tf.keras.callbacks.ModelCheckpoint(
        # Native Keras format: legacy .h5 cannot rebuild MultiHeadAttention under Keras 3.
        os.path.join(_models_dir, f"{SAVE_NAME}.keras"),
        monitor="val_loss", verbose=1, save_best_only=True, mode="min",
    )
    model.fit(
        x_train_ben, x_train_ben,   # reconstruction: target = input
        epochs=args.epochs, batch_size=32,
        validation_data=(x_valid_ben, x_valid_ben),
        callbacks=[early_stop, checkpoint],
    )
    print(f"\n[+] Model saved → {_models_dir}/{SAVE_NAME}.keras")

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
            "latent_dim":  args.latent_dim,
            "error_mean":  err_mean,
            "error_std":   err_std,
        }, f, indent=2)
    print(f"[+] Threshold saved → {threshold_path}")

    # ── FINAL EVALUATION ON HELD-OUT MIXED TEST SET ───────────────
    print("\n── Final Evaluation (held-out test set) ──────────────────────")
    if len(x_test) > 0 and len(np.unique(yw_test)) > 1:
        from sklearn.metrics import roc_auc_score, average_precision_score, classification_report
        from sklearn.ensemble import IsolationForest
        from dns_detect.models.thresholds import rates

        def _ranked(y, s):
            try:
                return float(average_precision_score(y, s)), float(roc_auc_score(y, s))
            except Exception:
                return None, None

        test_errors = compute_reconstruction_errors(model, x_test)
        test_pred   = (test_errors > threshold).astype(int)
        print(classification_report(yw_test, test_pred, target_names=["benign", "attack"],
                                    zero_division=0))
        pr_auc, roc_auc = _ranked(yw_test, test_errors)
        prevalence = float((yw_test == 1).mean())
        ae = {**rates(yw_test, test_pred), "pr_auc": pr_auc, "roc_auc": roc_auc,
              "recall_by_family": _family_recall(yw_test, test_pred, fam_test_win)}

        # Bottleneck check: attack windows must reconstruct clearly worse than benign ones.
        ben_p99 = float(np.percentile(test_errors[yw_test == 0], 99))
        atk_med = float(np.median(test_errors[yw_test == 1]))
        ae["separation"] = {"attack_median_error": atk_med, "benign_p99_error": ben_p99,
                            "ratio": atk_med / ben_p99 if ben_p99 > 0 else None}
        print(f"Autoencoder: recall={ae['recall']:.3f}  FPR={ae['fpr']:.3%}  PR-AUC={pr_auc}  "
              f"| attack median error / benign p99 error = {ae['separation']['ratio']}")

        # Baseline (Arp et al. P6): Isolation Forest on the same windows, flattened, benign-only,
        # with its threshold at the same benign-validation percentile → same false-alarm rate.
        flat = lambda w: w.reshape(len(w), -1)
        iso = IsolationForest(n_estimators=200, random_state=42, n_jobs=-1).fit(flat(x_train_ben))
        iso_val = -iso.score_samples(flat(x_valid_ben))
        iso_thr = float(np.percentile(iso_val, args.percentile))
        iso_test = -iso.score_samples(flat(x_test))
        iso_pred = (iso_test > iso_thr).astype(int)
        iso_pr, iso_roc = _ranked(yw_test, iso_test)
        iso_block = {**rates(yw_test, iso_pred), "pr_auc": iso_pr, "roc_auc": iso_roc,
                     "threshold": iso_thr,
                     "recall_by_family": _family_recall(yw_test, iso_pred, fam_test_win)}
        print(f"Isolation Forest: recall={iso_block['recall']:.3f}  FPR={iso_block['fpr']:.3%}  PR-AUC={iso_pr}")
        for f_name in ae["recall_by_family"]:
            print(f"   {f_name:16s} autoencoder recall={ae['recall_by_family'][f_name]['recall']:.3f}   "
                  f"isolation forest recall={iso_block['recall_by_family'][f_name]['recall']:.3f}")

        save_metrics_block("path_b", {
            "precision": ae["precision"],
            "recall":    ae["recall"],
            "f1":        ae["f1"],
            "fpr":       ae["fpr"],
            "pr_auc":    pr_auc,
            "pr_auc_baseline": prevalence,
            "roc_auc":   roc_auc,
            "threshold": threshold,
            "threshold_method": method,
            "window_size": N_DAYS,
            "latent_dim": args.latent_dim,
            "features":  PATH_B_FEATURES,
            "split": split_name,
            "autoencoder": ae,
            "isolation_forest_baseline": iso_block,
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
