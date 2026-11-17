"""Stand-in trainer so the GUI works before you wire in your own pipeline.
Path A trains a real Random Forest. Path B only simulates autoencoder epochs.
Replace it by setting TRAIN_COMMAND (see core/settings.py)."""
import json, os, sys, time
from pathlib import Path
import numpy as np
import pandas as pd


def make_sample(path: Path, n: int = 4000, seed: int = 0):
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.25).astype(int)
    df = pd.DataFrame({
        "query_len": np.where(y, rng.normal(38, 14, n), rng.normal(27, 10, n)),
        "entropy": np.where(y, rng.normal(3.6, 0.7, n), rng.normal(3.1, 0.7, n)),
        "nxdomain_ratio": np.where(y, rng.beta(3, 4, n), rng.beta(1, 6, n)),
        "qps": np.where(y, rng.gamma(3, 20, n), rng.gamma(2, 12, n)),
        "unique_subdomains": np.where(y, rng.poisson(30, n), rng.poisson(12, n)),
        "label": np.where(y, "attack", "benign"),
    })
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def main():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
    from sklearn.model_selection import train_test_split
    import joblib

    run = Path(os.environ["RUN_DIR"])
    params = json.loads(os.environ.get("PARAMS_JSON", "{}"))
    label = os.environ.get("LABEL_COLUMN", "label")
    path = os.environ.get("TRAIN_PATH", "both")
    seed = int(params.get("seed", 42))

    print(f"[data] loading {os.environ['DATASET_PATH']}", flush=True)
    df = pd.read_csv(os.environ["DATASET_PATH"])
    y = (~df[label].astype(str).str.lower().isin(["benign", "0", "normal"])).astype(int)
    X = df.drop(columns=[label]).select_dtypes("number").fillna(0)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=float(params.get("test_size", 0.2)),
                                          stratify=y, random_state=seed)
    print(f"[data] {len(Xtr)} train rows, {len(Xte)} test rows, {X.shape[1]} features", flush=True)

    metrics, loss = {}, []
    if path in ("A", "both"):
        n = int(params.get("n_estimators", 200))
        print(f"[path A] training Random Forest ({n} trees)", flush=True)
        rf = RandomForestClassifier(n_estimators=n, random_state=seed, n_jobs=-1).fit(Xtr, ytr)
        pred = rf.predict(Xte)
        tn, fp, fn, tp = confusion_matrix(yte, pred, labels=[0, 1]).ravel()
        metrics = {"accuracy": accuracy_score(yte, pred), "precision": precision_score(yte, pred, zero_division=0),
                   "recall": recall_score(yte, pred, zero_division=0), "f1": f1_score(yte, pred, zero_division=0),
                   "fpr": fp / max(fp + tn, 1), "confusion": [[int(tn), int(fp)], [int(fn), int(tp)]]}
        (run / "model").mkdir(exist_ok=True)
        joblib.dump(rf, run / "model" / "path_a_rf.joblib")
        print(f"[path A] f1={metrics['f1']:.4f} fpr={metrics['fpr']:.4f}", flush=True)
    if path in ("B", "both"):
        epochs = int(params.get("epochs", 10))
        print("[path B] SIMULATED autoencoder epochs (demo trainer)", flush=True)
        for e in range(1, epochs + 1):
            time.sleep(0.6)
            loss.append(round(1.0 / (1 + 0.5 * e) + 0.02 * np.random.rand(), 4))
            print(f"[path B] epoch {e}/{epochs} loss={loss[-1]}", flush=True)
        (run / "model").mkdir(exist_ok=True)
        (run / "model" / "path_b_placeholder.txt").write_text("demo only")
    metrics = {k: (round(v, 4) if isinstance(v, float) else v) for k, v in metrics.items()}
    metrics["loss_curve"] = loss
    (run / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print("[done] wrote metrics.json and model/", flush=True)


if __name__ == "__main__":
    if "--make-sample" in sys.argv:
        from core import settings as S
        make_sample(S.DATASETS / "sample_dns.csv")
        print("wrote", S.DATASETS / "sample_dns.csv")
    else:
        main()
