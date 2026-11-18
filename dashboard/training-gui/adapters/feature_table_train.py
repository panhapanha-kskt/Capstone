"""Train on a pre-aggregated, labelled feature table (e.g. DNSTunnel2026 train.csv).

Run by the training console (core/jobs.py) with RUN_DIR, DATASET_PATH, PARAMS_JSON and LABEL_COLUMN set.
This is NOT scripts/train_models.sh: that pipeline needs raw DNS queries. Models made here are compared in
the console but can't be promoted to the live Path A/B pipeline.

Rows: reads every row of the file. Every attack row is kept. Benign rows are all kept when they fit in
memory; otherwise a random sample is kept and each kept benign row is weighted by 1 / sample rate, so the
training signal and every reported metric still represent the whole file. The log and metrics say which.

Model: scikit-learn HistGradientBoostingClassifier on the numeric feature columns, class_weight="balanced"
for the rare attack class. The decision threshold is the one with the best F1 on a validation split.
Test data: a stratified hold-out of the file (test_size), or a second uploaded feature table (eval_path),
which is then scored row by row in full.

Writes RUN_DIR/model/{model.joblib, model_meta.json, evaluation_metrics.json} and RUN_DIR/metrics.json."""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

LABEL = os.environ.get("LABEL_COLUMN", "label")
CHUNK_ROWS = 1_000_000
MEM_FACTOR = 4 * 4          # float32 bytes x (data + split copies + binning + headroom)
MEM_SHARE = 0.6             # use at most this share of the free memory


def log(msg: str) -> None:
    print(f"[feature-table] {msg}", flush=True)


def available_memory() -> int:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    try:
        import psutil
        return int(psutil.virtual_memory().available)
    except Exception:
        return 8 * 1024 ** 3


def count_rows(path: Path) -> int:
    n, last = 0, b"\n"
    with open(path, "rb") as f:
        while block := f.read(64 << 20):
            n += block.count(b"\n")
            last = block[-1:]
    return max(n - 1 + (last != b"\n"), 0)        # minus the header line


def suggest(value: str):
    try:
        from core.data import suggest_label_roles   # same rules the console's check uses
        return suggest_label_roles([value]).get(value)
    except Exception:
        return None


class Labels:
    """Label value -> 1 (attack) / 0 (benign) / None (ignored), from the admin's choices."""

    def __init__(self, label_map: dict):
        self.map = {str(k).strip(): v for k, v in (label_map or {}).items()}
        self.unseen = {}

    def roles(self, raw: pd.Series) -> pd.Series:
        lab = raw.astype(str).str.strip()
        for v in lab[~lab.isin(self.map.keys())].unique():
            role = suggest(v) or "ignore"
            self.map[v] = role
            self.unseen[v] = role
            log(f"label value {v!r} was not in the check sample; using {role!r}")
        return lab.map(self.map)


def feature_columns(path: Path) -> list:
    head = pd.read_csv(path, nrows=50_000, low_memory=False)
    if LABEL not in head.columns:
        raise SystemExit(f"No '{LABEL}' column in {path.name}.")
    feats = [c for c in head.select_dtypes("number").columns if c != LABEL]
    if not feats:
        raise SystemExit(f"No numeric feature columns in {path.name}.")
    return feats


def read_table(path: Path, feats: list, labels: Labels, benign_rate: float, rng, total: int):
    """Stream the file; keep all attack rows and (a weighted sample of) benign rows."""
    xs, ys, ws = [], [], []
    st = {"rows_read": 0, "attack_rows": 0, "benign_rows": 0, "benign_kept": 0, "ignored_rows": 0}
    t0 = time.time()
    for chunk in pd.read_csv(path, usecols=feats + [LABEL], chunksize=CHUNK_ROWS, low_memory=False):
        role = labels.roles(chunk[LABEL])
        attack = (role == "attack").to_numpy()
        benign = (role == "benign").to_numpy()
        keep_b = benign & (rng.random(len(chunk)) < benign_rate) if benign_rate < 1 else benign
        keep = attack | keep_b
        x = chunk.loc[keep, feats].apply(pd.to_numeric, errors="coerce").to_numpy(np.float32)
        xs.append(x)
        ys.append(attack[keep].astype(np.int8))
        ws.append(np.where(attack[keep], 1.0, 1.0 / benign_rate).astype(np.float32))
        st["rows_read"] += len(chunk)
        st["attack_rows"] += int(attack.sum())
        st["benign_rows"] += int(benign.sum())
        st["benign_kept"] += int(keep_b.sum())
        st["ignored_rows"] += int(len(chunk) - attack.sum() - benign.sum())
        done = st["rows_read"] / total if total else 0
        log(f"read {st['rows_read']:,} rows ({done:.0%}) in {time.time() - t0:.0f} s: "
            f"{st['attack_rows']:,} attack, {st['benign_rows']:,} benign")
    if not xs:
        raise SystemExit("The file has no data rows.")
    return np.concatenate(xs), np.concatenate(ys), np.concatenate(ws), st


def weighted_metrics(y, p, w, thr) -> dict:
    from sklearn.metrics import average_precision_score
    pred = p >= thr
    pos, neg = y == 1, y == 0
    tp, fp = float(w[pos & pred].sum()), float(w[neg & pred].sum())
    fn, tn = float(w[pos & ~pred].sum()), float(w[neg & ~pred].sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
        "precision": round(prec, 4), "recall": round(rec, 4),
        "fpr": round(fp / (fp + tn), 6) if fp + tn else 0.0,
        "accuracy": round((tp + tn) / max(tp + tn + fp + fn, 1e-9), 6),
        "pr_auc": round(float(average_precision_score(y, p, sample_weight=w)), 4) if pos.any() else None,
        "false_alarms": int(round(fp)), "missed_attacks": int(round(fn)), "caught_attacks": int(round(tp)),
        "rows": int(len(y)), "weighted_rows": int(round(float(w.sum()))), "threshold": round(float(thr), 6),
    }


def best_threshold(y, p, w) -> float:
    from sklearn.metrics import precision_recall_curve
    prec, rec, thr = precision_recall_curve(y, p, sample_weight=w)
    f1 = np.where(prec + rec > 0, 2 * prec * rec / np.maximum(prec + rec, 1e-12), 0)[:-1]
    return float(thr[int(np.argmax(f1))]) if len(thr) else 0.5


def score_file(model, path: Path, feats: list, labels: Labels):
    ys, ps = [], []
    for chunk in pd.read_csv(path, usecols=feats + [LABEL], chunksize=CHUNK_ROWS, low_memory=False):
        role = labels.roles(chunk[LABEL])
        keep = role.isin(["attack", "benign"]).to_numpy()
        x = chunk.loc[keep, feats].apply(pd.to_numeric, errors="coerce").to_numpy(np.float32)
        ys.append((role[keep] == "attack").to_numpy().astype(np.int8))
        ps.append(model.predict_proba(x)[:, 1].astype(np.float32))
        log(f"scored {sum(len(a) for a in ys):,} rows of {path.name}")
    y = np.concatenate(ys)
    return y, np.concatenate(ps), np.ones(len(y), np.float32)


def main():
    import joblib
    import sklearn
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.model_selection import train_test_split

    run = Path(os.environ["RUN_DIR"])
    src = Path(os.environ["DATASET_PATH"])
    params = json.loads(os.environ.get("PARAMS_JSON", "{}"))
    seed = int(params.get("seed", 42))
    test_size = float(params.get("test_size", 0.2))
    eval_path = Path(params["eval_path"]) if params.get("eval_path") else None
    labels = Labels(params.get("label_map") or {})
    rng = np.random.default_rng(seed)

    feats = feature_columns(src)
    log(f"training file: {src.name} · {len(feats)} numeric feature columns · label column '{LABEL}'")
    log(f"label roles: {labels.map}")
    total = count_rows(src)
    budget = float(params.get("max_memory_gb") or 0) * 1e9 or available_memory() * MEM_SHARE
    need = total * len(feats) * MEM_FACTOR
    benign_rate = 1.0 if need <= budget else max(budget / need, 0.001)
    log(f"{total:,} rows · memory needed for all rows ~{need / 1e9:.1f} GB, budget {budget / 1e9:.1f} GB")
    if benign_rate < 1:
        log(f"not enough memory for every row: keeping ALL attack rows and {benign_rate:.1%} of benign rows, "
            f"each weighted x{1 / benign_rate:.1f} so results still represent the whole file")
    else:
        log("using every row of the file")

    X, y, w, st = read_table(src, feats, labels, benign_rate, rng, total)
    if y.sum() < 10 or (y == 0).sum() < 10:
        raise SystemExit(f"Need at least 10 attack and 10 benign rows; got {int(y.sum())} attack, {int((y == 0).sum())} benign.")
    idx = np.arange(len(y))
    if eval_path:
        tr_idx, te_idx = idx, None
    else:
        tr_idx, te_idx = train_test_split(idx, test_size=test_size, stratify=y, random_state=seed)
    fit_idx, val_idx = train_test_split(tr_idx, test_size=0.1, stratify=y[tr_idx], random_state=seed)
    log(f"training on {len(fit_idx):,} rows, choosing the threshold on {len(val_idx):,}, "
        + (f"testing on all of {eval_path.name}" if eval_path else f"testing on a {test_size:.0%} hold-out ({len(te_idx):,} rows)"))

    model = HistGradientBoostingClassifier(
        max_iter=int(params.get("n_estimators", 300)), learning_rate=0.1, max_leaf_nodes=63,
        class_weight="balanced", early_stopping=True, validation_fraction=0.1, n_iter_no_change=20,
        random_state=seed)
    t0 = time.time()
    model.fit(X[fit_idx], y[fit_idx], sample_weight=w[fit_idx])
    log(f"trained {model.n_iter_} boosting rounds in {time.time() - t0:.0f} s")

    p_val = model.predict_proba(X[val_idx])[:, 1]
    thr = best_threshold(y[val_idx], p_val, w[val_idx])
    val = weighted_metrics(y[val_idx], p_val, w[val_idx], thr)
    log(f"threshold {thr:.4f} (best F1 on validation: {val['f1']})")

    if eval_path:
        del X
        y_te, p_te, w_te = score_file(model, eval_path, feats, labels)
        test_name = eval_path.name
    else:
        y_te, w_te = y[te_idx], w[te_idx]
        p_te = model.predict_proba(X[te_idx])[:, 1]
        test_name = f"{test_size:.0%} hold-out of {src.name}"
    test = weighted_metrics(y_te, p_te, w_te, thr)
    log(f"test ({test_name}): F1 {test['f1']}, precision {test['precision']}, recall {test['recall']}, "
        f"false alarms {test['false_alarms']:,}, missed attacks {test['missed_attacks']:,}")

    out = run / "model"
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, out / "model.joblib")
    meta = {"trainer": "feature_table", "model": "HistGradientBoostingClassifier", "features": feats,
            "label_column": LABEL, "label_map": labels.map, "unseen_label_values": labels.unseen,
            "threshold": thr, "dataset": src.name, "test_data": test_name, "benign_sample_rate": benign_rate,
            **st, "rows_used": int(len(y)), "seed": seed, "sklearn": sklearn.__version__,
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    (out / "model_meta.json").write_text(json.dumps(meta, indent=2))
    (out / "evaluation_metrics.json").write_text(json.dumps({"validation": val, "test": test}, indent=2))
    metrics = {k: test[k] for k in ("f1", "precision", "recall", "fpr", "pr_auc", "accuracy", "false_alarms")}
    metrics.update(trainer="feature_table", source="feature_table", test_data=test_name,
                   test_rows=test["rows"], missed_attacks=test["missed_attacks"])
    if benign_rate < 1:
        metrics["note"] = (f"Benign rows were sampled at {benign_rate:.1%} for memory; every attack row was used, "
                           "and metrics are weighted to represent the whole file.")
    (run / "metrics.json").write_text(json.dumps(metrics, indent=2))
    log(f"wrote {out / 'model.joblib'} and metrics.json")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        if e.code not in (None, 0):
            print(f"[feature-table] ERROR: {e.code}", flush=True)
            sys.exit(1)
