"""Train on a pre-aggregated, labelled feature table (e.g. DNSTunnel2026 train.csv).

Run by the training console (core/jobs.py) with RUN_DIR, DATASET_PATH, PARAMS_JSON and LABEL_COLUMN set.
This is NOT scripts/train_models.sh: that pipeline needs raw DNS queries. Models made here are compared in
the console but can't be promoted to the live Path A/B pipeline.

Rows: reads every row of the file. Every attack row is kept. Benign rows are all kept when they fit in
memory; otherwise a random sample is kept and each kept benign row is weighted by 1 / sample rate, so the
training signal and every reported metric still represent the whole file. The log and metrics say which.

Standard: the same as scripts/train_models.sh / Path A (src/dns_detect/models/path_a.py, splits.py,
thresholds.py, config/settings.yaml), so results are judged the same way:
  split      per class, 72 % train / 14 % validation / 14 % test; oldest -> newest when the file has a
             'timestamp' column (splits._time_split), otherwise a seeded random order per class
  capping    each feature capped at the train rows' 0.1 % / 99.9 % quantiles (path_a_clip_quantile)
  model      HistGradientBoostingClassifier(learning_rate=0.1, max_iter=300, early_stopping,
             validation_fraction=0.15, class_weight="balanced") — Path A's gradient-boosting learner
  validation cut in two halves: isotonic calibration of the scores, then the alarm threshold
  threshold  threshold_for_fpr: false alarms on benign validation rows <= path_a_max_fpr (0.1 %)
  test       scored once; the best-F1 threshold is reported next to it for reference only

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
VAL_SHARE = TEST_SHARE = 0.14   # splits._time_split defaults used by train_models.sh


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


def project_settings() -> dict:
    """The training section of config/settings.yaml (the job runs in the project root)."""
    try:
        import yaml
        with open(Path.cwd() / "config" / "settings.yaml", encoding="utf-8") as f:
            return (yaml.safe_load(f) or {}).get("training") or {}
    except Exception as e:                       # noqa: BLE001 — fall back to the documented defaults
        log(f"config/settings.yaml not read ({e}); using path_a_max_fpr=0.001, path_a_clip_quantile=0.999")
        return {}


def _pipeline_module(name: str):
    """A module from the project's src/dns_detect, so this trainer uses the pipeline's own code."""
    src = str(Path.cwd() / "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    import importlib
    return importlib.import_module(name)


def threshold_for_fpr(y, s, max_fpr):
    try:
        return _pipeline_module("dns_detect.models.thresholds").threshold_for_fpr(y, s, max_fpr)
    except ImportError:                          # same rule as dns_detect.models.thresholds
        y, s = np.asarray(y).astype(int), np.asarray(s, dtype=float)
        ben = np.sort(s[y == 0])
        if len(ben) == 0:
            return 0.5
        k = int(np.floor(max_fpr * len(ben)))
        if k >= len(ben):
            return float(ben[0])
        b = ben[len(ben) - 1 - k]
        above = s[(y == 1) & (s > b)]
        return float((b + above.min()) / 2.0) if len(above) else float(np.nextafter(b, np.inf))


def split_like_pipeline(y, ts, seed: int, test_share: float = TEST_SHARE):
    """(train, val, test, name): per class 72/14/14 like train_models.sh's default time split."""
    if ts is not None:
        try:
            tr, va, te, name = _pipeline_module("dns_detect.models.splits")._time_split(
                pd.DataFrame({"timestamp": ts}), y, seed=seed, val_share=VAL_SHARE, test_share=test_share)
            return np.asarray(tr), np.asarray(va), np.asarray(te), name
        except (ImportError, ValueError) as e:
            log(f"time split not possible ({e}); using a random order per class")
    rng = np.random.default_rng(seed)
    tr, va, te = [], [], []
    for cls in np.unique(y):
        idx = rng.permutation(np.where(y == cls)[0])
        n = len(idx)
        n_te = max(1, int(round(n * test_share))) if test_share else 0
        n_va = max(1, int(round(n * VAL_SHARE)))
        te += idx[:n_te].tolist()
        va += idx[n_te:n_te + n_va].tolist()
        tr += idx[n_te + n_va:].tolist()
    tr = np.array(tr)
    rng.shuffle(tr)
    return tr, np.array(va), np.array(te, dtype=int), "per_class_random (no timestamp column)"


def halve(idx, y, seed: int):
    """Validation -> (calibration half, threshold half), both with both classes when possible."""
    from sklearn.model_selection import train_test_split
    if len(idx) >= 20 and np.bincount(y[idx], minlength=2).min() >= 2:
        return tuple(train_test_split(idx, test_size=0.5, stratify=y[idx], random_state=seed))
    log("[warn] validation too small to halve — calibration and threshold share it")
    return idx, idx


def clip_bounds(X, rows, q):
    """Per-feature (low, high) at the q / (1-q) quantiles of the training rows; None when q is 0/None."""
    if not q:
        return None
    low, high = np.empty(X.shape[1], np.float32), np.empty(X.shape[1], np.float32)
    for j in range(X.shape[1]):                   # one column at a time keeps memory small
        low[j], high[j] = np.nanquantile(X[rows, j], [1.0 - q, q])
    return low, high


def calibrate(model, X, y, w):
    """Isotonic calibration on held-out rows (sigmoid if few), as path_a.calibrate."""
    from sklearn.calibration import CalibratedClassifierCV
    if len(np.unique(y)) < 2:
        log("[warn] calibration half has one class — scores left uncalibrated")
        return model
    method = "isotonic" if len(y) >= 200 else "sigmoid"
    try:
        from sklearn.frozen import FrozenEstimator
        cal = CalibratedClassifierCV(FrozenEstimator(model), method=method)
    except ImportError:
        cal = CalibratedClassifierCV(model, method=method, cv="prefit")
    return cal.fit(X, y, sample_weight=w)


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


# Same list as dns_detect.parsing.dns_parser.FORBIDDEN_FEATURES, used when src/ can't be imported.
FORBIDDEN_FALLBACK = {
    "client_ip", "client_port", "timestamp", "hour_of_day", "day_of_week",
    "source_file", "source_type", "input_file", "label_source", "attack_family", "dup_key", "label",
}


def forbidden_features() -> set:
    """Identity, time and provenance columns that must never be a model input."""
    try:
        return set(_pipeline_module("dns_detect.parsing.dns_parser").FORBIDDEN_FEATURES) | FORBIDDEN_FALLBACK
    except Exception:
        return set(FORBIDDEN_FALLBACK)


def feature_columns(path: Path):
    """(numeric feature columns, timestamp column or None). Identity/time/provenance columns are dropped."""
    head = pd.read_csv(path, nrows=50_000, low_memory=False)
    if LABEL not in head.columns:
        raise SystemExit(f"No '{LABEL}' column in {path.name}.")
    banned = forbidden_features()
    dropped = [c for c in head.select_dtypes("number").columns if c != LABEL and c.lower() in banned]
    if dropped:
        log(f"not used as model inputs (identity/time/provenance): {', '.join(dropped)}")
    feats = [c for c in head.select_dtypes("number").columns if c != LABEL and c.lower() not in banned]
    if not feats:
        raise SystemExit(f"No numeric feature columns in {path.name}.")
    return feats, ("timestamp" if "timestamp" in head.columns else None)


def read_table(path: Path, feats: list, labels: Labels, benign_rate: float, rng, total: int, ts_col=None):
    """Stream the file; keep all attack rows and (a weighted sample of) benign rows."""
    xs, ys, ws, tss = [], [], [], []
    st = {"rows_read": 0, "attack_rows": 0, "benign_rows": 0, "benign_kept": 0, "ignored_rows": 0}
    t0 = time.time()
    cols = feats + [LABEL] + ([ts_col] if ts_col else [])
    for chunk in pd.read_csv(path, usecols=cols, chunksize=CHUNK_ROWS, low_memory=False):
        role = labels.roles(chunk[LABEL])
        attack = (role == "attack").to_numpy()
        benign = (role == "benign").to_numpy()
        keep_b = benign & (rng.random(len(chunk)) < benign_rate) if benign_rate < 1 else benign
        keep = attack | keep_b
        if ts_col:
            tss.append(chunk.loc[keep, ts_col].astype(str).to_numpy())
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
    return np.concatenate(xs), np.concatenate(ys), np.concatenate(ws), (np.concatenate(tss) if ts_col else None), st


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
        # Intervals use the rows actually scored (not the weights): they show how much these rows can prove.
        "benign_rows_scored": int(neg.sum()), "false_alarm_rows": int((neg & pred).sum()),
        "fpr_ci95": _interval(int((neg & pred).sum()), int(neg.sum())),
        "recall_ci95": _interval(int((pos & pred).sum()), int(pos.sum())),
    }


def _interval(k: int, n: int):
    try:
        return _pipeline_module("dns_detect.models.thresholds").rate_interval(k, n)
    except Exception:
        return None


def budget_check(false_alarm_rows: int, benign_rows: int, max_fpr: float):
    """(evidence dict, message) from dns_detect.models.thresholds, or (None, '') if unavailable."""
    try:
        t = _pipeline_module("dns_detect.models.thresholds")
        ev = t.budget_evidence(false_alarm_rows, benign_rows, max_fpr)
        return ev, t.budget_message(ev)
    except Exception:
        return None, ""


def best_threshold(y, p, w) -> float:
    from sklearn.metrics import precision_recall_curve
    prec, rec, thr = precision_recall_curve(y, p, sample_weight=w)
    f1 = np.where(prec + rec > 0, 2 * prec * rec / np.maximum(prec + rec, 1e-12), 0)[:-1]
    return float(thr[int(np.argmax(f1))]) if len(thr) else 0.5


def score_file(model, path: Path, feats: list, labels: Labels, clip=None):
    ys, ps = [], []
    for chunk in pd.read_csv(path, usecols=feats + [LABEL], chunksize=CHUNK_ROWS, low_memory=False):
        role = labels.roles(chunk[LABEL])
        keep = role.isin(["attack", "benign"]).to_numpy()
        x = chunk.loc[keep, feats].apply(pd.to_numeric, errors="coerce").to_numpy(np.float32)
        if clip is not None:
            np.clip(x, clip[0], clip[1], out=x)
        ys.append((role[keep] == "attack").to_numpy().astype(np.int8))
        ps.append(model.predict_proba(x)[:, 1].astype(np.float32))
        log(f"scored {sum(len(a) for a in ys):,} rows of {path.name}")
    y = np.concatenate(ys)
    return y, np.concatenate(ps), np.ones(len(y), np.float32)


def main():
    import joblib
    import sklearn
    from sklearn.ensemble import HistGradientBoostingClassifier

    run = Path(os.environ["RUN_DIR"])
    src = Path(os.environ["DATASET_PATH"])
    params = json.loads(os.environ.get("PARAMS_JSON", "{}"))
    seed = int(params.get("seed", 42))
    eval_path = Path(params["eval_path"]) if params.get("eval_path") else None
    labels = Labels(params.get("label_map") or {})
    cfg = project_settings()
    max_fpr = float(cfg.get("path_a_max_fpr", 0.001))
    clip_q = cfg.get("path_a_clip_quantile", 0.999)
    rng = np.random.default_rng(seed)

    feats, ts_col = feature_columns(src)
    log(f"training file: {src.name} · {len(feats)} numeric feature columns · label column '{LABEL}'"
        + (" · has timestamps" if ts_col else ""))
    log(f"label roles: {labels.map}")
    log(f"standard (as train_models.sh / Path A): split 72/14/14 per class, capping {clip_q}, "
        f"isotonic calibration, threshold at <= {max_fpr:.2%} false alarms on benign validation rows, seed {seed}")
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

    X, y, w, ts, st = read_table(src, feats, labels, benign_rate, rng, total, ts_col)
    if y.sum() < 10 or (y == 0).sum() < 10:
        raise SystemExit(f"Need at least 10 attack and 10 benign rows; got {int(y.sum())} attack, {int((y == 0).sum())} benign.")
    tr, va, te, split_name = split_like_pipeline(y, ts, seed, test_share=0.0 if eval_path else TEST_SHARE)
    cal_idx, thr_idx = halve(va, y, seed)
    log(f"split {split_name}: train {len(tr):,} · validation {len(va):,} (calibration {len(cal_idx):,}, "
        f"threshold {len(thr_idx):,}) · " + (f"test: all of {eval_path.name}" if eval_path else f"test {len(te):,}"))

    clip = clip_bounds(X, tr, clip_q)
    if clip is not None:
        n_capped = int(((X < clip[0]) | (X > clip[1])).sum())
        np.clip(X, clip[0], clip[1], out=X)
        log(f"outliers capped at the train {clip_q:.1%} quantiles (rows kept): {n_capped:,} values")

    model = HistGradientBoostingClassifier(
        learning_rate=0.1, max_iter=300, early_stopping=True, validation_fraction=0.15,
        class_weight="balanced", random_state=seed)
    t0 = time.time()
    model.fit(X[tr], y[tr], sample_weight=w[tr])
    log(f"trained {model.n_iter_} boosting rounds in {time.time() - t0:.0f} s")
    model = calibrate(model, X[cal_idx], y[cal_idx], w[cal_idx])

    p_thr = model.predict_proba(X[thr_idx])[:, 1]
    thr = threshold_for_fpr(y[thr_idx], p_thr, max_fpr)
    thr_f1 = best_threshold(y[thr_idx], p_thr, w[thr_idx])
    val = weighted_metrics(y[thr_idx], p_thr, w[thr_idx], thr)
    log(f"alarm threshold {thr:.6f} (validation false-alarm rate {val['fpr']:.4%} <= {max_fpr:.2%}); "
        f"best-F1 threshold for reference {thr_f1:.6f}")

    if eval_path:
        del X
        y_te, p_te, w_te = score_file(model, eval_path, feats, labels, clip)
        test_name = eval_path.name
    else:
        y_te, w_te = y[te], w[te]
        p_te = model.predict_proba(X[te])[:, 1]
        test_name = f"14% test split of {src.name} ({split_name})"
    test = weighted_metrics(y_te, p_te, w_te, thr)
    test_f1 = weighted_metrics(y_te, p_te, w_te, thr_f1)
    log(f"test ({test_name}): F1 {test['f1']}, precision {test['precision']}, recall {test['recall']}, "
        f"FPR {test['fpr']:.4%}, false alarms {test['false_alarms']:,}, missed attacks {test['missed_attacks']:,}")
    log(f"for reference, at the best-F1 threshold: F1 {test_f1['f1']}, false alarms {test_f1['false_alarms']:,}")
    budget, budget_msg = budget_check(test["false_alarm_rows"], test["benign_rows_scored"], max_fpr)
    if budget_msg:
        log(f"budget check: {budget_msg}")

    out = run / "model"
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, out / "model.joblib")
    meta = {"trainer": "feature_table", "model": "HistGradientBoostingClassifier + isotonic calibration",
            "standard": "train_models.sh / Path A", "features": feats, "label_column": LABEL,
            "label_map": labels.map, "unseen_label_values": labels.unseen, "threshold": thr,
            "threshold_rule": f"false alarms on benign validation rows <= {max_fpr}", "threshold_best_f1": thr_f1,
            "clip_quantile": clip_q, "clip": {"low": clip[0].tolist(), "high": clip[1].tolist()} if clip is not None else None,
            "split": split_name, "split_rows": {"train": int(len(tr)), "validation": int(len(va)), "test": int(len(te))},
            "dataset": src.name, "test_data": test_name, "benign_sample_rate": benign_rate,
            **st, "rows_used": int(len(y)), "seed": seed, "sklearn": sklearn.__version__,
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    (out / "model_meta.json").write_text(json.dumps(meta, indent=2))
    (out / "evaluation_metrics.json").write_text(json.dumps(
        {"validation_threshold_half": val, "test": test, "test_at_best_f1_threshold": test_f1,
         "budget_check": budget}, indent=2))
    metrics = {k: test[k] for k in ("f1", "precision", "recall", "fpr", "pr_auc", "accuracy", "false_alarms",
                                    "fpr_ci95", "recall_ci95")}
    metrics["budget_check"] = budget
    metrics.update(trainer="feature_table", source="feature_table", test_data=test_name,
                   test_rows=test["rows"], missed_attacks=test["missed_attacks"], max_fpr=max_fpr)
    if benign_rate < 1:
        metrics["note"] = (f"Benign rows were sampled at {benign_rate:.1%} for memory; every attack row was used, "
                           "and metrics are weighted to represent the whole file.")
    (run / "metrics.json").write_text(json.dumps(metrics, indent=2))
    log(f"wrote {out / 'model.joblib'} and metrics.json")
    write_run_record(out, src, seed)
    save_to_models(out, meta, metrics, params)


def save_to_models(out: Path, meta: dict, metrics: dict, params: dict) -> None:
    """Also keep a copy in the models folder when PARAMS_JSON has "save_to_models": "<name>"
    (or the SAVE_TO_MODELS env var). Written as <name>.joblib + <name>_meta.json next to the
    Path A / Path B files. The live pipeline (run_pipeline.sh, the bridge) does NOT load this
    model: it scores DNSTunnel2026-style 38-column tables only. The meta file says so."""
    name = params.get("save_to_models") or os.environ.get("SAVE_TO_MODELS")
    if not name:
        return
    import shutil
    models_dir = Path(os.environ.get("DNS_DETECT_MODELS_DIR") or (Path.cwd() / "models"))
    if not models_dir.is_absolute():
        models_dir = Path.cwd() / models_dir
    models_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(out / "model.joblib", models_dir / f"{name}.joblib")
    (models_dir / f"{name}_meta.json").write_text(json.dumps({
        **meta,
        "model_file": f"{name}.joblib",
        "source_run": str(out.parent),
        "test_metrics": metrics,
        "used_by_detection": False,
        "note": ("Feature-table model (trained on a pre-aggregated 38-column table). "
                 "Not loaded by the bridge or run_pipeline.sh; it cannot score raw DNS queries. "
                 "Kept here for the record and for scoring DNSTunnel2026-style tables."),
    }, indent=2))
    log(f"copied model to {models_dir / (name + '.joblib')} and {name}_meta.json (not used by detection)")


def write_run_record(out: Path, dataset: Path, seed: int) -> None:
    """run_record.json (git commit, pip freeze, dataset sha256, seed) via scripts/run_record.py.
    The dataset is recorded, not copied: feature tables can be several GB."""
    try:
        sys.path.insert(0, str(Path.cwd() / "scripts"))
        import run_record
        path = run_record.write_record(out, seed=seed, merged=dataset)
        log(f"wrote {path}")
    except Exception as e:                      # the model is already saved; never fail the run here
        log(f"run record not written: {e}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        if e.code not in (None, 0):
            print(f"[feature-table] ERROR: {e.code}", flush=True)
            sys.exit(1)
