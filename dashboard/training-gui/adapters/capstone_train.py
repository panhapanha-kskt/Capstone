"""Runs Capstone's scripts/train_models.sh for the training console.

The console sets RUN_DIR, DATASET_PATH, DATASET_NAME, TRAIN_PATH, PARAMS_JSON, PRODUCTION_DIR.
This adapter points the script's output at RUN_DIR/model (via DNS_DETECT_MODELS_DIR), so the live
models folder is untouched until an admin clicks Promote, then writes RUN_DIR/metrics.json.
Run with the Capstone repo as the working directory (PROJECT_DIR)."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Where each headline number sits in <models>/evaluation_metrics.json. First match wins.
# If your file uses other names, change them here; nothing else needs editing.
FUS = "fusion.test.learned_lr"
METRIC_PATHS = {
    "f1": [FUS + ".f1"], "precision": [FUS + ".precision"], "recall": [FUS + ".recall"],
    "fpr": [FUS + ".fpr"], "false_alarms": [FUS + ".false_alarms"],
}
PATH_A_PATHS = {"f1": ["path_a.f1"], "precision": ["path_a.precision"], "recall": ["path_a.recall"],
                "fpr": ["path_a.fpr"]}
EXTRA_PATHS = {"pr_auc": ["path_a.pr_auc"]}


def pick(d, paths):
    for p in paths:
        cur = d
        for k in p.split("."):
            cur = cur.get(k) if isinstance(cur, dict) else None
        if isinstance(cur, (int, float)) and not isinstance(cur, bool):
            return cur
    return None


def read_json(p):
    try:
        return json.loads(Path(p).read_text())
    except Exception:
        return {}


def needs_label_mapping(label_map: dict) -> bool:
    """False when the labels already are 0 = benign, 1 = attack (nothing to rewrite)."""
    same = {"0": "benign", "0.0": "benign", "1": "attack", "1.0": "attack"}
    return any(same.get(str(v).strip()) != role for v, role in (label_map or {}).items())


def map_labels(src: Path, dst: Path, label_map: dict, label_col: str = "label") -> Path:
    """Copy a CSV with its label column rewritten to 0/1 from the admin's choices.
    benign -> 0, attack -> 1, ignore -> row dropped; values without a choice stay unlabeled ("")."""
    import pandas as pd
    to01 = {"benign": "0", "attack": "1"}
    roles = {str(k).strip(): v for k, v in label_map.items()}
    first, kept, dropped = True, 0, 0
    for chunk in pd.read_csv(src, chunksize=500_000, dtype=str, keep_default_na=False):
        lab = chunk[label_col].str.strip()
        role = lab.map(roles)
        keep = (role != "ignore").to_numpy()
        part = chunk[keep].copy()
        part[label_col] = role[keep].map(to01).fillna("")
        part.to_csv(dst, mode="w" if first else "a", header=first, index=False)
        first, kept, dropped = False, kept + int(keep.sum()), dropped + int((~keep).sum())
    print(f"[console] labels mapped to 0/1 in {dst.name}: {kept:,} rows kept, {dropped:,} ignored", flush=True)
    return dst


def _mapped(src: Path, run: Path, label_map: dict, tag: str = "") -> Path:
    """The file to train on: src itself, or a 0/1-label copy when its CSV labels need mapping."""
    if src.is_file() and src.suffix.lower() == ".csv" and needs_label_mapping(label_map):
        return map_labels(src, run / f"labels01_{tag}{src.name}", label_map)
    return src


def build_command(params: dict, path: str, retrain: str, run: Path, dataset_name: str, dataset_path: Path) -> list:
    """The scripts/train_models.sh command line for one console run (--files / --data-dir stay last)."""
    cmd = ["bash", "scripts/train_models.sh", "--verbose",
           "--seed", str(params.get("seed", 42)),
           "--n-days", str(params.get("n_days", 20)),
           "--path-b-model", params.get("path_b_model", "trafficformer"),
           "--retrain" if retrain == "new_only" else "--force-retrain"]
    if path == "A":
        cmd.append("--path-a-only")
    if path == "B":
        cmd.append("--path-b-only")
    if params.get("new_split"):
        cmd.append("--new-split")
    elif params.get("split_manifest"):
        cmd += ["--split-manifest", str(params["split_manifest"])]
    if params.get("pcap_label") in ("0", "1"):
        cmd += ["--pcap-label", params["pcap_label"]]
    if params.get("allow_heuristic_labels"):
        cmd.append("--allow-heuristic-labels")
    label_map = params.get("label_map") or {}
    if dataset_name.startswith("bundle:"):                      # several files, like train_models.sh --files
        from core.data import bundle_files
        files = [_mapped(f, run, label_map, f"{i}_") for i, f in enumerate(bundle_files(dataset_name))]
        cmd += ["--files", *map(str, files)]
    elif dataset_name != "project-default":
        src = _mapped(dataset_path, run, label_map)
        cmd += ["--data-dir", str(src)] if src.is_dir() else ["--files", str(src)]
    return cmd


def main():
    run = Path(os.environ["RUN_DIR"])
    project = Path.cwd()
    params = json.loads(os.environ.get("PARAMS_JSON", "{}"))
    path = os.environ.get("TRAIN_PATH", "both")
    retrain = params.get("retrain", "all")
    prod = Path(os.environ.get("PRODUCTION_DIR", project / "models"))
    models = run / "model"

    # One-path runs and "new files only" runs build on the models already in production,
    # so start from a copy of them. Full runs start empty.
    if (path != "both" or retrain == "new_only") and prod.exists():
        print(f"[console] starting from a copy of {prod}", flush=True)
        shutil.copytree(prod, models)
    models.mkdir(exist_ok=True)

    cmd = build_command(params, path, retrain, run, os.environ.get("DATASET_NAME", ""),
                        Path(os.environ["DATASET_PATH"]))

    env = {**os.environ, "DNS_DETECT_MODELS_DIR": str(models)}
    print("[console] " + " ".join(cmd), flush=True)
    rc = subprocess.run(cmd, env=env).returncode
    if rc != 0:
        sys.exit(rc)

    ev, meta = read_json(models / "evaluation_metrics.json"), read_json(models / "training_metadata.json")
    metrics = {}
    if meta.get("fusion_trained") is True:
        paths = METRIC_PATHS
    elif path in ("A", "both"):
        paths = PATH_A_PATHS
    else:
        paths = {}
    for k, p in {**paths, **(EXTRA_PATHS if path != "B" else {})}.items():
        v = pick(ev, p)
        if v is not None:
            metrics[k] = round(v, 4) if isinstance(v, float) else v
    if not metrics:
        metrics["note"] = ("No comparable metrics in this run (Path B only and the fusion was not retrained, "
                           "or the metric names in adapters/capstone_train.py do not match evaluation_metrics.json).")
    metrics["source"] = "fusion" if meta.get("fusion_trained") is True else ("path_a" if paths else "none")
    metrics["raw_file"] = "model/evaluation_metrics.json"
    (run / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"[console] wrote metrics.json: {metrics}", flush=True)


if __name__ == "__main__":
    main()
