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
    if params.get("pcap_label") in ("0", "1"):
        cmd += ["--pcap-label", params["pcap_label"]]
    if params.get("allow_heuristic_labels"):
        cmd.append("--allow-heuristic-labels")
    if os.environ.get("DATASET_NAME") != "project-default":      # --files must stay last
        src = Path(os.environ["DATASET_PATH"])
        cmd += ["--data-dir", str(src)] if src.is_dir() else ["--files", str(src)]

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
