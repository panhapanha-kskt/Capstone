"""Model versions. Training never touches production; only promote() does."""
import json, shutil
from datetime import datetime, timezone
from . import settings as S
from . import jobs

KEYS = ["f1", "precision", "recall", "pr_auc", "accuracy", "fpr", "false_alarms"]
LABEL = {"f1": "F1", "precision": "Precision", "recall": "Recall", "pr_auc": "PR-AUC", "accuracy": "Accuracy",
         "fpr": "False positive rate", "false_alarms": "False alarms"}
WORSE_IF_LOWER = {"f1", "recall", "pr_auc"}
WORSE_IF_HIGHER = {"fpr", "false_alarms"}


def _load():
    if S.REGISTRY.exists():
        return json.loads(S.REGISTRY.read_text())
    return {"models": [], "production": None, "history": []}


def _save(reg):
    S.REGISTRY.write_text(json.dumps(reg, indent=2))


def sync():
    """Register every finished run that produced metrics.json as a new candidate version."""
    reg = _load()
    known = {m["run_id"] for m in reg["models"]}
    for j in reversed(jobs.list_jobs(500)):
        if j["status"] == "done" and j["has_metrics"] and j["run_id"] not in known:
            reg["models"].append({
                "version": f"v{len(reg['models']) + 1}", "run_id": j["run_id"],
                "created": j["started"], "dataset": j["dataset"], "train_path": j["train_path"],
                "params": j["params"], "metrics": jobs.get_metrics(j["run_id"]),
            })
    _save(reg)
    return reg


def list_models():
    reg = sync()
    return [{**m, "is_production": m["version"] == reg["production"]} for m in reg["models"]]


def _get(reg, version):
    m = next((m for m in reg["models"] if m["version"] == version), None)
    if not m:
        raise KeyError(f"Unknown model version: {version}")
    return m


def compare(candidate: str) -> dict:
    reg = sync()
    cand = _get(reg, candidate)
    prod = _get(reg, reg["production"]) if reg["production"] else None
    rows, warnings = [], []
    for k in KEYS:
        c = cand["metrics"].get(k)
        p = prod["metrics"].get(k) if prod else None
        if c is None and p is None:
            continue
        d = None if c is None or p is None else round(c - p, 4)
        rows.append({"metric": k, "candidate": c, "production": p, "delta": d})
        if d is not None and k in WORSE_IF_LOWER and d < 0:
            warnings.append(f"{LABEL[k]} is lower than the production model.")
        if d is not None and k in WORSE_IF_HIGHER and d > 0:
            warnings.append(f"{LABEL[k]} is higher than the production model.")
    return {"candidate": candidate, "production": reg["production"], "rows": rows, "warnings": warnings}


def _deploy(m):
    src = jobs._dir(m["run_id"]) / "model"
    if not src.exists():
        raise FileNotFoundError(f"Run {m['run_id']} has no model/ folder to deploy.")
    tmp = S.PRODUCTION.with_name(S.PRODUCTION.name + ".new")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src, tmp)
    if S.PRODUCTION.exists():   # keep the old folder instead of deleting it
        (S.HOME / "backups").mkdir(exist_ok=True)
        shutil.move(str(S.PRODUCTION), str(S.HOME / "backups" / datetime.now().strftime("%Y%m%d-%H%M%S")))
    tmp.rename(S.PRODUCTION)


def promote(version: str, force: bool = False) -> dict:
    reg = sync()
    m = _get(reg, version)
    if reg["production"] == version:
        raise RuntimeError(f"{version} is already in production.")
    warnings = compare(version)["warnings"]
    if warnings and not force:
        raise RuntimeError("Not promoted: " + " ".join(warnings) + " Confirm to override.")
    _deploy(m)
    reg["history"].append({"version": version, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    reg["production"] = version
    _save(reg)
    return {"production": version}


def rollback() -> dict:
    reg = sync()
    if len(reg["history"]) < 2:
        raise RuntimeError("No earlier production version to roll back to.")
    reg["history"].pop()
    prev = _get(reg, reg["history"][-1]["version"])
    _deploy(prev)
    reg["production"] = prev["version"]
    _save(reg)
    return {"production": prev["version"]}
