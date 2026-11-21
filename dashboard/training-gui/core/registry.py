"""Model versions. Training never touches production; only promote() does.

Capstone mode (audit C2): Promote and Roll back go through the same door as the pipeline's
Part B — scripts/part_b.py runs the project gate (>= 3 seeds, beats current + rule baselines),
waits for no detection run, promotes with promote_model.sh (archives the old models/, never
moves models/archive/), smoke-tests and rolls back by itself if the smoke test fails.
"Confirm to override" can't skip that gate. Demo mode keeps the simple folder copy.
"""
import json, re, shlex, shutil, subprocess
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


LIVE_VERSION = "live"   # the model in <repo>/models, whoever promoted it (part_b.py, promote_model.sh, console)


def _live_model():
    """Capstone mode: the model in models/ as a registry entry, read from PROMOTED.json + evaluation_metrics.json.
    The registry only remembers console promotions; part_b.py / run_all.sh promote too, so models/ is the truth."""
    if S.MODE != "capstone" or not (S.PRODUCTION / "evaluation_metrics.json").is_file():
        return None
    try:
        from adapters.capstone_train import pick, METRIC_PATHS, EXTRA_PATHS, read_json
        ev = read_json(S.PRODUCTION / "evaluation_metrics.json")
        metrics = {k: pick(ev, v) for k, v in {**METRIC_PATHS, **EXTRA_PATHS}.items()}
        metrics = {k: v for k, v in metrics.items() if v is not None}
        prom = read_json(S.PRODUCTION / "PROMOTED.json") if (S.PRODUCTION / "PROMOTED.json").is_file() else {}
        prov = read_json(S.PRODUCTION / "training_provenance.json") \
            if (S.PRODUCTION / "training_provenance.json").is_file() else {}
        return {"version": LIVE_VERSION, "run_id": prom.get("source_run") or str(S.PRODUCTION),
                "created": prom.get("promoted_at") or "", "dataset": f"{len(prov.get('source_files', []))} files "
                "(models/training_provenance.json)", "train_path": "both", "params": {}, "metrics": metrics,
                "trainer": "pipeline", "live": True}
    except Exception:
        return None


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
                "trainer": j.get("trainer", "pipeline"),
            })
    _save(reg)
    return reg


def list_models():
    reg = sync()
    out = [{**m, "is_production": m["version"] == reg["production"], "deployable": _deployable(m)}
           for m in reg["models"]]
    live = _live_model()
    if live and not any(m["is_production"] for m in out):
        out.insert(0, {**live, "is_production": True, "deployable": True})
    return out


def _deployable(m) -> bool:
    """Only train_models.sh runs produce the Path A/B model folder the live pipeline loads."""
    return m.get("trainer", "pipeline") == "pipeline"


def status() -> dict:
    """Which version is live, and which one Roll back would restore."""
    reg = sync()
    hist = [h["version"] for h in reg["history"]]
    prod = reg["production"]
    if prod is None:
        live = _live_model()
        if live:
            prod = f"{LIVE_VERSION} ({live['run_id']}, promoted {live['created'][:10] or 'by script'})"
    return {"production": prod, "previous": hist[-2] if len(hist) >= 2 else None, "history": hist}


def _get(reg, version):
    m = next((m for m in reg["models"] if m["version"] == version), None)
    if not m:
        raise KeyError(f"Unknown model version: {version}")
    return m


def compare(candidate: str) -> dict:
    reg = sync()
    cand = _get(reg, candidate)
    prod = _get(reg, reg["production"]) if reg["production"] else _live_model()
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
    if prod and cand.get("trainer", "pipeline") != prod.get("trainer", "pipeline"):
        warnings.insert(0, "Not a like-for-like comparison: these models were trained on different kinds of data "
                           "(feature table vs raw DNS queries) and tested on different test sets.")
    return {"candidate": candidate, "production": reg["production"] or (prod and prod["version"]),
            "rows": rows, "warnings": warnings, "deployable": _deployable(cand)}


PART_B_CODES = {
    1: "the project gate failed (see the gate report); models/ is unchanged.",
    2: "promoted, but the smoke test failed, so the previous models were put back.",
    3: "detection is running or another promote is in progress (or an error); try again shortly.",
    4: "training data for the gate is missing.",
    5: "the shadow check failed: the candidate behaves differently from the live model on current traffic; models/ unchanged.",
}


def _seedless(params):
    return {k: v for k, v in (params or {}).items() if k not in ("seed", "random_state")}


def _scoreable(x):
    """The gate needs the run's frozen test rows and split to compare it with the live model and the rules."""
    d = jobs._dir(x["run_id"]) / "model"
    return d.is_dir() and (d / "merged_features_labeled.json").is_file() and (d / "split_manifest.json").is_file()


def _siblings(reg, m):
    """Deployable runs trained the same way as m (same data, path, params apart from the seed): one run per
    seed (the newest), and only runs the gate can score. Two seed-42 runs are one seed, not two."""
    same = [x for x in reg["models"] if _deployable(x) and x["dataset"] == m["dataset"]
            and x.get("train_path") == m.get("train_path") and _seedless(x["params"]) == _seedless(m["params"])
            and _scoreable(x)]
    by_seed = {}
    for x in same:                                   # reg["models"] is oldest first: the newest run wins
        by_seed[(x["params"] or {}).get("seed", 42)] = x
    if m["version"] not in {x["version"] for x in by_seed.values()}:
        by_seed[(m["params"] or {}).get("seed", 42)] = m   # the clicked run is always in
    return list(by_seed.values())


def _shell():
    """(flavor, path converter) for running the project's bash scripts, WSL-aware on Windows."""
    try:
        from adapters.capstone_train import bash_flavor, to_shell_path
        flavor = bash_flavor()
        return lambda p: to_shell_path(p, flavor)
    except Exception:
        return str


def _run_project(script_cmd: str):
    """Run a command in the project root through bash. Returns (exit code, output)."""
    conv = _shell()
    cmd = f"cd {shlex.quote(conv(S.PROJECT_DIR))} && {script_cmd}"
    r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=3 * 3600)
    return r.returncode, (r.stdout + r.stderr)[-4000:]


def _run_part_b(name: str, model_dirs: list):
    conv = _shell()
    runs = " ".join(f"--run {shlex.quote(conv(d))}" for d in model_dirs)
    return _run_project(f"python3 scripts/part_b.py --name {shlex.quote(name)} --auto-promote {runs}")


def _promote_capstone(reg, m):
    if not _scoreable(m):
        raise RuntimeError(f"{m['version']} can't go through the gate: its run folder has no merged_features_labeled.json "
                           "or split_manifest.json (it was trained before the console saved them), so the gate cannot "
                           "score it against the live model. Train it again to get a run the gate can judge.")
    group = _siblings(reg, m)
    dirs = [jobs._dir(x["run_id"]) / "model" for x in group]
    code, out = _run_part_b(f"console_{m['version']}", dirs)
    if code != 0:
        seeds = sorted((x["params"] or {}).get("seed", 42) for x in group)
        hint = (f" Only {len(group)} comparable run(s) (seed {', '.join(map(str, seeds))}); the gate needs >= 3 "
                "different seeds — train the same dataset and settings with seed 43 and 44, then Promote again.") \
            if len(group) < 3 else ""
        raise RuntimeError(PART_B_CODES.get(code, f"part_b exit {code}.") + hint
                           + "\n" + "\n".join(out.strip().splitlines()[-8:]))
    # part_b picks the median-seed run; record that one as production.
    hit = re.search(r"promoted (\S+)", out)
    chosen = next((x for x in group if hit and x["run_id"] in hit.group(1)), m)
    return chosen


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
    if not _deployable(m):
        raise RuntimeError(f"{version} was trained by the feature-table trainer on pre-aggregated features. The live "
                           "detection pipeline loads Path A/B models, so it can't be promoted. Its model files are in "
                           f"the run folder runs/{m['run_id']}/model.")
    if S.MODE == "capstone":
        m = _promote_capstone(reg, m)   # gate + lock + smoke test; force can't skip it
        version = m["version"]
    else:
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
    prev = _get(reg, reg["history"][-2]["version"])
    if S.MODE == "capstone":
        # Same door as Part B: restore the newest models/archive/ folder; nothing is deleted.
        code, out = _run_project("bash scripts/rollback_model.sh")
        if code != 0:
            raise RuntimeError("Roll back failed; models/ unchanged.\n" + out.strip()[-800:])
    else:
        _deploy(prev)
    reg["history"].pop()
    reg["production"] = prev["version"]
    _save(reg)
    return {"production": prev["version"]}
