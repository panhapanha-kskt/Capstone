"""Runs training as a background process. State lives in files, so the
FastAPI app and the Streamlit app can both read it and a page refresh loses nothing."""
import json, os, shutil, signal, subprocess, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from . import settings as S
from .data import dataset_path

_procs = {}  # run_id -> Popen, kept only so finished children get reaped


def _dir(run_id: str) -> Path:
    p = (S.RUNS / Path(run_id).name)
    if not p.exists():
        raise FileNotFoundError(f"Run not found: {run_id}")
    return p


def _alive(pid: int) -> bool:
    if os.name == "nt":   # os.kill(pid, 0) would terminate the process on Windows
        import ctypes
        k = ctypes.windll.kernel32
        h = k.OpenProcess(0x1000, False, pid)
        if not h:
            return False
        code = ctypes.c_ulong()
        k.GetExitCodeProcess(h, ctypes.byref(code))
        k.CloseHandle(h)
        return code.value == 259   # STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _status(d: Path) -> str:
    if (d / "cancelled").exists():
        return "cancelled"
    if (d / "exitcode").exists():
        return "done" if (d / "exitcode").read_text().strip() == "0" else "failed"
    job = json.loads((d / "job.json").read_text())
    proc = _procs.get(d.name)
    if proc is not None:
        proc.poll()
    return "running" if _alive(job["pid"]) else "failed"


def get_job(run_id: str) -> dict:
    d = _dir(run_id)
    job = json.loads((d / "job.json").read_text())
    job["status"] = _status(d)
    job["has_metrics"] = (d / "metrics.json").exists()
    for marker in ("cancelled", "exitcode"):      # written when the run stops; its time is the finish time
        if (d / marker).exists():
            job["finished"] = datetime.fromtimestamp((d / marker).stat().st_mtime, timezone.utc).isoformat(timespec="seconds")
            break
    return job


def list_jobs(limit: int = 30):
    ids = sorted((p.name for p in S.RUNS.iterdir() if (p / "job.json").exists()), reverse=True)
    return [get_job(i) for i in ids[:limit]]


def running_job():
    return next((j for j in list_jobs() if j["status"] == "running"), None)


def start_job(dataset: str, train_path: str = "both", params: dict | None = None,
              trainer: str = "pipeline") -> dict:
    if trainer not in ("pipeline", "feature_table"):
        raise ValueError("trainer must be pipeline or feature_table")
    if train_path not in (("features",) if trainer == "feature_table" else ("A", "B", "both")):
        raise ValueError("train_path must be A, B or both")
    if running_job():
        raise RuntimeError("Another training job is already running. Wait or cancel it.")
    data_file = dataset_path(dataset)
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
    d = S.RUNS / run_id
    d.mkdir(parents=True)
    params = params or {}
    env = {
        **os.environ,
        "RUN_DIR": str(d), "DATASET_PATH": str(data_file), "DATASET_NAME": dataset, "PRODUCTION_DIR": str(S.PRODUCTION), "TRAIN_PATH": train_path,
        "PARAMS_JSON": json.dumps(params), "LABEL_COLUMN": S.LABEL_COL,
        "PYTHONPATH": f"{S.ROOT}{os.pathsep}{os.environ.get('PYTHONPATH', '')}",
        "PYTHONUNBUFFERED": "1",
        "TRAIN_CMD": S.FEATURE_TRAIN_COMMAND if trainer == "feature_table" else S.TRAIN_COMMAND,
    }
    log = open(d / "train.log", "wb")
    flags = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    tried, proc, err = [], None, None
    for py in dict.fromkeys(x for x in (sys.executable, shutil.which("python"), shutil.which("python3")) if x):
        tried.append(py)
        try:
            proc = subprocess.Popen([py, "-m", "core.runner", str(d)], cwd=S.PROJECT_DIR, env=env,
                                    stdout=log, stderr=subprocess.STDOUT, **flags)
            break
        except OSError as e:
            err = e
    if proc is None:
        log.close()
        shutil.rmtree(d, ignore_errors=True)
        raise RuntimeError(f"Could not start the training process. Python tried: {tried}. "
                           f"Working folder: {S.PROJECT_DIR} (exists: {Path(S.PROJECT_DIR).exists()}). Error: {err}")
    _procs[run_id] = proc
    job = {"run_id": run_id, "dataset": dataset, "train_path": train_path, "params": params, "trainer": trainer,
           "started": datetime.now(timezone.utc).isoformat(timespec="seconds"), "pid": proc.pid}
    (d / "job.json").write_text(json.dumps(job, indent=2))
    return get_job(run_id)


def cancel_job(run_id: str) -> dict:
    d = _dir(run_id)
    if _status(d) != "running":
        raise RuntimeError("This run is not running.")
    (d / "cancelled").write_text(str(time.time()))
    pid = json.loads((d / "job.json").read_text())["pid"]
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
    else:
        os.killpg(pid, signal.SIGTERM)
    return get_job(run_id)


def tail_log(run_id: str, lines: int = 200) -> str:
    f = _dir(run_id) / "train.log"
    # the log is UTF-8 (bash/Python output); Windows' default code page would garble it
    return "\n".join(f.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]) if f.exists() else ""


def get_metrics(run_id: str):
    f = _dir(run_id) / "metrics.json"
    return json.loads(f.read_text()) if f.exists() else None
