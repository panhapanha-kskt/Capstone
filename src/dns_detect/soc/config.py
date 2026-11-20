"""Load config/soc.yaml (or $SOC_CONFIG) on top of safe defaults, resolve paths and the Python to use.

Every relative path is taken from the repo root of THIS copy (the folder above scripts/), so soc.sh
works from any copy of the repo. Environment overrides (tests, live check):
  SOC_CONFIG          another YAML file (merged over the defaults below; missing keys keep the default)
  SOC_PYTHON          interpreter for the services (else config `python:`, else $VIRTUAL_ENV, else python3)
  SOC_LISTENER_CMD    replaces detector.listener.cmd   (shell-split)
  SOC_DETECTOR_CMD    replaces detector.dashboard.cmd
  SOC_LEARNER_CMD     replaces learner.cmd
  SOC_TRAIN_CMD / SOC_EXPORT_CMD / SOC_PART_B_CMD / SOC_NOW   read by scripts/learner.py
"""
import copy
import os
import shlex
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PYTHON = "/home/Panha/dns-venv/bin/python3"

DEFAULTS = {
    "python": DEFAULT_PYTHON,
    "state_dir": "runs/soc",
    "log_dir": "logs/soc",
    "log_rotate": {"max_bytes": 10 * 1024 * 1024, "backups": 5},
    "keep_train_logs": 20,
    "paths": {"runs_dir": "runs", "models_dir": "models"},
    "detector": {
        "listener": {"cmd": ["{python}", "scripts/technitium_push_listener.py", "--port", "8787"],
                     "health_url": "http://127.0.0.1:8787/healthz"},
        "dashboard": {"cmd": ["{python}", "dashboard/server.py", "--port", "9000"],
                      "health_url": "http://127.0.0.1:9000/api/health"},
        "technitium_url": "http://127.0.0.1:5380",
        "nice": 0,
        "stop_timeout_s": 15,
    },
    "learner": {"cmd": ["{python}", "scripts/learner.py"], "heartbeat_stale_s": 180,
                "stop_timeout_s": 30, "promote_grace_s": 180},
    "health": {"interval_s": 15, "timeout_s": 5, "startup_grace_s": 90, "fail_threshold": 4},
    "restart_backoff": {"base_s": 2, "max_s": 300, "reset_after_healthy_s": 120},
    "poll_interval_s": 60,
    "cooldown_minutes": 1440,
    "max_runs_per_day": 2,
    "training_priority": {"nice": 10, "ionice_class": 3},
    "triggers": {
        "drift": {"enabled": True, "report": "data/processed/monitoring_report.json",
                  "consecutive_reports": 3, "edge_triggered": True, "require_new_data": True},
        "captures": {"enabled": True, "dir": "data/processed/week7", "pattern": "*.json",
                     "require_sha256sums": True, "settle_seconds": 120},
        "verdicts": {"enabled": True, "store": "dashboard/data/alert_management.json",
                     "min_new_verdicts": 50, "verdict_settle_minutes": 60,
                     "export_url": "http://127.0.0.1:9000",
                     "feedback_file": "data/feedback/verdict_labels.json"},
    },
    "train": {"seeds": "42 43 44", "split": None},
    "auto_promote": False,
    "max_auto_promotions_per_week": 1,
    "promote_retry": {"interval_s": 120, "max_attempts": 15},
}


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def config_path():
    return Path(os.environ.get("SOC_CONFIG") or ROOT / "config" / "soc.yaml")


def rpath(p):
    """A config path → absolute (relative ones are from the repo root)."""
    p = Path(str(p))
    return p if p.is_absolute() else ROOT / p


def load(path=None):
    path = Path(path) if path else config_path()
    data = {}
    if path.is_file():
        import yaml  # PyYAML, already used for config/*.yaml
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cfg = _merge(DEFAULTS, data)
    cfg["_config_file"] = str(path.resolve()) if path.is_file() else None
    # SOC_DASHBOARD_DATA_DIR moves the dashboard's alert store, like dashboard/server.py does.
    ddir = os.environ.get("SOC_DASHBOARD_DATA_DIR")
    if ddir:
        cfg["triggers"]["verdicts"]["store"] = str(Path(ddir) / "alert_management.json")
    py, why = resolve_python(cfg)
    cfg["_python"], cfg["_python_source"] = py, why
    return cfg


def resolve_python(cfg):
    """(interpreter, where it came from). Order: $SOC_PYTHON, config `python:`, $VIRTUAL_ENV, python3 on PATH."""
    env = os.environ.get("SOC_PYTHON")
    if env:
        return env, "SOC_PYTHON"
    conf = cfg.get("python")
    if conf and os.access(str(conf), os.X_OK):
        return str(conf), "config"
    venv = os.environ.get("VIRTUAL_ENV")
    if venv and os.access(os.path.join(venv, "bin", "python3"), os.X_OK):
        return os.path.join(venv, "bin", "python3"), "VIRTUAL_ENV"
    found = shutil.which("python3")
    if found:
        return found, "PATH"
    import sys
    return sys.executable, "sys.executable"


def expand(cmd, cfg):
    """A config command (list or string) → argv, with {python} and {root} filled in."""
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    return [str(c).replace("{python}", cfg["_python"]).replace("{root}", str(ROOT)) for c in cmd]


def env_cmd(name, default, cfg):
    v = os.environ.get(name)
    return expand(shlex.split(v), cfg) if v else expand(default, cfg)


def children(cfg, svc):
    """[(name, argv, health_url or None, nice)] for one service."""
    if svc == "detector":
        d = cfg["detector"]
        return [("listener", env_cmd("SOC_LISTENER_CMD", d["listener"]["cmd"], cfg),
                 d["listener"].get("health_url"), int(d.get("nice") or 0)),
                ("dashboard", env_cmd("SOC_DETECTOR_CMD", d["dashboard"]["cmd"], cfg),
                 d["dashboard"].get("health_url"), int(d.get("nice") or 0))]
    if svc == "learner":
        return [("learner", env_cmd("SOC_LEARNER_CMD", cfg["learner"]["cmd"], cfg), None, 0)]
    raise ValueError(f"unknown service {svc!r}")


def state_dir(cfg):
    return rpath(cfg["state_dir"])


def log_dir(cfg):
    return rpath(cfg["log_dir"])
