"""Audit Week 7 safety fixes C1 (alert caps), C2 (console promote) and H1 (detection lock)."""
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pd = pytest.importorskip("pandas")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.detection.engine import ALERT_CAPS, RuleBasedDNSDetector, _prioritise  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lock = _load("pipeline_lock", ROOT / "src/dns_detect/utils/pipeline_lock.py")


# ── C1: alert caps keep the strongest/newest and never drop silently ──────────
def _ml_frame(n_noise=250, n_attack=30):
    rows = []
    for i in range(n_noise):          # a noisy morning: many weak hits, oldest first
        rows.append({"row_id": i, "timestamp": f"2026-11-20T09:{i // 60:02d}:{i % 60:02d}",
                     "client_ip": "10.0.0.5", "domain": f"n{i}.noise.lab",
                     "ml_combined_label": 1, "ml_combined_score": 0.51, "ml_confidence": "LOW"})
    for j in range(n_attack):         # the real tunnel in the afternoon, strong scores
        rows.append({"row_id": 1000 + j, "timestamp": f"2026-11-20T15:00:{j:02d}",
                     "client_ip": "10.0.0.66", "domain": f"x{j}.tunnel.evil",
                     "ml_combined_label": 1, "ml_combined_score": 0.97, "ml_confidence": "HIGH"})
    return pd.DataFrame(rows)


def test_rule5_keeps_late_strong_attack_and_summarises_overflow():
    det = RuleBasedDNSDetector()
    det.has_ml_scores = True
    df = _ml_frame()
    alerts = det.rule5_ml_attack_detection(df)
    cap = ALERT_CAPS["rule5"]
    normal = [a for a in alerts if not a["details"].get("overflow")]
    over = [a for a in alerts if a["details"].get("overflow")]
    assert len(normal) == cap
    attack_ids = {a["details"]["row_id"] for a in normal if a["domain"].endswith("tunnel.evil")}
    assert attack_ids == set(range(1000, 1030)), "every afternoon attack row must still alert"
    assert len(over) == 1 and over[0]["details"]["suppressed"] == len(df) - cap
    assert sum(over[0]["details"]["top_domains"].values()) <= len(df) - cap


def test_no_overflow_alert_under_cap():
    det = RuleBasedDNSDetector()
    det.has_ml_scores = True
    alerts = det.rule5_ml_attack_detection(_ml_frame(n_noise=10, n_attack=5))
    assert len(alerts) == 15 and not any(a["details"].get("overflow") for a in alerts)


def test_prioritise_ties_go_to_newest():
    df = pd.DataFrame({"s": [0.5, 0.5, 0.5], "timestamp": ["2026-01-01T01:00", "2026-01-01T03:00", "2026-01-01T02:00"]})
    top, rest = _prioritise(df, ["s"], 2)
    assert list(top["timestamp"]) == ["2026-01-01T03:00", "2026-01-01T02:00"] and len(rest) == 1


def test_no_silent_break_left_in_engine():
    src = (ROOT / "src/dns_detect/detection/engine.py").read_text(encoding="utf-8")
    assert "if len(alerts) >=" not in src


# ── H1: detection lock seen by part_b ────────────────────────────────────────
def test_detection_heartbeat_blocks_promote(tmp_path):
    assert not lock.pipeline_running(tmp_path)
    with lock.detection_running(tmp_path) as beat:
        beat()
        assert lock.pipeline_running(tmp_path)
    assert not lock.pipeline_running(tmp_path)


def test_stale_heartbeat_is_ignored(tmp_path):
    rd = tmp_path / ".pipeline.readers"
    rd.mkdir()
    f = rd / "crashed-1"
    f.write_text("x")
    old = time.time() - lock.STALE_SECONDS - 5
    os.utime(f, (old, old))
    assert not lock.pipeline_running(tmp_path)


def test_part_b_refuses_while_dashboard_detects(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    gate_report = {"seeds": [{"seed": 42, "run": str(runs / "r"), "candidate": {"false_alarms": 1}}]}
    gate = tmp_path / "gate.py"
    gate.write_text("import sys,json\nout=sys.argv[sys.argv.index('--out')+1]\n"
                    f"open(out,'w').write(json.dumps({gate_report!r}))\n")
    promote = tmp_path / "promote.sh"
    promote.write_text("touch PROMOTED_CALLED\n")
    env = {**os.environ, "PART_B_GATE": f"{sys.executable} {gate}", "PART_B_PROMOTE": f"bash {promote}"}
    with lock.detection_running(runs):
        r = subprocess.run([sys.executable, str(ROOT / "scripts/part_b.py"), "--name", "t", "--run", str(runs / "r"),
                            "--auto-promote", "--runs-dir", str(runs), "--models-dir", str(tmp_path / "m")],
                           cwd=tmp_path, env=env, capture_output=True, text=True)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "PROMOTED" not in r.stdout and not (ROOT / "PROMOTED_CALLED").exists()
    assert "detection is running" in r.stdout or "run_pipeline.sh is running" in r.stdout


def test_dashboard_run_pipeline_holds_lock():
    src = (ROOT / "dashboard/server.py").read_text(encoding="utf-8")
    assert "PIPELINE_LOCK.detection_running(ROOT / \"runs\")" in src


# ── C2: console promote goes through part_b in capstone mode ─────────────────
@pytest.fixture
def registry(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    import tempfile
    os.environ.setdefault("TRAINGUI_HOME", tempfile.mkdtemp(prefix="traingui_test_"))
    sys.path.insert(0, str(ROOT / "dashboard" / "training-gui"))
    from core import registry as R, settings as S, jobs
    monkeypatch.setattr(S, "MODE", "capstone")
    monkeypatch.setattr(S, "RUNS", tmp_path / "runs")
    monkeypatch.setattr(S, "REGISTRY", tmp_path / "registry.json")
    models = []
    for i, seed in enumerate((42, 43, 44)):
        rid = f"run{i}"
        (S.RUNS / rid / "model").mkdir(parents=True)
        models.append({"version": f"v{i + 1}", "run_id": rid, "created": "", "dataset": "d", "train_path": "both",
                       "params": {"seed": seed, "n": 5}, "metrics": {"f1": 0.9}, "trainer": "pipeline"})
    S.REGISTRY.write_text(json.dumps({"models": models, "production": None, "history": []}))
    monkeypatch.setattr(jobs, "list_jobs", lambda n=500: [])
    monkeypatch.setattr(R, "_deploy", lambda m: pytest.fail("capstone promote must not copy folders directly"))
    return R


def test_console_promote_uses_part_b_with_all_seeds(registry, monkeypatch):
    seen = {}

    def fake(name, dirs):
        seen["dirs"] = [str(d) for d in dirs]
        return 0, f"✓ promoted {dirs[1]} (seed 43)"
    monkeypatch.setattr(registry, "_run_part_b", fake)
    out = registry.promote("v1", force=False)
    assert len(seen["dirs"]) == 3
    assert out["production"] == "v2", "production = the median seed part_b chose"


def test_console_promote_force_cannot_skip_gate(registry, monkeypatch):
    monkeypatch.setattr(registry, "_run_part_b", lambda name, dirs: (1, "✗ gate FAIL"))
    with pytest.raises(RuntimeError, match="gate failed"):
        registry.promote("v1", force=True)
    assert registry._load()["production"] is None


def test_console_rollback_uses_rollback_script(registry, monkeypatch):
    reg = registry._load()
    reg["production"], reg["history"] = "v2", [{"version": "v1", "at": ""}, {"version": "v2", "at": ""}]
    registry._save(reg)
    calls = []
    monkeypatch.setattr(registry, "_run_project", lambda cmd: (calls.append(cmd), (0, "ok"))[1])
    assert registry.rollback() == {"production": "v1"}
    assert calls == ["bash scripts/rollback_model.sh"]
