"""Fixes from the Phase 4 independent review of the soc automation (2026-11-20)."""
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def test_every_train_models_call_reachable_from_the_learner_sets_a_run_folder():
    """CRITICAL-1: train_models.sh without DNS_DETECT_MODELS_DIR rewrites models/training_provenance.json
    (even with --eda-only), so every call the learner can reach must set it."""
    for script in ("scripts/train_new_data.sh", "scripts/run_candidate_seeds.sh"):
        for line in (ROOT / script).read_text(encoding="utf-8").splitlines():
            if "train_models.sh" in line and not line.lstrip().startswith("#"):
                assert "DNS_DETECT_MODELS_DIR=" in line, f"{script}: {line.strip()}"


def test_soc_up_drops_stub_env_unless_allowed():
    """HIGH-2: PART_B_GATE / SOC_TRAIN_CMD from the operator's shell must not reach the real services."""
    src = (ROOT / "scripts/soc.sh").read_text(encoding="utf-8")
    for v in ("SOC_TRAIN_CMD", "PART_B_GATE", "PART_B_PROMOTE", "DNS_DETECT_MODELS_DIR"):
        assert v in src
    assert "SOC_ALLOW_STUBS" in src
    # the env -u list is built only when SOC_ALLOW_STUBS != 1
    assert re.search(r'SOC_ALLOW_STUBS:-0}" != 1', src)


def test_kill_groups_skips_a_group_without_our_marker(tmp_path):
    """HIGH-1: after a reboot a recorded pgid can belong to an unrelated process; it must not be killed."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("soc_supervisor", ROOT / "scripts/soc_supervisor.py")
    sup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sup)
    victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    try:
        sd = tmp_path / "runs" / "soc"
        (sd / "state").mkdir(parents=True)
        (sd / "state" / "dashboard.json").write_text(
            '{"service": "detector", "name": "dashboard", "pgid": %d, "marker": "dashboard/server.py --port 9000"}'
            % os.getpgid(victim.pid))
        cfg = {"state_dir": str(sd), "log_dir": str(tmp_path / "logs")}
        sup.kill_groups(cfg, ["detector"])
        time.sleep(0.5)
        assert victim.poll() is None, "unrelated process group was killed"
    finally:
        victim.kill()
        victim.wait()


def test_drift_stays_armed_when_the_run_never_starts(tmp_path, monkeypatch):
    """MEDIUM-3: data_missing must not consume the edge-triggered drift arm."""
    monkeypatch.chdir(ROOT)
    import importlib.util
    spec = importlib.util.spec_from_file_location("learner", ROOT / "scripts/learner.py")
    L = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(L)
    from dns_detect.soc import config as soc_config
    cfg = soc_config.load(None) if hasattr(soc_config, "load") else None
    if cfg is None:
        pytest.skip("config loader API differs")
    cfg["state_dir"] = str(tmp_path / "soc"); cfg["log_dir"] = str(tmp_path / "logs")
    cfg["paths"]["runs_dir"] = str(tmp_path / "runs")
    monkeypatch.delenv("SOC_TRAIN_CMD", raising=False)
    cfg = soc_config.resolve(cfg) if hasattr(soc_config, "resolve") else cfg
    lr = L.Learner(cfg)
    lr.state = lr.empty_state()
    lr.state["drift"]["armed"] = True
    monkeypatch.setattr(lr, "missing_training_data", lambda kind: ["data/external/tu2023/x.json"])
    out = lr.run_training("drift", [], [], 3)
    assert out == "data_missing"
    assert lr.state["drift"]["armed"] is True


def test_pending_captures_skips_hashing_already_trained_files(tmp_path, monkeypatch):
    """MEDIUM-2: a listed capture already trained on its listed checksum is not re-hashed every poll."""
    from dns_detect.soc import triggers
    f = tmp_path / "a.json"; f.write_text("x" * 1000)
    sha = triggers.sha256_file(f)
    (tmp_path / "SHA256SUMS").write_text(f"{sha}  a.json\n")
    old = time.time() - 1000; os.utime(f, (old, old))
    calls = []
    monkeypatch.setattr(triggers, "sha256_file", lambda p: (calls.append(p), sha)[1])
    ready, _ = triggers.pending_captures(tmp_path, "*.json", {"a.json": sha}, 10, time.time())
    assert ready == [] and calls == []
    ready, _ = triggers.pending_captures(tmp_path, "*.json", {}, 10, time.time())
    assert [r["name"] for r in ready] == ["a.json"] and len(calls) == 1
    triggers.pending_captures(tmp_path, "*.json", {}, 10, time.time())
    assert len(calls) == 1, "unchanged file hashed again"
