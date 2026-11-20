"""Shadow check (scripts/shadow_check.py) and its place in part_b.py --shadow. Stubs only."""
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("shadow_check", ROOT / "scripts/shadow_check.py")
SC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SC)
T = dict(SC.DEFAULTS)


def rows(labels):
    return [{"row_id": i, "ml_combined_label": l} for i, l in enumerate(labels)]


def test_identical_candidate_passes():
    live = rows([1] * 50 + [0] * 450)
    stats = SC.compare(live, live)
    ok, checks = SC.verdict(stats, T)
    assert ok and stats["agreement"] == 1.0 and stats["new_flags"] == 0


def test_candidate_that_floods_alerts_fails():
    live = rows([1] * 50 + [0] * 450)
    cand = rows([1] * 300 + [0] * 200)
    ok, checks = SC.verdict(SC.compare(live, cand), T)
    assert ok is False and not [c for c in checks if c["check"] == "flag rate"][0]["ok"]


def test_candidate_that_silently_drops_detections_fails_on_agreement():
    live = rows([1] * 100 + [0] * 400)
    cand = rows([0] * 500)                       # misses every tunnel the live model sees
    ok, checks = SC.verdict(SC.compare(live, cand), T)
    assert ok is False and not [c for c in checks if c["check"] == "agreement"][0]["ok"]


def test_too_few_rows_gives_no_verdict():
    live = rows([1, 0] * 20)
    ok, checks = SC.verdict(SC.compare(live, live), T)
    assert ok is None and checks[0]["check"] == "rows"


def test_rows_are_matched_by_row_id_not_position():
    live = rows([1] * 150 + [0] * 150)
    cand = list(reversed(rows([1] * 150 + [0] * 150)))   # same labels per row_id, different order
    assert SC.compare(live, cand)["agreement"] == 1.0


def test_cli_exit_4_without_live_traffic(tmp_path):
    r = subprocess.run([sys.executable, str(ROOT / "scripts/shadow_check.py"), "--candidate", str(tmp_path),
                        "--features", str(tmp_path / "none.json"), "--live-ml", str(tmp_path / "none2.json"),
                        "--out", str(tmp_path / "rep.json")], capture_output=True, text=True)
    assert r.returncode == 4 and json.loads((tmp_path / "rep.json").read_text())["exit"] == 4


# ── part_b.py --shadow ────────────────────────────────────────────────────────
GATE = """import json, sys
a = sys.argv; out = a[a.index("--out") + 1]; runs = a[a.index("--runs") + 1:a.index("--out")]
json.dump({"seeds": [{"run": r, "seed": 42 + i, "candidate": {"false_alarms": 5}} for i, r in enumerate(runs)]}, open(out, "w"))
"""


@pytest.fixture
def lab(tmp_path):
    runs, models = tmp_path / "runs", tmp_path / "models"
    runs.mkdir(); models.mkdir(); (models / "m.txt").write_text("live")
    (tmp_path / "gate.py").write_text(GATE)
    (tmp_path / "promote.py").write_text("import pathlib,os\npathlib.Path(os.environ['M'], 'm.txt').write_text('promoted')\n")
    (tmp_path / "smoke.py").write_text("")
    env = {**os.environ, "M": str(models), "PART_B_GATE": f"{sys.executable} {tmp_path / 'gate.py'}",
           "PART_B_PROMOTE": f"{sys.executable} {tmp_path / 'promote.py'}",
           "PART_B_SMOKE": f"{sys.executable} {tmp_path / 'smoke.py'}"}
    return tmp_path, runs, models, env


def part_b(lab, shadow_rc, *flags):
    tmp, runs, models, env = lab
    (tmp / "shadow.py").write_text(f"import sys; sys.exit({shadow_rc})")
    env = {**env, "PART_B_SHADOW": f"{sys.executable} {tmp / 'shadow.py'}"}
    return subprocess.run([sys.executable, str(ROOT / "scripts/part_b.py"), "--name", "c", "--seeds", "42 43 44",
                           "--runs-dir", str(runs), "--models-dir", str(models), *flags],
                          env=env, capture_output=True, text=True, cwd=tmp)


def test_shadow_fail_blocks_promote_exit_5(lab):
    r = part_b(lab, 1, "--shadow", "--auto-promote")
    assert r.returncode == 5, r.stdout + r.stderr
    assert (lab[2] / "m.txt").read_text() == "live"
    last = json.loads((lab[1] / "promotion_log.jsonl").read_text().splitlines()[-1])
    assert last["shadow"] == "FAIL" and last["promoted"] is False


def test_shadow_pass_then_promote(lab):
    r = part_b(lab, 0, "--shadow", "--auto-promote")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (lab[2] / "m.txt").read_text() == "promoted"


def test_shadow_no_verdict_does_not_block(lab):
    r = part_b(lab, 4, "--shadow")
    assert r.returncode == 10 and "no verdict" in r.stdout


def test_without_flag_shadow_is_not_run(lab):
    tmp = lab[0]
    (tmp / "shadow.py").write_text("import pathlib; pathlib.Path('SHADOW_RAN').touch(); raise SystemExit(1)")
    r = part_b(lab, 1)
    assert r.returncode == 10 and not (tmp / "SHADOW_RAN").exists()
