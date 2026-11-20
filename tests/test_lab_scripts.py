"""Week 7 Task 2 automation: scripts/lab_capture.sh (dry run) and scripts/train_new_data.sh (--check-only)."""
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _project(tmp_path):
    proj = tmp_path / "proj"
    (proj / "scripts").mkdir(parents=True)
    (proj / "models").mkdir()
    for s in ("lab_capture.sh", "train_new_data.sh"):
        shutil.copy(ROOT / "scripts" / s, proj / "scripts" / s)
    return proj


def _write(p, rows):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rows))


def _setup_data(proj, new_benign_type="TXT"):
    _write(proj / "data/old/a.json", [{"domain": f"x{i}.t.ex", "query_type": "TXT", "label": 1} for i in range(100)])
    _write(proj / "data/old/b.json", [{"domain": f"w{i}.ex.com", "query_type": "A", "label": 0} for i in range(100)])
    (proj / "models/training_provenance.json").write_text(json.dumps(
        {"source_files": [{"path": "data/old/a.json"}, {"path": "data/old/b.json"}]}))
    wk = proj / "data/processed/week7"
    _write(wk / "tunnels_iodine_a.json", [{"domain": f"q{i}.t1.zone1.lab", "query_type": "A", "label": 1} for i in range(50)])
    _write(wk / "benign_mail_b2.json", [{"domain": f"e{i}.com", "query_type": new_benign_type, "label": 0} for i in range(30)])
    subprocess.run("sha256sum data/processed/week7/*.json > data/processed/week7/SHA256SUMS",
                   shell=True, cwd=proj, check=True)
    return wk


def _check(proj):
    return subprocess.run(["bash", "scripts/train_new_data.sh", "data/processed/week7", "--check-only"],
                          cwd=proj, capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "RUN_NAME": "t"})


def test_check_only_reports_rule_no_longer_perfect(tmp_path):
    proj = _project(tmp_path)
    wk = _setup_data(proj)
    r = _check(proj)
    assert r.returncode == 0, r.stderr
    assert "no longer perfect" in r.stdout
    files = (wk / "files_t.txt").read_text().split()
    assert files[:2] == ["data/old/a.json", "data/old/b.json"] and len(files) == 4
    rep = json.loads((wk / "check_t.json").read_text())
    assert rep["rule_record_type"]["perfect"] is False and rep["attack_rows"] == 150


def test_check_only_stops_on_changed_file(tmp_path):
    proj = _project(tmp_path)
    wk = _setup_data(proj)
    with open(wk / "benign_mail_b2.json", "a") as f:
        f.write(" ")
    r = _check(proj)
    assert r.returncode != 0 and "checksum mismatch" in r.stderr


def test_check_only_stops_when_live_training_file_missing(tmp_path):
    proj = _project(tmp_path)
    _setup_data(proj)
    (proj / "data/old/b.json").unlink()
    r = _check(proj)
    assert r.returncode != 0 and "data/old/b.json" in r.stderr


def test_rule_still_perfect_is_reported(tmp_path):
    proj = _project(tmp_path)
    wk = _setup_data(proj, new_benign_type="A")
    _write(wk / "tunnels_iodine_a.json", [{"domain": "q.t1.zone1.lab", "query_type": "TXT", "label": 1}] * 10)
    subprocess.run("sha256sum data/processed/week7/*.json > data/processed/week7/SHA256SUMS", shell=True, cwd=proj, check=True)
    r = _check(proj)
    assert r.returncode == 0 and "still PERFECT" in r.stdout


def test_lab_capture_dry_run_runs_the_whole_chain(tmp_path):
    proj = _project(tmp_path)
    r = subprocess.run(["bash", "scripts/lab_capture.sh", "a2"], cwd=proj, capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "DRY_RUN": "1", "HOME": str(tmp_path)})
    assert r.returncode == 0, r.stderr
    out = r.stdout
    order = ["capture_dns.sh -o captures/a2", "iodined -f -c -P Lab123 10.99.0.1 t2.zone2.lab",
             "iodine -r -T CNAME", "ping -q -c 3000", "make_labeled_features.py --label 1 --family iodine_cname --domain t2.zone2.lab"]
    pos = [out.index(s) for s in order]
    assert pos == sorted(pos)


def test_lab_capture_rejects_unknown_capture(tmp_path):
    proj = _project(tmp_path)
    r = subprocess.run(["bash", "scripts/lab_capture.sh", "convert", "zz"], cwd=proj, capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin", "DRY_RUN": "1"})
    assert r.returncode != 0 and "unknown capture" in r.stderr
