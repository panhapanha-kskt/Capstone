"""Training console: pipeline compatibility check, API additions and page structure.

Regression tests for the 2026-11-19 UX/routing work: DNSTunnel2026's aggregated train.csv was
reported "Ready to train" although scripts/train_models.sh cannot use it; the page had no URL
routes, step status or next actions."""

import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pandas")
pytest.importorskip("httpx")

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("TRAINGUI_HOME", tempfile.mkdtemp(prefix="traingui_test_"))   # before core.settings is imported
os.environ.setdefault("ADMIN_TOKEN", "test-token")
sys.path.insert(0, str(ROOT / "dashboard" / "training-gui"))

from fastapi.testclient import TestClient  # noqa: E402

from api import main  # noqa: E402
from core import data, jobs, registry  # noqa: E402
from core import settings as S  # noqa: E402

TOKEN = {"X-Admin-Token": os.environ["ADMIN_TOKEN"]}
PAGE = ROOT / "dashboard" / "training-gui" / "api" / "static" / "index.html"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for p in S.DATASETS.iterdir():
        p.unlink()
    for p in S.RUNS.iterdir():
        shutil.rmtree(p)
    S.REGISTRY.unlink(missing_ok=True)
    monkeypatch.setattr(S, "MODE", "capstone")
    monkeypatch.setattr(S, "PRODUCTION", Path(tempfile.mkdtemp(prefix="traingui_prod_")))   # no live model
    monkeypatch.setattr(S, "REQUIRE_LABEL", False)
    monkeypatch.setattr(S, "VALIDATE_SAMPLE_ROWS", 200_000)
    yield


def _write(name, header, rows):
    (S.DATASETS / name).write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    return name


AGG_HEADER = ("hits,domain_data_portion,fqdn_count,fqdn_hit_ratio,unique_dns_types,dns_type_A_count,"
              "dns_type_TXT_ratio,file_chunk_detection_positive_ratio,label")


def _aggregated(name="agg.csv", n=200):
    return _write(name, AGG_HEADER,
                  [f"{i},0.0001,1,1.0,1,1,0.0,0.0,{'dnstunnel' if i % 50 == 0 else 'safe'}" for i in range(n)])


def _raw(name="raw.csv", n=200, header="timestamp,client_ip,domain,label", label=lambda i: int(i % 10 == 0)):
    return _write(name, header,
                  [f"2026-11-18T10:{i // 60 % 60:02d}:{i % 60:02d},10.0.0.{i % 5},q{i}.example.com,{label(i)}" for i in range(n)])


# ── pipeline compatibility (core/data.validate_csv, capstone mode) ──────────────

def test_raw_query_csv_passes_the_pipeline_check():
    r = data.validate_csv(_raw())
    assert r["ok"] is True and r["errors"] == []
    assert r["pipeline"] == {"compatible": True, "query_column": "domain", "path_b_ready": True}
    assert not any("Path B" in w or "0/1" in w for w in r["warnings"])


def test_labelled_feature_table_goes_to_the_feature_table_trainer():
    r = data.validate_csv(_aggregated())
    assert r["ok"] is True and r["kind"] == "feature_table" and r["check_version"] == data.CHECK_VERSION
    assert r["pipeline"]["compatible"] is False and r["pipeline"]["query_column"] is None   # not fooled by domain_data_portion
    assert r["label_roles"] == {"dnstunnel": "attack", "safe": "benign"}
    assert any("feature-table trainer" in n and "not promoted" in n for n in r["notes"])


def test_unlabelled_feature_table_is_rejected_with_an_actionable_message():
    name = _write("nolabel.csv", "hits,domain_data_portion,fqdn_count", [f"{i},0.1,1" for i in range(200)])
    r = data.validate_csv(name)
    assert r["ok"] is False and r["kind"] == "unsupported"
    msg = " ".join(r["errors"])
    assert "pre-aggregated features (3 columns such as hits, domain_data_portion" in msg
    assert "needs raw DNS query records" in msg and "needs a label column" in msg


@pytest.mark.parametrize("values,expected", [
    (["safe", "dnstunnel"], {"safe": "benign", "dnstunnel": "attack"}),
    (["0", "1"], {"0": "benign", "1": "attack"}),
    (["normal", "weird"], {"normal": "benign", "weird": "attack"}),          # the only other value
    (["benign", "dga", "exfiltration"], {"benign": "benign", "dga": "attack", "exfiltration": "attack"}),
    (["red", "blue"], {"red": None, "blue": None}),                          # unknown: admin must choose
])
def test_label_role_suggestions(values, expected):
    assert data.suggest_label_roles(values) == expected


def test_text_labels_and_missing_path_b_columns_are_warnings():
    name = _write("q.csv", "query,label", [f"a{i}.example.com,{'dnstunnel' if i % 10 == 0 else 'safe'}" for i in range(200)])
    r = data.validate_csv(name)
    assert r["ok"] is True and r["kind"] == "raw_queries"
    assert r["pipeline"] == {"compatible": True, "query_column": "query", "path_b_ready": False}
    assert any("No timestamp, client_ip column" in w and "Path B" in w for w in r["warnings"])
    assert any("not 0/1" in n and "dnstunnel" in n for n in r["notes"])
    assert r["label_roles"] == {"dnstunnel": "attack", "safe": "benign"}


def test_week3_feature_files_still_count_as_compatible():
    name = _write("w3.csv", "entropy,subdomain_depth,first_label,label", [f"3.1,2,abc{i},{i % 2}" for i in range(200)])
    r = data.validate_csv(name)
    assert r["ok"] is True and r["pipeline"]["compatible"] is True


def test_demo_mode_keeps_its_own_rules(monkeypatch):
    monkeypatch.setattr(S, "MODE", "demo")
    monkeypatch.setattr(S, "REQUIRE_LABEL", True)
    r = data.validate_csv(_aggregated())
    assert "pipeline" not in r and r["ok"] is True      # demo trainer uses numeric columns + label


def test_train_refuses_an_incompatible_dataset_before_starting_a_job():
    c = TestClient(main.app)
    name = _write("nolabel.csv", "hits,fqdn_count", [f"{i},1" for i in range(200)])
    r = c.post("/api/train", headers=TOKEN, json={"dataset": name, "train_path": "both"})
    assert r.status_code == 422 and "pre-aggregated features" in r.json()["detail"]
    assert list(S.RUNS.iterdir()) == []


def test_train_needs_both_a_benign_and_an_attack_label():
    c = TestClient(main.app)
    r = c.post("/api/train", headers=TOKEN, json={"dataset": _aggregated(), "label_map": {"dnstunnel": "benign"}})
    assert r.status_code == 422 and "one label value marked benign and one marked attack" in r.json()["detail"]
    name = _write("colors.csv", "f1,f2,label", [f"{i},{i % 7},{'red' if i % 9 else 'blue'}" for i in range(200)])
    r = c.post("/api/train", headers=TOKEN, json={"dataset": name})
    assert r.status_code == 422 and "Choose benign, attack or ignore" in r.json()["detail"]
    assert list(S.RUNS.iterdir()) == []


def _wait(run_id, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        j = jobs.get_job(run_id)
        if j["status"] != "running":
            return j
        time.sleep(0.5)
    raise AssertionError("run did not finish")


def test_feature_table_run_trains_end_to_end_and_cannot_be_promoted():
    import numpy as np
    rng = np.random.default_rng(0)
    rows = []
    for i in range(4000):
        attack = i % 40 == 0
        rows.append(f"{rng.normal() + (6 if attack else 0):.4f},{rng.normal():.4f},{i % 7},{'dnstunnel' if attack else 'safe'}")
    name = _write("ft.csv", "f1,f2,f3,label", rows)
    c = TestClient(main.app)
    r = c.post("/api/train", headers=TOKEN, json={"dataset": name, "seed": 1, "test_size": 0.25})
    assert r.status_code == 200, r.text
    j = _wait(r.json()["run_id"])
    log = jobs.tail_log(j["run_id"])
    assert j["status"] == "done", log
    assert j["trainer"] == "feature_table" and j["train_path"] == "features"
    assert "using every row of the file" in log
    m = jobs.get_metrics(j["run_id"])
    # train_models.sh / Path A standard: 72/14/14 per class, FPR-budget threshold, calibration, capping
    assert m["trainer"] == "feature_table" and m["f1"] > 0.5 and "14% test split" in m["test_data"]
    assert m["max_fpr"] == 0.001 and m["fpr"] <= 0.01
    meta = json.loads((S.RUNS / j["run_id"] / "model" / "model_meta.json").read_text())
    assert meta["label_map"] == {"dnstunnel": "attack", "safe": "benign"} and meta["rows_read"] == 4000
    assert meta["attack_rows"] == 100 and meta["benign_sample_rate"] == 1.0
    assert meta["split_rows"] == {"train": 2880, "validation": 560, "test": 560}      # 72 / 14 / 14 of 4,000
    assert meta["split"].startswith("per_class_random") and meta["clip_quantile"] == 0.999
    assert meta["threshold_rule"] == "false alarms on benign validation rows <= 0.001"
    assert "isotonic" in meta["model"] and "standard (as train_models.sh / Path A)" in log
    ms = c.get("/api/models", headers=TOKEN).json()
    assert len(ms) == 1 and ms[0]["deployable"] is False and ms[0]["trainer"] == "feature_table"
    r = c.post(f"/api/models/{ms[0]['version']}/promote", headers=TOKEN, json={"force": True})
    assert r.status_code == 409 and "can't be promoted" in r.json()["detail"]
    assert c.get(f"/api/models/{ms[0]['version']}/compare", headers=TOKEN).json()["deployable"] is False


def test_raw_query_csv_labels_are_mapped_to_0_1_for_the_pipeline(tmp_path):
    from adapters import capstone_train as ct
    assert not ct.needs_label_mapping({"0": "benign", "1": "attack"})
    assert ct.needs_label_mapping({"safe": "benign", "dnstunnel": "attack"})
    src = tmp_path / "q.csv"
    src.write_text("domain,label\na.com,safe\nb.com,dnstunnel\nc.com,junk\nd.com,\ne.com,other\n")
    out = ct.map_labels(src, tmp_path / "out.csv", {"safe": "benign", "dnstunnel": "attack", "junk": "ignore"})
    assert out.read_text().splitlines() == ["domain,label", "a.com,0", "b.com,1", "d.com,", "e.com,"]


# ── API additions ────────────────────────────────────────────────────────────

def test_models_status_names_the_live_and_previous_version():
    c = TestClient(main.app)
    assert c.get("/api/models/status", headers=TOKEN).json() == {"production": None, "previous": None, "history": []}
    S.REGISTRY.write_text(json.dumps({"models": [], "production": "v2",
                                      "history": [{"version": "v1", "at": "x"}, {"version": "v2", "at": "y"}]}))
    assert c.get("/api/models/status", headers=TOKEN).json() == {"production": "v2", "previous": "v1", "history": ["v1", "v2"]}
    assert c.get("/api/models/status").status_code == 401


def test_finished_runs_report_their_finish_time():
    d = S.RUNS / "20261119-000000-abcd"
    d.mkdir()
    (d / "job.json").write_text(json.dumps({"run_id": d.name, "dataset": "raw.csv", "train_path": "both",
                                            "params": {}, "started": "2026-11-19T00:00:00+00:00", "pid": 999999}))
    assert "finished" not in jobs.get_job(d.name) or jobs.get_job(d.name)["status"] != "done"
    (d / "exitcode").write_text("0")
    j = jobs.get_job(d.name)
    assert j["status"] == "done" and j["finished"].startswith("20")


# ── page structure (index.html) ──────────────────────────────────────────────

@pytest.fixture(scope="module")
def page():
    return PAGE.read_text(encoding="utf-8")


def test_steps_are_page_navigation_links_not_aria_tabs(page):
    assert 'role="tab' not in page and "aria-selected" not in page
    nav = page[page.index('<nav aria-label="Training steps">'):page.index("</nav>")]
    for step in ("data", "train", "runs", "models"):
        assert f'href="#/{step}"' in nav
    assert 'setAttribute("aria-current","page")' in page
    assert page.count('<h2 tabindex="-1">') == 4


def test_hash_routes_drive_the_page(page):
    assert 'window.addEventListener("hashchange",render)' in page
    for route in ('"#/train?dataset="', '"#/runs/"', 'href="#/data?dataset=${', 'href="#/models/${', 'href="#/runs/${'):
        assert route in page
    assert 'location.replace("#/data")' in page          # unknown routes fall back to Data
    assert "document.title=" in page


def test_polling_only_runs_on_the_runs_step(page):
    assert page.count("setInterval(") == 1
    runs_view = page[page.index("async function viewRuns"):page.index("async function pollRuns")]
    assert "setInterval(" in runs_view
    render = page[page.index("async function render"):page.index("// ── Step status")]
    assert "stopPolling();" in render


def test_no_silently_swallowed_errors(page):
    assert not re.search(r"catch\(\s*\(\s*\)\s*=>\s*(\{\s*\}|null|undefined)\s*\)", page)
    assert not re.search(r"catch\s*\(\s*\w*\s*\)\s*\{\s*\}", page)


def test_labels_are_a_general_setting_not_pcap_only(page):
    assert 'id="labelrows"' in page and 'id="pcaprow"' in page
    assert ">Label for .pcap files<" not in page
    start = page[page.index('$("start").onclick'):page.index("// ── 3. Runs")]
    assert "label_map:labelMap()" in start and "labelProblem(kind)" in start
    assert "CHECK_VERSION=2" in page and "p.v===CHECK_VERSION" in page


def test_training_is_blocked_until_a_dataset_passed_the_check(page):
    train = page[page.index("async function viewTrain"):page.index("function drawReview")]
    assert "Blocked: check a dataset first" in train and "passed(name)" in train
    start = page[page.index('$("start").onclick'):page.index("// ── 3. Runs")]
    assert 'go("#/runs/"' in start and '$("start").disabled=true' in start


# ── multi-file datasets (train_models.sh --files) and split choice ───────────────

@pytest.fixture
def project(tmp_path, monkeypatch):
    """A tiny project tree: data/ with training files, outputs that must be hidden, and splits."""
    d = tmp_path / "data"
    (d / "processed" / "splits").mkdir(parents=True)
    (d / "external" / "cic").mkdir(parents=True)
    (d / "raw").mkdir()
    rec = lambda lab, n: json.dumps([{"domain": f"q{i}.example.com", "timestamp": f"2026-11-18T10:00:{i % 60:02d}",
                                      "client_ip": "10.0.0.1", "label": lab} for i in range(n)])
    (d / "processed" / "labeled_tunnels.json").write_text(rec(1, 30))
    (d / "processed" / "labeled_benign.json").write_text(rec(0, 50))
    (d / "external" / "cic" / "cic_benign_train.json").write_text(rec(0, 20))
    (d / "raw" / "2026-03-18.log").write_text("x")
    for hidden in ("merged_features_all.json", "week4_unified_alerts.json", "merge_report.json"):
        (d / "processed" / hidden).write_text("[]")
    (d / "attack_manifest.example.csv").write_text("family,start,end\n")
    (d / "processed" / "splits" / "time_seed42.json").write_text("{}")
    (d / "processed" / "splits" / "capture_group_seed42.json").write_text("{}")
    monkeypatch.setattr(S, "PROJECT_DIR", tmp_path)
    for b in S.BUNDLES.iterdir():
        b.unlink()
    return tmp_path


PF = ["data/processed/labeled_tunnels.json", "data/processed/labeled_benign.json", "data/external/cic/cic_benign_train.json"]


def test_project_files_lists_training_data_only(project):
    paths = [f["path"] for f in data.list_project_files()]
    assert paths == ["data/external/cic/cic_benign_train.json", "data/processed/labeled_benign.json",
                     "data/processed/labeled_tunnels.json", "data/raw/2026-03-18.log"]


def test_combined_dataset_is_created_checked_listed_and_deleted(project):
    c = TestClient(main.app)
    r = c.post("/api/bundles", headers=TOKEN, json={"name": "labelled_v3", "files": [{"source": "project", "path": p} for p in PF]})
    assert r.status_code == 200 and r.json() == {"name": "bundle:labelled_v3", "files": 3}
    ds = {d["name"]: d for d in c.get("/api/datasets", headers=TOKEN).json()}
    assert ds["bundle:labelled_v3"]["kind"] == "bundle" and ds["bundle:labelled_v3"]["label"] == "labelled_v3 (3 files)"
    v = c.get("/api/datasets/bundle%3Alabelled_v3/validate", headers=TOKEN).json()
    assert v["ok"] is True and v["kind"] == "bundle" and v["class_counts"] == {"1": 30, "0": 70}
    assert [f["rows"] for f in v["files"]] == [30, 50, 20] and all(f["status"] == "ok" for f in v["files"])
    assert "train_models.sh (--files)" in v["notes"][0]
    assert c.post("/api/bundles/bundle%3Alabelled_v3/delete", headers=TOKEN).status_code == 200
    assert all(f.is_file() for f in (project / p for p in PF))          # data files are never deleted
    assert "bundle:labelled_v3" not in [d["name"] for d in c.get("/api/datasets", headers=TOKEN).json()]


@pytest.mark.parametrize("name,files,code,msg", [
    ("x", [{"source": "project", "path": "../secret.json"}, {"source": "project", "path": PF[0]}], 409, "only files inside the project's data/ folder"),
    ("x", [{"source": "project", "path": "README.md"}, {"source": "project", "path": PF[0]}], 409, "only files inside"),
    ("x", [{"source": "project", "path": PF[0]}, {"source": "project", "path": PF[0]}], 409, "at least two different files"),
    ("x", [{"source": "project", "path": PF[0]}, {"source": "project", "path": "data/processed/nope.json"}], 404, "file not found"),
    ("x", [{"source": "upload", "path": "../a.csv"}, {"source": "project", "path": PF[0]}], 409, "not an uploaded dataset"),
    ("bad name!", [{"source": "project", "path": p} for p in PF[:2]], 409, "Name:"),
])
def test_combined_dataset_rejects_unsafe_or_invalid_input(project, name, files, code, msg):
    r = TestClient(main.app).post("/api/bundles", headers=TOKEN, json={"name": name, "files": files})
    assert r.status_code == code and msg in r.json()["detail"]
    assert list(S.BUNDLES.iterdir()) == []


def test_feature_tables_cannot_join_a_combined_dataset(project):
    agg = _aggregated()
    data.create_bundle("mix", [{"source": "upload", "path": agg}, {"source": "project", "path": PF[0]}])
    v = data.validate_csv("bundle:mix")
    assert v["ok"] is False and any(agg in e and "pre-aggregated feature table" in e for e in v["errors"])


def test_combined_dataset_and_split_become_the_train_models_command(project, tmp_path):
    from adapters.capstone_train import build_command
    raw = _raw("q.csv", label=lambda i: "dnstunnel" if i % 10 == 0 else "safe")
    data.create_bundle("v3", [{"source": "project", "path": PF[0]}, {"source": "project", "path": PF[1]},
                              {"source": "upload", "path": raw}])
    run = tmp_path / "run"
    run.mkdir()
    params = {"path_b_model": "iforest", "seed": 7, "split_manifest": str(data.split_path("capture_group_seed42.json")),
              "label_map": {"safe": "benign", "dnstunnel": "attack"}}
    cmd = build_command(params, "both", "all", run, "bundle:v3", data.dataset_path("bundle:v3"))
    i = cmd.index("--files")
    assert cmd[i + 1:i + 3] == [str(project / PF[0]), str(project / PF[1])] and len(cmd) == i + 4    # --files last
    assert cmd[i + 3] == str(run / f"labels01_2_{raw}")                    # text labels -> 0/1 copy
    assert (run / f"labels01_2_{raw}").read_text().splitlines()[1].endswith(",1")
    assert cmd[cmd.index("--split-manifest") + 1].endswith("capture_group_seed42.json")
    assert cmd[cmd.index("--path-b-model") + 1] == "iforest" and "--force-retrain" in cmd
    assert "--split-manifest" not in build_command({**params, "new_split": True}, "both", "all", run, "bundle:v3",
                                                   data.dataset_path("bundle:v3"))


def test_splits_are_listed_and_unknown_splits_refused(project):
    c = TestClient(main.app)
    assert c.get("/api/splits", headers=TOKEN).json() == [
        {"name": "capture_group_seed42.json", "size_kb": 0.0, "default": False},
        {"name": "time_seed42.json", "size_kb": 0.0, "default": True}]
    for bad in ("../../etc/passwd", "nope.json"):
        r = c.post("/api/train", headers=TOKEN, json={"dataset": _raw(), "split_manifest": bad})
        assert r.status_code in (404, 409)
    assert list(S.RUNS.iterdir()) == []


def test_page_offers_combined_datasets_and_split_choice(page):
    assert 'id="bnew"' in page and 'api("/bundles"' in page and 'api("/project-files")' in page
    assert 'id="sp"' in page and "split_manifest:" in page and 'api("/splits")' in page


def test_a_stored_sign_in_hides_the_gate_after_a_refresh(page):
    """Regression (browser check 2026-11-19): after reload the gate stayed on top and every step rendered empty."""
    boot = page[page.index("async function boot"):page.index("if(token)boot()")]
    ok_path = boot[:boot.index("catch(e)")]
    assert '$("gate").hidden=true' in ok_path


def test_step_2_is_a_confirm_page_with_train_models_defaults(page):
    train = page[page.index('<section id="train"'):page.index('<section id="runs"')]
    order = [train.index(x) for x in ('id="dscard"', 'id="labelpanel"', 'id="adv"', 'id="review"', 'id="start"')]
    assert order == sorted(order)                                   # dataset → labels → (advanced) → review → start
    assert '<details class="panel" id="adv">' in train                # settings closed by default
    for gone in ('id="ev"', 'id="fts"', 'id="mem"'):                  # fixed by the train_models.sh standard
        assert gone not in page
    assert 'const DEFAULTS={tp:"both",pb:"iforest",nd:"20",rt:"all",sd:"42",sp:""' in page
    check = page[page.index("async function check(name,btn)"):page.index("function showReport")]
    assert 'if(r.ok){setSelected(r.name);go("#/train?dataset="' in check   # a passed check opens step 2



# ── Windows server -> WSL / Git Bash (run 20261119-014540-c577 failed and pointed at the live models/) ──

@pytest.mark.parametrize("flavor,path,expected", [
    ("wsl", r"C:\Programming-CTF\Capstone\data\processed\labeled_tunnels.json", "/mnt/c/Programming-CTF/Capstone/data/processed/labeled_tunnels.json"),
    ("msys", r"D:\x\y.json", "/d/x/y.json"),
    ("unknown", r"C:\x\y.json", "C:/x/y.json"),
    ("posix", "/mnt/c/x/y.json", "/mnt/c/x/y.json"),
    ("wsl", "--force-retrain", "--force-retrain"),
    ("wsl", "iforest", "iforest"),
])
def test_paths_are_converted_for_the_bash_that_runs_train_models(flavor, path, expected):
    from adapters import capstone_train as ct
    assert ct.to_shell_path(path, flavor) == expected


def test_wsl_receives_the_run_model_folder(tmp_path):
    from adapters import capstone_train as ct
    env = ct.shell_env(tmp_path / "model", "wsl")
    assert env["DNS_DETECT_MODELS_DIR"] == str(tmp_path / "model") and env["WSLENV"].startswith("DNS_DETECT_MODELS_DIR/p")
    assert "WSLENV" not in ct.shell_env(tmp_path / "model", "posix") or os.environ.get("WSLENV")
    assert ct.same_dir("/mnt/c/A/runs/x/model/", "/mnt/c/a/runs/x/model") and not ct.same_dir("", "/x")


def _fake_train_env(monkeypatch, tmp_path, seen_models_dir):
    """Run capstone_train.main with a fake bash: returns what DNS_DETECT_MODELS_DIR looks like inside it."""
    import subprocess
    from adapters import capstone_train as ct
    run = tmp_path / "run"
    run.mkdir()
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["bash", "-c"]:
            out = "Linux 6.6.87.2-microsoft-standard-WSL2" if "uname" in cmd[2] else seen_models_dir(run / "model")
            return subprocess.CompletedProcess(cmd, 0, stdout=out + "\n", stderr="")
        return subprocess.CompletedProcess(cmd, 1)           # "train_models.sh" fails fast
    monkeypatch.setattr(ct.subprocess, "run", fake_run)
    monkeypatch.setattr(ct, "bash_flavor", lambda: "wsl")          # a Windows server whose bash is WSL
    monkeypatch.setenv("RUN_DIR", str(run))
    monkeypatch.setenv("DATASET_PATH", str(tmp_path))
    monkeypatch.setenv("DATASET_NAME", "project-default")
    monkeypatch.setenv("PARAMS_JSON", "{}")
    monkeypatch.setenv("PRODUCTION_DIR", str(tmp_path / "no-prod"))
    return ct, calls


def test_training_refuses_to_start_when_bash_would_use_the_live_models(monkeypatch, tmp_path, capsys):
    ct, calls = _fake_train_env(monkeypatch, tmp_path, lambda models: "")       # the variable did not arrive
    with pytest.raises(SystemExit) as e:
        ct.main()
    assert e.value.code == 3
    assert not any("scripts/train_models.sh" in c for c in calls)              # never started
    assert "Stopped before training so the live models/ folder is not overwritten" in capsys.readouterr().out


def test_training_starts_when_bash_sees_the_run_folder(monkeypatch, tmp_path, capsys):
    from adapters import capstone_train as ct0
    ct, calls = _fake_train_env(monkeypatch, tmp_path, lambda models: ct0.to_shell_path(models, "wsl"))
    with pytest.raises(SystemExit) as e:
        ct.main()
    assert e.value.code == 1                                                   # the fake train_models.sh "failed"
    started = [c for c in calls if "scripts/train_models.sh" in c]
    out = capsys.readouterr().out
    assert len(started) == 1 and f"models go to {tmp_path / 'run' / 'model'}" in out
    assert out.index("models go to") < out.index("scripts/train_models.sh")      # checked before starting


def test_run_log_is_read_as_utf8():
    d = S.RUNS / "20261119-000001-aaaa"
    d.mkdir()
    (d / "job.json").write_text(json.dumps({"run_id": d.name, "dataset": "x", "train_path": "both", "params": {},
                                            "started": "2026-11-19T00:00:00+00:00", "pid": 999999}))
    (d / "train.log").write_bytes("Training DNS models · log ✓ → done\n".encode("utf-8"))
    assert jobs.tail_log(d.name) == "Training DNS models · log ✓ → done"


# ── 2026-11-21: the live model in models/ counts as production; siblings = one run per seed, scoreable ──
def _reg_run(version, seed, scoreable=True):
    rid = f"run_{version}"
    d = S.RUNS / rid / "model"
    d.mkdir(parents=True, exist_ok=True)
    if scoreable:
        (d / "merged_features_labeled.json").write_text("[]")
        (d / "split_manifest.json").write_text("{}")
    return {"version": version, "run_id": rid, "created": "", "dataset": "d", "train_path": "both",
            "params": {"seed": seed, "n": 5}, "metrics": {"f1": 0.9}, "trainer": "pipeline"}


def test_siblings_one_run_per_seed_and_only_scoreable(monkeypatch):
    monkeypatch.setattr(jobs, "list_jobs", lambda n=500: [])
    reg = {"models": [_reg_run("v1", 42, scoreable=False), _reg_run("v2", 42), _reg_run("v3", 43),
                      _reg_run("v4", 42)], "production": None, "history": []}
    S.REGISTRY.write_text(json.dumps(reg))
    got = sorted(x["version"] for x in registry._siblings(registry._load(), reg["models"][3]))
    assert got == ["v3", "v4"], "v1 (not scoreable) and v2 (older seed-42 run) must not be counted"


def test_live_models_folder_is_shown_as_production(monkeypatch, tmp_path):
    monkeypatch.setattr(jobs, "list_jobs", lambda n=500: [])
    prod = tmp_path / "models"
    prod.mkdir()
    (prod / "evaluation_metrics.json").write_text(json.dumps(
        {"fusion": {"test": {"learned_lr": {"f1": 0.99, "precision": 0.98, "recall": 1.0, "fpr": 0.006, "false_alarms": 8}}}}))
    (prod / "PROMOTED.json").write_text(json.dumps({"source_run": "runs/v3_iforest", "promoted_at": "2026-11-19T08:03:12+00:00"}))
    monkeypatch.setattr(S, "PRODUCTION", prod)
    S.REGISTRY.write_text(json.dumps({"models": [_reg_run("v2", 42)], "production": None, "history": []}))
    ms = registry.list_models()
    live = [m for m in ms if m["is_production"]]
    assert len(live) == 1 and live[0]["run_id"] == "runs/v3_iforest" and live[0]["metrics"]["false_alarms"] == 8
    assert "runs/v3_iforest" in registry.status()["production"]
    cmp = registry.compare("v2")
    assert cmp["production"] == "live" and any(r["production"] is not None for r in cmp["rows"])


def test_promote_refuses_a_run_the_gate_cannot_score(monkeypatch):
    monkeypatch.setattr(jobs, "list_jobs", lambda n=500: [])
    S.REGISTRY.write_text(json.dumps({"models": [_reg_run("v1", 42, scoreable=False)], "production": None, "history": []}))
    monkeypatch.setattr(registry, "_run_part_b", lambda *a: pytest.fail("part_b must not run for an unscoreable run"))
    with pytest.raises(RuntimeError, match="can't go through the gate"):
        registry.promote("v1", force=True)


def test_page_has_no_override_prompt_in_capstone_mode():
    assert 'document.body.dataset.mode!=="demo")throw e' in PAGE.read_text(encoding="utf-8")


# ── Dataset delete (2026-11-26) ────────────────────────────────

def test_uploaded_dataset_can_be_deleted(project):
    c = TestClient(main.app)
    _write("old.csv", "query,label", ["a.example.com,0"])
    assert "old.csv" in [d["name"] for d in c.get("/api/datasets", headers=TOKEN).json()]
    r = c.post("/api/datasets/old.csv/delete", headers=TOKEN)
    assert r.status_code == 200 and r.json() == {"deleted": "old.csv"}
    assert not (S.DATASETS / "old.csv").exists()
    assert "old.csv" not in [d["name"] for d in c.get("/api/datasets", headers=TOKEN).json()]


def test_dataset_delete_needs_admin_token(project):
    _write("keep.csv", "query,label", ["a.example.com,0"])
    assert TestClient(main.app).post("/api/datasets/keep.csv/delete").status_code == 401
    assert (S.DATASETS / "keep.csv").is_file()


@pytest.mark.parametrize("name,code", [
    ("missing.csv", 404),
    ("project-default", 409),            # data/raw is never deleted from the console
    ("bundle:anything", 409),            # combined datasets use their own delete
    ("..%2Fsecret.csv", 404),            # no path tricks out of the datasets folder
])
def test_dataset_delete_refuses_non_uploads(project, name, code):
    assert TestClient(main.app).post(f"/api/datasets/{name}/delete", headers=TOKEN).status_code == code
    assert (project / "data" / "raw" / "2026-03-18.log").is_file()


def test_dataset_delete_refused_while_combined_dataset_uses_it(project):
    c = TestClient(main.app)
    _write("up.csv", "query,label", ["a.example.com,0"])
    r = c.post("/api/bundles", headers=TOKEN, json={"name": "mix", "files": [
        {"source": "upload", "path": "up.csv"}, {"source": "project", "path": PF[0]}]})
    assert r.status_code == 200
    r = c.post("/api/datasets/up.csv/delete", headers=TOKEN)
    assert r.status_code == 409 and "mix" in r.json()["detail"]
    assert (S.DATASETS / "up.csv").is_file()


def test_dataset_delete_refused_while_training_on_it(project, monkeypatch):
    _write("busy.csv", "query,label", ["a.example.com,0"])
    monkeypatch.setattr(jobs, "running_job", lambda: {"run_id": "r1", "dataset": "busy.csv", "status": "running"})
    r = TestClient(main.app).post("/api/datasets/busy.csv/delete", headers=TOKEN)
    assert r.status_code == 409 and "r1" in r.json()["detail"]
    assert (S.DATASETS / "busy.csv").is_file()


def test_page_offers_dataset_delete_with_confirmation():
    page = PAGE.read_text(encoding="utf-8")
    fn = page[page.index("async function deleteDataset"):page.index("async function deleteBundle")]
    assert "confirm(" in fn and "cannot be undone" in fn and '"/datasets/"+enc(name)+"/delete"' in fn
    assert 'data-delfile="' in page and 'button[data-delfile]' in page
