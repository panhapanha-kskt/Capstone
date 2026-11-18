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
        rows.append(f"{rng.normal() + (3 if attack else 0):.4f},{rng.normal():.4f},{i % 7},{'dnstunnel' if attack else 'safe'}")
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
    assert m["trainer"] == "feature_table" and m["f1"] > 0.5 and "25% hold-out" in m["test_data"]
    meta = json.loads((S.RUNS / j["run_id"] / "model" / "model_meta.json").read_text())
    assert meta["label_map"] == {"dnstunnel": "attack", "safe": "benign"} and meta["rows_read"] == 4000
    assert meta["attack_rows"] == 100 and meta["benign_sample_rate"] == 1.0
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
    for route in ('"#/train?dataset="', '"#/runs/"', '"#/data?dataset="', 'href="#/models/${', 'href="#/runs/${'):
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
