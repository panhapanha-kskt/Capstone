"""scripts/learner.py: the three triggers, cooldown, limits, locks, promotion flag, exit codes, allowlist.

Training is a stub (SOC_TRAIN_CMD) that only records how it was called; nothing is trained, the real gate is
never run, and every path (runs/, models/, captures, alert store, monitoring report) lives in tmp_path.
"""
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from dns_detect.soc import config as soc_config  # noqa: E402
from dns_detect.soc import triggers as T  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


L = _load("soc_learner", ROOT / "scripts" / "learner.py")

STUB = r'''import json, os, sys, time
a = sys.argv
run = a[a.index("--run") + 1] if "--run" in a else os.environ.get("RUN_NAME")
if "--name" in a:
    run = a[a.index("--name") + 1]
with open(os.environ["STUB_CALLS"], "a") as f:
    f.write(json.dumps({"argv": a, "AUTO_PROMOTE": os.environ.get("AUTO_PROMOTE"),
                        "FEEDBACK": os.environ.get("FEEDBACK"), "RUN_NAME": os.environ.get("RUN_NAME"),
                        "SEEDS": os.environ.get("SEEDS"), "FILES": os.environ.get("FILES"),
                        "nice": os.nice(0)}) + "\n")
rc = int(os.environ.get("STUB_RC", "10"))
pb = os.environ.get("STUB_PB")
if pb:
    row = {"time": "t", "git_commit": None, "name": run, "gate": "FAIL" if rc == 1 else "PASS",
           "promoted": rc == 0, "decision": pb, "chosen": "runs/%s_s42" % run}
    with open(os.path.join(os.environ["STUB_RUNS"], "promotion_log.jsonl"), "a") as f:
        f.write(json.dumps(row) + "\n")
if os.environ.get("STUB_TOUCH_MODELS"):
    open(os.environ["STUB_TOUCH_MODELS"], "w").write("changed %s" % time.time())
sys.exit(rc)
'''


class Lab:
    def __init__(self, tmp, monkeypatch):
        self.tmp = tmp
        self.runs, self.models, self.caps = tmp / "runs", tmp / "models", tmp / "week7"
        self.store = tmp / "dash" / "alert_management.json"
        self.report = tmp / "monitoring_report.json"
        for d in (self.runs, self.models, self.caps, self.store.parent):
            d.mkdir(parents=True)
        data = tmp / "live_train.json"
        data.write_text("[]")
        (self.models / "training_provenance.json").write_text(json.dumps({"source_files": [{"path": str(data)}]}))
        (self.models / "split_manifest.json").write_text("{}")
        (self.models / "model.txt").write_text("live")
        self.store.write_text(json.dumps({"schema_version": 1, "records": {}}))
        self.calls = tmp / "calls.jsonl"
        (tmp / "stub.py").write_text(STUB)
        self.stub = f"{sys.executable} {tmp / 'stub.py'}"
        for k in ("SOC_TRAIN_CMD", "SOC_EXPORT_CMD", "SOC_PART_B_CMD", "SOC_NOW", "SOC_AUTO_PROMOTE",
                  "AUTO_PROMOTE", "SOC_DASHBOARD_DATA_DIR", "FEEDBACK", "FILES", "STUB_PB", "STUB_TOUCH_MODELS"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("SOC_TRAIN_CMD", self.stub)
        monkeypatch.setenv("SOC_EXPORT_CMD", f"{sys.executable} -c pass")
        monkeypatch.setenv("SOC_PART_B_CMD", self.stub)
        monkeypatch.setenv("STUB_CALLS", str(self.calls))
        monkeypatch.setenv("STUB_RUNS", str(self.runs))
        monkeypatch.setenv("STUB_RC", "10")
        self.monkeypatch = monkeypatch
        self.cfg = soc_config._merge(soc_config.DEFAULTS, {
            "state_dir": str(tmp / "soc"), "log_dir": str(tmp / "logs"),
            "paths": {"runs_dir": str(self.runs), "models_dir": str(self.models)},
            "triggers": {"drift": {"report": str(self.report)},
                         "captures": {"dir": str(self.caps)},
                         "verdicts": {"store": str(self.store), "feedback_file": str(tmp / "fb.json")}},
            "training_priority": {"nice": 10, "ionice_class": None},
        })
        self.cfg.update(_python=sys.executable, _python_source="test", _config_file=None)
        self.t = time.time() + 3600          # files written now are already "settled"

    def learner(self, auto=False, **cfg):
        for k, v in cfg.items():
            self.cfg[k] = v
        return L.Learner(self.cfg, auto_promote=auto, clock=lambda: self.t, out=io.StringIO())

    def add_capture(self, name="cap1.json", listed=True, content='[{"label": 1}]', good_sum=True):
        p = self.caps / name
        p.write_text(content)
        if listed:
            sha = hashlib.sha256(content.encode()).hexdigest() if good_sum else "0" * 64
            with open(self.caps / "SHA256SUMS", "a") as f:
                f.write(f"{sha}  {name}\n")
        return p

    def add_verdicts(self, n, minutes_ago=120, start=0):
        d = json.loads(self.store.read_text())
        for i in range(start, start + n):
            at = T.iso(self.t - minutes_ago * 60 - i)
            d["records"][f"fp{i}"] = {"verdict": "false_positive", "verdict_at": at, "status": "Closed"}
        self.store.write_text(json.dumps(d))

    def write_report(self, recommended, tag):
        self.report.write_text(json.dumps({"retrain_recommended": recommended, "reasons": [tag]}))

    def calls_made(self):
        if not self.calls.exists():
            return []
        return [json.loads(x) for x in self.calls.read_text().splitlines()]

    def log_rows(self, source="learner"):
        p = self.runs / "promotion_log.jsonl"
        if not p.exists():
            return []
        rows = [json.loads(x) for x in p.read_text().splitlines()]
        return [r for r in rows if r.get("source") == source] if source else rows

    def state(self):
        return json.loads((self.tmp / "soc" / "learner_state.json").read_text())


@pytest.fixture
def lab(tmp_path, monkeypatch):
    return Lab(tmp_path, monkeypatch)


# ── (b) captures ─────────────────────────────────────────────────────────────
def test_capture_trigger_fires_on_new_listed_verified_file(lab):
    lr = lab.learner()
    lr.startup()
    lab.add_capture()
    assert lr.poll() == "ready"
    (call,) = lab.calls_made()
    assert call["argv"][-4:] == ["--trigger", "captures", "--run", call["RUN_NAME"]]
    assert call["RUN_NAME"].startswith("soc_captures_") and call["nice"] >= 10
    assert lab.state()["captures"]["trained"] == {"cap1.json": hashlib.sha256(b'[{"label": 1}]').hexdigest()}


def test_capture_trigger_ignores_unlisted_bad_sum_unsettled_and_trained(lab):
    lab.add_capture("unlisted.json", listed=False)
    lab.add_capture("bad.json", good_sum=False)
    young = lab.add_capture("young.json")
    os.utime(young, (lab.t - 10, lab.t - 10))
    done = lab.add_capture("done.json")
    trained = {"done.json": T.sha256_file(done)}
    ready, why = T.pending_captures(lab.caps, "*.json", trained, 120, lab.t)
    assert ready == []
    assert why == {"unlisted.json": "not in SHA256SUMS", "bad.json": "checksum mismatch", "young.json": "not settled"}
    lr = lab.learner()
    lr.startup()
    lr.state["captures"]["trained"] = trained
    assert lr.poll() is None and lab.calls_made() == []


def test_first_start_does_not_trigger_on_files_the_live_model_learned_from(lab):
    old = lab.add_capture("old.json")
    prov = json.loads((lab.models / "training_provenance.json").read_text())
    prov["source_files"].append({"path": str(old)})
    (lab.models / "training_provenance.json").write_text(json.dumps(prov))
    lab.add_verdicts(60)                                   # old verdicts: already there at first start
    lab.write_report(True, "r0")                           # the report on disk at first start does not count
    lr = lab.learner()
    lr.startup()
    assert lab.log_rows()[0]["event"] == "state_seeded"
    assert lr.poll() is None and lab.calls_made() == []
    lab.add_capture("new.json")
    assert lr.poll() == "ready"
    assert lab.calls_made()[0]["argv"][-3] == "captures"


# ── (c) verdicts ─────────────────────────────────────────────────────────────
def test_verdicts_49_do_not_fire_50_do(lab):
    lr = lab.learner()
    lr.startup()
    lab.add_verdicts(49)
    assert lr.poll() is None and lab.calls_made() == []
    lab.add_verdicts(1, start=49)
    assert lr.poll() == "ready"
    (call,) = lab.calls_made()
    assert call["FEEDBACK"] == str(lab.tmp / "fb.json") and call["argv"][-3] == "verdicts"
    st = lab.state()["verdicts"]
    assert st["trained_count"] == 50 and st["trained_until"] is not None


def test_unsettled_empty_demo_and_old_verdicts_are_not_counted(lab):
    recs = {
        "a": {"verdict": "true_positive", "verdict_at": T.iso(lab.t - 3600 * 2)},     # counted
        "b": {"verdict": "true_positive", "verdict_at": T.iso(lab.t - 60)},           # too fresh
        "c": {"verdict": None, "verdict_at": None},                                    # no verdict
        "d": {"verdict": "false_positive", "verdict_at": T.iso(lab.t - 3600 * 2), "demo": True},
        "e": {"verdict": "false_positive", "verdict_at": T.iso(lab.t - 3600 * 50)},   # before trained_until
    }
    got = T.settled_verdicts(recs, T.iso(lab.t - 3600 * 10), 60, lab.t)
    assert [fp for fp, _ in got] == ["a"]


def test_dashboard_data_dir_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_DASHBOARD_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SOC_CONFIG", str(tmp_path / "none.yaml"))
    cfg = soc_config.load()
    assert cfg["triggers"]["verdicts"]["store"] == str(tmp_path / "alert_management.json")


# ── (a) drift ────────────────────────────────────────────────────────────────
def test_drift_counts_distinct_reports_edge_triggered_and_rearms(lab):
    st = {}
    for i in range(2):
        lab.write_report(True, f"r{i}")
        st, _ = T.update_drift(st, lab.report)
    assert not T.drift_due(st, 3)
    st, changed = T.update_drift(st, lab.report)            # same report read again: not counted
    assert not changed and not T.drift_due(st, 3)
    lab.write_report(True, "r2")
    st, _ = T.update_drift(st, lab.report)
    assert T.drift_due(st, 3)
    st["armed"] = False                                      # fired
    lab.write_report(True, "r3")
    st, _ = T.update_drift(st, lab.report)
    assert not T.drift_due(st, 3)                            # 4th: edge-triggered, no new fire
    lab.write_report(False, "ok")
    st, _ = T.update_drift(st, lab.report)
    assert st["armed"] and st["consecutive"] == 0           # re-armed
    for i in range(3):
        lab.write_report(True, f"again{i}")
        st, _ = T.update_drift(st, lab.report)
    assert T.drift_due(st, 3)


def test_corrupt_report_and_store_do_not_crash_or_trigger(lab):
    lab.report.write_text("{not json")
    lab.store.write_text("garbage")
    lr = lab.learner()
    lr.startup()
    assert lr.poll() is None and lab.calls_made() == []


def test_drift_requires_new_data_by_default(lab):
    lr = lab.learner()
    lr.startup()
    for i in range(3):
        lab.write_report(True, f"r{i}")
        assert lr.poll() in (None, "drift_without_new_data")
    assert lab.calls_made() == []
    skips = [r for r in lab.log_rows() if r["event"] == "skipped"]
    assert len(skips) == 1 and skips[0]["reason"] == "drift_without_new_data"
    lab.write_report(True, "r3")
    assert lr.poll() is None and len([r for r in lab.log_rows() if r["event"] == "skipped"]) == 1


def test_drift_with_a_few_verdicts_trains_on_them(lab):
    lr = lab.learner()
    lr.startup()
    lab.add_verdicts(3)                                     # fewer than 50: (c) alone would not fire
    for i in range(3):
        lab.write_report(True, f"r{i}")
        out = lr.poll()
    assert out == "ready"
    (call,) = lab.calls_made()
    assert call["argv"][-3] == "drift" and call["FEEDBACK"]
    lab.write_report(True, "r4")
    lab.t += 2 * 86400
    assert lr.poll() is None                                 # edge-triggered: no second drift run


def test_drift_without_require_new_data_fires_once(lab):
    lab.cfg["triggers"]["drift"]["require_new_data"] = False
    lr = lab.learner()
    lr.startup()
    for i in range(3):
        lab.write_report(True, f"r{i}")
        out = lr.poll()
    assert out == "ready" and lab.calls_made()[0]["FEEDBACK"] is None


def test_priority_captures_then_verdicts_then_drift():
    caps, verds = [{"name": "x"}], [("fp", 1.0)] * 50
    assert T.choose(caps, verds, True, 50, True) == ("captures", None)
    assert T.choose([], verds, True, 50, True) == ("verdicts", None)
    assert T.choose([], verds[:3], True, 50, True) == ("drift", None)
    assert T.choose([], [], True, 50, True) == (None, "drift_without_new_data")
    assert T.choose([], [], False, 50, True) == (None, None)


# ── gates: cooldown, action limit, locks ─────────────────────────────────────
def test_cooldown_blocks_and_is_logged_once(lab):
    lr = lab.learner()
    lr.startup()
    lab.add_capture("a.json")
    assert lr.poll() == "ready"
    lab.add_capture("b.json")
    assert lr.poll() == "cooldown"
    assert lr.poll() == "cooldown"
    assert len([r for r in lab.log_rows() if r.get("reason") == "cooldown"]) == 1
    assert len(lab.calls_made()) == 1
    lab.t += 24 * 3600 + 1
    assert lr.poll() == "ready" and len(lab.calls_made()) == 2


def test_max_runs_per_day(lab):
    lr = lab.learner(cooldown_minutes=0, max_runs_per_day=2)
    lr.startup()
    for i in range(3):
        lab.add_capture(f"c{i}.json")
        out = lr.poll()
        lab.t += 60
    assert out == "action_limit" and len(lab.calls_made()) == 2


@pytest.mark.parametrize("which", ["learner", "promote"])
def test_lock_is_respected(lab, which):
    lr = lab.learner()
    lr.startup()
    lab.add_capture()
    path = lab.tmp / "soc" / "learner.lock" if which == "learner" else lab.runs / ".promote.lock"
    with open(path, "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        assert lr.poll() == "locked"
        assert lr.poll() == "locked"
    assert lab.calls_made() == []
    assert len([r for r in lab.log_rows() if r.get("reason") == "locked"]) == 1
    assert lr.poll() == "ready"                              # no cooldown after "locked"


def test_training_child_holds_the_learner_lock(lab):
    lab.monkeypatch.setenv("SOC_TRAIN_CMD", f"{sys.executable} -c \"import fcntl,sys; "
                           f"f=open(r'{lab.tmp / 'soc' / 'learner.lock'}','a'); "
                           f"sys.exit(0 if (lambda: fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB))() is None else 9)\"")
    lr = lab.learner()
    lr.startup()
    lab.add_capture()
    # the child can't take the lock the learner holds → BlockingIOError → exit 1 (not 0)
    assert lr.poll() == "error"


# ── promotion only when explicitly enabled ───────────────────────────────────
def test_promotion_refused_without_the_flag_even_if_parent_env_says_so(lab):
    lab.monkeypatch.setenv("AUTO_PROMOTE", "1")
    lab.cfg["auto_promote"] = "yes"                         # not a real boolean true → off
    lr = lab.learner()
    lr.startup()
    lab.add_capture()
    lr.poll()
    assert lab.calls_made()[0]["AUTO_PROMOTE"] is None


def test_promotion_flag_passed_when_enabled_and_weekly_limit(lab):
    lab.monkeypatch.setenv("STUB_RC", "0")
    lr = lab.learner(auto=True, cooldown_minutes=0)
    lr.startup()
    lab.add_capture("a.json")
    assert lr.poll() == "promoted"
    lab.t += 3600
    lab.add_capture("b.json")
    lr.poll()
    c = lab.calls_made()
    assert c[0]["AUTO_PROMOTE"] == "1" and c[1]["AUTO_PROMOTE"] is None   # max 1 auto-promotion per week
    assert any(r.get("reason") == "weekly auto-promote limit reached" for r in lab.log_rows())


def test_config_auto_promote_true_enables(lab):
    lab.cfg["auto_promote"] = True
    lr = lab.learner()
    lr.startup()
    lab.add_capture()
    lr.poll()
    assert lab.calls_made()[0]["AUTO_PROMOTE"] == "1"


def test_busy_promote_is_retried_then_left_for_a_human(lab):
    lab.monkeypatch.setenv("STUB_RC", "3")
    lab.monkeypatch.setenv("STUB_PB", L.BUSY_DECISION)
    lab.cfg["promote_retry"] = {"interval_s": 120, "max_attempts": 3}
    lr = lab.learner(auto=True)
    lr.startup()
    lab.add_capture()
    assert lr.poll() == "promote_busy"
    run = lab.state()["pending_promote"]["run"]
    assert lab.state()["captures"]["trained"]            # training finished: inputs marked
    outs = []
    for _ in range(3):
        lab.t += 121
        outs.append(lr.poll())
    assert outs == ["promote_retry:promote_busy"] * 3
    retry_calls = lab.calls_made()[1:]
    assert len(retry_calls) == 3 and all("--auto-promote" in c["argv"] and run in c["argv"] for c in retry_calls)
    last = [r for r in lab.log_rows() if r["event"] == "promote_retry"][-1]
    assert last["decision"] == "ready_to_promote_manually" and lab.state()["pending_promote"] is None


def test_busy_promote_retry_succeeds(lab):
    lab.monkeypatch.setenv("STUB_RC", "3")
    lab.monkeypatch.setenv("STUB_PB", L.BUSY_DECISION)
    lr = lab.learner(auto=True)
    lr.startup()
    lab.add_capture()
    lr.poll()
    lab.monkeypatch.setenv("STUB_RC", "0")
    lab.monkeypatch.setenv("STUB_PB", "promoted")
    lab.t += 121
    assert lr.poll() == "promote_retry:promoted" and lab.state()["pending_promote"] is None


def test_exit3_that_is_not_busy_is_an_error_not_a_retry(lab):
    lab.monkeypatch.setenv("STUB_RC", "3")
    lab.monkeypatch.setenv("STUB_PB", "promote failed, models/ unchanged")
    lr = lab.learner(auto=True)
    lr.startup()
    lab.add_capture()
    assert lr.poll() == "error" and lab.state()["pending_promote"] is None


# ── exit codes ───────────────────────────────────────────────────────────────
def test_exit4_data_missing_sets_cooldown_and_does_not_mark_inputs(lab):
    lab.monkeypatch.setenv("STUB_RC", "4")
    lr = lab.learner()
    lr.startup()
    lab.add_capture()
    assert lr.poll() == "data_missing"
    st = lab.state()
    assert st["captures"]["trained"] == {} and st["cooldown_until"] > lab.t
    fin = [r for r in lab.log_rows() if r["event"] == "run_finished"][-1]
    assert fin["exit"] == 4 and fin["decision"] == "data_missing"


def test_missing_live_training_files_are_caught_before_running_anything(lab):
    lab.monkeypatch.delenv("SOC_TRAIN_CMD")               # real command path; it must not be reached
    prov = {"source_files": [{"path": str(lab.tmp / "tu2023_missing.json")}]}
    (lab.models / "training_provenance.json").write_text(json.dumps(prov))
    lr = lab.learner()
    lr.startup()
    lab.add_capture()
    assert lr.poll() == "data_missing"
    assert lab.calls_made() == [] and lab.state()["captures"]["trained"] == {}
    assert not list((lab.tmp / "logs").glob("train_*.log"))


@pytest.mark.parametrize("rc,pb,outcome", [(1, "kept current models", "gate_fail"),
                                           (10, "ready, waiting for approval", "ready"),
                                           (2, "smoke test failed, rolled back", "rolled_back")])
def test_completed_runs_mark_inputs_trained(lab, rc, pb, outcome):
    lab.monkeypatch.setenv("STUB_RC", str(rc))
    lab.monkeypatch.setenv("STUB_PB", pb)
    lr = lab.learner()
    lr.startup()
    lab.add_capture()
    assert lr.poll() == outcome
    assert lab.state()["captures"]["trained"]
    if outcome == "ready":
        fin = [r for r in lab.log_rows() if r["event"] == "run_finished"][-1]
        assert "--auto-promote" in fin["promote_command"] and lab.state()["last_ready"]["run"] == fin["run"]


def test_exit1_without_a_gate_line_is_an_error_and_inputs_stay_new(lab):
    lab.monkeypatch.setenv("STUB_RC", "1")
    lr = lab.learner()
    lr.startup()
    lab.add_capture()
    assert lr.poll() == "error" and lab.state()["captures"]["trained"] == {}


def test_aborted_run_is_logged_on_next_start(lab):
    lr = lab.learner()
    lr.startup()
    lr.state["last_run"] = {"run": "soc_x", "trigger": "captures", "started_at": lab.t - 50,
                            "finished_at": None, "exit": None, "outcome": None}
    lr.save_state()
    lr2 = lab.learner()
    lr2.startup()
    assert [r for r in lab.log_rows() if r["event"] == "run_aborted"][0]["run"] == "soc_x"
    assert lab.state()["cooldown_until"] > lab.t


# ── audit log and models/ guard ──────────────────────────────────────────────
def test_every_decision_is_one_learner_json_line_and_idle_polls_write_nothing(lab):
    lr = lab.learner()
    lr.startup()
    n = len(lab.log_rows(None))
    for _ in range(5):
        assert lr.poll() is None
    assert len(lab.log_rows(None)) == n
    lab.add_capture()
    lr.poll()
    rows = lab.log_rows(None)
    learner_rows = [r for r in rows if r.get("source") == "learner"]
    assert [r["event"] for r in learner_rows][-2:] == ["run_started", "run_finished"]
    for r in learner_rows:
        assert {"time", "event", "decision", "trigger", "reason", "run", "exit", "git_commit"} <= set(r)


def test_models_changed_outside_a_promote_is_flagged(lab):
    lab.monkeypatch.setenv("STUB_TOUCH_MODELS", str(lab.models / "model.txt"))
    lr = lab.learner()
    lr.startup()
    lab.add_capture()
    assert lr.poll() == "ready"
    assert [r for r in lab.log_rows() if r["event"] == "models_changed_unexpectedly"]


# ── allowlist ────────────────────────────────────────────────────────────────
def test_learner_only_builds_allowed_commands(lab):
    lab.monkeypatch.delenv("SOC_TRAIN_CMD")
    lab.monkeypatch.delenv("SOC_EXPORT_CMD")
    lab.monkeypatch.delenv("SOC_PART_B_CMD")
    lr = lab.learner()
    cmds = [lr.train_cmd(k, "captures", "r") for k in ("captures", "verdicts", "defaults")]
    cmds += [lr.export_cmd(), lr.part_b_cmd("r", "42 43 44")]
    used = {Path(a).name for c in cmds for a in c if str(a).endswith((".sh", ".py"))}
    assert used == {"train_new_data.sh", "run_candidate_seeds.sh", "export_feedback_labels.py", "part_b.py"}
    assert used <= {Path(s).name for s in L.ALLOWED_SCRIPTS}
    for bad in ("scripts/train_models.sh", str(ROOT / "scripts/promote_model.sh"), "rollback_model.sh",
                str(ROOT / "scripts/run_all.sh")):
        with pytest.raises(L.NotAllowed):
            L.check_allowed(["bash", bad])
    with pytest.raises(L.NotAllowed):                       # also through the env override
        lab.monkeypatch.setenv("SOC_TRAIN_CMD", "bash scripts/train_models.sh")
        lr.train_cmd("captures", "captures", "r")


def test_learner_source_never_runs_forbidden_scripts_directly():
    src = (ROOT / "scripts" / "learner.py").read_text(encoding="utf-8")
    code = src.split('"""', 2)[2]                            # skip the module docstring
    for name in ("train_models.sh", "promote_model.sh", "rollback_model.sh"):
        # the names may appear only in the FORBIDDEN_SCRIPTS tuple and comments/strings explaining it
        assert f'"scripts/{name}"' not in code and f"scripts/{name}\"" not in code
    assert code.count("subprocess.Popen(") == 1             # every child goes through run_logged()


def test_pending_promote_is_handed_over_if_auto_promote_is_now_off(lab):
    lab.monkeypatch.setenv("STUB_RC", "3")
    lab.monkeypatch.setenv("STUB_PB", L.BUSY_DECISION)
    lr = lab.learner(auto=True)
    lr.startup()
    lab.add_capture()
    assert lr.poll() == "promote_busy"
    lr2 = lab.learner(auto=False)
    lab.t += 121
    lr2.poll()
    st = lab.state()
    assert st["pending_promote"] is None and st["last_ready"]["run"].startswith("soc_captures_")
    assert len(lab.calls_made()) == 1                       # part_b was not run again without the flag
