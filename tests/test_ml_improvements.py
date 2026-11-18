"""Tests for the ML improvement items (docs/Week6/ML_IMPROVEMENT_RESEARCH_2026-11-19.md §6):
1 run record, 2 forbidden features, 3 compare gate, 4 FPR intervals, 5 twin-free test metrics."""

import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "dashboard" / "training-gui" / "adapters"))

from dns_detect.models.thresholds import (  # noqa: E402
    rate_interval, min_rows_for_rate, budget_evidence, budget_message, rates)
from dns_detect.parsing.dns_parser import (  # noqa: E402
    FORBIDDEN_FEATURES, PATH_A_FEATURES, PATH_B_FEATURES, check_model_features)


# ─────────────── item 4: intervals and the budget check ───────────────

def test_rate_interval_contains_point_and_is_ordered():
    lo, hi = rate_interval(5, 10)
    assert 0 < lo < 0.5 < hi < 1
    assert rate_interval(0, 10)[0] == 0.0
    assert rate_interval(10, 10)[1] == 1.0
    assert rate_interval(0, 0) is None


def test_rate_interval_known_value():
    # Clopper-Pearson 95% for 0/3000: upper = 1 - 0.025**(1/3000) ≈ 0.001229
    assert rate_interval(0, 3000)[1] == pytest.approx(1 - 0.025 ** (1 / 3000), rel=1e-6)


def test_rule_of_three_rows_needed():
    assert min_rows_for_rate(0.001) == 2995
    assert min_rows_for_rate(0.01) == 299


def test_budget_evidence_small_test_set_cannot_prove_budget():
    ev = budget_evidence(0, 1168, 0.001)        # the latest GUI run's benign test rows
    assert not ev["enough_rows"] and not ev["within_budget"]
    assert ev["upper"] == pytest.approx(1 - 0.05 ** (1 / 1168), rel=1e-6)
    assert "cannot show" in budget_message(ev)


def test_budget_evidence_large_clean_test_set_proves_budget():
    ev = budget_evidence(0, 4000, 0.001)
    assert ev["enough_rows"] and ev["within_budget"]
    assert "within the" in budget_message(ev)
    ev = budget_evidence(20, 4000, 0.001)
    assert ev["enough_rows"] and not ev["within_budget"]
    assert "above" in budget_message(ev)


def test_rates_reports_intervals():
    r = rates([0, 0, 0, 0, 1, 1], [1, 0, 0, 0, 1, 0])
    assert r["fpr_ci95"][0] <= r["fpr"] <= r["fpr_ci95"][1]
    assert r["recall_ci95"][0] <= r["recall"] <= r["recall_ci95"][1]


# ─────────────── item 2: forbidden features ───────────────

def test_live_feature_lists_have_no_forbidden_columns():
    assert not set(PATH_A_FEATURES) & FORBIDDEN_FEATURES
    assert not set(PATH_B_FEATURES) & FORBIDDEN_FEATURES
    with pytest.raises(ValueError):
        check_model_features(list(PATH_A_FEATURES) + ["timestamp"])


def _saved_feature_lists():
    """Feature lists written into trained models (live models/ and any run folders), read only."""
    places = [ROOT / "models", *sorted((ROOT / "runs").glob("*")),
              *sorted((ROOT / "dashboard" / "training-gui" / "gui_data" / "runs").glob("*/model"))]
    out = []
    for d in places:
        for name in ("dns_threshold.json", "model_meta.json"):
            p = d / name
            if p.is_file():
                try:
                    feats = json.loads(p.read_text()).get("features")
                except ValueError:
                    continue
                if feats:
                    out.append((str(p.relative_to(ROOT)), feats))
    return out


@pytest.mark.parametrize("where,features", _saved_feature_lists() or [("none found", [])])
def test_saved_models_have_no_forbidden_columns(where, features):
    bad = sorted({f.lower() for f in features} & FORBIDDEN_FEATURES)
    assert not bad, f"{where} uses identity/time/provenance input(s) {bad}"


def test_feature_table_trainer_drops_forbidden_columns(tmp_path):
    import feature_table_train as ft
    csv = tmp_path / "t.csv"
    pd.DataFrame({"qlen": [1, 2], "entropy": [3.0, 4.0], "client_port": [53, 54],
                  "timestamp": [1700000000, 1700000300], "Hour_Of_Day": [1, 2],
                  "label": ["safe", "dnstunnel"]}).to_csv(csv, index=False)
    feats, ts = ft.feature_columns(csv)
    assert feats == ["qlen", "entropy"]
    assert ts == "timestamp"                     # still used for the time split, never as input
    assert ft.forbidden_features() >= FORBIDDEN_FEATURES


# ─────────────── item 1: run record ───────────────

def test_run_record_hashes_inputs_and_copies_merged(tmp_path):
    import hashlib
    import run_record
    src = tmp_path / "in.json"
    src.write_text('[{"q": 1}]')
    prov = tmp_path / "prov.json"
    prov.write_text(json.dumps({"source_files": [{"path": str(src), "records": 1}, {"path": "/no/such"}]}))
    split = tmp_path / "split.json"
    split.write_text("{}")
    merged = tmp_path / "merged_features_labeled.json"
    merged.write_text("[]")
    out = tmp_path / "run"
    path = run_record.write_record(out, prov, split, 43, merged, copy_merged=True)
    rec = json.loads(path.read_text())
    assert rec["seed"] == 43
    assert rec["inputs"][0]["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    assert rec["inputs"][1]["sha256"] is None            # missing files are recorded, not fatal
    assert rec["split_manifest"]["sha256"] == hashlib.sha256(b"{}").hexdigest()
    assert (out / "merged_features_labeled.json").read_text() == "[]"
    assert rec["git"]["commit"] is None or len(rec["git"]["commit"]) == 40
    assert isinstance(rec["pip_freeze"], list)


def test_run_record_without_copy_leaves_data_out(tmp_path):
    import run_record
    merged = tmp_path / "m.json"
    merged.write_text("[]")
    run_record.write_record(tmp_path / "run", merged=merged)
    assert not (tmp_path / "run" / "m.json").exists()


def test_train_models_calls_run_record_and_copies_only_outside_models():
    sh = (ROOT / "scripts" / "train_models.sh").read_text()
    assert "run_record.py" in sh and "--copy-merged" in sh
    assert '"$PROJECT_ROOT/models"' in sh            # the live folder gets the record, not the data


# ─────────────── item 5: test metrics without train twins ───────────────

def test_twin_free_metrics_drops_rows_seen_in_train():
    pytest.importorskip("tensorflow")               # path_a imports keras
    from dns_detect.models.path_a import twin_free_metrics
    groups = np.array(["a", "b", "c", "a", "d", "e"])
    tr, te = np.array([0, 1, 2]), np.array([3, 4, 5])
    y_test = np.array([0, 0, 1])
    scores = np.array([0.9, 0.1, 0.8])               # the twin of "a" is the false alarm
    out = twin_free_metrics(groups, tr, te, y_test, scores, 0.5)
    assert (out["rows"], out["benign"], out["attack"]) == (2, 1, 1)
    assert out["metrics"]["false_alarms"] == 0 and out["metrics"]["recall"] == 1.0
    none = twin_free_metrics(np.array(["a", "a"]), np.array([0]), np.array([1]), np.array([1]),
                             np.array([0.9]), 0.5)
    assert none["rows"] == 0 and none["metrics"] is None


# ─────────────── item 3: success criteria and compare gate ───────────────

import compare_models as cm  # noqa: E402


def _crit(**kw):
    c = {"min_seeds": 3, "same_split": True, "detector": "fusion", "recall_min": 0.95,
         "fpr_budget": 0.001, "require_point_fpr_within_budget": True,
         "require_upper_bound_within_budget": False, "current_recall_tolerance": 0.0,
         "current_false_alarms_not_higher": True, "beat_rule_baselines": True, "twin_free_recall_min": None}
    c.update(kw)
    return c


def _seed(seed, fa=0, recall=1.0, f1=0.99, cur_fa=5, rule_f1=0.8, benign=4000, sha="s"):
    cand = {"recall": recall, "fpr": fa / benign, "false_alarms": fa, "benign": benign, "attack": 100,
            "f1": f1, "precision": 1.0, "budget_check": budget_evidence(fa, benign, 0.001)}
    return {"run": f"r{seed}", "seed": seed, "split_sha256": sha, "candidate": cand, "twin_free": None,
            "current": {"recall": 1.0, "false_alarms": cur_fa, "f1": 0.9},
            "rules": {"record_type": {"f1": rule_f1, "false_alarms": 0, "recall": 0.5}}}


def test_gate_passes_good_candidate():
    rep = cm.evaluate(_crit(), [_seed(42), _seed(43), _seed(44)])
    assert rep["passed"], rep["checks"]
    assert rep["aggregate"]["recall"]["n"] == 3


@pytest.mark.parametrize("seeds,crit,failing", [
    ([_seed(42), _seed(43)], {}, "seeds"),
    ([_seed(42), _seed(43), _seed(44, sha="other")], {}, "same split"),
    ([_seed(42), _seed(43), _seed(44, recall=0.9)], {}, "recall floor (every seed)"),
    ([_seed(42, fa=20), _seed(43, fa=20), _seed(44, fa=20)], {}, "FPR within budget (mean)"),
    ([_seed(42, fa=3, cur_fa=1), _seed(43, fa=3, cur_fa=1), _seed(44, fa=3, cur_fa=1)], {},
     "false alarms vs current model (mean)"),
    ([_seed(42), _seed(43, rule_f1=0.995), _seed(44)], {}, "beats every rule baseline (F1, every seed)"),
    ([_seed(42, benign=1168), _seed(43, benign=1168), _seed(44, benign=1168)],
     {"require_upper_bound_within_budget": True}, "FPR 95% upper bound within budget (every seed)"),
])
def test_gate_fails_each_criterion(seeds, crit, failing):
    rep = cm.evaluate(_crit(**crit), seeds)
    assert not rep["passed"]
    assert failing in [c["criterion"] for c in rep["checks"] if not c["passed"]]


def test_gate_fails_when_current_model_not_scored():
    seeds = [_seed(s) for s in (42, 43, 44)]
    seeds[0]["current"] = "r42: no merged_features_labeled.json or split_manifest.json in the run folder"
    rep = cm.evaluate(_crit(), seeds)
    assert not rep["passed"]
    assert any(c["criterion"] == "versus current model" and not c["passed"] for c in rep["checks"])


def test_criteria_file_loads_with_settings_budget():
    crit = cm.load_criteria()
    assert crit["min_seeds"] >= 3 and crit["fpr_budget"] == pytest.approx(0.001)


def test_detector_block_reads_pipeline_metrics():
    ev = {"path_a": {"recall": 1.0, "fpr": 0.001, "false_alarms": 1, "f1": 0.99, "precision": 0.99,
                     "test_support": {"benign": 1000, "attack": 50}},
          "fusion": {"test": {"learned_lr": {"recall": 0.98, "fpr": 0.0, "false_alarms": 0, "benign": 1000,
                                             "attack": 50, "f1": 0.99, "precision": 1.0}}}}
    assert cm.detector_block(ev, "fusion")["recall"] == 0.98
    assert cm.detector_block(ev, "path_a")["benign"] == 1000
    assert cm.detector_block({}, "fusion") is None


def test_compare_cli_runs_on_metric_only_folders(tmp_path):
    """No data copied in the runs → the current/rule checks are reported as not run and the gate fails."""
    runs = []
    for s in (42, 43, 44):
        d = tmp_path / f"c_s{s}"
        d.mkdir()
        (d / "evaluation_metrics.json").write_text(json.dumps({"fusion": {"test": {"learned_lr": {
            "recall": 1.0, "fpr": 0.0, "false_alarms": 0, "benign": 4000, "attack": 100,
            "f1": 1.0, "precision": 1.0}}}}))
        (d / "training_metadata.json").write_text(json.dumps({"seed": s, "split_sha256": "x"}))
        runs.append(str(d))
    out = tmp_path / "rep.json"
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "compare_models.py"), "--runs", *runs,
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 1, r.stderr
    assert "GATE: FAIL" in r.stdout
    rep = json.loads(out.read_text())
    assert any("not run" in c["detail"] or "no merged" in c["detail"] for c in rep["checks"])
