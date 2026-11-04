"""Tests for Bridge V2 (fusion/bridge.py): fail-closed scoring, Path B coverage, row_id joins,
fusion method tracking, confidence tiers, label provenance and the Week-4 contract.

Path A / Path B are stubbed (no TensorFlow, no trained models needed)."""

import json
import os
import subprocess
import sys
import types
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.fusion import bridge, stacker  # noqa: E402
from dns_detect.ingest.labeling import UntrustedLabelError, validate_training_labels  # noqa: E402


# ── fixtures ─────────────────────────────────────────────────────────────────

def _records(n=25, clients=("10.0.0.1",), attack_every=5):
    recs = []
    for i in range(n):
        c = clients[i % len(clients)]
        att = i % attack_every == 0
        recs.append({"domain": (f"{'x' * 60}{i}.tunnel.example" if att else f"www{i}.example.com"),
                     "query_length": 70 if att else 18, "entropy": 4.4 if att else 2.5,
                     "subdomain_depth": 2, "numeric_ratio": 0.1, "answer_size": 0,
                     "first_label_length": 61 if att else 5, "client_ip": c,
                     "timestamp": f"2026-01-01T00:00:{i:02d}", "attack_count": int(att),
                     "attack_signature": "HIGH_ENTROPY,ENCODING" if att else "NORMAL",
                     "label": int(att), "label_source": "provenance"})
    return recs


@pytest.fixture
def week3(tmp_path):
    p = tmp_path / "week3.json"
    p.write_text(json.dumps(_records()))
    return p


def _fake_score_frame(df):
    s = np.where(pd.to_numeric(df["query_length"]) > 50, 0.97, 0.02)
    return s, (s >= 0.5).astype(int), 0.5, "rf_only"


def _install_fake_path_b(monkeypatch, window=20):
    """score_records emulating per-client windows: only the last record of each window scores."""
    def score_records(path, save_name, model_dir=None):
        recs = json.loads(Path(path).read_text())
        n = len(recs)
        scores, anom, cov = np.zeros(n), np.zeros(n, dtype=int), np.zeros(n, dtype=bool)
        seen = {}
        for i, r in enumerate(recs):
            seen[r["client_ip"]] = seen.get(r["client_ip"], 0) + 1
            if seen[r["client_ip"]] >= window:
                cov[i] = True
                scores[i] = 0.0 if i == window - 1 else (0.9 if r["attack_count"] else 0.3)   # a REAL zero
                anom[i] = int(scores[i] > 0.5)
        return scores, anom, cov, 0.5
    fake = types.ModuleType("dns_detect.models.path_b_predict")
    fake.score_records = score_records
    monkeypatch.setitem(sys.modules, "dns_detect.models.path_b_predict", fake)


@pytest.fixture
def models(monkeypatch, tmp_path):
    """Path A 'present', stubbed scoring, and isolated fusion artefact paths."""
    for f in ("rf.pkl", "scaler.pkl"):
        (tmp_path / f).write_text("x")
    monkeypatch.setattr(bridge, "MODEL_RF", str(tmp_path / "rf.pkl"))
    monkeypatch.setattr(bridge, "MODEL_SCALER", str(tmp_path / "scaler.pkl"))
    monkeypatch.setattr(bridge, "score_frame", _fake_score_frame)
    for name, fn in (("MODEL_FUSION", "v1.pkl"), ("META_FUSION", "v1.json"),
                     ("MODEL_FUSION_V2", "v2.pkl"), ("META_FUSION_V2", "v2.json")):
        monkeypatch.setattr(stacker, name, str(tmp_path / fn))
    monkeypatch.setattr(bridge, "V1_TIERS", str(tmp_path / "v1_tiers.json"))
    monkeypatch.setattr(bridge, "FALLBACK_QUANTILES", str(tmp_path / "fallback.json"))
    monkeypatch.setattr(bridge, "load_detection_allowlist", lambda: set())
    monkeypatch.setattr(bridge, "_fusion_mode", lambda: "lr")
    _install_fake_path_b(monkeypatch)
    return tmp_path


def _train_v1(tmp_path):
    X = pd.DataFrame({"ml_score_A": [0.0, 0.1, 0.9, 1.0] * 5, "ml_score_B": [0.0, 0.2, 0.8, 1.0] * 5,
                      "query_length": [10] * 20, "entropy": [1.0] * 20, "subdomain_depth": [1] * 20})
    lr, meta = stacker.fit(X, np.array([0, 0, 1, 1] * 5), 0.0)
    stacker.save(lr, meta)
    return lr, meta


def _run(week3, tmp_path, **kw):
    out = tmp_path / "out.json"
    bridge.run_bridge(str(week3), str(out), path_b_model=kw.pop("path_b_model", "fake"), **kw)
    return pd.DataFrame(json.loads(out.read_text())), out


# ── H1 fail closed ───────────────────────────────────────────────────────────

def test_missing_path_a_raises_by_default(models, week3, tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, "MODEL_RF", str(tmp_path / "missing_rf.pkl"))
    _train_v1(tmp_path)
    with pytest.raises(bridge.ModelUnavailableError):
        _run(week3, tmp_path, mode="production")


def test_allow_missing_path_a_requires_development(models, week3, tmp_path):
    with pytest.raises(ValueError):
        _run(week3, tmp_path, mode="production", allow_missing_path_a=True)


def test_dev_override_marks_every_record_degraded(models, week3, tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, "MODEL_RF", str(tmp_path / "missing_rf.pkl"))
    _train_v1(tmp_path)
    with pytest.warns(UserWarning):
        df, _ = _run(week3, tmp_path, mode="development", allow_missing_path_a=True)
    assert df["ml_score_A"].isna().all()
    assert (df["fusion_method"] == "degraded").all() and (df["fusion_status"] == "degraded").all()
    assert (df["ml_verdict_A"] == "SKIP").all()
    assert (df["ml_confidence"] == "UNSCORED").all()          # never CLEAN
    assert (df["ml_combined_verdict"] == "ml_unscored").all() # never shown as benign
    assert df["ml_combined_score"].isna().all()


def test_degraded_rows_rejected_in_production_merge():
    df = pd.DataFrame({"ml_score_A": [np.nan, 0.9], "ml_label_A": [np.nan, 1],
                       "query_length": [10, 10], "entropy": [1.0, 1.0], "subdomain_depth": [1, 1]})
    with pytest.raises(bridge.ModelUnavailableError):
        bridge.merge_ml_scores(df, pd.Series([np.nan, np.nan]), pd.Series([np.nan, np.nan]),
                               mode="production", fusion="or", allowlist=set())


# ── H2 Path B coverage ───────────────────────────────────────────────────────

def test_path_b_window_coverage(models, week3, tmp_path):
    _train_v1(tmp_path)
    df, _ = _run(week3, tmp_path)
    assert df.loc[:18, "ml_score_B"].isna().all()                 # records 1–19: no window yet
    assert (df.loc[:18, "has_score_B"] == 0).all()
    assert (df.loc[19:, "has_score_B"] == 1).all()
    assert df.loc[19, "ml_score_B"] == 0.0                        # a real zero stays a zero
    assert df.loc[20:, "ml_score_B"].notna().all()


def test_path_b_disabled_leaves_all_nan(models, week3, tmp_path):
    _train_v1(tmp_path)
    df, out = _run(week3, tmp_path, no_path_b=True)
    assert df["ml_score_B"].isna().all() and (df["has_score_B"] == 0).all()
    assert "NaN" not in out.read_text()                           # JSON has null, never NaN


def test_merge_keeps_real_zero_distinct_from_missing():
    df = pd.DataFrame({"ml_score_A": [0.1, 0.1], "ml_label_A": [0, 0]})
    out = bridge.merge_ml_scores(df, pd.Series([0.0, 0.0]), pd.Series([0, 0]), covered_b=[True, False],
                                 fusion="or", allowlist=set())
    assert out["has_score_B"].tolist() == [1, 0]
    assert out.loc[0, "ml_score_B"] == 0.0 and np.isnan(out.loc[1, "ml_score_B"])


# ── M5 row_id joins ──────────────────────────────────────────────────────────

def _base(n=5):
    return pd.DataFrame({"row_id": np.arange(n), "domain": [f"d{i}" for i in range(n)]})


def test_join_survives_shuffled_scores():
    scores = pd.DataFrame({"row_id": np.arange(5), "ml_score_A": np.arange(5) / 10}).sample(frac=1, random_state=1)
    out = bridge.join_on_row_id(_base(), scores, "Path A")
    assert out["ml_score_A"].tolist() == [0.0, 0.1, 0.2, 0.3, 0.4]
    assert out["domain"].tolist() == [f"d{i}" for i in range(5)]


def test_join_rejects_duplicate_row_ids():
    with pytest.raises(bridge.AlignmentError):
        bridge.join_on_row_id(_base(), pd.DataFrame({"row_id": [0, 0, 1, 2, 3], "s": range(5)}), "x")


def test_join_rejects_missing_row_ids():
    with pytest.raises(bridge.AlignmentError):
        bridge.join_on_row_id(_base(), pd.DataFrame({"row_id": [0, 1, 2, 3], "s": range(4)}), "x")
    with pytest.raises(bridge.AlignmentError):
        bridge.join_on_row_id(_base(), pd.DataFrame({"row_id": [0, 1, None, 3, 4], "s": range(5)}), "x")


def test_join_rejects_unmatched_records():
    with pytest.raises(bridge.AlignmentError):
        bridge.join_on_row_id(_base(), pd.DataFrame({"row_id": [0, 1, 2, 3, 4, 99], "s": range(6)}), "x")


def test_path_b_order_mismatch_detected(week3):
    df = pd.DataFrame(json.loads(week3.read_text()))
    df.loc[0, "client_ip"] = "10.9.9.9"
    with pytest.raises(bridge.AlignmentError):
        bridge.check_path_b_alignment(str(week3), df, len(df))
    with pytest.raises(bridge.AlignmentError):
        bridge.check_path_b_alignment(str(week3), df, len(df) - 1)


def test_output_preserves_record_order_and_week3_columns(models, week3, tmp_path):
    _train_v1(tmp_path)
    df, _ = _run(week3, tmp_path)
    assert df["row_id"].tolist() == list(range(25))
    recs = json.loads(week3.read_text())
    assert df["domain"].tolist() == [r["domain"] for r in recs]
    assert {"attack_count", "attack_signature", "label_source"} <= set(df.columns)


# ── fusion method ────────────────────────────────────────────────────────────

def test_missing_fusion_model_raises_in_production(models, week3, tmp_path):
    with pytest.raises(bridge.ModelUnavailableError):
        _run(week3, tmp_path, mode="production")


def test_missing_fusion_model_dev_uses_or_fallback(models, week3, tmp_path):
    with pytest.warns(UserWarning):
        df, _ = _run(week3, tmp_path, mode="development")
    assert (df["fusion_method"] == "or_fallback").all() and (df["fusion_status"] == "fallback").all()
    assert df["ml_combined_label"].tolist() == df["ml_combined_label_or"].tolist()


def test_learned_fusion_is_the_decision(models, week3, tmp_path):
    lr, meta = _train_v1(tmp_path)
    df, out = _run(week3, tmp_path)
    assert (df["fusion_method"] == "lr").all()
    exp, _ = stacker.predict(df.assign(ml_score_B=df["ml_score_B"].fillna(0.0)), lr, meta)
    assert np.allclose(df["ml_combined_score"], exp)
    meta_out = json.loads(Path(str(out) + ".meta.json").read_text())
    assert meta_out["fusion_method"] == {"lr": 25}


def test_fusion_v2_mode(models, week3, tmp_path, monkeypatch):
    rng = np.random.default_rng(0)
    n = 400
    y = np.r_[np.zeros(n // 2, int), np.ones(n // 2, int)]
    X = pd.DataFrame({"ml_score_A": np.where(y == 1, rng.uniform(0.8, 1, n), rng.uniform(0, 0.2, n)),
                      "ml_score_B": np.where(y == 1, rng.uniform(0.6, 1, n), rng.uniform(0, 0.5, n)),
                      "query_length": 20, "entropy": 2.0, "subdomain_depth": 1})
    groups = np.r_[[f"b{i % 20}" for i in range(n // 2)], [f"a{i % 3}" for i in range(n // 2)]]
    lr, meta, _ = stacker.fit_v2(X, y, groups, 0.01)
    stacker.save_v2(lr, meta)
    monkeypatch.setattr(bridge, "_fusion_mode", lambda: "lr_v2")
    df, _ = _run(week3, tmp_path)
    assert (df["fusion_method"] == "lr").all() and (df["confidence_method"] == "calibration_part_benign").all()


def test_invalid_fusion_setting_rejected(monkeypatch):
    monkeypatch.setattr(bridge, "_ensemble_setting", lambda name, d: "weighted" if name == "fusion" else d)
    with pytest.raises(ValueError):
        bridge._fusion_mode()
    monkeypatch.setattr(bridge, "_ensemble_setting", lambda name, d: "staging" if name == "bridge_mode" else d)
    with pytest.raises(ValueError):
        bridge._bridge_mode()


def test_label_thr_column_removed(models, week3, tmp_path):
    _train_v1(tmp_path)
    df, _ = _run(week3, tmp_path)
    assert "ml_combined_label_thr" not in df.columns


# ── fallback score and tiers ─────────────────────────────────────────────────

def test_benign_quantile_edges():
    ben = np.array([0.1, 0.2, 0.2, 0.4])
    q = bridge.benign_quantile(ben, [0.0, 0.2, 0.3, 0.9, np.nan])
    assert q[:4].tolist() == [0.0, 0.75, 0.75, 1.0] and np.isnan(q[4])
    assert np.isnan(bridge.benign_quantile(np.array([]), [0.5])).all()


def test_fallback_score_uses_frozen_quantiles(models, week3, tmp_path):
    (tmp_path / "fallback.json").write_text(json.dumps({"path_a_benign_sorted": [0.01, 0.02, 0.03, 0.5],
                                                        "path_b_benign_sorted": [0.1, 0.2, 0.3, 0.4]}))
    with pytest.warns(UserWarning):
        df, _ = _run(week3, tmp_path, mode="development")
    assert df["ml_combined_score"].between(0, 1).all()
    assert (df["confidence_method"] == "benign_quantile_scale").all()


def test_tiers_monotone_and_ties():
    cuts = {"q90": 0.5, "q99": 0.5}                    # tied quantiles: MEDIUM band collapses
    t = bridge.assign_tiers([0.1, 0.5, 0.7, 0.95, np.nan], [0, 0, 0, 1, 0], cuts)
    assert t.tolist() == ["CLEAN", "MEDIUM", "MEDIUM", "HIGH", "UNSCORED"]
    t2 = bridge.assign_tiers([0.6, 0.75], [0, 0], {"q90": 0.7, "q99": 0.3})   # inverted: q99 raised to q90
    assert t2.tolist() == ["CLEAN", "MEDIUM"]


def test_tiers_from_v1_sidecar(models, week3, tmp_path):
    _train_v1(tmp_path)
    (tmp_path / "v1_tiers.json").write_text(json.dumps({"q90": 0.2, "q99": 0.4, "high": 0.5,
                                                        "tier_source": "v1_in_sample_val"}))
    df, _ = _run(week3, tmp_path)
    assert (df["confidence_method"] == "v1_in_sample_val").all()
    alarm = df["ml_combined_label"] == 1
    assert (df.loc[alarm, "ml_confidence"] == "HIGH").all()


def test_tier_summary_reports_expected_volume():
    df = pd.DataFrame({"ml_confidence": ["HIGH", "CLEAN", "CLEAN", "LOW"],
                       "confidence_method": ["calibration_part_benign"] * 4})
    s = bridge.tier_summary(df, 0.001)
    assert s["HIGH"]["expected_benign_per_10k"] == 10.0 and s["CLEAN"]["records"] == 2


# ── threat score and legacy columns ──────────────────────────────────────────

def test_threat_score_is_fused_score_and_legacy_kept():
    df = pd.DataFrame({"ml_score_A": [0.9, 0.2], "ml_score_B": [0.5, np.nan], "attack_count": [3, 0],
                       "ml_combined_score": [0.8, 0.1], "suppressed_by_allowlist": [False, False]})
    out = bridge.ensure_week4_compatible(df)
    assert out["ml_threat_score"].tolist() == [0.8, 0.1]
    assert out.loc[0, "ml_threat_score_legacy"] == pytest.approx(0.4 * 0.5 + 0.35 * 0.9 + 0.25 * 0.5)
    assert out.loc[1, "ml_threat_score_legacy"] == pytest.approx(0.35 * 0.2)


def test_allowlisted_alarm_cannot_resurface_via_threat_score():
    df = pd.DataFrame({"ml_score_A": [0.99], "ml_label_A": [1], "domain": ["a.vsassets.io"],
                       "attack_count": [0]})
    out = bridge.ensure_week4_compatible(
        bridge.merge_ml_scores(df, pd.Series([np.nan]), pd.Series([np.nan]), fusion="or",
                               allowlist={"vsassets.io"}))
    assert out.loc[0, "ml_combined_label"] == 0 and out.loc[0, "ml_threat_score"] == 0.0


def test_legacy_blend_formula():
    df = pd.DataFrame({"ml_score_A": [0.2, 0.9], "ml_label_A": [0, 1]})
    out = bridge.merge_ml_scores(df, pd.Series([1.0, np.nan]), pd.Series([1, np.nan]), 0.6, 0.4,
                                 fusion="or", allowlist=set())
    assert out["ml_combined_score_legacy"].tolist() == pytest.approx([max(0.2, 0.12 + 0.4), 0.9])


def test_cli_weights_emit_deprecation(models, week3, tmp_path, monkeypatch):
    _train_v1(tmp_path)
    monkeypatch.setattr(sys, "argv", ["bridge", "--week3", str(week3), "--output", str(tmp_path / "o.json"),
                                      "--path-b-model", "fake", "--weight-a", "0.7", "--weight-b", "0.3"])
    with pytest.warns(DeprecationWarning):
        bridge.main()
    df = pd.DataFrame(json.loads((tmp_path / "o.json").read_text()))
    a, b = df["ml_score_A"], df["ml_score_B"].fillna(0)
    assert np.allclose(df["ml_combined_score_legacy"], np.maximum(a, 0.7 * a + 0.3 * b))


# ── features ─────────────────────────────────────────────────────────────────

def test_missing_feature_columns_raise(models, tmp_path):
    recs = [{k: v for k, v in r.items() if k not in ("numeric_ratio",)} for r in _records()]
    p = tmp_path / "w.json"
    p.write_text(json.dumps(recs))
    _train_v1(tmp_path)
    with pytest.raises(bridge.MissingFeaturesError) as e:
        _run(p, tmp_path)
    assert "digit_ratio" in str(e.value)


def test_fill_missing_features_dev_only_and_recorded(models, tmp_path):
    recs = [{k: v for k, v in r.items() if k != "numeric_ratio"} for r in _records()]
    p = tmp_path / "w.json"
    p.write_text(json.dumps(recs))
    _train_v1(tmp_path)
    with pytest.raises(ValueError):
        _run(p, tmp_path, mode="production", fill_missing_features=True)
    with pytest.warns(UserWarning):
        df, out = _run(p, tmp_path, mode="development", fill_missing_features=True)
    assert df["features_filled"].all()
    assert json.loads(Path(str(out) + ".meta.json").read_text())["features_filled"]["columns"] == ["digit_ratio"]


def test_check_features_reports_null_rows():
    raw = pd.DataFrame({"query_length": [1, None], "entropy": [1, 1], "domain": ["a", "b"],
                        "answer_size": [0, 0], "subdomain_depth": [1, 1], "numeric_ratio": [0, 0]})
    r = bridge.check_features(raw)
    assert r["missing_columns"] == [] and r["rows_missing"] == {"query_length": 1}


# ── labels ───────────────────────────────────────────────────────────────────

def test_trusted_labels_preserved_and_tagged():
    out = bridge.generate_labels_from_week3([{"label": 1, "label_source": "manifest", "attack_count": 0},
                                             {"label": 0, "attack_count": 4}])
    assert [r["label"] for r in out] == [1, 0]
    assert [r["label_source"] for r in out] == ["manifest", "file"]


def test_unlabeled_records_refused_by_default():
    with pytest.raises(ValueError):
        bridge.generate_labels_from_week3([{"attack_count": 2}])
    with pytest.raises(ValueError):       # an untrusted label is not silently kept either
        bridge.generate_labels_from_week3([{"label": 1, "label_source": "weak_behavioral"}])


def test_heuristic_labels_need_opt_in_and_are_tagged():
    with pytest.warns(UserWarning):
        out = bridge.generate_labels_from_week3([{"attack_count": 2}, {"attack_count": 0},
                                                 {"label": 0, "label_source": "provenance"}],
                                                allow_heuristic=True)
    assert [(r["label"], r["label_source"]) for r in out] == [(1, "heuristic"), (0, "heuristic"), (0, "provenance")]


def test_training_guard_rejects_heuristic_labels():
    recs = [{"label": 1, "label_source": "heuristic"}, {"label": 0, "label_source": "provenance"}]
    with pytest.raises(UntrustedLabelError):
        validate_training_labels(recs)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        out = validate_training_labels(recs, allow_untrusted=True)
    assert out["untrusted"] == 1 and out["by_source"] == {"heuristic": 1, "provenance": 1}
    assert validate_training_labels([{"label": 0}])["untrusted"] == 0       # no source = file


def test_relabeling_does_not_launder_untrusted_sources():
    from dns_detect.ingest.labeling import label_records
    recs = [{"domain": "a.example.com", "label": 1, "label_source": "heuristic", "client_ip": "1.1.1.1",
             "timestamp": "2026-01-01T00:00:00"}]
    out = label_records(recs)
    labeled = out[0] if isinstance(out, tuple) else out
    assert labeled[0]["label_source"] == "heuristic"


def test_attack_type_priority_not_signature_order():
    a = bridge.generate_labels_from_week3([{"label": 1, "attack_signature": "NXDOMAIN_FLOOD,ENCODING"}])[0]
    b = bridge.generate_labels_from_week3([{"label": 1, "attack_signature": "ENCODING,NXDOMAIN_FLOOD"}])[0]
    assert a["attack_type_id"] == b["attack_type_id"] == bridge.ATTACK_TYPE_MAP["ENCODING"]
    assert a["attack_type_ENCODING"] == a["attack_type_NXDOMAIN_FLOOD"] == 1 and a["attack_type_AMPLIFICATION"] == 0


# ── Week-4 contract ──────────────────────────────────────────────────────────

def test_week4_columns_present(models, week3, tmp_path):
    _train_v1(tmp_path)
    df, _ = _run(week3, tmp_path)
    for c in bridge.WEEK4_COLUMNS + ("ml_combined_label_or", "ml_combined_score_legacy", "ml_threat_score_legacy",
                                     "fusion_method", "fusion_status", "has_score_B", "attack_count",
                                     "attack_signature", "ml_score_A", "ml_score_B", "ml_combined_verdict"):
        assert c in df.columns, c


def test_unchanged_week4_engine_reads_bridge_output(models, week3, tmp_path):
    _train_v1(tmp_path)
    _, out = _run(week3, tmp_path)
    alerts = tmp_path / "alerts.json"
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8"}
    r = subprocess.run([sys.executable, "-m", "dns_detect.detection.engine", "--input", str(out),
                        "--output", str(alerts)], env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=300)
    assert r.returncode == 0, r.stderr[-2000:]
    data = json.loads(alerts.read_text())
    assert "alerts" in data and data["total_queries_analyzed"] == 25


def test_deterministic_output(models, week3, tmp_path):
    _train_v1(tmp_path)
    a, _ = _run(week3, tmp_path)
    b, _ = _run(week3, tmp_path)
    pd.testing.assert_frame_equal(a, b)
