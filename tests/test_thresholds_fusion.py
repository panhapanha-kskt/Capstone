"""Tests for models/thresholds.py, fusion/stacker.py inputs and stable row ids (Steps 2, 5, 7)."""

import sys
from pathlib import Path

import numpy as np
import pytest
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.models.thresholds import rates, threshold_for_fpr  # noqa: E402
from dns_detect.models.splits import stable_row_ids  # noqa: E402
from dns_detect.fusion.stacker import fusion_inputs  # noqa: E402


def test_threshold_meets_budget():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(1000), np.ones(200)]
    s = np.r_[rng.uniform(0, 0.6, 1000), rng.uniform(0.4, 1.0, 200)]
    t = threshold_for_fpr(y, s, 0.01)
    assert ((s >= t) & (y == 0)).sum() <= 10


def test_zero_budget_flags_no_benign():
    y = np.r_[np.zeros(50), np.ones(50)]
    s = np.r_[np.linspace(0, 0.3, 50), np.linspace(0.2, 1, 50)]
    t = threshold_for_fpr(y, s, 0.0)
    assert ((s >= t) & (y == 0)).sum() == 0


def test_gap_midpoint_on_separable_scores():
    y = np.r_[np.zeros(10), np.ones(10)]
    s = np.r_[np.zeros(10), np.ones(10)]
    assert threshold_for_fpr(y, s, 0.001) == 0.5


def test_benign_only_threshold_sits_just_above_max():
    s = np.array([0.1, 0.2, 0.3])
    t = threshold_for_fpr(np.zeros(3), s, 0.0)
    assert 0.3 < t < 0.3000001


def test_rates_counts():
    r = rates([0, 0, 1, 1], [1, 0, 1, 0])
    assert r["false_alarms"] == 1 and r["recall"] == 0.5 and r["fpr"] == 0.5


def test_stable_row_ids_survive_reordering_and_extra_rows():
    df = pd.DataFrame({"source_file": ["a", "a", "b"], "timestamp": ["t1", "t1", "t2"],
                       "client_ip": ["c", "c", "d"], "domain": ["x.com", "x.com", "y.com"],
                       "query_type": ["A", "A", "TXT"]})
    ids = stable_row_ids(df)
    assert len(set(ids)) == 3                       # exact repeats still get distinct ids
    more = pd.concat([df.iloc[[2]], pd.DataFrame({"source_file": ["z"], "timestamp": ["t9"],
                                                  "client_ip": ["e"], "domain": ["z.com"],
                                                  "query_type": ["A"]})])
    assert stable_row_ids(more)[0] == ids[2]        # same query → same id in another file


def test_fusion_inputs_rule_hits_and_coverage():
    df = pd.DataFrame({"ml_score_A": [0.9, 0.1], "ml_score_B": [0.0, 0.7],
                       "query_length": [150, 20], "entropy": [4.5, 2.0], "subdomain_depth": [7, 2]})
    X = fusion_inputs(df)
    assert X.shape == (2, 4)
    assert X[0, 2] == 0.0 and X[1, 2] == 1.0         # has_score_B
    assert X[0, 3] == 2.0 and X[1, 3] == 0.0         # R3 + R4 hits


def _bridge_frame():
    return pd.DataFrame({"ml_score_A": [0.95, 0.10, 0.60], "ml_label_A": [1, 0, 0],
                         "query_length": [30, 30, 30], "entropy": [2.0, 2.0, 2.0],
                         "subdomain_depth": [1, 1, 1]})


def test_merge_lr_mode_uses_stacker(monkeypatch, tmp_path):
    from dns_detect.fusion import bridge, stacker
    X = pd.DataFrame({"ml_score_A": [0.0, 0.1, 0.9, 1.0], "ml_score_B": [0.0, 0.2, 0.8, 1.0],
                      "query_length": [10] * 4, "entropy": [1.0] * 4, "subdomain_depth": [1] * 4})
    lr, meta = stacker.fit(X, np.array([0, 0, 1, 1]), 0.0)
    monkeypatch.setattr(stacker, "MODEL_FUSION", str(tmp_path / "f.pkl"))
    monkeypatch.setattr(stacker, "META_FUSION", str(tmp_path / "f.json"))
    stacker.save(lr, meta)
    monkeypatch.setattr(bridge, "_fusion_mode", lambda: "lr")
    out = bridge.merge_ml_scores(_bridge_frame(), pd.Series([0.0, 0.0, 0.9]),
                                 pd.Series([0, 0, 1]), decision_threshold=0.5)
    assert out["ml_combined_label_or"].tolist() == [1, 0, 1]   # OR decision kept for audit
    assert out["ml_combined_score"].between(0, 1).all()


def test_merge_lr_mode_falls_back_to_or_without_model(monkeypatch, tmp_path):
    # Bridge V2: the OR fallback is development-only and is marked; production raises
    # (tests/test_bridge.py). The OR decision is now always kept as ml_combined_label_or.
    from dns_detect.fusion import bridge, stacker
    monkeypatch.setattr(stacker, "MODEL_FUSION", str(tmp_path / "missing.pkl"))
    monkeypatch.setattr(stacker, "META_FUSION", str(tmp_path / "missing.json"))
    monkeypatch.setattr(bridge, "_fusion_mode", lambda: "lr")
    with pytest.warns(UserWarning):
        out = bridge.merge_ml_scores(_bridge_frame(), pd.Series([0.0, 0.0, 0.9]),
                                     pd.Series([0, 0, 1]), decision_threshold=0.5, mode="development")
    assert out["ml_combined_label_or"].tolist() == [1, 0, 1]
    assert out["ml_combined_label"].tolist() == [1, 0, 1]
    assert set(out["fusion_method"]) == {"or_fallback"}


def test_allowlist_suppresses_alarm_but_keeps_score(monkeypatch):
    from dns_detect.fusion import bridge
    monkeypatch.setattr(bridge, "_fusion_mode", lambda: "or")
    df = _bridge_frame()
    df["domain"] = ["a1b2.gallerycdn.vsassets.io", "x.example.com", "notvsassets.io"]
    df["ml_label_A"] = [1, 0, 1]
    out = bridge.merge_ml_scores(df, pd.Series([0.0, 0.0, 0.0]), pd.Series([0, 0, 0]),
                                 decision_threshold=0.5, allowlist={"vsassets.io"})
    unsuppressed = bridge.merge_ml_scores(df, pd.Series([0.0, 0.0, 0.0]), pd.Series([0, 0, 0]),
                                          decision_threshold=0.5, allowlist=set())
    assert out["ml_combined_label"].tolist() == [0, 0, 1]          # label boundary respected
    assert out["suppressed_by_allowlist"].tolist() == [True, False, False]
    # score kept for audit (Bridge V2: in OR mode the score is a benign-quantile score, not raw A)
    np.testing.assert_equal(out.loc[0, "ml_combined_score"], unsuppressed.loc[0, "ml_combined_score"])
    assert out.loc[0, "ml_combined_score_legacy"] == 0.95


def test_detection_allowlist_file_has_no_dynamic_dns():
    from dns_detect.fusion.bridge import load_detection_allowlist
    allow = load_detection_allowlist()
    assert "vsassets.io" in allow
    assert not allow & {"duckdns.org", "no-ip.com", "ngrok.io", "trycloudflare.com", "blogspot.com"}
