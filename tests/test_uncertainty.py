"""T9: error ranges for every detector (dns_detect.models.uncertainty, scripts/evaluate_detectors.py)."""
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.models.uncertainty import (  # noqa: E402
    wilson_interval, recall_at_fpr, point_metrics, cluster_bootstrap, evaluate_detector,
    seed_spread, time_blocks)


def test_wilson_interval_brackets_rate_and_handles_edges():
    lo, hi = wilson_interval(5, 100)
    assert lo < 0.05 < hi
    assert wilson_interval(0, 50)[0] == 0.0 and wilson_interval(0, 50)[1] < 0.08
    assert wilson_interval(0, 0) is None
    # 0/3000 at 95%: Wilson upper ≈ z²/(n+z²) = 0.00128
    assert wilson_interval(0, 3000)[1] == pytest.approx(3.8415 / (3000 + 3.8415), rel=1e-3)


def test_recall_at_fpr_is_descriptive_upper_bound():
    y = np.r_[np.zeros(1000), np.ones(10)]
    s = np.r_[np.linspace(0, 0.5, 1000), np.full(10, 0.9)]
    assert recall_at_fpr(y, s, 0.001) == 1.0            # all attacks above every benign score
    s2 = s.copy(); s2[-5:] = 0.1                          # half the attacks sit inside benign scores
    assert recall_at_fpr(y, s2, 0.001) == 0.5
    assert recall_at_fpr(np.zeros(5), np.zeros(5)) is None


def test_point_metrics_counts():
    y = np.array([0, 0, 0, 1, 1])
    p = np.array([1, 0, 0, 1, 0])
    m = point_metrics(y, p.astype(float), p)
    assert (m["false_alarms"], m["true_positives"], m["benign"], m["attack"]) == (1, 1, 3, 2)
    assert m["recall"] == 0.5 and m["fpr"] == pytest.approx(1 / 3)


def test_cluster_bootstrap_resamples_groups_not_rows():
    # one benign group holds all the false alarms: a group bootstrap must sometimes drop it
    # entirely (FPR 0) and sometimes count it twice, so the FPR interval is wide.
    y = np.r_[np.zeros(200), np.ones(50)]
    preds = np.r_[np.r_[np.ones(20), np.zeros(180)], np.ones(50)]
    groups = np.r_[["bad.example"] * 20, [f"g{i}" for i in range(180)], [f"a{i}" for i in range(50)]]
    ci = cluster_bootstrap(y, preds.astype(float), preds, groups, n_boot=300, seed=1)
    assert ci["fpr"][0] == 0.0 and ci["fpr"][1] >= 0.15
    # with one row per group, the same data gives a narrower interval
    rows = np.arange(250).astype(str)
    ci_rows = cluster_bootstrap(y, preds.astype(float), preds, rows, n_boot=300, seed=1)
    assert ci_rows["fpr"][1] - ci_rows["fpr"][0] < ci["fpr"][1] - ci["fpr"][0]


def test_cluster_bootstrap_is_reproducible_and_stratified():
    y = np.r_[np.zeros(30), np.ones(30)]
    s = np.r_[np.random.default_rng(0).uniform(0, 0.4, 30), np.random.default_rng(1).uniform(0.6, 1, 30)]
    p = (s > 0.5).astype(int)
    g = np.arange(60).astype(str)
    a = cluster_bootstrap(y, s, p, g, n_boot=50, seed=7)
    b = cluster_bootstrap(y, s, p, g, n_boot=50, seed=7)
    assert a == b
    assert a["recall"] == [1.0, 1.0]       # both classes always present → recall defined every draw


def test_evaluate_detector_reports_all_three_kinds():
    y = np.r_[np.zeros(400), np.ones(100)]
    s = np.r_[np.linspace(0, 0.6, 400), np.linspace(0.5, 1, 100)]
    p = (s >= 0.55).astype(int)
    out = evaluate_detector(y, s, p, groups=np.arange(500) // 5, n_boot=100, seed=0)
    assert out["point"]["false_alarms"] == int(((s >= 0.55) & (y == 0)).sum())
    assert out["exact"]["fpr_clopper_pearson"][0] <= out["point"]["fpr"] <= out["exact"]["fpr_clopper_pearson"][1]
    assert out["exact"]["fpr_wilson"][0] <= out["point"]["fpr"] <= out["exact"]["fpr_wilson"][1]
    assert out["bootstrap"]["fpr"][0] <= out["point"]["fpr"] <= out["bootstrap"]["fpr"][1]
    assert out["n_groups"] == {"benign": 80, "attack": 20}
    assert evaluate_detector(y, s, p)["bootstrap"] is None


def test_seed_spread_and_time_blocks():
    sp = seed_spread([13, 16, 2])
    assert sp["mean"] == pytest.approx(31 / 3) and sp["min"] == 2 and sp["max"] == 16 and sp["n"] == 3
    assert seed_spread([None]) is None
    blocks = time_blocks(["2026-01-01T10:05:00Z", "2026-01-01T10:59:00Z", "2026-01-01T11:00:00Z", "bad"], 60)
    assert blocks[0] == blocks[1] != blocks[2] and blocks[3] == "na"


def test_evaluate_detectors_script_markdown_has_rule_baseline():
    sys.path.insert(0, str(ROOT / "scripts"))
    import evaluate_detectors as ed
    y = np.r_[np.zeros(100), np.ones(20)]
    lab = np.r_[np.zeros(100), np.ones(20)].astype(int)
    s = {"y": y.astype(int), "a_score": lab.astype(float), "a_label": lab, "b_score": lab.astype(float),
         "b_label": lab, "b_covered": np.ones(120, bool), "f_score": lab.astype(float), "f_label": lab,
         "rule_label": lab, "domain": np.arange(120).astype(str), "timestamp": np.array(["na"] * 120)}
    res = ed.evaluate_run(s, "domain", 60, 20, 0)
    md = ed.markdown({"group": "domain", "n_boot": 20, "runs": {"r": res}, "seed_spread": None})
    assert "rule_record_type" in md and "path_b (covers 100%)" in md
    assert res["fusion"]["point"]["false_alarms"] == 0


def test_score_cache_key_and_unicode_round_trip(tmp_path):
    """The cache key is computed without error, and string arrays survive np.load(allow_pickle=False)."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import pandas as pd
    import evaluate_detectors as ed
    run = tmp_path / "run"
    run.mkdir()
    for name in ("data.json", "split.json", "fusion_lr.pkl", "dns_tunnel_rf.pkl"):
        (run / name).write_text("x")
    k = ed.cache_key(run / "data.json", run / "split.json", run)
    assert len(k) == 16 and k == ed.cache_key(run / "data.json", run / "split.json", run)
    col = pd.Series(["a.example", "b.example"], dtype="string")      # pandas-3 style strings
    out = tmp_path / "c.npz"
    np.savez_compressed(out, domain=np.asarray(col.astype(str).tolist(), dtype=str))
    z = np.load(out, allow_pickle=False)
    assert list(z["domain"]) == ["a.example", "b.example"]
