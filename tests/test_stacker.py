"""Tests for fusion V2 (fusion/stacker.py) and the Neyman-Pearson threshold (models/thresholds.py)."""

import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.fusion import stacker  # noqa: E402
from dns_detect.models.thresholds import (  # noqa: E402
    InsufficientCalibrationError, np_min_samples, np_threshold, np_violation_bound,
)

SPEC = {"rule_thresholds": {"tunneling_length_threshold": 100.0, "tunneling_entropy_threshold": 4.0,
                            "subdomain_depth_threshold": 5.0},
        "transform": {"score_A": "logit", "score_B": "logit_standardised", "eps": stacker.EPS},
        "score_B_scaling": {"mean": 0.0, "std": 1.0, "n_present": 1}}


def _frame(a, b, length=None, ent=None, depth=None):
    n = len(a)
    return pd.DataFrame({"ml_score_A": a, "ml_score_B": b,
                         "query_length": length if length is not None else [20] * n,
                         "entropy": ent if ent is not None else [2.0] * n,
                         "subdomain_depth": depth if depth is not None else [1] * n})


def _synthetic(n_benign=600, n_attack=400, seed=0, n_groups=40):
    """Benign and attack rows in distinct parent-domain groups; Path B missing for ~5%."""
    rng = np.random.default_rng(seed)
    a = np.r_[rng.beta(1, 30, n_benign), rng.beta(30, 1, n_attack)]
    b = np.r_[rng.beta(2, 8, n_benign), rng.beta(8, 2, n_attack)]
    b[rng.random(len(b)) < 0.05] = np.nan
    y = np.r_[np.zeros(n_benign, int), np.ones(n_attack, int)]
    groups = np.r_[[f"b{i % n_groups}" for i in range(n_benign)], [f"a{i % 4}" for i in range(n_attack)]]
    df = _frame(a, b, length=rng.integers(10, 200, len(a)), ent=rng.uniform(1, 5, len(a)),
                depth=rng.integers(1, 8, len(a)))
    df["parent_domain"] = groups
    return df, y, groups


# ── 1–3 missing-value handling ───────────────────────────────────────────────

def test_missing_path_b_gives_has_score_b_zero():
    X = stacker.fusion_inputs_v2(_frame([0.5], [np.nan]), SPEC)
    assert X[0, 2] == 0.0 and X[0, 1] == 0.0


def test_real_zero_path_b_score_is_present():
    X = stacker.fusion_inputs_v2(_frame([0.5], [0.0]), SPEC)
    assert X[0, 2] == 1.0


def test_negative_path_b_score_is_present():
    X = stacker.fusion_inputs_v2(_frame([0.5, 0.5], [-0.3, 0.7]), SPEC)
    assert X[:, 2].tolist() == [1.0, 1.0]


def test_v1_input_builder_unchanged():
    X = stacker.fusion_inputs(_frame([0.9, 0.1], [0.0, 0.7], [150, 20], [4.5, 2.0], [7, 2]))
    assert X.shape == (2, 4) and X[0, 2] == 0.0 and X[0, 3] == 2.0      # V1 keeps its (b > 0) quirk


# ── 4 validation ─────────────────────────────────────────────────────────────

def test_missing_score_a_raises_keyerror():
    with pytest.raises(KeyError):
        stacker.fusion_inputs_v2(_frame([0.5], [0.5]).drop(columns="ml_score_A"), SPEC)


@pytest.mark.parametrize("bad", [np.nan, np.inf, "abc"])
def test_bad_score_a_raises(bad):
    df = _frame([0.5, 0.5], [0.5, 0.5]).astype({"ml_score_A": object})
    df.loc[1, "ml_score_A"] = bad
    with pytest.raises(ValueError):
        stacker.fusion_inputs_v2(df, SPEC)


def test_infinite_score_b_raises():
    with pytest.raises(ValueError):
        stacker.fusion_inputs_v2(_frame([0.5], [np.inf]), SPEC)


def test_missing_rule_column_raises_not_filled():
    with pytest.raises(KeyError):
        stacker.fusion_inputs_v2(_frame([0.5], [0.5]).drop(columns="subdomain_depth"), SPEC)


def test_rule_column_aliases_accepted():
    df = _frame([0.5], [0.5]).rename(columns={"entropy": "query_entropy", "subdomain_depth": "subdomain_count"})
    assert stacker.fusion_inputs_v2(df, SPEC).shape == (1, 5)


# ── 5–6 transforms ───────────────────────────────────────────────────────────

def test_probability_clipping_is_finite():
    X = stacker.fusion_inputs_v2(_frame([0.0, 1.0], [0.0, 1.0]), SPEC)
    assert np.all(np.isfinite(X))
    lim = math.log((1 - stacker.EPS) / stacker.EPS)
    assert X[0, 0] == pytest.approx(-lim) and X[1, 0] == pytest.approx(lim)


def test_logit_values():
    X = stacker.fusion_inputs_v2(_frame([0.5, 0.8], [0.5, 0.2]), SPEC)
    assert X[0, 0] == pytest.approx(0.0) and X[1, 0] == pytest.approx(math.log(4))
    assert X[1, 1] == pytest.approx(math.log(0.25))


def test_path_b_logit_recovers_z_score():
    z = np.array([-2.0, 0.0, 3.5])
    X = stacker.fusion_inputs_v2(_frame([0.5] * 3, 1 / (1 + np.exp(-z))), SPEC)
    assert np.allclose(X[:, 1], z)


def test_path_b_standardised_with_saved_statistics():
    spec = {**SPEC, "score_B_scaling": {"mean": 1.0, "std": 2.0}}
    X = stacker.fusion_inputs_v2(_frame([0.5], [1 / (1 + math.exp(-5.0))]), spec)
    assert X[0, 1] == pytest.approx(2.0)


# ── 7–8 rules ────────────────────────────────────────────────────────────────

def test_r3_and_r4_are_independent_columns():
    X = stacker.fusion_inputs_v2(_frame([0.5] * 3, [0.5] * 3, [150, 20, 150], [4.5, 2.0, 4.5], [1, 7, 7]), SPEC)
    assert X[:, 3].tolist() == [1.0, 0.0, 1.0]
    assert X[:, 4].tolist() == [0.0, 1.0, 1.0]


def test_rule_thresholds_frozen_after_config_change(monkeypatch, tmp_path):
    df, y, g = _synthetic()
    lr, meta, _ = stacker.fit_v2(df, y, g, 0.01, rule_thresholds=SPEC["rule_thresholds"])
    before = stacker.predict_versioned(df, lr, meta)
    monkeypatch.setattr(stacker, "_detection_setting", lambda name, default: 1.0)   # "edit settings.yaml"
    after = stacker.predict_versioned(df, lr, meta)
    assert np.array_equal(before[0], after[0]) and meta["rule_thresholds"] == SPEC["rule_thresholds"]


# ── 9–11 versioned loading ───────────────────────────────────────────────────

@pytest.fixture
def model_paths(monkeypatch, tmp_path):
    for name, fn in (("MODEL_FUSION", "v1.pkl"), ("META_FUSION", "v1.json"),
                     ("MODEL_FUSION_V2", "v2.pkl"), ("META_FUSION_V2", "v2.json")):
        monkeypatch.setattr(stacker, name, str(tmp_path / fn))
    return tmp_path


def test_v1_model_loads_and_predicts_identically(model_paths):
    df = _frame([0.0, 0.1, 0.9, 1.0], [0.0, 0.2, 0.8, 1.0])
    lr, meta = stacker.fit(df, np.array([0, 0, 1, 1]), 0.0)
    stacker.save(lr, meta)
    model, m = stacker.load_versioned(1)
    assert stacker.meta_version(m) == 1
    assert np.array_equal(stacker.predict(df, model, m)[0], stacker.predict_versioned(df, model, m)[0])
    assert stacker.load_versioned() is not None          # falls back to V1 when no V2 exists


def test_v2_save_load_validates_schema(model_paths):
    df, y, g = _synthetic()
    lr, meta, _ = stacker.fit_v2(df, y, g, 0.01)
    stacker.save_v2(lr, meta)
    model, m = stacker.load_versioned(2)
    assert m["model_version"] == 2 and m["feature_schema"] == stacker.FUSION_INPUTS_V2
    bad = {**m, "feature_schema": ["logit_A"]}
    (model_paths / "v2.json").write_text(json.dumps(bad))
    with pytest.raises(stacker.FusionSchemaError):
        stacker.load_versioned(2)


def test_v2_missing_metadata_key_raises(model_paths):
    df, y, g = _synthetic()
    lr, meta, _ = stacker.fit_v2(df, y, g, 0.01)
    meta = {k: v for k, v in meta.items() if k != "score_B_scaling"}
    with pytest.raises(stacker.FusionSchemaError):
        stacker.save_v2(lr, meta)


def test_unknown_version_raises(model_paths):
    with pytest.raises(stacker.FusionSchemaError):
        stacker.meta_version({"model_version": 7})
    with pytest.raises(stacker.FusionSchemaError):
        stacker.load_versioned(3)


def test_save_v2_never_overwrites_v1(model_paths, monkeypatch):
    df, y, g = _synthetic()
    lr, meta, _ = stacker.fit_v2(df, y, g, 0.01)
    with pytest.raises(ValueError):
        stacker.save_v2(lr, meta, model_path=stacker.MODEL_FUSION)


# ── 12–13 Neyman-Pearson ─────────────────────────────────────────────────────

def test_np_min_samples_matches_closed_form():
    assert np_min_samples(0.001, 0.05) == 2995
    n = np_min_samples(0.01, 0.1)
    assert (1 - 0.01) ** n <= 0.1 < (1 - 0.01) ** (n - 1)


def test_np_bound_at_k_equals_n_is_closed_form():
    assert np_violation_bound(3000, 3000, 0.001) == pytest.approx(0.999 ** 3000, rel=1e-9)


def test_np_bound_matches_binomial_tail():
    from math import comb
    n, k, a = 30, 27, 0.1
    exact = sum(comb(n, j) * (1 - a) ** j * a ** (n - j) for j in range(k, n + 1))
    assert np_violation_bound(n, k, a) == pytest.approx(exact, rel=1e-9)


def test_np_threshold_picks_smallest_valid_order_statistic():
    s = np.arange(1, 1001, dtype=float)
    r = np_threshold(s, 0.05, 0.05)
    assert np_violation_bound(1000, r["k"], 0.05) <= 0.05 < np_violation_bound(1000, r["k"] - 1, 0.05)
    assert r["threshold"] == s[r["k"] - 1] and r["rule"] == ">"


def test_np_guarantee_holds_by_simulation():
    rng = np.random.default_rng(7)
    alpha, delta, trials = 0.05, 0.1, 400
    viol = 0
    for _ in range(trials):
        t = np_threshold(rng.uniform(size=200), alpha, delta)["threshold"]
        viol += (1 - t) > alpha                   # population FPR of `score > t` for U(0,1) benign
    assert viol / trials <= delta + 0.04          # Monte-Carlo slack


def test_np_insufficient_samples_raises():
    with pytest.raises(InsufficientCalibrationError) as e:
        np_threshold(np.random.default_rng(0).uniform(size=1000), 0.001, 0.05)
    assert e.value.n_required == 2995


@pytest.mark.parametrize("alpha,delta", [(0, 0.05), (1, 0.05), (0.01, 0), (0.01, 1.5)])
def test_np_rejects_bad_parameters(alpha, delta):
    with pytest.raises(ValueError):
        np_threshold(np.ones(10), alpha, delta)


def test_np_ties_strict_rule_never_exceeds_budget():
    s = np.r_[np.zeros(3990), np.ones(10)]           # heavy ties
    r = np_threshold(s, 0.01, 0.05)
    assert (s > r["threshold"]).mean() <= 0.01


def test_fallback_threshold_recorded_in_metadata():
    df, y, g = _synthetic()
    _, meta, _ = stacker.fit_v2(df, y, g, 0.001)
    assert meta["threshold_method"].startswith("empirical_fallback")
    assert meta["n_required_for_np"] == 2995 and meta["n_cal_benign"] < 2995


def test_np_method_used_when_enough_calibration_rows():
    df, y, g = _synthetic(n_benign=4000, n_attack=400, n_groups=80)
    _, meta, _ = stacker.fit_v2(df, y, g, 0.01, delta=0.05)
    assert meta["threshold_method"] == "neyman_pearson" and meta["n_cal_benign"] >= 299


# ── 14–16 grouped CV, OOF, no test labels ────────────────────────────────────

def test_grouped_folds_have_no_parent_domain_overlap():
    _, y, g = _synthetic()
    folds, _ = stacker.oof_folds(y, g, 5, 0)
    for tr, te in folds:
        assert not set(g[tr]) & set(g[te])


def test_every_validation_row_gets_one_oof_prediction():
    df, y, g = _synthetic()
    out = stacker.oof_scores(df, y, g, 5, 0)
    assert not np.isnan(out["oof"]).any() and out["skipped_folds"] == []


def test_fit_and_calibration_parts_are_disjoint_groups_and_cal_is_benign():
    _, y, g = _synthetic()
    fit, cal = stacker.fit_cal_split(y, g, 0)
    assert not set(g[fit]) & set(g[cal])
    assert (y[cal] == 0).all() and set(np.r_[fit, cal]) == set(range(len(y)))


def test_threshold_ignores_held_out_test_labels():
    """eval_fusion.run_once: flipping every test-part label must not change any fitted model."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import eval_fusion
    df, y, _ = _synthetic(seed=1)
    df["label"] = y
    df["ml_label_A"] = (df["ml_score_A"] >= 0.5).astype(int)
    df["ml_label_B"] = (df["ml_score_B"].fillna(0) >= 0.5).astype(int)
    rng = np.random.default_rng(0)
    idx = rng.permutation(len(df))
    fit_idx, test_idx = np.sort(idx[:700]), np.sort(idx[700:])
    r1 = eval_fusion.run_once(df, fit_idx, test_idx, 3, 0.01, 0.05)
    flipped = df.copy()
    flipped.loc[flipped.index[test_idx], "label"] = 1 - flipped["label"].to_numpy()[test_idx]
    r2 = eval_fusion.run_once(flipped, fit_idx, test_idx, 3, 0.01, 0.05)
    for m in ("fusion_v1", "fusion_v2"):
        assert r1["methods"][m]["threshold"] == r2["methods"][m]["threshold"]
        assert r1["methods"][m]["coefficients"] == r2["methods"][m]["coefficients"]


# ── 17–20 train/inference consistency, metadata, bridge, determinism ────────

def test_training_and_inference_use_identical_transform():
    df, y, g = _synthetic()
    lr, meta, diag = stacker.fit_v2(df, y, g, 0.01)
    cal = df.iloc[diag["cal_idx"]]
    score, _ = stacker.predict_versioned(cal, lr, meta)
    assert np.allclose(score, diag["cal_scores"])


def test_metadata_is_complete():
    df, y, g = _synthetic()
    _, meta, _ = stacker.fit_v2(df, y, g, 0.01, extra_meta={"dataset_sha256": "x"})
    for k in stacker.REQUIRED_META_V2 + ("rows", "versions", "trained_at", "random_seed", "cv",
                                         "tier_boundaries", "class_prior_validation", "dataset_sha256"):
        assert k in meta, k
    assert set(meta["versions"]) == {"python", "numpy", "pandas", "scikit_learn"}
    assert meta["score_name"] == "fusion_score" and meta["class_weight"] is None


def test_tier_boundaries_monotone():
    t = stacker.tier_boundaries(np.r_[np.zeros(500), np.linspace(0, 1, 500)], 0.3)
    assert t["q90"] <= t["q99"] <= t["high"] == 0.3


def test_repeated_predictions_are_deterministic():
    df, y, g = _synthetic()
    lr1, m1, _ = stacker.fit_v2(df, y, g, 0.01, seed=5)
    lr2, m2, _ = stacker.fit_v2(df, y, g, 0.01, seed=5)
    assert m1["coefficients"] == m2["coefficients"] and m1["threshold"] == m2["threshold"]
    assert np.array_equal(stacker.predict_versioned(df, lr1, m1)[0], stacker.predict_versioned(df, lr2, m2)[0])


def test_strict_alarm_rule():
    df, y, g = _synthetic()
    lr, meta, _ = stacker.fit_v2(df, y, g, 0.01)
    score, label = stacker.predict_versioned(df, lr, meta)
    assert np.array_equal(label, (score > meta["threshold"]).astype(int))
