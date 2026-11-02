"""Tests for src/dns_detect/models/baselines.py (Need-Improve.md N4)."""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.models.baselines import (  # noqa: E402
    record_type_rule, entropy_threshold, length_threshold,
    literature_entropy_rule, fit_threshold, fit_all_baselines,
)


def _df():
    return pd.DataFrame({
        "query_type": ["A", "TXT", "AAAA", "NULL", "KEY", "A", "TXT", "MX", "A", "A"],
        "query_entropy": [1.0, 4.5, 2.0, 5.0, 4.1, 1.1, 4.2, 3.0, 1.0, 1.5],
        "query_length": [10, 60, 15, 55, 70, 11, 65, 20, 12, 18],
        "label": [0, 1, 0, 1, 1, 0, 1, 0, 0, 0],
    })


def test_record_type_rule_matches_hand_count():
    df = _df()
    out = record_type_rule(df)
    assert out.sum() == 4  # TXT, NULL, KEY, TXT
    assert out.dtype == bool


def test_record_type_rule_absent_column():
    df = pd.DataFrame({"query_entropy": [1.0, 2.0]})
    assert record_type_rule(df).sum() == 0


def test_entropy_threshold_rule():
    df = _df()
    out = entropy_threshold(4.0).predict(df)
    # entropies > 4.0: 4.5, 5.0, 4.1, 4.2 → 4 True
    assert out.sum() == 4


def test_literature_entropy_rule_frozen_at_4():
    assert literature_entropy_rule().threshold == 4.0


def test_fit_threshold_prefers_discriminative_t():
    y = np.array([0, 0, 0, 1, 1, 1])
    v = np.array([1.0, 1.5, 2.0, 5.0, 5.5, 6.0])
    t = fit_threshold(y, v)
    # Any t in [2.0, 5.0) gives perfect F1; the grid should return something in that range.
    assert 2.0 <= t < 5.0


def test_fit_threshold_empty_inputs():
    assert fit_threshold(np.array([]), np.array([])) == 0.0


def test_fit_all_baselines_returns_four_detectors():
    df = _df()
    y = df["label"].to_numpy()
    detectors = fit_all_baselines(df, y)
    assert set(detectors) == {"record_type", "entropy_train_fit", "entropy_4.0_literature", "length_train_fit"}
    for name, det in detectors.items():
        pred = det.predict(df)
        score = det.score(df)
        assert pred.dtype == bool
        assert len(pred) == len(df)
        assert len(score) == len(df)


def test_length_threshold_fits_sensibly():
    df = _df()
    y = df["label"].to_numpy()
    detectors = fit_all_baselines(df, y)
    length_rule = detectors["length_train_fit"]
    # Attack queries have lengths 60/55/70/65; benign is ≤ 20. A threshold between 20
    # and 55 is correct; fit_threshold prefers the smaller t on ties.
    assert 20 <= length_rule.threshold < 55
