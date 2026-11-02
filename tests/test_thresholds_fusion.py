"""Tests for models/thresholds.py, fusion/stacker.py inputs and stable row ids (Steps 2, 5, 7)."""

import sys
from pathlib import Path

import numpy as np
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
