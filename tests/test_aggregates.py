"""Tests for features/aggregates.py (ML_IMPROVEMENT_GUIDE Step 3)."""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.features.aggregates import (  # noqa: E402
    BigramModel, FEATURES_WINDOW, add_window_features,
)


def _tunnel(n=60, step_s=1.0, client="10.0.0.9", parent="tun.example.com", qtype="TXT"):
    t0 = pd.Timestamp("2026-01-01T00:00:00")
    return pd.DataFrame({
        "domain": [f"x{i:04d}abc.{parent}" for i in range(n)],
        "client_ip": client,
        "query_type": qtype,
        "response_code": "noerror",
        "timestamp": [(t0 + pd.Timedelta(seconds=i * step_s)).isoformat() for i in range(n)],
    })


def test_all_window_columns_added():
    out = add_window_features(_tunnel(10))
    for c in FEATURES_WINDOW:
        assert c in out.columns


def test_sixty_unique_subdomains_counted_at_last_query():
    out = add_window_features(_tunnel(60))
    assert out["uniq_subdomains_5m"].iloc[-1] == 60
    assert out["uniq_ratio_5m"].iloc[-1] == 1.0
    assert out["tunnel_rr_share_5m"].iloc[-1] == 1.0


def test_past_only_no_future_leak():
    """A query's features must not change when later queries are added."""
    df = _tunnel(60)
    early = add_window_features(df.iloc[:30].copy())
    full = add_window_features(df)
    cols = FEATURES_WINDOW
    np.testing.assert_allclose(early[cols].to_numpy(), full.iloc[:30][cols].to_numpy())


def test_window_forgets_old_queries():
    """Queries more than 5 minutes apart never share a window."""
    df = _tunnel(10, step_s=400.0)
    out = add_window_features(df)
    assert (out["uniq_subdomains_5m"] == 1).all()


def test_regular_timing_has_zero_iat_std():
    out = add_window_features(_tunnel(20, step_s=2.0))
    assert out["iat_std_5m"].iloc[-1] < 1e-9
    assert out["iat_std_5m"].iloc[0] == -1.0     # fewer than 3 queries yet


def test_deterministic_and_order_independent():
    df = _tunnel(40)
    a = add_window_features(df)
    b = add_window_features(df.sample(frac=1.0, random_state=1)).sort_index()
    np.testing.assert_allclose(a[FEATURES_WINDOW].to_numpy(), b[FEATURES_WINDOW].to_numpy())


def test_missing_timestamp_does_not_crash():
    df = _tunnel(5)
    df.loc[2, "timestamp"] = None
    out = add_window_features(df)
    assert out["qpm_client_5m"].notna().all()


def test_bigram_scores_words_above_random_strings():
    m = BigramModel().fit(["www.google.com", "mail.yahoo.com", "news.bbc.co.uk", "store.apple.com",
                           "login.microsoft.com", "images.amazon.com", "maps.google.com"])
    assert m.score("www.amazon.com") > m.score("q7zx9k2vbw4.example.com")


def test_bigram_roundtrip():
    m = BigramModel().fit(["www.example.com"])
    m2 = BigramModel.from_dict(m.to_dict())
    assert m.score("www.example.org") == m2.score("www.example.org")
