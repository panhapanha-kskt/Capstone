"""Path C converter: native query rows → DNSTunnel2026's 38 window features (features/dnstunnel2026.py).

Hand-computed expectations on a tiny two-client capture. No scikit-learn, no TensorFlow."""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.features import dnstunnel2026 as d26  # noqa: E402

T0 = "2026-11-21T10:00:"   # all rows inside one minute → they share the same first window tick


def _rows():
    # client A: 3 queries to evil-tunnel.com (2 distinct FQDNs, A + TXT), 1 query to google.com
    # client B: 1 query to evil-tunnel.com (third distinct FQDN), 2 queries to google.com
    return pd.DataFrame([
        {"domain": "k3jd92lsa0f.evil-tunnel.com", "timestamp": T0 + "01", "client_ip": "A", "query_type": "TXT", "label": 1, "attack_family": "iodine"},
        {"domain": "k3jd92lsa0f.evil-tunnel.com", "timestamp": T0 + "02", "client_ip": "A", "query_type": "TXT", "label": 1, "attack_family": "iodine"},
        {"domain": "q7w2e9r4t1y6.evil-tunnel.com", "timestamp": T0 + "03", "client_ip": "A", "query_type": "A",   "label": 1, "attack_family": "iodine"},
        {"domain": "www.google.com",              "timestamp": T0 + "04", "client_ip": "A", "query_type": "A",   "label": 0, "attack_family": None},
        {"domain": "mail.evil-tunnel.com",        "timestamp": T0 + "05", "client_ip": "B", "query_type": "MX",  "label": 0, "attack_family": None},
        {"domain": "www.google.com",              "timestamp": T0 + "06", "client_ip": "B", "query_type": "A",   "label": 0, "attack_family": None},
        {"domain": "www.google.com",              "timestamp": T0 + "07", "client_ip": "B", "query_type": "AAAA", "label": 0, "attack_family": None},
    ])


def _first_window(win: pd.DataFrame, company: str, parent: str) -> pd.Series:
    sub = win[(win.company == company) & (win.parent_domain == parent)].sort_values("window_end")
    assert len(sub) == 5, "a query inside one minute belongs to 5 consecutive 1-minute ticks"
    return sub.iloc[0]


def test_feature_list_matches_dataset_order():
    assert len(d26.FEATURES_C) == 38
    assert d26.FEATURES_C[0] == "hits" and d26.FEATURES_C[-1] == "file_chunk_detection_positive_ratio"
    assert "dns_type_TXT_count" in d26.FEATURES_C and "dns_type_OTHER_ratio" in d26.FEATURES_C


def test_window_counts_and_record_profile():
    win, member = d26.window_features(_rows(), d26.Readability())
    a_evil = _first_window(win, "A", "evil-tunnel.com")
    assert a_evil.hits == 3 and a_evil.fqdn_count == 2 and a_evil.fqdn_hit_ratio == pytest.approx(1.5)
    assert a_evil.unique_dns_types == 2
    assert a_evil.dns_type_TXT_count == 2 and a_evil.dns_type_TXT_ratio == pytest.approx(2 / 3)
    assert a_evil.dns_type_A_count == 1 and a_evil.dns_type_OTHER_count == 0
    assert a_evil.top1_records_count == 2 and a_evil.top1_records_ratio == pytest.approx(2 / 3)
    # client A sent 4 queries in the window, 3 of them to this domain
    assert a_evil.domain_data_portion == pytest.approx(0.75)
    # label aggregation: any attack query → attack window, family carried
    assert a_evil.label == 1 and a_evil.attack_rows == 3 and a_evil.attack_family == "iodine"
    b_google = _first_window(win, "B", "google.com")
    assert b_google.hits == 2 and b_google.dns_type_AAAA_count == 1 and b_google.label == 0
    assert b_google.attack_family == "benign"


def test_other_company_features_same_window():
    win, _ = d26.window_features(_rows(), d26.Readability())
    a_evil = _first_window(win, "A", "evil-tunnel.com")
    # the other company (B) sent 1 query to evil-tunnel.com with 1 FQDN nobody else used
    assert a_evil.other_comp_window_hits == 1
    assert a_evil.other_comp_window_unique_company == 1
    assert a_evil.other_comp_window_fqdn_count == 1
    assert a_evil.other_comp_window_fqdn_hit_ratio == pytest.approx(1.0)
    # B's view of google.com: A sent 1 query to www.google.com, the same FQDN B uses → not exclusive to B
    b_google = _first_window(win, "B", "google.com")
    assert b_google.other_comp_window_hits == 1 and b_google.other_comp_window_fqdn_count == 1
    # 24 h history covers the same rows here (nothing older), so it equals the window view
    assert a_evil.other_comp_last_24_hits == 1 and a_evil.other_comp_last_24_unique_company == 1
    assert a_evil.other_comp_last_24_fqdn_count == 1 and a_evil.other_comp_last_24_fqdn_hit_ratio == pytest.approx(1.0)


def test_history_window_sees_older_traffic_but_current_window_does_not():
    rows = _rows()
    old = rows.iloc[[4]].copy()                       # B → mail.evil-tunnel.com, 3 hours earlier
    old["timestamp"] = "2026-11-21T07:00:00"
    win, _ = d26.window_features(pd.concat([old, rows], ignore_index=True), d26.Readability())
    a_evil = _first_window(win, "A", "evil-tunnel.com")
    assert a_evil.other_comp_window_hits == 1          # only B's 10:00 query
    assert a_evil.other_comp_last_24_hits == 2         # plus the 07:00 one
    assert a_evil.other_comp_last_24_fqdn_count == 1   # same FQDN twice


def test_readability_heuristic_and_ratio():
    r = d26.Readability()                              # no fastText file → heuristic
    assert r.source == "heuristic"
    flags = r.positive(["k3jd92lsa0f", "mail", "", "www"])
    assert flags.tolist() == [True, False, False, False]
    win, _ = d26.window_features(_rows(), r)
    a_evil = _first_window(win, "A", "evil-tunnel.com")
    assert a_evil.file_chunk_detection_positive == 2 and a_evil.file_chunk_detection_negative == 0
    assert a_evil.file_chunk_detection_positive_ratio == pytest.approx(1.0)
    b_evil = _first_window(win, "B", "evil-tunnel.com")
    assert b_evil.file_chunk_detection_positive == 0 and b_evil.file_chunk_detection_negative == 1


def test_membership_maps_every_row_to_five_windows_and_scores_come_back():
    rows = _rows()
    win, member = d26.window_features(rows, d26.Readability())
    assert member.shape == (len(rows) * 5, 2)
    assert set(member[:, 0]) == set(range(len(rows)))
    # per-window score = 1 for attack windows, 0 otherwise → attack queries get 1 back, benign 0
    score = win["label"].to_numpy(dtype=float)
    per_row, covered = d26.rows_from_windows(len(rows), member, score, how="max")
    assert covered.all()
    assert per_row[:3].tolist() == [1.0, 1.0, 1.0] and per_row[3:].tolist() == [0.0] * 4
    first, _ = d26.rows_from_windows(len(rows), member, win["window_end"].to_numpy(), how="first")
    assert (first == win["window_end"].min()).all()    # every query's first window ends at the first tick


def test_rows_without_timestamp_or_domain_are_uncovered():
    rows = _rows()
    rows.loc[0, "timestamp"] = None
    rows.loc[1, "domain"] = ""
    win, member = d26.window_features(rows, d26.Readability())
    _, covered = d26.rows_from_windows(len(rows), member, np.zeros(len(win)))
    assert not covered[0] and not covered[1] and covered[2:].all()


def test_empty_input():
    win, member = d26.window_features(pd.DataFrame(columns=["domain", "timestamp", "client_ip"]), d26.Readability())
    assert len(win) == 0 and member.shape == (0, 2)
    assert list(win.columns[:3]) == d26.KEY_COLUMNS


def test_mixed_timestamp_formats_are_ordered_correctly():
    """Audit finding #2: a second timestamp format must not fall back to row order."""
    rows = _rows()
    rows.loc[4, "timestamp"] = "2026-11-21 10:00:05.123456"   # space + microseconds, same instant
    win, _ = d26.window_features(rows, d26.Readability())
    assert _first_window(win, "A", "evil-tunnel.com").other_comp_window_hits == 1
