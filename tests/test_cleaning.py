"""Tests for ingest/cleaning.py, Path A outlier capping and the model-feature leakage guard."""
import os
import sys

import numpy as np
import pandas as pd
import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

from dns_detect.ingest.cleaning import clean_records  # noqa: E402
from dns_detect.models.path_a import apply_clip, fit_clip_bounds  # noqa: E402
from dns_detect.parsing.dns_parser import check_model_features, missing_value_report  # noqa: E402


def pkt(domain, port=40000, **kw):
    r = {"domain": domain, "timestamp": "2026-10-23T23:22:27.454732", "client_ip": "10.0.0.1",
         "client_port": port, "query_type": "A", "protocol": "UDP", "query_length": len(domain)}
    r.update(kw)
    return r


def test_normalises_name_and_types():
    kept, _, rep = clean_records([pkt("WWW.Example.COM.", query_type=" txt", protocol="udp")])
    assert kept[0]["domain"] == "www.example.com"
    assert kept[0]["query_type"] == "TXT" and kept[0]["protocol"] == "UDP"
    assert rep["normalised_values"] == {"domain": 1, "query_type": 1, "protocol": 1}


@pytest.mark.parametrize("rec, reason", [
    (pkt(""), "empty_domain"),
    (pkt(".".join(["a" * 60] * 4) + ".example.com"), "name_too_long"),      # 255 chars
    (pkt("x" * 64 + ".com"), "label_too_long"),
    (pkt("a.com", label=2), "bad_label"),
    (pkt("a.com", digit_ratio=1.5), "out_of_range_feature"),
    (pkt("a.com", query_length=-3), "out_of_range_feature"),
    (pkt("a.com", entropy=float("inf")), "non_finite_feature"),
])
def test_rejects_what_cannot_be_dns(rec, reason):
    kept, rejected, rep = clean_records([rec, pkt("ok.com", port=1)])
    assert [r["domain"] for r in kept] == ["ok.com"]
    assert rejected[0]["reject_reason"] == reason
    assert rep["rejected_by_reason"] == {reason: 1}


def test_tunnel_payload_characters_are_flagged_not_dropped():
    name = "sisaqgc/ba+x.dns2tcp-key.com"
    kept, rejected, rep = clean_records([pkt(name, label=1), pkt("4.3.2.1.in-addr.arpa", port=1, label=0),
                                         pkt("com", port=2, label=0)])
    assert not rejected and kept[0]["domain"] == name
    assert rep["flags"]["non_hostname_chars"] == {"rows": 1, "by_label": {"1": 1}}
    assert rep["flags"]["infra_query"] == {"rows": 2, "by_label": {"0": 2}}


def test_only_identical_packet_copies_are_dropped():
    recs = [pkt("a.com"), pkt("a.com"),           # copy of the same packet
            pkt("a.com", port=40001),              # parallel query from another port: real traffic
            {"domain": "b.com"}, {"domain": "b.com"}]   # no packet identity: repeats kept
    kept, _, rep = clean_records(recs)
    assert len(kept) == 4 and rep["exact_packet_copies_dropped"] == 1
    kept, _, _ = clean_records(recs, {"drop_exact_packet_copies": False})
    assert len(kept) == 5


def test_unparsed_timestamps_are_counted():
    _, _, rep = clean_records([pkt("a.com", timestamp="not a time"), pkt("b.com", port=1)])
    assert rep["flags"]["unparsed_timestamp"]["rows"] == 1


def test_input_records_are_not_modified():
    r = pkt("A.COM.")
    clean_records([r])
    assert r["domain"] == "A.COM."


def test_clip_bounds_come_from_train_and_cap_test():
    X_train = np.column_stack([np.arange(1000.0), np.zeros(1000)])
    bounds = fit_clip_bounds(X_train, 0.99)
    X_test = np.array([[5000.0, 0.0], [-10.0, 0.0], [500.0, 0.0]])
    capped, counts = apply_clip(X_test, bounds)
    assert capped[0, 0] == pytest.approx(bounds["high"][0]) and capped[1, 0] == pytest.approx(bounds["low"][0])
    assert capped[2, 0] == 500.0 and counts.tolist() == [2, 0]


def test_clip_off_changes_nothing():
    X = np.array([[1.0, 1e9]])
    assert fit_clip_bounds(X, 0) is None
    out, counts = apply_clip(X, None)
    assert out is X and counts.tolist() == [0, 0]


def test_missing_value_report():
    df = pd.DataFrame({"query_length": [3, None, "x"], "digit_ratio": [0.1, 0.2, 0.3]})
    rep = missing_value_report(df, ["query_length", "digit_ratio", "answer_count"])
    assert rep["query_length"] == {"absent": False, "missing": 2, "share": 0.6667}
    assert rep["answer_count"]["absent"] and rep["answer_count"]["missing"] == 3
    assert "digit_ratio" not in rep


def test_identity_columns_can_never_be_model_inputs():
    with pytest.raises(ValueError, match="client_ip"):
        check_model_features(["query_length", "client_ip"])
    check_model_features(["query_length", "digit_ratio"])
