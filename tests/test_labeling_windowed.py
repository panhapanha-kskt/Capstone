"""Tests for N9 windowed-labeling additions in src/dns_detect/ingest/labeling.py."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.ingest.labeling import (  # noqa: E402
    domain_stats, label_records, labeling_config_hash, load_settings,
)


def _records(parent="tunnel.example", n_subs=60, qtype="TXT", ts_base="2026-01-01T00:00:00Z", client="10.0.0.1"):
    return [
        {
            "domain": f"sub{i}.{parent}",
            "query_type": qtype,
            "client_ip": client,
            "response_code": "NOERROR",
            "timestamp": ts_base,
        }
        for i in range(n_subs)
    ]


def test_labeling_config_hash_is_stable():
    cfg = load_settings()
    h1 = labeling_config_hash(cfg, {"benign.example"})
    h2 = labeling_config_hash(cfg, {"benign.example"})
    assert h1 == h2
    h3 = labeling_config_hash(cfg, set())
    assert h1 != h3


def test_window_bucket_present_when_enabled():
    cfg = load_settings()
    cfg["window_seconds"] = 3600
    df, parents, enum, by_window = domain_stats(_records(), cfg)
    assert "window" in df.columns
    assert len(by_window) >= 1  # at least one (parent, window) bucket exists


def test_window_bucket_empty_when_disabled():
    cfg = load_settings()
    cfg["window_seconds"] = 0
    _, _, _, by_window = domain_stats(_records(), cfg)
    assert by_window == {}


def test_labeling_report_includes_new_fields():
    cfg = load_settings()
    cfg["window_seconds"] = 3600
    labeled, abstained, report = label_records(_records(), cfg=cfg)
    assert "labeling_config_hash" in report
    assert "abstain_share_by_source" in report
    assert "abstain_share_by_family" in report
    assert report["window_seconds"] == 3600


def test_tunnel_record_type_triggers_attack_label():
    """Many unique TXT subdomains with high unique ratio → attack vote."""
    cfg = load_settings()
    cfg["window_seconds"] = 0
    labeled, abstained, report = label_records(_records(n_subs=60), cfg=cfg)
    # min_attack_votes = 2 by default; many_unique_subdomains + tunnel_record_types vote.
    assert report["attack"] >= 1
