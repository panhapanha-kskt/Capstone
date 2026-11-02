"""Tests for scripts/make_evasion_set.py (ML_IMPROVEMENT_GUIDE Step 8)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import make_evasion_set as ev  # noqa: E402

PAYLOAD_DOMAIN = "aabbccddeeffgghhiijjkkllmmnnoopp.qqrrssttuu.tun.example.com"


def _attack_rows(n=10):
    return [{"label": 1, "domain": PAYLOAD_DOMAIN, "query_type": "TXT", "client_ip": "10.0.0.1",
             "source_file": "cap.pcap", "attack_family": "toolx",
             "timestamp": f"2026-01-01T00:00:{i:02d}"} for i in range(n)]


def test_short_labels_at_most_15():
    d = ev._rewrite(PAYLOAD_DOMAIN, "short_labels", 0)
    sub = d[: -len(".example.com")]
    assert all(len(p) <= 15 for p in sub.split("."))


def test_hex_is_hex_payload():
    d = ev._rewrite(PAYLOAD_DOMAIN, "hex", 0)
    first = d.split(".")[0]
    assert all(c in "0123456789abcdef" for c in first)


def test_names_respect_dns_limits():
    for v in ev.VARIANTS:
        d = ev._rewrite(PAYLOAD_DOMAIN * 3, v, 1)
        assert len(d) <= 253 or v in ("original", "slow", "a_aaaa")
        assert all(len(p) <= 63 for p in d.split(".")) or v in ("original", "slow", "a_aaaa")


def test_spread_uses_five_parents():
    from dns_detect.ingest.labeling import parent_domain
    parents = {parent_domain(ev._rewrite(PAYLOAD_DOMAIN, "spread", i)) for i in range(10)}
    assert len(parents) == 5


def test_generate_splits_halves_and_slows_time():
    rows = ev.generate(_attack_rows(10))
    slow = [r for r in rows if r["evasion_variant"] == "slow"]
    assert sum(r["evasion_split"] == "test" for r in slow) == 5
    assert slow[-1]["timestamp"].startswith("2026-01-01T00:01:30")   # 9 s × 10
    a = [r for r in rows if r["evasion_variant"] == "a_aaaa"]
    assert {r["query_type"] for r in a} == {"A", "AAAA"}
    assert all(r["label"] == 1 for r in rows)
