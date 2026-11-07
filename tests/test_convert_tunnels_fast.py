"""The fast path of scripts/convert_external_tunnels.py must produce exactly what the original
(--legacy) path produces: same truncation counts, same domain, same kept rows, same records."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

scapy_all = pytest.importorskip("scapy.all")

import convert_external_tunnels as cet  # noqa: E402
from dns_detect.features.extractor import DNSFeatureExtractor  # noqa: E402
from make_labeled_features import truncation_report  # noqa: E402


def _query(name, t, sport=40000, qtype="TXT", tcp=False):
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether
    l4 = TCP(sport=sport, dport=53) if tcp else UDP(sport=sport, dport=53)
    p = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / l4 / DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype))
    p.time = t
    return p


def _response(name, t):
    from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether
    p = (Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / UDP(sport=53, dport=40000)
         / DNS(qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata="1.2.3.4")))
    p.time = t
    return p


def _make_family(tmp_path: Path) -> Path:
    from scapy.all import IP, UDP, Ether, Raw, wrpcap
    fam = tmp_path / "root" / "faketool"
    fam.mkdir(parents=True)
    t0 = 1_600_000_000.0
    for f in range(2):
        pkts = []
        for i in range(60):
            t = t0 + f * 1000 + i
            pkts.append(_query(f"a{i:03d}x{f}q9z.data.tunnel-example.com", t, qtype="TXT" if i % 3 else "A"))
            if i % 5 == 0:
                pkts.append(_response(f"a{i:03d}x{f}q9z.data.tunnel-example.com", t + 0.1))
            if i % 7 == 0:
                pkts.append(_query("www.ordinary-site.org", t + 0.2, qtype="A"))
            if i % 11 == 0:
                pkts.append(Ether() / IP() / UDP(sport=5000, dport=6000) / Raw(b"not dns"))
        pkts.append(_query("x1y2.data.tunnel-example.com", t0 + f * 1000 + 99, tcp=True))
        wrpcap(str(fam / f"faketool_txt_{f}.pcap"), pkts)
    return fam


def test_scan_matches_truncation_report(tmp_path):
    fam = _make_family(tmp_path)
    for pcap in cet.family_pcaps(fam):
        rep, _ = cet.scan_pcap(str(pcap))
        assert rep == truncation_report(str(pcap))


@pytest.mark.parametrize("max_rows", [0, 50])     # no cap, and a cap that drops rows
def test_fast_path_equals_legacy(tmp_path, max_rows):
    fam = _make_family(tmp_path)
    ex = DNSFeatureExtractor()

    legacy, l_dom, l_drop = cet.convert_family_legacy(fam, ex, None, 0.01)
    l_n = len(legacy)
    legacy = cet.cap_family(legacy, max_rows, 10, 42)

    scanned = cet.scan_all([(fam, p) for p in cet.family_pcaps(fam)], jobs=1)
    fast, f_dom, f_drop, f_n = cet.convert_family(fam, ex, None, 0.01, scanned, max_rows, 10, 42)

    assert (f_dom, f_drop, f_n) == (l_dom, l_drop, l_n)
    assert f_dom == "tunnel-example.com" and f_drop > 0
    assert fast == legacy                                # same rows, same keys, same values
    assert [list(r) for r in fast] == [list(r) for r in legacy]   # same key order
    if max_rows:
        assert len(fast) == max_rows


def test_parallel_scan_equals_serial(tmp_path):
    fam = _make_family(tmp_path)
    jobs = [(fam, p) for p in cet.family_pcaps(fam)]
    assert cet.scan_all(jobs, jobs=2) == cet.scan_all(jobs, jobs=1)
