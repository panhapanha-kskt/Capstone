"""Tests for EDA #1 (features/eda_data.py) and make_labeled_features.py --unlabeled."""
import csv
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

from dns_detect.features import eda_data  # noqa: E402


# ── helpers ─────────────────────────────────────────────────

def log_line(ts, ip, qname, qtype="A", rcode="NoError", answer=""):
    return (f"[{ts} Local] [{ip}:5353] [UDP] QNAME: {qname}; QTYPE: {qtype}; QCLASS: IN; "
            f"RCODE: {rcode}; ANSWER: [{answer}]\n")


def write_log(path, lines):
    path.write_text("".join(lines), encoding="utf-8")
    return str(path)


def write_json(path, records):
    path.write_text(json.dumps(records), encoding="utf-8")
    return str(path)


def rec(domain, label=None, family=None, ts="2026-01-01T10:00:00", ip="10.0.0.1", qtype="A"):
    r = {"domain": domain, "timestamp": ts, "client_ip": ip, "query_type": qtype,
         "response_code": "unknown", "answer_size": 0}
    if label is not None:
        r["label"] = label
        r["attack_family"] = family or ("benign" if label == 0 else "tunnel")
    return r


TUNNEL = "a" * 60 + ".b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0.tunnel.example.com"


@pytest.fixture
def labeled_json(tmp_path):
    recs = ([rec(f"site{i}.com", 0, ts=f"2026-01-01T10:{i % 60:02d}:00") for i in range(60)]
            + [rec(f"{i}{TUNNEL}", 1, "dns2tcp", ts=f"2026-01-01T11:{i % 60:02d}:00", qtype="TXT")
               for i in range(40)])
    return write_json(tmp_path / "labeled.json", recs)


@pytest.fixture
def flood_log(tmp_path):
    lines = ["[2026-03-18 13:43:05 Local] DNS Server config file was loaded\n"]
    lines += [log_line(f"2026-03-18 13:44:{i % 60:02d}", "192.168.1.5", f"w{i}.lab.local", rcode="NxDomain")
              for i in range(120)]
    return write_log(tmp_path / "flood.log", lines)


# ── label status ────────────────────────────────────────────

def test_label_status_by_type(tmp_path, labeled_json):
    partial = write_json(tmp_path / "partial.json", [rec("a.com", 0), rec("b.com")])
    unl = write_json(tmp_path / "unl.json", [rec("a.com"), rec("b.com")])
    csv_lab = tmp_path / "lab.csv"
    csv_lab.write_text("domain,label\na.com,1\nb.com,0\n", encoding="utf-8")
    csv_unl = tmp_path / "unl.csv"
    csv_unl.write_text("domain\na.com\n", encoding="utf-8")
    log = write_log(tmp_path / "x.log", [log_line("2026-01-01 10:00:00", "1.2.3.4", "a.com")])

    assert eda_data.label_status(labeled_json)["status"] == "labeled"
    assert eda_data.label_status(partial) == {"status": "partial", "rows": 2, "labeled_rows": 1}
    assert eda_data.label_status(unl)["status"] == "unlabeled"
    assert eda_data.label_status(str(csv_lab))["status"] == "labeled"
    assert eda_data.label_status(str(csv_unl))["status"] == "unlabeled"
    assert eda_data.label_status(log)["status"] == "unlabeled"
    assert eda_data.label_status("cap.pcap", None)["status"] == "unlabeled"
    assert eda_data.label_status("cap.pcap", "1")["status"] == "labeled"


# ── section A: labeled ──────────────────────────────────────

def test_labeled_section_balance_and_easy_measure(labeled_json):
    rep = eda_data.run_eda([labeled_json], [])
    a = rep["labeled"]
    assert a["class_balance"] == {"attack": 40, "benign": 60, "attack_share": 0.4}
    assert a["separability_auc"]["query_length"] == 1.0
    assert any("'query_length' alone separates" in w for w in rep["warnings"])
    assert a["same_period"] is True        # captured an hour apart: same period


def test_labeled_classes_from_different_periods(tmp_path):
    path = write_json(tmp_path / "l.json",
                      [rec("a.com", 0, ts="2026-05-01T00:00:00") for _ in range(10)]
                      + [rec("b.com", 1, ts="2019-05-01T00:00:00") for _ in range(10)])
    rep = eda_data.run_eda([path], [])
    assert rep["labeled"]["same_period"] is False
    assert rep["labeled"]["gap_days"] > 2500
    assert any("days apart" in w for w in rep["warnings"])


# ── section B: unlabeled ────────────────────────────────────

def test_unlabeled_flood_and_empty_file(tmp_path, flood_log):
    empty = write_log(tmp_path / "empty.log", ["[2026-03-19 00:03:22 Local] Logging started.\n"])
    rep = eda_data.run_eda([], [flood_log, empty])
    per_file = {f["file"]: f for f in rep["unlabeled"]["per_file"]}
    assert per_file["flood.log"]["queries"] == 120
    assert per_file["flood.log"]["lines"] == 121
    assert per_file["flood.log"]["nxdomain_rate"] == 1.0
    assert per_file["flood.log"]["top_client_share"] == 1.0
    assert per_file["empty.log"]["queries"] == 0
    w = " ".join(rep["warnings"])
    assert "empty.log has 0 DNS queries" in w
    assert "one client (192.168.1.5)" in w
    assert "NXDOMAIN rate" in w
    assert "unique subdomains under lab.local" in w


def test_long_label_counted(tmp_path):
    path = write_log(tmp_path / "t.log", [log_line("2026-01-01 10:00:00", "1.1.1.1", TUNNEL, "TXT")])
    rep = eda_data.run_eda([], [path])
    assert rep["unlabeled"]["profile"]["long_labels"] == 1
    assert rep["unlabeled"]["profile"]["tunnel_qtype_share"] == 1.0


# ── section C: comparison ───────────────────────────────────

def test_comparison_shift_and_nearest_profile(labeled_json, tmp_path):
    same = write_json(tmp_path / "same.json", [rec(f"site{i}.com") for i in range(60)])
    rep = eda_data.run_eda([labeled_json], [same])
    near = {p["file"]: p for p in rep["comparison"]["nearest_profile"]}
    assert near["same.json"]["looks_like"] == "benign"

    tunnel_like = write_json(tmp_path / "tun.json", [rec(f"{i}{TUNNEL}", qtype="TXT") for i in range(60)])
    rep2 = eda_data.run_eda([labeled_json], [tunnel_like])
    assert {p["file"]: p for p in rep2["comparison"]["nearest_profile"]}["tun.json"]["looks_like"] == "attack"
    assert rep2["comparison"]["shift"]["query_length"]["psi"] > 0.25


def test_identical_groups_have_no_shift(tmp_path):
    lab = write_json(tmp_path / "l.json", [rec(f"s{i}.example{i % 7}.com", i % 2) for i in range(200)])
    unl = write_json(tmp_path / "u.json", [rec(f"s{i}.example{i % 7}.com") for i in range(200)])
    rep = eda_data.run_eda([lab], [unl])
    assert all(v["psi"] < 0.1 for v in rep["comparison"]["shift"].values())


# ── outputs ─────────────────────────────────────────────────

def test_reports_written_with_all_sections(labeled_json, flood_log, tmp_path):
    out = tmp_path / "out" / "eda_data_report.json"
    rep = eda_data.run_eda([labeled_json], [flood_log], output=str(out))
    assert json.loads(out.read_text(encoding="utf-8"))["totals"] == rep["totals"]
    page = (tmp_path / "out" / "eda_data_report.html").read_text(encoding="utf-8")
    for section in ("A · Labeled data", "B · Unlabeled data", "C · Labeled vs unlabeled", "D · What this means"):
        assert section in page
    assert page.count("<svg") >= 5
    assert rep["implications"]


def test_status_cli(labeled_json, flood_log):
    res = subprocess.run([sys.executable, "-m", "dns_detect.features.eda_data", "--status", labeled_json, flood_log],
                         capture_output=True, text=True, env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")})
    assert res.returncode == 0, res.stderr
    lines = [ln.split("\t") for ln in res.stdout.strip().splitlines()]
    assert [ln[0] for ln in lines] == ["labeled", "unlabeled"]
    # no empty fields: bash `read` with IFS=tab merges consecutive tabs
    assert all(len(ln) == 3 and all(ln) for ln in lines)


def test_pcap_with_and_without_label(tmp_path):
    scapy = pytest.importorskip("scapy.all")
    pkts = [scapy.IP(src="10.0.0.9", dst="8.8.8.8") / scapy.UDP(sport=1234, dport=53)
            / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=f"q{i}.example.com", qtype="TXT")) for i in range(5)]
    pkts.append(scapy.IP(src="8.8.8.8", dst="10.0.0.9") / scapy.UDP(sport=53, dport=1234)
                / scapy.DNS(qr=1, rcode=3, qd=scapy.DNSQR(qname="q0.example.com")))
    path = str(tmp_path / "cap.pcap")
    scapy.wrpcap(path, pkts)

    rep_unl = eda_data.run_eda([], [path])
    f = rep_unl["unlabeled"]["per_file"][0]
    assert f["queries"] == 5 and f["responses"] == 1

    rep_lab = eda_data.run_eda([path], [], pcap_label="1")
    assert rep_lab["labeled"]["class_balance"]["attack"] == 5


# ── make_labeled_features.py --unlabeled ────────────────────

def test_make_labeled_features_unlabeled(tmp_path, flood_log):
    out = tmp_path / "feat.json"
    res = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "make_labeled_features.py"),
                          "--unlabeled", "--input", flood_log, "--output", str(out)],
                         capture_output=True, text=True, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    assert res.returncode == 0, res.stderr
    recs = json.loads(out.read_text(encoding="utf-8"))
    assert len(recs) == 120
    assert all("label" not in r and r["label_source"] == "none" for r in recs)
