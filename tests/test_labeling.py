"""Tests for Step 8 labeling (ingest/labeling.py): precedence, manifest, labeling functions, abstain."""
import json
import os
import random
import string
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

from dns_detect.ingest.labeling import (  # noqa: E402
    DEFAULTS, label_records, load_manifest, parent_domain, validate,
)

RNG = random.Random(7)


def q(domain, ip="10.0.0.1", ts="2026-03-18T13:45:00", qtype="A", rcode="NoError", **extra):
    r = {"domain": domain, "client_ip": ip, "timestamp": ts, "query_type": qtype, "response_code": rcode}
    r.update(extra)
    return r


def b32(n):
    return "".join(RNG.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(n))


def tunnel_rows(parent="evil-tunnel.com", n=80, qtype="TXT"):
    return [q(f"{b32(60)}.{b32(30)}.{parent}", qtype=qtype) for _ in range(n)]


def ordinary_rows(n=20):
    return [q(d) for d in ["www.example.com", "mail.example.com", "example.com", "news.example.org"] * (n // 4)]


def run(records, manifest=None, allowlist=None):
    return label_records(records, manifest, allowlist or set(), dict(DEFAULTS))


def test_parent_domain():
    assert parent_domain("a.b.example.co.uk") == "example.co.uk"
    assert parent_domain("x.y.dns2tcp-key.com") == "dns2tcp-key.com"
    assert parent_domain("gov.in") == "gov.in"
    assert parent_domain("www.mha.gov.in") == "mha.gov.in"


def test_file_label_never_overwritten():
    rows = tunnel_rows(n=60)
    rows[0]["label"] = 0
    rows[0]["label_source"] = "provenance"
    labeled, _, rep = run(rows)
    first = next(r for r in labeled if r["label_source"] == "provenance")
    assert first["label"] == 0
    assert rep["by_label_source"]["provenance"] == 1


def test_tunnel_needs_two_agreeing_signals_and_ordinary_is_benign():
    labeled, abstained, rep = run(tunnel_rows() + ordinary_rows())
    tun = [r for r in labeled if r["parent_domain"] == "evil-tunnel.com"]
    assert len(tun) == 80 and all(r["label"] == 1 and r["attack_family"] == "tunnel" for r in tun)
    assert {"many_unique_subdomains", "high_information", "tunnel_record_types"} <= set(tun[0]["lf_votes"])
    ben = [r for r in labeled if r["parent_domain"] in ("example.com", "example.org")]
    assert ben and all(r["label"] == 0 and r["label_source"] == "weak_behavioral" for r in ben)
    assert not abstained


def test_single_signal_abstains():
    # 25 long encoded names under one parent: long_encoded_labels fires, but < 50 unique subdomains
    # and < 4096 chars of information → only one attack vote → abstain, not attack.
    rows = [q(f"{b32(55)}.cdn-thing.net") for _ in range(25)]
    labeled, abstained, rep = run(rows)
    assert not labeled and len(abstained) == 25
    assert abstained[0]["lf_votes"] == ["long_encoded_labels"]
    assert any("left out of training" in w for w in rep["warnings"])


def test_allowlist_vetoes_attack():
    labeled, _, _ = run(tunnel_rows(parent="sophosxl.net"), allowlist={"sophosxl.net"})
    assert all(r["label"] == 0 and "allowlisted" in r["lf_votes"] for r in labeled)


def test_nxdomain_enumeration():
    words = ["".join(RNG.choice(string.ascii_lowercase) for _ in range(6)) for _ in range(120)]
    rows = [q(f"{w}.lab.local", ip="192.168.1.5", rcode="NxDomain") for w in words]
    labeled, _, rep = run(rows)
    assert all(r["label"] == 1 and r["attack_family"] == "nxdomain_enum" for r in labeled)
    assert rep["nxdomain_enumeration"] == [{"client": "192.168.1.5", "parent": "lab.local"}]


def _manifest(tmp_path, rows):
    p = tmp_path / "manifest.csv"
    p.write_text("campaign_id,family,source_ip,start,end,target_domain\n" + "\n".join(rows) + "\n", encoding="utf-8")
    return str(p)


def test_manifest_target_domain_and_background(tmp_path):
    m = _manifest(tmp_path, ["C-1,dns_tunneling,10.0.0.9,2026-03-18T13:40:00,2026-03-18T13:50:00,t.example.net"])
    rows = [q("abc.t.example.net", ip="10.0.0.9"),          # attack
            q("www.google.com", ip="10.0.0.9"),             # attacker host background → abstain
            q("abc.t.example.net", ip="10.0.0.1")]          # other client → not the manifest's
    labeled, abstained, rep = run(rows, manifest=m)
    man = [r for r in labeled if r["label_source"] == "manifest"]
    assert len(man) == 1 and man[0]["campaign_id"] == "C-1" and man[0]["attack_family"] == "dns_tunneling"
    assert any(r["domain"] == "www.google.com" and "outside target_domain" in r["abstain_reason"] for r in abstained)
    assert rep["manifest_windows"][0]["matched"] == 1 and rep["manifest_windows"][0]["background"] == 1


def test_manifest_skew_and_zero_match_warning(tmp_path):
    m = _manifest(tmp_path, ["C-1,flood,,2026-03-18T13:45:01,2026-03-18T13:46:00,",
                             "C-2,ghost,,2020-01-01T00:00:00,2020-01-01T00:01:00,"])
    labeled, _, rep = run([q("x.lab.local", ts="2026-03-18T13:45:00")], manifest=m)   # 1 s before C-1
    assert labeled[0]["label_source"] == "manifest"
    assert any("C-2" in w and "matched no rows" in w for w in rep["warnings"])
    assert len(load_manifest(m)) == 2


def test_validate_reports_against_existing_labels():
    rows = [dict(r, label=1, attack_family="tunnel", attack_count=1) for r in tunnel_rows()] + \
           [dict(r, label=0, attack_family="benign", attack_count=0) for r in ordinary_rows()]
    res = validate(rows, set(), dict(DEFAULTS))
    assert res["wrong_labels"] == 0 and res["precision"] == 1.0
    assert res["per_family"]["tunnel"]["labeled_attack"] == 80
    assert "old_attack_count_rule" in res


def test_cli_writes_labeled_abstained_and_report(tmp_path):
    inp = tmp_path / "merged.json"
    rows = tunnel_rows() + ordinary_rows() + [q(f"{b32(55)}.odd.net") for _ in range(5)]
    inp.write_text(json.dumps(rows), encoding="utf-8")
    out, ab, rep = tmp_path / "labeled.json", tmp_path / "abstained.json", tmp_path / "report.json"
    res = subprocess.run([sys.executable, "-m", "dns_detect.ingest.labeling", "--input", str(inp), "--output", str(out),
                          "--abstained", str(ab), "--report", str(rep)],
                         capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src"), "PYTHONIOENCODING": "utf-8"})
    assert res.returncode == 0, res.stderr
    labeled = json.loads(out.read_text(encoding="utf-8"))
    abstained = json.loads(ab.read_text(encoding="utf-8"))
    assert all(r["label"] in (0, 1) for r in labeled)
    assert len(abstained) == 5 and all("label" not in r for r in abstained)
    assert json.loads(rep.read_text(encoding="utf-8"))["by_label_source"]["abstain"] == 5
