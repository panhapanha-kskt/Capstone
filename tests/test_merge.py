"""Tests for ingest/merge.py (provenance, duplicates, label/schema checks) and models/splits.py."""
import json
import os
import sys

import numpy as np

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))

from dns_detect.features.extractor import DNSFeatureExtractor  # noqa: E402
from dns_detect.ingest.merge import merge  # noqa: E402
from dns_detect.models.splits import drop_conflicting_groups, grouped_split, overlap_share  # noqa: E402
from dns_detect.parsing.dns_parser import FEATURES_8, feature_vector_key, load_as_dataframe  # noqa: E402

EX = DNSFeatureExtractor()


def rec(domain, label=None, source_file=None, answer_size=0):
    """A record in the extractor / make_labeled_features format."""
    r = EX.extract_single_domain_features(domain)
    r.update({"timestamp": "2026-01-01T10:00:00", "client_ip": "10.0.0.1", "query_type": "A",
              "response_code": "unknown", "answer_size": answer_size})
    if label is not None:
        r["label"] = label
    if source_file:
        r["source_file"] = source_file
    return r


def write(path, records):
    path.write_text(json.dumps(records), encoding="utf-8")
    return str(path)


def test_provenance_fields(tmp_path):
    labeled = write(tmp_path / "labeled.json", [rec("a.com", 0, "benign_dns.pcap"), rec("x1y2.tun.net", 1, "dns2tcp_up.pcapng")])
    extracted = write(tmp_path / "extracted_day_123.json", [rec("b.com")])
    out = tmp_path / "merged.json"
    merge([labeled, f"{extracted}=data/raw/day.log"], str(out))
    rows = json.loads(out.read_text(encoding="utf-8"))
    by_src = {r["source_file"]: r for r in rows}
    assert by_src["benign_dns.pcap"]["source_type"] == "pcap"          # kept from the record
    assert by_src["benign_dns.pcap"]["label_source"] == "file"
    assert by_src["day.log"]["source_type"] == "log"                    # original, not the extracted JSON
    assert by_src["day.log"]["input_file"] == "extracted_day_123.json"
    assert by_src["day.log"]["label_source"] == "none" and "label" not in by_src["day.log"]
    assert all(len(r["dup_key"]) == 16 for r in rows)


def test_duplicates_and_conflicts(tmp_path):
    a = write(tmp_path / "a.json", [rec("same.com", 0, "a.pcap")] * 4 + [rec("conflict.org", 0, "a.pcap")])
    b = write(tmp_path / "b.json", [rec("other.net", 1, "b.pcap"), rec("conflict.org", 1, "b.pcap")])
    rep = merge([a, b], str(tmp_path / "m.json"), report_path=str(tmp_path / "r.json"))
    d, lab = rep["duplicates"], rep["labels"]
    assert d["distinct_feature_vectors"] == 3
    assert d["rows_in_duplicated_vectors"] == 6          # 4× same.com + 2× conflict.org
    assert d["vectors_shared_across_sources"] == 1        # conflict.org in a and b
    assert lab["conflicting_vectors"] == 1 and lab["rows_in_conflicting_vectors"] == 2
    assert any("both labels" in w for w in rep["warnings"])
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["rows"] == 7


def test_single_label_sources_and_constant_feature(tmp_path):
    a = write(tmp_path / "a.json", [rec(f"s{i}.com", 0, "benign.pcap") for i in range(5)])
    b = write(tmp_path / "b.json", [rec(f"t{i}x9.tun.net", 1, "tunnel.pcap") for i in range(5)])
    rep = merge([a, b], str(tmp_path / "m.json"))
    w = " ".join(rep["warnings"])
    assert "only one class" in w
    assert "'answer_count' is 0 in every row" in w


def test_feature_constant_in_one_source_type_only(tmp_path):
    pcap = write(tmp_path / "p.json", [rec(f"s{i}.com", 0, "cap.pcap") for i in range(5)])
    log = write(tmp_path / "e.json", [rec(f"q{i}.com", answer_size=i) for i in range(5)])
    rep = merge([pcap, f"{log}=day.log"], str(tmp_path / "m.json"))
    assert rep["schema"]["pcap"]["constant_features"]["answer_count"] == 0.0
    assert "answer_count" not in rep["schema"]["log"]["constant_features"]
    assert any("'answer_count' is constant in pcap rows but varies in log" in x for x in rep["warnings"])


def test_registry_only_with_flag(tmp_path):
    a = write(tmp_path / "a.json", [rec("a.com", 0)])
    reg = tmp_path / "registry.json"
    merge([a], str(tmp_path / "m.json"))
    assert not reg.exists()
    merge([a], str(tmp_path / "m.json"), registry=str(reg))
    entries = json.loads(reg.read_text(encoding="utf-8"))["trained_files"]
    assert len(entries) == 1 and len(entries[0]["checksum"]) == 64   # full sha256, as --retrain expects


def test_stored_key_matches_path_a_features(tmp_path):
    a = write(tmp_path / "a.json", [rec(f"n{i % 7}.example.com", i % 2) for i in range(30)])
    out = tmp_path / "m.json"
    merge([a], str(out))
    df = load_as_dataframe(str(out))
    assert (df["dup_key"].to_numpy() == feature_vector_key(df).to_numpy()).all()
    assert set(FEATURES_8) <= set(df.columns)


# ── grouped split ───────────────────────────────────────────

def _data(n_groups=300, reps=5, seed=0):
    rng = np.random.default_rng(seed)
    groups = np.repeat(np.arange(n_groups), reps).astype(str)
    y = np.repeat(rng.integers(0, 2, n_groups), reps)
    return y, groups


def test_grouped_split_has_no_leak_and_both_classes():
    y, groups = _data()
    tr, va, te, method = grouped_split(y, groups)
    assert method == "grouped_by_feature_vector"
    assert overlap_share(groups, tr, te) == 0.0 and overlap_share(groups, tr, va) == 0.0
    assert not set(groups[va]) & set(groups[te])
    assert all(len(np.unique(y[s])) == 2 for s in (tr, va, te))
    assert len(tr) + len(va) + len(te) == len(y)
    assert 0.10 < len(te) / len(y) < 0.20


def test_grouped_split_falls_back_when_too_few_groups():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1] * 5)
    groups = np.array(["a", "a", "a", "a", "b", "b", "b", "b"] * 5)
    *_, method = grouped_split(y, groups)
    assert method == "random_rows_fallback"


def test_drop_conflicting_groups():
    y = np.array([0, 1, 0, 0])
    groups = np.array(["g1", "g1", "g2", "g3"])
    keep, n = drop_conflicting_groups(y, groups)
    assert n == 1 and keep.tolist() == [False, False, True, True]
