#!/usr/bin/env python3
"""
make_labeled_features.py — Turn a capture into labeled feature records (provenance labels).

Use this when you know what a WHOLE capture is: a tunneling-tool pcap is all attack
traffic, and a quiet benign-only capture is all benign. That is ground truth by
provenance — the same way benchmark datasets (CIC-*) label separately captured benign and
attack traffic — and it is independent of the extractor's heuristics (no circular labels).

Inputs:  .pcap / .pcapng (DNS queries via scapy) or a Technitium .log
Output:  JSON records with the SAME feature fields as features/extractor.py, plus
         label (0/1), attack_family, label_source, source_file.

Feature consistency notes (avoid measurement artifacts the model could cheat on):
  - pcap records are built with the extractor's own feature + heuristic functions.
  - Only DNS *queries* are used (qr=0); answer_size is 0 for pcap queries, which matches
    what the Technitium-log parser produces in practice.

Examples:
  # attack captures (family taken from the filename prefix, e.g. dns2tcp / dnsexfiltrator)
  python3 scripts/make_labeled_features.py --label 1 \
      --input ~/Downloads/dns2tcp_*.pcapng ~/Downloads/dnsexfiltrator_txt_up.pcap \
      --output data/processed/labeled_tunnels.json

  # benign-only Technitium log captured with NO attacks running
  python3 scripts/make_labeled_features.py --label 0 --family benign \
      --input data/raw/benign_2026-10-25.log --output data/processed/labeled_benign.json
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from dns_detect.features.extractor import DNSFeatureExtractor  # noqa: E402


def _family_from_name(path: str) -> str:
    """dns2tcp_txt_up.pcapng -> 'dns2tcp'; dnsexfiltrator_txt_up.pcap -> 'dnsexfiltrator'."""
    return Path(path).stem.split("_")[0].lower() or "attack"


def _heuristic_flags(ex: DNSFeatureExtractor, feat: dict, domain: str, qtype: str) -> None:
    """Fill the extractor's heuristic fields for a pcap query (kept for the detection
    engine / EDA; they are NOT used as labels). NXDOMAIN and cache-poisoning need
    response/history context a single query lacks, so they stay False."""
    feat["is_nxdomain_flood"] = False
    is_rand, rand_count = ex.detect_random_subdomains(domain)
    feat["is_random_subdomain"] = is_rand
    feat["random_subdomain_count"] = rand_count
    feat["is_amplification"] = ex.detect_amplification_attack(qtype, len(domain))
    feat["is_cache_poisoning"] = False
    feat.update(ex.detect_encoding_patterns(domain))
    feat["is_high_entropy"] = ex.detect_high_entropy_domains(domain, feat["entropy"])
    sig = []
    if feat["is_random_subdomain"]:
        sig.append("RANDOM_SUBDOMAIN")
    if feat["is_amplification"]:
        sig.append("AMPLIFICATION")
    if feat["is_high_entropy"]:
        sig.append("HIGH_ENTROPY")
    if feat.get("is_base32") or feat.get("is_base64"):
        sig.append("ENCODING")
    feat["attack_signature"] = ",".join(sig) if sig else "NORMAL"
    feat["attack_count"] = len(sig)


def records_from_pcap(path: str, ex: DNSFeatureExtractor, domain_filter: str = None):
    try:
        from scapy.utils import PcapReader
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        try:
            from scapy.layers.dns import dnsqtypes
        except ImportError:
            dnsqtypes = {}
    except ImportError:
        sys.exit("[error] scapy is required for pcap input:  pip install scapy")

    out, skipped = [], 0
    with PcapReader(path) as reader:          # streams; handles pcap and pcapng
        for pkt in reader:
            if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
                continue
            if int(pkt[DNS].qr) != 0:         # queries only
                continue
            qname = pkt[DNSQR].qname
            domain = (qname.decode(errors="ignore") if isinstance(qname, bytes)
                      else str(qname)).rstrip(".").lower()
            if not domain:
                continue
            if domain_filter and not (domain == domain_filter or domain.endswith("." + domain_filter)):
                skipped += 1
                continue

            ts = datetime.fromtimestamp(float(pkt.time))
            if pkt.haslayer(IP):
                src = pkt[IP].src
            elif pkt.haslayer(IPv6):
                src = pkt[IPv6].src
            else:
                src = "unknown"
            qtype_num = int(pkt[DNSQR].qtype)
            qtype = dnsqtypes.get(qtype_num, str(qtype_num))
            sport = int(getattr(pkt, "sport", 0) or 0)

            feat = ex.extract_single_domain_features(domain)
            feat.update({
                "timestamp":     ts.isoformat(),
                "client_ip":     src,
                "client_port":   sport,
                "protocol":      "TCP" if pkt.haslayer(TCP) else "UDP",
                "query_type":    qtype,
                "response_code": "unknown",
                "answer_size":   0,
                "hour_of_day":   ts.hour,
                "day_of_week":   ts.weekday(),
            })
            _heuristic_flags(ex, feat, domain, qtype)
            out.append(feat)
    if skipped:
        print(f"    (skipped {skipped} queries outside --domain {domain_filter})")
    return out


def records_from_log(path: str, ex: DNSFeatureExtractor):
    return ex.extract_features_from_technitium_log(path)


def main():
    ap = argparse.ArgumentParser(
        description="Convert pcap/pcapng/Technitium-log captures into labeled feature records."
    )
    ap.add_argument("--input", nargs="+", required=True, help="one or more .pcap/.pcapng/.log files")
    ap.add_argument("--label", type=int, choices=[0, 1], required=True,
                    help="ground-truth label for EVERY query in these files (1=attack, 0=benign)")
    ap.add_argument("--family", default=None,
                    help="attack family (default: filename prefix for attacks, 'benign' for label 0)")
    ap.add_argument("--domain", default=None,
                    help="keep only queries under this base domain (e.g. the tunnel's domain)")
    ap.add_argument("--output", required=True, help="output JSON path")
    args = ap.parse_args()

    ex = DNSFeatureExtractor()
    all_recs = []
    print("=" * 70)
    print(f"PROVENANCE LABELING — every query labelled {'ATTACK' if args.label else 'BENIGN'}")
    print("=" * 70)
    for path in args.input:
        if not os.path.isfile(path):
            print(f"  [warn] not found, skipping: {path}")
            continue
        ext = Path(path).suffix.lower()
        if ext in (".pcap", ".pcapng", ".cap"):
            recs = records_from_pcap(path, ex, args.domain)
        elif ext == ".log":
            recs = records_from_log(path, ex)
        else:
            print(f"  [warn] unsupported type {ext}, skipping: {path}")
            continue

        family = args.family or ("benign" if args.label == 0 else _family_from_name(path))
        for r in recs:
            r["label"] = args.label
            r["attack_family"] = family
            r["label_source"] = "provenance"
            r["source_file"] = os.path.basename(path)
        clients = len({r.get("client_ip") for r in recs})
        print(f"  {os.path.basename(path):<34} {len(recs):>7} queries  "
              f"family={family}  clients={clients}")
        all_recs.extend(recs)

    if not all_recs:
        sys.exit("[error] no DNS queries extracted — check the files (and --domain if used)")

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(all_recs, f, indent=2, default=str)
    print(f"\n✅ {len(all_recs)} labeled records → {args.output}")


if __name__ == "__main__":
    main()
