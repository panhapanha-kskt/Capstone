#!/usr/bin/env python3
"""
convert_cic_dns.py — Rebuild the CIC-Bell-DNS-EXF-2021 benign files (ML_IMPROVEMENT_GUIDE Step 9).

Records how data/external/cic/cic_benign_{train,test}.json were made, so they can be rebuilt:
  captures 1+2 → cic_benign_train.json   (may be used for training)
  capture 3    → cic_benign_test.json    (outside false-alarm test only, never trained on)

Every query is labelled benign by provenance (label=0, attack_family=benign_cic), using the same
pcap reader as make_labeled_features.py. Each capture is first checked for truncated packets;
a capture above --max-truncated is refused (the CIC attack captures fail this: 96-byte snap length).

Input: the DNS-only copies (benign_heavy_N_dns.pcap). The source_file names must stay the same,
because stable row ids (models/splits.py) include them.

Usage:
  python3 scripts/convert_cic_dns.py                       # writes into data/external/cic/
  python3 scripts/convert_cic_dns.py --out-dir /tmp/cic    # rebuild elsewhere to compare
"""

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from dns_detect.features.extractor import DNSFeatureExtractor  # noqa: E402
from make_labeled_features import records_from_pcap, truncation_report  # noqa: E402

CIC_DIR = ROOT / "data" / "external" / "cic"
SPLITS = {
    "cic_benign_train.json": ["benign_heavy_1_dns.pcap", "benign_heavy_2_dns.pcap"],
    "cic_benign_test.json": ["benign_heavy_3_dns.pcap"],
}


def convert(pcaps, ex, max_truncated):
    out = []
    for name in pcaps:
        path = CIC_DIR / name
        rep = truncation_report(str(path))
        print(f"  {name:<28} {rep['dns_packets']:>7} DNS queries, "
              f"{rep['truncated_share']:.2%} truncated")
        if rep["truncated_share"] > max_truncated:
            sys.exit(f"[error] {name}: {rep['truncated_share']:.2%} of DNS queries are truncated "
                     f"(> {max_truncated:.0%}) — domains are missing, refusing to convert")
        recs = records_from_pcap(str(path), ex)
        for r in recs:
            r["label"] = 0
            r["attack_family"] = "benign_cic"
            r["label_source"] = "provenance"
            r["source_file"] = name
        out.extend(recs)
    return out


def main():
    ap = argparse.ArgumentParser(description="Rebuild the CIC benign train/test JSON files.")
    ap.add_argument("--out-dir", default=str(CIC_DIR))
    ap.add_argument("--max-truncated", type=float, default=0.01,
                    help="refuse a capture with more than this share of truncated DNS packets")
    args = ap.parse_args()

    ex = DNSFeatureExtractor()
    os.makedirs(args.out_dir, exist_ok=True)
    for out_name, pcaps in SPLITS.items():
        print(f"\n{out_name}")
        recs = convert(pcaps, ex, args.max_truncated)
        out = os.path.join(args.out_dir, out_name)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(recs, f, indent=2, default=str)
        print(f"  → {len(recs)} benign queries → {out}")


if __name__ == "__main__":
    main()
