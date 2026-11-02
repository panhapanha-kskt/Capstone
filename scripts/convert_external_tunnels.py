#!/usr/bin/env python3
"""
convert_external_tunnels.py — Turn public tunnel-tool pcaps into labeled records (TEST_REPORT §5, 1–2).

Built for Tu, Liu & Sun, "DNS tunnelling detection by fusing encoding feature and behavioral
feature", Computers & Security 132 (2023), doi:10.1016/j.cose.2023.103357. Its repository has
one folder per tool under datasets/base_malicious_dataset/: cobaltstrike, det, dns2tcp, dns_shell,
dnscat2, dnsexfiltrator, iodine, ozymandns. The repository states no license and asks users to
cite the paper; cite it in any report that uses these numbers.

Works for any folder laid out as <root>/<family>/*.pcap[ng]:
  1. Truncation check: refuse a capture whose queries are cut by the snap length (CIC lesson).
  2. Tunnel domain: the tool's queries all sit under one parent domain. The repository does not
     document it, so the parent with the most queries is used, unless --domain FAMILY=DOMAIN
     is given. Other queries (OS noise in the capture) are dropped, not labeled attack.
  3. Cap per family (--max-per-family) with contiguous time blocks
     (utils/sampling.sample_contiguous_blocks), so window features and Path B windows stay
     intact and no single tool dominates.
  4. Write <out-dir>/tunnels_<family>.json: label=1, attack_family=<family>, label_source=provenance.

Usage:
  git clone --depth 1 https://github.com/Utah1A/DNS-tunnelling-detection-by-fusing-encoding-feature-and-behavioral-feature \
      data/external/tu2023/repo
  python3 scripts/convert_external_tunnels.py --root data/external/tu2023/repo/datasets/base_malicious_dataset \
      --out-dir data/external/tu2023
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from dns_detect.features.extractor import DNSFeatureExtractor  # noqa: E402
from dns_detect.ingest.labeling import parent_domain, under  # noqa: E402
from dns_detect.utils.sampling import sample_contiguous_blocks  # noqa: E402
from make_labeled_features import records_from_pcap, truncation_report  # noqa: E402

PCAP_EXT = (".pcap", ".pcapng", ".cap")


def tunnel_domain(records: list) -> str:
    """Parent domain holding the most queries — the tunnel's domain in a single-tool capture."""
    counts = Counter(parent_domain(r["domain"]) for r in records)
    return counts.most_common(1)[0][0] if counts else ""


def cap_family(records: list, max_rows: int, block: int, seed: int) -> list:
    if not max_rows or len(records) <= max_rows:
        return records
    ts = pd.to_datetime(pd.Series([r.get("timestamp") for r in records]), errors="coerce", format="mixed")
    order = ts.astype("int64").where(ts.notna(), 0).to_numpy(dtype=float)
    keep = sample_contiguous_blocks(order, max_rows, min(block, max_rows), seed)
    return [records[i] for i in np.sort(keep)]


def convert_family(fam_dir: Path, ex, forced_domain: str, max_truncated: float) -> tuple:
    recs = []
    for pcap in sorted(p for p in fam_dir.rglob("*") if p.suffix.lower() in PCAP_EXT):
        rep = truncation_report(str(pcap))
        if rep["truncated_share"] > max_truncated:
            print(f"    [skip] {pcap.name}: {rep['truncated_share']:.1%} of queries truncated")
            continue
        for r in records_from_pcap(str(pcap), ex):
            r["source_file"] = f"{fam_dir.name}/{pcap.name}"
            recs.append(r)
    domain = forced_domain or tunnel_domain(recs)
    kept = [r for r in recs if under(r["domain"], domain)]
    return kept, domain, len(recs) - len(kept)


def main():
    ap = argparse.ArgumentParser(description="Convert per-tool tunnel pcaps to labeled records.")
    ap.add_argument("--root", required=True, help="folder with one sub-folder per tool")
    ap.add_argument("--out-dir", default="data/external/tu2023")
    ap.add_argument("--families", nargs="*", default=None, help="only these tool folders")
    ap.add_argument("--domain", nargs="*", default=[], metavar="FAMILY=DOMAIN",
                    help="tunnel domain per tool when auto-detection picks the wrong one")
    ap.add_argument("--max-per-family", type=int, default=5000)
    ap.add_argument("--block", type=int, default=500, help="contiguous block size for the cap")
    ap.add_argument("--max-truncated", type=float, default=0.01)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    forced = dict(s.split("=", 1) for s in args.domain)
    ex = DNSFeatureExtractor()
    os.makedirs(args.out_dir, exist_ok=True)
    summary = {}
    for fam_dir in sorted(p for p in Path(args.root).iterdir() if p.is_dir()):
        fam = fam_dir.name.lower()
        if args.families and fam not in args.families:
            continue
        recs, domain, dropped = convert_family(fam_dir, ex, forced.get(fam), args.max_truncated)
        if not recs:
            print(f"  {fam:<16} no tunnel queries — skipped")
            continue
        n_all = len(recs)
        recs = cap_family(recs, args.max_per_family, args.block, args.seed)
        for r in recs:
            r.update(label=1, attack_family=fam, label_source="provenance")
        out = os.path.join(args.out_dir, f"tunnels_{fam}.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(recs, f, indent=2, default=str)
        qtypes = Counter(r.get("query_type") for r in recs).most_common(3)
        summary[fam] = {"tunnel_domain": domain, "queries": n_all, "kept": len(recs),
                        "dropped_other_domains": dropped, "query_types": dict(qtypes)}
        print(f"  {fam:<16} domain={domain:<28} {n_all:>7} queries → {len(recs):>6} kept  "
              f"(dropped {dropped} other)  types={dict(qtypes)}")
    with open(os.path.join(args.out_dir, "conversion_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print("\nCheck every tunnel_domain above before training: a wrong one labels benign noise as attack.")


if __name__ == "__main__":
    main()
