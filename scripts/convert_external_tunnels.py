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

Speed (same output as the original, which is kept as --legacy):
  - each capture is read ONCE: the truncation count and the queries come from the same pass
    (the original parsed every file twice), and the captured length is taken from the packet's
    original bytes instead of re-encoding the packet;
  - features are computed only for the rows that survive the domain filter and the cap
    (the original computed them for every query, then threw most away). The extractor's
    features depend on the query alone, so the values are the same;
  - capture files are scanned in parallel on --jobs CPU cores (default: all but one).

Usage:
  git clone --depth 1 https://github.com/Utah1A/DNS-tunnelling-detection-by-fusing-encoding-feature-and-behavioral-feature \
      data/external/tu2023/repo
  python3 scripts/convert_external_tunnels.py --root data/external/tu2023/repo/datasets/base_malicious_dataset \
      --out-dir data/external/tu2023
  python3 scripts/convert_external_tunnels.py ... --jobs 3          # use 3 cores
  python3 scripts/convert_external_tunnels.py ... --legacy          # original single-core code path
"""

import argparse
import json
import os
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from dns_detect.features.extractor import DNSFeatureExtractor  # noqa: E402
from dns_detect.ingest.labeling import parent_domain, under  # noqa: E402
from dns_detect.utils.sampling import sample_contiguous_blocks  # noqa: E402
from make_labeled_features import _heuristic_flags, records_from_pcap, truncation_report  # noqa: E402

PCAP_EXT = (".pcap", ".pcapng", ".cap")


def family_pcaps(fam_dir: Path) -> list:
    return sorted(p for p in fam_dir.rglob("*") if p.suffix.lower() in PCAP_EXT)


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


def convert_family_legacy(fam_dir: Path, ex, forced_domain: str, max_truncated: float) -> tuple:
    """Original code path (--legacy): two full passes per file, features for every query."""
    recs = []
    for pcap in family_pcaps(fam_dir):
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


# ─────────────────────────────────────────────
# Fast path
# ─────────────────────────────────────────────

def scan_pcap(path: str) -> tuple:
    """
    One pass over a capture → (truncation report, light query rows).

    Truncation uses the rule of make_labeled_features.truncation_report (packets to port 53;
    cut when the on-wire length exceeds the captured length). Queries use the rule of
    make_labeled_features.records_from_pcap (DNS question present, qr == 0, non-empty name).
    A row is (domain, epoch time, client ip, client port, protocol, query type): no features yet.
    """
    from scapy.utils import PcapReader
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    try:
        from scapy.layers.dns import dnsqtypes
    except ImportError:
        dnsqtypes = {}

    rows, n, cut = [], 0, 0
    with PcapReader(path) as reader:
        for pkt in reader:
            l4 = UDP if pkt.haslayer(UDP) else TCP if pkt.haslayer(TCP) else None
            if l4 is not None and int(pkt[l4].dport) == 53:
                n += 1
                wire = getattr(pkt, "wirelen", None)
                if wire is not None:
                    raw = getattr(pkt, "original", None)
                    if wire > (len(raw) if raw else len(bytes(pkt))):
                        cut += 1
            if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
                continue
            if int(pkt[DNS].qr) != 0:
                continue
            qname = pkt[DNSQR].qname
            domain = (qname.decode(errors="ignore") if isinstance(qname, bytes)
                      else str(qname)).rstrip(".").lower()
            if not domain:
                continue
            if pkt.haslayer(IP):
                src = pkt[IP].src
            elif pkt.haslayer(IPv6):
                src = pkt[IPv6].src
            else:
                src = "unknown"
            qtype_num = int(pkt[DNSQR].qtype)
            rows.append((domain, float(pkt.time), src, int(getattr(pkt, "sport", 0) or 0),
                         "TCP" if pkt.haslayer(TCP) else "UDP", dnsqtypes.get(qtype_num, str(qtype_num))))
    rep = {"dns_packets": n, "truncated": cut, "truncated_share": round(cut / n, 4) if n else 0.0}
    return rep, rows


def _light(row: tuple, source_file: str) -> dict:
    domain, t, src, sport, proto, qtype = row
    ts = datetime.fromtimestamp(t)
    return {"domain": domain, "timestamp": ts.isoformat(), "_ts": ts, "client_ip": src,
            "client_port": sport, "protocol": proto, "query_type": qtype, "source_file": source_file}


def full_record(light: dict, ex) -> dict:
    """The record records_from_pcap would have built for this query (same keys, same order)."""
    domain, ts = light["domain"], light["_ts"]
    feat = ex.extract_single_domain_features(domain)
    feat.update({
        "timestamp":     light["timestamp"],
        "client_ip":     light["client_ip"],
        "client_port":   light["client_port"],
        "protocol":      light["protocol"],
        "query_type":    light["query_type"],
        "response_code": "unknown",
        "answer_size":   0,
        "hour_of_day":   ts.hour,
        "day_of_week":   ts.weekday(),
    })
    _heuristic_flags(ex, feat, domain, light["query_type"])
    feat["source_file"] = light["source_file"]
    return feat


def scan_all(jobs_list: list, jobs: int) -> dict:
    """Scan every (family, pcap) once, in parallel when jobs > 1. Returns {pcap path: (rep, rows)}."""
    out, total, t0 = {}, len(jobs_list), time.time()

    def done(path, res, k):
        out[path] = res
        fam = Path(path).parent.name
        print(f"  [{k:>3}/{total}] {fam}/{Path(path).name}: {len(res[1])} queries "
              f"({time.time() - t0:.0f}s)", flush=True)

    paths = [str(p) for _, p in jobs_list]
    if jobs <= 1:
        for k, p in enumerate(paths, 1):
            done(p, scan_pcap(p), k)
        return out
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        futs = {pool.submit(scan_pcap, p): p for p in paths}
        for k, fut in enumerate(as_completed(futs), 1):
            done(futs[fut], fut.result(), k)
    return out


def convert_family(fam_dir: Path, ex, forced_domain: str, max_truncated: float, scanned: dict,
                   max_rows: int, block: int, seed: int) -> tuple:
    """Fast path. Returns (capped full records, domain, dropped, kept-before-cap count)."""
    lights = []
    for pcap in family_pcaps(fam_dir):
        rep, rows = scanned[str(pcap)]
        if rep["truncated_share"] > max_truncated:
            print(f"    [skip] {pcap.name}: {rep['truncated_share']:.1%} of queries truncated")
            continue
        src = f"{fam_dir.name}/{pcap.name}"
        lights.extend(_light(r, src) for r in rows)
    domain = forced_domain or tunnel_domain(lights)
    kept = [r for r in lights if under(r["domain"], domain)]
    capped = cap_family(kept, max_rows, block, seed)        # uses only "timestamp": same rows
    return [full_record(r, ex) for r in capped], domain, len(lights) - len(kept), len(kept)


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
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1),
                    help="capture files scanned in parallel (default: CPU cores - 1)")
    ap.add_argument("--legacy", action="store_true", help="original single-core code path (for comparison)")
    args = ap.parse_args()
    t_start = time.time()

    forced = dict(s.split("=", 1) for s in args.domain)
    ex = DNSFeatureExtractor()
    os.makedirs(args.out_dir, exist_ok=True)
    summary = {}
    fam_dirs = [p for p in sorted(p for p in Path(args.root).iterdir() if p.is_dir())
                if not args.families or p.name.lower() in args.families]

    scanned = {}
    if not args.legacy:
        jobs_list = [(d, p) for d in fam_dirs for p in family_pcaps(d)]
        # Largest files first, so the big ones don't start last and hold up the end.
        jobs_list.sort(key=lambda dp: dp[1].stat().st_size, reverse=True)
        print(f"[*] scanning {len(jobs_list)} capture(s) from {len(fam_dirs)} tool(s) on "
              f"{min(args.jobs, max(1, len(jobs_list)))} core(s)", flush=True)
        scanned = scan_all(jobs_list, args.jobs)
        print()

    for fam_dir in fam_dirs:
        fam = fam_dir.name.lower()
        if args.legacy:
            recs, domain, dropped = convert_family_legacy(fam_dir, ex, forced.get(fam), args.max_truncated)
            n_all = len(recs)
            if recs:
                recs = cap_family(recs, args.max_per_family, args.block, args.seed)
        else:
            recs, domain, dropped, n_all = convert_family(
                fam_dir, ex, forced.get(fam), args.max_truncated, scanned,
                args.max_per_family, args.block, args.seed)
        if not recs:
            print(f"  {fam:<16} no tunnel queries — skipped")
            continue
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
    print(f"[*] done in {time.time() - t_start:.0f}s ({'legacy' if args.legacy else f'fast, {args.jobs} job(s)'})")


if __name__ == "__main__":
    main()
