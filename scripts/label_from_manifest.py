#!/usr/bin/env python3
"""
label_from_manifest.py — Ground-truth labels from an attack manifest (Tier 1).

Replaces the circular "label = f(attack_count)" labeling with INDEPENDENT ground
truth: you record each attack run in a manifest, and every DNS query whose
timestamp falls inside an attack window (and matches the attacker source, if given)
is labelled attack; everything else is benign.

This is the CICIDS2017 / HERA labeling methodology — label by time-window +
source, and treat anything unmatched as benign. It breaks the circularity that
caps the ML (see docs/ML_IMPROVEMENTS.md, AUDIT_REPORT.md).

Manifest (CSV, header row required). Minimum columns: family, start, end.
Optional: campaign_id, source_ip, target_domain.

    campaign_id,family,source_ip,start,end
    C-001,nxdomain_flood,192.168.18.52,2026-03-18T13:40:00,2026-03-18T13:55:00
    C-002,dns_tunneling,192.168.18.52,2026-03-18T14:10:00,2026-03-18T14:40:00

Timestamps are ISO-8601 (e.g. 2026-03-18T13:40:00). Keep all hosts on NTP so these
windows line up with the DNS log timestamps — clock drift silently mislabels.

Usage:
    python scripts/label_from_manifest.py \
        --features data/processed/week3_features_all.json \
        --manifest data/attack_manifest.csv \
        --output   data/processed/merged_features_labeled.json
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime

# Keep the nice unicode output working on consoles that default to a legacy
# codepage (e.g. Windows cp1252); no-op where already UTF-8 (Kali).
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Reuse the project's date parser if available (python-dateutil is a dependency);
# fall back to datetime.fromisoformat otherwise.
try:
    from dateutil.parser import parse as _parse_dt  # type: ignore

    def parse_ts(value):
        if value is None or value == "":
            return None
        try:
            return _parse_dt(str(value))
        except (ValueError, OverflowError):
            return None
except ImportError:  # pragma: no cover - dateutil is in requirements.txt
    def parse_ts(value):
        if value is None or value == "":
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None


def _naive(dt):
    """Drop tzinfo so naive log timestamps and manifest windows compare cleanly."""
    if dt is not None and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


def load_manifest(path):
    """Read the attack manifest CSV → list of normalized window dicts."""
    windows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=2):  # row 1 is the header
            row = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
            start = _naive(parse_ts(row.get("start")))
            end = _naive(parse_ts(row.get("end")))
            family = row.get("family") or "attack"
            if start is None or end is None:
                print(f"  [warn] manifest line {i}: bad/missing start/end — skipped")
                continue
            if end < start:
                start, end = end, start
            windows.append({
                "campaign_id": row.get("campaign_id") or f"C-{i}",
                "family": family,
                "source_ip": row.get("source_ip") or "",
                "start": start,
                "end": end,
            })
    return windows


def load_records(path):
    """Load the week3 features JSON (list of per-query records)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get("records", data.get("data", [data]))
    return data if isinstance(data, list) else [data]


def match_window(ts, client_ip, windows):
    """Return the first manifest window this record falls in, else None."""
    if ts is None:
        return None
    for w in windows:
        if w["start"] <= ts <= w["end"]:
            if not w["source_ip"] or str(client_ip) == w["source_ip"]:
                return w
    return None


def label_records(records, windows):
    labeled = []
    counts = {"attack": 0, "benign": 0}
    family_counts = {}
    missing_ts = 0

    for rec in records:
        r = dict(rec)
        # Records that already carry a ground-truth label (e.g. provenance labels from
        # scripts/make_labeled_features.py) are kept as-is — never overwritten.
        if r.get("label") in (0, 1, "0", "1"):
            r["label"] = int(r["label"])
            r.setdefault("attack_family", "benign" if r["label"] == 0 else "attack")
            key = "attack" if r["label"] == 1 else "benign"
            counts[key] += 1
            if r["label"] == 1:
                family_counts[r["attack_family"]] = family_counts.get(r["attack_family"], 0) + 1
            labeled.append(r)
            continue
        ts = _naive(parse_ts(r.get("timestamp")))
        if ts is None:
            missing_ts += 1
        client_ip = r.get("client_ip", r.get("source_ip", ""))

        w = match_window(ts, client_ip, windows)
        if w is not None:
            r["label"] = 1
            r["attack_family"] = w["family"]
            r["campaign_id"] = w["campaign_id"]
            counts["attack"] += 1
            family_counts[w["family"]] = family_counts.get(w["family"], 0) + 1
        else:
            r["label"] = 0
            r["attack_family"] = "benign"
            counts["benign"] += 1
        labeled.append(r)

    return labeled, counts, family_counts, missing_ts


def main():
    ap = argparse.ArgumentParser(
        description="Ground-truth DNS labels from an attack manifest (time-window + source)."
    )
    ap.add_argument("--features", required=True,
                    help="week3 features JSON (per-query records with timestamp + client_ip)")
    ap.add_argument("--manifest", required=True,
                    help="attack manifest CSV (family,start,end[,source_ip,campaign_id])")
    ap.add_argument("--output", required=True, help="labeled JSON output path")
    args = ap.parse_args()

    if not os.path.isfile(args.manifest):
        sys.exit(f"[error] manifest not found: {args.manifest}")
    if not os.path.isfile(args.features):
        sys.exit(f"[error] features not found: {args.features}")

    print("=" * 70)
    print("GROUND-TRUTH LABELING FROM ATTACK MANIFEST (time-window + source)")
    print("=" * 70)

    windows = load_manifest(args.manifest)
    if not windows:
        sys.exit("[error] no valid attack windows in manifest — nothing to label against")
    print(f"[*] Manifest windows: {len(windows)}")
    for w in windows:
        src = w["source_ip"] or "any-source"
        print(f"    - {w['campaign_id']:<10} {w['family']:<16} {src:<15} "
              f"{w['start']} → {w['end']}")

    records = load_records(args.features)
    print(f"[*] Loaded {len(records)} feature records from {args.features}")

    labeled, counts, family_counts, missing_ts = label_records(records, windows)

    if missing_ts:
        print(f"  [warn] {missing_ts} record(s) had no parseable timestamp → "
              f"labelled benign (verify your extractor output)")

    total = len(labeled)
    rate = counts["attack"] / max(total, 1) * 100
    print(f"\n[*] Ground-truth labels: {counts['benign']} benign  |  "
          f"{counts['attack']} attack  ({rate:.1f}% attack)")
    print("    Per-family attack counts:")
    for fam, n in sorted(family_counts.items(), key=lambda x: -x[1]):
        print(f"      - {fam}: {n}")

    if counts["attack"] == 0:
        print("\n  [warn] ZERO attack rows matched. Check that manifest windows/timezone "
              "line up with log timestamps (NTP!), and that source_ip matches client_ip.")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(labeled, f, indent=2, default=str)

    print(f"\n✅ Ground-truth labeled data saved → {args.output}")
    print("   These labels are INDEPENDENT of attack_count (breaks circular labeling).")


if __name__ == "__main__":
    main()
