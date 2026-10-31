#!/usr/bin/env python3
"""
label_from_manifest.py — Ground-truth labels from an attack manifest (kept for its CLI).

The logic now lives in src/dns_detect/ingest/labeling.py (Step 8 of train_models.sh):
  file label → attack manifest → behaviour rules → left out (abstain).

Manifest (CSV, header row required). Minimum columns: family, start, end.
Optional: campaign_id, source_ip, target_domain.

    campaign_id,family,source_ip,start,end,target_domain
    C-001,nxdomain_flood,192.168.18.52,2026-03-18T13:40:00,2026-03-18T13:55:00,lab.local
    C-002,dns_tunneling,192.168.18.52,2026-03-18T14:10:00,2026-03-18T14:40:00,tunnel.example.com

A query is an attack when its timestamp falls inside a window (± a small clock-skew margin),
it comes from source_ip (if given) and, when target_domain is given, it is under that domain.
Other queries from the attacker host inside the window are left out (background traffic).
Timestamps are ISO-8601. Keep all hosts on NTP so the windows line up with the DNS logs.

Usage:
    python scripts/label_from_manifest.py \
        --features data/processed/merged_features_all.json \
        --manifest data/attack_manifest.csv \
        --output   data/processed/merged_features_labeled.json
"""

import argparse
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from dns_detect.ingest.labeling import label_records, load_allowlist, load_records  # noqa: E402


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Ground-truth DNS labels from an attack manifest.")
    ap.add_argument("--features", required=True, help="features JSON (per-query records with timestamp + client_ip)")
    ap.add_argument("--manifest", required=True, help="attack manifest CSV")
    ap.add_argument("--output", required=True, help="labeled JSON output path")
    ap.add_argument("--allowlist", default=str(PROJECT_ROOT / "config" / "dns_allowlist.txt"))
    args = ap.parse_args()
    for p in (args.manifest, args.features):
        if not os.path.isfile(p):
            sys.exit(f"[error] not found: {p}")

    labeled, abstained, report = label_records(load_records(args.features), args.manifest,
                                               load_allowlist(args.allowlist))
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(labeled, f, indent=2, default=str)
    print(f"Labeled {report['attack']} attack / {report['benign']} benign · {report['by_label_source']}")
    for w in report["manifest_windows"]:
        print(f"  {w['campaign_id']:<12} {w['family']:<16} matched={w['matched']}  background(left out)={w['background']}")
    for w in report["warnings"]:
        print(f"  ! {w}")
    print(f"Saved → {args.output}")


if __name__ == "__main__":
    main()
