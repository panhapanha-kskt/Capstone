#!/usr/bin/env python3
"""
Save analyst verdicts from the running SOC dashboard as a labelled CSV for the next retraining.

    python scripts/export_feedback_labels.py                       # dashboard on 127.0.0.1:9000
    python scripts/export_feedback_labels.py --url http://127.0.0.1:8000 --include-demo

Output: data/feedback/labels_<YYYYMMDD_HHMMSS>.csv with one row per alert that has a verdict.
  label 1 = true_positive (attack), 0 = false_positive / benign_positive, empty = duplicate (skip).

Retraining stays a human decision: review the file, then merge the rows you trust into the labelled
training data (see docs/Week6/SOC_ML_INTEGRATION.md, "Feedback loop").
"""

import argparse
import csv
import io
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--url", default="http://127.0.0.1:9000", help="dashboard base URL")
    p.add_argument("--out-dir", default=str(ROOT / "data" / "feedback"))
    p.add_argument("--include-demo", action="store_true", help="keep rows from demo-mode alerts")
    args = p.parse_args()

    url = args.url.rstrip("/") + "/api/feedback/export?format=csv"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:  # noqa: S310 (local dashboard)
            text = r.read().decode("utf-8")
    except OSError as e:
        sys.exit(f"Could not reach the dashboard at {args.url}: {e}")

    rows = list(csv.DictReader(io.StringIO(text)))
    fields = rows[0].keys() if rows else csv.DictReader(io.StringIO(text)).fieldnames or []
    kept = [r for r in rows if args.include_demo or r.get("demo") not in ("True", "true", "1")]
    usable = [r for r in kept if r.get("label") in ("0", "1")]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"labels_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(fields))
        w.writeheader()
        w.writerows(kept)

    attack = sum(1 for r in usable if r["label"] == "1")
    print(f"Wrote {out} ({len(kept)} rows: {attack} attack, {len(usable) - attack} benign, "
          f"{len(kept) - len(usable)} not usable; {len(rows) - len(kept)} demo rows skipped)")


if __name__ == "__main__":
    main()
