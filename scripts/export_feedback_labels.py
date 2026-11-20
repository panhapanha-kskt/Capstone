#!/usr/bin/env python3
"""
Save analyst verdicts from the SOC dashboard for review and for the next retraining.

    python scripts/export_feedback_labels.py                       # dashboard on 127.0.0.1:9000
    python scripts/export_feedback_labels.py --url http://127.0.0.1:8000 --include-demo
    python scripts/export_feedback_labels.py --from-json feedback.json   # offline, from a saved export

Writes two files in data/feedback/:
  labels_<YYYYMMDD_HHMMSS>.csv   one row per verdict, for people to read (as before)
  verdict_labels.json            training rows: each verdict joined to the DNS query that raised the alert
                                 (from the pipeline's data/processed/week3_features_all.json), with
                                 label_source="analyst". Use it with:
                                     ./scripts/train_models.sh --feedback data/feedback/verdict_labels.json
  verdict_labels.meta.json       counts, skipped reasons and the SHA-256 of both input files

Labels: true_positive → 1; benign_positive / false_positive / fp_model_logic / fp_bad_data → 0;
undetermined and duplicate are skipped. Export soon after triage: the features file is rewritten by
every pipeline run, and verdicts whose query is no longer in it are skipped (and counted), not guessed.
"""

import argparse
import csv
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.ingest.feedback import build_verdict_rows, sha256_file  # noqa: E402


def fetch(url: str) -> list:
    with urllib.request.urlopen(url, timeout=15) as r:  # noqa: S310 (local dashboard)
        data = json.loads(r.read().decode("utf-8"))
    return data.get("records", []) if isinstance(data, dict) else data


def write_csv(rows: list, out: Path):
    fields = sorted({k for r in rows for k in r}) if rows else ["fp", "label", "verdict"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            # spreadsheet-safe: a cell starting with = + - @ is shown as text
            w.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for k, v in r.items()})


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--url", default="http://127.0.0.1:9000", help="dashboard base URL")
    p.add_argument("--from-json", help="read a saved /api/feedback/export JSON instead of the dashboard")
    p.add_argument("--features", default=str(ROOT / "data" / "processed" / "week3_features_all.json"),
                   help="the pipeline's per-query features file the alerts came from")
    p.add_argument("--out-dir", default=str(ROOT / "data" / "feedback"))
    p.add_argument("--include-demo", action="store_true", help="keep rows from demo-mode alerts")
    a = p.parse_args(argv)

    try:
        if a.from_json:
            raw = json.loads(Path(a.from_json).read_text(encoding="utf-8"))
            feedback = raw.get("records", []) if isinstance(raw, dict) else raw
        else:
            feedback = fetch(a.url.rstrip("/") + "/api/feedback/export")
    except (OSError, ValueError) as e:
        sys.exit(f"Could not read the verdicts ({a.from_json or a.url}): {e}")

    out_dir = Path(a.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = out_dir / f"labels_{stamp}.csv"
    write_csv([r for r in feedback if a.include_demo or not r.get("demo")], csv_path)

    feat = Path(a.features)
    if not feat.is_file():
        sys.exit(f"Wrote {csv_path}. No training rows: features file not found: {feat}")
    records = json.loads(feat.read_text(encoding="utf-8"))
    records = records.get("records", []) if isinstance(records, dict) else records
    rows, skipped = build_verdict_rows(feedback, records, include_demo=a.include_demo)

    json_path = out_dir / "verdict_labels.json"
    json_path.write_text(json.dumps(rows, indent=1, default=str), encoding="utf-8")
    attack = sum(1 for r in rows if r["label"] == 1)
    meta = {"exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "verdicts_in": len(feedback), "training_rows": len(rows), "attack": attack,
            "benign": len(rows) - attack, "skipped": dict(skipped),
            "features_file": str(feat), "features_sha256": sha256_file(feat),
            "verdict_labels_sha256": sha256_file(json_path)}
    (out_dir / "verdict_labels.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(f"Wrote {csv_path} ({len(feedback)} verdicts, for review)")
    print(f"Wrote {json_path}: {len(rows)} training rows ({attack} attack, {len(rows) - attack} benign)"
          + (f"; skipped {dict(skipped)}" if skipped else ""))
    print("Train with them: ./scripts/train_models.sh --feedback data/feedback/verdict_labels.json "
          "(needs at least 50 usable verdicts)")


if __name__ == "__main__":
    main()
