"""
feedback.py — Analyst verdicts as training rows (Week 7 Task 12).

Two halves, one rule set:
  * build_verdict_rows()  — used by scripts/export_feedback_labels.py. Joins each verdict from the SOC
    dashboard to the DNS query that raised the alert (by the alert's row_id in the pipeline's
    week3_features_all.json), and stores the query's 5-minute window features as they were at
    detection time (`analyst_window`), because the surrounding traffic is not in the training data.
  * check_feedback()      — used by train_models.sh --feedback (step 8). Validates and filters the
    exported rows before they join the training data.

Why the checks (Arp et al., "Dos and Don'ts of ML in Computer Security", USENIX Security 2022; label
noise and leakage are pitfalls P2 and P6):
  - only explicit labels: true_positive → 1; benign_positive / false_positive / fp_model_logic /
    fp_bad_data → 0; undetermined and duplicate are skipped; demo alerts are skipped;
  - one row per alert (the latest verdict wins);
  - a verdict row whose content id is in the frozen TEST set of the base split is dropped, so an
    analyst label can never change the test score (new rows go to train/val only, never test);
  - a minimum number of verdicts (feedback.min_verdicts, default 50) so a handful of labels can't
    steer a model, and a cap (feedback.max_rows, default 5000, most recent kept) so verdicts can't
    swamp the curated data.

CLI (train_models.sh):
    python3 -m dns_detect.ingest.feedback --input data/feedback/verdict_labels.json \
        --output data/processed/feedback_checked.json --report data/processed/feedback_report.json \
        [--base-manifest data/processed/splits/time_seed42.json] [--min 50] [--max-rows 5000]
Prints one summary line on success; exit code 2 with the reason on stderr when the verdicts can't be used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

VERDICT_TO_LABEL = {"true_positive": 1, "benign_positive": 0, "false_positive": 0,
                    "fp_model_logic": 0, "fp_bad_data": 0}
SKIPPED_VERDICTS = {"undetermined", "duplicate"}
LABEL_SOURCE = "analyst"
DEFAULT_MIN_VERDICTS = 50
DEFAULT_MAX_ROWS = 5000
# ML / pipeline outputs on the query record that must not become training inputs.
DROP_FIELDS_PREFIX = ("ml_", "fusion_", "confidence_method", "suppressed_by_allowlist")
REQUIRED_FIELDS = ("domain", "timestamp", "client_ip")


class FeedbackError(ValueError):
    """The verdicts can't be used for training (too few, malformed)."""


def settings() -> dict:
    out = {"min_verdicts": DEFAULT_MIN_VERDICTS, "max_rows": DEFAULT_MAX_ROWS}
    try:
        from dns_detect.config import settings as s
        fb = getattr(s, "feedback", None)
        if fb is not None:
            out.update({k: v for k, v in vars(fb).items() if k in out})
    except Exception:
        pass
    return out


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _truthy(v) -> bool:
    return v is True or str(v).lower() in ("true", "1", "yes")


# ── export side ──────────────────────────────────────────────────
def build_verdict_rows(feedback: list, records: list, include_demo: bool = False):
    """feedback: rows from /api/feedback/export; records: the pipeline's week3_features_all.json.
    Returns (rows, skipped Counter). Each row is the original query record plus label fields."""
    import pandas as pd
    from dns_detect.features.aggregates import FEATURES_WINDOW, add_window_features

    skipped: Counter = Counter()
    wanted = {}
    for fb in feedback:
        verdict = fb.get("verdict")
        if verdict in SKIPPED_VERDICTS or verdict not in VERDICT_TO_LABEL:
            skipped["verdict_not_a_label"] += 1
            continue
        if _truthy(fb.get("demo")) and not include_demo:
            skipped["demo_alert"] += 1
            continue
        rid = fb.get("row_id")
        try:
            rid = int(rid)
        except (TypeError, ValueError):
            skipped["alert_has_no_query_row"] += 1      # e.g. NXDOMAIN-flood or Z-score alerts
            continue
        if not 0 <= rid < len(records):
            skipped["query_row_not_in_features_file"] += 1
            continue
        rec = records[rid]
        if (str(rec.get("domain", "")).lower() != str(fb.get("domain", "")).lower()
                or str(rec.get("client_ip", "")) != str(fb.get("client_ip", ""))):
            skipped["features_file_is_from_another_run"] += 1
            continue
        prev = wanted.get(fb.get("fp"))
        if prev is None or str(fb.get("verdict_at") or "") >= str(prev[1].get("verdict_at") or ""):
            if prev is not None:
                skipped["older_verdict_same_alert"] += 1
            wanted[fb.get("fp")] = (rid, fb)
        else:
            skipped["older_verdict_same_alert"] += 1
    if not wanted:
        return [], skipped

    win = add_window_features(pd.DataFrame(records))[FEATURES_WINDOW]
    rows = []
    for fp, (rid, fb) in wanted.items():
        rec = {k: v for k, v in records[rid].items()
               if not str(k).startswith(DROP_FIELDS_PREFIX) and k != "row_id"}
        label = VERDICT_TO_LABEL[fb["verdict"]]
        rec.update({
            "label": label,
            "label_source": LABEL_SOURCE,
            "attack_family": "analyst_confirmed" if label == 1 else "benign",
            "verdict": fb["verdict"], "verdict_by": fb.get("verdict_by"), "verdict_at": fb.get("verdict_at"),
            "verdict_reason": fb.get("verdict_reason"), "alert_fp": fp, "alert_rule": fb.get("rule"),
            "source_row_id": rid,
            "analyst_window": {c: float(win.iloc[rid][c]) for c in FEATURES_WINDOW},
        })
        rows.append(rec)
    rows.sort(key=lambda r: str(r.get("verdict_at") or ""))
    return rows, skipped


# ── training side ────────────────────────────────────────────────
def check_feedback(rows: list, base_manifest: dict | None = None,
                   min_verdicts: int = DEFAULT_MIN_VERDICTS, max_rows: int = DEFAULT_MAX_ROWS):
    """Return (kept_rows, report). Raises FeedbackError if fewer than min_verdicts remain."""
    import pandas as pd
    from dns_detect.models.splits import stable_row_ids

    dropped: Counter = Counter()
    kept, by_alert = [], {}
    for r in rows:
        if r.get("label_source") != LABEL_SOURCE or r.get("label") not in (0, 1) or isinstance(r.get("label"), bool):
            dropped["not_an_analyst_label"] += 1
            continue
        if any(r.get(f) in (None, "") for f in REQUIRED_FIELDS):
            dropped["incomplete_query_record"] += 1
            continue
        key = r.get("alert_fp") or (r["domain"], r["client_ip"], r["timestamp"])
        if key in by_alert:
            dropped["duplicate_alert"] += 1
            if str(r.get("verdict_at") or "") >= str(kept[by_alert[key]].get("verdict_at") or ""):
                kept[by_alert[key]] = r
            continue
        by_alert[key] = len(kept)
        kept.append(r)

    if kept and base_manifest and isinstance(base_manifest.get("row_ids"), dict):
        test_ids = {k for k, v in base_manifest["row_ids"].items() if v == "test"}
        ids = stable_row_ids(pd.DataFrame(kept))
        before = len(kept)
        kept = [r for r, i in zip(kept, ids) if i not in test_ids]
        dropped["in_frozen_test_set"] += before - len(kept)

    kept.sort(key=lambda r: str(r.get("verdict_at") or ""))
    if len(kept) > max_rows:
        dropped["over_max_rows"] += len(kept) - max_rows
        kept = kept[-max_rows:]

    attack = sum(1 for r in kept if r["label"] == 1)
    times = sorted(str(r.get("verdict_at")) for r in kept if r.get("verdict_at"))
    report = {"input_rows": len(rows), "used": len(kept), "attack": attack, "benign": len(kept) - attack,
              "dropped": dict(dropped), "min_verdicts": min_verdicts, "max_rows": max_rows,
              "verdict_dates": [times[0], times[-1]] if times else None}
    if len(kept) < min_verdicts:
        raise FeedbackError(f"only {len(kept)} usable analyst verdict(s) after checks "
                            f"(dropped: {dict(dropped) or 'none'}); at least {min_verdicts} are needed "
                            f"(feedback.min_verdicts in config/settings.yaml). Training was not started.")
    return kept, report


def main(argv=None):
    cfg = settings()
    ap = argparse.ArgumentParser(description="Check analyst verdicts before they join the training data.")
    ap.add_argument("--input", required=True, help="verdict_labels.json from scripts/export_feedback_labels.py")
    ap.add_argument("--output", required=True, help="checked rows, added to the training files")
    ap.add_argument("--report", required=True)
    ap.add_argument("--base-manifest", help="base split; verdict rows in its test set are dropped")
    ap.add_argument("--min", type=int, default=int(cfg["min_verdicts"]))
    ap.add_argument("--max-rows", type=int, default=int(cfg["max_rows"]))
    a = ap.parse_args(argv)
    try:
        data = json.loads(Path(a.input).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"cannot read {a.input}: {e}", file=sys.stderr)
        return 2
    rows = data.get("records", []) if isinstance(data, dict) else data
    base = None
    if a.base_manifest and Path(a.base_manifest).is_file():
        base = json.loads(Path(a.base_manifest).read_text(encoding="utf-8"))
    try:
        kept, report = check_feedback(rows, base, a.min, a.max_rows)
    except FeedbackError as e:
        print(str(e), file=sys.stderr)
        return 2
    report.update({"input_file": a.input, "input_sha256": sha256_file(a.input),
                   "base_manifest": a.base_manifest if base else None})
    Path(a.output).write_text(json.dumps(kept, indent=1), encoding="utf-8")
    Path(a.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    d = report["dropped"]
    print(f"{report['used']} {report['attack']} {report['benign']} {sum(d.values())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
