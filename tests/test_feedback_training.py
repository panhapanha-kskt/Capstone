"""Week 7 Task 12: analyst verdicts → training rows (export, checks, labels, window features, run record)."""
import json
import random
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.features.aggregates import FEATURES_WINDOW, add_window_features  # noqa: E402
from dns_detect.ingest.feedback import FeedbackError, build_verdict_rows, check_feedback  # noqa: E402
from dns_detect.ingest.labeling import label_records, validate_training_labels  # noqa: E402
from dns_detect.models.splits import stable_row_ids  # noqa: E402

BASE = datetime(2026, 3, 18, 13, 0, 0)


def _records(n=120):
    rnd = random.Random(7)
    out = []
    for i in range(n):
        tun = i % 2 == 0
        d = (f"{''.join(rnd.choice('abcdefghijklmnopqrstuvwxyz234567') for _ in range(30))}.t1.lab-tunnel.example"
             if tun else f"www{i}.example.com")
        out.append({"timestamp": (BASE + timedelta(seconds=i)).isoformat(), "client_ip": "10.0.0.5" if tun else "10.0.0.9",
                    "domain": d, "query_type": "A", "response_code": "NoError", "query_length": len(d),
                    "entropy": 4.2 if tun else 3.0, "source_file": "2026-03-18.log", "row_id": i,
                    "ml_score_A": 0.9 if tun else 0.1, "fusion_method": "lr"})
    return out


def _verdict(recs, i, verdict, at="2026-11-20T01:00:00Z", **kw):
    return {"fp": f"{i:016x}", "verdict": verdict, "verdict_at": at, "verdict_by": "analyst-1", "row_id": i,
            "domain": recs[i]["domain"], "client_ip": recs[i]["client_ip"], "demo": False, **kw}


def _rows(n, start=0):
    recs = _records(max(120, 2 * (n + start)))
    fb = [_verdict(recs, i, "true_positive" if i % 2 == 0 else "benign_positive") for i in range(start, start + n)]
    rows, _ = build_verdict_rows(fb, recs)
    return rows


# ── export ─────────────────────────────────────────────────────
def test_export_maps_labels_and_skips_unusable_verdicts():
    recs = _records()
    fb = [_verdict(recs, 0, "true_positive"), _verdict(recs, 1, "benign_positive"),
          _verdict(recs, 3, "fp_model_logic"), _verdict(recs, 5, "undetermined"), _verdict(recs, 7, "duplicate"),
          _verdict(recs, 9, "true_positive", demo=True), {"fp": "aa", "verdict": "true_positive", "row_id": None},
          dict(_verdict(recs, 11, "true_positive"), domain="other.example")]
    rows, skipped = build_verdict_rows(fb, recs)
    assert [r["label"] for r in rows] == [1, 0, 0]
    assert all(r["label_source"] == "analyst" for r in rows)
    assert skipped == {"verdict_not_a_label": 2, "demo_alert": 1, "alert_has_no_query_row": 1,
                       "features_file_is_from_another_run": 1}
    r = rows[0]
    assert not any(k.startswith(("ml_", "fusion_")) for k in r) and "row_id" not in r
    assert set(r["analyst_window"]) == set(FEATURES_WINDOW)


def test_export_keeps_latest_verdict_per_alert():
    recs = _records()
    fb = [_verdict(recs, 0, "true_positive", at="2026-11-20T01:00:00Z"),
          _verdict(recs, 0, "benign_positive", at="2026-11-20T02:00:00Z")]
    rows, skipped = build_verdict_rows(fb, recs)
    assert len(rows) == 1 and rows[0]["label"] == 0 and skipped["older_verdict_same_alert"] == 1


def test_window_features_match_detection_time():
    recs = _records()
    rows, _ = build_verdict_rows([_verdict(recs, 40, "true_positive")], recs)
    full = add_window_features(pd.DataFrame(recs))
    assert rows[0]["analyst_window"]["uniq_subdomains_5m"] == full.iloc[40]["uniq_subdomains_5m"] > 1


# ── training-side checks ───────────────────────────────────────
def test_fewer_than_minimum_is_refused():
    with pytest.raises(FeedbackError, match="at least 50"):
        check_feedback(_rows(10), min_verdicts=50)


def test_rows_in_frozen_test_set_are_dropped():
    rows = _rows(50)
    ids = stable_row_ids(pd.DataFrame(rows))
    manifest = {"row_ids": {ids[0]: "test", ids[1]: "train"}}
    kept, rep = check_feedback(rows, manifest, min_verdicts=1)
    assert len(kept) == 49 and rep["dropped"]["in_frozen_test_set"] == 1


def test_duplicates_and_cap():
    rows = _rows(10)
    kept, rep = check_feedback(rows + [dict(rows[0])], min_verdicts=1, max_rows=5)
    assert rep["dropped"]["duplicate_alert"] == 1 and rep["dropped"]["over_max_rows"] == 5 and len(kept) == 5


def test_non_analyst_rows_rejected():
    rows = _rows(3)
    bad = [dict(rows[0], label_source="heuristic"), dict(rows[1], label=None), dict(rows[2], domain="")]
    kept, rep = check_feedback(bad, min_verdicts=0)
    assert kept == [] and rep["dropped"] == {"not_an_analyst_label": 2, "incomplete_query_record": 1}


# ── labels and features in training ────────────────────────────
def test_analyst_labels_are_trusted_and_kept():
    rows = _rows(4)
    labeled, abstained, _ = label_records(rows)
    assert [r["label"] for r in labeled] == [r["label"] for r in rows] and not abstained
    assert validate_training_labels(labeled)["by_source"] == {"analyst": 4}


def test_window_override_only_touches_analyst_rows():
    recs = _records(40)
    df = pd.DataFrame(recs)
    plain = add_window_features(df)
    df["analyst_window"] = [None] * len(df)
    df.at[3, "analyst_window"] = {c: 99.0 for c in FEATURES_WINDOW}
    out = add_window_features(df)
    assert all(out.iloc[3][c] == 99.0 for c in FEATURES_WINDOW)
    others = [i for i in range(len(df)) if i != 3]
    pd.testing.assert_frame_equal(out.iloc[others][FEATURES_WINDOW], plain.iloc[others][FEATURES_WINDOW])


# ── CLI, run record, wiring ────────────────────────────────────
def test_cli_writes_checked_rows_and_report(tmp_path):
    inp = tmp_path / "verdict_labels.json"
    inp.write_text(json.dumps(_rows(50)))
    r = subprocess.run([sys.executable, "-m", "dns_detect.ingest.feedback", "--input", str(inp),
                        "--output", str(tmp_path / "out.json"), "--report", str(tmp_path / "rep.json")],
                       capture_output=True, text=True, env={"PYTHONPATH": str(ROOT / "src"), "PATH": ""})
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["50", "25", "25", "0"]
    rep = json.loads((tmp_path / "rep.json").read_text())
    assert rep["used"] == 50 and len(rep["input_sha256"]) == 64


def test_cli_refuses_below_minimum(tmp_path):
    inp = tmp_path / "v.json"
    inp.write_text(json.dumps(_rows(5)))
    r = subprocess.run([sys.executable, "-m", "dns_detect.ingest.feedback", "--input", str(inp),
                        "--output", str(tmp_path / "o.json"), "--report", str(tmp_path / "r.json")],
                       capture_output=True, text=True, env={"PYTHONPATH": str(ROOT / "src"), "PATH": ""})
    assert r.returncode == 2 and "at least 50" in r.stderr and not (tmp_path / "o.json").exists()


def test_run_record_includes_feedback(tmp_path):
    sys.path.insert(0, str(ROOT / "scripts"))
    import run_record
    rep = tmp_path / "feedback_report.json"
    rep.write_text(json.dumps({"used": 60, "input_sha256": "ab" * 32}))
    path = run_record.write_record(tmp_path / "run", feedback_report=str(rep))
    assert json.loads(path.read_text())["analyst_feedback"]["used"] == 60


def test_train_models_wiring():
    sh = (ROOT / "scripts" / "train_models.sh").read_text(encoding="utf-8")
    assert "--feedback)" in sh and "dns_detect.ingest.feedback" in sh and "--feedback-report" in sh
