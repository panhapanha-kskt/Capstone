"""Path B ordering across mixed ISO precision and timezone offsets."""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.parsing.dns_parser import load_multifeature_with_meta  # noqa: E402


def test_multifeature_order_mixed_iso_precision_and_timezones(tmp_path):
    stamps = [
        "2026-01-01T00:00:00",
        "2026-01-01T00:00:00.500000",
        "2026-01-01T01:00:00+01:00",
        "2025-12-31T19:00:00-05:00",
        "not-a-time",
    ]
    path = tmp_path / "mixed.json"
    path.write_text(json.dumps([{"timestamp": t, "client_ip": "host"} for t in stamps]))
    X, labels, clients, order = load_multifeature_with_meta(str(path), features=["query_length"])
    epoch = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    np.testing.assert_array_equal(order, [epoch, epoch + 0.5, epoch, epoch, 4.0])
    assert order[1] > order[0] and order[2] == order[0]
    assert X.shape == (5, 1) and labels.tolist() == [0] * 5
    assert clients.tolist() == ["host"] * 5
