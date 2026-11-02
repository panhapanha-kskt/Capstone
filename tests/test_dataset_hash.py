"""Tests for src/dns_detect/utils/dataset_hash.py (Need-Improve.md N14)."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.utils.dataset_hash import dataset_hash, short  # noqa: E402


def _write(path, content):
    path.write_bytes(content.encode() if isinstance(content, str) else content)


def test_hash_is_deterministic():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        a, b = d / "a.json", d / "b.json"
        _write(a, "aaa")
        _write(b, "bbb")
        h1 = dataset_hash([str(a), str(b)], ["x", "y"], root=str(d))
        h2 = dataset_hash([str(b), str(a)], ["y", "x"], root=str(d))
        assert h1 == h2


def test_hash_changes_with_byte():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        a = d / "a.json"
        _write(a, "aaa")
        h1 = dataset_hash([str(a)], ["x"], root=str(d))
        _write(a, "aab")
        h2 = dataset_hash([str(a)], ["x"], root=str(d))
        assert h1 != h2


def test_hash_changes_with_schema():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        a = d / "a.json"
        _write(a, "aaa")
        h1 = dataset_hash([str(a)], ["x"], root=str(d))
        h2 = dataset_hash([str(a)], ["x", "y"], root=str(d))
        assert h1 != h2


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        dataset_hash(["/nonexistent/path"], ["x"])


def test_short_truncates():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        a = d / "a.json"
        _write(a, "aaa")
        h = dataset_hash([str(a)], ["x"], root=str(d))
        assert len(short(h, 16)) == 16
        assert short(h, 8) == h[:8]
