"""Tests for splits.prepare_training_split — the one split train_models.sh gives Path A, Path B and fusion."""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.models.splits import (  # noqa: E402
    build_indices, prepare_training_split, stable_row_ids, write_manifest,
)


def _df(n=200, start="2026-01-01", src="cap.json", offset=0):
    y = np.tile([0, 1], n // 2)
    return pd.DataFrame({
        "label": y,
        "timestamp": pd.date_range(start, periods=n, freq="s").astype(str),
        "client_ip": "10.0.0.1",
        "domain": [f"q{offset + i}.example.com" for i in range(n)],
        "query_type": "A",
        "source_file": src,
    })


def _base_for(df, tmp_path):
    ids = stable_row_ids(df)
    tr, val, te, _ = build_indices(df, df["label"].to_numpy(), "time", seed=42)
    return write_manifest(str(tmp_path / "base.json"), "time", 42, ids, tr, val, te)


def test_fresh_split_is_time_ordered_and_complete():
    df = _df()
    ids, idx, info = prepare_training_split(df, df["label"].to_numpy())
    assert info["mode"] == "new"
    assert sum(len(v) for v in idx.values()) == len(df)
    ts = pd.to_datetime(df["timestamp"])
    for cls in (0, 1):  # per class: every train row is earlier than every test row
        m = df["label"].to_numpy() == cls
        tr = ts[np.intersect1d(idx["train"], np.where(m)[0])]
        te = ts[np.intersect1d(idx["test"], np.where(m)[0])]
        assert tr.max() < te.min()


def test_base_covering_all_rows_is_reused_unchanged(tmp_path):
    df = _df()
    base = _base_for(df, tmp_path)
    ids, idx, info = prepare_training_split(df, df["label"].to_numpy(), base)
    assert info["mode"] == "reused" and info["n_new"] == 0
    for s in ("train", "val", "test"):
        assert {ids[i] for i in idx[s]} == {r for r, v in base["row_ids"].items() if v == s}


def test_new_rows_extend_train_val_only_and_test_stays_frozen(tmp_path):
    old = _df()
    base = _base_for(old, tmp_path)
    new = _df(100, start="2026-02-01", src="new.json", offset=10_000)
    df = pd.concat([old, new], ignore_index=True)
    ids, idx, info = prepare_training_split(df, df["label"].to_numpy(), base, train_share=0.8)
    assert info["mode"] == "extended" and info["n_new"] == 100
    test_ids = {ids[i] for i in idx["test"]}
    assert test_ids == {r for r, v in base["row_ids"].items() if v == "test"}
    new_pos = set(range(len(old), len(df)))
    assert not new_pos & set(idx["test"].tolist())
    assert len(new_pos & set(idx["train"].tolist())) == 80     # earliest 80 % of new rows → train


def test_unrelated_base_gives_fresh_split(tmp_path):
    base = _base_for(_df(offset=50_000), tmp_path)
    df = _df()
    _, _, info = prepare_training_split(df, df["label"].to_numpy(), base)
    assert info["mode"] == "new"


def test_single_class_validation_fails_closed(tmp_path):
    df = _df()
    ids = stable_row_ids(df)
    y = df["label"].to_numpy()
    ben, att = np.where(y == 0)[0], np.where(y == 1)[0]
    base = write_manifest(str(tmp_path / "b.json"), "time", 42, ids,
                          np.concatenate([ben[:60], att[:80]]), ben[60:], att[80:])
    with pytest.raises(ValueError, match="only one class"):
        prepare_training_split(df, y, base)
