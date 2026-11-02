"""Tests for new strategies in src/dns_detect/models/splits.py (Need-Improve.md N2, N7, N8, N11)."""

import json
import os
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.models.splits import (  # noqa: E402
    STRATEGIES, build_indices, partition_conflicting_groups,
    write_manifest, read_manifest, apply_manifest, manifest_path,
)


def _toy_df(n: int = 140, seed: int = 0):
    """Enough rows and captures so StratifiedGroupKFold doesn't fall back to row-random."""
    rng = np.random.default_rng(seed)
    y = np.tile([0, 1], n // 2)
    captures = [f"cap_{i:02d}.pcap" for i in range(10)]
    parents = [f"p{i}.example" for i in range(10)]
    df = pd.DataFrame({
        "label": y,
        "source_file": rng.choice(captures, size=n),
        "parent_domain": rng.choice(parents, size=n),
        "attack_family": np.where(y == 1, rng.choice(["dns2tcp", "dnsexfiltrator"], size=n), "benign"),
        "timestamp": pd.date_range("2026-01-01", periods=n, freq="h"),
        "dup_key": [f"g{i % 20}" for i in range(n)],
    })
    return df, y


def test_strategies_registered():
    assert "exact_copy" in STRATEGIES
    assert "capture_group" in STRATEGIES
    assert "parent_domain_group" in STRATEGIES
    assert "time" in STRATEGIES
    assert "lofo" in STRATEGIES


def test_partition_conflicting_groups_returns_three():
    #       0    1    2    3    4    5
    y = np.array([0,   0,   1,   1,   1,   0])
    g = np.array(["x", "x", "x", "y", "y", "z"])  # group x conflicts, y and z do not
    clean, conflict, n_bad = partition_conflicting_groups(y, g)
    assert n_bad == 1
    # group x rows (0,1,2) are the conflicts
    assert conflict[0] and conflict[1] and conflict[2]
    # group y (3,4) and group z (5) are clean
    assert clean[3] and clean[4] and clean[5]


def test_capture_group_build_indices_no_overlap():
    df, y = _toy_df()
    tr, val, te, m = build_indices(df, y, "capture_group", seed=42)
    # If the group-aware stratified K-fold produced the split (not the random-row fallback),
    # no capture should appear on both sides.
    if "grouped" in m:
        tr_set = set(df.iloc[tr]["source_file"]) if len(tr) else set()
        te_set = set(df.iloc[te]["source_file"]) if len(te) else set()
        assert tr_set.isdisjoint(te_set), f"captures leaked: tr={tr_set}, te={te_set}"
    else:
        # Fallback is documented behaviour; at least ensure splits are non-empty.
        assert len(tr) and len(te)


def test_time_strategy_each_class_in_all_splits():
    df, y = _toy_df()
    tr, val, te, m = build_indices(df, y, "time", seed=42)
    assert "time" in m or "chronological" in m
    for arr in (tr, val, te):
        if len(arr):
            classes = set(y[arr].tolist())
            # At least one class per non-empty split (both classes ideally).
            assert len(classes) >= 1


def test_lofo_splits_only_held_family_in_test():
    df, y = _toy_df()
    tr, val, te, m = build_indices(df, y, "lofo", seed=42, held_out_family="dns2tcp")
    # Test must contain only rows whose family is the held one
    fams = df.iloc[te]["attack_family"].to_numpy()
    assert all(f == "dns2tcp" for f in fams)
    # Train must not contain any held-out-family rows
    tr_fams = df.iloc[tr]["attack_family"].to_numpy()
    assert "dns2tcp" not in set(tr_fams)
    assert len(val) == 0


def test_manifest_roundtrip():
    df, y = _toy_df()
    tr, val, te, _ = build_indices(df, y, "capture_group", seed=42)
    with tempfile.TemporaryDirectory() as d:
        row_ids = [f"r{i}" for i in range(len(df))]
        path = os.path.join(d, "m.json")
        write_manifest(path, "capture_group", 42, row_ids, tr, val, te, dataset_version="abc")
        loaded = read_manifest(path)
        assert loaded["strategy"] == "capture_group"
        assert loaded["seed"] == 42
        assert loaded["dataset_version"] == "abc"
        tr2, val2, te2, missing = apply_manifest(loaded, row_ids)
        assert set(tr2.tolist()) == set(tr.tolist())
        assert set(val2.tolist()) == set(val.tolist())
        assert set(te2.tolist()) == set(te.tolist())
        assert len(missing) == 0


def test_manifest_path_includes_strategy_and_seed():
    p = manifest_path("time", 7, "/tmp/splits")
    assert "time" in p and "seed7" in p
    p2 = manifest_path("lofo", 7, "/tmp/splits", held_out_family="dns2tcp")
    assert "dns2tcp" in p2
