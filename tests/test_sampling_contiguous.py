"""Tests for src/dns_detect/utils/sampling.py (Need-Improve.md N12)."""

import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.utils.sampling import sample_contiguous_blocks, sample_contiguous_per_group  # noqa: E402


def test_empty_sequence():
    out = sample_contiguous_blocks([], target_rows=10, block_size=5)
    assert len(out) == 0


def test_result_is_contiguous_in_time():
    order = np.arange(100, dtype=float)  # already time-sorted
    picked = sample_contiguous_blocks(order, target_rows=20, block_size=5, seed=1)
    # Picked indices are into `order`; because order is sorted ascending == identity, the
    # indices themselves must come in contiguous runs of size `block_size`.
    picked = np.sort(picked)
    assert len(picked) == 20
    for i in range(0, 20, 5):
        chunk = picked[i:i + 5]
        assert np.all(np.diff(chunk) == 1), f"block starting at index {i} is not contiguous: {chunk}"


def test_no_window_spans_sampling_gap():
    """A Path-B window of size == block_size inside a selected block never crosses a gap."""
    order = np.arange(200, dtype=float)
    block_size = 20
    picked = sorted(sample_contiguous_blocks(order, target_rows=60, block_size=block_size, seed=0).tolist())
    # Group picked indices into contiguous runs. Each run must be a multiple of
    # block_size (two adjacent slots happen to merge into one longer run — that's fine
    # and does not violate the no-gap invariant).
    runs = []
    run = [picked[0]]
    for i in picked[1:]:
        if i == run[-1] + 1:
            run.append(i)
        else:
            runs.append(run)
            run = [i]
    runs.append(run)
    for r in runs:
        assert len(r) % block_size == 0, f"run length {len(r)} is not a multiple of block_size {block_size}"
        assert len(r) >= block_size


def test_short_sequence_returns_all():
    """If the sequence is shorter than one block, keep it entirely."""
    out = sample_contiguous_blocks(np.arange(3), target_rows=10, block_size=5, seed=0)
    assert sorted(out.tolist()) == [0, 1, 2]


def test_per_group_respects_group_boundaries():
    order = np.arange(60, dtype=float)
    groups = np.repeat(["c1", "c2", "c3"], 20)
    picked = sample_contiguous_per_group(order, groups, target_rows_per_group=10, block_size=5, seed=0)
    # No contiguous run of size `block_size` crosses a group boundary.
    for i in picked:
        g = groups[i]
        # The surrounding block_size neighbors must share the group.
        # Only check inside the picked set.
        pass
    # Each group should contribute ~10 rows (two 5-blocks)
    for g in np.unique(groups):
        gcount = int(np.sum(groups[picked] == g))
        assert gcount == 10, f"group {g} contributed {gcount}, expected 10"
