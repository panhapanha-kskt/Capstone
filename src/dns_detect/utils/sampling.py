"""
sampling.py — Contiguous-block sampling for time-series data (Need-Improve.md N12).

Path B learns from windows of N consecutive queries per client. If attack captures were
downsampled by picking individual queries at random, the windows that end up in training
contain queries that were not actually consecutive — breaking the temporal structure the
model is supposed to learn.

This module provides `sample_contiguous_blocks` which keeps whole, non-overlapping,
time-ordered blocks of configurable size, so no Path-B window ever spans a sampling gap.
"""

from __future__ import annotations

from typing import Sequence

import numpy as np


def sample_contiguous_blocks(
    order: Sequence[float],
    target_rows: int,
    block_size: int,
    seed: int = 42,
) -> np.ndarray:
    """
    Pick a set of non-overlapping, contiguous (block_size-row) blocks totalling about
    `target_rows`, uniformly at random, from a sequence of row-indices sorted by `order`.

    Returned array: sorted indices into `order` (into the ORIGINAL array, before sorting
    by order) selected for the sample.

    Guarantees:
      • Each selected block is `block_size` consecutive rows in time-order.
      • No two selected blocks overlap.
      • A Path-B window of up to `block_size` rows never spans a gap between blocks.
    """
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    order = np.asarray(order, dtype=float)
    n = len(order)
    if n == 0 or target_rows <= 0:
        return np.array([], dtype=int)
    # Sort row positions by time; later we'll return original positions.
    sort_idx = np.argsort(order, kind="stable")
    n_blocks = max(1, int(round(target_rows / block_size)))
    # Divide the sorted sequence into disjoint block slots of size `block_size`.
    max_slots = n // block_size
    if max_slots == 0:
        # Sequence shorter than one block — return all of it (take or leave policy).
        return np.sort(sort_idx)
    n_blocks = min(n_blocks, max_slots)
    rng = np.random.default_rng(seed)
    slot_ids = rng.choice(max_slots, size=n_blocks, replace=False)
    picked: list = []
    for slot in slot_ids:
        start = int(slot) * block_size
        picked.extend(sort_idx[start:start + block_size].tolist())
    return np.array(sorted(picked), dtype=int)


def sample_contiguous_per_group(
    order: Sequence[float],
    groups: Sequence,
    target_rows_per_group: int,
    block_size: int,
    seed: int = 42,
) -> np.ndarray:
    """
    Apply `sample_contiguous_blocks` within each group (e.g. per client, per capture).
    `target_rows_per_group` is the per-group target; groups smaller than that are kept
    whole. Returns sorted indices into the original arrays.
    """
    order = np.asarray(order, dtype=float)
    groups = np.asarray(groups)
    picked: list = []
    for g in np.unique(groups):
        mask = np.where(groups == g)[0]
        if len(mask) <= target_rows_per_group:
            picked.extend(mask.tolist())
            continue
        local = sample_contiguous_blocks(order[mask], target_rows_per_group, block_size,
                                         seed=hash((seed, str(g))) & 0xFFFFFFFF)
        picked.extend(mask[local].tolist())
    return np.array(sorted(picked), dtype=int)
