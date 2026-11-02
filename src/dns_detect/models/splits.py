"""
splits.py — Train / validation / test splits for Path A, Path B and fusion.

Original role: Path A split by `feature_vector_key` so exact-copy leakage is removed
(`grouped_split` + `drop_conflicting_groups` + `overlap_share`). Those remain the
canonical in-sample split so previous results stay reproducible.

Need-Improve.md adds (N2, N11, N13):
  • Several named split *strategies*, not just one: exact_copy, capture_group,
    parent_domain_group, time, lofo.
  • A manifest I/O layer so Path A, Path B and fusion score themselves on the
    *same* rows per strategy (N11), and so a run can be reproduced seed-by-seed.
  • partition_conflicting_groups — keep the conflicts as a named error category
    (N8) instead of silently dropping them.

A manifest is a JSON file:
    {"strategy": ..., "seed": ..., "dataset_version": ..., "created_at": ...,
     "row_ids": {"<row_id>": "train"|"val"|"test", ...},
     "n_train": ..., "n_val": ..., "n_test": ...,
     "notes": "..."}

`row_id` is the row's position in the labeled JSON file by default. If the
caller supplies explicit ids, those are stored instead so manifests survive row
reordering.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold, train_test_split


# ─────────────────────────────────────────────
# Original API (kept for backward compat with path_a._train)
# ─────────────────────────────────────────────

def drop_conflicting_groups(y: np.ndarray, groups: np.ndarray):
    """Boolean mask that keeps rows whose group has a single label. Returns (mask, n_groups_dropped)."""
    labels_per_group: dict = {}
    for g, lab in zip(groups, y):
        labels_per_group.setdefault(g, set()).add(int(lab))
    bad = {g for g, s in labels_per_group.items() if len(s) > 1}
    return np.array([g not in bad for g in groups]), len(bad)


def partition_conflicting_groups(y: np.ndarray, groups: np.ndarray):
    """
    N8: Instead of dropping conflicts silently, return (clean_mask, conflict_mask, n_conflict_groups).
    Caller is expected to persist the conflict partition as an error-analysis set.
    """
    mask, n_bad = drop_conflicting_groups(y, groups)
    return mask, (~mask), n_bad


def grouped_split(y: np.ndarray, groups: np.ndarray, seed: int = 42):
    """
    ≈ 71 / 14 / 14 % train / val / test with no group in two splits. Falls back to a
    stratified random row split (method 'random_rows_fallback') when StratifiedGroupKFold
    cannot keep both classes in every fold.
    """
    y = np.asarray(y)
    groups = np.asarray(groups)
    idx = np.arange(len(y))
    try:
        outer = StratifiedGroupKFold(n_splits=7, shuffle=True, random_state=seed)
        rest, test = next(outer.split(idx, y, groups))
        inner = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=seed)
        tr_rel, val_rel = next(inner.split(rest, y[rest], groups[rest]))
        train, val = rest[tr_rel], rest[val_rel]
        if all(len(np.unique(y[s])) == 2 for s in (train, val, test)):
            return train, val, test, "grouped_by_feature_vector"
    except ValueError:
        pass
    train, tmp = train_test_split(idx, test_size=0.30, random_state=seed, stratify=y)
    val, test = train_test_split(tmp, test_size=0.50, random_state=seed, stratify=y[tmp])
    return train, val, test, "random_rows_fallback"


def overlap_share(groups: np.ndarray, train_idx: np.ndarray, test_idx: np.ndarray) -> float:
    """Share of test rows whose exact group also appears in training (0.0 = no leak)."""
    if len(test_idx) == 0:
        return 0.0
    return float(np.isin(groups[test_idx], groups[train_idx]).mean())


# ─────────────────────────────────────────────
# N2: new named strategies
# ─────────────────────────────────────────────

STRATEGIES = ("exact_copy", "capture_group", "parent_domain_group", "time", "lofo")


def _groups_for_strategy(df: pd.DataFrame, strategy: str) -> np.ndarray:
    """Return a 1-D group label per row for group-based strategies."""
    if strategy == "exact_copy":
        # Reuse the per-row dup_key when the merge step wrote it; otherwise fall back
        # to a hash of FEATURES_8 computed on the fly.
        if "dup_key" in df.columns:
            return df["dup_key"].astype(str).to_numpy()
        from dns_detect.parsing.dns_parser import feature_vector_key  # local import avoids cycle
        return feature_vector_key(df).to_numpy()
    if strategy == "capture_group":
        if "source_file" not in df.columns:
            raise ValueError("capture_group needs a 'source_file' column")
        return df["source_file"].astype(str).to_numpy()
    if strategy == "parent_domain_group":
        if "parent_domain" in df.columns:
            return df["parent_domain"].astype(str).to_numpy()
        if "domain" in df.columns:
            from dns_detect.ingest.labeling import parent_domain  # local import
            return df["domain"].astype(str).map(parent_domain).to_numpy()
        raise ValueError("parent_domain_group needs a 'parent_domain' or 'domain' column")
    raise ValueError(f"strategy {strategy!r} is not group-based")


def _time_split(df: pd.DataFrame, y: np.ndarray, seed: int = 42,
                val_share: float = 0.14, test_share: float = 0.14):
    """
    Per-class chronological cut: inside each class, sort by timestamp and take the
    *earliest* (1 - val - test) share for train, the next `val_share` for val and the
    last `test_share` for test. This handles the attack/benign 683-day gap documented
    in Need-Improve.md P4 — a global time cut would otherwise land all of one class
    on one side.
    """
    if "timestamp" not in df.columns:
        raise ValueError("time strategy needs a 'timestamp' column")
    ts = pd.to_datetime(df["timestamp"], errors="coerce")
    if getattr(ts.dt, "tz", None) is not None:
        ts = ts.dt.tz_convert(None)
    secs = (ts - pd.Timestamp("1970-01-01")).dt.total_seconds().to_numpy()
    # Rows without a timestamp fall back to the row index (stable, deterministic).
    order_key = np.where(np.isnan(secs), np.arange(len(df), dtype=float), secs)
    y = np.asarray(y)
    train, val, test = [], [], []
    for cls in np.unique(y):
        idx = np.where(y == cls)[0]
        idx = idx[np.argsort(order_key[idx], kind="stable")]
        n = len(idx)
        n_test = max(1, int(round(n * test_share)))
        n_val = max(1, int(round(n * val_share)))
        n_train = max(1, n - n_val - n_test)
        if n_train + n_val + n_test > n:
            n_train = n - n_val - n_test
        train.extend(idx[:n_train].tolist())
        val.extend(idx[n_train:n_train + n_val].tolist())
        test.extend(idx[n_train + n_val:].tolist())
    rng = np.random.default_rng(seed)
    train = np.array(train)
    val = np.array(val)
    test = np.array(test)
    rng.shuffle(train)
    return train, val, test, "time_per_class_chronological"


def _lofo_split(df: pd.DataFrame, y: np.ndarray, held_out_family: str):
    """
    Leave-One-Family-Out: train = benign + all attack families EXCEPT the held-out one,
    test = held-out family. 'val' is the empty array by convention; the caller should
    use `train` for both training and threshold calibration (document the leakage trade-off).
    """
    if "attack_family" not in df.columns:
        raise ValueError("lofo strategy needs an 'attack_family' column")
    fam = df["attack_family"].astype(str).to_numpy()
    y = np.asarray(y)
    held = (y == 1) & (fam == held_out_family)
    rest = ~held
    train = np.where(rest)[0]
    test = np.where(held)[0]
    val = np.array([], dtype=int)
    return train, val, test, f"lofo:{held_out_family}"


def build_indices(df: pd.DataFrame, y: np.ndarray, strategy: str, seed: int = 42,
                  held_out_family: str | None = None):
    """
    Dispatch for all strategies. Returns (train_idx, val_idx, test_idx, method_name).
    """
    if strategy in ("exact_copy", "capture_group", "parent_domain_group"):
        groups = _groups_for_strategy(df, strategy)
        tr, val, te, method = grouped_split(y, groups, seed=seed)
        if method == "grouped_by_feature_vector":
            method = f"grouped_by_{strategy}"
        return tr, val, te, method
    if strategy == "time":
        return _time_split(df, y, seed=seed)
    if strategy == "lofo":
        if not held_out_family:
            raise ValueError("lofo strategy requires `held_out_family`")
        return _lofo_split(df, y, held_out_family)
    raise ValueError(f"unknown strategy {strategy!r}")


# ─────────────────────────────────────────────
# N11: shared, versioned split manifest
# ─────────────────────────────────────────────

def manifest_path(strategy: str, seed: int, out_dir: str = "data/processed/splits",
                  held_out_family: str | None = None) -> str:
    tag = f"{strategy}"
    if held_out_family:
        tag += f"-{held_out_family}"
    tag += f"_seed{seed}"
    return os.path.join(out_dir, f"{tag}.json")


def write_manifest(path: str, strategy: str, seed: int, row_ids: Sequence,
                   train_idx: np.ndarray, val_idx: np.ndarray, test_idx: np.ndarray,
                   dataset_version: str | None = None, notes: str = "") -> dict:
    assign = {}
    for i in train_idx:
        assign[str(row_ids[int(i)])] = "train"
    for i in val_idx:
        assign[str(row_ids[int(i)])] = "val"
    for i in test_idx:
        assign[str(row_ids[int(i)])] = "test"
    data = {
        "strategy": strategy,
        "seed": int(seed),
        "dataset_version": dataset_version,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "n_train": int(len(train_idx)),
        "n_val": int(len(val_idx)),
        "n_test": int(len(test_idx)),
        "notes": notes,
        "row_ids": assign,
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return data


def read_manifest(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


ROW_ID_FIELDS = ("source_file", "timestamp", "client_ip", "domain", "query_type")


def stable_row_ids(df: pd.DataFrame) -> list:
    """
    Content-based row id: sha1 of the query's identifying fields plus an occurrence counter
    for exact repeats. The same query gets the same id in labeled_*.json, the merged file and
    the labeled merge, so one manifest can drive Path A, Path B and fusion.
    """
    import hashlib

    cols = [c for c in ROW_ID_FIELDS if c in df.columns]
    if not cols:
        return [str(i) for i in range(len(df))]
    keys = df[cols].astype(str).agg("|".join, axis=1)
    seen: dict = {}
    out = []
    for k in keys:
        n = seen.get(k, 0)
        seen[k] = n + 1
        out.append(hashlib.sha1(f"{k}#{n}".encode()).hexdigest()[:20])
    return out


def load_manifest_indices(path: str, df: pd.DataFrame):
    """Read a manifest and return (train, val, test, missing, manifest) index arrays for `df`."""
    manifest = read_manifest(path)
    tr, val, te, missing = apply_manifest(manifest, stable_row_ids(df))
    return tr, val, te, missing, manifest


def apply_manifest(manifest: dict, row_ids: Sequence):
    """
    Translate the manifest's {row_id: split} mapping to integer index arrays positioned
    for the given `row_ids` order. Rows missing from the manifest are returned as a 4th
    index array (useful for the error-analysis / conflict partition).
    """
    assign = manifest["row_ids"]
    train, val, test, missing = [], [], [], []
    for i, rid in enumerate(row_ids):
        split = assign.get(str(rid))
        if split == "train":
            train.append(i)
        elif split == "val":
            val.append(i)
        elif split == "test":
            test.append(i)
        else:
            missing.append(i)
    return (np.array(train, dtype=int), np.array(val, dtype=int),
            np.array(test, dtype=int), np.array(missing, dtype=int))
