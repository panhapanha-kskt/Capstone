"""
splits.py — Leak-free train / validation / test split for Path A.

The merged training data repeats the same feature vectors many times (the same DNS
names, the same tunnel query shapes). A random row split puts copies of one vector in
both train and test, so the test score measures memorisation. Here every distinct
feature vector (a "group", see dns_parser.feature_vector_key) lands in exactly one
split, while the attack/benign ratio is kept per split (StratifiedGroupKFold).
"""

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold, train_test_split


def drop_conflicting_groups(y: np.ndarray, groups: np.ndarray):
    """Boolean mask that keeps rows whose group has a single label. Returns (mask, n_groups_dropped)."""
    labels_per_group = {}
    for g, lab in zip(groups, y):
        labels_per_group.setdefault(g, set()).add(int(lab))
    bad = {g for g, s in labels_per_group.items() if len(s) > 1}
    return np.array([g not in bad for g in groups]), len(bad)


def grouped_split(y: np.ndarray, groups: np.ndarray, seed: int = 42):
    """
    ≈ 71 / 14 / 14 % train / val / test with no group in two splits.
    Returns (train_idx, val_idx, test_idx, method). Falls back to a stratified random
    row split (method "random_rows_fallback") when there are too few groups to keep
    both classes in every split.
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
    """Share of test rows whose exact feature vector also appears in training (0.0 = no leak)."""
    if len(test_idx) == 0:
        return 0.0
    return float(np.isin(groups[test_idx], groups[train_idx]).mean())
