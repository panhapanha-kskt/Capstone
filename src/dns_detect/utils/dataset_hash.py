"""
dataset_hash.py — Reproducibility hash for a labeled training set (Need-Improve.md N14).

`merged_features_*.json` is overwritten every run, so models cannot be traced back to the
dataset version that produced them. This module computes a stable sha256 from the sorted
(relpath, size, content-sha256) tuples of a set of files, mixed with the sorted schema
(feature-column names). Any change to a byte in an input, to the set of inputs, or to the
model's expected columns gives a different digest.

The schema is mixed in because two different feature sets can share identical raw inputs
but produce different models; `training_metadata.json` should distinguish them.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterable


def _file_sha256(path: str, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for buf in iter(lambda: f.read(chunk), b""):
            h.update(buf)
    return h.hexdigest()


def dataset_hash(paths: Iterable[str], schema: Iterable[str], root: str | None = None) -> str:
    """
    Deterministic sha256 digest of a dataset.

    paths : files whose content defines the dataset. Order is not meaningful; files are
            sorted by path (relative to `root` when given) before hashing.
    schema: feature-column names. Order is not meaningful; sorted before hashing.
    root  : base directory for relative paths, so the digest is stable across machines.
    """
    entries: list[tuple[str, int, str]] = []
    for p in paths:
        abs_p = os.path.abspath(p)
        if not os.path.isfile(abs_p):
            # Raise rather than skip — a missing input IS a change to the dataset.
            raise FileNotFoundError(abs_p)
        rel = os.path.relpath(abs_p, root) if root else abs_p
        rel = Path(rel).as_posix()
        entries.append((rel, os.path.getsize(abs_p), _file_sha256(abs_p)))

    entries.sort(key=lambda t: t[0])
    schema_sorted = sorted(str(s) for s in schema)

    h = hashlib.sha256()
    for rel, size, digest in entries:
        h.update(f"{rel}\0{size}\0{digest}\n".encode("utf-8"))
    h.update(b"--schema--\n")
    for col in schema_sorted:
        h.update(col.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def short(digest: str, n: int = 16) -> str:
    """Short form for display / filenames (first n hex chars)."""
    return digest[:n]
