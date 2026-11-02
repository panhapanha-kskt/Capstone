#!/usr/bin/env python3
"""
extend_manifest.py — Add new training data to an existing split without moving any old row.

Rows already in --base keep their split, so test results stay comparable with the earlier
run (same test rows). Rows from --add files are split per source file in time order:
the earliest --train-share go to train, the rest to val. They never go to test.

Used for TEST_REPORT next step 2: train with CIC benign captures 1+2 (capture 3 stays the
outside test set and is never added).

Usage:
  python3 scripts/extend_manifest.py \
      --base data/processed/splits/time_seed42.json \
      --data data/processed/week4/merged_week4.json \
      --add data/external/cic/cic_benign_train.json \
      --out data/processed/week4/splits/time_seed42_cic.json
"""

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.parsing.dns_parser import _load_json_records, FEATURES_8  # noqa: E402
from dns_detect.models.splits import read_manifest, stable_row_ids, write_manifest  # noqa: E402
from dns_detect.utils.dataset_hash import dataset_hash  # noqa: E402


def extend(base: dict, data_df: pd.DataFrame, add_df: pd.DataFrame, train_share: float):
    ids = stable_row_ids(data_df)
    add_ids = set(stable_row_ids(add_df))
    assign = dict(base["row_ids"])
    ts = pd.to_datetime(data_df.get("timestamp"), errors="coerce", format="mixed")
    new = [i for i, rid in enumerate(ids) if rid in add_ids and rid not in assign]
    src = data_df["source_file"].astype(str).to_numpy() if "source_file" in data_df else np.zeros(len(ids))
    for f in sorted(set(src[new])):
        rows = sorted((i for i in new if src[i] == f), key=lambda i: (ts.iloc[i], i))
        cut = int(round(train_share * len(rows)))
        for k, i in enumerate(rows):
            assign[ids[i]] = "train" if k < cut else "val"
    idx = {s: np.array([i for i, rid in enumerate(ids) if assign.get(rid) == s], dtype=int)
           for s in ("train", "val", "test")}
    return ids, idx, len(new)


def main():
    ap = argparse.ArgumentParser(description="Add rows to a split manifest without moving old rows.")
    ap.add_argument("--base", required=True, help="existing manifest")
    ap.add_argument("--data", required=True, help="merged file holding old + new rows")
    ap.add_argument("--add", nargs="+", required=True, help="file(s) whose rows are the new ones")
    ap.add_argument("--train-share", type=float, default=0.85, help="earliest share of new rows → train")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    base = read_manifest(args.base)
    data_df = pd.DataFrame(_load_json_records(args.data))
    add_df = pd.concat([pd.DataFrame(_load_json_records(p)) for p in args.add], ignore_index=True)
    ids, idx, n_new = extend(base, data_df, add_df, args.train_share)
    n_missing = len(ids) - sum(len(v) for v in idx.values())
    notes = (f"{base.get('notes', '')}; extended from {os.path.basename(args.base)} with "
             f"{', '.join(os.path.basename(p) for p in args.add)} (train_share={args.train_share}, never test)")
    write_manifest(args.out, base["strategy"], base["seed"], ids, idx["train"], idx["val"], idx["test"],
                   dataset_version=dataset_hash([args.data], FEATURES_8), notes=notes)
    print(f"[+] {n_new} new rows added (train/val only); {n_missing} rows in no split")
    print(f"    train={len(idx['train'])}  val={len(idx['val'])}  test={len(idx['test'])}  → {args.out}")


if __name__ == "__main__":
    main()
