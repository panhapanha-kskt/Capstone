#!/usr/bin/env python3
"""
prepare_split.py — Build the one split manifest a training run uses for Path A, Path B and fusion.

Used by train_models.sh (step "Split"). Why one shared split:
  - The fusion (stacker) must be fitted on rows that neither Path A nor Path B trained on
    (Wolpert 1992; scikit-learn StackingClassifier). Separate per-model splits break that.
  - A chronological split avoids temporal snooping in security data (Arp et al. 2022;
    Pendlebury et al. 2019, TESSERACT).
  - Keeping the old test rows frozen when data is added keeps runs comparable.

With --base, rows already in the base manifest keep their split; new rows go to train/val
only (never test). Without a usable base, a fresh --strategy split is made.

Usage:
  python3 scripts/prepare_split.py --labeled data/processed/merged_features_labeled.json \
      --base data/processed/splits/time_seed42.json --out models/split_manifest.json
Prints one tab-separated summary line: mode n_train n_val n_test n_new sha256
"""

import argparse
import contextlib
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.models.splits import prepare_training_split, read_manifest, write_manifest  # noqa: E402
from dns_detect.parsing.dns_parser import FEATURES_8, load_as_dataframe  # noqa: E402
from dns_detect.utils.dataset_hash import dataset_hash  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Make the shared train/val/test split for one training run.")
    ap.add_argument("--labeled", required=True, help="labeled JSON the models will train on")
    ap.add_argument("--base", default=None, help="existing manifest to reuse / extend (optional)")
    ap.add_argument("--strategy", default="time", help="strategy for a fresh split (default: time)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--train-share", type=float, default=0.85, help="earliest share of new rows → train")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with contextlib.redirect_stdout(sys.stderr):   # stdout carries only the summary line
        df = load_as_dataframe(args.labeled)
    if "label" not in df.columns:
        sys.exit("[error] labeled file has no 'label' column")
    y = df["label"].astype(int).to_numpy()
    base = read_manifest(args.base) if args.base and os.path.isfile(args.base) else None

    try:
        ids, idx, info = prepare_training_split(df, y, base, args.strategy, args.seed, args.train_share)
    except ValueError as e:
        sys.exit(f"[error] {e}")

    src = os.path.basename(args.base) if base else "-"
    notes = (f"train_models.sh run split; mode={info['mode']}; base={src}; method={info['method']}; "
             f"new rows → train/val only (train_share={args.train_share})")
    written = write_manifest(args.out, info["strategy"] or args.strategy, info["seed"] or args.seed, ids,
                             idx["train"], idx["val"], idx["test"],
                             dataset_version=dataset_hash([args.labeled], FEATURES_8), notes=notes)
    # Fingerprint of the row assignment only (not created_at), so the same split → same hash.
    sha = hashlib.sha256(json.dumps(written["row_ids"], sort_keys=True).encode()).hexdigest()
    print(f"[*] split {info['mode']} (base {src}): train={info['n_train']} val={info['n_val']} "
          f"test={info['n_test']} new_rows={info['n_new']} → {args.out}", file=sys.stderr)
    print("\t".join(str(v) for v in (info["mode"], info["n_train"], info["n_val"], info["n_test"],
                                     info["n_new"], sha)))


if __name__ == "__main__":
    main()
