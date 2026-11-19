#!/usr/bin/env python3
"""
smoke_models.py — Check that a models folder loads and scores like the run it came from.

    python3 scripts/smoke_models.py --models models --reference runs/v3_iforest [--rows 5000]

1. Path B: the threshold file says Isolation Forest, its features equal the live
   PATH_B_FEATURES (same names, same order), and the scores of a fixed sample from the
   reference run's data match the reference folder's scores exactly (float tolerance).
2. Path A: the same check for the saved feature list and the sample's scores.
Exit code 0 = pass. Reads only; writes nothing.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def _child(kind, rows, out):
    if kind == "b":
        from dns_detect.models.path_b_predict import score_records
        s, a, cov, thr = score_records(rows, "dns_trafficformer")
        np.save(out, np.c_[s, a, cov])
    else:
        from dns_detect.parsing.dns_parser import load_as_dataframe
        from dns_detect.models.path_a import score_frame
        s, p, thr, dec = score_frame(load_as_dataframe(rows))
        np.save(out, np.c_[s, p])


def score(models_dir, kind, rows, tmp):
    out = Path(tmp) / f"{kind}_{abs(hash(models_dir))}.npy"
    env = {**os.environ, "DNS_DETECT_MODELS_DIR": str(Path(models_dir).resolve()),
           "PYTHONPATH": str(ROOT / "src")}
    r = subprocess.run([sys.executable, __file__, "--_child", kind, rows, str(out)],
                       env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{kind} scoring with {models_dir} failed: "
                           f"{(r.stderr or r.stdout).strip().splitlines()[-1:]}")
    return np.load(out)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--_child":
        return _child(*sys.argv[2:5])
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="models")
    ap.add_argument("--reference", required=True)
    ap.add_argument("--data", help="records to score (default: <reference>/merged_labeled.json)")
    ap.add_argument("--rows", type=int, default=5000)
    ap.add_argument("--skip-path-a", action="store_true", help="Path B only (Path A needs TensorFlow)")
    a = ap.parse_args()

    from dns_detect.parsing.dns_parser import PATH_B_FEATURES, PATH_A_FEATURES
    ok = True
    m = Path(a.models)
    tb = json.loads((m / "dns_trafficformer_threshold.json").read_text())
    nb = json.loads((m / "dns_trafficformer_norm.json").read_text())
    ta = json.loads((m / "dns_threshold.json").read_text())
    checks = [
        ("Path B model type is iforest", tb.get("model_type") == "iforest"),
        ("Path B features = live PATH_B_FEATURES (names and order)", nb.get("features") == PATH_B_FEATURES),
        ("Path B n_features matches", tb.get("n_features") == len(PATH_B_FEATURES)),
        ("Path A features = live PATH_A_FEATURES (names and order)", ta.get("features") == PATH_A_FEATURES),
        ("Isolation Forest file present", (m / "dns_trafficformer_iforest.pkl").is_file()),
    ]
    for name, good in checks:
        print(f"  [{'PASS' if good else 'FAIL'}] {name}")
        ok &= bool(good)

    data = a.data or str(Path(a.reference) / "merged_labeled.json")
    rows = json.loads(Path(data).read_text())[: a.rows]
    with tempfile.TemporaryDirectory() as tmp:
        sample = str(Path(tmp) / "sample.json")
        Path(sample).write_text(json.dumps(rows))
        kinds = ["b"] + ([] if a.skip_path_a else ["a"])
        for kind in kinds:
            x, y = score(a.models, kind, sample, tmp), score(a.reference, kind, sample, tmp)
            same = x.shape == y.shape and np.allclose(x, y, rtol=0, atol=1e-9)
            label = "Path B" if kind == "b" else "Path A"
            extra = f", {int(x[:, 1].sum())} alarms" if len(x) else ""
            print(f"  [{'PASS' if same else 'FAIL'}] {label} scores on {len(rows)} rows match {a.reference}{extra}")
            ok &= same
    print("SMOKE TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
