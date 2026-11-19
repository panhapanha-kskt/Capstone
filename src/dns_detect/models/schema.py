"""
schema.py — Refuse to serve a model whose saved inputs differ from the code (Week 7 Task 8).

Training-serving skew is a named failure mode (Zinkevich, Rules of ML #29–#37), and the
ML Test Score's data tests start with "feature expectations are captured in a schema"
(Breck et al. 2017). The models folder already records its schema; this module compares it
with the live code before anything is scored:

  Path A   dns_threshold.json "features"      == PATH_A_FEATURES (names and order)
  Path B   <name>_norm.json "features"         == PATH_B_FEATURES (names and order)
           <name>_threshold.json "n_features"  == len(PATH_B_FEATURES)
           <name>_threshold.json "window_size" == training.path_b_window_size
           the model file named by "model_type" exists (iforest → _iforest.pkl, else .keras/.h5)
  Fusion   fusion_lr.json "inputs"             == stacker.FUSION_INPUTS (when the file exists)
  All      no identity / time / provenance column (FORBIDDEN_FEATURES)

    python -m dns_detect.models.schema [--models-dir DIR] [--path-b-model NAME] [--warn-only]
exit code 0 = match, 2 = mismatch (1 with --warn-only never happens: it only prints).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


class ModelSchemaError(RuntimeError):
    """The saved model inputs do not match the live feature code."""


def _setting(section: str, name: str, default):
    try:
        from dns_detect.config import settings
        return getattr(getattr(settings, section), name, default)
    except Exception:
        return default


def _default_path_b_name() -> str:
    try:
        from dns_detect.config import settings
        return str(settings.models.path_b.model_name)
    except Exception:
        return "dns_trafficformer"


def _diff(saved, live) -> str:
    saved, live = list(saved or []), list(live)
    missing = [f for f in live if f not in saved]
    extra = [f for f in saved if f not in live]
    if not missing and not extra:
        return "same names, different order"
    parts = []
    if missing:
        parts.append(f"missing {missing}")
    if extra:
        parts.append(f"extra {extra}")
    return ", ".join(parts)


def _read(path: Path):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except ValueError as e:
        raise ModelSchemaError(f"{path.name} is not valid JSON: {e}")


def schema_problems(models_dir=None, path_b_name: str | None = None, check_path_b: bool = True) -> list:
    """All mismatches between the models folder and the live code (empty list = OK)."""
    from dns_detect.parsing.dns_parser import PATH_A_FEATURES, PATH_B_FEATURES, FORBIDDEN_FEATURES
    from dns_detect.utils.paths import MODELS_DIR
    d = Path(models_dir) if models_dir else Path(MODELS_DIR)
    problems = []

    a = _read(d / "dns_threshold.json")
    if a is None:
        problems.append(f"Path A: {d / 'dns_threshold.json'} not found")
    else:
        feats = a.get("features")
        if feats != list(PATH_A_FEATURES):
            problems.append(f"Path A features differ from PATH_A_FEATURES ({_diff(feats, PATH_A_FEATURES)})")
        bad = sorted({str(f).lower() for f in feats or []} & FORBIDDEN_FEATURES)
        if bad:
            problems.append(f"Path A uses identity/time/provenance input(s) {bad}")

    if check_path_b:
        name = path_b_name or _default_path_b_name()
        t = _read(d / f"{name}_threshold.json")
        n = _read(d / f"{name}_norm.json")
        if t is None or n is None:
            problems.append(f"Path B: {name}_threshold.json and {name}_norm.json are required in {d}")
        else:
            feats = n.get("features")
            if feats != list(PATH_B_FEATURES):
                problems.append(f"Path B features differ from PATH_B_FEATURES ({_diff(feats, PATH_B_FEATURES)})")
            bad = sorted({str(f).lower() for f in feats or []} & FORBIDDEN_FEATURES)
            if bad:
                problems.append(f"Path B uses identity/time/provenance input(s) {bad}")
            if t.get("n_features") is not None and int(t["n_features"]) != len(PATH_B_FEATURES):
                problems.append(f"Path B n_features {t['n_features']} != {len(PATH_B_FEATURES)} in the code")
            win = _setting("training", "path_b_window_size", None)
            if win is not None and t.get("window_size") is not None and int(t["window_size"]) != int(win):
                problems.append(f"Path B window_size {t['window_size']} != training.path_b_window_size {win}")
            if t.get("model_type") == "iforest":
                if not (d / f"{name}_iforest.pkl").is_file():
                    problems.append(f"Path B says model_type=iforest but {name}_iforest.pkl is missing")
            elif not any((d / f"{name}{ext}").is_file() for ext in (".keras", ".h5")):
                problems.append(f"Path B model file {name}.keras / .h5 is missing")

    f = _read(d / "fusion_lr.json")
    if f is not None:
        from dns_detect.fusion.stacker import FUSION_INPUTS
        if f.get("inputs") != list(FUSION_INPUTS):
            problems.append(f"Fusion inputs differ from FUSION_INPUTS ({_diff(f.get('inputs'), FUSION_INPUTS)})")
    return problems


def check_model_schema(models_dir=None, path_b_name: str | None = None, check_path_b: bool = True,
                       strict: bool = True) -> list:
    """Raise ModelSchemaError on any mismatch (strict), or print a warning and return the list."""
    problems = schema_problems(models_dir, path_b_name, check_path_b)
    if problems:
        where = models_dir or os.environ.get("DNS_DETECT_MODELS_DIR") or "models/"
        msg = (f"Model schema check failed for {where}:\n  - " + "\n  - ".join(problems)
               + "\nThe saved model was trained with different inputs than this code computes; "
                 "retrain or restore the matching code. Nothing was scored.")
        if strict:
            raise ModelSchemaError(msg)
        print(f"[warn] {msg}", file=sys.stderr)
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check that a models folder matches the live feature code.")
    ap.add_argument("--models-dir", default=None, help="default: DNS_DETECT_MODELS_DIR or models/")
    ap.add_argument("--path-b-model", default=None, help="Path B save name (default: settings models.path_b)")
    ap.add_argument("--no-path-b", action="store_true", help="skip the Path B checks")
    ap.add_argument("--warn-only", action="store_true", help="print problems but exit 0")
    a = ap.parse_args(argv)
    try:
        problems = check_model_schema(a.models_dir, a.path_b_model, not a.no_path_b, strict=not a.warn_only)
    except ModelSchemaError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 2
    print("✓ model schema matches the code" if not problems else "! model schema problems (warn-only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
