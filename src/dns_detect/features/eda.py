#!/usr/bin/env python3
"""
eda.py — Exploratory Data Analysis (the "data analysis" stage)

Sits between MERGE and LABELING in the training pipeline. It does NOT
modify the data; it only profiles the merged feature set so problems are
caught before training:
  - record count and per-feature missing-value rates
  - class balance (from attack_count, the pre-label signal)
  - per-feature summary statistics (mean / std / min / max / quantiles)
  - pairwise correlation between the 8 model features
  - obvious red flags (constant features, extreme imbalance, all-NaN cols)

Writes a JSON report and prints a human-readable summary. A non-zero exit
is never raised for "bad" data — EDA informs, it does not gate.

Usage:
  python -m dns_detect.features.eda --input data/processed/merged_features_all.json
  python -m dns_detect.features.eda --input merged.json --output eda_report.json
"""

import os
import json
import argparse
import numpy as np
import pandas as pd

from dns_detect.parsing.dns_parser import load_as_dataframe, FEATURES_8


def _load(input_path: str) -> pd.DataFrame:
    if input_path.endswith(".json"):
        try:
            return load_as_dataframe(input_path)
        except Exception:
            with open(input_path) as f:
                data = json.load(f)
            return pd.DataFrame(data if isinstance(data, list) else [data])
    return pd.read_csv(input_path)


def run_eda(input_path: str, output_path: str = None) -> dict:
    print("\n" + "=" * 70)
    print("EXPLORATORY DATA ANALYSIS")
    print("=" * 70)
    print(f"Input: {input_path}")

    df = _load(input_path)
    n = len(df)
    print(f"\n[*] Records: {n}")
    print(f"[*] Columns: {len(df.columns)}")

    report = {
        "input": input_path,
        "n_records": int(n),
        "n_columns": int(len(df.columns)),
        "features": {},
        "missing": {},
        "class_balance": {},
        "correlation": {},
        "warnings": [],
    }

    if n == 0:
        report["warnings"].append("Dataset is empty.")
        print("\n⚠ Empty dataset — nothing to analyse.")
        _save(report, output_path)
        return report

    # ── Class balance (pre-label signal) ──────────────────────────
    if "attack_count" in df.columns:
        ac = pd.to_numeric(df["attack_count"], errors="coerce").fillna(0)
        attack = int((ac >= 1).sum())
        benign = int((ac == 0).sum())
        rate = attack / max(n, 1)
        report["class_balance"] = {
            "attack": attack, "benign": benign, "attack_rate": round(rate, 4)
        }
        print(f"\n── Class balance (from attack_count) ─────────────────")
        print(f"   attack = {attack}  |  benign = {benign}  |  attack rate = {rate*100:.1f}%")
        if rate < 0.01:
            report["warnings"].append(f"Severe class imbalance: attack rate {rate*100:.2f}%.")
        elif rate > 0.6:
            report["warnings"].append(
                f"Attack rate {rate*100:.1f}% is very high — verify the data is not attack-dominated."
            )
    else:
        print("\n⚠ No 'attack_count' column — class balance unknown until labeling.")
        report["warnings"].append("No attack_count column for class-balance estimate.")

    # ── Missing values ────────────────────────────────────────────
    print(f"\n── Missing values (model features) ───────────────────")
    for col in FEATURES_8:
        if col not in df.columns:
            report["missing"][col] = {"present": False, "missing_rate": 1.0}
            report["warnings"].append(f"Feature '{col}' is absent — will be zero-filled.")
            print(f"   {col:<22}: ABSENT (zero-filled at train time)")
            continue
        series = pd.to_numeric(df[col], errors="coerce")
        miss = float(series.isna().mean())
        report["missing"][col] = {"present": True, "missing_rate": round(miss, 4)}
        if miss > 0:
            print(f"   {col:<22}: {miss*100:.1f}% missing")

    # ── Per-feature statistics ────────────────────────────────────
    print(f"\n── Feature statistics ────────────────────────────────")
    print(f"   {'feature':<22}{'mean':>10}{'std':>10}{'min':>10}{'max':>10}")
    present = [c for c in FEATURES_8 if c in df.columns]
    for col in present:
        s = pd.to_numeric(df[col], errors="coerce").dropna()
        if len(s) == 0:
            report["features"][col] = None
            continue
        stats = {
            "mean": float(s.mean()), "std": float(s.std()),
            "min": float(s.min()), "max": float(s.max()),
            "p25": float(s.quantile(0.25)), "p50": float(s.quantile(0.50)),
            "p75": float(s.quantile(0.75)),
        }
        report["features"][col] = {k: round(v, 4) for k, v in stats.items()}
        print(f"   {col:<22}{stats['mean']:>10.3f}{stats['std']:>10.3f}"
              f"{stats['min']:>10.3f}{stats['max']:>10.3f}")
        if stats["std"] == 0:
            report["warnings"].append(f"Feature '{col}' is constant (std=0) — no signal.")

    # ── Correlation matrix ────────────────────────────────────────
    if len(present) >= 2:
        num = df[present].apply(pd.to_numeric, errors="coerce")
        corr = num.corr().round(3)
        report["correlation"] = corr.where(pd.notna(corr), None).to_dict()
        # Flag strongly correlated pairs (possible redundancy)
        print(f"\n── Highly correlated feature pairs (|r| > 0.9) ───────")
        flagged = False
        for i, a in enumerate(present):
            for b in present[i + 1:]:
                r = corr.loc[a, b]
                if pd.notna(r) and abs(r) > 0.9:
                    flagged = True
                    print(f"   {a} ~ {b}: r = {r:.2f}")
                    report["warnings"].append(f"'{a}' and '{b}' highly correlated (r={r:.2f}).")
        if not flagged:
            print("   none")

    # ── Summary ───────────────────────────────────────────────────
    print(f"\n── Warnings ──────────────────────────────────────────")
    if report["warnings"]:
        for w in report["warnings"]:
            print(f"   ⚠ {w}")
    else:
        print("   ✅ none")

    _save(report, output_path)
    return report


def _save(report: dict, output_path: str):
    if not output_path:
        return
    d = os.path.dirname(output_path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n✅ EDA report saved → {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="EDA — profile the merged DNS feature set before training."
    )
    parser.add_argument("--input", "-i", required=True, help="Merged features JSON/CSV")
    parser.add_argument("--output", "-o", default=None, help="Where to write the JSON report")
    args = parser.parse_args()
    run_eda(args.input, args.output)


if __name__ == "__main__":
    main()
