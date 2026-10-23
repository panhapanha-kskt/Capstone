#!/usr/bin/env python3
"""
monitor.py — Post-deployment monitoring & retrain trigger

The last two stages of the detection pipeline: once models are deployed and
scoring live traffic, we must watch for the conditions that quietly erode a
detector's accuracy and decide when a retrain is warranted.

It checks three things against the training baseline (models/training_metadata.json):

  1. DATA DRIFT    — do live feature distributions still match training?
                     Uses Population Stability Index (PSI) per feature.
  2. ALERT VOLUME  — is the live alert rate wildly different from expected?
                     A sudden spike or collapse often means drift or breakage.
  3. SCORE HEALTH  — are ML scores saturating (all ~0 or all ~1)? That signals
                     a miscalibrated or stale model.

PSI interpretation (industry convention):
  < 0.1  : no significant shift
  0.1–0.25 : moderate shift — monitor
  > 0.25 : major shift — retrain recommended

Exit code is always 0; the retrain recommendation is in the report and the
printed summary so an operator (or a cron job reading the JSON) decides.

Usage:
  python -m dns_detect.monitoring.monitor \
      --live   data/week3_features_with_ml.json \
      --alerts data/week4_unified_alerts.json \
      --output data/monitoring_report.json
"""

import os
import json
import argparse
import numpy as np
import pandas as pd

from dns_detect.parsing.dns_parser import FEATURES_8
from dns_detect.utils.paths import PROJECT_ROOT

PSI_MODERATE = 0.10
PSI_MAJOR = 0.25


def _population_stability_index(expected: np.ndarray,
                                actual: np.ndarray,
                                bins: int = 10) -> float:
    """
    PSI between a reference (expected) and a live (actual) distribution.
    Bins are quantile edges from the reference so each reference bucket holds
    ~equal mass. Returns a single non-negative float.
    """
    expected = expected[np.isfinite(expected)]
    actual = actual[np.isfinite(actual)]
    if len(expected) == 0 or len(actual) == 0:
        return 0.0

    edges = np.quantile(expected, np.linspace(0, 1, bins + 1))
    edges = np.unique(edges)
    if len(edges) < 3:  # near-constant reference — PSI undefined, treat as no shift
        return 0.0
    edges[0], edges[-1] = -np.inf, np.inf

    e_counts, _ = np.histogram(expected, bins=edges)
    a_counts, _ = np.histogram(actual, bins=edges)

    e_pct = e_counts / max(e_counts.sum(), 1)
    a_pct = a_counts / max(a_counts.sum(), 1)

    eps = 1e-6
    e_pct = np.clip(e_pct, eps, None)
    a_pct = np.clip(a_pct, eps, None)

    return float(np.sum((a_pct - e_pct) * np.log(a_pct / e_pct)))


def _load_df(path: str) -> pd.DataFrame:
    if path.endswith(".json"):
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict) and "alerts" in data:
            return pd.DataFrame(data["alerts"])
        return pd.DataFrame(data if isinstance(data, list) else [data])
    return pd.read_csv(path)


def _load_training_baseline() -> dict:
    meta_path = PROJECT_ROOT / "models" / "training_metadata.json"
    if not meta_path.exists():
        return {}
    try:
        with open(meta_path) as f:
            return json.load(f)
    except Exception:
        return {}


def run_monitor(live_path: str,
                alerts_path: str = None,
                output_path: str = None) -> dict:
    print("\n" + "=" * 70)
    print("POST-DEPLOYMENT MONITORING")
    print("=" * 70)

    meta = _load_training_baseline()
    snapshot = meta.get("feature_snapshot", {})
    report = {
        "live_input": live_path,
        "trained_on": meta.get("last_trained", "unknown"),
        "drift": {},
        "alert_volume": {},
        "score_health": {},
        "retrain_recommended": False,
        "reasons": [],
    }

    live = _load_df(live_path)
    n = len(live)
    print(f"[*] Live records: {n}")
    print(f"[*] Models trained: {report['trained_on']}")

    if n == 0:
        report["reasons"].append("No live records to evaluate.")
        _save(report, output_path)
        return report

    # ── 1. DATA DRIFT (PSI per feature) ───────────────────────────
    print(f"\n── Data drift (PSI vs training baseline) ─────────────")
    if not snapshot:
        print("   ⚠ No training feature_snapshot found — run train_models.sh to enable drift checks.")
        report["reasons"].append("No training baseline snapshot available.")
    else:
        for col in FEATURES_8:
            if col not in live.columns or col not in snapshot:
                continue
            ref = snapshot[col]
            # Reconstruct an approximate reference distribution from the saved
            # summary stats (mean/std) — a normal proxy, since raw training
            # values are not retained. PSI is robust to this approximation.
            ref_mean = ref.get("mean", 0.0)
            ref_std = ref.get("stdev", 0.0) or 1.0
            rng = np.random.default_rng(42)
            ref_sample = rng.normal(ref_mean, ref_std, size=max(n, 1000))
            live_vals = pd.to_numeric(live[col], errors="coerce").to_numpy(dtype=float)

            psi = _population_stability_index(ref_sample, live_vals)
            band = ("major" if psi > PSI_MAJOR else
                    "moderate" if psi > PSI_MODERATE else "stable")
            report["drift"][col] = {"psi": round(psi, 4), "band": band}
            marker = "🔴" if band == "major" else ("🟡" if band == "moderate" else "🟢")
            print(f"   {marker} {col:<22}: PSI = {psi:.3f}  ({band})")
            if band == "major":
                report["retrain_recommended"] = True
                report["reasons"].append(f"Major drift in '{col}' (PSI={psi:.2f}).")

    # ── 2. ALERT VOLUME ───────────────────────────────────────────
    if alerts_path and os.path.exists(alerts_path):
        alerts = _load_df(alerts_path)
        n_alerts = len(alerts)
        alert_rate = n_alerts / max(n, 1)
        report["alert_volume"] = {
            "n_alerts": int(n_alerts),
            "alert_rate": round(alert_rate, 4),
        }
        print(f"\n── Alert volume ──────────────────────────────────────")
        print(f"   alerts = {n_alerts}  |  alert rate = {alert_rate*100:.1f}% of live queries")
        if alert_rate > 0.5:
            report["retrain_recommended"] = True
            report["reasons"].append(
                f"Alert rate {alert_rate*100:.0f}% is implausibly high — likely drift or misconfiguration."
            )
        elif n_alerts == 0:
            report["reasons"].append("Zero alerts on live traffic — verify the detector is still firing.")

    # ── 3. SCORE HEALTH ───────────────────────────────────────────
    score_col = next((c for c in ("ml_combined_score", "ml_score_A") if c in live.columns), None)
    if score_col:
        scores = pd.to_numeric(live[score_col], errors="coerce").dropna()
        if len(scores) > 0:
            mean = float(scores.mean())
            frac_hi = float((scores > 0.95).mean())
            frac_lo = float((scores < 0.05).mean())
            report["score_health"] = {
                "column": score_col,
                "mean": round(mean, 4),
                "frac_saturated_high": round(frac_hi, 4),
                "frac_saturated_low": round(frac_lo, 4),
            }
            print(f"\n── Score health ({score_col}) ───────────────────────")
            print(f"   mean = {mean:.3f}  |  >0.95: {frac_hi*100:.1f}%  |  <0.05: {frac_lo*100:.1f}%")
            if frac_hi > 0.9 or frac_lo > 0.99:
                report["retrain_recommended"] = True
                report["reasons"].append(
                    "ML scores are saturated — model is no longer discriminating; recalibrate/retrain."
                )

    # ── VERDICT ───────────────────────────────────────────────────
    print(f"\n── Retrain trigger ───────────────────────────────────")
    if report["retrain_recommended"]:
        print("   🔴 RETRAIN RECOMMENDED")
        for r in report["reasons"]:
            print(f"      - {r}")
        print("\n   Run: ./scripts/train_models.sh --retrain")
    else:
        print("   🟢 Models healthy — no retrain needed.")
        if report["reasons"]:
            for r in report["reasons"]:
                print(f"      note: {r}")

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
    print(f"\n✅ Monitoring report saved → {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Post-deployment monitoring & retrain trigger for the DNS detector."
    )
    parser.add_argument("--live", "-l", required=True,
                        help="Live scored features (ml_bridge output JSON/CSV)")
    parser.add_argument("--alerts", "-a", default=None,
                        help="Detection engine alerts JSON (optional)")
    parser.add_argument("--output", "-o", default=None,
                        help="Where to write the monitoring report JSON")
    args = parser.parse_args()
    run_monitor(args.live, args.alerts, args.output)


if __name__ == "__main__":
    main()
