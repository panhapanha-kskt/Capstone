#!/usr/bin/env python3
"""
make_evasion_set.py — Evasion variants of real tunnel traffic (ML_IMPROVEMENT_GUIDE Step 8).

Takes the labeled attack queries and rewrites them the way an evasive tunnel would, then
recomputes every per-query feature. Window features are recomputed when the records are
scored, so slowing a tunnel down or spreading it over domains changes them as it would live.

  slow          same queries over 10× the time
  short_labels  payload re-split into labels of at most 15 characters
  low_entropy   payload characters mapped to dictionary words
  hex           payload hex-encoded
  spread        queries rotated across 5 registrable domains
  a_aaaa        A / AAAA queries instead of TXT / KEY / NULL

Each variant is cut in time per capture: the first half is marked `evasion_split = "train"`
(may be added to training data), the second half `"test"` (never trained on).

Usage:
  python scripts/make_evasion_set.py --input data/processed/merged_features_labeled.json \
      --out-dir data/processed/evasion
  python scripts/make_evasion_set.py --evaluate --out-dir data/processed/evasion   # score saved models
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dns_detect.ingest.labeling import parent_domain, subdomain_part  # noqa: E402
from dns_detect.parsing.dns_parser import compute_entropy  # noqa: E402

VARIANTS = ("original", "slow", "short_labels", "low_entropy", "hex", "spread", "a_aaaa")
WORDS = ("time", "home", "news", "mail", "shop", "blog", "game", "cloud", "photo", "video", "music", "store",
         "world", "local", "sport", "food", "travel", "media", "data", "info", "help", "live", "team", "book",
         "city", "star", "blue", "green", "smart", "fast", "open", "free", "best", "your", "play", "work",
         "life", "art", "map", "car", "box", "web", "app", "net", "code", "link", "park", "case", "line",
         "road", "page", "site", "zone", "list", "club", "deal", "plan", "talk", "view", "card", "hub", "kit",
         "lab", "pro")
MAX_LABEL = 63
MAX_NAME = 253


def _labels(text: str, size: int) -> list:
    return [text[i:i + size] for i in range(0, len(text), size)] or ["x"]


def _build(sub_labels: list, parent: str) -> str:
    name = ".".join(sub_labels + [parent])
    while len(name) > MAX_NAME and len(sub_labels) > 1:   # DNS name length limit
        sub_labels = sub_labels[:-1]
        name = ".".join(sub_labels + [parent])
    return name


def _rewrite(domain: str, variant: str, i: int) -> str:
    d = str(domain).lower().rstrip(".")
    parent = parent_domain(d)
    payload = subdomain_part(d, parent).replace(".", "")
    if variant in ("original", "slow", "a_aaaa"):
        return d
    if variant == "short_labels":
        return _build(_labels(payload, 15), parent)
    if variant == "hex":
        return _build(_labels(payload.encode().hex(), MAX_LABEL), parent)
    if variant == "low_entropy":
        words = "".join(WORDS[ord(c) % len(WORDS)] for c in payload)
        return _build(_labels(words, MAX_LABEL), parent)
    if variant == "spread":
        sld, _, tld = parent.partition(".")
        return _build(_labels(payload, MAX_LABEL), f"{sld}{i % 5}.{tld}" if tld else f"{sld}{i % 5}")
    raise ValueError(variant)


def _refresh_features(r: dict) -> dict:
    d = r["domain"]
    labels = [p for p in d.split(".") if p]
    r["query_length"] = len(d)
    r["entropy"] = round(compute_entropy(d), 6)
    r["subdomain_depth"] = d.count(".")
    r["numeric_ratio"] = round(sum(c.isdigit() for c in d) / max(len(d), 1), 6)
    r["num_labels"] = len(labels)
    r["first_label"] = labels[0] if labels else ""
    r["first_label_length"] = len(labels[0]) if labels else 0
    r["first_label_entropy"] = round(compute_entropy(labels[0]), 6) if labels else 0.0
    for k in ("has_digits", "unique_char_ratio", "longest_label", "query_entropy", "digit_ratio",
              "subdomain_count", "dup_key", "parent_domain"):
        r.pop(k, None)   # derived again from `domain` when loaded
    return r


def generate(records: list) -> list:
    attacks = [r for r in records if str(r.get("label")) in ("1", "1.0")]
    out = []
    by_src: dict = {}
    for r in attacks:
        by_src.setdefault(r.get("source_file", "?"), []).append(r)
    for src, rows in by_src.items():
        ts = pd.to_datetime(pd.Series([r.get("timestamp") for r in rows]), errors="coerce", utc=True, format="mixed")
        order = np.argsort(ts.to_numpy(), kind="stable")
        t0 = ts.min()
        half = len(rows) // 2
        for variant in VARIANTS:
            for rank, j in enumerate(order):
                r = dict(rows[j])
                r["domain"] = _rewrite(r["domain"], variant, rank)
                if variant == "slow" and pd.notna(ts.iloc[j]):
                    r["timestamp"] = (t0 + (ts.iloc[j] - t0) * 10).tz_convert(None).isoformat()
                if variant == "a_aaaa":
                    r["query_type"] = "A" if rank % 2 == 0 else "AAAA"
                r = _refresh_features(r)
                r["evasion_variant"] = variant
                r["evasion_split"] = "train" if rank < half else "test"
                r["attack_family"] = f"{r.get('attack_family', 'attack')}+{variant}"
                # Separate client per variant so variants never share windows with each other.
                r["client_ip"] = f"{r.get('client_ip', '?')}#{variant}"
                out.append(r)
    return out


def evaluate(out_dir: str, path_b_model: str = "dns_trafficformer") -> dict:
    """Recall of the saved Path A and Path B on the test half of every variant."""
    from dns_detect.parsing.dns_parser import load_as_dataframe
    from dns_detect.models.path_a import score_frame
    results = {}
    try:
        from dns_detect.models.path_b_predict import score_records
    except Exception:
        score_records = None
    print(f"\n   {'variant':14s} {'rows':>6s} {'Path A recall':>14s} {'Path B recall':>14s}")
    for variant in VARIANTS:
        path = os.path.join(out_dir, f"{variant}.json")
        if not os.path.exists(path):
            continue
        df = load_as_dataframe(path)
        test = (df["evasion_split"] == "test").to_numpy()
        _, pred_a, _, _ = score_frame(df)
        row = {"rows": int(test.sum()), "path_a_recall": float(pred_a[test].mean())}
        if score_records is not None:
            try:
                _, pred_b, covered, _ = score_records(path, path_b_model)
                m = test & covered
                row["path_b_recall"] = float(pred_b[m].mean()) if m.any() else None
                row["path_b_covered"] = float(covered[test].mean())
            except Exception as e:
                row["path_b_error"] = str(e)
        results[variant] = row
        pb = row.get("path_b_recall")
        print(f"   {variant:14s} {row['rows']:6d} {row['path_a_recall']:14.3f} "
              f"{(f'{pb:.3f}' if pb is not None else '-'):>14s}")
    return results


def main():
    ap = argparse.ArgumentParser(description="Build and score DNS-tunnel evasion variants")
    ap.add_argument("--input", default="data/processed/merged_features_labeled.json")
    ap.add_argument("--out-dir", default="data/processed/evasion")
    ap.add_argument("--evaluate", action="store_true", help="score saved Path A / Path B on the test halves")
    ap.add_argument("--path-b-model", default="dns_trafficformer")
    args = ap.parse_args()

    if args.evaluate:
        res = evaluate(args.out_dir, args.path_b_model)
        mpath = ROOT / "models" / "evaluation_metrics.json"
        try:
            allm = json.loads(mpath.read_text())
        except Exception:
            allm = {}
        allm["evasion"] = res
        mpath.write_text(json.dumps(allm, indent=2))
        print(f"\n[+] Evasion recall → {mpath} (key: evasion)")
        return

    with open(args.input, encoding="utf-8") as f:
        records = json.load(f)
    rows = generate(records)
    os.makedirs(args.out_dir, exist_ok=True)
    counts = Counter(r["evasion_variant"] for r in rows)
    for variant in VARIANTS:
        part = [r for r in rows if r["evasion_variant"] == variant]
        with open(os.path.join(args.out_dir, f"{variant}.json"), "w", encoding="utf-8") as f:
            json.dump(part, f, default=str)
    train = [r for r in rows if r["evasion_split"] == "train" and r["evasion_variant"] != "original"]
    with open(os.path.join(args.out_dir, "evasion_train.json"), "w", encoding="utf-8") as f:
        json.dump(train, f, default=str)
    print(f"[+] {len(rows)} rows in {len(counts)} variants → {args.out_dir}/<variant>.json")
    print(f"    training half (all variants except original): {len(train)} rows → {args.out_dir}/evasion_train.json")
    for v in VARIANTS:
        sample = next(r["domain"] for r in rows if r["evasion_variant"] == v)
        print(f"    {v:14s} e.g. {sample[:90]}")


if __name__ == "__main__":
    main()
