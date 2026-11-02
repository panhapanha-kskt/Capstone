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
  python scripts/make_evasion_set.py --evaluate --mix-benign data/external/cic/cic_benign_test.json
                                     # same, with each tunnel hidden inside benign traffic
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
from dns_detect.utils.paths import MODELS_DIR  # noqa: E402

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


def mix_with_benign(attack: pd.DataFrame, benign: pd.DataFrame) -> pd.DataFrame:
    """Put a benign client's traffic on the same client and time span as each tunnel.

    In isolation every window holds tunnel queries only. On a real machine the tunnel runs
    next to normal browsing, which dilutes client-level features (queries per minute,
    NXDOMAIN share). For each tunnel client, the benign rows are shifted onto the tunnel's
    start time, repeated if the tunnel runs longer, and given the tunnel's client_ip.
    Returns attack + benign rows; `mixed_benign` marks the added benign rows.
    """
    b_ts = pd.to_datetime(benign["timestamp"], errors="coerce", format="mixed").dt.tz_localize(None)
    benign = benign.assign(_t=b_ts).dropna(subset=["_t"]).sort_values("_t", kind="stable")
    b_off = (benign["_t"] - benign["_t"].iloc[0]).to_numpy()
    b_span = b_off[-1] + np.timedelta64(1, "s")
    a_ts = pd.to_datetime(attack["timestamp"], errors="coerce", format="mixed").dt.tz_localize(None)
    parts = [attack.assign(mixed_benign=False)]
    for client, idx in attack.groupby("client_ip").groups.items():
        t0, t1 = a_ts.loc[idx].min(), a_ts.loc[idx].max()
        if pd.isna(t0):
            continue
        k = 0
        while t0 + k * b_span <= t1:
            start = t0 + k * b_span
            ts = start + b_off
            keep = ts <= t1
            part = benign.loc[keep].drop(columns="_t").copy()
            part["timestamp"] = [t.isoformat() for t in pd.DatetimeIndex(ts[keep])]
            part["client_ip"] = client
            part["label"] = 0
            part["mixed_benign"] = True
            parts.append(part)
            k += 1
    return pd.concat(parts, ignore_index=True)


def evaluate(out_dir: str, path_b_model: str = "dns_trafficformer", mix_benign: str = None) -> dict:
    """Recall of the saved Path A and Path B on the test half of every variant.

    With mix_benign (a benign JSON never trained on, e.g. CIC capture 3), each variant is
    scored together with that benign traffic on the same client, and the false-alarm rate
    on those benign rows is reported as well.
    """
    import tempfile
    from dns_detect.parsing.dns_parser import load_as_dataframe
    from dns_detect.models.path_a import score_frame
    results = {}
    try:
        from dns_detect.models.path_b_predict import score_records
    except Exception:
        score_records = None
    benign = load_as_dataframe(mix_benign) if mix_benign else None
    print(f"\n   {'variant':14s} {'rows':>6s} {'Path A recall':>14s} {'Path B recall':>14s}"
          + (f" {'A benign FPR':>13s} {'B benign FPR':>13s}" if mix_benign else ""))
    for variant in VARIANTS:
        path = os.path.join(out_dir, f"{variant}.json")
        if not os.path.exists(path):
            continue
        df = load_as_dataframe(path)
        tmp = None
        if benign is not None:
            df = mix_with_benign(df, benign)
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                json.dump(df.to_dict(orient="records"), f, default=str)
                tmp = path = f.name
        test = (df["evasion_split"] == "test").to_numpy()
        added = df["mixed_benign"].to_numpy(dtype=bool) if benign is not None else np.zeros(len(df), bool)
        _, pred_a, _, _ = score_frame(df)
        row = {"rows": int(test.sum()), "path_a_recall": float(pred_a[test].mean())}
        if added.any():
            row["benign_rows"] = int(added.sum())
            row["path_a_benign_fpr"] = float(pred_a[added].mean())
        if score_records is not None:
            try:
                _, pred_b, covered, _ = score_records(path, path_b_model)
                m = test & covered
                row["path_b_recall"] = float(pred_b[m].mean()) if m.any() else None
                row["path_b_covered"] = float(covered[test].mean())
                if added.any() and (added & covered).any():
                    row["path_b_benign_fpr"] = float(pred_b[added & covered].mean())
            except Exception as e:
                row["path_b_error"] = str(e)
        if tmp:
            os.unlink(tmp)
        results[variant] = row
        pb = row.get("path_b_recall")
        line = (f"   {variant:14s} {row['rows']:6d} {row['path_a_recall']:14.3f} "
                f"{(f'{pb:.3f}' if pb is not None else '-'):>14s}")
        if added.any():
            fb = row.get("path_b_benign_fpr")
            line += f" {row['path_a_benign_fpr']:13.4f} {(f'{fb:.4f}' if fb is not None else '-'):>13s}"
        print(line)
    return results


def main():
    ap = argparse.ArgumentParser(description="Build and score DNS-tunnel evasion variants")
    ap.add_argument("--input", default="data/processed/merged_features_labeled.json")
    ap.add_argument("--out-dir", default="data/processed/evasion")
    ap.add_argument("--evaluate", action="store_true", help="score saved Path A / Path B on the test halves")
    ap.add_argument("--path-b-model", default="dns_trafficformer")
    ap.add_argument("--mix-benign", default=None, metavar="FILE",
                    help="with --evaluate: score each variant mixed with this benign traffic "
                         "(use data never trained on, e.g. data/external/cic/cic_benign_test.json)")
    args = ap.parse_args()

    if args.evaluate:
        res = evaluate(args.out_dir, args.path_b_model, args.mix_benign)
        key = "evasion_mixed" if args.mix_benign else "evasion"
        mpath = MODELS_DIR / "evaluation_metrics.json"
        try:
            allm = json.loads(mpath.read_text())
        except Exception:
            allm = {}
        allm[key] = res
        mpath.write_text(json.dumps(allm, indent=2))
        print(f"\n[+] Evasion recall → {mpath} (key: {key})")
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
