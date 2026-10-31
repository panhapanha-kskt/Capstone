#!/usr/bin/env python3
"""
merge.py — Merge all pre-processed feature files into one training table, with safeguards.

Merging sources into one table is normal, but only safe when the merged data stays
traceable and its problems are visible. Besides concatenating the records this module:

  1. Provenance   — every row gets source_file (the ORIGINAL capture/log, not the
                    intermediate JSON), source_type and label_source.
  2. Schema check — per source type: model features missing from the records, and
                    features that are constant in one source type but vary in another
                    (or constant everywhere), e.g. answer_count = 0 in every PCAP row.
  3. Duplicates   — dup_key = hash of the 8 model features (dns_parser.feature_vector_key),
                    the input the model actually sees. Rows are kept (repetition is real
                    traffic frequency); Path A splits by dup_key so copies never sit in
                    both train and test.
  4. Labels       — feature vectors seen with both labels, and whether every source
                    holds only one class (source == label → shortcut risk).

Outputs: the merged JSON (same file as before), training_provenance.json (same format,
plus per-source summary), a merge report JSON, and — only with --registry — the
trained-files registry update.

Usage:
  python -m dns_detect.ingest.merge \
      --input data/processed/labeled_tunnels.json data/processed/extracted_x.json=data/raw/x.log \
      --output data/processed/merged_features_all.json \
      --provenance models/training_provenance.json \
      --report data/processed/merge_report.json \
      [--registry models/trained_files_registry.json]
"""

import argparse
import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from dns_detect.parsing.dns_parser import (
    FEATURES_8, PATH_B_FEATURES, _load_json_records, records_to_feature_frame, feature_vector_key,
)

# Week-3 field names that map to model feature names (same map as dns_parser)
RENAME = {"entropy": "query_entropy", "numeric_ratio": "digit_ratio", "subdomain_depth": "subdomain_count",
          "answer_size": "answer_count", "first_label_length": "longest_label"}
TYPE_BY_EXT = {".log": "log", ".pcap": "pcap", ".pcapng": "pcap", ".cap": "pcap", ".json": "json", ".csv": "csv"}
PROVENANCE_FIELDS = ("source_file", "source_type", "input_file", "label_source", "dup_key")


def _sha256(path: str, short: bool = False) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16] if short else h.hexdigest()


def parse_input(spec: str):
    """'features.json' or 'features.json=original.log' → (path, original or None)."""
    if "=" in spec:
        path, original = spec.split("=", 1)
        return path, original or None
    return spec, None


def _load_csv(path: str) -> list:
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append({k: (float(v) if v and v.replace(".", "", 1).replace("-", "", 1).isdigit() else v)
                         for k, v in row.items()})
    return rows


def _is_label(v) -> bool:
    return v in (0, 1, "0", "1", 0.0, 1.0)


def load_input(path: str, original: str = None):
    """Records of one input file with provenance fields filled in."""
    ext = Path(path).suffix.lower()
    records = _load_csv(path) if ext == ".csv" else _load_json_records(path)
    records = [r for r in records if isinstance(r, dict)]
    fallback_source = os.path.basename(original) if original else os.path.basename(path)
    out = []
    for r in records:
        r = dict(r)
        # Keep a source_file that make_labeled_features.py already recorded (the capture it came from)
        src = r.get("source_file") or fallback_source
        r["source_file"] = src
        r["source_type"] = TYPE_BY_EXT.get(Path(src).suffix.lower(), TYPE_BY_EXT.get(ext, ext.lstrip(".")))
        r["input_file"] = os.path.basename(path)
        if _is_label(r.get("label")):
            r["label"] = int(float(r["label"]))
            r.setdefault("label_source", "file")
        else:
            r.pop("label", None)
            r["label_source"] = r.get("label_source") or "none"
        out.append(r)
    return out


def _present_features(records: list) -> set:
    """Model-feature names present in raw records (after the Week-3 rename); derived ones count when 'domain' exists."""
    keys = set()
    for r in records[:200]:
        keys.update(RENAME.get(k, k) for k in r)
    if "domain" in keys or "query" in keys:
        keys.update({"longest_label", "has_digits", "unique_char_ratio", "query_length", "query_entropy",
                     "subdomain_count", "digit_ratio"})
    return keys


def build_report(records: list, feats: pd.DataFrame, inputs: list) -> dict:
    df = feats.copy()
    df["source_file"] = [r["source_file"] for r in records]
    df["source_type"] = [r["source_type"] for r in records]
    df["label"] = [r.get("label") for r in records]
    df["dup_key"] = [r["dup_key"] for r in records]
    n = len(df)
    warnings = []

    # ── duplicates ────────────────────────────────────────────
    sizes = df["dup_key"].value_counts()
    dup_rows = int(sizes[sizes > 1].sum())
    vec_sources = df.groupby("dup_key")["source_file"].nunique()
    query_cols = [c for c in ("domain", "timestamp", "client_ip", "query_type") if all(c in r for r in records[:50])]
    exact_dup_queries = 0
    if query_cols:
        q = pd.DataFrame([{c: r.get(c) for c in query_cols} for r in records])
        exact_dup_queries = int(q.duplicated().sum())
    duplicates = {
        "distinct_feature_vectors": int(sizes.size),
        "rows_in_duplicated_vectors": dup_rows,
        "duplicated_share": round(dup_rows / n, 4) if n else 0.0,
        "vectors_shared_across_sources": int((vec_sources > 1).sum()),
        "exact_duplicate_queries": exact_dup_queries,
        "largest_groups": [{"dup_key": k, "rows": int(v)} for k, v in sizes.head(5).items()],
    }
    if n and dup_rows / n > 0.5:
        warnings.append(f"{dup_rows / n:.0%} of rows repeat another row's exact feature vector "
                        f"({sizes.size} distinct of {n}) — split by feature vector, not by row.")

    # ── labels ────────────────────────────────────────────────
    lab = df[df["label"].notna()]
    per_source = []
    for src, g in df.groupby("source_file", sort=True):
        gl = g[g["label"].notna()]
        per_source.append({"source_file": src, "source_type": g["source_type"].iloc[0], "rows": int(len(g)),
                           "labeled_rows": int(len(gl)), "attack": int((gl["label"] == 1).sum()),
                           "benign": int((gl["label"] == 0).sum())})
    conflicts = lab.groupby("dup_key")["label"].nunique()
    conflict_keys = set(conflicts[conflicts > 1].index)
    labels = {
        "labeled_rows": int(len(lab)),
        "unlabeled_rows": int(n - len(lab)),
        "attack": int((lab["label"] == 1).sum()),
        "benign": int((lab["label"] == 0).sum()),
        "conflicting_vectors": len(conflict_keys),
        "rows_in_conflicting_vectors": int(lab["dup_key"].isin(conflict_keys).sum()),
    }
    if conflict_keys:
        warnings.append(f"{len(conflict_keys)} feature vector(s) appear with both labels "
                        f"({labels['rows_in_conflicting_vectors']} rows) — Path A drops them before training.")
    labeled_sources = [s for s in per_source if s["labeled_rows"]]
    if len(labeled_sources) >= 2 and all(not (s["attack"] and s["benign"]) for s in labeled_sources) \
            and labels["attack"] and labels["benign"]:
        warnings.append("Every labeled source file holds only one class — the source decides the label, so "
                        "capture differences can become a shortcut for the model.")

    # ── schema ────────────────────────────────────────────────
    schema = {}
    model_feats = list(dict.fromkeys(FEATURES_8 + PATH_B_FEATURES))
    for stype in sorted(df["source_type"].unique()):
        recs = [r for r in records if r["source_type"] == stype]
        present = _present_features(recs)
        part = df[df["source_type"] == stype]
        schema[stype] = {
            "rows": int(len(part)),
            "missing_features": [f for f in model_feats if f not in present],
            "constant_features": {f: float(part[f].iloc[0]) for f in FEATURES_8
                                  if len(part) and part[f].nunique() == 1},
        }
        if schema[stype]["missing_features"]:
            warnings.append(f"{stype} rows lack model feature(s) {', '.join(schema[stype]['missing_features'])} "
                            f"(filled with 0).")
    types = list(schema)
    for f in FEATURES_8:
        const_in = [t for t in types if f in schema[t]["constant_features"]]
        if not const_in:
            continue
        if len(const_in) == len(types):
            if df[f].nunique() == 1:
                warnings.append(f"'{f}' is {df[f].iloc[0]:g} in every row — it carries no information.")
        else:
            varies_in = [t for t in types if t not in const_in]
            warnings.append(f"'{f}' is constant in {', '.join(const_in)} rows but varies in {', '.join(varies_in)} "
                            f"rows — the model can learn the source instead of the traffic.")

    return {
        "merged_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rows": n,
        "inputs": inputs,
        "per_source": per_source,
        "duplicates": duplicates,
        "labels": labels,
        "schema": schema,
        "warnings": warnings,
    }


def merge(input_specs: list, output: str, provenance: str = None, report_path: str = None,
          registry: str = None) -> dict:
    records, inputs = [], []
    for spec in input_specs:
        path, original = parse_input(spec)
        if not path or not os.path.isfile(path):
            print(f"  [warn] input not found, skipped: {path}", file=sys.stderr)
            continue
        try:
            recs = load_input(path, original)
        except Exception as e:
            print(f"  [warn] could not load {path}: {e}", file=sys.stderr)
            continue
        ext = Path(path).suffix.lower()
        inputs.append({"path": path, "original": original, "type": "csv" if ext == ".csv" else "json",
                       "records": len(recs), "checksum": _sha256(path, short=True)})
        records.extend(recs)
        print(f"  [{inputs[-1]['type']}] {len(recs):>7} records  <- {path}" + (f"  (from {original})" if original else ""))

    if not records:
        raise SystemExit("ERROR: merged dataset is empty")

    feats = records_to_feature_frame(records)
    keys = feature_vector_key(feats).tolist()
    for r, k in zip(records, keys):
        r["dup_key"] = k

    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        json.dump(records, f, default=str)

    rep = build_report(records, feats, inputs)

    if provenance:
        os.makedirs(os.path.dirname(os.path.abspath(provenance)), exist_ok=True)
        with open(provenance, "w", encoding="utf-8") as f:
            json.dump({
                "merged_at": rep["merged_at"],
                "total_records": len(records),
                "source_files": inputs,
                "source_counts": {
                    "json_files": sum(1 for i in inputs if i["type"] == "json"),
                    "csv_files": sum(1 for i in inputs if i["type"] == "csv"),
                    "pcap_converted": sum(1 for i in inputs if "pcap" in i["path"]),
                    "log_converted": sum(1 for i in inputs if "extracted_" in i["path"]),
                },
                "per_source": rep["per_source"],
            }, f, indent=2)

    if report_path:
        os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=2, default=str)

    if registry:
        try:
            with open(registry, encoding="utf-8") as f:
                reg = json.load(f)
        except Exception:
            reg = {"trained_files": []}
        existing = {e["checksum"] for e in reg.get("trained_files", [])}
        for i in inputs:
            full = _sha256(i["path"])
            if full not in existing:
                reg.setdefault("trained_files", []).append({
                    "path": i["path"], "checksum": full, "type": i["type"],
                    "records": i["records"], "trained_at": rep["merged_at"],
                })
        with open(registry, "w", encoding="utf-8") as f:
            json.dump(reg, f, indent=2)

    d, lab = rep["duplicates"], rep["labels"]
    print(f"  Merged {len(records)} records from {len(inputs)} file(s) → {output}")
    print(f"  Distinct feature vectors: {d['distinct_feature_vectors']}  ·  rows in duplicated vectors: "
          f"{d['rows_in_duplicated_vectors']} ({d['duplicated_share']:.0%})  ·  label conflicts: {lab['conflicting_vectors']}")
    for w in rep["warnings"]:
        print(f"  ! {w}")
    return rep


def main():
    ap = argparse.ArgumentParser(description="Merge pre-processed feature files into one training table.")
    ap.add_argument("--input", nargs="+", required=True,
                    help="feature files (.json/.csv); 'file=original' records the original log/pcap")
    ap.add_argument("--output", required=True, help="merged JSON path")
    ap.add_argument("--provenance", default=None, help="training_provenance.json path")
    ap.add_argument("--report", default=None, help="merge report JSON path")
    ap.add_argument("--registry", default=None, help="trained-files registry to update (omit to leave it untouched)")
    args = ap.parse_args()
    merge(args.input, args.output, args.provenance, args.report, args.registry)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    main()
