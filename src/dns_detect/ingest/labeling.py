#!/usr/bin/env python3
"""
labeling.py — Step 8: give training rows a label, best evidence first, or leave them out.

Precedence per row (label_source records which one decided):
  1. file / provenance — the row already carries a label (labeled JSON, --pcap-label)  → kept
  2. manifest          — the row matches an attack window in data/attack_manifest.csv
                         (time ± skew, source IP, and target_domain when given)        → attack
  3. weak_behavioral   — research-based labeling functions over the traffic of the
                         row's parent domain agree                                     → attack / benign
  4. abstain           — nothing confident → left OUT of training, saved for review

Why behaviour, not tool signatures: payload signatures only catch tools we already know,
while traffic analysis generalises (Farnham, SANS 2013). Every tunnel has to push many
unique, mostly once-queried subdomains carrying data under one parent domain (Nadler et al.
2019; Ozery et al., NDSS 2024). Single indicators false-positive on CDNs, AV reputation
lookups and DNS blocklists, so labels need several agreeing signals plus an allowlist
(Elastic). Labeling functions vote or abstain, Snorkel-style (Ratner et al., VLDB 2018).

These per-domain labels are a different view from Path A's per-query features, but they
are still weak labels: Path A never grades itself on them (only on file/manifest labels).

Usage:
  python -m dns_detect.ingest.labeling --input merged_features_all.json \
      --output merged_features_labeled.json [--manifest data/attack_manifest.csv] \
      [--allowlist config/dns_allowlist.txt] [--abstained abstained_rows.json] [--report labeling_report.json]
  python -m dns_detect.ingest.labeling --input labeled.json --validate    # score the labeling functions
"""

import argparse
import csv
import json
import math
import os
import sys
from collections import Counter
from datetime import timedelta

import pandas as pd

try:
    from dateutil.parser import parse as _parse_dt
except ImportError:  # pragma: no cover - python-dateutil is in requirements.txt
    from datetime import datetime as _dt

    def _parse_dt(v):
        return _dt.fromisoformat(str(v).replace("Z", "+00:00"))

TRUSTED_SOURCES = {"file", "provenance", "manifest"}
TUNNEL_RECORD_TYPES = {"TXT", "NULL", "KEY", "CNAME", "MX", "SRV", "PRIVATE", "65399", "10"}

DEFAULTS = {
    "manifest_skew_seconds": 2,
    "min_unique_subdomains": 50,
    "min_unique_ratio": 0.8,
    "min_information_chars": 4096,
    "long_label_chars": 52,
    "long_subdomain_chars": 40,
    "min_subdomain_entropy": 4.0,
    "min_share": 0.5,
    "tunnel_record_min_subdomains": 20,
    "nxdomain_share": 0.8,
    "ordinary_max_subdomains": 10,
    "ordinary_max_p95_length": 40,
    "min_attack_votes": 2,
}

# Public second levels where the registrable domain has three labels (example.co.uk).
SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk", "sch.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "gr.jp", "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.in", "gov.in", "net.in", "org.in", "ac.in", "nic.in", "res.in", "edu.in",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.kr", "or.kr", "go.kr", "ac.kr",
    "com.tw", "org.tw", "gov.tw", "edu.tw", "com.hk", "org.hk", "gov.hk", "edu.hk", "com.sg", "gov.sg", "edu.sg",
    "com.my", "gov.my", "edu.my", "co.id", "go.id", "ac.id", "or.id", "co.th", "go.th", "ac.th", "in.th",
    "com.vn", "gov.vn", "edu.vn", "com.kh", "gov.kh", "edu.kh", "org.kh", "co.za", "gov.za", "ac.za", "org.za",
    "com.mx", "gob.mx", "com.ar", "gob.ar", "com.tr", "gov.tr", "edu.tr", "com.ru", "com.ua", "co.il", "ac.il",
    "gov.il", "com.pk", "gov.pk", "edu.pk", "com.ph", "gov.ph", "com.eg", "com.sa", "gov.sa", "com.ng", "gov.ng",
}


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def load_settings() -> dict:
    cfg = dict(DEFAULTS)
    try:
        from dns_detect.config import settings
        lab = getattr(settings, "labeling", None)
        if lab is not None:
            cfg.update({k: v for k, v in vars(lab).items() if k in DEFAULTS})
    except Exception:
        pass
    return cfg


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def parent_domain(domain: str) -> str:
    labels = [p for p in str(domain).lower().rstrip(".").split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def subdomain_part(domain: str, parent: str) -> str:
    d = str(domain).lower().rstrip(".")
    return d[: -len(parent) - 1] if parent and d.endswith("." + parent) else ""


def under(domain: str, base: str) -> bool:
    d, b = str(domain).lower().rstrip("."), str(base).lower().rstrip(".")
    return bool(b) and (d == b or d.endswith("." + b))


def _is_label(v) -> bool:
    return v in (0, 1, "0", "1", 0.0, 1.0)


def _ts(v):
    if v in (None, ""):
        return None
    try:
        t = _parse_dt(str(v))
    except (ValueError, OverflowError, TypeError):
        return None
    return t.replace(tzinfo=None) if t.tzinfo else t


def load_allowlist(path: str) -> set:
    if not path or not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8") as f:
        return {ln.strip().lower().rstrip(".") for ln in f if ln.strip() and not ln.lstrip().startswith("#")}


def load_records(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get("records", data.get("data", [data]))
    return [r for r in (data if isinstance(data, list) else [data]) if isinstance(r, dict)]


# ─────────────────────────────────────────────
# MANIFEST (ground truth for lab attacks)
# ─────────────────────────────────────────────

def load_manifest(path: str) -> list:
    """Attack manifest CSV → windows. Columns: family, start, end [, campaign_id, source_ip, target_domain]."""
    windows = []
    with open(path, newline="", encoding="utf-8") as f:
        for i, row in enumerate(csv.DictReader(f), start=2):
            row = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
            start, end = _ts(row.get("start")), _ts(row.get("end"))
            if start is None or end is None:
                print(f"  [warn] manifest line {i}: bad/missing start/end — skipped")
                continue
            if end < start:
                start, end = end, start
            windows.append({
                "campaign_id": row.get("campaign_id") or f"C-{i}",
                "family": row.get("family") or "attack",
                "source_ip": row.get("source_ip") or "",
                "target_domain": (row.get("target_domain") or "").lower().rstrip("."),
                "start": start, "end": end, "matched": 0, "background": 0,
            })
    return windows


def manifest_decision(rec: dict, windows: list, skew: float):
    """('attack', window) | ('abstain', window) | None. Background queries of the attacker host → abstain."""
    ts = _ts(rec.get("timestamp"))
    if ts is None:
        return None
    ip = str(rec.get("client_ip", rec.get("source_ip", "")))
    pad = timedelta(seconds=skew)
    for w in windows:
        if w["start"] - pad <= ts <= w["end"] + pad and (not w["source_ip"] or ip == w["source_ip"]):
            if w["target_domain"] and not under(rec.get("domain", ""), w["target_domain"]):
                return "abstain", w
            return "attack", w
    return None


# ─────────────────────────────────────────────
# LABELING FUNCTIONS (traffic analysis per parent domain)
# ─────────────────────────────────────────────

def domain_stats(records: list, cfg: dict) -> tuple:
    """Per-parent and per-(client, parent) statistics over ALL rows, plus the LF votes they imply."""
    df = pd.DataFrame({
        "domain": [str(r.get("domain") or r.get("query") or "").lower().rstrip(".") for r in records],
        "client": [str(r.get("client_ip", "")) for r in records],
        "qtype": [str(r.get("query_type", "")).upper() for r in records],
        "rcode": [str(r.get("response_code", "unknown")).lower() for r in records],
    })
    df["parent"] = df["domain"].map(parent_domain)
    df["sub"] = [subdomain_part(d, p) for d, p in zip(df["domain"], df["parent"])]
    df["qlen"] = df["domain"].str.len()
    df["max_label"] = df["domain"].map(lambda d: max((len(x) for x in d.split(".")), default=0))
    sub_entropy = {s: entropy(s) for s in df["sub"].unique()}
    df["long_encoded"] = (df["max_label"] > cfg["long_label_chars"]) | (
        (df["sub"].str.len() >= cfg["long_subdomain_chars"]) & (df["sub"].map(sub_entropy) >= cfg["min_subdomain_entropy"]))
    df["tunnel_rr"] = df["qtype"].isin(TUNNEL_RECORD_TYPES)

    parents = {}
    for p, g in df.groupby("parent", sort=False):
        uniq_subs = g.loc[g["sub"] != "", "sub"].unique()
        n_uniq = len(uniq_subs)
        st = {
            "queries": int(len(g)),
            "unique_subdomains": n_uniq,
            "unique_ratio": round(n_uniq / len(g), 4),
            "information_chars": int(sum(len(s) for s in uniq_subs)),
            "long_encoded_share": round(float(g["long_encoded"].mean()), 4),
            "tunnel_record_share": round(float(g["tunnel_rr"].mean()), 4),
            "p95_length": float(g["qlen"].quantile(0.95)),
            "clients": int(g["client"].nunique()),
        }
        votes = []
        if n_uniq >= cfg["min_unique_subdomains"] and st["unique_ratio"] >= cfg["min_unique_ratio"]:
            votes.append("many_unique_subdomains")
        if st["information_chars"] >= cfg["min_information_chars"]:
            votes.append("high_information")
        if st["long_encoded_share"] >= cfg["min_share"]:
            votes.append("long_encoded_labels")
        if st["tunnel_record_share"] >= cfg["min_share"] and n_uniq >= cfg["tunnel_record_min_subdomains"]:
            votes.append("tunnel_record_types")
        st["attack_votes"] = votes
        st["ordinary"] = (n_uniq <= cfg["ordinary_max_subdomains"] and st["p95_length"] < cfg["ordinary_max_p95_length"]
                          and st["tunnel_record_share"] < cfg["min_share"])
        parents[p] = st

    enum = set()
    known = df[df["rcode"] != "unknown"]
    for (c, p), g in known.groupby(["client", "parent"], sort=False):
        subs = g.loc[g["sub"] != "", "sub"]
        if subs.nunique() >= cfg["min_unique_subdomains"] and (g["rcode"] == "nxdomain").mean() >= cfg["nxdomain_share"]:
            enum.add((c, p))
    return df, parents, enum


def lf_decision(row_parent: str, row_client: str, row_domain: str, parents: dict, enum: set,
                allowlist: set, cfg: dict) -> tuple:
    """(label | None, family, votes) for one row from the labeling functions."""
    st = parents.get(row_parent, {})
    votes = list(st.get("attack_votes", []))
    if (row_client, row_parent) in enum:
        votes.append("nxdomain_enumeration")
    if any(under(row_domain, a) for a in allowlist):
        return 0, "benign", votes + ["allowlisted"]
    # A client getting NXDOMAIN for most of many unique names is enumeration / a random-subdomain flood;
    # a tunnel gets answers from the attacker's own name server, so NXDOMAIN decides the family.
    if "nxdomain_enumeration" in votes:
        return 1, "nxdomain_enum", votes
    if len(votes) >= cfg["min_attack_votes"]:
        return 1, "tunnel", votes
    if st.get("ordinary") and not votes:
        return 0, "benign", ["ordinary_domain"]
    return None, None, votes


# ─────────────────────────────────────────────
# MAIN LABELING
# ─────────────────────────────────────────────

def label_records(records: list, manifest: str = None, allowlist: set = None, cfg: dict = None):
    cfg = cfg or load_settings()
    allowlist = allowlist or set()
    windows = load_manifest(manifest) if manifest and os.path.isfile(manifest) else []
    df, parents, enum = domain_stats(records, cfg)

    labeled, abstained = [], []
    by_source = Counter()
    lf_fired = Counter()
    for i, rec in enumerate(records):
        r = dict(rec)
        parent, client, domain = df.at[i, "parent"], df.at[i, "client"], df.at[i, "domain"]
        r["parent_domain"] = parent
        # 1. label already in the file
        if _is_label(r.get("label")):
            r["label"] = int(float(r["label"]))
            src = r.get("label_source") if r.get("label_source") in TRUSTED_SOURCES else "file"
            r["label_source"] = src
            r.setdefault("attack_family", "benign" if r["label"] == 0 else "attack")
            by_source[src] += 1
            labeled.append(r)
            continue
        # 2. manifest
        m = manifest_decision(r, windows, cfg["manifest_skew_seconds"]) if windows else None
        if m and m[0] == "attack":
            w = m[1]
            w["matched"] += 1
            r.update(label=1, label_source="manifest", attack_family=w["family"], campaign_id=w["campaign_id"])
            by_source["manifest"] += 1
            labeled.append(r)
            continue
        if m and m[0] == "abstain":
            m[1]["background"] += 1
            r.update(label_source="abstain", abstain_reason=f"attacker host traffic outside target_domain "
                                                            f"({m[1]['campaign_id']})")
            by_source["abstain"] += 1
            abstained.append(r)
            continue
        # 3. behaviour labeling functions
        lab, fam, votes = lf_decision(parent, client, domain, parents, enum, allowlist, cfg)
        lf_fired.update(votes)
        r["lf_votes"] = votes
        if lab is None:
            r.update(label_source="abstain", abstain_reason="labeling functions not confident")
            r.pop("label", None)
            by_source["abstain"] += 1
            abstained.append(r)
        else:
            r.update(label=lab, label_source="weak_behavioral", attack_family=fam)
            by_source["weak_behavioral"] += 1
            labeled.append(r)

    warnings = []
    for w in windows:
        if w["matched"] == 0:
            warnings.append(f"Manifest window {w['campaign_id']} ({w['family']}) matched no rows — check clock/timezone, "
                            f"source_ip and target_domain.")
    if by_source["weak_behavioral"] and not windows:
        warnings.append(f"{by_source['weak_behavioral']} row(s) labeled by behaviour rules (no attack manifest) — "
                        f"weak labels, used for training only.")
    if by_source["abstain"]:
        warnings.append(f"{by_source['abstain']} row(s) left out of training (no confident label).")

    decided = {p: s for p, s in parents.items() if s["attack_votes"]}
    report = {
        "rows": len(records),
        "attack": sum(1 for r in labeled if r["label"] == 1),
        "benign": sum(1 for r in labeled if r["label"] == 0),
        "by_label_source": dict(by_source),
        "labeling_functions_fired": dict(lf_fired),
        "parents_with_attack_votes": dict(sorted(decided.items(), key=lambda kv: -kv[1]["unique_subdomains"])[:50]),
        "nxdomain_enumeration": [{"client": c, "parent": p} for c, p in sorted(enum)],
        "manifest_windows": [{k: (str(v) if k in ("start", "end") else v) for k, v in w.items()} for w in windows],
        "settings": cfg,
        "warnings": warnings,
    }
    return labeled, abstained, report


def validate(records: list, allowlist: set = None, cfg: dict = None) -> dict:
    """Hide the existing labels, run the labeling functions, and compare (plus the old attack_count rule)."""
    cfg = cfg or load_settings()
    truth = [int(float(r["label"])) for r in records if _is_label(r.get("label"))]
    rows = [r for r in records if _is_label(r.get("label"))]
    df, parents, enum = domain_stats(rows, cfg)
    pred = [lf_decision(df.at[i, "parent"], df.at[i, "client"], df.at[i, "domain"], parents, enum,
                        allowlist or set(), cfg)[0] for i in range(len(rows))]

    def score(pairs):
        tp = sum(1 for y, p in pairs if y == 1 and p == 1)
        fp = sum(1 for y, p in pairs if y == 0 and p == 1)
        fn = sum(1 for y, p in pairs if y == 1 and p == 0)
        return {"precision": round(tp / (tp + fp), 4) if tp + fp else None,
                "recall_of_decided": round(tp / (tp + fn), 4) if tp + fn else None}

    decided = [(y, p) for y, p in zip(truth, pred) if p is not None]
    out = {"rows": len(rows), "coverage": round(len(decided) / len(rows), 4) if rows else 0.0,
           "abstained": len(rows) - len(decided), **score(decided),
           "wrong_labels": sum(1 for y, p in decided if y != p), "per_family": {}}
    fams = [str(r.get("attack_family", "attack")) for r in rows]
    for fam in sorted({f for f, y in zip(fams, truth) if y == 1}):
        idx = [i for i, (f, y) in enumerate(zip(fams, truth)) if y == 1 and f == fam]
        out["per_family"][fam] = {"rows": len(idx),
                                  "labeled_attack": sum(1 for i in idx if pred[i] == 1),
                                  "labeled_benign": sum(1 for i in idx if pred[i] == 0),
                                  "abstained": sum(1 for i in idx if pred[i] is None)}
    ben = [i for i, y in enumerate(truth) if y == 0]
    out["benign"] = {"rows": len(ben), "labeled_benign": sum(1 for i in ben if pred[i] == 0),
                     "labeled_attack": sum(1 for i in ben if pred[i] == 1),
                     "abstained": sum(1 for i in ben if pred[i] is None)}
    if all("attack_count" in r for r in rows):
        old = [(y, 1 if int(r.get("attack_count") or 0) >= 1 else 0) for y, r in zip(truth, rows)]
        out["old_attack_count_rule"] = {"coverage": 1.0, **score(old), "wrong_labels": sum(1 for y, p in old if y != p)}
    return out


def _dump(path, obj, indent=None):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=indent, default=str)


def main():
    ap = argparse.ArgumentParser(description="Step 8 labeling: file labels → manifest → behaviour rules → abstain.")
    ap.add_argument("--input", required=True, help="merged features JSON")
    ap.add_argument("--output", help="labeled JSON (rows with a label only)")
    ap.add_argument("--manifest", default=None, help="attack manifest CSV")
    ap.add_argument("--allowlist", default=None, help="benign parent domains, one per line")
    ap.add_argument("--abstained", default=None, help="where to save rows left out of training")
    ap.add_argument("--report", default=None, help="labeling report JSON")
    ap.add_argument("--validate", action="store_true",
                    help="score the labeling functions against the labels already in --input")
    args = ap.parse_args()

    records = load_records(args.input)
    allow = load_allowlist(args.allowlist)
    if args.validate:
        res = validate(records, allow)
        print(json.dumps(res, indent=2))
        if args.report:
            _dump(args.report, res, indent=2)
        return
    if not args.output:
        ap.error("--output is required unless --validate is used")

    labeled, abstained, report = label_records(records, args.manifest, allow)
    _dump(args.output, labeled)
    if args.abstained:
        _dump(args.abstained, abstained)
    if args.report:
        _dump(args.report, report, indent=2)
    src = report["by_label_source"]
    print(f"  Labeled {report['attack']} attack / {report['benign']} benign · "
          + ", ".join(f"{k} {v}" for k, v in sorted(src.items())))
    for w in report["warnings"]:
        print(f"  ! {w}")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    main()
