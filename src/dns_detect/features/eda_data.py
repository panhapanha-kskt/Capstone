#!/usr/bin/env python3
"""
eda_data.py — EDA #1: labeled data · unlabeled data · comparison

Runs right after "Find new data" in the training pipeline, before any pre-processing.
Every discovered file (.log, .pcap/.pcapng, .json, .csv) is read into ONE per-query
table with the same measures, then analysed in four sections:

  A  Labeled data     — quality, class balance, attack vs benign per measure,
                        single-measure separability (AUC), outliers, date/source bias
  B  Unlabeled data   — quality (empty files, unparseable lines), distributions,
                        clients, NXDOMAIN, outliers, how it will get labels
  C  Comparison       — distribution shift labeled → unlabeled (PSI, KS) and, per
                        unlabeled file, whether it looks like attack, benign or neither
  D  Implications     — what the findings mean for features and model choice

It never modifies data and never exits non-zero for "bad" data — EDA informs, it
does not gate. Writes a JSON report (numbers + warnings) and an offline HTML page
with inline SVG charts.

Usage:
  python -m dns_detect.features.eda_data --labeled a.json --unlabeled b.log \
      --output data/processed/eda_data_report.json
  python -m dns_detect.features.eda_data --status a.json b.log c.pcap --pcap-label 1
"""

import argparse
import csv
import html
import json
import math
import os
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from dns_detect.features.extractor import DNSFeatureExtractor
from dns_detect.monitoring.monitor import _population_stability_index

MEASURES = ["query_length", "longest_label", "subdomain_count", "entropy", "digit_ratio"]
TUNNEL_QTYPES = {"TXT", "NULL", "CNAME", "ANY", "KEY"}
RCODE_NAMES = {0: "NoError", 1: "FormatError", 2: "ServerFailure", 3: "NxDomain", 4: "NotImplemented", 5: "Refused"}

# Warning thresholds (heuristics from DNS detection guides; see docs in the plan)
NX_HIGH = 0.20            # NXDOMAIN share above this is high
LONG_LABEL = 52           # labels longer than this are a strong tunneling sign
DOMINANT_CLIENT = 0.95    # one client sending this share of a file's queries
MANY_SUBDOMAINS = 50      # unique subdomains under one parent domain
AUC_TOO_EASY = 0.95       # one measure separating the classes this well
MINORITY_CLASS = 0.10     # smaller class below this share
PSI_MAJOR = 0.25          # labeled → unlabeled shift


# ─────────────────────────────────────────────
# LABEL STATUS (used by "Find new data")
# ─────────────────────────────────────────────

def _is_label(v) -> bool:
    return v in (0, 1, "0", "1", 0.0, 1.0, "0.0", "1.0")


def label_status(path: str, pcap_label=None) -> dict:
    """{'status': labeled|partial|unlabeled, 'rows': n or None, 'labeled_rows': n or None}."""
    ext = Path(path).suffix.lower()
    if ext in (".pcap", ".pcapng", ".cap"):
        return {"status": "labeled" if _is_label(pcap_label) else "unlabeled", "rows": None, "labeled_rows": None}
    if ext == ".json":
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            data = data if isinstance(data, list) else [data]
        except Exception:
            return {"status": "unlabeled", "rows": 0, "labeled_rows": 0}
        rows = len(data)
        lab = sum(1 for r in data if isinstance(r, dict) and _is_label(r.get("label")))
    elif ext == ".csv":
        try:
            with open(path, newline="", encoding="utf-8") as f:
                data = list(csv.DictReader(f))
        except Exception:
            return {"status": "unlabeled", "rows": 0, "labeled_rows": 0}
        rows = len(data)
        lab = sum(1 for r in data if _is_label((r.get("label") or "").strip()))
    else:  # .log and anything else: Technitium logs never carry labels
        return {"status": "unlabeled", "rows": None, "labeled_rows": None}
    status = "unlabeled" if lab == 0 else ("labeled" if lab == rows else "partial")
    return {"status": status, "rows": rows, "labeled_rows": lab}


# ─────────────────────────────────────────────
# READERS → one row per DNS query
# ─────────────────────────────────────────────

def _family_from_name(path: str) -> str:
    return Path(path).stem.split("_")[0].lower() or "attack"


def _row(file, ts, client, qtype, rcode, domain, has_answer, label, family):
    return {"file": file, "timestamp": ts, "client_ip": client, "qtype": qtype, "rcode": rcode,
            "domain": (domain or "").rstrip(".").lower(), "has_answer": has_answer,
            "label": label, "attack_family": family}


def read_log(path: str):
    ex = DNSFeatureExtractor()
    rows, lines = [], 0
    name = os.path.basename(path)
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            lines += 1
            p = ex.parse_technitium_log_line(line)
            if not p:
                continue
            rows.append(_row(name, p["timestamp"].isoformat(), p["client_ip"], p["query_type"],
                             p["response_code"], p["domain"], p["answer_size"] > 0, None, None))
    return rows, {"kind": "log", "lines": lines, "queries": len(rows)}


def read_pcap(path: str, pcap_label=None):
    name = os.path.basename(path)
    try:
        from scapy.utils import PcapReader
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        try:
            from scapy.layers.dns import dnsqtypes
        except ImportError:
            dnsqtypes = {}
    except ImportError:
        return [], {"kind": "pcap", "error": "scapy not installed — file not analysed"}

    label = int(float(pcap_label)) if _is_label(pcap_label) else None
    family = None if label is None else ("benign" if label == 0 else _family_from_name(path))
    rows, packets, responses, resp_rcodes = [], 0, 0, {}
    with PcapReader(path) as reader:
        for pkt in reader:
            packets += 1
            if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
                continue
            if int(pkt[DNS].qr) == 1:
                responses += 1
                rc = RCODE_NAMES.get(int(pkt[DNS].rcode), str(int(pkt[DNS].rcode)))
                resp_rcodes[rc] = resp_rcodes.get(rc, 0) + 1
                continue
            qname = pkt[DNSQR].qname
            domain = qname.decode(errors="ignore") if isinstance(qname, bytes) else str(qname)
            src = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "unknown")
            qt = int(pkt[DNSQR].qtype)
            rows.append(_row(name, datetime.fromtimestamp(float(pkt.time)).isoformat(), src,
                             dnsqtypes.get(qt, str(qt)), "unknown", domain, None, label, family))
    return rows, {"kind": "pcap", "packets": packets, "queries": len(rows),
                  "responses": responses, "response_rcodes": resp_rcodes}


def _rows_from_records(records, name):
    rows = []
    for r in records:
        if not isinstance(r, dict):
            continue
        ans = r.get("answer_size", r.get("answer_count"))
        try:
            has_answer = float(ans) > 0 if ans not in (None, "") else None
        except (TypeError, ValueError):
            has_answer = None
        lab = int(float(r["label"])) if _is_label(r.get("label")) else None
        rows.append(_row(name, r.get("timestamp"), r.get("client_ip", "unknown"),
                         r.get("query_type", "unknown"), r.get("response_code", "unknown"),
                         r.get("domain") or r.get("query") or "", has_answer, lab,
                         r.get("attack_family") if lab is not None else None))
    return rows


def read_json(path: str):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    data = data if isinstance(data, list) else [data]
    return _rows_from_records(data, os.path.basename(path)), {"kind": "json", "records": len(data)}


def read_csv(path: str):
    with open(path, newline="", encoding="utf-8") as f:
        data = list(csv.DictReader(f))
    return _rows_from_records(data, os.path.basename(path)), {"kind": "csv", "records": len(data)}


def read_any(path: str, pcap_label=None):
    ext = Path(path).suffix.lower()
    try:
        if ext == ".log":
            return read_log(path)
        if ext in (".pcap", ".pcapng", ".cap"):
            return read_pcap(path, pcap_label)
        if ext == ".json":
            return read_json(path)
        if ext == ".csv":
            return read_csv(path)
        return [], {"kind": ext.lstrip(".") or "unknown", "error": "unsupported file type"}
    except Exception as e:  # a broken file is a finding, not a crash
        return [], {"kind": ext.lstrip("."), "error": f"could not read: {e}"}


# ─────────────────────────────────────────────
# COMMON TABLE
# ─────────────────────────────────────────────

def build_table(rows: list) -> pd.DataFrame:
    cols = ["file", "timestamp", "client_ip", "qtype", "rcode", "domain", "has_answer", "label", "attack_family"]
    df = pd.DataFrame(rows, columns=cols)
    if df.empty:
        for m in MEASURES + ["parent_domain"]:
            df[m] = pd.Series(dtype=float)
        df["ts"] = pd.Series(dtype="datetime64[ns]")
        df["group"] = pd.Series(dtype=str)
        return df
    ex = DNSFeatureExtractor()
    doms = df["domain"].fillna("").astype(str)
    labels = doms.str.split(".")
    df["query_length"] = doms.str.len()
    df["longest_label"] = labels.apply(lambda ls: max((len(x) for x in ls), default=0))
    df["subdomain_count"] = doms.str.count(r"\.")
    df["entropy"] = doms.apply(ex.calculate_entropy)
    df["digit_ratio"] = doms.apply(ex.calculate_numeric_ratio)
    df["parent_domain"] = labels.apply(lambda ls: ".".join(ls[-2:]) if len(ls) >= 2 else ".".join(ls))
    ts = pd.to_datetime(df["timestamp"], errors="coerce", format="ISO8601")
    if getattr(ts.dt, "tz", None) is not None:
        ts = ts.dt.tz_convert(None)
    df["ts"] = ts
    df["group"] = np.where(df["label"].notna(), "labeled", "unlabeled")
    df["qtype"] = df["qtype"].fillna("unknown").astype(str).str.upper()
    df["rcode"] = df["rcode"].fillna("unknown").astype(str)
    df["client_ip"] = df["client_ip"].fillna("unknown").astype(str)
    return df


# ─────────────────────────────────────────────
# STATISTICS HELPERS
# ─────────────────────────────────────────────

def _fmt_pct(v) -> str:
    """0.9995 → '99.95%' (not a misleading '100.0%'); None → 'n/a'."""
    if v is None:
        return "n/a"
    return f"{v:.2%}" if 0.995 <= v < 1 or 0 < v < 0.005 else f"{v:.1%}"


def _r(x, n=4):
    try:
        x = float(x)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(x) or math.isinf(x) else round(x, n)


def measure_stats(s: pd.Series) -> dict:
    s = pd.to_numeric(s, errors="coerce").dropna()
    if s.empty:
        return {}
    q1, q3 = s.quantile(0.25), s.quantile(0.75)
    iqr = q3 - q1
    return {
        "mean": _r(s.mean()), "median": _r(s.median()), "p95": _r(s.quantile(0.95)),
        "min": _r(s.min()), "max": _r(s.max()), "std": _r(s.std()),
        "skew": _r(s.skew()) if len(s) > 2 else None,
        "iqr_fence": _r(q3 + 1.5 * iqr),
        "outliers_1_5_iqr": int(((s < q1 - 1.5 * iqr) | (s > q3 + 1.5 * iqr)).sum()),
        "outliers_3_iqr": int(((s < q1 - 3 * iqr) | (s > q3 + 3 * iqr)).sum()),
    }


def _share(counts: pd.Series, top=8) -> list:
    total = int(counts.sum())
    return [{"value": str(k), "count": int(v), "share": _r(v / total if total else 0)}
            for k, v in counts.head(top).items()]


def _nx_rate(df: pd.DataFrame):
    known = df[df["rcode"].str.lower() != "unknown"]
    if known.empty:
        return None
    return _r((known["rcode"].str.lower() == "nxdomain").mean())


def profile(df: pd.DataFrame) -> dict:
    """Univariate profile of a group of queries."""
    if df.empty:
        return {"rows": 0}
    clients = df["client_ip"].value_counts()
    ts = df["ts"].dropna()
    dup_cols = ["file", "timestamp", "client_ip", "domain", "qtype"]
    subs_per_parent = df.groupby("parent_domain")["domain"].nunique().sort_values(ascending=False)
    return {
        "rows": int(len(df)),
        "files": int(df["file"].nunique()),
        "clients": int(clients.size),
        "top_clients": _share(clients, 5),
        "first_seen": ts.min().isoformat() if not ts.empty else None,
        "last_seen": ts.max().isoformat() if not ts.empty else None,
        "duration_min": _r((ts.max() - ts.min()).total_seconds() / 60, 1) if len(ts) > 1 else 0.0,
        "query_types": _share(df["qtype"].value_counts()),
        "tunnel_qtype_share": _r(df["qtype"].isin(TUNNEL_QTYPES).mean()),
        "response_codes": _share(df["rcode"].value_counts()),
        "nxdomain_rate": _nx_rate(df),
        "top_parent_domains": _share(df["parent_domain"].value_counts(), 5),
        "max_subdomains_per_parent": {"parent": str(subs_per_parent.index[0]),
                                      "unique_subdomains": int(subs_per_parent.iloc[0])},
        "unique_domains": int(df["domain"].nunique()),
        "duplicate_rows": int(df.duplicated(subset=dup_cols).sum()),
        "missing": {
            "client_ip": _r((df["client_ip"].isin(["unknown", ""])).mean()),
            "timestamp": _r(df["ts"].isna().mean()),
            "response_code": _r((df["rcode"].str.lower() == "unknown").mean()),
            "domain": _r((df["domain"] == "").mean()),
        },
        "answers_recorded": _r(df["has_answer"].notna().mean()),
        "long_labels": int((df["longest_label"] > LONG_LABEL).sum()),
        "longest_names": df.sort_values("query_length", ascending=False)["domain"].head(5).tolist(),
        "measures": {m: measure_stats(df[m]) for m in MEASURES},
    }


def _auc(y, x):
    from sklearn.metrics import roc_auc_score
    try:
        a = roc_auc_score(y, x)
    except ValueError:
        return None
    return _r(max(a, 1 - a))  # separability regardless of direction


def _ks(a, b):
    a, b = np.sort(np.asarray(a, float)), np.sort(np.asarray(b, float))
    if len(a) == 0 or len(b) == 0:
        return None
    grid = np.concatenate([a, b])
    cdf_a = np.searchsorted(a, grid, side="right") / len(a)
    cdf_b = np.searchsorted(b, grid, side="right") / len(b)
    return _r(np.max(np.abs(cdf_a - cdf_b)))


def _range(df):
    ts = df["ts"].dropna()
    return (ts.min(), ts.max()) if not ts.empty else (None, None)


# ─────────────────────────────────────────────
# SECTIONS
# ─────────────────────────────────────────────

def section_labeled(lab: pd.DataFrame, warnings: list) -> dict:
    out = {"rows": int(len(lab))}
    if lab.empty:
        out["note"] = "No labeled data in this run."
        return out
    y = lab["label"].astype(int)
    n_att, n_ben = int((y == 1).sum()), int((y == 0).sum())
    out["class_balance"] = {"attack": n_att, "benign": n_ben,
                            "attack_share": _r(n_att / len(lab))}
    out["per_file"] = [
        {"file": f, "attack": int((g["label"] == 1).sum()), "benign": int((g["label"] == 0).sum())}
        for f, g in lab.groupby("file")
    ]
    fam = lab[lab["label"] == 1]["attack_family"].fillna("unknown").value_counts()
    out["attack_families"] = _share(fam, 20)
    out["per_class"] = {"attack": profile(lab[y == 1]), "benign": profile(lab[y == 0])}
    out["profile"] = profile(lab)

    minority = min(n_att, n_ben) / len(lab)
    if n_att == 0 or n_ben == 0:
        warnings.append(f"Labeled data has only one class ({n_att} attack / {n_ben} benign) — Path A can't train on it alone.")
    elif minority < MINORITY_CLASS:
        warnings.append(f"Labeled classes are imbalanced: smaller class is {minority:.1%} of the labeled rows.")

    if n_att and n_ben:
        out["separability_auc"] = {m: _auc(y, lab[m]) for m in MEASURES}
        easy = {m: a for m, a in out["separability_auc"].items() if a is not None and a > AUC_TOO_EASY}
        for m, a in sorted(easy.items(), key=lambda kv: -kv[1]):
            warnings.append(f"'{m}' alone separates attack from benign (AUC {a:.3f}) — the labeled data may be too easy.")

        a0, a1 = _range(lab[y == 1])
        b0, b1 = _range(lab[y == 0])
        out["date_ranges"] = {"attack": [str(a0), str(a1)], "benign": [str(b0), str(b1)]}
        out["same_period"] = True
        if a0 is not None and b0 is not None:
            gap = max(b0 - a1, a0 - b1)          # > 0 when the ranges don't overlap
            out["gap_days"] = _r(max(gap.total_seconds(), 0) / 86400, 1)
            if gap.total_seconds() > 86400:      # captured more than a day apart
                out["same_period"] = False
                warnings.append(f"Attack data ({a0:%Y-%m-%d}…{a1:%Y-%m-%d}) and benign data ({b0:%Y-%m-%d}…{b1:%Y-%m-%d}) "
                                f"were captured {out['gap_days']:,.0f} days apart — the model could learn when, not what.")
        mixed = [r["file"] for r in out["per_file"] if r["attack"] and r["benign"]]
        out["files_with_both_classes"] = mixed
    return out


def section_unlabeled(unl: pd.DataFrame, file_meta: dict, unl_files: list, manifest: bool,
                      total_rows: int, warnings: list) -> dict:
    out = {"rows": int(len(unl))}
    per_file = []
    for f in unl_files:
        name = os.path.basename(f)
        meta = file_meta.get(name, {})
        g = unl[unl["file"] == name]
        item = {"file": name, "kind": meta.get("kind"), "queries": int(len(g))}
        if "lines" in meta:
            item["lines"] = meta["lines"]
            item["non_query_lines"] = meta["lines"] - meta.get("queries", 0)
        if meta.get("kind") == "pcap":
            item["responses"] = meta.get("responses", 0)
        if meta.get("error"):
            item["error"] = meta["error"]
            warnings.append(f"{name}: {meta['error']}.")
        elif len(g) == 0:
            warnings.append(f"{name} has 0 DNS queries (only server/status lines) — it adds nothing to training.")
        if not g.empty:
            clients = g["client_ip"].value_counts()
            item["clients"] = int(clients.size)
            item["top_client_share"] = _r(clients.iloc[0] / len(g))
            item["nxdomain_rate"] = _nx_rate(g)
            ts = g["ts"].dropna()
            item["duration_min"] = _r((ts.max() - ts.min()).total_seconds() / 60, 1) if len(ts) > 1 else 0.0
            if len(g) >= 50 and item["top_client_share"] >= DOMINANT_CLIENT:
                warnings.append(f"{name}: one client ({clients.index[0]}) sends {_fmt_pct(item['top_client_share'])} of the queries.")
            if item["nxdomain_rate"] is not None and len(g) >= 50 and item["nxdomain_rate"] > NX_HIGH:
                warnings.append(f"{name}: NXDOMAIN rate {_fmt_pct(item['nxdomain_rate'])} (above {NX_HIGH:.0%} is high).")
            if meta.get("kind") == "pcap" and meta.get("responses", 0) == 0:
                warnings.append(f"{name}: PCAP has queries only (no responses) — answer counts will be 0.")
            # queries per minute timeline for the HTML report
            if not ts.empty:
                per_min = ts.dt.floor("min").value_counts().sort_index()
                item["timeline_per_min"] = [int(v) for v in per_min.values][:600]
        per_file.append(item)
    out["per_file"] = per_file

    if unl.empty:
        out["note"] = "No unlabeled queries in this run."
        return out

    out["profile"] = profile(unl)
    nx_by_client = (unl[unl["rcode"].str.lower() != "unknown"]
                    .groupby("client_ip")["rcode"]
                    .agg(lambda s: (s.str.lower() == "nxdomain").mean()))
    vol = unl["client_ip"].value_counts()
    out["nxdomain_rate_per_client"] = [{"client": c, "queries": int(vol[c]), "nxdomain_rate": _r(nx_by_client.get(c))}
                                       for c in vol.head(10).index]
    out["query_length_per_qtype"] = [{"qtype": q, "count": int(len(g)), "median": _r(g["query_length"].median()),
                                      "p95": _r(g["query_length"].quantile(0.95))}
                                     for q, g in unl.groupby("qtype")]
    subs = unl.groupby("parent_domain")["domain"].nunique().sort_values(ascending=False)
    out["unique_subdomains_per_parent"] = _share(subs, 10)
    if len(subs) and subs.iloc[0] > MANY_SUBDOMAINS:
        warnings.append(f"Unlabeled: {subs.iloc[0]} unique subdomains under {subs.index[0]} (over {MANY_SUBDOMAINS} is a tunneling sign).")

    share = len(unl) / total_rows if total_rows else 0
    out["labeling_plan"] = {
        "method": "attack manifest (time window + source)" if manifest else "heuristic attack_count (circular)",
        "share_of_all_rows": _r(share),
    }
    if not manifest and share > 0.5:
        warnings.append(f"{share:.0%} of the data is unlabeled and there is no attack manifest — most training labels "
                        f"would come from heuristics.")
    return out


def section_comparison(lab: pd.DataFrame, unl: pd.DataFrame, warnings: list) -> dict:
    if lab.empty or unl.empty:
        return {"note": "Needs both labeled and unlabeled data."}
    out = {"shift": {}}
    for m in MEASURES:
        a = pd.to_numeric(lab[m], errors="coerce").to_numpy(float)
        b = pd.to_numeric(unl[m], errors="coerce").to_numpy(float)
        psi = _r(_population_stability_index(a, b))
        out["shift"][m] = {"psi": psi, "ks": _ks(a, b),
                           "labeled_median": _r(np.nanmedian(a)), "unlabeled_median": _r(np.nanmedian(b))}
    big = [m for m, v in out["shift"].items() if v["psi"] is not None and v["psi"] > PSI_MAJOR]
    if big:
        warnings.append(f"Unlabeled data differs strongly from labeled data on {', '.join(big)} (PSI > {PSI_MAJOR}) — "
                        f"a model trained on the labeled part may not fit it.")

    # Nearest labeled profile per unlabeled file, in standardized (z) space
    mu = lab[MEASURES].mean()
    sd = lab[MEASURES].std().replace(0, 1).fillna(1)
    z = lambda d: ((d[MEASURES] - mu) / sd).mean()
    centroids = {}
    for name, cls in (("attack", 1), ("benign", 0)):
        part = lab[lab["label"] == cls]
        if not part.empty:
            centroids[name] = z(part)
    out["nearest_profile"] = []
    for f, g in unl.groupby("file"):
        v = z(g)
        dists = {k: _r(float(np.sqrt(((v - c) ** 2).mean())), 3) for k, c in centroids.items()}
        if not dists:
            continue
        nearest = min(dists, key=dists.get)
        verdict = nearest if dists[nearest] <= 1.5 else "neither"
        out["nearest_profile"].append({"file": f, "distances": dists, "looks_like": verdict})
    return out


def implications(rep: dict) -> list:
    notes = []
    A, B, C = rep["labeled"], rep["unlabeled"], rep["comparison"]
    easy = {m: a for m, a in (A.get("separability_auc") or {}).items() if a and a > AUC_TOO_EASY}
    if easy:
        m = max(easy, key=easy.get)
        notes.append(f"Feature engineering: '{m}' alone nearly separates the classes. High model scores will mostly "
                     f"reflect this one measure; add harder data (long benign names, short-name attacks) before "
                     f"trusting accuracy.")
    if A.get("same_period") is False:
        notes.append("Bias: attack and benign data come from different periods. Keep time fields (timestamp, hour, "
                     "day) out of the features, and test on data captured in the same period.")
    prof_a = (A.get("per_class") or {}).get("attack", {})
    if prof_a.get("rows") and prof_a.get("missing", {}).get("response_code", 0) > 0.9:
        notes.append("Feature engineering: labeled rows have no response codes / answers (PCAP queries only) while "
                     "Technitium logs do. Don't rely on answer_count or RCODE features until both sources record them.")
    for item in B.get("per_file", []):
        if (item.get("top_client_share") or 0) >= DOMINANT_CLIENT and (item.get("nxdomain_rate") or 0) > NX_HIGH:
            notes.append(f"Feature engineering: {item['file']} is one client producing mostly NXDOMAIN. Per-query "
                         f"features can't see that; per-client behavioural features (NXDOMAIN share, query rate, "
                         f"unique subdomains per parent) would.")
            break
    skews = [v.get("skew") for v in (rep["all"].get("measures") or {}).values() if v.get("skew") is not None]
    if skews and max(skews) > 2:
        notes.append("Algorithm choice: length/count measures are strongly right-skewed with long tails. Tree models "
                     "(Random Forest, Gradient Boosting) handle this without scaling; linear or distance-based "
                     "models would need log scaling.")
    bal = A.get("class_balance")
    if bal and bal["attack"] and bal["benign"]:
        ratio = max(bal["attack"], bal["benign"]) / min(bal["attack"], bal["benign"])
        notes.append(f"Algorithm choice: labeled class ratio is {ratio:.1f}:1 — "
                     + ("balanced enough; report PR-AUC alongside F1." if ratio < 3
                        else "use class weights and judge models by PR-AUC, not accuracy."))
    for p in C.get("nearest_profile", []):
        if p["looks_like"] == "neither":
            notes.append(f"Coverage: {p['file']} looks like neither labeled class. Label it (attack manifest) or keep "
                         f"it out of evaluation; Path B (trained on normal traffic) is the better judge for it.")
    if (B.get("labeling_plan") or {}).get("method", "").startswith("heuristic") and B.get("rows"):
        notes.append("Garbage in: unlabeled rows will get heuristic labels from the same features the model learns. "
                     "Add data/attack_manifest.csv for independent labels.")
    return notes


# ─────────────────────────────────────────────
# HTML REPORT (inline SVG, no dependencies)
# ─────────────────────────────────────────────

ESC = html.escape


def _svg_bars(items, title, color="var(--bar)", fmt=lambda v: f"{v:,.0f}", width=560, max_items=10):
    items = [(str(k), float(v)) for k, v in items][:max_items]
    if not items:
        return ""
    row, label_w, pad = 22, 190, 8
    bar_w = width - label_w - 70
    vmax = max(v for _, v in items) or 1
    h = row * len(items) + pad * 2
    parts = [f'<svg viewBox="0 0 {width} {h}" role="img" aria-label="{ESC(title)}">']
    for i, (k, v) in enumerate(items):
        y = pad + i * row
        w = max(1.0, bar_w * v / vmax)
        lab = k if len(k) <= 30 else k[:29] + "…"
        parts.append(f'<text x="{label_w - 8}" y="{y + 15}" text-anchor="end" class="lbl">{ESC(lab)}</text>'
                     f'<rect x="{label_w}" y="{y + 4}" width="{w:.1f}" height="{row - 8}" rx="3" fill="{color}"/>'
                     f'<text x="{label_w + w + 6:.1f}" y="{y + 15}" class="val">{ESC(fmt(v))}</text>')
    parts.append("</svg>")
    return f'<figure><figcaption>{ESC(title)}</figcaption>{"".join(parts)}</figure>'


def _svg_hist(groups: dict, title, bins=30, markers=(), width=560, height=200):
    groups = {k: np.asarray(pd.to_numeric(pd.Series(v), errors="coerce").dropna(), float)
              for k, v in groups.items() if len(v)}
    if not groups:
        return ""
    pooled = np.concatenate(list(groups.values()))
    lo, hi = float(np.min(pooled)), float(np.quantile(pooled, 0.995))
    if hi <= lo:
        hi = lo + 1
    edges = np.linspace(lo, hi, bins + 1)
    left, right, top, bottom = 40, 10, 24, 28
    pw, ph = width - left - right, height - top - bottom
    hists = {}
    for k, v in groups.items():
        c, _ = np.histogram(np.clip(v, lo, hi), bins=edges)
        hists[k] = c / max(c.sum(), 1)
    ymax = max(h.max() for h in hists.values()) or 1
    colors = {"attack": "var(--attack)", "benign": "var(--benign)", "unlabeled": "var(--unl)", "labeled": "var(--bar)"}
    sx = lambda x: left + pw * (x - lo) / (hi - lo)
    sy = lambda y: top + ph * (1 - y / ymax)
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{ESC(title)}">',
             f'<line x1="{left}" y1="{top + ph}" x2="{left + pw}" y2="{top + ph}" class="axis"/>']
    for i, (k, h) in enumerate(hists.items()):
        pts = [f"{sx(edges[0]):.1f},{sy(0):.1f}"]
        for j, val in enumerate(h):
            pts.append(f"{sx(edges[j]):.1f},{sy(val):.1f}")
            pts.append(f"{sx(edges[j + 1]):.1f},{sy(val):.1f}")
        pts.append(f"{sx(edges[-1]):.1f},{sy(0):.1f}")
        col = colors.get(k, "var(--bar)")
        parts.append(f'<polyline points="{" ".join(pts)}" fill="{col}" fill-opacity="0.18" stroke="{col}" stroke-width="1.6"/>')
        parts.append(f'<rect x="{left + 4 + i * 110}" y="6" width="10" height="10" rx="2" fill="{col}"/>'
                     f'<text x="{left + 18 + i * 110}" y="15" class="lbl">{ESC(k)}</text>')
    for x, lab in markers:
        if x is not None and lo <= x <= hi:
            parts.append(f'<line x1="{sx(x):.1f}" y1="{top}" x2="{sx(x):.1f}" y2="{top + ph}" class="mark"/>'
                         f'<text x="{sx(x) + 3:.1f}" y="{top + 10}" class="lbl">{ESC(lab)}</text>')
    for x in (lo, (lo + hi) / 2, hi):
        parts.append(f'<text x="{sx(x):.1f}" y="{height - 8}" text-anchor="middle" class="val">{x:,.1f}</text>')
    parts.append(f'<text x="{left - 4}" y="{top + 8}" text-anchor="end" class="val">{ymax:.0%}</text></svg>')
    return f'<figure><figcaption>{ESC(title)}</figcaption>{"".join(parts)}</figure>'


def _svg_spark(values, width=260, height=36):
    if not values or len(values) < 2:
        return ""
    vmax = max(values) or 1
    step = width / (len(values) - 1)
    pts = " ".join(f"{i * step:.1f},{height - 2 - (height - 4) * v / vmax:.1f}" for i, v in enumerate(values))
    return (f'<svg viewBox="0 0 {width} {height}" class="spark" role="img" aria-label="queries per minute">'
            f'<polyline points="{pts}" fill="none" stroke="var(--unl)" stroke-width="1.5"/></svg>')


def _table(headers, rows):
    head = "".join(f"<th>{ESC(str(h))}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c if isinstance(c, _Raw) else ESC('' if c is None else str(c))}</td>"
                                    for c in r) + "</tr>" for r in rows)
    return f'<div class="tw"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


class _Raw(str):
    """Marks pre-built HTML inside a table cell."""


_pct = _fmt_pct


def render_html(rep: dict, df: pd.DataFrame) -> str:
    A, B, C = rep["labeled"], rep["unlabeled"], rep["comparison"]
    lab, unl = df[df["group"] == "labeled"], df[df["group"] == "unlabeled"]
    s = []

    # Summary
    bal = A.get("class_balance", {})
    tiles = [("Labeled rows", f"{A.get('rows', 0):,}"),
             ("Attack / benign", f"{bal.get('attack', 0):,} / {bal.get('benign', 0):,}" if bal else "—"),
             ("Unlabeled rows", f"{B.get('rows', 0):,}"),
             ("Warnings", str(len(rep["warnings"])))]
    s.append('<div class="tiles">' + "".join(f'<div class="tile"><span>{ESC(k)}</span><b>{ESC(v)}</b></div>'
                                             for k, v in tiles) + "</div>")
    if rep["warnings"]:
        s.append('<section class="warn"><h2>Warnings</h2><ul>' +
                 "".join(f"<li>{ESC(w)}</li>" for w in rep["warnings"]) + "</ul></section>")
    files = [[f["file"], f["group"], f["status"], f.get("kind"), f.get("queries")] for f in rep["files"]]
    s.append("<h2>Files found</h2>" + _table(["File", "Group", "Label status", "Type", "Queries"], files))

    # A
    s.append('<h2>A · Labeled data</h2>')
    if lab.empty:
        s.append(f'<p class="muted">{ESC(A.get("note", ""))}</p>')
    else:
        s.append('<h3>Class balance</h3><div class="grid">')
        s.append(_svg_bars([("attack", bal["attack"]), ("benign", bal["benign"])], "Rows per class"))
        s.append(_svg_bars([(r["value"], r["count"]) for r in A.get("attack_families", [])], "Attack rows per family",
                           color="var(--attack)"))
        s.append("</div>")
        s.append(_table(["File", "Attack", "Benign"], [[r["file"], r["attack"], r["benign"]] for r in A["per_file"]]))
        s.append('<h3>Attack vs benign, per measure</h3>')
        auc = A.get("separability_auc", {})
        rows = []
        for m in MEASURES:
            pa = A["per_class"]["attack"].get("measures", {}).get(m, {})
            pb = A["per_class"]["benign"].get("measures", {}).get(m, {})
            a = auc.get(m)
            flag = _Raw(f'<span class="pill bad">{a:.3f}</span>' if a and a > AUC_TOO_EASY else f"{a:.3f}" if a else "n/a")
            rows.append([m, pa.get("median"), pb.get("median"), pa.get("p95"), pb.get("p95"), flag])
        s.append(_table(["Measure", "Attack median", "Benign median", "Attack p95", "Benign p95",
                         "AUC (1 measure alone)"], rows))
        s.append('<div class="grid">')
        for m in MEASURES:
            fence = A["profile"]["measures"].get(m, {}).get("iqr_fence")
            marks = [(fence, "IQR fence")] + ([(LONG_LABEL, "52 chars")] if m == "longest_label" else [])
            s.append(_svg_hist({"attack": lab[lab["label"] == 1][m], "benign": lab[lab["label"] == 0][m]},
                               f"{m} — attack vs benign (share of rows)", markers=marks))
        s.append("</div><h3>Query types and response codes</h3><div class=\"grid\">")
        for cls in ("attack", "benign"):
            pc = A["per_class"][cls]
            s.append(_svg_bars([(r["value"], r["count"]) for r in pc.get("query_types", [])],
                               f"Query types — {cls}", color=f"var(--{cls})"))
        s.append("</div>")
        dr = A.get("date_ranges")
        if dr:
            s.append(f'<p>Attack data: {ESC(dr["attack"][0])} → {ESC(dr["attack"][1])}<br>'
                     f'Benign data: {ESC(dr["benign"][0])} → {ESC(dr["benign"][1])}</p>')

    # B
    s.append('<h2>B · Unlabeled data</h2>')
    trows = []
    for f in B.get("per_file", []):
        trows.append([f["file"], f.get("kind"), f.get("lines", "—"), f["queries"], f.get("clients", "—"),
                      _pct(f.get("top_client_share")), _pct(f.get("nxdomain_rate")), f.get("duration_min", "—"),
                      _Raw(_svg_spark(f.get("timeline_per_min", [])))])
    if trows:
        s.append(_table(["File", "Type", "Lines", "Queries", "Clients", "Top client", "NXDOMAIN", "Minutes",
                         "Queries per minute"], trows))
    if unl.empty:
        s.append(f'<p class="muted">{ESC(B.get("note", ""))}</p>')
    else:
        p = B["profile"]
        s.append('<div class="grid">')
        s.append(_svg_bars([(r["value"], r["count"]) for r in p["query_types"]], "Query types", color="var(--unl)"))
        s.append(_svg_bars([(r["value"], r["count"]) for r in p["response_codes"]], "Response codes", color="var(--unl)"))
        s.append(_svg_bars([(r["client"], (r["nxdomain_rate"] or 0) * 100) for r in B["nxdomain_rate_per_client"]],
                           "NXDOMAIN rate per client (top 10 by volume)", color="var(--attack)", fmt=lambda v: f"{v:.1f}%"))
        s.append(_svg_bars([(r["value"], r["count"]) for r in B["unique_subdomains_per_parent"]],
                           "Unique subdomains per parent domain", color="var(--unl)"))
        for m in ("query_length", "longest_label", "entropy"):
            fence = p["measures"].get(m, {}).get("iqr_fence")
            marks = [(fence, "IQR fence")] + ([(LONG_LABEL, "52 chars")] if m == "longest_label" else [])
            s.append(_svg_hist({"unlabeled": unl[m]}, f"{m} — unlabeled", markers=marks))
        s.append("</div>")
        lp = B.get("labeling_plan", {})
        s.append(f'<p>Will be labeled by: <b>{ESC(lp.get("method", ""))}</b> · '
                 f'{_pct(lp.get("share_of_all_rows"))} of all rows.</p>')

    # C
    s.append('<h2>C · Labeled vs unlabeled</h2>')
    if "shift" not in C:
        s.append(f'<p class="muted">{ESC(C.get("note", ""))}</p>')
    else:
        rows = []
        for m, v in C["shift"].items():
            psi = v["psi"]
            flag = _Raw(f'<span class="pill bad">{psi:.2f}</span>' if psi is not None and psi > PSI_MAJOR
                        else f"{psi:.2f}" if psi is not None else "n/a")
            rows.append([m, v["labeled_median"], v["unlabeled_median"], flag, v["ks"]])
        s.append(_table(["Measure", "Labeled median", "Unlabeled median", "PSI", "KS"], rows))
        s.append(_table(["Unlabeled file", "Distance to attack", "Distance to benign", "Looks like"],
                        [[p["file"], p["distances"].get("attack"), p["distances"].get("benign"), p["looks_like"]]
                         for p in C.get("nearest_profile", [])]))
        s.append('<div class="grid">')
        for m in ("query_length", "entropy"):
            s.append(_svg_hist({"attack": lab[lab["label"] == 1][m], "benign": lab[lab["label"] == 0][m],
                                "unlabeled": unl[m]}, f"{m} — labeled classes vs unlabeled"))
        s.append("</div>")

    # D
    s.append('<h2>D · What this means for the model</h2>')
    s.append("<ul>" + "".join(f"<li>{ESC(n)}</li>" for n in rep["implications"]) + "</ul>" if rep["implications"]
             else '<p class="muted">No specific implications found.</p>')

    css = """
:root{--bg:#f4f5f7;--surface:#fff;--ink:#1c2230;--muted:#5d6878;--line:#d5dae1;--bar:#2f62c9;
--attack:#c2453b;--benign:#16857d;--unl:#7a4fc4;--warn-bg:#fdf3e1;--warn:#b7700b;
--font:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;--mono:"IBM Plex Mono",ui-monospace,Consolas,monospace;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#121519;--surface:#1b2027;--ink:#e3e7ed;--muted:#9aa4b1;--line:#353d48;
--bar:#7aa2f0;--attack:#ee7d72;--benign:#45c2b6;--unl:#ad8ef0;--warn-bg:#2b2413;--warn:#f0b54a;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font);line-height:1.5}
main{max-width:1180px;margin:0 auto;padding:28px 20px 60px}h1{margin:0 0 4px;font-size:1.6rem}
h2{margin:34px 0 10px;font-size:1.25rem;border-bottom:1px solid var(--line);padding-bottom:6px}h3{margin:20px 0 8px;font-size:1rem}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile span{display:block;color:var(--muted);font-size:13px}.tile b{font-size:1.35rem;font-variant-numeric:tabular-nums}
.warn{background:var(--warn-bg);border-left:4px solid var(--warn);border-radius:8px;padding:4px 16px}.warn h2{border:0;color:var(--warn);margin-top:10px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:14px}
figure{margin:0;background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
figcaption{font-size:13px;color:var(--muted);margin-bottom:4px}svg{width:100%;height:auto;display:block}
svg .lbl{font-size:11px;fill:var(--ink)}svg .val{font-size:10.5px;fill:var(--muted);font-family:var(--mono)}
svg .axis{stroke:var(--line)}svg .mark{stroke:var(--warn);stroke-dasharray:4 3}svg.spark{width:200px}
.tw{overflow-x:auto;margin:10px 0}table{border-collapse:collapse;width:100%;background:var(--surface);font-size:14px}
th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;font-variant-numeric:tabular-nums}th{background:var(--bg);font-weight:600}
.pill{padding:1px 7px;border-radius:999px;font-family:var(--mono);font-size:12px}.pill.bad{background:var(--attack);color:#fff}
@media (max-width:480px){.grid{grid-template-columns:1fr}}
"""
    return (f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1"><title>DNS Data EDA</title>'
            f'<style>{css}</style></head><body><main><h1>DNS data EDA — labeled · unlabeled · comparison</h1>'
            f'<p class="muted">Generated {ESC(rep["generated_at"])} · runs right after “Find new data”, before '
            f'pre-processing. Thresholds are heuristics; warnings inform, they never stop training.</p>'
            f'{"".join(s)}</main></body></html>')


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def run_eda(labeled_files, unlabeled_files, pcap_label=None, manifest=None, output=None) -> dict:
    rows, file_meta, files = [], {}, []
    for group, paths in (("labeled", labeled_files), ("unlabeled", unlabeled_files)):
        for p in paths:
            r, meta = read_any(p, pcap_label if group == "labeled" else None)
            n_lab = sum(1 for x in r if x["label"] is not None)
            status = "unlabeled" if n_lab == 0 else ("labeled" if n_lab == len(r) else "partial")
            rows.extend(r)
            file_meta[os.path.basename(p)] = meta
            files.append({"file": os.path.basename(p), "path": p, "group": group, "status": status,
                          "kind": meta.get("kind"), "queries": len(r), "error": meta.get("error")})

    df = build_table(rows)
    lab, unl = df[df["group"] == "labeled"], df[df["group"] == "unlabeled"]
    warnings = []
    has_manifest = bool(manifest) and os.path.isfile(manifest)
    rep = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "files": files,
        "totals": {"rows": int(len(df)), "labeled_rows": int(len(lab)), "unlabeled_rows": int(len(unl))},
        "all": profile(df),
    }
    rep["labeled"] = section_labeled(lab, warnings)
    # Labeled files that turned out empty / unreadable are worth a warning too
    for f in files:
        if f["group"] == "labeled":
            if f["error"]:
                warnings.append(f"{f['file']}: {f['error']}.")
            elif f["queries"] == 0:
                warnings.append(f"{f['file']} has 0 DNS queries.")
    rep["unlabeled"] = section_unlabeled(unl, file_meta, list(unlabeled_files), has_manifest, len(df), warnings)
    rep["comparison"] = section_comparison(lab, unl, warnings)
    rep["warnings"] = warnings
    rep["implications"] = implications(rep)

    print(f"EDA #1: {len(df)} queries · labeled {len(lab)} · unlabeled {len(unl)} · {len(warnings)} warning(s)")
    for w in warnings:
        print(f"  ! {w}")
    for n in rep["implications"]:
        print(f"  → {n}")

    if output:
        os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
        with open(output, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=2, default=str)
        html_path = os.path.splitext(output)[0] + ".html"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(render_html(rep, df))
        print(f"Report → {output}\nReport → {html_path}")
    return rep


def main():
    ap = argparse.ArgumentParser(description="EDA #1 — labeled data, unlabeled data and their comparison.")
    ap.add_argument("--labeled", nargs="*", default=[], help="files whose rows carry labels")
    ap.add_argument("--unlabeled", nargs="*", default=[], help="files without labels")
    ap.add_argument("--status", nargs="*", default=None,
                    help="only print '<status>\\t<labeled rows>\\t<path>' per file and exit")
    ap.add_argument("--pcap-label", default=None, help="label given to PCAPs with --pcap-label (0/1)")
    ap.add_argument("--manifest", default=None, help="attack manifest path (affects the labeling plan)")
    ap.add_argument("--output", default=None, help="JSON report path (HTML written next to it)")
    args = ap.parse_args()

    if args.status is not None:
        for p in args.status:
            st = label_status(p, args.pcap_label)
            # never an empty field: bash `read` with IFS=tab would merge two tabs into one
            print(f"{st['status']}\t{st['labeled_rows'] if st['labeled_rows'] is not None else '-'}\t{p}")
        return
    run_eda(args.labeled, args.unlabeled, args.pcap_label, args.manifest, args.output)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    main()
