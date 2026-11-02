#!/usr/bin/env python3
"""
cleaning.py — Validate, normalise and de-duplicate DNS records before they are merged.

Generic cleaning recipes (fix invalid characters, delete outliers, drop duplicates) would
erase the very signal a tunnel detector learns from, so every rule here is DNS-specific:

  1. Normalise   — domain: strip, lowercase, drop the trailing root dot (the same rule
                   labeling.py and make_labeled_features.py use); query_type/protocol upper.
                   Nothing else about the name is touched.
  2. Reject      — only what cannot be a real DNS query: empty name, name > 253 chars or a
                   label > 63 (RFC 1035), a label outside {0, 1}, an infinite feature, or a
                   per-query feature outside its possible range. Rejected rows are returned
                   with a `reject_reason` for a quarantine file, never silently dropped.
  3. Flag        — counted, never changed: characters outside [a-z0-9-_.] (base64 payloads
                   such as 'sisaqgc/ba.dns2tcp-key.com' are attack signal), infrastructure
                   queries (*.arpa, bare TLDs for DNSSEC), and timestamps that do not parse.
  4. De-duplicate — only identical packet copies (same name, timestamp, client IP AND port,
                   query type and protocol), a capture artefact. Repeated queries are real
                   traffic frequency and stay; dup_key keeps them on one side of a split.

Used by ingest/merge.py. Detection never calls this: live traffic is scored as it arrives,
malformed names included, because they may be the attack.
"""

import math
import re
from collections import Counter

import pandas as pd

DEFAULTS = {
    "max_name_length": 253,           # RFC 1035 §2.3.4
    "max_label_length": 63,
    "drop_exact_packet_copies": True,
    # Per-query features that are shares of the name, so they must lie in [0, 1].
    "ratio_features": ["digit_ratio", "numeric_ratio", "unique_char_ratio"],
    # Per-query lengths, counts and entropies: never negative.
    "non_negative_features": ["query_length", "query_entropy", "entropy", "subdomain_count",
                              "subdomain_depth", "longest_label", "first_label_length",
                              "answer_count", "answer_size"],
}

PACKET_KEY = ("domain", "timestamp", "client_ip", "client_port", "query_type", "protocol")
HOSTNAME_CHARS = re.compile(r"^[a-z0-9._-]*$")


def load_settings() -> dict:
    """DEFAULTS overridden by the `cleaning:` block of config/settings.yaml."""
    cfg = dict(DEFAULTS)
    try:
        from dns_detect.config import settings
        sec = getattr(settings, "cleaning", None)
        if sec is not None:
            cfg.update({k: v for k, v in vars(sec).items() if k in cfg})
    except Exception:
        pass
    return cfg


def _name_field(r: dict) -> str:
    return "domain" if "domain" in r or "query" not in r else "query"


def _number(v):
    """float(v), or None for missing / non-numeric values (those are counted as missing elsewhere)."""
    if v is None or isinstance(v, bool):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _reject_reason(r: dict, name: str, cfg: dict):
    if not name:
        return "empty_domain"
    if len(name) > cfg["max_name_length"]:
        return "name_too_long"
    if any(len(lbl) > cfg["max_label_length"] for lbl in name.split(".")):
        return "label_too_long"
    if "label" in r and r["label"] is not None and r["label"] not in (0, 1):
        return "bad_label"
    for f in cfg["ratio_features"] + cfg["non_negative_features"]:
        x = _number(r.get(f))
        if x is None or math.isnan(x):
            continue
        if math.isinf(x):
            return "non_finite_feature"
        if x < 0 or (f in cfg["ratio_features"] and x > 1):
            return "out_of_range_feature"
    return None


def _label_key(r: dict) -> str:
    return str(r["label"]) if r.get("label") in (0, 1) else "none"


def clean_records(records: list, cfg: dict = None):
    """
    records → (kept, rejected, report). Records are copied, never modified in place.
    Rejected rows carry `reject_reason`; the report counts every change and flag.
    """
    cfg = {**DEFAULTS, **(cfg or {})}
    kept, rejected = [], []
    normalised = Counter()
    flags = {"non_hostname_chars": Counter(), "infra_query": Counter(), "unparsed_timestamp": Counter()}

    for r in records:
        r = dict(r)
        field = _name_field(r)
        raw = r.get(field)
        name = "" if raw is None else str(raw).strip().lower().rstrip(".")
        if raw is not None and name != raw:
            normalised["domain"] += 1
        r[field] = name
        for f in ("query_type", "protocol"):
            if isinstance(r.get(f), str) and r[f] != r[f].strip().upper():
                r[f] = r[f].strip().upper()
                normalised[f] += 1

        reason = _reject_reason(r, name, cfg)
        if reason:
            r["reject_reason"] = reason
            rejected.append(r)
            continue

        lab = _label_key(r)
        if not HOSTNAME_CHARS.match(name):
            flags["non_hostname_chars"][lab] += 1
        if name.endswith(".arpa") or name == "arpa" or "." not in name:
            flags["infra_query"][lab] += 1
        kept.append(r)

    # Timestamps: one vectorised parse; rows without one keep their file order downstream.
    if kept:
        ts = pd.to_datetime(pd.Series([r.get("timestamp") for r in kept], dtype=object),
                            errors="coerce", format="mixed", utc=True)
        for r, bad in zip(kept, ts.isna().to_numpy()):
            if bad:
                flags["unparsed_timestamp"][_label_key(r)] += 1

    copies = 0
    if cfg["drop_exact_packet_copies"]:
        seen, unique = set(), []
        for r in kept:
            key = (r.get(_name_field(r)),) + tuple(r.get(f) for f in PACKET_KEY[1:])
            if all(v not in (None, "") for v in key):
                key = tuple(str(v) for v in key)
                if key in seen:
                    copies += 1
                    continue
                seen.add(key)
            unique.append(r)
        kept = unique

    report = {
        "input_rows": len(records),
        "kept_rows": len(kept),
        "rejected_rows": len(rejected),
        "rejected_by_reason": dict(Counter(r["reject_reason"] for r in rejected)),
        "exact_packet_copies_dropped": copies,
        "normalised_values": dict(normalised),
        "flags": {k: {"rows": sum(c.values()), "by_label": dict(c)} for k, c in flags.items()},
        "rules": {k: cfg[k] for k in ("max_name_length", "max_label_length", "drop_exact_packet_copies")},
    }
    return kept, rejected, report
