"""
dnstunnel2026.py — Path C input: DNSTunnel2026's 38 window features from native query rows.

DNSTunnel2026 (Zenodo, CC BY 4.0) is a pre-aggregated table: one row per <company, domain,
5-minute window> (1-minute step), 38 numeric features, no query names. Its train.csv cannot go
through train_models.sh (no `domain` column), so a model trained on it can only score LIVE traffic
if that traffic is first converted into the same 38 columns. This module is that converter.

Mapping onto this project's data (documented approximations — the dataset README defines the
features in words, not code; see docs/Week7/PATH_C_DNSTUNNEL2026.md):
  company   → `client_ip` by default (one lab client = one company). `company_col` changes it.
  domain    → the registered parent domain (ingest.labeling.parent_domain, PSL-based).
  FQDN      → the full query name.
  window    → (T - 300 s, T], T on every 60-second tick (window_seconds / step_seconds).
  24 h      → (T - 86400 s, T] (history_seconds).
  record    → for top1_records_* the most-queried FQDN of the group (the README says "most
              frequently queried DNS record"; the published rows are not fully consistent).
  file_chunk_detection_* → a readability model on the SUBDOMAIN part of each distinct FQDN:
              the authors' fastText model (dga_quantized_model.bin, labels __label__dga /
              __label__notdga) when the `fasttext` package and the file are available, otherwise
              an entropy/length heuristic. The source is recorded in `Readability.source`.

Public API
  FEATURES_C                 the 38 column names, in the dataset's order (`hits` first).
  Readability(...)           subdomain → chunk-positive flags (fastText or heuristic).
  window_features(df, ...)   → (windows DataFrame, membership) where membership is an (n_pairs, 2)
                             int array of [row index in df, row index in windows]: every query row
                             appears in up to window/step windows. Rows without a timestamp or a
                             parsable domain appear in none.
  rows_from_windows(n, membership, values, how="max")
                             → (per-row value, covered mask): each query takes the max (or first)
                             value of the windows that contain it.

Every number is computed from the rows given, so training (merged labelled file) and detection
(week3 features of one log) go through exactly the same code — the project's rule for Path A/B.
"""

from __future__ import annotations

import math
import os
from collections import Counter
from typing import Iterable

import numpy as np
import pandas as pd

WINDOW_SECONDS = 300
STEP_SECONDS = 60
HISTORY_SECONDS = 86_400

RECORD_TYPES = ["A", "AAAA", "TXT", "SOA", "NS", "MX", "DS", "CNAME", "HTTPS"]   # OTHER = the rest

FEATURES_C = (
    ["hits", "domain_data_portion", "fqdn_count", "fqdn_hit_ratio", "unique_dns_types"]
    + [f"dns_type_{t}_{k}" for t in RECORD_TYPES + ["OTHER"] for k in ("count", "ratio")]
    + ["top1_records_count", "top1_records_ratio",
       "other_comp_last_24_fqdn_count", "other_comp_last_24_fqdn_hit_ratio",
       "other_comp_last_24_hits", "other_comp_last_24_unique_company",
       "other_comp_window_fqdn_count", "other_comp_window_fqdn_hit_ratio",
       "other_comp_window_hits", "other_comp_window_unique_company",
       "file_chunk_detection_positive", "file_chunk_detection_negative",
       "file_chunk_detection_positive_ratio"]
)
assert len(FEATURES_C) == 38

KEY_COLUMNS = ["company", "parent_domain", "window_end"]


# ─────────────────────────────────────────────
# readability (file-chunk) model
# ─────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def heuristic_chunk_positive(subdomain: str, min_len: int = 10, min_entropy: float = 3.2) -> bool:
    """Fallback readability rule: long, high-entropy subdomain strings look like encoded chunks.
    Thresholds are deliberately below labeling.yaml's long_encoded_labels rule (40 chars / 4.0 bits):
    DNSTunnel2026 includes short-chunk scenarios (min_length configurations)."""
    s = str(subdomain).replace(".", "")
    return len(s) >= min_len and _entropy(s) >= min_entropy


class Readability:
    """Subdomain → chunk-positive flag. fastText when possible, heuristic otherwise.

    `source` is "fasttext:<file>" or "heuristic". Results are cached per distinct subdomain.
    The fastText input form is the raw subdomain string (dots kept); `text_form="spaces"` replaces
    dots by spaces. The authors did not publish the form they used — record which one a model was
    trained/validated with (path_c meta) and keep it fixed at inference.
    """

    def __init__(self, model_path: str | None = None, text_form: str = "raw", positive_label: str = "__label__dga"):
        self.text_form = text_form
        self.positive_label = positive_label
        self._cache: dict[str, bool] = {"": False}
        self._ft = None
        self.source = "heuristic"
        if model_path and os.path.exists(model_path):
            try:
                import fasttext  # type: ignore
                self._ft = fasttext.load_model(model_path)
                self.source = f"fasttext:{os.path.basename(model_path)}"
            except Exception as e:  # noqa: BLE001 — fall back, but say so
                self.source = f"heuristic (fasttext unavailable: {type(e).__name__})"

    def _text(self, sub: str) -> str:
        return sub.replace(".", " ") if self.text_form == "spaces" else sub

    def positive(self, subdomains: Iterable[str]) -> np.ndarray:
        subs = [str(s) for s in subdomains]
        todo = [s for s in set(subs) if s not in self._cache]
        if todo:
            if self._ft is not None:
                labels, _ = self._ft.predict([self._text(s) for s in todo])
                for s, lab in zip(todo, labels):
                    self._cache[s] = self.positive_label in lab
            else:
                for s in todo:
                    self._cache[s] = heuristic_chunk_positive(s)
        return np.fromiter((self._cache[s] for s in subs), dtype=bool, count=len(subs))


# ─────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────

def _parent_and_sub(domains: pd.Series):
    from dns_detect.ingest.labeling import parent_domain, subdomain_part
    parents = domains.map(parent_domain)
    subs = pd.Series([subdomain_part(d, p) for d, p in zip(domains, parents)], index=domains.index)
    return parents, subs


def _epoch(ts: pd.Series) -> np.ndarray:
    from dns_detect.features.aggregates import epoch_seconds
    return epoch_seconds(ts)


def _domain_series(df: pd.DataFrame) -> pd.Series:
    from dns_detect.features.aggregates import domain_series
    return domain_series(df)


def _qtype(df: pd.DataFrame) -> pd.Series:
    col = next((c for c in ("query_type", "qtype", "record_type") if c in df.columns), None)
    if col is None:
        return pd.Series(["A"] * len(df), index=df.index)
    return df[col].fillna("A").astype(str).str.strip().str.upper()


# ─────────────────────────────────────────────
# main conversion
# ─────────────────────────────────────────────

def window_features(df: pd.DataFrame, readability: Readability | None = None, *,
                    company_col: str = "client_ip", window_seconds: int = WINDOW_SECONDS,
                    step_seconds: int = STEP_SECONDS, history_seconds: int = HISTORY_SECONDS):
    """
    Native query rows → DNSTunnel2026 window rows.

    Returns (windows, membership):
      windows     DataFrame with KEY_COLUMNS, FEATURES_C and, when `label` is in df, `label`
                  (1 if any query in the group is attack), `attack_rows` and `attack_family`
                  (most common family among the group's attack rows, else "benign").
      membership  int array (n_pairs, 2): [query row position in df, window row position].
    """
    if readability is None:
        readability = Readability()
    n = len(df)
    if n == 0:
        return _empty_windows(df), np.zeros((0, 2), dtype=int)

    dom = _domain_series(df)
    parents, subs = _parent_and_sub(dom)
    t = _epoch(df["timestamp"]) if "timestamp" in df.columns else np.full(n, np.nan)
    company = (df[company_col].astype(str).to_numpy() if company_col in df.columns
               else np.array(["?"] * n))
    qtype = _qtype(df).to_numpy()
    ok = ~np.isnan(t) & (dom.to_numpy() != "") & (parents.to_numpy() != "")
    if not ok.any():
        return _empty_windows(df), np.zeros((0, 2), dtype=int)

    base = pd.DataFrame({
        "row": np.arange(n)[ok],
        "t": t[ok],
        "company": company[ok],
        "parent_domain": parents.to_numpy()[ok],
        "fqdn": dom.to_numpy()[ok],
        "sub": subs.to_numpy()[ok],
        "qtype": qtype[ok],
    })
    if "label" in df.columns:
        base["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int).to_numpy()[ok]
        base["family"] = (df["attack_family"].fillna("benign").astype(str).to_numpy()[ok]
                          if "attack_family" in df.columns else np.where(base["label"] == 1, "attack", "benign"))

    # Every query belongs to window/step consecutive ticks: T0 = first tick >= t, then T0 + k·step.
    k = max(1, window_seconds // step_seconds)
    t0 = np.ceil(base["t"].to_numpy() / step_seconds) * step_seconds
    rep = base.loc[base.index.repeat(k)].reset_index(drop=True)
    rep["window_end"] = np.repeat(t0, k) + np.tile(np.arange(k) * step_seconds, len(base))

    keys = ["window_end", "company", "parent_domain"]
    g = rep.groupby(keys, sort=True)
    win = g.size().rename("hits").reset_index()
    win["fqdn_count"] = g["fqdn"].nunique().to_numpy()
    win["fqdn_hit_ratio"] = win["hits"] / win["fqdn_count"]
    win["unique_dns_types"] = g["qtype"].nunique().to_numpy()

    # record-type profile: counts per listed type, OTHER = the rest; ratios over the group's hits
    for rt in RECORD_TYPES:
        win[f"dns_type_{rt}_count"] = g["qtype"].apply(lambda s, rt=rt: int((s == rt).sum())).to_numpy()
    win["dns_type_OTHER_count"] = win["hits"] - sum(win[f"dns_type_{rt}_count"] for rt in RECORD_TYPES)
    for rt in RECORD_TYPES + ["OTHER"]:
        win[f"dns_type_{rt}_ratio"] = win[f"dns_type_{rt}_count"] / win["hits"]

    # most-queried FQDN of the group
    top1 = rep.groupby(keys + ["fqdn"]).size().groupby(level=[0, 1, 2]).max()
    win["top1_records_count"] = top1.to_numpy()
    win["top1_records_ratio"] = win["top1_records_count"] / win["hits"]

    # share of the company's traffic in this window that went to this domain
    comp_total = rep.groupby(["window_end", "company"]).size().rename("comp_total").reset_index()
    win = win.merge(comp_total, on=["window_end", "company"], how="left")
    win["domain_data_portion"] = win["hits"] / win["comp_total"]

    # other companies, same window: hits, unique companies, distinct FQDNs not exclusive to us
    per_wp = rep.groupby(["window_end", "parent_domain"]).agg(
        wp_hits=("fqdn", "size"), wp_fqdn=("fqdn", "nunique"), wp_comp=("company", "nunique")).reset_index()
    win = win.merge(per_wp, on=["window_end", "parent_domain"], how="left")
    c_all = rep.groupby(["window_end", "parent_domain", "fqdn"]).size().rename("c_all")
    c_self = rep.groupby(keys + ["fqdn"]).size().rename("c_self").reset_index()
    c_self = c_self.join(c_all, on=["window_end", "parent_domain", "fqdn"])
    exclusive = (c_self[c_self["c_self"] == c_self["c_all"]]
                 .groupby(keys).size().rename("fqdn_exclusive").reset_index())
    win = win.merge(exclusive, on=keys, how="left").fillna({"fqdn_exclusive": 0})
    win["other_comp_window_hits"] = win["wp_hits"] - win["hits"]
    win["other_comp_window_unique_company"] = win["wp_comp"] - 1
    win["other_comp_window_fqdn_count"] = win["wp_fqdn"] - win["fqdn_exclusive"].astype(int)
    win["other_comp_window_fqdn_hit_ratio"] = np.where(
        win["other_comp_window_fqdn_count"] > 0,
        win["other_comp_window_hits"] / win["other_comp_window_fqdn_count"].replace(0, 1), 0.0)

    # other companies, last 24 h: per (window_end, parent) slice of that parent's time-sorted rows
    h24 = _history_features(base, win, history_seconds)
    for c in ("other_comp_last_24_fqdn_count", "other_comp_last_24_fqdn_hit_ratio",
              "other_comp_last_24_hits", "other_comp_last_24_unique_company"):
        win[c] = h24[c]

    # readability of the group's distinct subdomains
    distinct = rep.drop_duplicates(keys + ["fqdn"])[keys + ["sub"]].copy()
    distinct["pos"] = readability.positive(distinct["sub"].to_numpy())
    pos = distinct.groupby(keys)["pos"].sum().rename("file_chunk_detection_positive").reset_index()
    win = win.merge(pos, on=keys, how="left").fillna({"file_chunk_detection_positive": 0})
    win["file_chunk_detection_positive"] = win["file_chunk_detection_positive"].astype(int)
    win["file_chunk_detection_negative"] = win["fqdn_count"] - win["file_chunk_detection_positive"]
    win["file_chunk_detection_positive_ratio"] = win["file_chunk_detection_positive"] / win["fqdn_count"]

    if "label" in base.columns:
        lab = rep.groupby(keys).agg(label=("label", "max"), attack_rows=("label", "sum")).reset_index()
        win = win.merge(lab, on=keys, how="left")
        fam = (rep[rep["label"] == 1].groupby(keys)["family"]
               .agg(lambda s: s.value_counts().index[0]).rename("attack_family").reset_index())
        win = win.merge(fam, on=keys, how="left").fillna({"attack_family": "benign"})

    # membership: query row → window row
    win = win.reset_index(drop=True)
    win["wid"] = np.arange(len(win))
    m = rep.merge(win[keys + ["wid"]], on=keys, how="left")
    membership = np.column_stack([m["row"].to_numpy(dtype=int), m["wid"].to_numpy(dtype=int)])

    cols = KEY_COLUMNS + FEATURES_C + [c for c in ("label", "attack_rows", "attack_family") if c in win.columns]
    out = win[cols].copy()
    for c in FEATURES_C:
        out[c] = pd.to_numeric(out[c], errors="coerce").fillna(0.0).astype(float)
    return out, membership


def _history_features(base: pd.DataFrame, win: pd.DataFrame, history_seconds: int) -> pd.DataFrame:
    """other_comp_last_24_* for every window row, from the parent's rows in (T - history, T]."""
    out = {c: np.zeros(len(win), dtype=float) for c in (
        "other_comp_last_24_fqdn_count", "other_comp_last_24_fqdn_hit_ratio",
        "other_comp_last_24_hits", "other_comp_last_24_unique_company")}
    by_parent = {}
    for p, grp in base.groupby("parent_domain", sort=False):
        order = np.argsort(grp["t"].to_numpy(), kind="stable")
        by_parent[p] = (grp["t"].to_numpy()[order], grp["company"].to_numpy()[order], grp["fqdn"].to_numpy()[order])
    cache: dict[tuple, tuple] = {}
    T = win["window_end"].to_numpy(dtype=float)
    P = win["parent_domain"].to_numpy()
    C = win["company"].to_numpy()
    for i in range(len(win)):
        key = (P[i], T[i])
        if key not in cache:
            ts, comps, fqdns = by_parent[P[i]]
            lo = np.searchsorted(ts, T[i] - history_seconds, side="right")
            hi = np.searchsorted(ts, T[i], side="right")
            cache[key] = (comps[lo:hi], fqdns[lo:hi])
        comps, fqdns = cache[key]
        other = comps != C[i]
        n_other = int(other.sum())
        if n_other:
            fq = np.unique(fqdns[other]).size
            out["other_comp_last_24_hits"][i] = n_other
            out["other_comp_last_24_fqdn_count"][i] = fq
            out["other_comp_last_24_fqdn_hit_ratio"][i] = n_other / fq if fq else 0.0
            out["other_comp_last_24_unique_company"][i] = np.unique(comps[other]).size
    return pd.DataFrame(out)


def _empty_windows(df: pd.DataFrame) -> pd.DataFrame:
    cols = KEY_COLUMNS + FEATURES_C + (["label", "attack_rows", "attack_family"] if "label" in df.columns else [])
    return pd.DataFrame({c: pd.Series(dtype=float if c in FEATURES_C else object) for c in cols})


def rows_from_windows(n_rows: int, membership: np.ndarray, values: np.ndarray, how: str = "max"):
    """
    Per-query value from per-window values. `how`: "max" (default; detection: the worst window a
    query took part in), "first" (the earliest window containing the query, i.e. the one ending at
    the first tick after it — the value available soonest in a stream).
    Returns (values[n_rows] with NaN where uncovered, covered[n_rows] bool).
    """
    out = np.full(n_rows, np.nan, dtype=float)
    covered = np.zeros(n_rows, dtype=bool)
    if membership.size == 0:
        return out, covered
    rows, wids = membership[:, 0], membership[:, 1]
    v = np.asarray(values, dtype=float)[wids]
    if how == "first":
        # membership is ordered by query row then by increasing window_end, so the first pair wins
        first = np.ones(len(rows), dtype=bool)
        first[1:] = rows[1:] != rows[:-1]
        out[rows[first]] = v[first]
        covered[rows[first]] = True
        return out, covered
    out = np.full(n_rows, -np.inf, dtype=float)
    np.maximum.at(out, rows, v)
    covered[rows] = True
    out[~covered] = np.nan
    return out, covered
