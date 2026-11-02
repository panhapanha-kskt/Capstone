"""
aggregates.py — Behaviour features over a sliding time window (ML_IMPROVEMENT_GUIDE Step 3).

Per-query features cannot see what makes a tunnel a tunnel: many unique, once-used
subdomains under one parent domain, a steady stream of data, regular timing
(Nadler et al. 2019; Ozery et al., NDSS 2024). These features describe the traffic
around each query.

Leakage rule: a query's window is (t − W, t] and contains only queries at or before it
in time order (ties broken by file order). Nothing after a query ever changes its
features, so training and live detection compute identical values.

One code path: `add_window_features` is called by Path A training, Path A / bridge
inference, Path B loading and the CV driver. `BigramModel` is fitted on training benign
rows only and saved with the model.
"""

from __future__ import annotations

import json
import math
from collections import Counter, deque

import numpy as np
import pandas as pd

WINDOW_SECONDS = 300
TUNNEL_RR = {"TXT", "NULL", "KEY"}

FEATURES_WINDOW = [
    "uniq_subdomains_5m",   # distinct subdomains under the parent domain in the window
    "uniq_ratio_5m",        # distinct subdomains ÷ queries for that parent
    "info_chars_per_min",   # characters carried by distinct subdomains, per minute
    "nxdomain_share_5m",    # client's share of NXDOMAIN answers
    "qpm_client_5m",        # client's queries per minute
    "iat_std_5m",           # std. dev. of seconds between queries (client + parent); -1 if < 3 queries
    "tunnel_rr_share_5m",   # client's share of TXT/NULL/KEY queries
]
FEATURES_AGG = FEATURES_WINDOW + ["bigram_logprob"]


# ─────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────

def _parent_and_sub(domain: str):
    from dns_detect.ingest.labeling import parent_domain, subdomain_part  # local: avoids import cycle
    p = parent_domain(domain)
    return p, subdomain_part(domain, p)


def domain_series(df: pd.DataFrame) -> pd.Series:
    """Lower-cased query name from whichever column the record format uses."""
    for col in ("domain", "query", "qname", "query_name"):
        if col in df.columns:
            return df[col].fillna("").astype(str).str.lower().str.rstrip(".")
    return pd.Series([""] * len(df), index=df.index)


def epoch_seconds(series: pd.Series) -> np.ndarray:
    """Timestamps → float seconds since epoch (naive strings are read as UTC). NaT → NaN."""
    ts = pd.to_datetime(series, errors="coerce", utc=True, format="mixed")
    return (ts - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds().to_numpy(dtype=float)


# ─────────────────────────────────────────────
# sliding-window features
# ─────────────────────────────────────────────

def add_window_features(df: pd.DataFrame, window_seconds: int = WINDOW_SECONDS) -> pd.DataFrame:
    """Return a copy of `df` with FEATURES_WINDOW columns added. Labels are never read."""
    out = df.copy()
    n = len(out)
    if n == 0:
        for c in FEATURES_WINDOW:
            out[c] = pd.Series(dtype=float)
        return out

    domains = domain_series(out).to_numpy()
    parents, subs = zip(*(_parent_and_sub(d) for d in domains)) if n else ((), ())
    parents, subs = np.asarray(parents, dtype=object), np.asarray(subs, dtype=object)
    clients = (out["client_ip"].fillna("?").astype(str).to_numpy()
               if "client_ip" in out.columns else np.array(["?"] * n, dtype=object))
    qtypes = (out["query_type"].fillna("").astype(str).str.upper().to_numpy()
              if "query_type" in out.columns else np.array([""] * n, dtype=object))
    rcodes = (out["response_code"].fillna("").astype(str).str.lower().to_numpy()
              if "response_code" in out.columns else np.array([""] * n, dtype=object))
    t = epoch_seconds(out["timestamp"]) if "timestamp" in out.columns else np.full(n, np.nan)

    uniq = np.ones(n)
    ratio = np.ones(n)
    info = np.array([len(s) for s in subs], dtype=float) / (window_seconds / 60.0)
    nx = (rcodes == "nxdomain").astype(float)
    qpm = np.full(n, 1.0 / (window_seconds / 60.0))
    iat = np.full(n, -1.0)
    rr = np.isin(qtypes, list(TUNNEL_RR)).astype(float)
    uniq[np.array([s == "" for s in subs])] = 0.0

    valid = ~np.isnan(t)
    # Stable time order; equal timestamps keep file order, so "past" is well defined.
    order = np.lexsort((np.arange(n), np.where(valid, t, np.inf)))
    order = order[valid[order]]
    minutes = window_seconds / 60.0

    # Per parent domain: distinct subdomains, ratio, information volume.
    by_parent: dict = {}
    for i in order:
        by_parent.setdefault(parents[i], []).append(i)
    for idx in by_parent.values():
        win: deque = deque()
        cnt: Counter = Counter()
        chars = 0
        for i in idx:
            win.append(i)
            s = subs[i]
            if s:
                if cnt[s] == 0:
                    chars += len(s)
                cnt[s] += 1
            while t[win[0]] <= t[i] - window_seconds:
                j = win.popleft()
                sj = subs[j]
                if sj:
                    cnt[sj] -= 1
                    if cnt[sj] == 0:
                        del cnt[sj]
                        chars -= len(sj)
            uniq[i] = len(cnt)
            ratio[i] = len(cnt) / len(win)
            info[i] = chars / minutes

    # Per client: NXDOMAIN share, rate, tunnel record-type share.
    by_client: dict = {}
    for i in order:
        by_client.setdefault(clients[i], []).append(i)
    is_nx = rcodes == "nxdomain"
    is_rr = np.isin(qtypes, list(TUNNEL_RR))
    for idx in by_client.values():
        win = deque()
        n_nx = n_rr = 0
        for i in idx:
            win.append(i)
            n_nx += int(is_nx[i])
            n_rr += int(is_rr[i])
            while t[win[0]] <= t[i] - window_seconds:
                j = win.popleft()
                n_nx -= int(is_nx[j])
                n_rr -= int(is_rr[j])
            m = len(win)
            nx[i] = n_nx / m
            rr[i] = n_rr / m
            qpm[i] = m / minutes

    # Per (client, parent): timing regularity, via running sums of consecutive gaps.
    by_pair: dict = {}
    for i in order:
        by_pair.setdefault((clients[i], parents[i]), []).append(i)
    for idx in by_pair.values():
        win = deque()
        s1 = s2 = 0.0
        for i in idx:
            if win:
                d = t[i] - t[win[-1]]
                s1 += d
                s2 += d * d
            win.append(i)
            while t[win[0]] <= t[i] - window_seconds:
                j = win.popleft()
                if win:
                    d = t[win[0]] - t[j]
                    s1 -= d
                    s2 -= d * d
            k = len(win) - 1  # number of gaps
            if k >= 2:
                mean = s1 / k
                iat[i] = math.sqrt(max(s2 / k - mean * mean, 0.0))

    out["uniq_subdomains_5m"] = uniq
    out["uniq_ratio_5m"] = ratio
    out["info_chars_per_min"] = info
    out["nxdomain_share_5m"] = nx
    out["qpm_client_5m"] = qpm
    out["iat_std_5m"] = iat
    out["tunnel_rr_share_5m"] = rr
    return out


# ─────────────────────────────────────────────
# character-pair (bigram) language model
# ─────────────────────────────────────────────

class BigramModel:
    """
    Add-α smoothed character-bigram model of benign query names.
    score = mean log P(next char | char) over the name, with '^' / '$' marking label edges.
    Encoded data and DGA names score low because their character pairs are rare in real names.
    """

    VOCAB = 40  # a–z, 0–9, '-', '_', '^', '$'

    def __init__(self, alpha: float = 1.0):
        self.alpha = alpha
        self.pairs: Counter = Counter()
        self.firsts: Counter = Counter()

    @staticmethod
    def _tokens(name: str):
        for label in str(name).lower().rstrip(".").split("."):
            if label:
                s = "^" + label + "$"
                for a, b in zip(s, s[1:]):
                    yield a, b

    def fit(self, names) -> "BigramModel":
        for name in names:
            for a, b in self._tokens(name):
                self.pairs[a + b] += 1
                self.firsts[a] += 1
        return self

    def score(self, name: str) -> float:
        total, k = 0.0, 0
        for a, b in self._tokens(name):
            total += math.log((self.pairs.get(a + b, 0) + self.alpha)
                              / (self.firsts.get(a, 0) + self.alpha * self.VOCAB))
            k += 1
        return total / k if k else 0.0

    def score_many(self, names) -> np.ndarray:
        cache: dict = {}
        out = []
        for name in names:
            if name not in cache:
                cache[name] = self.score(name)
            out.append(cache[name])
        return np.asarray(out, dtype=float)

    def to_dict(self) -> dict:
        return {"alpha": self.alpha, "pairs": dict(self.pairs), "firsts": dict(self.firsts)}

    @classmethod
    def from_dict(cls, d: dict) -> "BigramModel":
        m = cls(alpha=float(d.get("alpha", 1.0)))
        m.pairs = Counter(d.get("pairs", {}))
        m.firsts = Counter(d.get("firsts", {}))
        return m

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f)

    @classmethod
    def load(cls, path: str) -> "BigramModel":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


def add_aggregate_features(df: pd.DataFrame, bigram: BigramModel | None,
                           window_seconds: int = WINDOW_SECONDS, features=None) -> pd.DataFrame:
    """Window features plus `bigram_logprob` (0.0 when no fitted bigram model is given)."""
    features = list(features) if features is not None else FEATURES_AGG
    out = df
    if any(f in FEATURES_WINDOW for f in features) and not all(f in df.columns for f in FEATURES_WINDOW):
        out = add_window_features(df, window_seconds)
    if "bigram_logprob" in features:
        out = out.copy() if out is df else out
        out["bigram_logprob"] = bigram.score_many(domain_series(out)) if bigram is not None else 0.0
    return out
