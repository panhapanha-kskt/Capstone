"""
Tier 1 triage evidence: alert grouping into cases, DNS evidence from the per-query feature file,
the auto-evaluated DNS-tunnel checklist, the ML "why" panel, and enrichment (offline Tranco + IP flags;
optional VirusTotal / AbuseIPDB). Standard library only; no shared state with server.py except what is
passed in.

Checklist thresholds follow Elastic's "Potential DNS Tunneling via Long and Unique Subdomains"
investigation guide and SigmaHQ's DNS tunnelling rules (see docs/Week6/TIER1_TRIAGE_REPORT.md).
"""

import hashlib
import ipaddress
import json
import math
import queue
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".corp", ".home.arpa", ".localdomain", ".test")
BASELINE_FEATURES = ("query_length", "entropy", "subdomain_depth", "longest_label", "digit_ratio",
                     "query_rate", "first_label_length")
RARE_QTYPES = ("TXT", "NULL", "CNAME", "MX", "SRV", "ANY")
BENIGN_KEYWORDS = ("cdn", "akamai", "cloudfront", "fastly", "edgekey", "azureedge", "amazonaws", "googleapis",
                   "gstatic", "windowsupdate", "update", "ocsp", "crl", "pki", "digicert", "letsencrypt",
                   "sophos", "mcafee", "trendmicro", "spamhaus", "senderbase", "apple", "microsoft", "office")
ZSCORE_RE = re.compile(r"(\w+) Z-score = (-?[\d.]+) \(value: (-?[\d.]+), baseline mean: (-?[\d.]+)\)")
HEX_LABEL_RE = re.compile(r"^[0-9a-f]{16,}$")
# Elastic guide thresholds
LONG_LABEL = 50
VOLUME_QUERIES, VOLUME_DISTINCT, VOLUME_WINDOW = 25, 15, 300
NULL_MIN = 3


# ──────────────────────────────────────────────────────────────
# Grouping
# ──────────────────────────────────────────────────────────────
def _labels(domain):
    return [l for l in str(domain or "").lower().rstrip(".").split(".") if l]


def has_domain(domain):
    return str(domain or "").strip().lower() not in ("", "n/a", "unknown", "multiple", "none")


def is_internal(domain, internal_zones=()):
    d = ".".join(_labels(domain))
    if not d:
        return False
    zones = [z.lower().strip(".") for z in internal_zones]
    return any(d == z or d.endswith("." + z) for z in zones) or any(("." + d).endswith(s) for s in INTERNAL_SUFFIXES)


def case_apex(domain, internal_zones=()):
    """Registered domain (last two labels); one more label inside internal zones, where everything
    shares the same parent (e.g. *.lab.local)."""
    labels = _labels(domain)
    if len(labels) < 2:
        return ".".join(labels) or None
    apex = ".".join(labels[-2:])
    if is_internal(apex, internal_zones) and len(labels) >= 3:
        apex = ".".join(labels[-3:])
    return apex


def rule_family(rule_name):
    r = str(rule_name or "").lower()
    if "z-score" in r or "statistical" in r:
        return "zscore"
    if r.startswith("ml ") or "ml model" in r or r.startswith("ml"):
        return "ml"
    if "nxdomain" in r:
        return "nxdomain"
    return "heuristic"


FAMILY_LABEL = {"zscore": "Statistical (Z-score) anomalies", "ml": "ML model detections",
                "nxdomain": "NXDOMAIN bursts", "heuristic": "Rule-based detections"}


def group_of(alert, mode, internal_zones=()):
    ip = str(alert.get("client_ip") or "unknown")
    fam = rule_family(alert.get("rule_name"))
    if mode == "source":
        part = fam
    elif fam == "nxdomain" or not has_domain(alert.get("domain")):
        part = "nxdomain" if fam == "nxdomain" else "(no domain)"
    else:
        part = case_apex(alert.get("domain"), internal_zones) or "(no domain)"
    key = "c-" + hashlib.sha1(f"{mode}|{ip}|{part}".encode("utf-8")).hexdigest()[:12]
    return key, ip, part


def group_alerts(alerts, mode, internal_zones=()):
    """[(alert, fp)] -> {key: {"key", "mode", "client", "group", "items": [(alert, fp), ...]}}"""
    cases = {}
    for alert, fp in alerts:
        key, ip, part = group_of(alert, mode, internal_zones)
        c = cases.get(key)
        if c is None:
            c = cases[key] = {"key": key, "mode": mode, "client": ip, "group": part,
                              "label": FAMILY_LABEL.get(part, part) if mode == "source" else part, "items": []}
        c["items"].append((alert, fp))
    return cases


# ──────────────────────────────────────────────────────────────
# IP flags and Tranco (offline enrichment)
# ──────────────────────────────────────────────────────────────
def ip_flags(ip, resolvers=()):
    """Flags that matter at Tier 1: a shared source (resolver/NAT/gateway/loopback) hides the real host."""
    s = str(ip or "").strip()
    if s in ("multiple", "unknown", ""):
        return {"valid": False, "shared": s == "multiple", "flags": [s or "unknown"],
                "warning": "Source is not a single host." if s else None}
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return {"valid": False, "shared": False, "flags": ["invalid"], "warning": None}
    flags = []
    if a.is_loopback:
        flags.append("loopback")
    if a.is_private:
        flags.append("private")
    if a.is_link_local:
        flags.append("link-local")
    if a.is_multicast or a.is_reserved:
        flags.append("reserved")
    if a.version == 4 and a in ipaddress.ip_network("172.16.0.0/12") and s.endswith(".1"):
        flags.append("docker-gateway")
    if s in set(resolvers):
        flags.append("resolver")
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        flags.append("cgnat")
    shared = any(f in flags for f in ("loopback", "docker-gateway", "resolver", "cgnat"))
    return {"valid": True, "global": a.is_global, "shared": shared, "flags": flags,
            "warning": ("Shared source (resolver / NAT / gateway / loopback): many clients look like one. "
                        "Find the real endpoint before closing, and never allowlist this IP.") if shared else None}


class Tranco:
    """Optional local Tranco top-sites list (CSV 'rank,domain', manually downloaded from tranco-list.eu).
    Only the first `top_n` rows are kept in memory."""

    def __init__(self, path, top_n=100_000):
        self.path, self.top_n = Path(path), int(top_n)
        self._lock = threading.Lock()
        self._sig = None
        self._ranks = {}

    def _load(self):
        try:
            st = self.path.stat()
        except OSError:
            self._sig, self._ranks = None, {}
            return
        sig = (st.st_mtime, st.st_size, self.top_n)
        if sig == self._sig:
            return
        ranks = {}
        with open(self.path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= self.top_n:
                    break
                parts = line.strip().split(",")
                if len(parts) >= 2 and parts[0].isdigit():
                    ranks.setdefault(parts[1].lower().strip("."), int(parts[0]))
        self._sig, self._ranks = sig, ranks

    def available(self):
        with self._lock:
            self._load()
            return bool(self._ranks)

    def rank(self, domain):
        """Rank of the domain or its closest listed parent, else None."""
        with self._lock:
            self._load()
            labels = _labels(domain)
            for i in range(len(labels) - 1):
                r = self._ranks.get(".".join(labels[i:]))
                if r:
                    return {"rank": r, "listed_as": ".".join(labels[i:])}
        return None


# ──────────────────────────────────────────────────────────────
# Per-query feature index
# ──────────────────────────────────────────────────────────────
def _f(v):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if math.isfinite(x) else None


def _ts(v):
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _truthy(v):
    return v is True or str(v).lower() in ("true", "1", "yes")


def _flag(v):
    """Model label: True / 1 / 1.0 / "ATTACK" -> True."""
    return _truthy(v) or (_f(v) or 0) >= 1 or str(v).upper() == "ATTACK"


class FeatureIndex:
    """Lazy, mtime-cached index over data/processed/week3_features_with_ml.json (rewritten each run).
    Has its own lock; callers must not hold the dashboard's STATE/STORE locks while calling get()."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._sig = None
        self._snap = None

    def get(self):
        try:
            st = self.path.stat()
        except OSError:
            return None
        sig = (st.st_mtime, st.st_size)
        with self._lock:
            if sig != self._sig:
                self._snap = self._build()
                self._sig = sig
            return self._snap

    def _build(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                rows = json.load(f)
        except (OSError, ValueError):
            return None
        if isinstance(rows, dict):
            rows = rows.get("records") or rows.get("features") or []
        by_pair, by_client = defaultdict(list), defaultdict(list)
        for r in rows:
            if not isinstance(r, dict):
                continue
            ip = str(r.get("client_ip") or "")
            dom = str(r.get("domain") or "").lower().rstrip(".")
            by_pair[(ip, dom)].append(r)
            by_client[ip].append(r)
        baseline = {}
        for ip, rs in by_client.items():
            b = {}
            for feat in BASELINE_FEATURES:
                vals = [x for x in (_f(r.get(feat)) for r in rs) if x is not None]
                if len(vals) >= 5:
                    mu = sum(vals) / len(vals)
                    sd = math.sqrt(sum((v - mu) ** 2 for v in vals) / (len(vals) - 1))
                    b[feat] = (mu, sd)
            baseline[ip] = b
        return {"rows": len(rows), "by_pair": dict(by_pair), "by_client": dict(by_client),
                "baseline": baseline, "loaded_at": time.time()}


def case_rows(snap, case, internal_zones=(), limit=20000):
    """Feature rows behind a case: exact (client, domain) matches of member alerts; in entity mode also
    every query from the client under the case apex."""
    if not snap:
        return []
    seen, out = set(), []

    def add(rs):
        for r in rs:
            if id(r) not in seen and len(out) < limit:
                seen.add(id(r))
                out.append(r)

    client = case["client"]
    for alert, _ in case["items"]:
        add(snap["by_pair"].get((str(alert.get("client_ip") or ""), str(alert.get("domain") or "").lower().rstrip(".")), []))
    if case["mode"] == "entity" and case["group"] not in ("nxdomain", "(no domain)"):
        apex = case["group"]
        for r in snap["by_client"].get(client, []):
            d = str(r.get("domain") or "").lower()
            if d == apex or d.endswith("." + apex):
                add([r])
    elif case["mode"] == "source" and case["group"] == "nxdomain":
        add([r for r in snap["by_client"].get(client, []) if str(r.get("response_code")) == "NxDomain"][:limit])
    return out


# ──────────────────────────────────────────────────────────────
# Evidence + checklist + ML panel
# ──────────────────────────────────────────────────────────────
def parse_zscore(description):
    m = ZSCORE_RE.search(str(description or ""))
    if not m:
        return None
    return {"feature": m.group(1), "z": float(m.group(2)), "value": float(m.group(3)),
            "baseline_mean": float(m.group(4))}


def _max_window(points, window):
    """points: sorted [(ts, name)] -> (max queries, max distinct names) in any `window`-second span."""
    best_n = best_d = 0
    names = Counter()
    j = 0
    for i, (t, name) in enumerate(points):
        names[name] += 1
        while points[j][0] < t - window:
            n2 = points[j][1]
            names[n2] -= 1
            if not names[n2]:
                del names[n2]
            j += 1
        best_n = max(best_n, i - j + 1)
        best_d = max(best_d, len(names))
    return best_n, best_d


def case_evidence(case, rows, demo=False):
    alerts = [a for a, _ in case["items"]]
    if rows:
        source = f"{len(rows)} queries from the per-query feature file"
        names = [str(r.get("domain") or "").lower() for r in rows]
        qtypes = Counter(str(r.get("query_type") or "?") for r in rows)
        rcodes = Counter(str(r.get("response_code") or "?") for r in rows)
        label_max = max((_f(r.get("longest_label")) or 0) for r in rows)
        qlens = [x for x in (_f(r.get("query_length")) for r in rows) if x is not None]
        enc = Counter(str(r.get("encoding_type")) for r in rows if str(r.get("encoding_type")) not in ("None", "", "none"))
        hex_n = sum(1 for n in names if any(HEX_LABEL_RE.match(l) for l in n.split(".")))
        high_ent = sum(1 for r in rows if _truthy(r.get("is_high_entropy")))
        rnd = sum(1 for r in rows if _truthy(r.get("is_random_subdomain")))
        allow = sum(1 for r in rows if _truthy(r.get("suppressed_by_allowlist")))
        rate = max(((_f(r.get("query_rate")) or 0) for r in rows), default=0)
        stamps = sorted((t, n) for t, n in ((_ts(r.get("timestamp")), n) for r, n in zip(rows, names)) if t is not None)
    else:
        source = "alert fields only (demo mode or no feature file)" if demo else "alert fields only (no matching queries in the feature file)"
        names = [str(a.get("domain") or "").lower() for a in alerts if has_domain(a.get("domain"))]
        qtypes = Counter(str((a.get("details") or {}).get("query_type") or "?") for a in alerts)
        rcodes = Counter()
        label_max = max((max((len(l) for l in n.split(".")), default=0) for n in names), default=0)
        qlens = [float(len(n)) for n in names]
        enc, hex_n, high_ent, rnd, allow, rate = Counter(), sum(1 for n in names if any(HEX_LABEL_RE.match(l) for l in n.split("."))), 0, 0, 0, 0
        stamps = sorted((t, n) for t, n in ((_ts(a.get("query_time")), str(a.get("domain") or "").lower()) for a in alerts) if t is not None)
    total = len(names)
    distinct = len(set(names))
    win_n, win_d = _max_window(stamps, VOLUME_WINDOW) if stamps else (0, 0)
    timeline = Counter(time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) for t, _ in stamps)
    samples = sorted(set(names), key=len, reverse=True)[:10]
    zs = [z for z in (parse_zscore(a.get("description")) for a in alerts) if z]
    nx = rcodes.get("NxDomain", 0)
    return {
        "source": source,
        "total_queries": total, "distinct_names": distinct,
        "query_types": dict(qtypes.most_common()), "response_codes": dict(rcodes.most_common()),
        "nxdomain_ratio": round(nx / sum(rcodes.values()), 3) if rcodes else None,
        "longest_label": int(label_max) if label_max else 0,
        "mean_query_length": round(sum(qlens) / len(qlens), 1) if qlens else None,
        "max_query_length": int(max(qlens)) if qlens else None,
        "encodings": dict(enc), "hex_labels": hex_n,
        "high_entropy": high_ent, "random_subdomain": rnd, "allowlisted": allow,
        "max_query_rate": round(rate, 4) if rate else None,
        "max_5min_queries": win_n, "max_5min_distinct": win_d,
        "first_seen": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stamps[0][0])) if stamps else None,
        "last_seen": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stamps[-1][0])) if stamps else None,
        "timeline": [{"minute": k, "count": v} for k, v in sorted(timeline.items())][-120:],
        "samples": samples,
        "zscores": {"count": len(zs), "max": max(zs, key=lambda z: abs(z["z"])) if zs else None,
                    "features": dict(Counter(z["feature"] for z in zs))},
        "rule_counts": dict(Counter(a.get("rule_name") for a in alerts).most_common()),
        "techniques": sorted({t for a in alerts for t in (a.get("mitre_techniques") or [])}),
    }


CHECKLIST = [
    # id, label, indicates (tunnel | benign | caution), required (manual items only)
    ("src_shared", "Source is a resolver / NAT / gateway / loopback (shared IP)", "caution", False),
    ("long_labels", f"Labels of {LONG_LABEL}+ characters", "tunnel", False),
    ("volume", f"{VOLUME_QUERIES}+ queries and {VOLUME_DISTINCT}+ distinct names in 5 minutes", "tunnel", False),
    ("rare_qtypes", "TXT / NULL / CNAME / MX queries present", "tunnel", False),
    ("encoding", "Encoded labels (base32 / base64 / hex)", "tunnel", False),
    ("randomness", "High-entropy or random subdomains", "tunnel", False),
    ("nxdomain", "Most answers are NXDOMAIN", "tunnel", False),
    ("ml_agree", "Both ML paths flag the traffic", "tunnel", False),
    ("popular", "Domain is in the Tranco top list", "benign", False),
    ("benign_like", "Name looks like CDN / cloud / certificate / update traffic", "benign", False),
    ("reputation", "Threat-intel reputation (VirusTotal / AbuseIPDB)", "tunnel", False),
    ("m_host_review", "Reviewed the other cases for this host (Pivots)", "manual", True),
    ("m_owner", "Checked the asset owner, change ticket or user", "manual", True),
]


def auto_checklist(case, ev, rows, ipf, tranco_hit, tranco_available, reputation):
    """{item_id: {"result": True|False|None, "detail": str}} for the automatic items."""
    out = {}
    qt = ev["query_types"]
    total = ev["total_queries"] or 0
    out["src_shared"] = {"result": bool(ipf.get("shared")), "detail": ", ".join(ipf.get("flags") or []) or "single host"}
    out["long_labels"] = {"result": ev["longest_label"] >= LONG_LABEL if total else None,
                          "detail": f"longest label {ev['longest_label']} chars"}
    out["volume"] = {"result": (ev["max_5min_queries"] >= VOLUME_QUERIES and ev["max_5min_distinct"] >= VOLUME_DISTINCT)
                     if total else None,
                     "detail": f"max {ev['max_5min_queries']} queries / {ev['max_5min_distinct']} distinct in 5 min"}
    rare = sum(v for k, v in qt.items() if k in RARE_QTYPES)
    out["rare_qtypes"] = {"result": (rare / total > 0.1 or qt.get("NULL", 0) >= NULL_MIN) if total and "?" not in qt else None,
                          "detail": ", ".join(f"{k} {v}" for k, v in qt.items()) or "no query types"}
    enc_n = sum(ev["encodings"].values()) + ev["hex_labels"]
    out["encoding"] = {"result": enc_n > 0 if total else None,
                       "detail": (", ".join(f"{k} {v}" for k, v in ev["encodings"].items()) +
                                  (f", hex {ev['hex_labels']}" if ev["hex_labels"] else "")).strip(", ") or "none"}
    out["randomness"] = {"result": (ev["high_entropy"] + ev["random_subdomain"]) > 0 if rows else None,
                         "detail": f"high-entropy {ev['high_entropy']}, random {ev['random_subdomain']}"}
    out["nxdomain"] = {"result": (ev["nxdomain_ratio"] or 0) > 0.5 if ev["nxdomain_ratio"] is not None and total >= 10 else None,
                       "detail": f"NXDOMAIN ratio {ev['nxdomain_ratio']}" if ev["nxdomain_ratio"] is not None else "no response codes"}
    both = None
    if rows:
        both = any(_flag(r.get("ml_label_A")) and _flag(r.get("ml_label_B")) for r in rows)
    else:
        ds = [a.get("details") or {} for a, _ in case["items"]]
        if any("ml_score_A" in d for d in ds):
            both = any((_f(d.get("ml_combined_label")) or 0) >= 1 and d.get("ml_score_B") is not None for d in ds)
    out["ml_agree"] = {"result": both, "detail": "Path A and Path B labels" if both is not None else "no ML scores"}
    out["popular"] = {"result": (tranco_hit is not None) if tranco_available else None,
                      "detail": (f"rank {tranco_hit['rank']} ({tranco_hit['listed_as']})" if tranco_hit else
                                 ("not listed" if tranco_available else "Tranco list not installed (dashboard/data/tranco.csv)"))}
    names = " ".join(ev["samples"])
    hits = sorted({k for k in BENIGN_KEYWORDS if k in names})
    out["benign_like"] = {"result": bool(hits) if ev["samples"] else None,
                          "detail": ", ".join(hits) if hits else "no CDN/cloud/update keywords"}
    if reputation is None:
        out["reputation"] = {"result": None, "detail": "online enrichment disabled"}
    else:
        out["reputation"] = reputation
    return out


def ml_panel(case, rows, snap, thresholds=None, demo=False):
    thresholds = thresholds or {}
    alerts = [a for a, _ in case["items"]]
    ds = [a.get("details") or {} for a in alerts]

    def agg(key):
        vals = [x for x in (_f(d.get(key)) for d in ds) if x is not None]
        if not vals and rows:
            vals = [x for x in (_f(r.get(key)) for r in rows) if x is not None]
        return {"max": round(max(vals), 4), "mean": round(sum(vals) / len(vals), 4), "n": len(vals)} if vals else None

    sig = Counter()
    for d in ds:
        for s in str(d.get("attack_signature") or "").split(","):
            if s.strip():
                sig[s.strip()] += 1
    if not sig and rows:
        for r in rows:
            for s in str(r.get("attack_signature") or "").split(","):
                if s.strip() and s.strip() != "NORMAL":
                    sig[s.strip()] += 1
    conf = Counter(str(d.get("ml_confidence")) for d in ds if d.get("ml_confidence"))
    deviations = []
    base = ((snap or {}).get("baseline") or {}).get(case["client"], {}) if snap else {}
    if rows and base:
        for feat, (mu, sd) in base.items():
            vals = [x for x in (_f(r.get(feat)) for r in rows) if x is not None]
            if vals and sd > 0:
                m = sum(vals) / len(vals)
                deviations.append({"feature": feat, "case_mean": round(m, 3), "client_mean": round(mu, 3),
                                   "z": round((m - mu) / sd, 2)})
    deviations.sort(key=lambda d: -abs(d["z"]))
    return {
        "score_a": agg("ml_score_A"), "score_b": agg("ml_score_B"),
        "combined": agg("ml_combined_score"), "threat": agg("ml_threat_score"),
        "confidence": dict(conf.most_common()), "signatures": dict(sig.most_common(6)),
        "thresholds": thresholds,
        "top_deviations": deviations[:5],
        "deviation_note": "Deviation of this case's queries from the client's own baseline (z-score). "
                          "This is context, not model attribution.",
        "demo": demo or any(d.get("demo") for d in ds),
    }


def suggestion(checklist_auto, ml):
    kind = {c[0]: c[2] for c in CHECKLIST}
    hit = [k for k, v in checklist_auto.items() if (v or {}).get("result") is True]
    tunnel = [k for k in hit if kind.get(k) == "tunnel"]
    benign = [k for k in hit if kind.get(k) == "benign"]
    shared = (checklist_auto.get("src_shared") or {}).get("result") is True
    high_ml = bool(ml.get("combined") and ml["combined"]["max"] >= 0.9)
    if len(tunnel) >= 3 or (high_ml and len(tunnel) >= 2):
        verdict, text = "escalate", "Several tunnel indicators agree. Likely true positive: escalate to Tier 2."
    elif benign and not tunnel:
        verdict, text = "close", "Only benign indicators. Likely benign / false positive (model logic): close with a reason."
    else:
        verdict, text = "review", "Mixed or weak indicators. Work the checklist; escalate if still unsure after ~15 min."
    if shared:
        text += " Source is a shared IP: identify the real endpoint first."
    return {"action": verdict, "text": text, "tunnel_indicators": tunnel, "benign_indicators": benign}


# ──────────────────────────────────────────────────────────────
# Optional online enrichment (VirusTotal / AbuseIPDB), off by default
# ──────────────────────────────────────────────────────────────
class OnlineEnricher:
    """Background lookups; request threads only read the cache or queue work. Never sends internal
    names or non-global IPs off the machine."""

    def __init__(self, get_config, cache_get, cache_put, internal_zones_fn):
        self._get_config = get_config          # () -> {"virustotal": {...}, "abuseipdb": {...}}
        self._cache_get, self._cache_put = cache_get, cache_put
        self._zones = internal_zones_fn
        self._q = queue.Queue(maxsize=500)
        self._pending = set()
        self._lock = threading.Lock()
        self._last_call = {}
        self._thread = None

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="soc-enricher", daemon=True)
            self._thread.start()

    @staticmethod
    def _cfg(cfg, name):
        c = (cfg or {}).get(name) or {}
        return c if c.get("enabled") and c.get("api_key") else None

    def eligible(self, kind, value):
        if kind == "domain":
            return has_domain(value) and not is_internal(value, self._zones()) and "." in str(value)
        try:
            return ipaddress.ip_address(str(value)).is_global
        except ValueError:
            return False

    def lookup(self, kind, value):
        """Cached result, or {"status": "disabled" | "not_sent" | "pending"}; never blocks."""
        provider = "virustotal" if kind == "domain" else "abuseipdb"
        cfg = self._cfg(self._get_config(), provider)
        if not cfg:
            return {"status": "disabled", "provider": provider}
        if not self.eligible(kind, value):
            return {"status": "not_sent", "provider": provider,
                    "detail": "internal name or non-public IP: never sent to an external service"}
        key = f"{provider}:{str(value).lower()}"
        hit = self._cache_get(key)
        if hit and time.time() - hit.get("fetched_at", 0) < float(cfg.get("ttl_hours", 24)) * 3600:
            return hit
        with self._lock:
            if key not in self._pending:
                try:
                    self._q.put_nowait((provider, kind, str(value), key))
                    self._pending.add(key)
                except queue.Full:
                    return {"status": "error", "provider": provider, "detail": "lookup queue full"}
        return dict(hit or {}, status="pending", provider=provider) if hit else {"status": "pending", "provider": provider}

    def _loop(self):
        while True:
            provider, kind, value, key = self._q.get()
            try:
                cfg = self._cfg(self._get_config(), provider)
                if cfg:
                    gap = float(cfg.get("min_interval_seconds", 15 if provider == "virustotal" else 2))
                    wait = self._last_call.get(provider, 0) + gap - time.time()
                    if wait > 0:
                        time.sleep(wait)
                    self._last_call[provider] = time.time()
                    res = self._fetch(provider, value, cfg)
                    self._cache_put(key, res)
            except Exception as e:  # never let the worker die
                self._cache_put(key, {"status": "error", "provider": provider, "detail": str(e)[:200],
                                      "fetched_at": time.time()})
            finally:
                with self._lock:
                    self._pending.discard(key)

    @staticmethod
    def _fetch(provider, value, cfg, timeout=4.0):
        now = time.time()
        try:
            if provider == "virustotal":
                req = urllib.request.Request("https://www.virustotal.com/api/v3/domains/" + urllib.parse.quote(value),
                                             headers={"x-apikey": cfg["api_key"], "Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https host)
                    attr = (json.loads(r.read().decode("utf-8")).get("data") or {}).get("attributes") or {}
                stats = attr.get("last_analysis_stats") or {}
                mal = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
                created = attr.get("creation_date")
                return {"status": "ok", "provider": provider, "fetched_at": now,
                        "result": mal > 0, "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0), "reputation": attr.get("reputation"),
                        "domain_age_days": int((now - created) / 86400) if isinstance(created, (int, float)) else None,
                        "detail": f"VirusTotal: {mal} engines flag it"}
            req = urllib.request.Request("https://api.abuseipdb.com/api/v2/check?" +
                                         urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90}),
                                         headers={"Key": cfg["api_key"], "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https host)
                d = json.loads(r.read().decode("utf-8")).get("data") or {}
            score = int(d.get("abuseConfidenceScore") or 0)
            return {"status": "ok", "provider": provider, "fetched_at": now, "result": score >= 25,
                    "abuse_score": score, "reports": d.get("totalReports"), "country": d.get("countryCode"),
                    "isp": d.get("isp"), "detail": f"AbuseIPDB confidence {score}%"}
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"status": "error", "provider": provider, "fetched_at": now, "detail": str(e)[:200]}
