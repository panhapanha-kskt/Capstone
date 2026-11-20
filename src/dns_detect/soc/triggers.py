"""The learner's three triggers as pure functions (research doc C5, user decisions 2026-11-20).

  (b) captures  new capture files: listed in SHA256SUMS, checksum OK, settled, not trained yet
  (c) verdicts  >= min_new_verdicts settled analyst verdicts newer than trained_until
  (a) drift     N distinct consecutive monitoring reports with retrain_recommended, edge-triggered,
                and (require_new_data) only if there is at least one new capture or verdict

Priority b > c > a. Nothing here starts a process or writes a file.
"""
import datetime
import fnmatch
import hashlib
import json
from pathlib import Path


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_time(value):
    """ISO-8601 (with Z or offset; naive = UTC) → epoch seconds, or None."""
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()


def iso(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z")


# ── (b) captures ─────────────────────────────────────────────────────────────
def read_sha256sums(folder):
    """{file name: sha256} from <folder>/SHA256SUMS (sha256sum format; '*' binary marker allowed)."""
    p = Path(folder) / "SHA256SUMS"
    out = {}
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            continue
        name = parts[1].lstrip("*").strip()
        out[Path(name).name] = parts[0].lower()
    return out


_HASH_CACHE = {}   # path -> (size, mtime, sha256): a settled file is hashed once, not on every poll


def sha256_cached(p):
    st = p.stat()
    key = (st.st_size, st.st_mtime)
    hit = _HASH_CACHE.get(str(p))
    if hit and hit[:2] == key:
        return hit[2]
    sha = sha256_file(p)
    _HASH_CACHE[str(p)] = (key[0], key[1], sha)
    return sha


def pending_captures(folder, pattern, trained, settle_s, now, require_sums=True):
    """New capture files ready to train on: [{"name", "sha256"}], plus {name: why_not} for the rest.

    trained = {name: sha256} already used for training (a file whose content changed counts as new)."""
    folder = Path(folder)
    ready, why_not = [], {}
    if not folder.is_dir():
        return ready, why_not
    sums = read_sha256sums(folder)
    for p in sorted(folder.iterdir()):
        name = p.name
        if not p.is_file() or not fnmatch.fnmatch(name, pattern) or name.startswith(("check_", "files_")):
            continue
        try:
            age = now - p.stat().st_mtime
        except OSError:
            continue
        if age < settle_s:
            why_not[name] = "not settled"
            continue
        if require_sums and name not in sums:
            why_not[name] = "not in SHA256SUMS"
            continue
        if require_sums and trained.get(name) == sums.get(name):
            continue                               # listed, already trained on this exact checksum: skip the hash
        sha = sha256_cached(p)
        if require_sums and sums.get(name) != sha:
            why_not[name] = "checksum mismatch"
            continue
        if trained.get(name) == sha:
            continue
        ready.append({"name": name, "sha256": sha})
    return ready, why_not


# ── (c) verdicts ─────────────────────────────────────────────────────────────
def load_store(path):
    """Records of dashboard/data/alert_management.json ({fp: record}); {} if missing or unreadable."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    recs = data.get("records", {}) if isinstance(data, dict) else {}
    if isinstance(recs, list):
        recs = {str(r.get("fp", i)): r for i, r in enumerate(recs) if isinstance(r, dict)}
    return recs if isinstance(recs, dict) else {}


def settled_verdicts(records, trained_until, settle_minutes, now):
    """[(fp, verdict_epoch)] for reviewed records (a verdict is set; demo alerts skipped) whose verdict_at is
    newer than trained_until and older than the settle time (an analyst may still change a fresh one)."""
    since = parse_time(trained_until) if isinstance(trained_until, str) else trained_until
    cutoff = now - settle_minutes * 60
    out = []
    for fp, r in records.items():
        if not isinstance(r, dict) or not r.get("verdict") or r.get("demo"):
            continue
        t = parse_time(r.get("verdict_at"))
        if t is None or t > cutoff or (since is not None and t <= since):
            continue
        out.append((fp, t))
    return sorted(out, key=lambda x: x[1])


def newest_verdict_time(records):
    ts = [parse_time(r.get("verdict_at")) for r in records.values() if isinstance(r, dict) and r.get("verdict")]
    ts = [t for t in ts if t is not None]
    return max(ts) if ts else None


# ── (a) drift ────────────────────────────────────────────────────────────────
def update_drift(drift_state, report_path):
    """Read the monitoring report; count it only if it is a NEW report (different sha256).

    Returns (state, changed). A report with retrain_recommended false resets the count and re-arms the
    trigger. An unreadable report changes nothing."""
    st = dict(drift_state or {})
    st.setdefault("armed", True)
    st.setdefault("consecutive", 0)
    st.setdefault("last_report_sha256", None)
    p = Path(report_path)
    try:
        raw = p.read_bytes()
        rep = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError):
        return st, False
    sha = hashlib.sha256(raw).hexdigest()
    if sha == st["last_report_sha256"]:
        return st, False
    st["last_report_sha256"] = sha
    if isinstance(rep, dict) and rep.get("retrain_recommended") is True:
        st["consecutive"] += 1
    else:
        st["consecutive"] = 0
        st["armed"] = True
    return st, True


def drift_due(drift_state, n, edge_triggered=True):
    st = drift_state or {}
    return (st.get("armed", True) or not edge_triggered) and st.get("consecutive", 0) >= n


# ── choosing one trigger ─────────────────────────────────────────────────────
def choose(caps, verdicts, drift_is_due, min_verdicts, require_new_data, enabled=None):
    """(trigger or None, note). One trigger per run, priority b > c > a.

    note = "drift_without_new_data" when drift is due but require_new_data blocks it."""
    en = {"captures": True, "verdicts": True, "drift": True, **(enabled or {})}
    if en["captures"] and caps:
        return "captures", None
    if en["verdicts"] and len(verdicts) >= min_verdicts:
        return "verdicts", None
    if en["drift"] and drift_is_due:
        if require_new_data and not (caps or verdicts):
            return None, "drift_without_new_data"
        return "drift", None
    return None, None
