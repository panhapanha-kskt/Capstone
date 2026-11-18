"""Dataset checks shown to the admin before training."""
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
from . import settings as S

BUNDLE_PREFIX = "bundle:"     # multi-file datasets: "bundle:<name>", stored as <HOME>/bundles/<name>.json
BUNDLE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# Pipeline outputs and helpers in data/ that are not training data (detection results, reports, manifests)
SKIP_DIRS = {"splits", "feedback", "__pycache__"}
SKIP_FILE = re.compile(r"^(merged_features_|abstained_rows|rejected_rows|week[34]_|attack_manifest)|_report\.json$|\.meta\.json$")
DEFAULT_SPLIT = "time_seed42.json"   # train_models.sh BASE_MANIFEST


# What scripts/train_models.sh can read from a CSV. It passes CSVs straight to
# dns_detect.ingest.merge, which builds each row's model features with
# dns_parser.extract_features_from_record (needs a query name) or, for Week-3 files,
# week3_frame_to_features. Path B builds per-client time windows (timestamp + client_ip),
# and merge only accepts label 0/1 (anything else counts as unlabeled).
QUERY_COLUMNS = ("query", "qname", "query_name", "domain")
WEEK3_COLUMNS = ("entropy", "subdomain_depth", "first_label")
PATH_B_COLUMNS = ("timestamp", "client_ip")
PIPELINE_LABEL = "label"


CHECK_VERSION = 2   # bump when the check's rules change, so the console re-checks old results

# Label values that clearly mean benign / attack. Anything else must be chosen in step 2.
BENIGN_LABELS = {"0", "0.0", "benign", "safe", "normal", "legit", "legitimate", "clean", "good",
                 "false", "negative", "no", "non-tunnel", "nontunnel", "not_tunnel"}
ATTACK_HINTS = ("attack", "malicious", "tunnel", "exfil", "dga", "c2", "botnet", "anomal", "bad", "positive")
ATTACK_EXACT = {"1", "1.0", "true", "yes", "malware"}


def suggest_label_roles(values) -> dict:
    """{label value: "benign" | "attack" | None} — a best guess the admin confirms in step 2."""
    roles = {}
    for v in values:
        lv = str(v).strip().lower()
        if lv in BENIGN_LABELS:
            roles[str(v)] = "benign"
        elif lv in ATTACK_EXACT or any(h in lv for h in ATTACK_HINTS):
            roles[str(v)] = "attack"
        else:
            roles[str(v)] = None
    unknown = [v for v, r in roles.items() if r is None]
    known = {r for r in roles.values() if r}
    if len(roles) == 2 and len(unknown) == 1 and len(known) == 1:     # e.g. {"safe", "evil"}: the other one
        roles[unknown[0]] = "attack" if known == {"benign"} else "benign"
    return roles


def _check_pipeline(df: pd.DataFrame, out: dict) -> None:
    """Decide which trainer can use this CSV (out["kind"], out["pipeline"]) and add errors/warnings/notes.

    raw_queries   -> scripts/train_models.sh (Path A + Path B + fusion)
    feature_table -> adapters/feature_table_train.py (pre-aggregated, labelled numeric features)"""
    cols = [str(c) for c in df.columns]
    qcol = next((c for c in QUERY_COLUMNS if c in cols), None)
    week3 = any(c in cols for c in WEEK3_COLUMNS)
    path_b = all(c in cols for c in PATH_B_COLUMNS)
    out["pipeline"] = {"compatible": bool(qcol or week3), "query_column": qcol, "path_b_ready": path_b}
    has_label = PIPELINE_LABEL in cols
    roles = suggest_label_roles(sorted(df[PIPELINE_LABEL].dropna().astype(str).str.strip().unique())) if has_label else {}
    out["label_roles"] = roles

    if qcol or week3:
        out["kind"] = "raw_queries"
        out["notes"].append("Raw DNS query records: trained by scripts/train_models.sh (Path A, Path B and fusion).")
        if not path_b:
            missing = ", ".join(c for c in PATH_B_COLUMNS if c not in cols)
            out["warnings"].append(f"No {missing} column: Path B (per-client time windows) cannot use this file. "
                                   "Train Path A only, or add the missing columns.")
        other = sorted(v for v in roles if v not in ("0", "1", "0.0", "1.0"))
        if other:
            out["notes"].append(f"Label values such as {', '.join(other[:3])} are not 0/1. Step 2 maps them to "
                                "benign/attack, and the run trains on a copy of the file with 0/1 labels.")
        return

    numeric = [c for c in df.select_dtypes("number").columns if c != PIPELINE_LABEL]
    if has_label and numeric:
        out["kind"] = "feature_table"
        dropped = len(cols) - len(numeric) - 1
        out["notes"].append(
            f"Pre-aggregated feature table ({len(numeric)} numeric feature columns, no query names). It is trained "
            "with the feature-table trainer (gradient-boosted trees on these columns), not scripts/train_models.sh. "
            "Its models can be compared in step 4 but not promoted to the live Path A/B pipeline."
            + (f" {dropped} non-numeric column(s) are not used." if dropped else ""))
        seen = {r for r in roles.values() if r}
        if len(roles) < 2:
            msg = f"Only one label value ({', '.join(roles) or 'none'}) in the rows checked; training needs benign and attack rows."
            (out["warnings"] if out.get("sampled") else out["errors"]).append(msg)
        elif seen != {"benign", "attack"}:
            out["notes"].append("Choose which label values mean benign and which mean attack in step 2.")
        return

    out["kind"] = "unsupported"
    sample = ", ".join(cols[:4]) + (", ..." if len(cols) > 4 else "")
    out["errors"].append(
        f"This file is pre-aggregated features ({len(cols)} columns such as {sample}) without a '{PIPELINE_LABEL}' "
        "column; the training pipeline needs raw DNS query records (one row per query with a query or domain column, "
        "plus timestamp and client_ip for Path B), and the feature-table trainer needs a label column.")


# ── project files, multi-file datasets (bundles) and splits ─────────────────────

def project_data_root() -> Path:
    return S.PROJECT_DIR / "data"


def list_project_files() -> list:
    """Data files under <project>/data that train_models.sh can read (--files)."""
    root = project_data_root()
    if S.MODE != "capstone" or not root.is_dir():
        return []
    out = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(S.PROJECT_DIR)
        if (not p.is_file() or p.suffix.lower() not in S.UPLOAD_EXTS or SKIP_FILE.search(p.name)
                or any(part in SKIP_DIRS or part.startswith(".") for part in rel.parts) or len(rel.parts) > 5):
            continue
        out.append({"path": rel.as_posix(), "size_mb": round(p.stat().st_size / 1e6, 2)})
    return out


def _member_path(m: dict) -> Path:
    """Resolve one bundle member; only files inside <project>/data or the uploaded datasets."""
    raw = str(m.get("path") or "")
    if m.get("source") == "project":
        root = project_data_root().resolve()
        p = (S.PROJECT_DIR / raw).resolve()
        if root != p and root not in p.parents:
            raise ValueError(f"{raw}: only files inside the project's data/ folder can be used.")
    elif m.get("source") == "upload":
        if raw.startswith(BUNDLE_PREFIX) or Path(raw).name != raw:
            raise ValueError(f"{raw}: not an uploaded dataset file.")
        p = S.DATASETS / raw
    else:
        raise ValueError(f"{raw}: unknown source {m.get('source')!r}.")
    if p.suffix.lower() not in S.UPLOAD_EXTS:
        raise ValueError(f"{raw}: accepted file types are {', '.join(sorted(S.UPLOAD_EXTS))}.")
    return p


def _bundle_spec(name: str) -> dict:
    return json.loads(dataset_path(name).read_text(encoding="utf-8"))


def bundle_files(name: str) -> list:
    """Absolute paths of a multi-file dataset's files, in the order chosen."""
    return [_member_path(m) for m in _bundle_spec(name)["files"]]


def create_bundle(name: str, files: list) -> dict:
    if S.MODE != "capstone":
        raise ValueError("Multi-file datasets are for the Capstone training pipeline.")
    name = (name or "").strip()
    if not BUNDLE_NAME.match(name):
        raise ValueError("Name: 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit.")
    target = S.BUNDLES / f"{name}.json"
    if target.exists():
        raise ValueError(f"A multi-file dataset called {name} already exists.")
    members, seen = [], set()
    for f in files or []:
        m = {"source": f.get("source"), "path": str(f.get("path") or "")}
        p = _member_path(m)
        if not p.is_file():
            raise FileNotFoundError(f"{m['path']}: file not found.")
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            members.append(m)
    if len(members) < 2:
        raise ValueError("Choose at least two different files.")
    if len(members) > 50:
        raise ValueError("Choose at most 50 files.")
    target.write_text(json.dumps({"name": name, "files": members,
                                  "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}, indent=2),
                      encoding="utf-8")
    return {"name": BUNDLE_PREFIX + name, "files": len(members)}


def delete_bundle(name: str) -> dict:
    """Remove the multi-file dataset's list only; the data files are never touched."""
    p = dataset_path(name if name.startswith(BUNDLE_PREFIX) else BUNDLE_PREFIX + name)
    p.unlink()
    return {"deleted": p.stem}


def list_splits() -> list:
    d = S.PROJECT_DIR / "data" / "processed" / "splits"
    if S.MODE != "capstone" or not d.is_dir():
        return []
    return [{"name": p.name, "size_kb": round(p.stat().st_size / 1e3, 1), "default": p.name == DEFAULT_SPLIT}
            for p in sorted(d.glob("*.json"))]


def split_path(name: str) -> Path:
    if not name or Path(name).name != name or not name.endswith(".json"):
        raise ValueError(f"Unknown split: {name}")
    p = S.PROJECT_DIR / "data" / "processed" / "splits" / name
    if not p.is_file():
        raise FileNotFoundError(f"Split not found: {name}")
    return p


def dataset_path(name: str) -> Path:
    if name == S.DEFAULT_DATASET and S.MODE == "capstone":
        return S.PROJECT_DIR / "data" / "raw"
    if name.startswith(BUNDLE_PREFIX):
        bn = name[len(BUNDLE_PREFIX):]
        p = S.BUNDLES / f"{Path(bn).name}.json"
        if Path(bn).name != bn or not p.exists():
            raise FileNotFoundError(f"Dataset not found: {name}")
        return p
    p = S.DATASETS / Path(name).name      # Path(name).name blocks ../ tricks; symlinks are allowed
    if not p.exists():
        raise FileNotFoundError(f"Dataset not found: {name}")
    return p


def list_datasets():
    items = []
    if S.MODE == "capstone":
        items.append({"name": S.DEFAULT_DATASET, "label": "Project default (data/raw)", "size_mb": None})
    for p in sorted(S.DATASETS.iterdir()):
        if p.name.startswith("."):
            continue
        if p.is_dir() or p.suffix.lower() in S.UPLOAD_EXTS:
            items.append({"name": p.name, "label": p.name + ("/ (folder)" if p.is_dir() else ""),
                          "size_mb": None if p.is_dir() else round(p.stat().st_size / 1e6, 2), "kind": "file"})
    for b in sorted(S.BUNDLES.glob("*.json")):
        try:
            files = bundle_files(BUNDLE_PREFIX + b.stem)
        except (ValueError, KeyError, OSError, json.JSONDecodeError):
            files = []
        size = sum(f.stat().st_size for f in files if f.is_file())
        items.append({"name": BUNDLE_PREFIX + b.stem, "label": f"{b.stem} ({len(files)} files)",
                      "size_mb": round(size / 1e6, 2), "kind": "bundle", "files": len(files)})
    return items


def validate_csv(name: str) -> dict:
    p = dataset_path(name)
    out = {"name": name, "rows": None, "columns": None, "class_counts": {}, "missing_pct": 0,
           "numeric_features": [], "warnings": [], "errors": [], "notes": [], "preview": [],
           "check_version": CHECK_VERSION}
    if name.startswith(BUNDLE_PREFIX):
        _check_bundle(name, out)
    elif not p.exists():
        out["errors"].append(f"Folder not found: {p}")
    elif p.is_dir() or p.suffix.lower() != ".csv":
        n = sum(1 for f in p.rglob("*") if f.is_file()) if p.is_dir() else 1
        out["kind"] = "files"
        out["warnings"].append(f"{n} file(s). The training script checks and labels this data itself; see the run log.")
    else:
        _check_csv(p, out)
    out["ok"] = not out["errors"]
    return out


def _check_csv(p: Path, out: dict) -> None:
    """Checks for one CSV file; fills out (errors, warnings, notes, counts, kind)."""
    n_max = S.VALIDATE_SAMPLE_ROWS
    try:
        df = pd.read_csv(p, nrows=n_max + 1, low_memory=False)
    except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError, ValueError) as e:
        out["errors"].append(f"Could not read this file as CSV: {str(e).splitlines()[0][:200]}")
        return
    sampled = len(df) > n_max
    if sampled:
        df = df.iloc[:n_max]
        out["warnings"].append(f"Large file ({p.stat().st_size / 1e6:,.0f} MB): checked the first {n_max:,} rows only, "
                               "so the class counts below are for those rows, not the whole file.")
    out.update(rows=None if sampled else len(df), columns=len(df.columns), sampled=sampled,
               preview=df.head(5).fillna("").to_dict("records"))
    has_label = S.LABEL_COL in df.columns
    if has_label:
        out["class_counts"] = df[S.LABEL_COL].astype(str).value_counts().to_dict()
        if min(out["class_counts"].values()) / len(df) < 0.05:
            out["warnings"].append("A class is under 5% of the data. Expect low recall on that class.")
    elif S.REQUIRE_LABEL:
        out["errors"].append(f"Missing label column '{S.LABEL_COL}'. Found: {list(df.columns)[:10]}")
    else:
        out["warnings"].append(f"No '{S.LABEL_COL}' column. The script will label this data from the attack manifest or heuristics.")
    if not sampled and len(df) < 100:
        out["warnings"].append(f"Only {len(df)} rows. Results will be unreliable.")
    out["missing_pct"] = round(float(df.isna().mean().mean() * 100), 2)
    if out["missing_pct"] > 5:
        out["warnings"].append(f"{out['missing_pct']}% of cells are empty.")
    out["numeric_features"] = df.select_dtypes("number").columns.drop(S.LABEL_COL, errors="ignore").tolist()
    if S.REQUIRE_LABEL and not out["numeric_features"]:
        out["errors"].append("No numeric feature columns found.")
    if S.MODE == "capstone":
        _check_pipeline(df, out)


def _json_label_counts(p: Path):
    """Label counts of a features JSON the way ingest/merge reads it (0/1, everything else unlabeled)."""
    data = json.loads(p.read_text(encoding="utf-8"))
    rows = data if isinstance(data, list) else data.get("records", []) if isinstance(data, dict) else []
    c = Counter()
    for r in rows:
        v = r.get("label") if isinstance(r, dict) else None
        c[str(int(float(v))) if v in (0, 1, "0", "1", 0.0, 1.0) else "unlabeled"] += 1
    return len(rows), c


def _check_bundle(name: str, out: dict) -> None:
    """A multi-file dataset: every file must be something scripts/train_models.sh can train on."""
    out["kind"] = "bundle"
    out["files"] = []
    total, roles, has_pcap = Counter(), {}, False
    try:
        members = _bundle_spec(name)["files"]
    except (OSError, KeyError, json.JSONDecodeError) as e:
        out["errors"].append(f"Could not read the multi-file dataset: {e}")
        return
    for m in members:
        shown = m.get("path", "?")
        entry = {"path": shown, "source": m.get("source"), "type": Path(shown).suffix.lower().lstrip(".")}
        out["files"].append(entry)
        try:
            fp = _member_path(m)
        except ValueError as e:
            out["errors"].append(str(e)); entry["status"] = "not allowed"; continue
        if not fp.is_file():
            out["errors"].append(f"{shown}: file not found."); entry["status"] = "missing"; continue
        entry["size_mb"] = round(fp.stat().st_size / 1e6, 2)
        ext = fp.suffix.lower()
        if ext == ".csv":
            sub = {"class_counts": {}, "warnings": [], "errors": [], "notes": [], "numeric_features": [], "preview": []}
            _check_csv(fp, sub)
            if not sub["errors"] and sub.get("kind") != "raw_queries":
                sub["errors"].append("is a pre-aggregated feature table; multi-file datasets are trained by "
                                     "scripts/train_models.sh, which needs raw DNS query records. Train it on its own.")
            out["errors"] += [f"{shown}: {e}" for e in sub["errors"]]
            out["warnings"] += [f"{shown}: {w}" for w in sub["warnings"] if not w.startswith("A class is under")]
            out["notes"] += [f"{shown}: {n}" for n in sub["notes"] if "not 0/1" in n]
            total.update(sub["class_counts"]); roles.update(sub.get("label_roles") or {})
            entry.update(rows=sub.get("rows"), class_counts=sub["class_counts"], status="error" if sub["errors"] else "ok")
        elif ext == ".json":
            try:
                n, c = _json_label_counts(fp)
            except (OSError, ValueError, AttributeError) as e:
                out["errors"].append(f"{shown}: could not read as JSON records ({e})"); entry["status"] = "error"; continue
            total.update(c)
            entry.update(rows=n, class_counts=dict(c), status="ok")
            if c.get("unlabeled"):
                out["notes"].append(f"{shown}: {c['unlabeled']:,} rows have no 0/1 label; the pipeline labels them "
                                    "from the attack manifest or heuristics.")
        else:
            has_pcap = has_pcap or ext in (".pcap", ".pcapng")
            entry["status"] = "ok (no labels in the file)"
    out["class_counts"] = dict(total)
    out["label_roles"] = roles
    out["has_pcap"] = has_pcap
    out["notes"].insert(0, f"{len(members)} files, trained together by scripts/train_models.sh (--files): "
                           "Path A, Path B and fusion.")
    labelled = {k: v for k, v in total.items() if k != "unlabeled"}
    if labelled and len(labelled) < 2:
        out["warnings"].append("Only one label value across these files; training needs both benign and attack rows "
                               "(or a manifest / heuristics for the unlabeled ones).")
