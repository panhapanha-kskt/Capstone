"""Dataset checks shown to the admin before training."""
from pathlib import Path
import pandas as pd
from . import settings as S


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


def dataset_path(name: str) -> Path:
    if name == S.DEFAULT_DATASET and S.MODE == "capstone":
        return S.PROJECT_DIR / "data" / "raw"
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
                          "size_mb": None if p.is_dir() else round(p.stat().st_size / 1e6, 2)})
    return items


def validate_csv(name: str) -> dict:
    p = dataset_path(name)
    out = {"name": name, "rows": None, "columns": None, "class_counts": {}, "missing_pct": 0,
           "numeric_features": [], "warnings": [], "errors": [], "notes": [], "preview": [],
           "check_version": CHECK_VERSION}
    if not p.exists():
        out["errors"].append(f"Folder not found: {p}")
    elif p.is_dir() or p.suffix.lower() != ".csv":
        n = sum(1 for f in p.rglob("*") if f.is_file()) if p.is_dir() else 1
        out["kind"] = "files"
        out["warnings"].append(f"{n} file(s). The training script checks and labels this data itself; see the run log.")
    else:
        n_max = S.VALIDATE_SAMPLE_ROWS
        try:
            df = pd.read_csv(p, nrows=n_max + 1, low_memory=False)
        except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError, ValueError) as e:
            out["errors"].append(f"Could not read this file as CSV: {str(e).splitlines()[0][:200]}")
            out["ok"] = False
            return out
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
    out["ok"] = not out["errors"]
    return out
