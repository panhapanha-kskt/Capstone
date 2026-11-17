"""Dataset checks shown to the admin before training."""
from pathlib import Path
import pandas as pd
from . import settings as S


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
           "numeric_features": [], "warnings": [], "errors": [], "preview": []}
    if not p.exists():
        out["errors"].append(f"Folder not found: {p}")
    elif p.is_dir() or p.suffix.lower() != ".csv":
        n = sum(1 for f in p.rglob("*") if f.is_file()) if p.is_dir() else 1
        out["warnings"].append(f"{n} file(s). The training script checks and labels this data itself; see the run log.")
    else:
        df = pd.read_csv(p)
        out.update(rows=len(df), columns=len(df.columns), preview=df.head(5).fillna("").to_dict("records"))
        has_label = S.LABEL_COL in df.columns
        if has_label:
            out["class_counts"] = df[S.LABEL_COL].astype(str).value_counts().to_dict()
            if min(out["class_counts"].values()) / len(df) < 0.05:
                out["warnings"].append("A class is under 5% of the data. Expect low recall on that class.")
        elif S.REQUIRE_LABEL:
            out["errors"].append(f"Missing label column '{S.LABEL_COL}'. Found: {list(df.columns)[:10]}")
        else:
            out["warnings"].append(f"No '{S.LABEL_COL}' column. The script will label this data from the attack manifest or heuristics.")
        if len(df) < 100:
            out["warnings"].append(f"Only {len(df)} rows. Results will be unreliable.")
        out["missing_pct"] = round(float(df.isna().mean().mean() * 100), 2)
        if out["missing_pct"] > 5:
            out["warnings"].append(f"{out['missing_pct']}% of cells are empty.")
        out["numeric_features"] = df.select_dtypes("number").columns.drop(S.LABEL_COL, errors="ignore").tolist()
        if S.REQUIRE_LABEL and not out["numeric_features"]:
            out["errors"].append("No numeric feature columns found.")
    out["ok"] = not out["errors"]
    return out
