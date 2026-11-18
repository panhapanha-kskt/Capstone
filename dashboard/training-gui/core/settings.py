"""Central settings. Override any of these with environment variables."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOME = Path(os.getenv("TRAINGUI_HOME", ROOT / "gui_data"))
DATASETS = HOME / "datasets"
BUNDLES = HOME / "bundles"          # multi-file datasets: lists of files, never copies
RUNS = HOME / "runs"
REGISTRY = HOME / "registry.json"

MODE = os.getenv("TRAINGUI_MODE", "capstone")
if MODE not in ("demo", "capstone"):
    raise ValueError("TRAINGUI_MODE must be 'demo' or 'capstone'")

PROJECT_ROOT = ROOT.parent.parent
# Where the *live* model is copied when an admin clicks "Promote".
# Point this at the folder your detection pipeline loads models from (e.g. <repo>/models).
DEFAULT_PRODUCTION = PROJECT_ROOT / "models" if MODE == "capstone" else HOME / "production"
PRODUCTION = Path(os.getenv("PRODUCTION_DIR", DEFAULT_PRODUCTION))

LABEL_COL = os.getenv("LABEL_COLUMN", "label")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "0"))   # 0 = no limit; set e.g. MAX_UPLOAD_MB=500 to cap uploads
# Large CSVs are checked on their first rows only, so "Upload and check" stays fast and light on memory.
VALIDATE_SAMPLE_ROWS = int(os.getenv("VALIDATE_SAMPLE_ROWS", "200000"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin")

# Directory the training command runs in (set to your Capstone repo for real training).
DEFAULT_PROJECT_DIR = PROJECT_ROOT if MODE == "capstone" else ROOT
PROJECT_DIR = Path(os.getenv("PROJECT_DIR", DEFAULT_PROJECT_DIR))
# The command that trains. It receives these environment variables:
#   RUN_DIR       folder for this run: write metrics.json and model/ here
#   DATASET_PATH  the chosen CSV
#   TRAIN_PATH    "A", "B" or "both"
#   PARAMS_JSON   JSON string with the admin's parameters
#   LABEL_COLUMN  name of the label column
DEFAULT_TRAIN_COMMAND = (
    f'"{sys.executable}" -m adapters.capstone_train'
    if MODE == "capstone"
    else f'"{sys.executable}" -m core.demo_trainer'
)
TRAIN_COMMAND = os.getenv("TRAIN_COMMAND", DEFAULT_TRAIN_COMMAND)
# Pre-aggregated, labelled feature tables (e.g. DNSTunnel2026) use their own trainer.
FEATURE_TRAIN_COMMAND = os.getenv("FEATURE_TRAIN_COMMAND", f'"{sys.executable}" -m adapters.feature_table_train')

for _d in (DATASETS, BUNDLES, RUNS, PRODUCTION.parent):
    _d.mkdir(parents=True, exist_ok=True)

REQUIRE_LABEL = MODE == "demo"   # Capstone labels unlabeled data itself (manifest, then heuristics)
UPLOAD_EXTS = {".csv"} if MODE == "demo" else {".csv", ".json", ".log", ".pcap", ".pcapng"}
DEFAULT_DATASET = "project-default"   # capstone mode: let the script scan <PROJECT_DIR>/data/raw
