# Training console (admin GUI)

The FastAPI training console is served by `dashboard/server.py` at `/training` on the dashboard's
host and port. Its API runs privately behind the dashboard, so there is no separate GUI server or
port to start. It defaults to Capstone mode: training uses the repository's `data/raw/` as the
project-default dataset and promotes models to `models/`. One shared core (`core/`) also supports
the optional standalone Streamlit front end:

| Front end | Start with | Open |
|---|---|---|
| Dashboard-integrated FastAPI page | `python dashboard/server.py` | `http://127.0.0.1:8000/training` |
| Optional Streamlit | `streamlit run streamlit_app.py` | http://localhost:8501 |

Both read the same files in `dashboard/training-gui/gui_data/`.

## Run real Capstone training

From the project root, start the dashboard. No `TRAINGUI_MODE`, `PROJECT_DIR`, `PRODUCTION_DIR`,
or `TRAIN_COMMAND` overrides are needed:

```powershell
$env:ADMIN_TOKEN = "pick-a-secret"
python dashboard\server.py --watch infra\technitium-elk\data\dns_logs
```

Open `/training`, choose **Project default (data/raw)** to train with the repository's real DNS
logs, then review the run before promoting the candidate into `models/`. On Windows, Capstone mode
requires Bash on `PATH` (for example, Git Bash or WSL).

## Try it with the demo trainer

Set `TRAINGUI_MODE=demo` before starting the dashboard to opt into the synthetic demo trainer.
The sample dataset is in `dashboard/training-gui/gui_data/datasets/`.

## Use it with your Capstone repo (scripts/train_models.sh)
Start the GUI from the same Python environment you use for Capstone (it needs TensorFlow etc.):

```
$env:TRAINGUI_MODE = "capstone"
$env:PROJECT_DIR = (Get-Location).Path
$env:PRODUCTION_DIR = Join-Path (Get-Location).Path "models"
$env:TRAIN_COMMAND = "python -m adapters.capstone_train"
$env:ADMIN_TOKEN = "pick-a-secret"
python dashboard\server.py
```
The training console appears at `/training` on the same dashboard server.
How it works:
- Each run calls `scripts/train_models.sh` with `DNS_DETECT_MODELS_DIR=gui_data/runs/<run>/model`, so the live `models/` folder is not touched while training.
- One-path runs (Path A or B only) and "only files not trained before" start from a copy of the current `models/`, so the script finds the other path and its file registry.
- Datasets: upload .csv .json .log .pcap .pcapng, or put files or folders (symlinks work) in `gui_data/datasets/`. "Project default" means the script scans `data/raw/`.
- Promote (Capstone mode) goes through `scripts/part_b.py`: it gathers every run trained the same way (needs >= 3
  seeds), runs the project gate, waits for detection to be idle, promotes with `scripts/promote_model.sh` (the old
  set goes to `models/archive/`), smoke-tests and rolls back by itself if that fails. "Confirm to override" cannot
  skip the gate. Roll back uses `scripts/rollback_model.sh`.
- Metrics are read from `evaluation_metrics.json` using the names in the top of `adapters/capstone_train.py`. Check the Runs page after your first run; if a metric shows "-", fix its name there.
- False alarm counts are only comparable between runs that share the same test split (keep "fresh split" off).

## Safety built in
- One training job at a time.
- Training never touches production; only Promote does, and it warns when F1 drops or false positives rise.
- Rollback restores the previous promoted version.
- Admin token required (default `admin`; local use only. Set a stronger `ADMIN_TOKEN` before exposing the dashboard).
- Uploads: .csv only, size-limited, file name sanitised.
- Demo mode runs on Linux, macOS and Windows. Capstone mode needs `bash` (your train_models.sh is a bash script): on Windows use WSL or Git Bash.
