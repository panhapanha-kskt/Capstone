# Restructure Plan — DNS Traffic Anomaly Detection

> **Status:** Awaiting approval. Read-only analysis — nothing has been moved, renamed, or deleted.

---

## 1. Current-State Map

### Directory Tree

```
detecting-dns-traffic/
├── README.md                              # 517-line academic paper
├── PLAN/
│   └── PLAN.md                            # Capstone extension plan (revision 2)
├── Document/
│   └── Document_DNS.md                    # Technical documentation (566 lines)
├── __pycache__/                           # ORPHANED — .pyc with no .py (Python 3.12)
│   ├── config.cpython-312.pyc
│   ├── detector.cpython-312.pyc
│   └── monitor.cpython-312.pyc
├── data/                                  # ALL 14 files are generated pipeline output (~50 MB)
│   ├── alerts
│   ├── blocked_domains.txt
│   ├── daily_summary.csv
│   ├── dns_features_all.csv
│   ├── extracted_2026-03-18_1773817951.json
│   ├── merged_features_all.json
│   ├── merged_features_labeled.json
│   ├── week3_attack_summary.json
│   ├── week3_features_all.json
│   ├── week3_features_with_ml.json
│   ├── week3_project_summary.json
│   ├── week3_suspicious_domains.json
│   ├── week4_unified_alerts.csv
│   └── week4_unified_alerts.json
├── logs/                                  # 12 runtime logs (March 2026)
├── model_memory/                          # Canonical model store + metadata
│   ├── dns_scaler.pkl
│   ├── dns_threshold.json
│   ├── dns_trafficformer.h5
│   ├── dns_trafficformer_norm.json
│   ├── dns_trafficformer_threshold.json
│   ├── dns_tunnel_rf.pkl                  # 16.7 MB
│   ├── dns_tunnel_transformer.keras
│   ├── pipeline_awareness_check.sh        # Auto-generated drift script
│   ├── trained_files_registry.json
│   ├── training_metadata.json
│   └── training_provenance.json
├── scripts/
│   ├── DNS_feature_extractor.py           # Week 3 feature extraction (standalone)
│   ├── Ml_bridge.py                       # Fusion: Week3 → ML → Week4 glue
│   ├── Model.py                           # Path A: RF + Transformer ensemble
│   ├── Predict.py                         # Path B: Trafficformer inference
│   ├── Train.py                           # Path B: Trafficformer training
│   ├── Week4_detection_engine.py          # Detection engine (standalone)
│   ├── dns_parser.py                      # Shared parser (leaf dependency)
│   ├── Run_Pipeline.sh                    # Detection pipeline orchestrator
│   ├── Train_Models.sh                    # Model training orchestrator
│   ├── attack.c                           # Lab attack simulator (8 attack modes)
│   ├── attack                             # Compiled ELF binary (48 KB)
│   ├── dns_tunnel_rf.pkl                  # DUPLICATE of model_memory/
│   ├── dns_tunnel_transformer.keras       # DUPLICATE
│   ├── dns_scaler.pkl                     # DUPLICATE
│   ├── dns_threshold.json                 # DUPLICATE
│   ├── pipeline_live.log                  # Runtime log
│   ├── __pycache__/                       # Build artifact
│   └── model/                             # DUPLICATE Path B artifacts
│       ├── dns_trafficformer.h5
│       ├── dns_trafficformer_norm.json
│       └── dns_trafficformer_threshold.json
├── technitium-dns/
│   ├── docker-compose.yml                 # ELK + Technitium stack
│   ├── filebeat.yml
│   ├── logstash.conf
│   └── data/dns_logs/                     # RAW INPUT — only real source data
│       ├── 2026-03-18.log
│       ├── 2026-03-19.log
│       └── 2026-03-20.log
└── nginx-1.28.1/                          # FULL Windows nginx bundle
    ├── nginx.exe                           # Binary
    ├── conf/ (9 files)                    # 8 stock + 1 ours (nginx.conf)
    ├── contrib/ (vim plugins, perl)       # Stock nginx
    ├── docs/ (licenses, changelogs)       # Stock nginx
    ├── html/                              # OUR Phone Store app
    │   ├── index.html, indextest.html
    │   ├── customer.js                    # Firebase config embedded
    │   └── styles.css
    ├── logs/ (access.log, error.log, nginx.pid)
    └── ssl/
        ├── lab.crt
        └── lab.key                        # PRIVATE KEY COMMITTED
```

### Call Graph

```
TRAINING (Train_Models.sh):
  Train_Models.sh
    ├─→ DNS_feature_extractor.py --input <log> --output <json>    [per .log]
    ├─→ [inline Python merges all JSON → merged_features_all.json]
    ├─→ Ml_bridge.py --label-only                                 [labels from attack_count]
    │     └── imports dns_parser._load_json_records()
    ├─→ Model.py --train <labeled>                                [Path A: RF + Transformer]
    │     └── imports dns_parser.load_as_dataframe(), FEATURES_8
    └─→ Train.py --filename <merged> --save_name dns_trafficformer [Path B: Trafficformer]
          ├── imports dns_parser.load_as_array()
          └── imports Model.transformer_encoder()  [via importlib hack]

DETECTION (Run_Pipeline.sh):
  Run_Pipeline.sh
    ├─→ [copies model_memory/ → scripts/ and scripts/model/]      ← the copy dance
    ├─→ DNS_feature_extractor.py                                   [batch mode]
    ├─→ Ml_bridge.py --week3 <features> --output <with_ml>
    │     ├── imports dns_parser.*
    │     ├── imports Model.* [via importlib hack]
    │     └── imports Predict.* [via importlib hack]
    └─→ Week4_detection_engine.py --input <with_ml> --output <alerts>
```

### Python Module Dependencies

```
dns_parser.py          ← leaf (no local imports)
  ├── Model.py         ← imports dns_parser
  │   ├── Train.py     ← imports dns_parser + Model.transformer_encoder (importlib)
  │   └── Ml_bridge.py ← imports dns_parser + Model.* + Predict.* (importlib + sys.path hack)
  └── Predict.py       ← imports dns_parser

DNS_feature_extractor.py  ← fully standalone
Week4_detection_engine.py ← fully standalone
```

### Missing Standard Files

| File | Exists? |
|------|---------|
| `requirements.txt` | **NO** |
| `.gitignore` | **NO** |
| `.env.example` | **NO** |
| `setup.py` / `pyproject.toml` | **NO** |

---

## 2. Problems Found

### CRITICAL

1. **`nginx-1.28.1/ssl/lab.key` — Private SSL key committed to git.** Even after removal, it persists in git history. The key must be rotated and history scrubbed with `git-filter-repo`.

2. **No `.gitignore`** — everything is tracked: `.pyc` files, 16.7 MB `.pkl` models, compiled binaries, runtime logs, 50 MB of generated data.

3. **Hardcoded `/home/paifern/DNS-_raffic-_Anomaly_Detection/`** in 5 source files:
   - `Run_Pipeline.sh:40` — `BASE_DIR`
   - `Train_Models.sh:98` — `BASE_DIR`
   - `DNS_feature_extractor.py:709-710` — `log_directory` and `output_directory`
   - `attack.c:47-48` — `DEFAULT_WORDLIST` paths
   - `model_memory/*.json` (3 files) — embedded absolute paths in JSON values

### HIGH

4. **Duplicate model artifacts (~17.9 MB wasted)** — every model file exists in both `model_memory/` AND `scripts/` (or `scripts/model/`). `Run_Pipeline.sh` copies them at runtime because Python loads from CWD.

5. **Full nginx Windows bundle committed** — `nginx.exe`, stock config, contrib/, docs/, logs/. Only our `nginx.conf`, `html/*` are needed.

6. **`importlib.import_module()` hacks** in `Ml_bridge.py` (lines 60-77) and `Train.py` (line 45) plus `sys.path.insert()` manipulation. Fragile cross-imports that break if CWD changes.

### MEDIUM

7. **Firebase API key** in `nginx-1.28.1/html/customer.js` (lines 2-8). Client-side Firebase keys are restricted by security rules — lower risk, but should be audited.

8. **All generated data tracked in git** — `data/` contains ~50 MB of regenerable pipeline output.

9. **Compiled binary `scripts/attack`** (ELF) tracked in git.

10. **"Week3" / "Week4" naming** in filenames and output — meaningless to anyone outside the course.

11. **Orphaned `__pycache__/`** at root — `config.cpython-312.pyc`, `detector.cpython-312.pyc`, `monitor.cpython-312.pyc` with no corresponding `.py` source files anywhere. Remnants of an earlier Python 3.12 architecture.

12. **No dependency manifest** — `requirements.txt` doesn't exist. Dependencies include numpy, pandas, scikit-learn, tensorflow, joblib, tqdm, python-dateutil, requests, pytz, scapy.

---

## 3. Proposed Target Layout

```
detecting-dns-traffic/
├── .gitignore
├── .env.example                   # MDTI credentials, override paths
├── README.md                      # NEW slim: abstract + quickstart + architecture link
├── requirements.txt               # Pinned versions
├── config/
│   └── settings.yaml              # All paths, thresholds, weights — no hardcoded /home/...
├── src/
│   └── dns_detect/
│       ├── __init__.py
│       ├── config.py              # Settings loader (YAML + env var overrides)
│       ├── parsing/
│       │   ├── __init__.py
│       │   └── dns_parser.py      # ← scripts/dns_parser.py
│       ├── features/
│       │   ├── __init__.py
│       │   └── extractor.py       # ← scripts/DNS_feature_extractor.py
│       ├── models/
│       │   ├── __init__.py
│       │   ├── path_a.py          # ← scripts/Model.py (RF + Transformer)
│       │   ├── path_b_train.py    # ← scripts/Train.py (Trafficformer train)
│       │   └── path_b_predict.py  # ← scripts/Predict.py (Trafficformer infer)
│       ├── fusion/
│       │   ├── __init__.py
│       │   └── bridge.py          # ← scripts/Ml_bridge.py
│       ├── detection/
│       │   ├── __init__.py
│       │   └── engine.py          # ← scripts/Week4_detection_engine.py
│       └── utils/
│           ├── __init__.py
│           └── paths.py           # Project root finder, path helpers
├── scripts/
│   ├── run_pipeline.sh            # ← scripts/Run_Pipeline.sh (rewritten, thin CLI)
│   ├── train_models.sh            # ← scripts/Train_Models.sh (rewritten, thin CLI)
│   └── pipeline_awareness_check.sh
├── attacks/
│   ├── attack.c                   # ← scripts/attack.c (fix hardcoded wordlist paths)
│   └── Makefile                   # NEW: build instructions
├── infra/
│   ├── technitium-elk/
│   │   ├── docker-compose.yml     # ← technitium-dns/
│   │   ├── filebeat.yml
│   │   └── logstash.conf
│   └── nginx-lab/
│       ├── nginx.conf             # ← nginx-1.28.1/conf/nginx.conf (our config only)
│       ├── html/                  # ← nginx-1.28.1/html/ (our app files)
│       │   ├── index.html
│       │   ├── indextest.html
│       │   ├── styles.css
│       │   └── customer.js
│       └── ssl/                   # .gitignored, only .gitkeep tracked
│           └── .gitkeep
├── models/                        # ONE canonical copy (gitignored except .gitkeep)
│   └── .gitkeep
├── data/
│   ├── raw/                       # ← technitium-dns/data/dns_logs/*.log
│   │   └── .gitkeep
│   ├── processed/                 # gitignored
│   │   └── .gitkeep
│   └── blocked_domains.txt        # Reference data (keep tracked)
├── outputs/                       # gitignored
│   └── .gitkeep
├── logs/                          # gitignored
│   └── .gitkeep
├── docs/
│   ├── README_full.md             # ← README.md (original academic paper)
│   ├── Document_DNS.md            # ← Document/Document_DNS.md
│   └── PLAN.md                    # ← PLAN/PLAN.md
└── tests/
    ├── __init__.py
    └── test_smoke.py              # NEW: verify imports + config load
```

---

## 4. Move Table

### Files to MOVE

| Old Path | New Path | Reason |
|----------|----------|--------|
| `README.md` | `docs/README_full.md` | Preserved; new slim README at root |
| `PLAN/PLAN.md` | `docs/PLAN.md` | Group docs |
| `Document/Document_DNS.md` | `docs/Document_DNS.md` | Group docs |
| `scripts/dns_parser.py` | `src/dns_detect/parsing/dns_parser.py` | Package structure |
| `scripts/DNS_feature_extractor.py` | `src/dns_detect/features/extractor.py` | Rename + package |
| `scripts/Model.py` | `src/dns_detect/models/path_a.py` | Descriptive rename + package |
| `scripts/Train.py` | `src/dns_detect/models/path_b_train.py` | Descriptive rename + package |
| `scripts/Predict.py` | `src/dns_detect/models/path_b_predict.py` | Descriptive rename + package |
| `scripts/Ml_bridge.py` | `src/dns_detect/fusion/bridge.py` | Descriptive rename + package |
| `scripts/Week4_detection_engine.py` | `src/dns_detect/detection/engine.py` | Drop "Week4" naming |
| `scripts/Run_Pipeline.sh` | `scripts/run_pipeline.sh` | Lowercase + rewrite paths |
| `scripts/Train_Models.sh` | `scripts/train_models.sh` | Lowercase + rewrite paths |
| `scripts/attack.c` | `attacks/attack.c` | Separate lab-only code |
| `model_memory/dns_tunnel_rf.pkl` | `models/dns_tunnel_rf.pkl` | Canonical location |
| `model_memory/dns_tunnel_transformer.keras` | `models/dns_tunnel_transformer.keras` | Canonical location |
| `model_memory/dns_scaler.pkl` | `models/dns_scaler.pkl` | Canonical location |
| `model_memory/dns_threshold.json` | `models/dns_threshold.json` | Canonical location |
| `model_memory/dns_trafficformer.h5` | `models/dns_trafficformer.h5` | Canonical location |
| `model_memory/dns_trafficformer_norm.json` | `models/dns_trafficformer_norm.json` | Canonical location |
| `model_memory/dns_trafficformer_threshold.json` | `models/dns_trafficformer_threshold.json` | Canonical location |
| `model_memory/training_metadata.json` | `models/training_metadata.json` | Canonical location |
| `model_memory/training_provenance.json` | `models/training_provenance.json` | Canonical location |
| `model_memory/trained_files_registry.json` | `models/trained_files_registry.json` | Canonical location |
| `model_memory/pipeline_awareness_check.sh` | `scripts/pipeline_awareness_check.sh` | Group with scripts |
| `technitium-dns/docker-compose.yml` | `infra/technitium-elk/docker-compose.yml` | Infra grouping |
| `technitium-dns/filebeat.yml` | `infra/technitium-elk/filebeat.yml` | Infra grouping |
| `technitium-dns/logstash.conf` | `infra/technitium-elk/logstash.conf` | Infra grouping |
| `technitium-dns/data/dns_logs/*.log` | `data/raw/*.log` | Raw data in data/ |
| `nginx-1.28.1/conf/nginx.conf` | `infra/nginx-lab/nginx.conf` | Our config only |
| `nginx-1.28.1/html/index.html` | `infra/nginx-lab/html/index.html` | Our app |
| `nginx-1.28.1/html/indextest.html` | `infra/nginx-lab/html/indextest.html` | Our app |
| `nginx-1.28.1/html/styles.css` | `infra/nginx-lab/html/styles.css` | Our app |
| `nginx-1.28.1/html/customer.js` | `infra/nginx-lab/html/customer.js` | Our app |
| `data/blocked_domains.txt` | `data/blocked_domains.txt` | Keep (reference data) |

### Files to DELETE

| Path | Reason |
|------|--------|
| `__pycache__/` (root, 3 files) | Orphaned .pyc — no source, Python 3.12 remnants |
| `scripts/__pycache__/` (3 files) | Build artifact |
| `scripts/attack` | Compiled ELF binary |
| `scripts/dns_tunnel_rf.pkl` | Duplicate of model_memory/ |
| `scripts/dns_tunnel_transformer.keras` | Duplicate of model_memory/ |
| `scripts/dns_scaler.pkl` | Duplicate of model_memory/ |
| `scripts/dns_threshold.json` | Duplicate of model_memory/ |
| `scripts/model/dns_trafficformer.h5` | Duplicate of model_memory/ |
| `scripts/model/dns_trafficformer_norm.json` | Duplicate of model_memory/ |
| `scripts/model/dns_trafficformer_threshold.json` | Duplicate of model_memory/ |
| `scripts/pipeline_live.log` | Runtime log |
| `nginx-1.28.1/nginx.exe` | Stock nginx binary |
| `nginx-1.28.1/contrib/` (entire) | Stock nginx |
| `nginx-1.28.1/docs/` (entire) | Stock nginx licenses/changelogs |
| `nginx-1.28.1/conf/fastcgi.conf` | Stock nginx config |
| `nginx-1.28.1/conf/fastcgi_params` | Stock nginx config |
| `nginx-1.28.1/conf/koi-utf` | Stock nginx config |
| `nginx-1.28.1/conf/koi-win` | Stock nginx config |
| `nginx-1.28.1/conf/mime.types` | Stock nginx config |
| `nginx-1.28.1/conf/scgi_params` | Stock nginx config |
| `nginx-1.28.1/conf/uwsgi_params` | Stock nginx config |
| `nginx-1.28.1/conf/win-utf` | Stock nginx config |
| `nginx-1.28.1/html/50x.html` | Stock nginx page |
| `nginx-1.28.1/logs/` (entire) | Runtime logs |
| `nginx-1.28.1/ssl/lab.key` | **PRIVATE KEY — must be rotated** |
| `nginx-1.28.1/ssl/lab.crt` | Companion to removed key |
| `logs/` (all 12 files) | Runtime logs — gitignored going forward |

### Files to GITIGNORE (remove from tracking, keep on disk)

| Path | Reason |
|------|--------|
| `data/` (all except `blocked_domains.txt`) | Generated pipeline output |

---

## 5. Code Changes Needed

### New files to create

**`src/dns_detect/utils/paths.py`** — Project root resolution:
```python
from pathlib import Path

def find_project_root() -> Path:
    current = Path(__file__).resolve().parent
    for _ in range(10):
        if (current / "config" / "settings.yaml").exists():
            return current
        current = current.parent
    raise RuntimeError("Cannot find project root (no config/settings.yaml)")

PROJECT_ROOT = find_project_root()
```

**`src/dns_detect/config.py`** — Settings loader:
- Reads `config/settings.yaml`
- Resolves all paths relative to `PROJECT_ROOT`
- Env var overrides: `DNS_DETECT_MODELS_DIR`, `DNS_DETECT_LOG_DIR`, `MDTI_*`

**`config/settings.yaml`** — Centralized configuration:
- All directory paths (models, data/raw, data/processed, outputs, logs, dns_logs)
- Model filenames (Path A: rf, transformer, scaler, threshold; Path B: h5, norm, threshold)
- Training params: n_days=20, sequence_length=10
- Ensemble weights: rf_weight=0.6, tf_weight=0.4
- Detection thresholds: zscore=2.0, nxdomain=200, tunneling entropy=4.0, etc.

### Import rewiring (per file)

**`src/dns_detect/models/path_a.py`** (was `Model.py`):
- `from dns_parser import ...` → `from dns_detect.parsing.dns_parser import load_as_dataframe, FEATURES_8`
- Replace bare CWD model constants (`MODEL_RF = "dns_tunnel_rf.pkl"`) with config-driven paths

**`src/dns_detect/models/path_b_train.py`** (was `Train.py`):
- Remove `sys.path.insert(0, SCRIPT_DIR)` (line 30)
- Remove `importlib.import_module("Model")` (line 45) → `from dns_detect.models.path_a import transformer_encoder`
- Model output dir: `"model/"` → config `models_dir`

**`src/dns_detect/models/path_b_predict.py`** (was `Predict.py`):
- `from dns_parser import ...` → `from dns_detect.parsing.dns_parser import load_as_array`
- `model_dir="model"` default → config fallback

**`src/dns_detect/fusion/bridge.py`** (was `Ml_bridge.py`) — **most complex rewiring**:
- Remove `sys.path.insert(0, ...)` (line 48)
- Remove both `importlib.import_module()` blocks (lines 60-77)
- Replace with clean imports:
  ```python
  from dns_detect.parsing.dns_parser import load_as_dataframe, load_as_array, FEATURES_8, _load_json_records, week3_record_to_length
  from dns_detect.models.path_a import build_sequences_unlabeled, ensemble_predict, load_threshold, SEQUENCE_LENGTH
  from dns_detect.models.path_b_predict import load_model_artifacts, build_windows, compute_reconstruction_errors, normalize_scores
  ```
- Model path loading: from config instead of bare filenames

**`src/dns_detect/features/extractor.py`** (was `DNS_feature_extractor.py`):
- Lines 709-710: Replace hardcoded `/home/paifern/...` with config-driven paths
  ```python
  from dns_detect.config import settings
  log_directory = str(settings.resolve_path("dns_logs_dir"))
  output_directory = str(settings.resolve_path("data_processed_dir"))
  ```

**`src/dns_detect/detection/engine.py`** (was `Week4_detection_engine.py`):
- Minimal changes — already standalone. Optionally load thresholds from config.

### Shell script rewrites

**`scripts/run_pipeline.sh`** and **`scripts/train_models.sh`**:
- Replace `BASE_DIR="/home/paifern/..."` with:
  ```bash
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
  ```
- Derive all paths from `$PROJECT_ROOT`
- Remove model copy dance (Run_Pipeline.sh lines 169-181) — Python loads from `$PROJECT_ROOT/models/` directly
- Change `python3 Model.py` → `PYTHONPATH="$PROJECT_ROOT/src" python3 -m dns_detect.models.path_a`
- Change `cd "$SCRIPT_DIR"` → `cd "$PROJECT_ROOT"`

### attack.c fix

Lines 47-48: Replace hardcoded `/home/paifern/` wordlist paths with `NULL` defaults (require `-w` flag):
```c
#define DEFAULT_WORDLIST         NULL  /* Pass via -w flag */
#define DEFAULT_NXDOMAIN_WORDLIST NULL
```

---

## 6. Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **SSL key in git history** | CRITICAL | Rotate key immediately. Scrub history with `git-filter-repo --invert-paths --path nginx-1.28.1/ssl/lab.key`. Force-push after all restructuring. |
| **Model artifacts lost during move** | HIGH | Back up `model_memory/` to a tarball before starting. Models are moved, never deleted without verification. |
| **Import breakage after Python restructure** | MEDIUM | Commit 4 moves all Python files AND updates all imports in a single atomic commit. Smoke test verifies imports immediately. |
| **Shell scripts fail on new paths** | MEDIUM | `bash -n` syntax check after rewrite. `grep -r "/home/paifern" scripts/` must return nothing. |
| **Pipeline produces different results** | MEDIUM | Capture baseline outputs before starting (see verification checklist). Compare after restructure. |
| **Firebase API key exposure** | LOW | Client-side Firebase keys are restricted by security rules. Audit Firebase console rules if repo goes public. |
| **model_memory JSON contains `/home/paifern/` paths** | LOW | These are historical metadata (informational). They'll be regenerated on next training run. Not used for path resolution. |

---

## 7. Execution Order

### Pre-work
```bash
git checkout -b restructure-backup   # safety snapshot
git checkout -b restructure          # working branch
# Back up model artifacts
tar czf ~/model_backup.tar.gz model_memory/
```

### Commit 1: Security — Add .gitignore, remove secrets and tracked junk
- Create `.gitignore`, `.env.example`
- `git rm --cached` all .pyc, logs, compiled binary, `nginx-1.28.1/ssl/lab.key`
- `git rm -r __pycache__/` (orphaned root), `scripts/__pycache__/`
- Verify: `git ls-files | grep -E "\.pyc|lab\.key|\.log$"` returns nothing

### Commit 2: Remove nginx bundle and duplicate model artifacts
- `git rm -r nginx-1.28.1/contrib/ nginx-1.28.1/docs/ nginx-1.28.1/nginx.exe`
- `git rm` stock nginx config files (fastcgi.conf, etc.), 50x.html, ssl/lab.crt
- `git rm` all duplicate model files in `scripts/` and `scripts/model/`
- `git rm scripts/pipeline_live.log scripts/attack`
- Verify: `git ls-files | grep -E "nginx\.exe|contrib|scripts/dns_tunnel"` returns nothing

### Commit 3: Create directory structure, move docs + infra + data
- Create all target directories
- `git mv` docs, infra configs, raw DNS logs, attack.c, model_memory → models
- Move nginx our-files (nginx.conf, html/*)
- Create new slim `README.md`
- Remove now-empty directories
- Verify: `ls docs/ infra/ attacks/ data/raw/` shows expected files

### Commit 4: Create Python package and rewrite imports
- Create `__init__.py` files, `config.py`, `paths.py`, `config/settings.yaml`
- `git mv` all 7 Python files to their new locations
- Update all imports, remove sys.path/importlib hacks, replace hardcoded paths
- Create `requirements.txt`
- Verify: `PYTHONPATH=src python -c "from dns_detect.fusion.bridge import run_bridge"` imports cleanly

### Commit 5: Rewrite shell scripts
- `git mv` + rewrite both shell scripts (lowercase names, dynamic paths)
- Move `pipeline_awareness_check.sh` to `scripts/`
- Create `attacks/Makefile`
- Fix `attack.c` hardcoded paths
- Verify: `bash -n scripts/*.sh` passes; `grep -rn "/home/paifern" src/ scripts/ attacks/` returns nothing

### Commit 6: Add smoke tests
- Create `tests/__init__.py`, `tests/test_smoke.py`
- Verify: `PYTHONPATH=src python -m pytest tests/test_smoke.py` passes

### Post-restructure: History scrubbing (separate, destructive)
```bash
pip install git-filter-repo
git filter-repo --invert-paths --path nginx-1.28.1/ssl/lab.key
git push --force-with-lease  # coordinate with collaborators
```

---

## 8. Verification Checklist

### Before starting (capture baseline)
```bash
# Save current alert output as reference
cp data/week4_unified_alerts.json ~/baseline_alerts.json
sha256sum data/week4_unified_alerts.json > ~/baseline_hashes.txt
python3 -c "import json; d=json.load(open('data/week4_unified_alerts.json')); print(d.get('total_alerts', len(d.get('alerts',[]))))"
# Record the number
```

### After each commit
| Commit | Verification |
|--------|-------------|
| 1 | `git ls-files \| grep -E "\.pyc\|lab\.key"` → empty |
| 2 | `git ls-files \| grep -E "nginx\.exe\|scripts/dns_tunnel"` → empty |
| 3 | `ls docs/PLAN.md infra/technitium-elk/docker-compose.yml attacks/attack.c data/raw/2026-03-18.log` → all exist |
| 4 | `PYTHONPATH=src python -c "from dns_detect.parsing.dns_parser import FEATURES_8; print(len(FEATURES_8))"` → `8` |
| 5 | `bash -n scripts/run_pipeline.sh` → clean; `grep -rn "/home/paifern" src/ scripts/ attacks/` → empty |
| 6 | `PYTHONPATH=src python -m pytest tests/test_smoke.py` → pass |

### End-to-end (after all commits)
```bash
cd project_root
export PYTHONPATH=src
python -m dns_detect.features.extractor --input data/raw/2026-03-18.log --output data/processed/test_features.json
python -c "import json; d=json.load(open('data/processed/test_features.json')); print(f'{len(d)} records')"
# Compare alert count with baseline
```

### Global hardcoded path check
```bash
grep -rn "/home/paifern" src/ scripts/ config/ attacks/ infra/
# Must return 0 results
```

---

## 9. Needs Your Decision

1. **Orphaned root `__pycache__/` (config, detector, monitor .pyc)** — These are Python 3.12 compiled files with no matching `.py` source anywhere. Do you have the original `config.py`, `detector.py`, `monitor.py` somewhere else, or are these from a scrapped earlier design? Safe to delete?

2. **`data/blocked_domains.txt`** — Is this a curated reference file you maintain, or a generated output? Currently planning to keep it tracked.

3. **Firebase config in `customer.js`** — Client-side API keys are typically safe, but do you want to extract it to an env-loaded config, or leave as-is since it's a lab demo?

4. **Raw DNS logs (`data/raw/*.log`)** — Should these stay tracked in git (they're your test dataset, ~3 files), or gitignored with a note on how to obtain them?

5. **Model artifacts** — After restructure, `models/` will be gitignored. Do you want to keep one snapshot of trained models tracked (e.g., via Git LFS) for reproducibility, or always regenerate via `train_models.sh`?

6. **`nginx-1.28.1/ssl/lab.key` history scrubbing** — This requires `git filter-repo` + force-push, which rewrites history for all collaborators. Should we do this as part of the restructure, or defer it?
