# DNS Traffic Anomaly Detection

**Hybrid Machine Learning Fusion for DNS Threat Detection**
CADT Capstone Project, 2025-2026

## Overview

Detects DNS-based attacks (tunneling, NXDOMAIN floods, amplification, cache poisoning) using a two-path ML fusion approach:

- **Path A:** Random Forest + Transformer ensemble (supervised classification)
- **Path B:** Trafficformer autoencoder (unsupervised anomaly detection)
- **ML Bridge:** Fuses both paths into a combined threat score
- **Detection Engine:** 6 rules + Z-score + MITRE ATT&CK mapping

## Architecture

```
Technitium DNS Server --> Filebeat --> Logstash --> Elasticsearch
                                          |
                                    Raw DNS Logs
                                          |
                              DNS Feature Extractor
                                          |
                        +-----------------+-----------------+
                        |                                   |
                    Path A (RF+TF)                   Path B (Trafficformer)
                        |                                   |
                        +----------> ML Bridge <------------+
                                        |
                                Detection Engine
                                        |
                                  Unified Alerts
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Train Path A + Path B + learned fusion on one shared time-ordered split
./scripts/train_models.sh --force-retrain \
    --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json
#   split: reuses data/processed/splits/time_seed42.json (test rows frozen; new rows → train/val)
#          and saves it as models/split_manifest.json
#   keep a run separate for comparison:  DNS_DETECT_MODELS_DIR=runs/v2 ./scripts/train_models.sh ...

# Run detection pipeline
./scripts/run_pipeline.sh
```

The ML bridge runs in **production mode** by default (`ensemble.bridge_mode` in `config/settings.yaml`):
it stops with an error when the Path A model or the learned fusion model (`ensemble.fusion: lr`) is missing,
instead of emitting unscored records. For demos without trained fusion, run the bridge with `--dev`
(or set `bridge_mode: development`); records that fall back are marked `fusion_method = or_fallback` /
`degraded`. See `docs/research/BRIDGE_V2_IMPLEMENTATION_REPORT.md`.

## Project Structure

```
config/          - settings.yaml (paths, thresholds, weights)
src/dns_detect/  - Python package (parsing, features, models, fusion, detection)
scripts/         - Shell CLI wrappers (train, detect)
attacks/         - Lab attack simulator (attack.c)
infra/           - Docker Compose (Technitium+ELK), nginx lab config
models/          - Trained model artifacts (gitignored)
data/raw/        - Raw DNS logs from Technitium
docs/            - Full academic paper, technical docs, extension plan
tests/           - Smoke tests
```

## Documentation

- [Full Academic Paper](docs/README_full.md)
- [Technical Documentation](docs/Document_DNS.md)
- [Extension Plan](docs/PLAN.md)

## Current Progress (2026-11-10)

### Completed

- **8 tunnel tools** converted and tested: dns2tcp, dnsexfiltrator, dns_shell, det, ozymandns, cobaltstrike, dnscat2, iodine
- **Baseline generalizes to unseen tools:** trained only on dns2tcp and dnsexfiltrator, it detected 5 of 6 new tools at 100% recall and iodine at 99.92% (4,996/5,000)
- **v3 combined model trained:** 100,000 attack rows (8 tools) + 118,334 benign rows, near 1:1 balance — 12x larger than any earlier run
- **v3 fusion results:** 7 false alarms on the frozen test set (down from 23 baseline), recall 1.0, precision 0.995
- **Tu et al. (2023) benign data converted:** 876,599 rows from 4 captures
- **Week 4 plan fully complete** — all per-tool tasks, unseen-tool tests, and documentation done

### v3 Model Comparison

| Run | Attack rows | Benign rows | Fusion false alarms | Recall |
|---|---|---|---|---|
| baseline | 10,000 | 8,349 | 23 | 1.0 |
| v_dnsshell | 15,000 | 8,349 | 7 | 1.0 |
| v_det | 15,000 | 8,349 | 38 | 1.0 |
| **v3** | **100,000** | **118,334** | **7** | **1.0** |

### Remaining Work

1. ~~Evaluate v3 on CIC capture 3~~ — done 2026-11-14: 1 / 25,222 false alarms (0.004%), within the 0.1% budget
2. Leave-one-tool-out test — main recall test since the frozen test set only contains dnsexfiltrator
3. Multi-seed check (5 seeds) for baseline, v_dnsshell, v_det, and v3
4. Fix Path B autoencoder — recall dropped to 0.0 after training on larger benign set (fusion compensates via Path A, but Path B needs repair)
5. Write conclusion and decide whether v3 replaces production `models/`

See [Week 5 Progress Report](docs/Week5/WEEK5_PROGRESS_REPORT.md) and [V3 Training Plan](docs/Week5/V3_BALANCED_TRAINING.md) for full details.

## Configuration

All paths, thresholds, and model parameters are in `config/settings.yaml`.
Environment variable overrides available via `.env` (see `.env.example`).
