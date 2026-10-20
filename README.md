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

# Train models (run once)
./scripts/train_models.sh

# Run detection pipeline
./scripts/run_pipeline.sh
```

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

## Configuration

All paths, thresholds, and model parameters are in `config/settings.yaml`.
Environment variable overrides available via `.env` (see `.env.example`).
