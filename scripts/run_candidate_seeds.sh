#!/usr/bin/env bash
# Train one candidate with several seeds into runs/<name>_s<seed> (never models/), then run the
# pass/fail gate (scripts/compare_models.py + config/success_criteria.yaml).
#
#   ./scripts/run_candidate_seeds.sh                         # labelled_v3 bundle, Isolation Forest, seeds 42 43 44
#   NAME=x SEEDS="42 43 44 45 46" SPLIT=path/to/split.json ./scripts/run_candidate_seeds.sh
#   FILES="a.json b.json" ./scripts/run_candidate_seeds.sh   # other training files
#
# Every seed uses the same split manifest, so seeds differ only in model randomness.
# A seed whose folder already has evaluation_metrics.json is not trained again.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${NAME:-labelled_v3_iforest}"
SEEDS="${SEEDS:-42 43 44}"
SPLIT="${SPLIT:-dashboard/training-gui/gui_data/runs/20261119-015201-8ffe/model/split_manifest.json}"
read -r -a FILES <<< "${FILES:-data/external/cic/cic_benign_train.json data/processed/labeled_benign.json data/processed/labeled_tunnels.json}"

[[ -f "$SPLIT" ]] || { echo "✗ split manifest not found: $SPLIT (set SPLIT=...)" >&2; exit 1; }
for f in "${FILES[@]}"; do [[ -f "$f" ]] || { echo "✗ training file not found: $f" >&2; exit 1; }; done

export PYTHONUNBUFFERED=1
mkdir -p runs
cp -f "$SPLIT" "runs/${NAME}_split.json"
start=$(date +%s)
for s in $SEEDS; do
  out="runs/${NAME}_s$s"
  if [[ -f "$out/evaluation_metrics.json" ]]; then echo "• seed $s: already trained ($out)"; continue; fi
  echo "• seed $s → $out"
  mkdir -p "$out"
  DNS_DETECT_MODELS_DIR="$out" bash scripts/train_models.sh --seed "$s" --n-days 20 --path-b-model iforest \
    --force-retrain --split-manifest "runs/${NAME}_split.json" --files "${FILES[@]}"
done
echo "• trained in $(( ($(date +%s) - start) / 60 )) min"

runs=()
for s in $SEEDS; do runs+=("runs/${NAME}_s$s"); done
python3 scripts/compare_models.py --runs "${runs[@]}" --out "runs/${NAME}_gate.json" || true
echo "• gate report: runs/${NAME}_gate.json"
