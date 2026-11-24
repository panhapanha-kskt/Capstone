#!/usr/bin/env bash
# Train one candidate with several seeds into runs/<name>_s<seed> (never models/), then run the
# pass/fail gate (scripts/compare_models.py + config/success_criteria.yaml) via scripts/part_b.py.
# AUTO_PROMOTE=1 promotes the median seed on PASS, smoke-tests it and rolls back if that fails.
#
#   ./scripts/run_candidate_seeds.sh                         # same data + split as the live model, seeds 42 43 44
#   RUN_NAME=x SEEDS="42 43 44 45 46" SPLIT=path/to/split.json ./scripts/run_candidate_seeds.sh
#   FILES="a.json b.json" ./scripts/run_candidate_seeds.sh   # other training files (on purpose)
#   ADD_FILES="new.json" ./scripts/run_candidate_seeds.sh     # the live model's files + new ones ("train more data")
#   FEEDBACK=data/feedback/verdict_labels.json ./scripts/run_candidate_seeds.sh   # + analyst verdicts, every seed
#
# Default training files = models/training_provenance.json (what the live model learned from), and
# default split = models/split_manifest.json (the live model's frozen test rows). So a retrain is never
# weaker by accident, and the gate compares candidate and live model on the same test rows. If one of
# those files is missing, the script stops and says which, instead of silently training on less.
#   Old 2-tool bundle:  RUN_NAME=labelled_v3_iforest FILES="data/external/cic/cic_benign_train.json data/processed/labeled_benign.json data/processed/labeled_tunnels.json" \
#                       SPLIT=dashboard/training-gui/gui_data/runs/20261119-015201-8ffe/model/split_manifest.json ./scripts/run_candidate_seeds.sh
#
# Every seed uses the same split manifest, so seeds differ only in model randomness.
# A seed whose folder already has evaluation_metrics.json is not trained again.
set -euo pipefail
cd "$(dirname "$0")/.."

# RUN_NAME, not NAME: WSL sets NAME to the computer name.
RUN_NAME="${RUN_NAME:-candidate_$(date +%Y%m%d_%H%M%S)}"
SEEDS="${SEEDS:-42 43 44}"
LIVE_PROV="models/training_provenance.json"
if [[ -z "${SPLIT:-}" ]]; then
  SPLIT="models/split_manifest.json"
  echo "• split: the live model's ($SPLIT)"
fi
if [[ -n "${FILES:-}" ]]; then FILES_GIVEN=true; else FILES_GIVEN=false; fi
if [[ -z "${FILES:-}" ]]; then
  [[ -f "$LIVE_PROV" ]] || { echo "✗ $LIVE_PROV not found: set FILES=\"...\" (or run_all.sh --files ...)" >&2; exit 4; }
  FILES="$(python3 -c 'import json,sys; print(" ".join(f["path"] for f in json.load(open(sys.argv[1]))["source_files"]))' "$LIVE_PROV")"
  echo "• training files: the live model's ($LIVE_PROV)"
fi
read -r -a FILES <<< "$FILES"
if [[ -n "${ADD_FILES:-}" ]]; then
  [[ "$FILES_GIVEN" == false ]] || { echo "✗ set FILES or ADD_FILES, not both (ADD_FILES already starts from the live model's files)" >&2; exit 4; }
  read -r -a ADD <<< "$ADD_FILES"
  added=0
  for a in "${ADD[@]}"; do
    dup=false
    for f in "${FILES[@]}"; do [[ "$(realpath -m "$f")" == "$(realpath -m "$a")" ]] && { dup=true; break; }; done
    if [[ "$dup" == true ]]; then
      echo "• add-files: $a is already a training file of the live model (not added twice)"
    else
      FILES+=("$a"); added=$((added + 1))
    fi
  done
  echo "• add-files: $added new file(s) added to the live model's training files"
fi

[[ -f "$SPLIT" ]] || { echo "✗ split manifest not found: $SPLIT (set SPLIT=...)" >&2; exit 4; }
missing=()
for f in "${FILES[@]}"; do [[ -f "$f" ]] || missing+=("$f"); done
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "✗ ${#missing[@]} of ${#FILES[@]} training files are not on this machine, so the candidate would learn from" >&2
  echo "  less data than the live model. Nothing was trained. Missing:" >&2
  printf '    %s\n' "${missing[@]}" >&2
  echo "  Copy them here (e.g. from the Kali VM with scp), or train on a subset on purpose with" >&2
  echo "  FILES=\"...\" / run_all.sh --retrain --files ... (the gate will then compare a weaker candidate)." >&2
  exit 4
fi

export PYTHONUNBUFFERED=1
feedback=(); [[ -n "${FEEDBACK:-}" ]] && feedback=(--feedback "$FEEDBACK")   # unset: command unchanged
mkdir -p runs
cp -f "$SPLIT" "runs/${RUN_NAME}_split.json"
start=$(date +%s)
for s in $SEEDS; do
  out="runs/${RUN_NAME}_s$s"
  if [[ -f "$out/evaluation_metrics.json" ]]; then echo "• seed $s: already trained ($out)"; continue; fi
  echo "• seed $s → $out"
  mkdir -p "$out"
  DNS_DETECT_MODELS_DIR="$out" bash scripts/train_models.sh --seed "$s" --n-days 20 --path-b-model iforest \
    --force-retrain --split-manifest "runs/${RUN_NAME}_split.json" --files "${FILES[@]}" ${feedback[@]+"${feedback[@]}"}
done
echo "• trained in $(( ($(date +%s) - start) / 60 )) min"

# Gate → (promote with AUTO_PROMOTE=1) → smoke test → rollback. The exit code is part_b.py's:
# 0 promoted · 10 PASS, ready to promote · 1 FAIL (models/ unchanged) · 2 rolled back · 3 busy/error.
promote_flag=()
[[ "${AUTO_PROMOTE:-0}" == 1 ]] && promote_flag=(--auto-promote)
[[ "${SHADOW:-0}" == 1 ]] && promote_flag+=(--shadow)   # SHADOW=1: shadow check on current traffic before promote
python3 scripts/part_b.py --name "$RUN_NAME" --seeds "$SEEDS" "${promote_flag[@]+"${promote_flag[@]}"}"
