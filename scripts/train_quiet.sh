#!/usr/bin/env bash
# train_quiet.sh — run the 4-step retrain-and-verify sequence, strip the scapy
# and TensorFlow noise, and write a clean log plus a full raw log.
#
# Usage:   ./scripts/train_quiet.sh
# Outputs: logs/train_quiet_<ts>.log   (clean, what you want to read)
#          logs/train_quiet_<ts>.raw   (full output, kept just in case)

set -o pipefail

PROJECT_ROOT="/home/ounnha/Documents/Capstone"
cd "$PROJECT_ROOT" || { echo "cannot cd $PROJECT_ROOT" >&2; exit 1; }

TS=$(date +%Y%m%d_%H%M%S)
mkdir -p logs
CLEAN_LOG="logs/train_quiet_${TS}.log"
RAW_LOG="logs/train_quiet_${TS}.raw"

# Resolve filter_noise.py: prefer the one in scripts/, fall back to scratchpad
FILTER="scripts/filter_noise.py"
if [ ! -f "$FILTER" ]; then
    FILTER="/tmp/claude-1000/-home-ounnha-Documents-Capstone/f0d030ed-afe5-4e40-83c4-516f4bf96efe/scratchpad/filter_noise.py"
fi

{
    echo "══════════════════════════════════════════════════════════════"
    echo "  STEP 1 — regenerate benign features (base64 fix propagates)"
    echo "══════════════════════════════════════════════════════════════"
    python3 scripts/make_labeled_features.py --label 0 --family benign \
        --input /home/ounnha/Downloads/benign_dns.pcap \
        --output data/processed/labeled_benign.json

    echo
    echo "══════════════════════════════════════════════════════════════"
    echo "  STEP 2 — benign false-positive rate from heuristic rules"
    echo "          (was 0.238 before the base64 fix)"
    echo "══════════════════════════════════════════════════════════════"
    python3 -c "import json,pandas as pd; d=pd.DataFrame(json.load(open('data/processed/labeled_benign.json'))); print('benign FP rate:', round(((d.attack_count>0)&(d.label==0)).mean(), 4))"

    echo
    echo "══════════════════════════════════════════════════════════════"
    echo "  STEP 3 — retrain Path A + Path B"
    echo "══════════════════════════════════════════════════════════════"
    ./scripts/train_models.sh --force-retrain \
        --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json

    echo
    echo "══════════════════════════════════════════════════════════════"
    echo "  STEP 4 — read Path B metrics from evaluation_metrics.json"
    echo "══════════════════════════════════════════════════════════════"
    python3 -c "
import json
m = json.load(open('models/evaluation_metrics.json'))
pb = m.get('path_b')
if pb is None:
    print('⚠  Path B block STILL missing from evaluation_metrics.json')
else:
    print('✅ Path B metrics are present:')
    print(json.dumps(pb, indent=2))
pa = m.get('path_a', {})
print()
print('── Path A (for reference) ──')
for k in ('precision','recall','f1','pr_auc','roc_auc','threshold','decision'):
    if k in pa:
        print(f'  {k:12s}: {pa[k]}')
"
} 2>&1 \
    | tee "$RAW_LOG" \
    | python3 "$FILTER" \
    | tee "$CLEAN_LOG"

echo
echo "──────────────────────────────────────────────────────────────"
echo "Clean log   → $CLEAN_LOG"
echo "Full raw    → $RAW_LOG"
echo "──────────────────────────────────────────────────────────────"
