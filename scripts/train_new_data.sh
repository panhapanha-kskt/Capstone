#!/usr/bin/env bash
# train_new_data.sh — Week 7 Task 2, steps 37–39: add new labelled captures to the training data,
# check them, and train a candidate over 3 seeds through the gate (Part B). Never writes to models/
# directly: promotion only happens through scripts/part_b.py (with AUTO_PROMOTE=1 or by hand).
#
#   bash scripts/train_new_data.sh data/processed/week7              # check → EDA → 3 seeds → gate
#   bash scripts/train_new_data.sh data/processed/week7 --check-only  # checksums + rule check, no training
#   AUTO_PROMOTE=1 bash scripts/train_new_data.sh data/processed/week7
#   RUN_NAME=v4 SEEDS="42 43 44" bash scripts/train_new_data.sh data/processed/week7
#
# Steps:
#   1. checksums: every file listed in <dir>/SHA256SUMS that is present here must match
#      (pcaps stay on the capture machine and are skipped)
#   2. file list: the live model's training files (models/training_provenance.json) + <dir>/*.json;
#      stops if any of the live files is missing (a candidate must not learn from less data)
#   3. per-file rows and labels; the record-type rule (TXT/NULL/KEY) on all labelled rows —
#      the point of the new data is that this rule is no longer perfect
#   4. EDA report (train_models.sh --eda-only)
#   5. seed 1 with a fresh time-ordered split (the new captures are the newest rows, so they land
#      in the test set), then the other seeds on that same split + the gate (run_candidate_seeds.sh)
# Writes <dir>/files_<RUN_NAME>.txt and <dir>/check_<RUN_NAME>.json.
set -euo pipefail
cd "$(dirname "$0")/.."

DIR="${1:?usage: train_new_data.sh <dir with new labelled .json files> [--check-only]}"
CHECK_ONLY=false; [[ "${2:-}" == "--check-only" ]] && CHECK_ONLY=true
RUN_NAME="${RUN_NAME:-newdata_$(date +%Y%m%d_%H%M%S)}"
SEEDS="${SEEDS:-42 43 44}"
PYTHON="${PYTHON:-python3}"
[[ -d "$DIR" ]] || { echo "✗ not a folder: $DIR" >&2; exit 1; }
FIRST_SEED="${SEEDS%% *}"
LIST="$DIR/files_${RUN_NAME}.txt"
CHECK="$DIR/check_${RUN_NAME}.json"

say() { printf '\033[0;36m•\033[0m %s\n' "$*"; }

# 1. checksums ────────────────────────────────────────────────────
if [[ -f "$DIR/SHA256SUMS" ]]; then
  say "checking $DIR/SHA256SUMS"
  out=$(sha256sum -c "$DIR/SHA256SUMS" --ignore-missing 2>&1) || { echo "$out" >&2; echo "✗ checksum mismatch: a file changed after capture" >&2; exit 1; }
  echo "$out" | sed 's/^/    /'
else
  echo "! no $DIR/SHA256SUMS: the new files can't be verified (scripts/lab_capture.sh writes it)" >&2
fi

# 2. file list ────────────────────────────────────────────────────
"$PYTHON" - "$DIR" "$LIST" <<'PY'
import json, os, sys, glob
d, out = sys.argv[1], sys.argv[2]
live = [f["path"] for f in json.load(open("models/training_provenance.json"))["source_files"]]
new = sorted(p for p in glob.glob(os.path.join(d, "*.json"))
             if not os.path.basename(p).startswith(("check_", "files_")))
missing = [p for p in live if not os.path.isfile(p)]
if missing:
    sys.exit("✗ live model's training files missing here (copy them first, e.g. from the Kali VM):\n    "
             + "\n    ".join(missing))
if not new:
    sys.exit(f"✗ no new .json files in {d}")
files = live + [p for p in new if p not in live]
open(out, "w").write("\n".join(files) + "\n")
print(f"• {len(live)} live-model files + {len(new)} new files → {out}")
PY

# 3. rows, labels, record-type rule ───────────────────────────────
"$PYTHON" - "$LIST" "$CHECK" <<'PY'
import json, sys
files = [l.strip() for l in open(sys.argv[1]) if l.strip()]
TUNNEL_RR = {"TXT", "NULL", "KEY"}
per, tot = [], {"attack": 0, "benign": 0, "a_rr": 0, "b_rr": 0}
for f in files:
    d = json.load(open(f))
    d = d.get("records", d) if isinstance(d, dict) else d
    a = [r for r in d if str(r.get("label")) in ("1", "1.0")]
    b = [r for r in d if str(r.get("label")) in ("0", "0.0")]
    rr = lambda r: str(r.get("query_type", "")).upper() in TUNNEL_RR
    per.append({"file": f, "rows": len(d), "attack": len(a), "benign": len(b),
                "query_types": sorted({str(r.get("query_type", "")).upper() for r in d})[:8]})
    tot["attack"] += len(a); tot["benign"] += len(b)
    tot["a_rr"] += sum(map(rr, a)); tot["b_rr"] += sum(map(rr, b))
recall = tot["a_rr"] / max(tot["attack"], 1)
fpr = tot["b_rr"] / max(tot["benign"], 1)
perfect = recall >= 0.999 and fpr <= 0.001
for p in per:
    print(f"    {p['rows']:>7} rows  attack {p['attack']:>6}  benign {p['benign']:>6}  {','.join(p['query_types'])}  {p['file']}")
print(f"• record-type rule (TXT/NULL/KEY = tunnel): catches {recall:.1%} of tunnels, flags {fpr:.2%} of normal queries")
print("  ✗ still PERFECT on this data: the new captures don't change the picture yet" if perfect else
      "  ✓ no longer perfect: the test can now show what the ML adds")
json.dump({"files": per, "rule_record_type": {"recall": recall, "fpr": fpr, "perfect": perfect},
           "attack_rows": tot["attack"], "benign_rows": tot["benign"]}, open(sys.argv[2], "w"), indent=2)
PY
say "check report → $CHECK"
$CHECK_ONLY && exit 0

# 4. EDA ──────────────────────────────────────────────────────────
mapfile -t FILES < "$LIST"
say "EDA report (data/processed/eda_data_report.html)"
# DNS_DETECT_MODELS_DIR: --eda-only still runs the merge, which rewrites <models dir>/training_provenance.json;
# point it at a scratch run folder so the live models/ is never written here (only promote_model.sh may).
DNS_DETECT_MODELS_DIR="runs/${RUN_NAME}_eda" bash scripts/train_models.sh --eda-only --force-retrain --files "${FILES[@]}"

# 5. seeds + gate ────────────────────────────────────────────────
mkdir -p runs
FIRST="runs/${RUN_NAME}_s${FIRST_SEED}"
if [[ ! -f "$FIRST/evaluation_metrics.json" ]]; then
  say "seed $FIRST_SEED with a fresh time-ordered split → $FIRST"
  DNS_DETECT_MODELS_DIR="$FIRST" bash scripts/train_models.sh --force-retrain --new-split --seed "$FIRST_SEED" \
    --path-b-model iforest --n-days 20 --files "${FILES[@]}"
fi
say "remaining seeds on the same split + gate"
RUN_NAME="$RUN_NAME" SEEDS="$SEEDS" SPLIT="$FIRST/split_manifest.json" FILES="${FILES[*]}" \
  AUTO_PROMOTE="${AUTO_PROMOTE:-0}" SHADOW="${SHADOW:-0}" bash scripts/run_candidate_seeds.sh
