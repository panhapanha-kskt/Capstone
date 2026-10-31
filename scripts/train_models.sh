#!/bin/bash
# ============================================================
#  DNS Traffic Anomaly Detection — ML Model Trainer
#  Trains Path A (RF + GBT) and Path B (Trafficformer) and saves them to models/.
#  Prints one short line per stage; the full output goes to logs/training_<time>.log.
#
#  Usage:
#    ./scripts/train_models.sh                              # scan data/raw/
#    ./scripts/train_models.sh --data-dir /path/to/folder   # scan a folder
#    ./scripts/train_models.sh --files a.csv b.pcap c.log   # specific files
#    ./scripts/train_models.sh --retrain                    # only files not trained before
#    ./scripts/train_models.sh --force-retrain              # retrain on all given data
#    ./scripts/train_models.sh --path-a-only | --path-b-only
#    ./scripts/train_models.sh --eda-only                   # stop after both EDA reports
#    ./scripts/train_models.sh --verbose                    # also stream the full output
#    ./scripts/train_models.sh --help
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; BOLD=''; NC=''; }   # no colour codes when piped

STEP_N=0
STEP_TOTAL=10
TRAIN_LOG=""
VERBOSE=false
EDA_ONLY=false
declare -a NOTES=()

# ── OUTPUT ─────────────────────────────────────────────────
# say: one numbered line per stage, followed by any notes collected for it.
# later: queue a warning to print under the next stage line.
log()   { if [[ -n "$TRAIN_LOG" ]]; then echo "$*" >> "$TRAIN_LOG"; fi; }
note()  { printf "      ${YELLOW}! %s${NC}\n" "$*"; log "  ! $*"; }
later() { NOTES+=("$*"); }
flush_notes() {
  local n
  for n in "${NOTES[@]+"${NOTES[@]}"}"; do note "$n"; done
  NOTES=()
}
say() {
  STEP_N=$((STEP_N + 1))
  printf "${GREEN}[%d/%d]${NC} %s\n" "$STEP_N" "$STEP_TOTAL" "$*"
  log "[$STEP_N/$STEP_TOTAL] $*"
  flush_notes
}
fail() {
  flush_notes
  printf "${RED}✗ %s${NC}\n" "$*" >&2
  log "✗ $*"
  if [[ -n "$TRAIN_LOG" ]]; then printf "  Full log: %s\n" "$TRAIN_LOG" >&2; fi
  exit 1
}

# run: command output goes to the log only (and to the screen with --verbose).
run() {
  if [[ "$VERBOSE" == true ]]; then
    "$@" 2>&1 | tee -a "$TRAIN_LOG"
  else
    "$@" >> "$TRAIN_LOG" 2>&1
  fi
}
# run_or_fail: like run, but on failure show the command's last output lines and stop.
run_or_fail() {
  local msg="$1"; shift
  local start
  start=$(wc -l < "$TRAIN_LOG")
  if ! run "$@"; then
    flush_notes
    [[ "$VERBOSE" == true ]] || tail -n +$((start + 1)) "$TRAIN_LOG" | tail -n 12 | sed 's/^/    /' >&2
    fail "$msg"
  fi
}
# json_num FILE a.b.c → that number from a JSON file, or "?"
json_num() {
  python3 -c "
import json
d = json.load(open('$1'))
for k in '$2'.split('.'):
    d = d.get(k, {}) if isinstance(d, dict) else {}
print('%.4g' % d if isinstance(d, (int, float)) else '?')" 2>/dev/null || echo "?"
}

# ── PATHS (resolved from project root) ──────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_ROOT/data/processed"
LOG_DIR="$PROJECT_ROOT/logs"
MODELS_DIR="$PROJECT_ROOT/models"
DNS_LOG_DIR="$PROJECT_ROOT/data/raw"
export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export TF_CPP_MIN_LOG_LEVEL=2   # hide TensorFlow's C++ info/warning lines
export PYTHONIOENCODING=utf-8   # output goes to a log file; keep → ✅ etc. printable everywhere
export PYTHONUNBUFFERED=1       # keep stdout and tracebacks in order in the log

# ── DEFAULTS ───────────────────────────────────────────────
RETRAIN=false
FORCE_RETRAIN=false
PATH_A_ONLY=false
PATH_B_ONLY=false
PATH_B_MODEL="dns_trafficformer"
N_DAYS=20
CUSTOM_DATA_DIR=""
PCAP_LABEL=""          # provenance label applied to every query in input pcaps (0/1)
declare -a EXTRA_FILES=()

# ── ARG PARSING ────────────────────────────────────────────
show_help() {
  cat <<EOF

Usage:  ./scripts/train_models.sh [options]

Data:
  --data-dir PATH     Scan a folder (3 levels deep) for .log .pcap .pcapng .json .csv
  --files F1 F2 ...   Train on specific files (can be combined with --data-dir)
  --pcap-label 0|1    Label for every query in .pcap files (1 = attack, 0 = benign);
                      without it PCAPs are kept as unlabeled data
  (neither given)     Scan data/raw/ for .log .json .csv

  Every file found is marked labeled or unlabeled: .json/.csv rows with a 'label'
  0/1 are labeled, .pcap is labeled with --pcap-label, .log is always unlabeled.
  Unlabeled data is labeled later from data/attack_manifest.csv, else by heuristics.

EDA:
  EDA #1 runs right after finding the data: labeled data, unlabeled data and their
  comparison → data/processed/eda_data_report.html (+ .json)
  EDA #2 runs after merging: feature profile → data/processed/eda_report.json
  --eda-only          Stop after both EDA reports (no labeling, no training,
                      nothing marked as trained)

Training:
  --retrain           Train only on files not trained before (skips the rest)
  --force-retrain     Retrain on all given data
  --path-a-only       Train only Path A (RF + GBT)
  --path-b-only       Train only Path B (Trafficformer)
  --n-days N          Path B window size in queries (default: 20)
  --model-name NAME   Path B model save name (default: dns_trafficformer)

Output:
  --verbose, -v       Also stream the full training output (always written to logs/)
  --help, -h          Show this help

Labels come from data/attack_manifest.csv when it exists, otherwise from heuristics.
After training:  ./scripts/run_pipeline.sh

EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --retrain)        RETRAIN=true;           shift ;;
    --force-retrain)  FORCE_RETRAIN=true;     shift ;;
    --path-a-only)    PATH_A_ONLY=true;       shift ;;
    --path-b-only)    PATH_B_ONLY=true;       shift ;;
    --n-days)         N_DAYS="${2:?--n-days needs a number}";           shift 2 ;;
    --model-name)     PATH_B_MODEL="${2:?--model-name needs a name}";   shift 2 ;;
    --data-dir)       CUSTOM_DATA_DIR="${2:?--data-dir needs a path}";  shift 2 ;;
    --pcap-label)     PCAP_LABEL="${2:?--pcap-label needs 0 or 1}";     shift 2 ;;
    --verbose|-v)     VERBOSE=true;           shift ;;
    --eda-only)       EDA_ONLY=true;          shift ;;
    --files)
      shift
      while [[ $# -gt 0 && "$1" != --* ]]; do
        EXTRA_FILES+=("$1"); shift
      done ;;
    --help|-h)        show_help ;;
    *) printf "${YELLOW}! Unknown option ignored: %s${NC}\n" "$1"; shift ;;
  esac
done

# ── FILE PATHS ─────────────────────────────────────────────
MERGED_FEATURES="$DATA_DIR/merged_features_all.json"
MERGED_LABELED="$DATA_DIR/merged_features_labeled.json"
EDA_REPORT="$DATA_DIR/eda_report.json"              # EDA #2 (features, after merge)
EDA_DATA_REPORT="$DATA_DIR/eda_data_report.json"    # EDA #1 (labeled · unlabeled · comparison)
ATTACK_MANIFEST="$PROJECT_ROOT/data/attack_manifest.csv"   # Tier 1 ground-truth labels (if present)
TRAINED_FILES_REGISTRY="$MODELS_DIR/trained_files_registry.json"

MEM_RF="$MODELS_DIR/dns_tunnel_rf.pkl"
MEM_TF="$MODELS_DIR/dns_tunnel_transformer.keras"
MEM_SCALER="$MODELS_DIR/dns_scaler.pkl"
MEM_THRESHOLD="$MODELS_DIR/dns_threshold.json"
MEM_PATH_B="$MODELS_DIR/${PATH_B_MODEL}.h5"
MEM_PATH_B_THRESHOLD="$MODELS_DIR/${PATH_B_MODEL}_threshold.json"
MEM_PATH_B_NORM="$MODELS_DIR/${PATH_B_MODEL}_norm.json"
MEM_METADATA="$MODELS_DIR/training_metadata.json"
MEM_PROVENANCE="$MODELS_DIR/training_provenance.json"

# ── SETUP ──────────────────────────────────────────────────
mkdir -p "$DATA_DIR" "$LOG_DIR" "$MODELS_DIR"
cd "$PROJECT_ROOT"
TRAIN_LOG="$LOG_DIR/training_$(date +%Y%m%d_%H%M%S).log"
START_TIME=$(date +%s)

printf "${BOLD}Training DNS models${NC} · log: %s\n" "${TRAIN_LOG#"$PROJECT_ROOT"/}"
log "Project root: $PROJECT_ROOT"
log "Models dir  : $MODELS_DIR"
log "Data dir    : $DATA_DIR"

# Registry of sha256 checksums for every file already trained on.
# --retrain uses it to skip known files; --force-retrain ignores it.
if [[ ! -f "$TRAINED_FILES_REGISTRY" ]]; then
  echo '{"trained_files": []}' > "$TRAINED_FILES_REGISTRY"
fi

file_already_trained() {
  local filepath="$1"
  [[ -f "$TRAINED_FILES_REGISTRY" ]] || return 1
  python3 -c "
import json, hashlib, sys
registry = json.load(open('$TRAINED_FILES_REGISTRY'))
trained  = {entry['checksum'] for entry in registry.get('trained_files', [])}
h = hashlib.sha256()
with open('$filepath', 'rb') as f:
    for chunk in iter(lambda: f.read(65536), b''): h.update(chunk)
sys.exit(0 if h.hexdigest() in trained else 1)
" 2>/dev/null
}

register_trained_file() {
  local filepath="$1"
  local records="$2"
  local filetype="$3"
  # --eda-only trains nothing, so nothing may be marked as trained
  [[ "$EDA_ONLY" == false ]] || return 0
  python3 - <<PYEOF
import json, hashlib
from datetime import datetime, timezone

registry_path = "$TRAINED_FILES_REGISTRY"
try:
    registry = json.load(open(registry_path))
except Exception:
    registry = {"trained_files": []}

h = hashlib.sha256()
with open("$filepath", "rb") as f:
    for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
checksum = h.hexdigest()

if checksum not in {e["checksum"] for e in registry["trained_files"]}:
    registry["trained_files"].append({
        "path":       "$filepath",
        "checksum":   checksum,
        "type":       "$filetype",
        "records":    "$records",
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=2)
PYEOF
}

# ══════════════════════════════════════════════════════════════
#  1. WHICH MODELS NEED TRAINING
# ══════════════════════════════════════════════════════════════
PATH_A_EXISTS=false
PATH_B_EXISTS=false
if [[ -f "$MEM_RF" && -f "$MEM_TF" && -f "$MEM_SCALER" && -f "$MEM_THRESHOLD" ]]; then PATH_A_EXISTS=true; fi
if [[ -f "$MEM_PATH_B" && -f "$MEM_PATH_B_THRESHOLD" && -f "$MEM_PATH_B_NORM" ]]; then PATH_B_EXISTS=true; fi

TRAIN_PATH_A=false
TRAIN_PATH_B=false
if [[ "$PATH_B_ONLY" == false ]] && [[ "$PATH_A_EXISTS" == false || "$RETRAIN" == true || "$FORCE_RETRAIN" == true ]]; then TRAIN_PATH_A=true; fi
if [[ "$PATH_A_ONLY" == false ]] && [[ "$PATH_B_EXISTS" == false || "$RETRAIN" == true || "$FORCE_RETRAIN" == true ]]; then TRAIN_PATH_B=true; fi

if [[ "$TRAIN_PATH_A" == false && "$TRAIN_PATH_B" == false && "$EDA_ONLY" == false ]]; then
  say "Models already trained — nothing to do (use --retrain or --force-retrain)"
  exit 0
fi

state() { if [[ "$1" == true ]]; then echo "found"; else echo "missing"; fi; }
if   [[ "$EDA_ONLY" == true ]]; then TODO="nothing (--eda-only: EDA reports only)"
elif [[ "$TRAIN_PATH_A" == true && "$TRAIN_PATH_B" == true ]]; then TODO="Path A + Path B"
elif [[ "$TRAIN_PATH_A" == true ]]; then TODO="Path A only"
else TODO="Path B only"; fi
say "Models: Path A $(state "$PATH_A_EXISTS"), Path B $(state "$PATH_B_EXISTS") → training $TODO"

# ══════════════════════════════════════════════════════════════
#  2. ENVIRONMENT
# ══════════════════════════════════════════════════════════════
command -v python3 &>/dev/null || fail "python3 not found"
python3 -c "from dns_detect.config import settings" &>/dev/null || \
  fail "dns_detect package not importable (check PYTHONPATH and src/dns_detect/)"

MISSING_PKGS=()
for spec in pandas:pandas numpy:numpy sklearn:scikit-learn tensorflow:tensorflow joblib:joblib; do
  python3 -c "import ${spec%%:*}" &>/dev/null || MISSING_PKGS+=("${spec#*:}")
done
if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
  later "Installed missing packages: ${MISSING_PKGS[*]}"
  run pip install "${MISSING_PKGS[@]}" --break-system-packages -q || fail "pip install failed: ${MISSING_PKGS[*]}"
fi
say "Environment ready ($(python3 --version 2>&1))"

# ══════════════════════════════════════════════════════════════
#  3. FIND NEW DATA
# ══════════════════════════════════════════════════════════════
declare -a SRC_CSV=()
declare -a SRC_JSON=()
declare -a SRC_PCAP=()
declare -a SRC_LOG=()
SKIPPED_ALREADY_TRAINED=0
NEW_FILES_FOUND=0

classify_file() {
  local f="$1"
  # A file the user named explicitly must exist — silently skipping it can drop a
  # whole class (e.g. the benign set) and train on the wrong data.
  [[ -f "$f" ]] || fail "File not found: $f  (check the path passed to --files / --data-dir)"

  if [[ "$FORCE_RETRAIN" == false && "$RETRAIN" == true ]] && file_already_trained "$f"; then
    SKIPPED_ALREADY_TRAINED=$((SKIPPED_ALREADY_TRAINED + 1))
    log "  skipped (already trained): $f"
    return
  fi

  case "${f,,}" in
    *.csv)           SRC_CSV+=("$f") ;;
    *.json)          SRC_JSON+=("$f") ;;
    *.pcap|*.pcapng) SRC_PCAP+=("$f") ;;
    *.log)           SRC_LOG+=("$f") ;;
    *) later "Unknown file type skipped: $f"; return ;;
  esac
  NEW_FILES_FOUND=$((NEW_FILES_FOUND + 1))
  log "  found: $f"
}

WHERE=""
if [[ -n "$CUSTOM_DATA_DIR" ]]; then
  [[ -d "$CUSTOM_DATA_DIR" ]] || fail "--data-dir not found: $CUSTOM_DATA_DIR"
  while IFS= read -r -d '' f; do
    classify_file "$f"
  done < <(find "$CUSTOM_DATA_DIR" -maxdepth 3 \
    \( -iname "*.csv" -o -iname "*.json" -o -iname "*.pcap" \
       -o -iname "*.pcapng" -o -iname "*.log" \) \
    -print0 2>/dev/null)
fi

for f in "${EXTRA_FILES[@]+"${EXTRA_FILES[@]}"}"; do
  classify_file "$f"
done

# Fallback: nothing given → default DNS log directory
if [[ $NEW_FILES_FOUND -eq 0 && $SKIPPED_ALREADY_TRAINED -eq 0 ]]; then
  WHERE="data/raw/"
  while IFS= read -r -d '' f; do
    classify_file "$f"
  done < <(find "$DNS_LOG_DIR" -maxdepth 3 \
    \( -iname "*.log" -o -iname "*.csv" -o -iname "*.json" \) \
    -print0 2>/dev/null)
fi

TOTAL_SRC=$(( ${#SRC_CSV[@]} + ${#SRC_JSON[@]} + ${#SRC_PCAP[@]} + ${#SRC_LOG[@]} ))

if [[ "$RETRAIN" == true && "$FORCE_RETRAIN" == false && $TOTAL_SRC -eq 0 ]]; then
  say "No new files since last training — models are up to date"
  exit 0
fi
[[ $TOTAL_SRC -gt 0 ]] || fail "No training data found. Use --data-dir or --files."

# ── Label status of every file: labeled data and unlabeled data both go forward ──
# .json/.csv: labeled when rows carry 'label' 0/1 (partial = some rows)
# .pcap:      labeled when --pcap-label is given, otherwise unlabeled (kept, not skipped)
# .log:       always unlabeled
declare -a SRC_LABELED=()
declare -a SRC_UNLABELED=()
PARTIAL_FILES=0
ALL_SRC=("${SRC_LOG[@]+"${SRC_LOG[@]}"}" "${SRC_PCAP[@]+"${SRC_PCAP[@]}"}"
         "${SRC_JSON[@]+"${SRC_JSON[@]}"}" "${SRC_CSV[@]+"${SRC_CSV[@]}"}")
STATUS_ARGS=(--status "${ALL_SRC[@]}")
[[ -z "$PCAP_LABEL" ]] || STATUS_ARGS+=(--pcap-label "$PCAP_LABEL")
while IFS=$'\t' read -r st _labeled_rows path; do
  path="${path%$'\r'}"   # Windows Python ends lines with \r\n
  [[ -n "$path" ]] || continue
  log "  label status: $st  $path"
  case "$st" in
    labeled)   SRC_LABELED+=("$path") ;;
    partial)   SRC_LABELED+=("$path"); PARTIAL_FILES=$((PARTIAL_FILES + 1)) ;;
    *)         SRC_UNLABELED+=("$path") ;;
  esac
done < <(python3 -m dns_detect.features.eda_data "${STATUS_ARGS[@]}" 2>>"$TRAIN_LOG")

if [[ $(( ${#SRC_LABELED[@]} + ${#SRC_UNLABELED[@]} )) -ne $TOTAL_SRC ]]; then
  later "Could not check label status (see log) — treating every file as unlabeled"
  SRC_LABELED=()
  SRC_UNLABELED=("${ALL_SRC[@]}")
fi

# "2 json, 1 log" for a list of files
type_desc() {
  local n_log=0 n_pcap=0 n_json=0 n_csv=0 f out=""
  for f in "$@"; do
    case "${f,,}" in
      *.log)           n_log=$((n_log + 1)) ;;
      *.pcap|*.pcapng) n_pcap=$((n_pcap + 1)) ;;
      *.json)          n_json=$((n_json + 1)) ;;
      *.csv)           n_csv=$((n_csv + 1)) ;;
    esac
  done
  for p in "$n_log log" "$n_pcap pcap" "$n_json json" "$n_csv csv"; do
    [[ "${p%% *}" == "0" ]] || out+="${out:+, }$p"
  done
  echo "$out"
}

FOUND_DESC="${#SRC_LABELED[@]} labeled"
[[ ${#SRC_LABELED[@]} -eq 0 ]] || FOUND_DESC+=" ($(type_desc "${SRC_LABELED[@]}"))"
FOUND_DESC+=", ${#SRC_UNLABELED[@]} unlabeled"
[[ ${#SRC_UNLABELED[@]} -eq 0 ]] || FOUND_DESC+=" ($(type_desc "${SRC_UNLABELED[@]}"))"
SKIP_DESC=""
[[ $SKIPPED_ALREADY_TRAINED -eq 0 ]] || SKIP_DESC=", skipped $SKIPPED_ALREADY_TRAINED already trained"

[[ $PARTIAL_FILES -eq 0 ]] || later "$PARTIAL_FILES file(s) are only partly labeled — their unlabeled rows count as unlabeled data"
if [[ ${#SRC_UNLABELED[@]} -gt 0 || $PARTIAL_FILES -gt 0 ]]; then
  if [[ -f "$ATTACK_MANIFEST" ]]; then
    later "Unlabeled data will be labeled from data/attack_manifest.csv"
  else
    later "No attack manifest — unlabeled data will be labeled by behaviour rules, or left out when unsure"
  fi
fi
if [[ "$RETRAIN" == true && "$FORCE_RETRAIN" == false ]]; then
  later "--retrain trains only on these new files; earlier training data is not included"
fi
say "Found $TOTAL_SRC new file(s)${WHERE:+ in $WHERE}: $FOUND_DESC$SKIP_DESC"

# ══════════════════════════════════════════════════════════════
#  4. EDA #1 — labeled data · unlabeled data · comparison  (informational)
# ══════════════════════════════════════════════════════════════
EDA1_ARGS=(--output "$EDA_DATA_REPORT")
[[ ${#SRC_LABELED[@]} -eq 0 ]]   || EDA1_ARGS+=(--labeled "${SRC_LABELED[@]}")
[[ ${#SRC_UNLABELED[@]} -eq 0 ]] || EDA1_ARGS+=(--unlabeled "${SRC_UNLABELED[@]}")
[[ -z "$PCAP_LABEL" ]]           || EDA1_ARGS+=(--pcap-label "$PCAP_LABEL")
[[ ! -f "$ATTACK_MANIFEST" ]]    || EDA1_ARGS+=(--manifest "$ATTACK_MANIFEST")

if run python3 -m dns_detect.features.eda_data "${EDA1_ARGS[@]}" && [[ -f "$EDA_DATA_REPORT" ]]; then
  EDA1_SUMMARY=$(python3 - "$EDA_DATA_REPORT" <<'PYEOF' 2>/dev/null || true
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
b = r["labeled"].get("class_balance") or {}
t = r["totals"]
print(t["labeled_rows"], b.get("attack", 0), b.get("benign", 0), t["unlabeled_rows"], len(r["warnings"]))
for w in r["warnings"][:3]:
    print(w)
PYEOF
)
  L_ROWS="?"; L_ATT="?"; L_BEN="?"; U_ROWS="?"; N_WARN="?"
  TOP_WARN=()
  if [[ -n "$EDA1_SUMMARY" ]]; then
    read -r L_ROWS L_ATT L_BEN U_ROWS N_WARN <<< "$(head -n 1 <<< "$EDA1_SUMMARY")" || true
    mapfile -t TOP_WARN < <(tail -n +2 <<< "$EDA1_SUMMARY")
  fi
  for w in "${TOP_WARN[@]+"${TOP_WARN[@]}"}"; do later "$w"; done
  if [[ "$N_WARN" =~ ^[0-9]+$ && $N_WARN -gt 3 ]]; then
    later "… $((N_WARN - 3)) more warning(s) in the report"
  fi
  LAB_PART="labeled $L_ROWS"
  [[ "$L_ROWS" == "0" ]] || LAB_PART+=" ($L_ATT attack / $L_BEN benign)"
  EDA1_HTML="${EDA_DATA_REPORT%.json}.html"
  say "EDA: $LAB_PART, unlabeled $U_ROWS · $N_WARN warning(s) → ${EDA1_HTML#"$PROJECT_ROOT"/}"
else
  later "EDA #1 failed — continuing (see log)"
  say "EDA (labeled · unlabeled) skipped"
fi

# ══════════════════════════════════════════════════════════════
#  5. PRE-PROCESS  (.log → features JSON, .pcap → features JSON, labeled or not)
# ══════════════════════════════════════════════════════════════
PREPROCESSED=0
# Merge inputs: feature files as found, plus "converted.json=original" so every merged row
# can name the log / capture it really came from.
MERGE_INPUTS=("${SRC_JSON[@]+"${SRC_JSON[@]}"}" "${SRC_CSV[@]+"${SRC_CSV[@]}"}")

for log_file in "${SRC_LOG[@]+"${SRC_LOG[@]}"}"; do
  base=$(basename "$log_file" .log)
  out_json="$DATA_DIR/extracted_${base}_$(date +%s).json"
  log "  extract: $log_file → $out_json"
  if run python3 -m dns_detect.features.extractor --input "$log_file" --output "$out_json" \
     && [[ -f "$out_json" ]]; then
    SRC_JSON+=("$out_json")
    MERGE_INPUTS+=("$out_json=$log_file")
    records=$(python3 -c "import json; print(len(json.load(open('$out_json'))))" 2>/dev/null || echo "?")
    # Registers the original log (not the extracted JSON) as trained
    register_trained_file "$log_file" "$records" "log"
    PREPROCESSED=$((PREPROCESSED + 1))
  else
    later "No DNS queries extracted, skipped: $(basename "$log_file") (see log)"
  fi
done

# PCAPs: labeled with --pcap-label, otherwise converted as unlabeled data (labeled in step 8)
if [[ -n "$PCAP_LABEL" ]]; then PCAP_LABEL_ARGS=(--label "$PCAP_LABEL"); else PCAP_LABEL_ARGS=(--unlabeled); fi
for pcap_file in "${SRC_PCAP[@]+"${SRC_PCAP[@]}"}"; do
  base=$(basename "$pcap_file")
  base="${base%.*}"
  out_json="$DATA_DIR/pcap_feat_${base}_$(date +%s).json"
  log "  convert: $pcap_file → $out_json (label=${PCAP_LABEL:-none})"
  if run python3 "$SCRIPT_DIR/make_labeled_features.py" \
       --input "$pcap_file" "${PCAP_LABEL_ARGS[@]}" --output "$out_json" \
     && [[ -f "$out_json" ]]; then
    SRC_JSON+=("$out_json")
    MERGE_INPUTS+=("$out_json=$pcap_file")
    records=$(python3 -c "import json; print(len(json.load(open('$out_json'))))" 2>/dev/null || echo "?")
    register_trained_file "$pcap_file" "$records" "pcap"
    PREPROCESSED=$((PREPROCESSED + 1))
  else
    later "PCAP conversion failed, skipped: $(basename "$pcap_file")"
  fi
done

if [[ $(( ${#SRC_LOG[@]} + ${#SRC_PCAP[@]} )) -eq 0 ]]; then
  say "Pre-process: nothing to convert (JSON/CSV only)"
else
  say "Pre-processed $PREPROCESSED file(s) into features"
fi

# ══════════════════════════════════════════════════════════════
#  6. MERGE ALL SOURCES → one features file
# ══════════════════════════════════════════════════════════════
if [[ ${#SRC_JSON[@]} -eq 0 && ${#SRC_CSV[@]} -eq 0 ]]; then
  fail "No usable feature files after pre-processing. Cannot train."
fi

MERGE_REPORT="$DATA_DIR/merge_report.json"
MERGE_ARGS=(--input "${MERGE_INPUTS[@]}" --output "$MERGED_FEATURES"
            --provenance "$MEM_PROVENANCE" --report "$MERGE_REPORT")
# --eda-only trains nothing, so nothing may be marked as trained
[[ "$EDA_ONLY" == true ]] || MERGE_ARGS+=(--registry "$TRAINED_FILES_REGISTRY")
run_or_fail "Merge failed" python3 -m dns_detect.ingest.merge "${MERGE_ARGS[@]}"
[[ -f "$MERGED_FEATURES" ]] || fail "Merge failed — $MERGED_FEATURES not created"

MERGE_SUMMARY=$(python3 - "$MERGE_REPORT" <<'PYEOF' 2>/dev/null || true
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
d, l = r["duplicates"], r["labels"]
print(r["rows"], len(r["inputs"]), d["distinct_feature_vectors"], f"{d['duplicated_share']:.0%}", l["conflicting_vectors"])
for w in r["warnings"][:3]:
    print(w)
PYEOF
)
RECORD_COUNT="?"; N_INPUTS="?"; N_DISTINCT="?"; DUP_PCT="?"; N_CONFLICTS="?"
MERGE_WARN=()
if [[ -n "$MERGE_SUMMARY" ]]; then
  read -r RECORD_COUNT N_INPUTS N_DISTINCT DUP_PCT N_CONFLICTS <<< "$(head -n 1 <<< "$MERGE_SUMMARY")" || true
  mapfile -t MERGE_WARN < <(tail -n +2 <<< "$MERGE_SUMMARY")
fi
for w in "${MERGE_WARN[@]+"${MERGE_WARN[@]}"}"; do later "$w"; done
say "Merged $RECORD_COUNT records from $N_INPUTS file(s) · $N_DISTINCT distinct feature vectors, $DUP_PCT of rows duplicated · $N_CONFLICTS label conflicts"

# ══════════════════════════════════════════════════════════════
#  7. EDA #2 — merged feature profile  (informational — never stops training)
# ══════════════════════════════════════════════════════════════
if run python3 -m dns_detect.features.eda --input "$MERGED_FEATURES" --output "$EDA_REPORT" \
   && [[ -f "$EDA_REPORT" ]]; then
  EDA_WARN=$(python3 -c "import json; print(len(json.load(open('$EDA_REPORT')).get('warnings', [])))" 2>/dev/null || echo "?")
  say "Feature EDA saved with $EDA_WARN warning(s) → ${EDA_REPORT#"$PROJECT_ROOT"/}"
else
  later "Feature EDA failed — continuing (see log)"
  say "Feature EDA skipped"
fi

if [[ "$EDA_ONLY" == true ]]; then
  flush_notes
  printf "${GREEN}${BOLD}✓ EDA done${NC} (--eda-only) · nothing labeled, trained or marked as trained · read %s, then run again without --eda-only\n" \
    "$(EDA1_HTML="${EDA_DATA_REPORT%.json}.html"; echo "${EDA1_HTML#"$PROJECT_ROOT"/}")"
  log "Stopped after EDA (--eda-only)"
  exit 0
fi

# ══════════════════════════════════════════════════════════════
#  8. LABEL
# ══════════════════════════════════════════════════════════════
# Precedence per row: label already in the file → attack manifest → behaviour rules → left out.
# See src/dns_detect/ingest/labeling.py for the research behind the rules.
LABEL_REPORT="$DATA_DIR/labeling_report.json"
ABSTAINED_ROWS="$DATA_DIR/abstained_rows.json"
ALLOWLIST="$PROJECT_ROOT/config/dns_allowlist.txt"
LABEL_ARGS=(--input "$MERGED_FEATURES" --output "$MERGED_LABELED" --abstained "$ABSTAINED_ROWS" --report "$LABEL_REPORT")
[[ ! -f "$ATTACK_MANIFEST" ]] || LABEL_ARGS+=(--manifest "$ATTACK_MANIFEST")
[[ ! -f "$ALLOWLIST" ]]       || LABEL_ARGS+=(--allowlist "$ALLOWLIST")
run_or_fail "Labeling failed" python3 -m dns_detect.ingest.labeling "${LABEL_ARGS[@]}"
[[ -f "$MERGED_LABELED" ]] || fail "Label generation failed — $MERGED_LABELED not created"

LABEL_SUMMARY=$(python3 - "$LABEL_REPORT" <<'PYEOF' 2>/dev/null || true
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
names = {"provenance": "files", "file": "files", "manifest": "manifest",
         "weak_behavioral": "behaviour", "abstain": "left out"}
agg = {}
for k, v in r["by_label_source"].items():
    agg[names.get(k, k)] = agg.get(names.get(k, k), 0) + v
print(", ".join(f"{k} {v}" for k, v in agg.items()))
for w in r["warnings"][:3]:
    print(w)
PYEOF
)
LABEL_SRC="$(head -n 1 <<< "$LABEL_SUMMARY")"
[[ -n "$LABEL_SRC" ]] || LABEL_SRC="see labeling_report.json"
LABEL_WARN=()
mapfile -t LABEL_WARN < <(tail -n +2 <<< "$LABEL_SUMMARY")
for w in "${LABEL_WARN[@]+"${LABEL_WARN[@]}"}"; do [[ -z "$w" ]] || later "$w"; done

LABEL_STATS=$(python3 -c "
import json
d = json.load(open('$MERGED_LABELED'))
a = sum(1 for r in d if r.get('label', 0) == 1)
b = sum(1 for r in d if r.get('label', 0) == 0)
types = sorted({str(r.get('attack_family', r.get('attack_type', 'unknown'))) for r in d if r.get('label', 0) == 1})
print(a, b, len(d), ','.join(types) or 'none')" 2>/dev/null || echo "? ? ? unknown")
read -r ATTACK_COUNT BENIGN_COUNT TOTAL_COUNT ATTACK_TYPES <<< "$LABEL_STATS"

# Both classes are required — stop BEFORE any model file is overwritten.
if [[ "$ATTACK_COUNT" == "0" || "$BENIGN_COUNT" == "0" ]]; then
  fail "Only one class (attack=$ATTACK_COUNT, benign=$BENIGN_COUNT). Add data for the missing class — existing models were not changed."
fi
say "Labeled $ATTACK_COUNT attack / $BENIGN_COUNT benign · $LABEL_SRC (families: $ATTACK_TYPES)"

# ══════════════════════════════════════════════════════════════
#  9. TRAIN PATH A  (supervised: RF + GBT, Transformer kept as a baseline)
# ══════════════════════════════════════════════════════════════
if [[ "$TRAIN_PATH_A" == true ]]; then
  run_or_fail "Path A training failed" python3 -m dns_detect.models.path_a --train "$MERGED_LABELED"
  for f in "$MEM_RF" "$MEM_TF" "$MEM_SCALER" "$MEM_THRESHOLD"; do
    [[ -f "$f" ]] || fail "Path A did not save $(basename "$f")"
  done
  METRICS="$MODELS_DIR/evaluation_metrics.json"
  say "Path A trained (F1 $(json_num "$METRICS" path_a.f1), PR-AUC $(json_num "$METRICS" path_a.pr_auc))"
else
  say "Path A skipped (existing model kept)"
fi

# ══════════════════════════════════════════════════════════════
#  10. TRAIN PATH B  (unsupervised: Trafficformer on benign windows)
# ══════════════════════════════════════════════════════════════
if [[ "$TRAIN_PATH_B" == true ]]; then
  run_or_fail "Path B training failed" python3 -m dns_detect.models.path_b_train \
    --filename "$MERGED_LABELED" --n_days "$N_DAYS" --save_name "$PATH_B_MODEL" --data_dir "/"
  [[ -f "$MEM_PATH_B" ]] || fail "Path B did not save ${PATH_B_MODEL}.h5"
  say "Path B trained (window $N_DAYS, anomaly threshold $(json_num "$MEM_PATH_B_THRESHOLD" threshold))"
else
  say "Path B skipped (existing model kept)"
fi

# ══════════════════════════════════════════════════════════════
#  SAVE TRAINING METADATA  (read by run_pipeline.sh and the monitor)
# ══════════════════════════════════════════════════════════════
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

run python3 - <<PYEOF || later "Could not save training metadata (see log)"
import json, statistics

meta_path = "$MEM_METADATA"
try:
    with open(meta_path) as f: meta = json.load(f)
except Exception:
    meta = {}
try:
    with open("$MEM_PROVENANCE") as f: prov = json.load(f)
except Exception:
    prov = {}

mode = "force" if "$FORCE_RETRAIN" == "true" else ("smart" if "$RETRAIN" == "true" else "initial")
update = {
    "last_trained":           "$NOW",
    "training_data":          "$MERGED_FEATURES",
    "total_samples":          "$TOTAL_COUNT",
    "attack_samples":         "$ATTACK_COUNT",
    "benign_samples":         "$BENIGN_COUNT",
    "attack_types_seen":      "$ATTACK_TYPES".split(","),
    "label_source":           "$LABEL_SRC",
    "path_b_model_name":      "$PATH_B_MODEL",
    "path_b_window_size":     $N_DAYS,
    "retrain_mode":           mode,
    "new_files_this_run":     $NEW_FILES_FOUND,
    "skipped_files_this_run": $SKIPPED_ALREADY_TRAINED,
    "source_summary": {
        "total_source_files": len(prov.get("source_files", [])),
        "csv_files":          prov.get("source_counts", {}).get("csv_files", 0),
        "json_files":         prov.get("source_counts", {}).get("json_files", 0),
        "pcap_converted":     prov.get("source_counts", {}).get("pcap_converted", 0),
        "log_converted":      prov.get("source_counts", {}).get("log_converted", 0),
    },
    "feature_snapshot": {},
    "model_files": {
        "rf":            "$MEM_RF",
        "transformer":   "$MEM_TF",
        "scaler":        "$MEM_SCALER",
        "threshold":     "$MEM_THRESHOLD",
        "trafficformer": "$MEM_PATH_B",
        "tf_threshold":  "$MEM_PATH_B_THRESHOLD",
        "tf_norm":       "$MEM_PATH_B_NORM",
        "provenance":    "$MEM_PROVENANCE",
    },
}

# Feature snapshot for drift checks (mean/std/min/max of the first 12 numeric fields)
try:
    with open("$MERGED_LABELED") as f: data = json.load(f)
    numeric_keys = [k for k in (data[0].keys() if data else [])
                    if isinstance(data[0].get(k), (int, float)) and k != "label"]
    snap = {}
    for k in numeric_keys[:12]:
        vals = [r[k] for r in data if isinstance(r.get(k), (int, float))]
        if vals:
            snap[k] = {
                "mean":  round(statistics.mean(vals), 4),
                "stdev": round(statistics.stdev(vals) if len(vals) > 1 else 0, 4),
                "min":   round(min(vals), 4),
                "max":   round(max(vals), 4),
            }
    update["feature_snapshot"] = snap
except Exception as e:
    print(f"  [warn] Feature snapshot skipped: {e}")

for path, trained in (("a", "$TRAIN_PATH_A"), ("b", "$TRAIN_PATH_B")):
    if trained == "true":
        update[f"path_{path}_trained"] = "$NOW"
        update[f"path_{path}_prev"]    = meta.get(f"path_{path}_trained", "first time")
    else:
        update[f"path_{path}_trained"] = meta.get(f"path_{path}_trained", "$NOW")

history = meta.get("training_history", [])
history.append({
    "date":          "$NOW",
    "total_samples": "$TOTAL_COUNT",
    "attack_samples": "$ATTACK_COUNT",
    "attack_types":  "$ATTACK_TYPES".split(","),
    "source_files":  len(prov.get("source_files", [])),
    "new_files":     $NEW_FILES_FOUND,
    "skipped_files": $SKIPPED_ALREADY_TRAINED,
    "retrain_mode":  mode,
    "path_a":        "$TRAIN_PATH_A",
    "path_b":        "$TRAIN_PATH_B",
})
update["training_history"] = history[-10:]

meta.update(update)
with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)
print(f"  Metadata -> {meta_path}")
PYEOF
flush_notes

ELAPSED=$(( $(date +%s) - START_TIME ))
printf "${GREEN}${BOLD}✓ Training complete${NC} in %dm %ds · models saved to models/ · next: ./scripts/run_pipeline.sh\n" \
  $((ELAPSED / 60)) $((ELAPSED % 60))
log "Training complete in ${ELAPSED}s"
