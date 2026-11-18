#!/bin/bash
# ============================================================
#  DNS Traffic Anomaly Detection — ONE-COMMAND RUNNER
#  Runs the whole 17-step flow end to end:
#    TRAIN (steps 1–11)  → train_models.sh   (auto-skips if models exist)
#    DETECT (steps 12–16)→ run_pipeline.sh   (extract → ML → rules → monitor)
#    RETRAIN TRIGGER (17)→ reads monitoring verdict (manual by default)
#
#  This is a thin wrapper — it does NOT reimplement any pipeline logic.
#
#  Usage:
#    ./scripts/run_all.sh                       # train-if-needed → detect → monitor
#    ./scripts/run_all.sh --retrain             # smart retrain on new data, then detect
#    ./scripts/run_all.sh --force-retrain       # full retrain, then detect
#    ./scripts/run_all.sh --skip-train          # detect only (models must already exist)
#    ./scripts/run_all.sh --zscore 2.5          # custom Z-score threshold for detection
#    ./scripts/run_all.sh --force-retrain --path-b-model iforest \
#        --files data/processed/labeled_tunnels.json data/processed/labeled_benign.json
#                                               # choose Path B + training data (passed to train_models.sh)
#    ./scripts/run_all.sh --auto-retrain        # if monitoring says so, retrain + re-detect once
#    ./scripts/run_all.sh --with-infra          # docker compose up Technitium+ELK first
#    ./scripts/run_all.sh --with-attack "127.0.0.1 lab.local --all-attacks -t 8 -r 5000 -d 60 -w subs.txt -W nx.txt"
#    ./scripts/run_all.sh --help
# ============================================================

set -euo pipefail

# ── COLOURS ────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     NC='\033[0m'

ok()   { echo -e "${GREEN}  ✅ $*${NC}"; }
info() { echo -e "${CYAN}  ℹ  $*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠  $*${NC}"; }
fail() { echo -e "${RED}  ❌ $*${NC}"; exit 1; }
stage(){ echo -e "\n${BOLD}${CYAN}━━ $* ${NC}"; }

banner() {
  printf "\n${BOLD}${CYAN}"
  printf "  ╔══════════════════════════════════════════════════════╗\n"
  printf "  ║   DNS Anomaly Detection — Full Flow (one command)    ║\n"
  printf "  ║   train → detect → monitor                           ║\n"
  printf "  ╚══════════════════════════════════════════════════════╝\n"
  printf "${NC}"
}

# ── PATHS (resolved from project root) ─────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_ROOT/data/processed"
LOG_DIR="$PROJECT_ROOT/logs"
MODELS_DIR="$PROJECT_ROOT/models"
DNS_LOG_DIR="$PROJECT_ROOT/data/raw"
INFRA_DIR="$PROJECT_ROOT/infra/technitium-elk"
INFRA_LOGS="$INFRA_DIR/data/dns_logs"
ATTACK_DIR="$PROJECT_ROOT/attacks"
export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

MONITOR_REPORT="$DATA_DIR/monitoring_report.json"
WEEK4_ALERTS="$DATA_DIR/week4_unified_alerts.json"

# ── DEFAULTS ───────────────────────────────────────────────
WITH_INFRA=false
WITH_ATTACK=false
ATTACK_ARGS=""
SKIP_TRAIN=false
AUTO_RETRAIN=false
ZSCORE_THRESHOLD=2.0
declare -a TRAIN_ARGS=()   # retrain flags passed through to train_models.sh
declare -a MODEL_ARGS=()   # model/label options passed through to train_models.sh (also on --auto-retrain)
declare -a DATA_ARGS=()    # --data-dir / --files passed through to train_models.sh (--files goes last)
RETRAIN_GIVEN=false

# ── ARG PARSING ────────────────────────────────────────────
show_help() {
  echo ""
  echo -e "${BOLD}Usage:${NC}  ./scripts/run_all.sh [options]"
  echo ""
  echo "Runs the whole flow in one command: train (if needed) → detect → monitor."
  echo ""
  echo "Options:"
  echo "  --with-infra           Bring up Technitium+ELK via docker compose first"
  echo "  --with-attack \"ARGS\"   Build + run attacks/attack with ARGS, then feed its logs"
  echo "                         (Kali/root — raw sockets). Copies new logs into data/raw/"
  echo "  --retrain              Smart retrain on NEW data only, then detect"
  echo "  --force-retrain        Full retrain on ALL data, then detect"
  echo "  --skip-train           Detect only (models must already exist in models/)"
  echo "  --zscore N             Z-score threshold for detection (default: 2.0)"
  echo "  --auto-retrain         If monitoring recommends it, retrain + re-detect once"
  echo "  --help                 Show this help"
  echo ""
  echo -e "${BOLD}Training options${NC} (passed to train_models.sh; see ./scripts/train_models.sh --help):"
  echo "  --path-b-model T       Path B algorithm: trafficformer (default, slow) or iforest (minutes)"
  echo "  --files F1 F2 ...      Train on these files (.json/.csv/.pcap/.log) instead of scanning data/raw/"
  echo "  --data-dir PATH        Train on every data file in this folder"
  echo "  --path-a-only          Train only Path A (RF + GBT)"
  echo "  --path-b-only          Train only Path B"
  echo "  --n-days N             Path B window size in queries (default: 20)"
  echo "  --seed N               Seed for both paths and a fresh split (default: 42)"
  echo "  --new-split            Make a fresh time-ordered split (results not comparable with older runs)"
  echo "  --split-manifest F     Reuse this base split"
  echo "  --pcap-label 0|1       Label every query in .pcap files (0 = benign, 1 = attack)"
  echo "  --allow-heuristic-labels  EXPERIMENTAL: train even with heuristic labels"
  echo "  --verbose              Stream the full training output"
  echo "  Detection (step B) always scores the logs in data/raw/, whatever data trained the models."
  echo "  Models that exist are kept unless you add --retrain or --force-retrain."
  echo ""
  echo -e "${BOLD}Examples:${NC}"
  echo "  ./scripts/run_all.sh"
  echo "  ./scripts/run_all.sh --force-retrain --zscore 2.5"
  echo "  ./scripts/run_all.sh --with-infra --with-attack \"127.0.0.1 lab.local --all-attacks -t 8 -r 5000 -d 60 -w subs.txt -W nx.txt\""
  echo ""
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-infra)    WITH_INFRA=true;                 shift ;;
    --with-attack)   WITH_ATTACK=true; ATTACK_ARGS="${2:-}"; shift 2 ;;
    --retrain)       TRAIN_ARGS+=(--retrain);  RETRAIN_GIVEN=true; shift ;;
    --force-retrain) TRAIN_ARGS+=(--force-retrain); RETRAIN_GIVEN=true; shift ;;
    --path-b-model)
      case "${2:-}" in trafficformer|iforest) ;; *) fail "--path-b-model needs trafficformer or iforest (got: ${2:-nothing})" ;; esac
      MODEL_ARGS+=(--path-b-model "$2"); shift 2 ;;
    --n-days|--seed|--split-manifest|--pcap-label)
      [[ -n "${2:-}" && "${2:-}" != --* ]] || fail "$1 needs a value"
      MODEL_ARGS+=("$1" "$2"); shift 2 ;;
    --path-a-only|--path-b-only|--new-split|--allow-heuristic-labels|--verbose|-v)
      MODEL_ARGS+=("$1"); shift ;;
    --data-dir)
      [[ -n "${2:-}" && "${2:-}" != --* ]] || fail "--data-dir needs a folder"
      DATA_ARGS=(--data-dir "$2" "${DATA_ARGS[@]+"${DATA_ARGS[@]}"}"); shift 2 ;;
    --files)
      shift; FILE_LIST=()
      while [[ $# -gt 0 && "$1" != --* ]]; do FILE_LIST+=("$1"); shift; done
      [[ ${#FILE_LIST[@]} -gt 0 ]] || fail "--files needs at least one file"
      DATA_ARGS+=(--files "${FILE_LIST[@]}") ;;
    --skip-train)    SKIP_TRAIN=true;                 shift ;;
    --auto-retrain)  AUTO_RETRAIN=true;               shift ;;
    --zscore)        ZSCORE_THRESHOLD="${2:-2.0}";    shift 2 ;;
    --help|-h)       show_help ;;
    *) warn "Unknown option: $1 (ignored)"; shift ;;
  esac
done

banner
START_TIME=$(date +%s)
cd "$PROJECT_ROOT"
mkdir -p "$DATA_DIR" "$LOG_DIR" "$MODELS_DIR" "$DNS_LOG_DIR"

# ── PREFLIGHT ──────────────────────────────────────────────
stage "Preflight"
info "Project root : $PROJECT_ROOT"
python3 --version &>/dev/null || fail "python3 not found"
ok "python3: $(python3 --version)"
python3 -c "from dns_detect.config import settings" 2>/dev/null || \
  fail "dns_detect package not importable (check PYTHONPATH and src/dns_detect/)"
ok "dns_detect package ready"

# ── OPTIONAL: BRING UP DOCKER INFRA ────────────────────────
if [[ "$WITH_INFRA" == true ]]; then
  stage "Infra — Technitium + ELK (docker compose)"
  command -v docker &>/dev/null || fail "docker not found (needed for --with-infra)"
  [[ -f "$INFRA_DIR/docker-compose.yml" ]] || fail "compose file not found: $INFRA_DIR/docker-compose.yml"
  ( cd "$INFRA_DIR" && docker compose up -d ) || fail "docker compose up failed"
  info "Waiting for Technitium DNS on :53 ..."
  dns_up=false
  for _ in $(seq 1 30); do
    if command -v dig &>/dev/null; then
      if dig +time=1 +tries=1 @127.0.0.1 lab.local &>/dev/null; then dns_up=true; break; fi
    else
      # Fallback: TCP check on the admin port 5380
      if (exec 3<>/dev/tcp/127.0.0.1/5380) 2>/dev/null; then dns_up=true; exec 3>&- 3<&-; break; fi
    fi
    sleep 2
  done
  if [[ "$dns_up" == true ]]; then ok "Technitium is answering"; else
    warn "Technitium not confirmed after wait — continuing anyway"
  fi
fi

# ── GROUND TRUTH: record each attack run in the attack manifest ──
# Training (Step 8) labels queries inside this window under the target domain as attack.
# source_ip is left empty: behind Docker, Technitium may see the bridge gateway, not this host.
# The window uses the clock the Technitium log uses (its "Local" is UTC unless the container sets TZ).
ATTACK_MANIFEST="$PROJECT_ROOT/data/attack_manifest.csv"
record_attack_in_manifest() {
  local target_domain family="" start="$ATTACK_START_UTC" end="$ATTACK_END_UTC" clock="UTC"
  target_domain=$(awk '{print $2}' <<< "$ATTACK_ARGS")
  for flag in $ATTACK_ARGS; do
    case "$flag" in
      --all-attacks)       family+="${family:++}all_attacks" ;;
      --nxdomain-flood)    family+="${family:++}nxdomain_flood" ;;
      --random-subdomains) family+="${family:++}random_subdomains" ;;
      --amplification)     family+="${family:++}amplification" ;;
      --cache-poison)      family+="${family:++}cache_poisoning" ;;
    esac
  done
  [[ -n "$family" ]] || family="attack_tool"
  # Which clock does the newest Technitium log use? Compare its last timestamp with now.
  local newest last_ts
  newest=$(ls -t "$INFRA_LOGS"/*.log 2>/dev/null | head -n 1 || true)
  if [[ -n "$newest" ]]; then
    last_ts=$(grep -o '^\[[0-9-]* [0-9:]* Local\]' "$newest" | tail -n 1 | tr -d '[]' | sed 's/ Local//')
    if [[ -n "$last_ts" ]]; then
      local now diff_local diff_utc
      now=$(date +%s)
      diff_local=$(( now - $(date -d "$last_ts" +%s 2>/dev/null || echo 0) ))
      diff_utc=$(( now - $(date -u -d "$last_ts" +%s 2>/dev/null || echo 0) ))
      if (( ${diff_local#-} < ${diff_utc#-} )); then start="$ATTACK_START_LOCAL"; end="$ATTACK_END_LOCAL"; clock="host local time"; fi
    fi
  fi
  [[ -f "$ATTACK_MANIFEST" ]] || echo "campaign_id,family,source_ip,start,end,target_domain" > "$ATTACK_MANIFEST"
  echo "C-$(date +%Y%m%d-%H%M%S),$family,,$start,$end,$target_domain" >> "$ATTACK_MANIFEST"
  ok "Recorded attack window in data/attack_manifest.csv ($family, $start → $end, $clock, domain $target_domain)"
}

# ── OPTIONAL: GENERATE ATTACK TRAFFIC ──────────────────────
if [[ "$WITH_ATTACK" == true ]]; then
  stage "Attack — generate labeled traffic (Kali/root, raw sockets)"
  [[ -n "$ATTACK_ARGS" ]] || fail "--with-attack needs arguments, e.g. --with-attack \"127.0.0.1 lab.local --all-attacks -t 8 -r 5000 -d 60 -w subs.txt -W nx.txt\""
  command -v gcc &>/dev/null || fail "gcc not found (needed to build attacks/attack)"
  info "Building attack tool ..."
  make -C "$ATTACK_DIR" || fail "attack build failed"
  info "Running: sudo ./attack $ATTACK_ARGS"
  ATTACK_START_LOCAL=$(date +%Y-%m-%dT%H:%M:%S); ATTACK_START_UTC=$(date -u +%Y-%m-%dT%H:%M:%S)
  # shellcheck disable=SC2086
  sudo "$ATTACK_DIR/attack" $ATTACK_ARGS || warn "attack exited non-zero (continuing)"
  ATTACK_END_LOCAL=$(date +%Y-%m-%dT%H:%M:%S); ATTACK_END_UTC=$(date -u +%Y-%m-%dT%H:%M:%S)
  record_attack_in_manifest
  # Feed the fresh Technitium logs into the pipeline input
  if compgen -G "$INFRA_LOGS/*.log" >/dev/null; then
    cp -f "$INFRA_LOGS"/*.log "$DNS_LOG_DIR"/ && ok "Copied new DNS logs → $DNS_LOG_DIR"
  else
    warn "No logs found in $INFRA_LOGS — is Technitium logging to file? (--with-infra / Log All Queries)"
  fi
fi

# ── CHECK INPUT LOGS EXIST ─────────────────────────────────
LOG_COUNT=$(find "$DNS_LOG_DIR" -name "*.log" 2>/dev/null | wc -l)
if [[ "$LOG_COUNT" -eq 0 && ! -f "$DATA_DIR/week3_features_all.json" ]]; then
  fail "No .log files in $DNS_LOG_DIR and no cached features. Add logs (or use --with-attack)."
fi
[[ "$LOG_COUNT" -gt 0 ]] && ok "Found $LOG_COUNT DNS log file(s) in data/raw/"

# ── STEP A: TRAIN (steps 1–11) ─────────────────────────────
if [[ "$SKIP_TRAIN" == true ]]; then
  stage "TRAIN — skipped (--skip-train)"
  [[ -f "$MODELS_DIR/dns_tunnel_rf.pkl" ]] || \
    fail "No trained models in models/ — cannot --skip-train. Run without it first."
  ok "Using existing models in models/"
else
  stage "TRAIN (steps 1–11) — train_models.sh"
  # --files must stay last: train_models.sh reads every following word as a file
  TRAIN_ARGS+=("${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"}" "${DATA_ARGS[@]+"${DATA_ARGS[@]}"}")
  if [[ ${#TRAIN_ARGS[@]} -gt 0 ]]; then
    info "train_models.sh ${TRAIN_ARGS[*]}"
  fi
  if [[ "$RETRAIN_GIVEN" == false && ( ${#MODEL_ARGS[@]} -gt 0 || ${#DATA_ARGS[@]} -gt 0 ) ]]; then
    warn "Training options given without --retrain/--force-retrain: existing models are kept; only missing ones are trained."
  else
    info "First run trains; if models already exist this auto-skips."
  fi
  "$SCRIPT_DIR/train_models.sh" "${TRAIN_ARGS[@]+"${TRAIN_ARGS[@]}"}" \
    || fail "Training stage failed"
  ok "Training stage complete"
fi

# ── STEP B: DETECT + MONITOR (steps 12–16) ─────────────────
stage "DETECT + MONITOR (steps 12–16) — run_pipeline.sh"
"$SCRIPT_DIR/run_pipeline.sh" --zscore "$ZSCORE_THRESHOLD" \
  || fail "Detection stage failed"
ok "Detection + monitoring complete"

# ── STEP C: RETRAIN TRIGGER (step 17) ──────────────────────
stage "RETRAIN TRIGGER (step 17)"
RETRAIN_FLAG=$(python3 -c "
import json
try:
    d = json.load(open('$MONITOR_REPORT'))
    print('yes' if d.get('retrain_recommended') else 'no')
except Exception:
    print('unknown')
" 2>/dev/null || echo "unknown")

if [[ "$RETRAIN_FLAG" == "yes" ]]; then
  if [[ "$AUTO_RETRAIN" == true ]]; then
    warn "Monitoring recommends retrain — auto-retraining (--auto-retrain)"
    "$SCRIPT_DIR/train_models.sh" --retrain "${MODEL_ARGS[@]+"${MODEL_ARGS[@]}"}" || fail "Auto-retrain failed"
    info "Re-running detection on freshly retrained models ..."
    "$SCRIPT_DIR/run_pipeline.sh" --zscore "$ZSCORE_THRESHOLD" || fail "Post-retrain detection failed"
    ok "Auto-retrain + re-detect complete"
  else
    warn "Monitoring RECOMMENDS RETRAIN."
    echo -e "    Run: ${BOLD}./scripts/run_all.sh --retrain${NC}   (or add --auto-retrain)"
  fi
elif [[ "$RETRAIN_FLAG" == "no" ]]; then
  ok "Models healthy — no retrain needed"
else
  info "Retrain status unknown (no monitoring report parsed)"
fi

# ── FINAL SUMMARY ──────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME)); MINS=$((ELAPSED / 60)); SECS=$((ELAPSED % 60))

echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  ✅  FULL FLOW COMPLETE  (${MINS}m ${SECS}s)${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BOLD}Final outputs:${NC}"
[[ -f "$WEEK4_ALERTS" ]]            && echo "  🚨 Alerts (JSON)    : $WEEK4_ALERTS"
CSV_PATH="${WEEK4_ALERTS%.json}.csv"
[[ -f "$CSV_PATH" ]]               && echo "  📊 Alerts (CSV)     : $CSV_PATH"
[[ -f "$MONITOR_REPORT" ]]         && echo "  📈 Monitoring       : $MONITOR_REPORT"
[[ -f "$MODELS_DIR/evaluation_metrics.json" ]] && \
  echo "  📐 Test metrics     : $MODELS_DIR/evaluation_metrics.json"
if grep -Eq '"model_type"[[:space:]]*:[[:space:]]*"iforest"' "$MODELS_DIR/dns_trafficformer_threshold.json" 2>/dev/null; then
  echo "  🌲 Path B in use    : Isolation Forest"
elif [[ -f "$MODELS_DIR/dns_trafficformer_threshold.json" ]]; then
  echo "  🧠 Path B in use    : Trafficformer"
fi
NEWEST_LOG=$(ls -t "$LOG_DIR"/pipeline_*.log 2>/dev/null | head -1 || true)
[[ -n "${NEWEST_LOG:-}" ]]         && echo "  📋 Pipeline log     : $NEWEST_LOG"
echo ""
