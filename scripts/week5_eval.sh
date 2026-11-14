#!/bin/bash
# ============================================================
#  week5_eval.sh — Week 5 evaluation in one command (docs/Week6/next task.md, Tasks 0-3)
#
#  Runs, in order, and writes everything to one log:
#    Task 0  check the Week 5 files exist (runs/, Tu data, training log, v3 row count)
#    Task 1  frozen-test comparison of every run (Path A, Path B, OR rule, fusion)
#    Task 2  false alarms on unseen benign traffic (CIC capture 3) for v3 and v3_iforest
#    Task 3  leave-one-tool-out on v3's training data (the slow part)
#  Then prints a SUMMARY block: paste that block back to fill in the tables.
#
#  Nothing is trained except the leave-one-tool-out Random Forests of Task 3 (one per tool,
#  in memory). Nothing in models/ or in any run folder's model files is changed.
#
#  Usage (from anywhere; run on the machine that has runs/ and the data):
#    ./scripts/week5_eval.sh                 # Tasks 0-3
#    ./scripts/week5_eval.sh --skip-lofo     # Tasks 0-2 only (minutes)
#    ./scripts/week5_eval.sh --redo-lofo     # recompute Task 3 even if runs/v3/cv_lofo.json exists
# ============================================================

set -uo pipefail   # no -e: one failed check must not hide the others

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT" || exit 1
export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export TF_CPP_MIN_LOG_LEVEL=2
export PYTHONIOENCODING=utf-8
export PYTHONUNBUFFERED=1   # print progress as it happens, even through the pipes below
unset DNS_DETECT_MODELS_DIR

SKIP_LOFO=false
REDO_LOFO=false
for a in "$@"; do
  case "$a" in
    --skip-lofo) SKIP_LOFO=true ;;
    --redo-lofo) REDO_LOFO=true ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $a (see --help)" >&2; exit 1 ;;
  esac
done

mkdir -p logs
STAMP=$(date +%Y%m%d_%H%M%S)
LOG="logs/week5_eval_${STAMP}.log"
SUMMARY="logs/week5_eval_${STAMP}_summary.txt"
V3_LOG="logs/training_20261107_220017.log"
CIC="data/external/cic/cic_benign_test.json"
CIC_CSV="cic_benign_test_model_results.csv"   # path_a --infer overwrites this committed file

exec > >(tee -a "$LOG") 2>&1
echo "week5_eval.sh · $(date) · log: $LOG"
: > "$SUMMARY"
sum() { echo "$*" >> "$SUMMARY"; }
hdr() { echo; echo "════════ $* ════════  ($(date +%H:%M:%S))"; }

# ── Task 0 ───────────────────────────────────────────────────
hdr "Task 0: Week 5 files"
sum "== Task 0: files =="
for p in runs/baseline runs/v_dnsshell runs/v_det runs/v3 runs/v3_iforest \
         runs/v3/evaluation_metrics.json runs/v3/split_manifest.json runs/v3/merged_labeled.json \
         "$V3_LOG" "$CIC"; do
  if [[ -e "$p" ]]; then state=ok; else state=MISSING; fi
  printf "  %-8s %s\n" "$state" "$p"
  sum "$(printf "%-8s %s" "$state" "$p")"
done
TU_N=$(ls data/external/tu2023/*.json 2>/dev/null | wc -l)
echo "  tu2023 json files: $TU_N"; sum "tu2023 json files: $TU_N"

if [[ -f runs/v3/merged_labeled.json ]]; then
  N=$(python3 -c "import json; print(len(json.load(open('runs/v3/merged_labeled.json'))))" 2>/dev/null || echo "?")
  echo "  runs/v3/merged_labeled.json rows: $N (expected 218334)"
  sum "v3 merged_labeled rows: $N (expected 218334)"
fi
if [[ -f "$V3_LOG" ]]; then
  echo "  v3 training log:"
  grep -E '^\[(8|9|10|11|12)/12\]|Training complete|Autoencoder:|Isolation Forest:|fusion weights' "$V3_LOG" \
    | sed 's/^/    /' | tee -a "$SUMMARY"
fi

# ── Task 1 ───────────────────────────────────────────────────
hdr "Task 1: frozen test set, every run"
sum ""; sum "== Task 1: frozen test set =="
python3 - runs/baseline runs/v_* runs/v3 runs/v3_iforest <<'EOF' | tee -a "$SUMMARY"
import json, os, sys
runs = [r for r in dict.fromkeys(sys.argv[1:]) if os.path.isfile(f"{r}/evaluation_metrics.json")]
f = lambda v: "-" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v))
print(f"{'run':14} {'PathB':13} {'A recall':>8} {'A FA':>5} {'A PR-AUC':>8} {'B recall':>8} {'B fpr':>7} "
      f"{'OR FA':>6} {'fus recall':>10} {'fus FA':>6}")
for r in runs:
    m = json.load(open(f"{r}/evaluation_metrics.json"))
    b = m.get("path_b") or {}
    t = (m.get("fusion") or {}).get("test") or {}
    pa, lr, orr = t.get("path_a") or {}, t.get("learned_lr") or {}, t.get("or_rule") or {}
    a = m.get("path_a") or {}
    print(f"{os.path.basename(r):14} {b.get('model_type', 'trafficformer'):13} {f(pa.get('recall')):>8} "
          f"{f(pa.get('false_alarms')):>5} {f(a.get('pr_auc')):>8} {f(b.get('recall')):>8} {f(b.get('fpr')):>7} "
          f"{f(orr.get('false_alarms')):>6} {f(lr.get('recall')):>10} {f(lr.get('false_alarms')):>6}")
if not runs:
    print("no run folder has evaluation_metrics.json")
EOF

# ── Task 2 ───────────────────────────────────────────────────
hdr "Task 2: CIC capture 3 (unseen benign, budget 25 of 25,222)"
sum ""; sum "== Task 2: CIC capture 3 (Path A, budget 25) =="
if [[ ! -f "$CIC" ]]; then
  echo "  MISSING $CIC — skipped"; sum "skipped: $CIC missing"
else
  for run in v3 v3_iforest; do
    if [[ ! -f "runs/$run/dns_tunnel_rf.pkl" ]]; then
      echo "  $run: no Path A model — skipped"; sum "$run: skipped (no runs/$run/dns_tunnel_rf.pkl)"; continue
    fi
    OUT=$(DNS_DETECT_MODELS_DIR="runs/$run" python3 -m dns_detect.models.path_a --infer "$CIC" 2>/dev/null)
    TOTAL=$(sed -n 's/.*Total analyzed : *\([0-9]*\).*/\1/p' <<< "$OUT")
    FLAG=$(sed -n 's/.*Attack detected: *\([0-9]*\).*/\1/p' <<< "$OUT")
    if [[ -f "$CIC_CSV" ]]; then
      cp "$CIC_CSV" "runs/$run/cic_test_results.csv"   # keep the scores; flagged domains are in here
      git checkout -- "$CIC_CSV" 2>/dev/null           # restore the committed file
    fi
    if [[ -n "$FLAG" && -n "$TOTAL" ]]; then
      RATE=$(python3 -c "print(f'{$FLAG/$TOTAL:.3%}')")
      OKB=$([[ "$FLAG" -le 25 ]] && echo "within budget" || echo "OVER budget")
      LINE="$run: $FLAG / $TOTAL flagged = $RATE  ($OKB)"
    else
      LINE="$run: could not read the result (see the log)"
      echo "$OUT" | tail -5
    fi
    echo "  $LINE"; sum "$LINE"
  done
  sum "reference: baseline 1, v_dnsshell 0, v_det 1"
fi

# ── Task 3 ───────────────────────────────────────────────────
hdr "Task 3: leave-one-tool-out on v3's training data"
sum ""; sum "== Task 3: leave-one-tool-out (feature set step3, threshold at 0.1% benign FPR) =="
LOFO_OUT="runs/v3/cv_lofo.json"
if [[ "$SKIP_LOFO" == true ]]; then
  echo "  skipped (--skip-lofo)"; sum "skipped (--skip-lofo)"
elif [[ ! -f runs/v3/merged_labeled.json ]]; then
  echo "  runs/v3/merged_labeled.json missing — skipped"; sum "skipped: runs/v3/merged_labeled.json missing"
else
  if [[ -f "$LOFO_OUT" && "$REDO_LOFO" == false ]]; then
    echo "  reusing existing $LOFO_OUT (use --redo-lofo to recompute)"
  else
    echo "  running (one Random Forest per tool; this is the slow part)..."
    python3 scripts/run_cv.py --labeled runs/v3/merged_labeled.json --strategies lofo \
        --lofo-feature-sets step3 --splits-dir runs/v3/cv_splits --out "$LOFO_OUT" 2>&1 \
      | grep --line-buffered -vE 'Invalid DH parameters|^I0000|oneDNN' || true
  fi
  if [[ -f "$LOFO_OUT" ]]; then
    python3 - "$LOFO_OUT" <<'EOF' | tee -a "$SUMMARY"
import json, sys
lofo = json.load(open(sys.argv[1]))["by_strategy"]["lofo"]["step3"]
for fam, b in sorted(lofo["per_family"].items()):
    if "error" in b:
        print(f"{fam:16} ERROR {b['error']}")
    else:
        print(f"{fam:16} recall={b['recall']:.4f}  fpr={b['fpr']:.4%}")
h = lofo["headline"]
print(f"headline: recall mean={h.get('unseen_tool_recall_mean')}  min={h.get('unseen_tool_recall_min')}  "
      f"benign fpr mean={h.get('benign_fpr_mean')}  tools={h.get('families')}")
EOF
  else
    echo "  no $LOFO_OUT produced — see the log"; sum "failed: no $LOFO_OUT (see $LOG)"
  fi
fi

# ── Summary ──────────────────────────────────────────────────
echo
echo "════════════════ SUMMARY — paste everything from here down ════════════════"
cat "$SUMMARY"
echo "════════════════ end of summary · full log: $LOG ════════════════"
