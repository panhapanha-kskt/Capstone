#!/bin/bash
# ============================================================
#  save_evidence.sh — Task 7 of docs/Week6/next task.md: save the small result files in git
#
#  Every Week 5/6 result lives only in runs/ and logs/ on this machine, and neither is in git.
#  This copies the result files that back the numbers in the reports into docs/Week5/evidence/,
#  checks them, and writes an index (docs/Week5/evidence/README.md). Once committed, all of it
#  is visible on GitHub. Model binaries and the large merged_labeled.json training copies are
#  not copied: they are not results, and they can exceed GitHub's 100 MB file limit.
#
#  Usage (run where runs/ and logs/ exist, i.e. on Kali):
#    bash scripts/save_evidence.sh
#  Then commit docs/Week5/evidence/ (the script prints the commands).
# ============================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(dirname "$SCRIPT_DIR")" || exit 1

EV=docs/Week5/evidence
MAX_KB=51200         # 50 MB: GitHub warns above 50 MB and rejects files above 100 MB
mkdir -p "$EV"
COPIED=(); SKIPPED=(); MISSING=()

copy() {   # copy <source> <dest-dir> [dest-name]
  local src=$1 dir=$2 name=${3:-$(basename "$1")}
  if [[ ! -f "$src" ]]; then MISSING+=("$src"); return; fi
  local kb=$(( $(stat -c %s "$src") / 1024 ))
  if (( kb > MAX_KB )); then SKIPPED+=("$src (${kb} KB, over ${MAX_KB} KB)"); return; fi
  mkdir -p "$EV/$dir"
  cp "$src" "$EV/$dir/$name" && COPIED+=("$dir/$name (${kb} KB)")
}
loglines() {   # loglines <log> <dest-dir> <dest-name> <grep pattern>
  local log=$1 dir=$2 name=$3 pat=$4
  if [[ ! -f "$log" ]]; then MISSING+=("$log"); return; fi
  mkdir -p "$EV/$dir"
  grep -aE "$pat" "$log" > "$EV/$dir/$name" && COPIED+=("$dir/$name (key lines of $(basename "$log"))")
}

echo "Saving evidence into $EV ..."

# ── Training runs: metrics, fusion weights, split, Path B threshold file ──
for run in baseline v_dnsshell v_det v3 v3_iforest; do
  for f in evaluation_metrics.json fusion_lr.json fusion_lr_tiers.json split_manifest.json \
           dns_trafficformer_threshold.json training_metadata.json; do
    copy "runs/$run/$f" "$run"
  done
done

# ── Multi-seed summaries (Task 5) ──
for run in baseline v_dnsshell v_det v3; do
  copy "runs/multiseed_$run/summary.json" "$run" multiseed_summary.json
done

# ── Leave-one-tool-out (Task 3) and CIC capture 3 scores (Task 2) ──
copy runs/v3/cv_lofo.json v3
for run in v3 v3_iforest; do copy "runs/$run/cic_test_results.csv" "$run"; done

# ── Path B-only Isolation Forest test (Task 10.2) ──
copy runs/v3_pathb_iforest/evaluation_metrics.json v3_pathb_iforest
copy runs/v3_pathb_iforest/dns_trafficformer_threshold.json v3_pathb_iforest

# ── Key lines of the training logs ──
loglines logs/training_20261107_220017.log v3 training_log_summary.txt \
  '^\[[0-9]+/12\]|Training complete|Autoencoder:|Isolation Forest:|fusion weights'
loglines logs/train_v3_iforest.log v3_iforest training_log_summary.txt \
  '^\[[0-9]+/12\]|Training complete'
LATEST_EVAL=$(ls -t logs/week5_eval_*_summary.txt 2>/dev/null | head -1)
[[ -n "$LATEST_EVAL" ]] && copy "$LATEST_EVAL" eval week5_eval_summary.txt
copy logs/multiseed_all.log eval multiseed_all.txt   # .txt: .gitignore ignores every *.log

# ── Week 4 unseen-tool results that survived (the only saved evidence for them) ──
CSV_NOTE=""
for f in tunnels_det_model_results.csv tunnels_dns_shell_model_results.csv; do
  if [[ -f "$f" ]]; then
    check=$(python3 -c "
import csv
rows = list(csv.DictReader(open('$f', encoding='utf-8')))
print(len(rows), sum(r.get('ml_label_A') == '1' for r in rows))" 2>/dev/null || echo "? ?")
    read -r n flagged <<< "$check"
    CSV_NOTE+="- \`$f\`: $n rows, $flagged flagged as attack"
    if [[ "$n" == "5000" && "$flagged" == "5000" ]]; then CSV_NOTE+=" (matches the Week 4 unseen-tool result 5,000 / 5,000)"$'\n'
    else CSV_NOTE+=" (does NOT match 5,000 / 5,000: from a different run; do not cite as the Week 4 result)"$'\n'; fi
    copy "$f" unseen_tool
  else
    MISSING+=("$f")
  fi
done

# ── Index ──
{
  echo "# Evidence for the Week 5 and Week 6 results"
  echo
  echo "Saved $(date '+%Y-%m-%d %H:%M') by \`scripts/save_evidence.sh\` from \`runs/\` and \`logs/\` on the training machine."
  echo "These are the small files behind the numbers in [V3_BALANCED_TRAINING.md](../V3_BALANCED_TRAINING.md),"
  echo "[V3_EVALUATION_RESULTS.md](../../Week6/V3_EVALUATION_RESULTS.md) and"
  echo "[PATH_B_ISOLATION_FOREST.md](../../Week6/PATH_B_ISOLATION_FOREST.md). Model files are not included."
  echo
  echo "| Folder | Contents |"
  echo "|---|---|"
  echo "| \`baseline\`, \`v_dnsshell\`, \`v_det\`, \`v3\`, \`v3_iforest\` | each run's \`evaluation_metrics.json\` (frozen-test results), fusion weights, split, Path B threshold, training metadata; \`multiseed_summary.json\` (5 seeds) |"
  echo "| \`v3\` | also \`cv_lofo.json\` (leave-one-tool-out), \`cic_test_results.csv\` (CIC capture 3 scores), key lines of the training log |"
  echo "| \`v3_iforest\` | also CIC capture 3 scores and key lines of its training log |"
  echo "| \`v3_pathb_iforest\` | the Path B-only Isolation Forest test (65.8 s run) |"
  echo "| \`eval\` | the latest \`week5_eval.sh\` summary and the multi-seed log |"
  echo "| \`unseen_tool\` | Week 4 unseen-tool results that survived (det, dns_shell) |"
  echo
  if [[ -n "$CSV_NOTE" ]]; then echo "## Unseen-tool CSV check"; echo; printf '%s' "$CSV_NOTE"; echo; fi
  echo "## Files"
  echo
  for c in "${COPIED[@]}"; do echo "- $c"; done
  if (( ${#SKIPPED[@]} )); then echo; echo "## Skipped (over 50 MB, too large for GitHub)"; echo; for s in "${SKIPPED[@]}"; do echo "- $s"; done; fi
  if (( ${#MISSING[@]} )); then echo; echo "## Not found when saved"; echo; for m in "${MISSING[@]}"; do echo "- $m"; done; fi
} > "$EV/README.md"

# ── Report ──
echo
echo "Copied ${#COPIED[@]} file(s)."
if [[ -n "$CSV_NOTE" ]]; then echo; echo "Unseen-tool CSV check:"; printf '%s' "$CSV_NOTE"; fi
if (( ${#SKIPPED[@]} )); then echo; echo "Skipped (over $((MAX_KB / 1024)) MB):"; printf '  %s\n' "${SKIPPED[@]}"; fi
if (( ${#MISSING[@]} )); then echo; echo "Not found (fine if that run or file never existed):"; printf '  %s\n' "${MISSING[@]}"; fi
echo
echo "Total size: $(du -sh "$EV" | cut -f1)   ·   index: $EV/README.md"
echo
echo "Next, commit it so it shows on GitHub:"
echo "  git add $EV"
echo "  git commit -m \"Task 7: save Week 5/6 evidence files\""
echo "  git push origin main"
REMOTE=$(git remote get-url origin 2>/dev/null | sed -E 's#^git@github.com:#https://github.com/#; s#\.git$##')
[[ -n "$REMOTE" ]] && echo "Then view it at: $REMOTE/tree/main/$EV"
