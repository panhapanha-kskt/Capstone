#!/usr/bin/env bash
# Undo the last promote: put back the newest models/archive/<label>_<date>/ (or the folder you name).
#   bash scripts/rollback_model.sh                     # newest archive
#   bash scripts/rollback_model.sh models/archive/X    # a specific one
# Nothing is deleted: the models being replaced go to models/archive/rolledback_<date>/.
set -euo pipefail
cd "$(dirname "$0")/.."
DEST="${MODELS_DIR:-models}"
SRC="${1:-$(ls -1dt "$DEST"/archive/*/ 2>/dev/null | grep -v '/rolledback_' | head -n 1 || true)}"
SRC="${SRC%/}"
[[ -n "$SRC" && -d "$SRC" ]] || { echo "✗ no archive to roll back to in $DEST/archive/" >&2; exit 1; }

BAD="$DEST/archive/rolledback_$(date +%Y-%m-%d_%H%M%S)"
mkdir -p "$BAD"
shopt -s dotglob nullglob
for f in "$DEST"/*; do
  n="$(basename "$f")"
  [[ "$n" == archive || "$n" == .gitkeep ]] && continue
  mv -- "$f" "$BAD/"
done
cp -rp "$SRC"/. "$DEST"/
echo "• rolled back: $SRC → $DEST (the replaced models are in $BAD)"
