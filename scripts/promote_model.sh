#!/usr/bin/env bash
# Promote a run folder into the live models/ folder. Nothing is deleted:
# everything currently in models/ is moved to models/archive/<label>_<date>/ first.
#
#   bash scripts/promote_model.sh runs/v3_iforest autoencoder_pathB
#
# Copies only the files the pipeline loads (not merged_labeled.json or CSVs), writes
# models/PROMOTED.json with the SHA-256 of every copied file, and fails if a file is missing.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN="${1:?usage: promote_model.sh <run folder> [archive label]}"
LABEL="${2:-previous}"
DEST="models"
ARCHIVE="$DEST/archive/${LABEL}_$(date +%Y-%m-%d_%H%M%S)"

FILES=(dns_tunnel_rf.pkl dns_tunnel_gbt.pkl dns_scaler.pkl dns_threshold.json bigram_table.json
       dns_trafficformer_iforest.pkl dns_trafficformer_norm.json dns_trafficformer_threshold.json
       fusion_lr.pkl fusion_lr.json fusion_lr_tiers.json
       evaluation_metrics.json training_metadata.json training_provenance.json
       trained_files_registry.json split_manifest.json)
OPTIONAL=(dns_tunnel_transformer.keras MODEL_CARD.md run_record.json)

for f in "${FILES[@]}"; do
  [[ -f "$RUN/$f" ]] || { echo "✗ $RUN/$f is missing — nothing was changed" >&2; exit 1; }
done

mkdir -p "$ARCHIVE"
shopt -s dotglob nullglob
for f in "$DEST"/*; do
  name="$(basename "$f")"
  [[ "$name" == archive || "$name" == .gitkeep ]] && continue
  mv -- "$f" "$ARCHIVE/"
done
echo "• archived the old models → $ARCHIVE/"

for f in "${FILES[@]}"; do cp -p "$RUN/$f" "$DEST/"; done
for f in "${OPTIONAL[@]}"; do [[ -f "$RUN/$f" ]] && cp -p "$RUN/$f" "$DEST/"; done

python3 - "$RUN" "$DEST" "$ARCHIVE" "${FILES[@]}" <<'PY'
import hashlib, json, sys, datetime, pathlib
run, dest, archive, files = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3], sys.argv[4:]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
out = {"promoted_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
       "source_run": run, "archived_previous_to": archive,
       "files": {f: sha(dest / f) for f in files}}
bad = [f for f in files if out["files"][f] != sha(pathlib.Path(run) / f)]
if bad:
    sys.exit(f"✗ copy mismatch: {bad}")
(dest / "PROMOTED.json").write_text(json.dumps(out, indent=2))
print(f"• copied {len(files)} files from {run}; SHA-256 recorded in {dest}/PROMOTED.json")
PY
echo "• roll back: move the files from $ARCHIVE/ back into $DEST/"
