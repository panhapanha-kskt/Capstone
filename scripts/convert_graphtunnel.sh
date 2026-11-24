#!/usr/bin/env bash
# convert_graphtunnel.sh — GraphTunnel "DNS-Tunnel-Datasets" (ggyggy666, IEEE 2024) → labelled rows
# this project can train on. Run from the project root in WSL with the venv active:
#
#   bash scripts/convert_graphtunnel.sh                 # convert (idempotent: skips files already made)
#   bash scripts/convert_graphtunnel.sh --normal-files 68 --wildcard-files 13   # ALL benign (RAM-heavy)
#
# Repo layout (git clone https://github.com/ggyggy666/DNS-Tunnel-Datasets.git data/external/graphtunnel/repo):
#   tunnel/        known tools: dnscat2 (cname/mx/txt), dnspot, iodine (7 record types), DNS-shell, tuns, dns2tcp-key
#   unkownTunnel/  cobaltstrike, dns2tcp (key/txt), ozymandns, tcp-over-dns (cname/txt)
#   crossEndPoint/ AndIodine from Android (cname/mx/null/srv/txt)
#   normal/        benign, Cloudflare top-1M (68 split files, ~2.0 M queries)
#   wildcard/      benign wildcard-DNS traffic (13 split files, ~0.64 M queries)
#
# Several captures exist twice: one merged .pcap AND a folder of split .pcapng pieces of the same session.
# Only the split folders are used for those, so no session is counted twice.
#
# Attack side: scripts/convert_external_tunnels.py per family (truncation check, one tunnel domain per
# family, contiguous blocks, cap 5,000 queries per family, label_source=provenance).
# Benign side: scripts/make_labeled_features.py --label 0 on whole files (never --max-per-file: Path B
# needs consecutive queries). By default the FIRST N files in time order are converted for training and
# the rest are left for a later-traffic check (Week 7 Task 4); --normal-files / --wildcard-files widen it.
#
# Cite: GraphTunnel: Robust DNS Tunnel Detection Based on DNS Recursive Resolution Graph (IEEE, 2024),
# https://github.com/ggyggy666/DNS-Tunnel-Datasets. The repo states no licence; it asks for citation.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO="data/external/graphtunnel/repo"
OUT="data/external/graphtunnel"
FAM="$OUT/families"            # one folder per attack family (symlinks into the repo)
NORMAL_FILES=15                 # ~440k benign queries; the other 53 files stay out for a later-traffic test
WILDCARD_FILES=4                # ~200k wildcard queries; the other 9 files stay out
MAX_PER_FAMILY=5000
while [[ $# -gt 0 ]]; do
  case "$1" in
    --normal-files)   NORMAL_FILES="$2"; shift 2 ;;
    --wildcard-files) WILDCARD_FILES="$2"; shift 2 ;;
    --max-per-family) MAX_PER_FAMILY="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ -d "$REPO" ]] || { echo "✗ $REPO not found: git clone --depth 1 https://github.com/ggyggy666/DNS-Tunnel-Datasets.git $REPO" >&2; exit 1; }
export PYTHONPATH="src${PYTHONPATH:+:$PYTHONPATH}"

# ── 1. one folder per attack family ─────────────────────────────────────────────
# family name → source (a folder of split pieces, or a single pcap). Folders win over merged singles.
declare -A SRC=(
  # tunnel/ (the paper's "known" tools)
  [dnscat2_cname]="tunnel/dnscat2-cname"      [dnscat2_mx]="tunnel/dnscat2-mx"        [dnscat2_txt]="tunnel/dnscat2-txt"
  [dnspot]="tunnel/dnspot"                    [dns2tcp_key_gt]="tunnel/dns2tcp-key"
  [iodine_null]="tunnel/iodine-NULL.pcap"     [iodine_a]="tunnel/iodine-a.pcap"       [iodine_cname]="tunnel/iodine-cname.pcap"
  [iodine_mx]="tunnel/iodine-mx.pcap"         [iodine_private]="tunnel/iodine-private.pcap"
  [iodine_srv]="tunnel/iodine-srv.pcap"       [iodine_txt]="tunnel/iodine-txt.pcap"
  [dns_shell_gt]="tunnel/DNS-shell.pcap"      [tuns]="tunnel/tuns.pcap"
  # unkownTunnel/ (the paper's "unknown" tools)
  [cobaltstrike_gt]="unkownTunnel/cobalstrike.pcap"
  [dns2tcp_txt_unk]="unkownTunnel/dns2tcp-txt.pcap"   [ozymandns_gt]="unkownTunnel/ozymandns.pcap"
  # unkownTunnel/dns2tcp-key.pcap is the same 34,555-query capture as tunnel/dns2tcp-key/ → not staged
  [tcp_over_dns_cname]="unkownTunnel/tcp-over-dns-CNAME"  [tcp_over_dns_txt]="unkownTunnel/tcp-over-dns-TXT"
  # crossEndPoint/ (Android)
  [andiodine_cname]="crossEndPoint/AndIodine-CNAME.pcap"  [andiodine_null]="crossEndPoint/AndIodine-NULL.pcap"
  [andiodine_mx]="crossEndPoint/AndIodine-MX"  [andiodine_srv]="crossEndPoint/AndIodine-SRV"  [andiodine_txt]="crossEndPoint/AndIodine-TXT"
)
mkdir -p "$FAM"
for fam in "${!SRC[@]}"; do
  src="$REPO/${SRC[$fam]}"
  mkdir -p "$FAM/$fam"
  if [[ -d "$src" ]]; then
    for f in "$src"/*.pcap*; do ln -sfn "$(realpath "$f")" "$FAM/$fam/$(basename "$f")"; done
  else
    ln -sfn "$(realpath "$src")" "$FAM/$fam/$(basename "$src")"
  fi
done
echo "• ${#SRC[@]} attack families staged under $FAM"

# ── 2. attacks → tunnels_<family>.json (skips families already converted) ──────
todo=()
for fam in $(printf '%s\n' "${!SRC[@]}" | sort); do
  [[ -f "$OUT/tunnels_$fam.json" ]] || todo+=("$fam")
done
if [[ ${#todo[@]} -gt 0 ]]; then
  echo "• converting ${#todo[@]} attack families (cap $MAX_PER_FAMILY queries each, truncation-checked)…"
  python3 scripts/convert_external_tunnels.py --root "$FAM" --out-dir "$OUT" \
      --max-per-family "$MAX_PER_FAMILY" --families "${todo[@]}"
else
  echo "• attack families already converted"
fi

# ── 3. benign → whole files, first N in time order ─────────────────────────────
convert_benign() {   # <family> <out.json> <N> <glob…>
  local fam="$1" out="$2" n="$3"; shift 3
  if [[ -f "$out" ]]; then echo "• $out exists, skipped"; return; fi
  mapfile -t files < <(printf '%s\n' "$@" | sort | head -n "$n")
  echo "• $fam: ${#files[@]} file(s) → $out"
  python3 scripts/make_labeled_features.py --label 0 --family "$fam" --input "${files[@]}" --output "$out"
}
convert_benign benign_graphtunnel "$OUT/benign_graphtunnel.json" "$NORMAL_FILES" "$REPO"/normal/normal/*.pcap
convert_benign benign_wildcard    "$OUT/benign_wildcard.json"    "$WILDCARD_FILES" "$REPO"/wildcard/*.pcap

# ── 4. what to train with ───────────────────────────────────────────────────────
echo
echo "Converted files:"
ls -1 "$OUT"/*.json | sed 's/^/  /'
echo
echo "Train (old data + all of these):"
echo "  DNS_DETECT_MODELS_DIR=runs/v4_graphtunnel ./scripts/train_models.sh --add-files $OUT/tunnels_*.json $OUT/benign_*.json"
echo "  (tunnels_dns2tcp_key_unk.json duplicates tunnels_dns2tcp_key_gt.json — the repo holds the same capture twice; delete one)"
echo "Later-traffic check (files NOT trained on): normal_000$(printf '%02d' "$NORMAL_FILES")… and wildcard_000$(printf '%02d' "$WILDCARD_FILES")… in $REPO"
