#!/usr/bin/env bash
# capture_dns.sh — Record DNS traffic for the Step 6 lab data (TEST_REPORT §5, limitations 1–3).
#
# Full packets (-s 0), so no query is cut short: the CIC attack captures were useless because
# of a 96-byte snap length. Files rotate every hour and are named after host and start time.
#
# Usage (on each machine; needs root for the capture interface):
#   sudo scripts/capture_dns.sh                       # benign: leave running for days of normal use
#   sudo scripts/capture_dns.sh -o captures -i eth0   # choose folder / interface
#
# Then convert, for example:
#   python3 scripts/make_labeled_features.py --label 0 --family benign_lab \
#       --input captures/*.pcap --output data/processed/week4/benign_lab.json
#   python3 scripts/make_labeled_features.py --label 1 --family iodine --domain <tunnel domain> \
#       --input captures/iodine_*.pcap --output data/processed/week4/tunnels_iodine.json
# and log every capture in docs/Week3/DATASHEET.md.
#
# Benign checklist (removes the record-type shortcut): at least 5 machines, several days, and
# real TXT / MX / DNSKEY / DS lookups — a mail client (SPF, DKIM, DMARC), a DNSSEC-validating
# resolver (Technitium in infra/technitium-elk/), Let's Encrypt renewals (_acme-challenge TXT).
# Attack runs: name the file <tool>_<mode>_*.pcap (iodine, dnscat2, …) and record the time window
# in data/attack_manifest.csv (scripts/run_all.sh does this for --with-attack runs).
set -euo pipefail

OUT="captures"
IFACE="any"
ROTATE=3600
while getopts "o:i:r:" opt; do
  case "$opt" in
    o) OUT="$OPTARG" ;;
    i) IFACE="$OPTARG" ;;
    r) ROTATE="$OPTARG" ;;
    *) echo "usage: $0 [-o out_dir] [-i interface] [-r rotate_seconds]" >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT"
echo "[*] capturing DNS on $IFACE → $OUT (new file every ${ROTATE}s, Ctrl-C to stop)"
exec tcpdump -i "$IFACE" -s 0 -n -G "$ROTATE" \
  -w "$OUT/dns_$(hostname)_%Y-%m-%dT%H-%M-%S.pcap" 'port 53'
