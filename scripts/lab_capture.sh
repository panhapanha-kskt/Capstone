#!/usr/bin/env bash
# lab_capture.sh — Week 7 Task 2: record one lab capture end to end and turn it into a labelled
# training file. Runs on the Kali lab machine (root), with the tunnel server in a Docker container.
#
#   sudo scripts/lab_capture.sh setup          # create the tunnel-server container (once)
#   sudo scripts/lab_capture.sh a1             # iodine over A      → data/processed/week7/tunnels_iodine_a.json
#   sudo scripts/lab_capture.sh a2             # iodine over CNAME  → tunnels_iodine_cname.json
#   sudo scripts/lab_capture.sh a3             # dnscat2 over A/CNAME → tunnels_dnscat2_acname.json
#   sudo scripts/lab_capture.sh a4             # dnscat2 default types → tunnels_dnscat2_default.json
#   sudo scripts/lab_capture.sh b2             # normal TXT/_dmarc/MX lookups → benign_mail_b2.json
#   sudo scripts/lab_capture.sh b3             # normal SRV lookups → benign_srv_b3.json
#   sudo scripts/lab_capture.sh b1 start|stop  # normal use for days; stop converts → benign_lab_b1.json
#   sudo scripts/lab_capture.sh short          # a1 a2 a3 a4 b2 b3, one after another (~3 h)
#   sudo scripts/lab_capture.sh convert a1     # (re)convert an existing capture only
#   sudo scripts/lab_capture.sh status         # what is captured / converted, row counts
#   DRY_RUN=1 scripts/lab_capture.sh a1        # print the commands, run nothing
#
# Every capture: recorder (scripts/capture_dns.sh, full packets) → server in the container → client →
# traffic → stop in reverse order → scripts/make_labeled_features.py (label by provenance: the whole
# capture is attack, or the whole capture is normal; --domain keeps only the tunnel's queries) →
# row count → sha256 in data/processed/week7/SHA256SUMS → one line in data/processed/week7/CAPTURES.log.
# Next step on the training machine: scripts/train_new_data.sh data/processed/week7
#
# Settings (environment): TUNSRV=tunsrv  PASS=Lab123  IFACE=any  PING_COUNT=3000  PAYLOAD_KB=300
#   DNSCAT_DIR=~/dnscat2  DNSCAT_TIMEOUT=900  B2_DOMAINS=1700  B3_DOMAINS=400  PYTHON=python3  MIN_ROWS=1000
# Safety: lab zones only (*.lab), tunnel server on Docker's private network, random test payloads only.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

TUNSRV="${TUNSRV:-tunsrv}"
PASS="${PASS:-Lab123}"
IFACE="${IFACE:-any}"
PING_COUNT="${PING_COUNT:-3000}"
PAYLOAD_KB="${PAYLOAD_KB:-300}"
DNSCAT_DIR="${DNSCAT_DIR:-${HOME:-/root}/dnscat2}"
DNSCAT_TIMEOUT="${DNSCAT_TIMEOUT:-900}"   # seconds; bounds a dnscat2 run if the session never closes
B2_DOMAINS="${B2_DOMAINS:-1700}"
B3_DOMAINS="${B3_DOMAINS:-400}"
PYTHON="${PYTHON:-python3}"
MIN_ROWS="${MIN_ROWS:-1000}"
DRY_RUN="${DRY_RUN:-0}"
CAP_DIR="captures"
OUT_DIR="data/processed/week7"
LAB_DIR="lab"

say()  { printf '\033[0;36m•\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m✗\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [[ "$DRY_RUN" == 1 ]]; then echo "  [dry-run] $*"; else "$@"; fi; }
bg()   { if [[ "$DRY_RUN" == 1 ]]; then echo "  [dry-run] $* &"; BG_PID=0; else "$@" & BG_PID=$!; fi; }

# name | label | family | domain (tunnels) | output file
spec() {
  case "$1" in
    a1) echo "1|iodine_a|t1.zone1.lab|tunnels_iodine_a.json" ;;
    a2) echo "1|iodine_cname|t2.zone2.lab|tunnels_iodine_cname.json" ;;
    a3) echo "1|dnscat2_acname|zone3.lab|tunnels_dnscat2_acname.json" ;;
    a4) echo "1|dnscat2_default|zone4.lab|tunnels_dnscat2_default.json" ;;
    b1) echo "0|benign_lab_b1||benign_lab_b1.json" ;;
    b2) echo "0|benign_mail_b2||benign_mail_b2.json" ;;
    b3) echo "0|benign_srv_b3||benign_srv_b3.json" ;;
    *)  return 1 ;;
  esac
}

need_root() { [[ "$DRY_RUN" == 1 || $EUID -eq 0 ]] || die "run as root: sudo $0 $*"; }

tunsrv_ip() {
  [[ "$DRY_RUN" == 1 ]] && { echo "172.17.0.2"; return; }
  docker inspect -f '{{.NetworkSettings.IPAddress}}' "$TUNSRV" 2>/dev/null \
    || die "container '$TUNSRV' not found: run  sudo $0 setup"
}

tunnels_running() { pgrep -x iodine >/dev/null 2>&1 || pgrep -f "dnscat --dns" >/dev/null 2>&1; }

# ── recorder ───────────────────────────────────────────────────
REC_PID=""
start_recorder() {   # $1 = capture name
  local dir="$CAP_DIR/$1"
  [[ "$DRY_RUN" == 1 ]] || { [[ -z "$(ls -A "$dir" 2>/dev/null)" ]] || die "$dir already has a capture; move it away or use: $0 convert $1"; }
  run mkdir -p "$dir"
  say "recorder → $dir (interface $IFACE)"
  bg scripts/capture_dns.sh -o "$dir" -i "$IFACE"
  REC_PID=$BG_PID
  run sleep 2
}
stop_recorder() {
  [[ -n "$REC_PID" && "$REC_PID" != 0 ]] && { kill -INT "$REC_PID" 2>/dev/null || true; wait "$REC_PID" 2>/dev/null || true; }
  REC_PID=""
  run sleep 1
}
cleanup() {
  [[ "$DRY_RUN" == 1 ]] && return
  pkill -x iodine 2>/dev/null || true
  pkill -f "dnscat --dns" 2>/dev/null || true
  docker exec "$TUNSRV" pkill iodined >/dev/null 2>&1 || true
  docker exec "$TUNSRV" pkill -f dnscat2.rb >/dev/null 2>&1 || true
  stop_recorder
}

# ── traffic generators ─────────────────────────────────────────
iodine_run() {   # $1 = record type, $2 = domain
  local ip; ip="$(tunsrv_ip)"
  say "iodine server ($2) in $TUNSRV"
  run docker exec -d "$TUNSRV" iodined -f -c -P "$PASS" 10.99.0.1 "$2"
  run sleep 2
  say "iodine client → $ip, record type $1 (waits for the tunnel)"
  run iodine -r -T "$1" -P "$PASS" "$ip" "$2"          # no -f: returns once the tunnel is up
  say "traffic: $PING_COUNT pings through the tunnel (~$((PING_COUNT / 5 / 60 + 1)) min)"
  run ping -q -c "$PING_COUNT" -i 0.2 -s 300 10.99.0.1 || warn "some pings were lost (normal for DNS tunnels)"
  run pkill -x iodine || true
  run docker exec "$TUNSRV" pkill iodined || true
}

dnscat_run() {   # $1 = domain, $2 = client type list ("" = tool default)
  local ip payload="/tmp/lab_payload_$$.bin"
  ip="$(tunsrv_ip)"
  [[ "$DRY_RUN" == 1 || -x "$DNSCAT_DIR/client/dnscat" ]] || die "dnscat client not built: cd $DNSCAT_DIR/client && make"
  [[ "$DRY_RUN" == 1 ]] || head -c "$((PAYLOAD_KB * 1024))" /dev/urandom > "$payload"
  say "dnscat2 server ($1) in $TUNSRV"
  # stdin kept open with sleep so the server console does not exit without a terminal
  run docker exec -d "$TUNSRV" bash -c "cd /opt/dnscat2/server && sleep infinity | ruby dnscat2.rb --dns 'host=0.0.0.0,port=53,domain=$1' --secret=$PASS --no-cache > /tmp/dnscat2_server.log 2>&1"
  run sleep 4
  local opts="server=$ip,port=53,domain=$1${2:+,type=$2}"
  say "dnscat2 client → $opts, sending ${PAYLOAD_KB} KB of random bytes"
  # --exec streams the payload through the tunnel; timeout bounds the run if the session stalls
  run timeout "$DNSCAT_TIMEOUT" "$DNSCAT_DIR/client/dnscat" --dns "$opts" --secret="$PASS" --exec "cat $payload" \
    || warn "dnscat2 client ended (timeout or session closed): check the row count below"
  run rm -f "$payload"
  run docker exec "$TUNSRV" pkill -f dnscat2.rb || true
}

b2_run() {
  local list="$LAB_DIR/domains_b2.txt"
  [[ "$DRY_RUN" == 1 || -s "$list" ]] || die "$list missing: run  $0 setup  (needs internet once)"
  say "normal mail-style lookups: TXT, _dmarc TXT, MX over $(wc -l < "$list" 2>/dev/null || echo "$B2_DOMAINS") domains (~1.5 h)"
  [[ "$DRY_RUN" == 1 ]] && { echo "  [dry-run] dig loop over $list"; return; }
  while read -r d; do
    for q in "TXT $d" "TXT _dmarc.$d" "MX $d"; do
      # shellcheck disable=SC2086
      dig +tries=1 +time=2 $q >/dev/null 2>&1 || true
      sleep $((RANDOM % 3 + 1))
    done
  done < "$list"
}

b3_run() {
  local list="$LAB_DIR/domains_b3.txt"
  [[ "$DRY_RUN" == 1 || -s "$list" ]] || die "$list missing: run  $0 setup"
  say "normal SRV lookups over $(wc -l < "$list" 2>/dev/null || echo "$B3_DOMAINS") domains (~40 min)"
  [[ "$DRY_RUN" == 1 ]] && { echo "  [dry-run] dig SRV loop over $list"; return; }
  while read -r d; do
    for s in _sip._tls _sipfederationtls._tcp _xmpp-client._tcp _ldap._tcp _kerberos._udp _autodiscover._tcp; do
      dig +tries=1 +time=2 SRV "$s.$d" >/dev/null 2>&1 || true
      sleep $((RANDOM % 2 + 1))
    done
  done < "$list"
}

# ── convert + checksums + log ──────────────────────────────────
convert() {   # $1 = capture name
  local s label family domain out files rows
  s="$(spec "$1")" || die "unknown capture: $1"
  IFS='|' read -r label family domain out <<< "$s"
  files=$(ls "$CAP_DIR/$1"/*.pcap 2>/dev/null || true)
  [[ "$DRY_RUN" == 1 || -n "$files" ]] || die "no pcap in $CAP_DIR/$1 — nothing was recorded"
  run mkdir -p "$OUT_DIR"
  say "convert $CAP_DIR/$1 → $OUT_DIR/$out (label $label, family $family${domain:+, domain $domain})"
  # shellcheck disable=SC2086
  run "$PYTHON" scripts/make_labeled_features.py --label "$label" --family "$family" \
      ${domain:+--domain "$domain"} --input $files --output "$OUT_DIR/$out"
  [[ "$DRY_RUN" == 1 ]] && return
  rows=$("$PYTHON" -c "import json,sys;print(len(json.load(open(sys.argv[1]))))" "$OUT_DIR/$out")
  # one checksum line per file, newest wins
  touch "$OUT_DIR/SHA256SUMS"
  local tmp; tmp="$(mktemp)"
  grep -v -F -e "$OUT_DIR/$out" $(for f in $files; do printf -- '-e %s ' "$f"; done) "$OUT_DIR/SHA256SUMS" > "$tmp" || true
  sha256sum $files "$OUT_DIR/$out" >> "$tmp"
  mv "$tmp" "$OUT_DIR/SHA256SUMS"
  printf '%s\t%s\tlabel=%s\tfamily=%s\tdomain=%s\trows=%s\thost=%s\tfiles=%s\n' \
    "$(date -Iseconds)" "$1" "$label" "$family" "${domain:--}" "$rows" "$(hostname)" "$(echo $files | tr ' ' ',')" \
    >> "$OUT_DIR/CAPTURES.log"
  if [[ "$rows" -lt "$MIN_ROWS" ]]; then
    warn "$out has only $rows rows (< $MIN_ROWS): run the capture again with more traffic (PING_COUNT / PAYLOAD_KB)"
  else
    ok "$out: $rows labelled rows"
  fi
}

capture() {   # $1 = a1..a4 | b2 | b3
  need_root
  trap cleanup EXIT INT TERM          # stop tunnels and the recorder however the capture ends
  spec "$1" >/dev/null || die "unknown capture: $1"
  if [[ "$1" == b* ]] && tunnels_running; then die "a tunnel is still running: normal captures must be tunnel-free"; fi
  start_recorder "$1"
  case "$1" in
    a1) iodine_run A "t1.zone1.lab" ;;
    a2) iodine_run CNAME "t2.zone2.lab" ;;
    a3) dnscat_run "zone3.lab" "A,CNAME" ;;
    a4) dnscat_run "zone4.lab" "" ;;
    b2) b2_run ;;
    b3) b3_run ;;
  esac
  stop_recorder
  trap - EXIT INT TERM
  cleanup
  convert "$1"
}

setup() {
  need_root
  if [[ "$DRY_RUN" == 1 ]] || ! docker inspect "$TUNSRV" >/dev/null 2>&1; then
    say "creating container $TUNSRV (tunnel server)"
    run docker run -dit --name "$TUNSRV" --cap-add NET_ADMIN --device /dev/net/tun ubuntu:22.04 bash
    run docker exec "$TUNSRV" bash -c "apt-get update && apt-get install -y iodine ruby-dev build-essential git iputils-ping netcat-openbsd procps && git clone https://github.com/iagox86/dnscat2.git /opt/dnscat2 && cd /opt/dnscat2/server && gem install bundler && bundle install"
  else
    run docker start "$TUNSRV" >/dev/null; ok "container $TUNSRV exists"
  fi
  run docker exec "$TUNSRV" bash -c "command -v pkill >/dev/null || (apt-get update && apt-get install -y procps)"
  ok "tunnel server IP: $(tunsrv_ip)"
  run mkdir -p "$LAB_DIR"
  if [[ "$DRY_RUN" == 1 || ! -s "$LAB_DIR/domains_b2.txt" ]]; then
    say "downloading the Tranco top-1M list (internet needed once)"
    run bash -c "cd $LAB_DIR && wget -q -O top-1m.csv.zip https://tranco-list.eu/top-1m.csv.zip && unzip -o -q top-1m.csv.zip"
    run bash -c "cut -d, -f2 $LAB_DIR/top-1m.csv | head -$B2_DOMAINS > $LAB_DIR/domains_b2.txt"
    run bash -c "cut -d, -f2 $LAB_DIR/top-1m.csv | sed -n '2000,$((1999 + B3_DOMAINS))p' > $LAB_DIR/domains_b3.txt"
  fi
  command -v iodine >/dev/null || warn "iodine not installed on this machine: sudo apt install iodine"
  [[ -x "$DNSCAT_DIR/client/dnscat" ]] || warn "dnscat client not built: git clone https://github.com/iagox86/dnscat2 $DNSCAT_DIR && make -C $DNSCAT_DIR/client"
  timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes || warn "clock not NTP-synced: sudo timedatectl set-ntp true"
  ok "setup done"
}

status() {
  printf '%-4s %-30s %-10s %s\n' "cap" "training file" "rows" "pcaps"
  for c in a1 a2 a3 a4 b1 b2 b3; do
    IFS='|' read -r _ _ _ out <<< "$(spec "$c")"
    local n="-" p
    [[ -f "$OUT_DIR/$out" ]] && n=$("$PYTHON" -c "import json,sys;print(len(json.load(open(sys.argv[1]))))" "$OUT_DIR/$out" 2>/dev/null || echo "?")
    p=$(ls "$CAP_DIR/$c"/*.pcap 2>/dev/null | wc -l || true)
    printf '%-4s %-30s %-10s %s\n' "$c" "$out" "$n" "$p"
  done
}

case "${1:-}" in
  setup)        setup ;;
  a1|a2|a3|a4|b2|b3) capture "$1" ;;
  short)        for c in a1 a2 a3 a4 b2 b3; do capture "$c"; done; status ;;
  b1)
    need_root
    case "${2:-}" in
      start) tunnels_running && die "stop the tunnels first"
             start_recorder b1; trap - EXIT; disown "$REC_PID" 2>/dev/null || true
             [[ "$DRY_RUN" == 1 ]] || echo "$REC_PID" > "$CAP_DIR/b1/.recorder.pid"
             ok "B1 recording in the background — use the machine normally, NO tunnels; stop with: $0 b1 stop" ;;
      stop)  pid=$(cat "$CAP_DIR/b1/.recorder.pid" 2>/dev/null || true)
             [[ -n "$pid" ]] && { run kill -INT "$pid" || true; run sleep 2; }
             run rm -f "$CAP_DIR/b1/.recorder.pid"; convert b1 ;;
      *)     die "usage: $0 b1 start|stop" ;;
    esac ;;
  convert)      [[ -n "${2:-}" ]] || die "usage: $0 convert a1|a2|a3|a4|b1|b2|b3"; convert "$2" ;;
  status)       trap - EXIT; status ;;
  *)            sed -n '2,25p' "$0"; exit 2 ;;
esac
