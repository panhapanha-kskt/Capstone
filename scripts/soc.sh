#!/usr/bin/env bash
# soc.sh — one command for the whole SOC: Detector (push listener + dashboard/server.py watch loop) and
# Learner (scripts/learner.py: trains only on drift / new captures / >=50 verdicts). Two independent
# services, each under its own supervisor (scripts/soc_supervisor.py), linked only by models/ + the gate.
#
#   bash scripts/soc.sh up [--auto-promote] [detector|learner]   start (a second `up` starts nothing twice)
#   bash scripts/soc.sh down [detector|learner]                  clean stop, checks for stray processes
#   bash scripts/soc.sh restart [--auto-promote] [detector|learner]
#   bash scripts/soc.sh status                                   services, last trigger, gate, live model
#   bash scripts/soc.sh logs [detector|learner] [-f]
#
# Settings: config/soc.yaml (or SOC_CONFIG=file). Promotion stays manual unless --auto-promote is given
# or `auto_promote: true` is set; then scripts/part_b.py promotes on gate PASS (smoke test + rollback).
# Exit codes: 0 ok · 1 error / stray processes after down · 2 up: started but not healthy yet ·
#             3 status: a service is not running.
# User-level only: no sudo, no systemd. Run from WSL/Linux with the project venv (config `python:`).
set -euo pipefail
if [[ -n "${SOC_CONFIG:-}" && "${SOC_CONFIG:0:1}" != / ]]; then
  SOC_CONFIG="$(cd "$(dirname "$SOC_CONFIG")" && pwd)/$(basename "$SOC_CONFIG")"; export SOC_CONFIG
fi
cd "$(dirname "$0")/.."
ROOT="$PWD"

usage() {
  sed -n '2,16p' "$ROOT/scripts/soc.sh" | sed 's/^# \{0,1\}//'
}

pick_python() {   # same order as src/dns_detect/soc/config.py: SOC_PYTHON, config python:, VIRTUAL_ENV, python3
  if [[ -n "${SOC_PYTHON:-}" ]]; then echo "$SOC_PYTHON"; return; fi
  local cfg="${SOC_CONFIG:-config/soc.yaml}" conf=""
  if [[ -f "$cfg" ]]; then
    conf="$(sed -n 's/^python:[[:space:]]*["'\'']\{0,1\}\([^"'\''#[:space:]]*\).*/\1/p' "$cfg" | head -n 1)"
  fi
  [[ -z "$conf" ]] && conf=/home/Panha/dns-venv/bin/python3
  if [[ "$conf" != null && -x "$conf" ]]; then echo "$conf"; return; fi
  if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python3" ]]; then echo "$VIRTUAL_ENV/bin/python3"; return; fi
  command -v python3
}

CMD="${1:-}"
case "$CMD" in
  -h|--help|help) usage; exit 0 ;;
  up|down|restart|status|logs) shift ;;
  *) usage >&2; exit 1 ;;
esac

PY="$(pick_python)"
"$PY" -c 'import yaml' 2>/dev/null || { echo "✗ $PY cannot import yaml (PyYAML): activate the project venv or set SOC_PYTHON" >&2; exit 1; }
eval "$("$PY" scripts/soc_supervisor.py env)"
mkdir -p "$SOC_STATE_DIR" "$SOC_LOG_DIR"

AUTO=false
SVCS=()
FOLLOW=false
for a in "$@"; do
  case "$a" in
    --auto-promote) AUTO=true ;;
    -f|--follow) FOLLOW=true ;;
    detector|learner) SVCS+=("$a") ;;
    *) echo "✗ unknown argument: $a" >&2; usage >&2; exit 1 ;;
  esac
done

held() { [[ -f "$1" ]] && ! flock -n "$1" true 2>/dev/null; }
sup_pid() { cat "$SOC_STATE_DIR/$1.supervisor.pid" 2>/dev/null || echo "?"; }
is_supervisor() { [[ "$1" =~ ^[0-9]+$ ]] && tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | grep -q "soc_supervisor.py $2"; }

svc_up() {
  local svc="$1" lock="$SOC_STATE_DIR/$1.supervisor.lock" i
  if held "$lock"; then
    echo "• $svc: already running (supervisor pid $(sup_pid "$svc")); nothing started"
    return 0
  fi
  local -a envs=(env -u SOC_AUTO_PROMOTE)        # auto-promote only when asked for on this command line
  # Test/demo overrides must never leak from the operator's shell into the real services (a stub gate
  # or stub training would bypass the real gate). Dropped unless SOC_ALLOW_STUBS=1 is set on purpose.
  if [[ "${SOC_ALLOW_STUBS:-0}" != 1 ]]; then
    local v dropped=()
    for v in SOC_TRAIN_CMD SOC_EXPORT_CMD SOC_PART_B_CMD SOC_LEARNER_CMD SOC_DETECTOR_CMD SOC_LISTENER_CMD SOC_NOW \
             PART_B_GATE PART_B_PROMOTE PART_B_SMOKE PART_B_ROLLBACK DNS_DETECT_MODELS_DIR; do
      [[ -n "${!v:-}" ]] && dropped+=("$v")
      envs+=(-u "$v")
    done
    [[ ${#dropped[@]} -gt 0 ]] && echo "• $svc: ignoring ${dropped[*]} from your shell (set SOC_ALLOW_STUBS=1 for a demo)"
  fi
  [[ "$svc" == learner && "$AUTO" == true ]] && envs+=(SOC_AUTO_PROMOTE=1)   # assignments go last for env
  if setsid --help 2>&1 | grep -q -- '--fork'; then
    "${envs[@]}" setsid -f "$PY" scripts/soc_supervisor.py "$svc" </dev/null >>"$SOC_LOG_DIR/supervisor-$svc.out" 2>&1
  else
    "${envs[@]}" nohup setsid "$PY" scripts/soc_supervisor.py "$svc" </dev/null >>"$SOC_LOG_DIR/supervisor-$svc.out" 2>&1 &
    disown || true
  fi
  for i in $(seq 1 100); do
    held "$lock" && { echo "• $svc: started (supervisor pid $(sup_pid "$svc"))"; return 0; }
    sleep 0.1
  done
  echo "✗ $svc: supervisor did not start; see $SOC_LOG_DIR/supervisor-$svc.out" >&2
  return 1
}

svc_down() {
  local svc="$1" lock="$SOC_STATE_DIR/$1.supervisor.lock" pid wait_s i
  if ! held "$lock"; then
    "$PY" scripts/soc_supervisor.py kill-groups "$svc"          # leftovers of a supervisor that was killed
    echo "• $svc: not running"
    return 0
  fi
  pid="$(sup_pid "$svc")"
  if [[ "$svc" == learner ]]; then wait_s=$((SOC_LRN_STOP + SOC_PROMOTE_GRACE + 5)); else wait_s=$((SOC_DET_STOP + 5)); fi
  if is_supervisor "$pid" "$svc"; then
    kill -TERM "$pid" 2>/dev/null || true
  else
    echo "! $svc: lock held but pid file does not point at a supervisor ($pid)" >&2
  fi
  for i in $(seq 1 $((wait_s * 10))); do
    held "$lock" || break
    sleep 0.1
  done
  if held "$lock"; then
    echo "! $svc: supervisor did not stop within ${wait_s}s: SIGKILL" >&2
    if is_supervisor "$pid" "$svc"; then kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true; fi
    "$PY" scripts/soc_supervisor.py kill-groups "$svc"
    sleep 0.5
  fi
  echo "• $svc: stopped"
}

check_strays() {
  local out="" i
  for i in $(seq 1 12); do
    out="$("$PY" scripts/soc_supervisor.py strays "$@" || true)"
    [[ -z "$out" ]] && return 0
    sleep 0.5
  done
  echo "✗ stray processes still running:" >&2
  echo "$out" | sed 's/^/    /' >&2
  return 1
}

do_up() {
  local -a svcs=("$@")
  local rc=0 s
  [[ ${#svcs[@]} -eq 0 ]] && svcs=(detector learner)
  for s in "${svcs[@]}"; do svc_up "$s" || rc=1; done
  [[ $rc -ne 0 ]] && return 1
  local wait_s="${SOC_UP_WAIT_S:-$SOC_STARTUP_GRACE}"
  echo "• waiting up to ${wait_s}s for health checks"
  if "$PY" scripts/soc_supervisor.py wait-healthy --timeout "$wait_s" "${svcs[@]}"; then
    "$PY" scripts/soc_supervisor.py status || true
    return 0
  fi
  "$PY" scripts/soc_supervisor.py status || true
  echo "! started, but not healthy yet (see: bash scripts/soc.sh logs)" >&2
  return 2
}

do_down() {
  local -a svcs=()
  local s
  for s in learner detector; do
    if [[ $# -eq 0 ]] || [[ " $* " == *" $s "* ]]; then svcs+=("$s"); fi
  done
  for s in "${svcs[@]}"; do svc_down "$s"; done
  check_strays "${svcs[@]}"
}

do_logs() {
  local -a files=() svcs=("$@")
  local s f
  [[ ${#svcs[@]} -eq 0 ]] && svcs=(detector learner)
  for s in "${svcs[@]}"; do
    if [[ "$s" == detector ]]; then
      files+=("$SOC_LOG_DIR/listener.log" "$SOC_LOG_DIR/dashboard.log" "$SOC_LOG_DIR/supervisor-detector.log")
    else
      files+=("$SOC_LOG_DIR/learner.log" "$SOC_LOG_DIR/supervisor-learner.log")
      f="$(ls -t "$SOC_LOG_DIR"/train_*.log 2>/dev/null | head -n 1 || true)"
      [[ -n "$f" ]] && files+=("$f")
    fi
  done
  local -a have=()
  for f in "${files[@]}"; do [[ -f "$f" ]] && have+=("$f"); done
  if [[ "$FOLLOW" == true ]]; then
    exec tail -n 50 -F "${files[@]}"
  fi
  if [[ ${#have[@]} -eq 0 ]]; then echo "no logs yet in $SOC_LOG_DIR"; return 0; fi
  tail -n 200 "${have[@]}"
}

case "$CMD" in
  up)      echo "• python: $SOC_PY ($SOC_PY_SOURCE)"; rc=0; do_up "${SVCS[@]+"${SVCS[@]}"}" || rc=$?; exit $rc ;;
  down)    do_down "${SVCS[@]+"${SVCS[@]}"}" ;;
  restart) do_down "${SVCS[@]+"${SVCS[@]}"}" || true; rc=0; do_up "${SVCS[@]+"${SVCS[@]}"}" || rc=$?; exit $rc ;;
  status)  rc=0; "$PY" scripts/soc_supervisor.py status || rc=$?; exit $rc ;;
  logs)    do_logs "${SVCS[@]+"${SVCS[@]}"}" ;;
esac
