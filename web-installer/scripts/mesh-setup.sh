#!/usr/bin/env bash
# LoRa Mesh post-flash setup: verify board, provision label, set clock,
# optional WiFi, all over USB. No sudo needed (uses sg dialout fallback).
set -u
PORT="${1:-}"
if [ -z "$PORT" ]; then
  echo "usage: $0 /dev/ttyACM0 [--label A|B|C] [--ssid NET [--pass SECRET]]" >&2
  exit 2
fi
LABEL=""; SSID=""; PASS=""
shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --label) LABEL="${2:-}"; shift 2;;
    --ssid) SSID="${2:-}"; shift 2;;
    --pass) PASS="${2:-}"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
HERE="$(cd "$(dirname "$0")" && pwd)"
# Locate repo: script may live in web-installer/scripts/ or be downloaded alone.
if [ -d "$HERE/../../host/meshctl" ]; then
  REPO="$(cd "$HERE/../.." && pwd)"
elif [ -d "$HERE/../host/meshctl" ]; then
  REPO="$(cd "$HERE/.." && pwd)"
else
  echo "cannot find repo (expected host/meshctl nearby); run from the LoRa_Mesh_Handoff tree." >&2
  exit 1
fi
if [ -x "$REPO/.venv/bin/python" ]; then
  PY="$REPO/.venv/bin/python"
else
  PY="$(command -v python3)"
fi
run() {
  if groups | grep -qw dialout && [ -r "$PORT" ] && [ -w "$PORT" ]; then
    PYTHONPATH="$REPO/host" "$PY" -m meshctl "$@"
  else
    # sg takes ONE command string; re-quote args so spaces survive.
    quoted=""
    for a in "$@"; do quoted="$quoted '${a//\'/\'\\\'\'}'"; done
    # shellcheck disable=SC2086
    sg dialout -c "PYTHONPATH=\"$REPO/host\" \"$PY\" -m meshctl$quoted"
  fi
}
echo "== 1/4 status ($PORT)"
run --port "$PORT" status || { echo "FAIL: no reply (board in app mode? try BOOTSEL+reflash)"; exit 1; }
if [ -n "$LABEL" ]; then
  echo "== 2/4 provision label $LABEL"
  run --port "$PORT" provision --label "$LABEL" || exit 1
else
  echo "== 2/4 provision skipped (pass --label A|B|C to set)"
fi
echo "== 3/4 clock set"
run --port "$PORT" time set --utc now || exit 1
if [ -n "$SSID" ]; then
  echo "== 4/4 wifi set (ssid only echoed, never the passphrase)"
  if [ -n "$PASS" ]; then
    run --port "$PORT" wifi set --ssid "$SSID" --pass "$PASS" || exit 1
  else
    run --port "$PORT" wifi set --ssid "$SSID" || exit 1
  fi
  run --port "$PORT" wifi status || exit 1
else
  echo "== 4/4 wifi skipped (pass --ssid NET [--pass SECRET] to join)"
fi
echo "OK: board live. Next: meshctl --port $PORT contacts | settings | listen"
