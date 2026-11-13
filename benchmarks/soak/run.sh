#!/usr/bin/env bash
# Run one soak pair over loopback with netem impairment, then report.
#
#   run.sh <rtc-rtc|pion-pion|rtc-pion> <minutes> <outdir>
#
# Environment: CYCLE_MIN (netem cycle length, default 20), IFACE (default lo), RULES (default
# rules.json next to this script), SOAK_RTC_BIN / SOAK_PION_BIN (prebuilt peers; skips the build).
# Needs Linux, python3, iproute2 and root (or sudo) for tc. Exits with report.py's status.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <rtc-rtc|pion-pion|rtc-pion> <minutes> <outdir>" >&2
  exit 2
fi
pair=$1 minutes=$2 outdir=$3
case "$pair" in rtc-rtc | pion-pion | rtc-pion) ;; *)
  echo "unknown pair: $pair" >&2
  exit 2
  ;;
esac

here=$(cd "$(dirname "$0")" && pwd)
cycle=${CYCLE_MIN:-20}
iface=${IFACE:-lo}
rules=${RULES:-$here/rules.json}
mkdir -p "$outdir"
outdir=$(cd "$outdir" && pwd)
jsonl=$outdir/$pair.jsonl
: >"$jsonl"
sudo=""
[ "$(id -u)" -ne 0 ] && sudo=sudo

rtc_bin=${SOAK_RTC_BIN:-}
pion_bin=${SOAK_PION_BIN:-}
if [[ "$pair" == *rtc* ]] && [ -z "$rtc_bin" ]; then
  cargo build --release --manifest-path "$here/Cargo.toml"
  rtc_bin=$(cargo metadata --no-deps --format-version 1 --manifest-path "$here/Cargo.toml" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/soak-rtc
fi
if [[ "$pair" == *pion* ]] && [ -z "$pion_bin" ]; then
  bindir=$(mktemp -d)
  pion_bin=$bindir/soak-pion
  (cd "$here/go" && go build -o "$pion_bin" .)
fi
bin() { if [ "$1" = rtc ]; then echo "$rtc_bin"; else echo "$pion_bin"; fi; }

offerer=${pair%-*} answerer=${pair#*-}
port=$((7100 + RANDOM % 500))
pids=()
cleanup() {
  trap - EXIT INT TERM
  [ -n "${bindir:-}" ] && rm -rf "$bindir"
  for p in "${pids[@]}"; do $sudo kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 143' INT TERM

"$(bin "$offerer")" --role offerer --signal "127.0.0.1:$port" --minutes "$minutes" --out "$jsonl" \
  --id "$offerer-offerer" 2>"$outdir/$pair.offerer.log" &
pids+=($!)
"$(bin "$answerer")" --role answerer --signal "127.0.0.1:$port" --minutes "$minutes" --out "$jsonl" \
  --id "$answerer-answerer" 2>"$outdir/$pair.answerer.log" &
pids+=($!)

# Impair only once both sides are connected, so the rendezvous and the handshake run clean.
for _ in $(seq 1 90); do
  [ "$(grep -c '"what":"join"' "$jsonl" || true)" -ge 2 ] && break
  kill -0 "${pids[0]}" 2>/dev/null && kill -0 "${pids[1]}" 2>/dev/null || break
  sleep 1
done
$sudo "$here/netem.sh" "$iface" "$minutes" "$cycle" "$jsonl" &
pids+=($!)

status=0
wait "${pids[0]}" || status=$?
wait "${pids[1]}" || status=$?
if [ "$status" -ne 0 ]; then
  echo "run.sh: a peer exited with status $status (see $outdir/$pair.*.log)" >&2
fi
$sudo kill "${pids[2]}" 2>/dev/null || true
wait "${pids[2]}" 2>/dev/null || true
pids=()

python3 "$here/report.py" --rules "$rules" --out "$outdir" "$jsonl"
