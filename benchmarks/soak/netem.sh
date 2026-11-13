#!/usr/bin/env bash
# Drive `tc netem` through a repeating phase cycle and log every change as a JSONL `phase` line.
#
#   netem.sh <iface> <minutes> <cycle_minutes> <events.jsonl>
#
# One cycle is clean 40 %, loss (2 % random) 15 %, burst (Gilbert-Elliott, ~5 % in bursts of ~5
# packets) 15 %, bw (1.5 Mbit/s cap plus 80 ms delay) 15 %, outage (100 % loss) 5 s, and clean
# again (recover) for the rest. At the default 20-minute cycle that is 8 / 3 / 3 / 3 minutes,
# 5 s, ~3 minutes. The cycle repeats until <minutes> have passed. Qdiscs are removed on exit.
#
# The bw cap is 1.5 Mbit/s per direction (NETEM_BW_MBIT overrides). `lo` is one device that both
# directions cross, so there the cap is doubled and each direction gets about 1.5 Mbit/s.
#
# Egress is always impaired. Ingress is impaired too, through an `ifb` device, except on `lo`
# (a packet crosses lo's egress and ingress both, so the egress shaping already covers each
# direction once). Override with NETEM_INGRESS=0|1|auto. Linux only; needs root/NET_ADMIN. To
# impair another network namespace, run this inside it: nsenter -t <pid> -n netem.sh ...
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <iface> <minutes> <cycle_minutes> <events.jsonl>" >&2
  exit 2
fi
iface=$1 minutes=$2 cycle_min=$3 events=$4
ifb=ifb-soak
ingress=${NETEM_INGRESS:-auto}
if [ "$ingress" = auto ]; then
  if [ "$iface" = lo ]; then ingress=0; else ingress=1; fi
fi

bw_mbit=${NETEM_BW_MBIT:-$([ "$iface" = lo ] && echo 3 || echo 1.5)}

now_ms() { date +%s%3N; }
arch=$(uname -m)

cleanup() {
  trap - EXIT INT TERM
  tc qdisc del dev "$iface" root 2>/dev/null || true
  if [ "$ingress" = 1 ]; then
    tc qdisc del dev "$iface" ingress 2>/dev/null || true
    tc qdisc del dev "$ifb" root 2>/dev/null || true
    ip link del "$ifb" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 143' INT TERM

if [ "$ingress" = 1 ]; then
  modprobe ifb 2>/dev/null || true
  ip link add "$ifb" type ifb
  ip link set "$ifb" up
  tc qdisc add dev "$iface" handle ffff: ingress
  tc filter add dev "$iface" parent ffff: protocol all u32 match u32 0 0 \
    action mirred egress redirect dev "$ifb"
fi

# apply <netem args...>: the same impairment on egress and (when enabled) on the ifb ingress copy.
apply() {
  if [ "$#" -eq 0 ]; then
    tc qdisc del dev "$iface" root 2>/dev/null || true
    [ "$ingress" = 1 ] && { tc qdisc del dev "$ifb" root 2>/dev/null || true; }
    return 0
  fi
  tc qdisc replace dev "$iface" root netem "$@"
  if [ "$ingress" = 1 ]; then tc qdisc replace dev "$ifb" root netem "$@"; fi
}

# phase <name> <seconds> <netem args...>
phase() {
  local name=$1 secs=$2
  shift 2
  apply "$@"
  printf '{"ts":%s,"impl":"netem","arch":"%s","kind":"phase","id":"netem","name":"%s"}\n' "$(now_ms)" "$arch" "$name" >>"$events"
  sleep "$secs" &
  wait $!
}

: >>"$events"
end=$(($(date +%s) + minutes * 60))
cycle=$(awk -v m="$cycle_min" 'BEGIN { printf "%d", m * 60 }')
clean=$((cycle * 40 / 100))
slot=$((cycle * 15 / 100))
outage=5
[ "$outage" -gt $((cycle / 20)) ] && outage=$((cycle / 20 > 0 ? cycle / 20 : 1))
recover=$((cycle - clean - 3 * slot - outage))

# Each phase is cut short at the deadline so the run length is exact.
left() { local l=$((end - $(date +%s))); [ "$l" -gt "$1" ] && echo "$1" || echo "$l"; }

while [ "$(date +%s)" -lt "$end" ]; do
  phase clean "$(left "$clean")"
  [ "$(date +%s)" -ge "$end" ] && break
  phase loss "$(left "$slot")" loss 2%
  [ "$(date +%s)" -ge "$end" ] && break
  phase burst "$(left "$slot")" loss gemodel 1% 20% 100% 0%
  [ "$(date +%s)" -ge "$end" ] && break
  phase bw "$(left "$slot")" delay 80ms rate "${bw_mbit}mbit" limit 300
  [ "$(date +%s)" -ge "$end" ] && break
  phase outage "$(left "$outage")" loss 100%
  [ "$(date +%s)" -ge "$end" ] && break
  phase recover "$(left "$recover")"
done
