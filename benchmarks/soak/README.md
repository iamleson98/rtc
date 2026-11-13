# Soak: rtc against pion over hours

Users of an SFU built on this library report calls that start fine and later freeze or lose audio.
Short tests do not see that kind of fault, so this harness runs two peers over loopback for hours
(two by default), impairs the path with `tc netem` on a repeating cycle, and compares the start of
the run with the end:

* counter wraparound: every run starts RTP sequence numbers 300 packets before 65536 and
  timestamps 20 s before 2^32 (video and audio), so SRTP rollover, extended sequence numbers and
  jitter maths cross their wraps within seconds, and again every ~9 minutes (video) afterwards;
* slow leaks: RSS, threads and file descriptors per process;
* queues that grow: data-channel latency, jitter, CPU;
* recovery: audio and video after packet loss, burst loss, a bandwidth cap and a 5 s outage.

Pion (Go) is the reference. `rtc` is the implementation under test; pion is reported, not gated.
The harness is generic: any implementation that writes the JSONL below can use `netem.sh` and
`report.py` (the rtcd SFU harnesses do).

| File | Role |
|---|---|
| `go/` | the pion/webrtc v4 peer (`soak-pion`), pinned in `go/go.mod` |
| `src/`, `Cargo.toml` | the `rtc` peer (`soak-rtc`), a standalone crate outside the main workspace |
| `netem.sh` | drives `tc netem` through the phase cycle and logs `phase` lines |
| `run.sh` | builds and starts a pair, runs `netem.sh` on `lo`, collects JSONL, calls `report.py` |
| `report.py` | JSONL to `summary.md` and `report.html`; applies `rules.json`; exit 1 on a gate breach |
| `rules.json` | thresholds; gates `rtc` only |

## Run it

Linux only (`tc`, `/proc`); needs Go, Rust, python3, iproute2, and root or sudo for `tc`.

```sh
benchmarks/soak/run.sh rtc-pion 120 out        # pair: rtc-rtc | pion-pion | rtc-pion, minutes, outdir
CYCLE_MIN=2 benchmarks/soak/run.sh rtc-rtc 3 out   # short smoke run
```

`rtc-pion` is bidirectional (each peer sends to the other), so it covers both directions. Output:
`out/<pair>.jsonl`, `out/<pair>.{offerer,answerer}.log`, `out/summary.md`, `out/report.html`.
`SOAK_RTC_BIN` / `SOAK_PION_BIN` use prebuilt peers; `IFACE` and `RULES` override the interface and
the rules file.

On a Mac, use a privileged Linux container (Colima's VM is aarch64, so this is also an arm64 run).
Build the two peers for Linux first (`cargo build --release` in a `rust` container, `go build` in a
`golang` one), then run in an image that has `iproute2` and `python3`:

```sh
docker run --rm --cap-add NET_ADMIN -v "$PWD":/rtc -v /path/to/peers:/peers -v /path/to/out:/out \
  -e SOAK_RTC_BIN=/peers/soak-rtc -e SOAK_PION_BIN=/peers/soak-pion -e CYCLE_MIN=2 \
  <image> /rtc/benchmarks/soak/run.sh rtc-pion 3 /out/run
```

Runs of a few minutes are smoke tests of the harness: the windows are too short to judge drift, so
the drift rules report `n/a` (see `min_clean_window_min`).

CI runs the three
pairs on x64 and arm64 (`.github/workflows/soak.yml`): weekly for 120 minutes, by hand with a
`minutes` input, and for pull requests that touch this directory for 10 minutes with 5-minute
cycles.

Windows of the report: after `warmup_min` the first `window_min` minutes are compared with the last
`window_min`, using clean-phase samples only. Short runs scale both down (window to a quarter of
the run, warmup to a sixth); a 3-minute smoke run therefore compares 45 s with 45 s.

## The peers

`soak-pion` (`go/`) and `soak-rtc` (`src/`) take the same flags and behave the same:

```
--role offerer|answerer   --signal HOST:PORT   --minutes N   --out FILE.jsonl   --id NAME
```

The offerer listens on `--signal` (plain TCP, one length-prefixed JSON message each way:
`{"sdp": ..., "candidates": [...]}`), the answerer dials it. ICE runs over loopback host
candidates. After connecting each peer runs `--minutes` and appends to `--out`; `--id` defaults to
`<impl>-<role>`. Each peer sends:

* audio: Opus payload type 111, 50 packets/s of 80 bytes, with the `ssrc-audio-level` extension;
* video: VP8 payload type 96, 30 fps, about 1.2 Mbit/s, packetised by the library's VP8
  payloader at MTU 1200 with the marker bit on each frame's last packet and a picture id; a
  keyframe every 4 s and on every PLI or FIR (the payload is synthetic, only the frame tag's
  keyframe bit is meaningful);
* a data channel (negotiated, id 1) at 10 messages/s;
* NACK retransmissions from the library's responder, using its default interceptors, and PLIs of
  its own when a video track comes out of a freeze (at most one a second).

RTP sequence numbers start 300 packets before 65536, and timestamps 20 s before 2^32 (90 kHz for
video, 48 kHz for audio), so every run crosses every wrap early. Both sides log an `event` of kind
`wrap` as the sender crosses and as the receiver sees it.

## netem phases

`netem.sh <iface> <minutes> <cycle_minutes> <events.jsonl>` repeats one cycle until the time is up
and appends a `phase` line at every change. Fractions of the cycle length (20 minutes by default):

| Phase | Share | Impairment |
|---|---|---|
| `clean` | 40 % (8 min) | none |
| `loss` | 15 % (3 min) | 2 % random loss |
| `burst` | 15 % (3 min) | Gilbert-Elliott loss, about 5 % in bursts of about 5 packets |
| `bw` | 15 % (3 min) | 1.5 Mbit/s cap per direction and 80 ms delay |
| `outage` | 5 s | 100 % loss |
| `recover` | the rest | none |

`lo` is a single device that both directions cross, so there the cap is 3 Mbit/s in total (about
1.5 each way); `NETEM_BW_MBIT` overrides it. Qdiscs are removed on exit. Egress is always shaped; ingress too through an `ifb` device, except on
`lo`, where a packet crosses egress and ingress both and egress shaping already covers each
direction once (`NETEM_INGRESS=0|1|auto` overrides). To impair another network namespace, run the
script inside it (`nsenter -t <pid> -n netem.sh ...`).

## JSONL schema (the contract)

One JSON object per line. Every line has:

| Field | Type | Meaning |
|---|---|---|
| `ts` | integer | unix time, milliseconds |
| `impl` | string | `rtcd-rs`, `rtcd-go`, `rtc`, `pion`, `chrome-...`; free text. `netem` for phase lines |
| `arch` | string | `x86_64` or `aarch64` (`uname -m`) |
| `kind` | string | `recv`, `proc`, `dc`, `event` or `phase` |
| `id` | string | what the line is about: a track (`rtc-offerer-video`), a process, a peer |

`recv`, one per received track every 5 s, counters cumulative since start:

| Field | Meaning |
|---|---|
| `media` | `video` or `audio` |
| `group` | `clean` (a path that is never impaired, e.g. a control participant) or `impaired` (on the netem path). Samples of a `clean` group count as clean in every phase |
| `frames` | video: frames completed (marker packet received); audio: audio packets received |
| `freezes`, `freeze_ms` | WebRTC stats freeze: an inter-frame interval longer than max(3 x average, average + 150 ms), average over the last 30 frames; `freeze_ms` is the summed interval. A freeze still open at a report counts at once |
| `packets` | RTP packets received (retransmissions included) |
| `lost` | expected minus received, from extended sequence numbers; falls when a retransmission fills a gap |
| `nack`, `pli` | NACKs and PLIs this receiver sent (library statistics; pion's NACK generator bypasses its own stats, so `pion` reads 0 NACKs) |
| `jitter_ms` | RFC 3550 interarrival jitter |
| `rtt_ms` | number or null: round trip from RTCP for the stream of the same kind that this peer sends; null when the library reports none (rtc never computes it) |
| `audio_gap_ms` | time the sender was sending but no audio packet arrived for more than 60 ms, summed |
| `stalled` | bool: no media packet for more than 2 s at some point since the previous report |

`proc`, one per process every 5 s: `rss_mb`, `cpu_pct`, `threads`, `fds`, `udp_rcvbuf_err`,
`udp_sndbuf_err` (the host's UDP `RcvbufErrors` / `SndbufErrors`).

`dc`, every 5 s: `sent`, `recv` (cumulative), `lat_ms_p50`, `lat_ms_p99` (this window; null when no
message arrived). The peers send `{"n":<count>,"ts":<unix microseconds>}` at 10 messages/s on a
negotiated channel, id 1, label `soak`.

`event`: `what` is `ice_state`, `wrap`, `join`, `leave` or `error`, with a `detail` string. `wrap`
lines read `send|recv audio|video seq|ts wrap`.

`phase`: `name` is `clean`, `loss`, `burst`, `bw`, `outage` or `recover`; the phase lasts until the
next `phase` line. Samples are assigned to phases by `ts`.

## What the report says

Per impl and architecture (columns side by side when both are present): first window to last
window for freezes per minute, freeze ms per minute, audio gap %, loss %, jitter, RTT, NACK and
PLI rates, data-channel p50 and p99, RSS, CPU, threads, FDs; RSS slope in MB/h (least squares after
warmup); stalls outside outage; recovery after each outage; counter regressions (a cumulative
counter going backwards); event counts; every metric per phase. `recover` counts as clean after its
first 15 s. Recovery time is from the end of the outage to the first sample where frames grow
again, so it has the 5 s sampling resolution.

## Rules (`rules.json`)

An impl listed in `gate_impls` fails the run (exit 1) when it breaks one of these; the others are
reported as `breach` without failing. A breach is `last > first * ratio + slack`.

| Key | Default | Rule |
|---|---|---|
| `gate_impls` | `[]` | impls whose breaches fail the run |
| `warmup_min` | 15 | skipped before the first window |
| `window_min` | 20 | window length; `min(window_min, total/4)` on short runs |
| `freeze_rate_ratio_max`, `freeze_rate_abs_slack_per_min` | 2.0, 0.5 | freezes per minute, clean phases |
| `audio_gap_ratio_max`, `audio_gap_abs_slack_pct` | 2.0, 0.5 | audio gap %, clean phases |
| `rss_slope_mb_per_h_max` | 30 | worst process; only judged on runs with at least `rss_slope_min_span_min` (30) minutes after warmup |
| `min_clean_window_min` | 5 | the two drift rules above are judged only when each window holds this much clean-phase time; a few minutes of data cannot tell a rate from one event |
| `stall_max_s` | 10 | longest stall outside outage |
| `recover_max_s` | 10 | slowest recovery after an outage; a track that never recovers fails |
