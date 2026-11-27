//! JSONL logging, per-track receive statistics and process sampling, all in the schema of
//! `../README.md`. Mirrors `../go/{log,recv,proc}.go`; keep the two in step.

use serde_json::{Map, Value, json};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FREEZE_WINDOW: usize = 30;
const AUDIO_GAP_MS: f64 = 60.0;
const STALLED_AFTER_MS: f64 = 2000.0;
const FREEZE_MIN_EXTRA_MS: f64 = 150.0;
const FREEZE_MIN_SAMPLES: usize = 5;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as i64)
}

pub fn round1(v: f64) -> f64 {
    (v * 10.0 + 0.5).floor() / 10.0
}

pub struct Logger {
    file: File,
    pub id: String,
}

impl Logger {
    pub fn open(path: &str, id: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file,
            id: id.to_owned(),
        })
    }

    pub fn emit(&mut self, kind: &str, id: &str, fields: Value) {
        self.emit_as("rtc", kind, id, fields);
    }

    /// An `attack` window edge (README.md, kind `attack`): written as the pseudo implementation `abuse`.
    /// `who` is the hostile connection, never a measured participant, so every measured receiver
    /// counts as innocent in the window.
    pub fn attack(&mut self, id: &str, name: &str, state: &str, seed: u64, detail: &str) {
        let who = format!("{}-abuser", self.id);
        self.emit_as(
            "abuse",
            "attack",
            id,
            json!({"name": name, "state": state, "group": "impaired", "who": [who], "seed": seed, "detail": detail}),
        );
    }

    fn emit_as(&mut self, imp: &str, kind: &str, id: &str, fields: Value) {
        let mut m: Map<String, Value> = fields.as_object().cloned().unwrap_or_default();
        m.insert("ts".into(), json!(now_ms()));
        m.insert("impl".into(), json!(imp));
        m.insert("arch".into(), json!(std::env::consts::ARCH));
        m.insert("kind".into(), json!(kind));
        m.insert("id".into(), json!(id));
        let mut line = Value::Object(m).to_string();
        line.push('\n');
        let _ = self.file.write_all(line.as_bytes());
    }

    pub fn event(&mut self, what: &str, detail: &str) {
        let id = self.id.clone();
        self.emit("event", &id, json!({"what": what, "detail": detail}));
    }
}

/// What one peer put on the wire, by datagram class (RFC 7983 demultiplexing, RTP and RTCP told apart
/// by RFC 5761): packets and bytes, cumulative. DTLS holds the SCTP of the data channel.
#[derive(Default)]
pub struct TxCounts {
    counts: [(u64, u64); 5],
}

const TX_CLASSES: [&str; 5] = ["rtp", "rtcp", "dtls", "stun", "other"];

impl TxCounts {
    pub fn add(&mut self, d: &[u8]) {
        let class = match d.first() {
            Some(0..=3) => 3,
            Some(20..=63) => 2,
            Some(128..=191) => match d.get(1) {
                Some(192..=223) => 1,
                _ => 0,
            },
            _ => 4,
        };
        self.counts[class].0 += 1;
        self.counts[class].1 += d.len() as u64;
    }

    pub fn fields(&self) -> Value {
        let mut m = Map::new();
        for (name, (pkts, bytes)) in TX_CLASSES.iter().zip(self.counts) {
            m.insert(format!("{name}_pkts"), json!(pkts));
            m.insert(format!("{name}_bytes"), json!(bytes));
        }
        Value::Object(m)
    }
}

/// Nearest-rank percentile of an unsorted slice; `null` when empty.
pub fn percentile(xs: &[f64], p: f64) -> Value {
    if xs.is_empty() {
        return Value::Null;
    }
    let mut s = xs.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let i = ((s.len() as f64 * p / 100.0 + 0.999_999) as usize).clamp(1, s.len()) - 1;
    json!(round1(s[i]))
}

/// Cumulative counters of one received track (README.md, kind `recv`).
pub struct RecvStats {
    pub media: &'static str,
    clock: f64, // RTP clock rate in kHz
    started: bool,
    base_ext: u32,
    max_ext: u32,
    cycles: u32,
    last_ts: u32,
    ts_wraps: u32,
    packets: u64,
    frames: u64,
    freezes: u64,
    freeze_ms: f64,
    audio_gap: f64,
    jitter_ticks: f64,
    last_arrival: Option<Instant>,
    last_frame: Option<Instant>,
    intervals: Vec<f64>,
    open_added: f64,
    open_freeze: bool,
    stall_seen: bool,
    last_pli: Option<Instant>,
}

impl RecvStats {
    pub fn new(media: &'static str, clock_rate: u32) -> Self {
        Self {
            media,
            clock: clock_rate as f64 / 1000.0,
            started: false,
            base_ext: 0,
            max_ext: 0,
            cycles: 0,
            last_ts: 0,
            ts_wraps: 0,
            packets: 0,
            frames: 0,
            freezes: 0,
            freeze_ms: 0.0,
            audio_gap: 0.0,
            jitter_ticks: 0.0,
            last_arrival: None,
            last_frame: None,
            intervals: Vec::new(),
            open_added: 0.0,
            open_freeze: false,
            stall_seen: false,
            last_pli: None,
        }
    }

    /// The freeze test of webrtc-stats `freezeCount` as Chrome applies it
    /// (video/video_quality_observer2.cc, `OnRenderedFrame`): the gap joins the window of the last
    /// 30 frame intervals first, freeze gaps included, and counts once that window holds five
    /// intervals and the gap is at least max(3 x average, average + 150 ms), the average rounded
    /// down to a whole millisecond. `go/recv.go` does the same.
    fn is_freeze(&self, gap: f64) -> bool {
        let earlier = &self.intervals[self.intervals.len().saturating_sub(FREEZE_WINDOW - 1)..];
        let n = earlier.len() + 1;
        if n < FREEZE_MIN_SAMPLES {
            return false;
        }
        let avg = ((earlier.iter().sum::<f64>() + gap) / n as f64).floor();
        gap >= (3.0 * avg).max(avg + FREEZE_MIN_EXTRA_MS)
    }

    /// Counts one received packet. Returns true when the track just came out of a freeze and a
    /// keyframe should be requested (at most once a second), as a decoder would.
    pub fn on_packet(
        &mut self,
        log: &mut Logger,
        now: Instant,
        seq: u16,
        ts: u32,
        marker: bool,
    ) -> bool {
        let mut pli = false;
        self.packets += 1;
        let mut newest = false;
        if !self.started {
            self.started = true;
            newest = true;
            self.base_ext = seq as u32;
            self.max_ext = seq as u32;
            self.last_ts = ts;
        } else {
            let d = seq.wrapping_sub(self.max_ext as u16) as i16;
            if d > 0 {
                newest = true;
                if seq < self.max_ext as u16 {
                    self.cycles += 1;
                    log.event(
                        "wrap",
                        &format!("recv {} seq wrap #{}", self.media, self.cycles),
                    );
                }
                self.max_ext += d as u32;
            }
        }
        if newest {
            if ts < self.last_ts && (ts.wrapping_sub(self.last_ts) as i32) > 0 {
                self.ts_wraps += 1;
                log.event(
                    "wrap",
                    &format!("recv {} ts wrap #{}", self.media, self.ts_wraps),
                );
            }
            if let Some(prev) = self.last_arrival
                && (self.media == "audio" || ts != self.last_ts)
            {
                let arrival = now.duration_since(prev).as_secs_f64() * 1000.0 * self.clock;
                let dev = (arrival - ts.wrapping_sub(self.last_ts) as i32 as f64).abs();
                self.jitter_ticks += (dev - self.jitter_ticks) / 16.0;
            }
            self.last_ts = ts;
        }
        if self.media == "audio" {
            self.frames += 1;
            if let Some(prev) = self.last_arrival {
                let g = now.duration_since(prev).as_secs_f64() * 1000.0;
                if g > AUDIO_GAP_MS {
                    self.audio_gap += g - self.open_added;
                }
            }
            self.open_added = 0.0;
        } else if marker {
            self.frames += 1;
            if newest
                && self.frame_done(now)
                && self
                    .last_pli
                    .is_none_or(|t| now.duration_since(t) > Duration::from_secs(1))
            {
                self.last_pli = Some(now);
                pli = true;
            }
        }
        if let Some(prev) = self.last_arrival
            && now.duration_since(prev).as_secs_f64() * 1000.0 > STALLED_AFTER_MS
        {
            self.stall_seen = true;
        }
        self.last_arrival = Some(now);
        pli
    }

    fn frame_done(&mut self, now: Instant) -> bool {
        let mut froze = false;
        if let Some(prev) = self.last_frame {
            let iv = now.duration_since(prev).as_secs_f64() * 1000.0;
            if self.is_freeze(iv) {
                froze = true;
                if !self.open_freeze {
                    self.freezes += 1;
                }
                self.freeze_ms += iv - self.open_added;
            }
            self.intervals.push(iv);
            if self.intervals.len() > FREEZE_WINDOW {
                self.intervals.remove(0);
            }
        }
        self.open_added = 0.0;
        self.open_freeze = false;
        self.last_frame = Some(now);
        froze
    }

    /// Closes the gaps still open at `now` and returns the recv line fields.
    pub fn snapshot(&mut self, now: Instant, nack: u32, pli: u32, rtt: Value) -> Value {
        if self.media == "audio"
            && let Some(prev) = self.last_arrival
        {
            let o = now.duration_since(prev).as_secs_f64() * 1000.0;
            if o > AUDIO_GAP_MS {
                self.audio_gap += o - self.open_added;
                self.open_added = o;
            }
        }
        if self.media == "video"
            && let Some(prev) = self.last_frame
        {
            let o = now.duration_since(prev).as_secs_f64() * 1000.0;
            if self.is_freeze(o) {
                if !self.open_freeze {
                    self.freezes += 1;
                    self.open_freeze = true;
                }
                self.freeze_ms += o - self.open_added;
                self.open_added = o;
            }
        }
        let expected = (self.max_ext - self.base_ext) as u64 + 1;
        let lost = if self.started {
            expected.saturating_sub(self.packets)
        } else {
            0
        };
        // Stalled: no media for more than 2 s at some point since the previous report.
        let open_stall = self
            .last_arrival
            .is_some_and(|a| now.duration_since(a).as_secs_f64() * 1000.0 > STALLED_AFTER_MS);
        let stalled = self.started && (self.stall_seen || open_stall);
        self.stall_seen = false;
        json!({
            "media": self.media, "group": "impaired", "frames": self.frames, "freezes": self.freezes,
            "freeze_ms": self.freeze_ms as i64, "packets": self.packets, "lost": lost, "nack": nack,
            "pli": pli, "jitter_ms": round1(self.jitter_ticks / self.clock), "rtt_ms": rtt,
            "audio_gap_ms": self.audio_gap as i64, "stalled": stalled,
        })
    }
}

/// Reads this process's resource use from /proc (zeros where /proc is missing).
#[derive(Default)]
pub struct ProcSampler {
    last: Option<(f64, Instant)>,
}

/// Prefix of the threads the abuse generators run on. Go's abusers are goroutines, which
/// `Threads:` never counts, so these are left out of the peer's thread count to keep it fair.
pub const ABUSE_THREAD_PREFIX: &str = "abuse-";

fn thread_names() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(d) = std::fs::read_dir("/proc/self/task") {
        for e in d.flatten() {
            let comm = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default();
            names.push(comm.trim_end().to_string());
        }
    }
    names
}

/// Threads of the peer itself: every thread whose name does not start with the abuse prefix.
fn peer_threads(names: &[String]) -> u64 {
    names
        .iter()
        .filter(|n| !n.starts_with(ABUSE_THREAD_PREFIX))
        .count() as u64
}

impl ProcSampler {
    pub fn sample(&mut self) -> Value {
        let (mut rss, mut rss_anon, mut rss_file) = (0.0, 0.0, 0.0);
        let (mut fds, mut cpu_pct) = (0u64, 0.0);
        let (mut rcv, mut snd) = (0u64, 0u64);
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                let mut f = line.split_whitespace();
                match (f.next(), f.next()) {
                    (Some("VmRSS:"), Some(kb)) => {
                        rss = round1(kb.parse::<f64>().unwrap_or(0.0) / 1024.0)
                    }
                    (Some("RssAnon:"), Some(kb)) => {
                        rss_anon = round1(kb.parse::<f64>().unwrap_or(0.0) / 1024.0)
                    }
                    (Some("RssFile:"), Some(kb)) => {
                        rss_file = round1(kb.parse::<f64>().unwrap_or(0.0) / 1024.0)
                    }
                    _ => {}
                }
            }
        }
        let threads = peer_threads(&thread_names());
        if let Ok(d) = std::fs::read_dir("/proc/self/fd") {
            fds = d.count() as u64;
        }
        if let Ok(s) = std::fs::read_to_string("/proc/self/stat")
            && let Some(i) = s.rfind(')')
        {
            let f: Vec<&str> = s[i + 1..].split_whitespace().collect();
            if f.len() > 13 {
                let t = (f[11].parse::<f64>().unwrap_or(0.0) + f[12].parse::<f64>().unwrap_or(0.0))
                    / 100.0;
                let now = Instant::now();
                if let Some((prev, at)) = self.last {
                    cpu_pct = round1((t - prev) / now.duration_since(at).as_secs_f64() * 100.0);
                }
                self.last = Some((t, now));
            }
        }
        if let Ok(s) = std::fs::read_to_string("/proc/net/snmp") {
            let mut head: Option<Vec<&str>> = None;
            for line in s.lines().filter(|l| l.starts_with("Udp:")) {
                let f: Vec<&str> = line.split_whitespace().collect();
                match &head {
                    None => head = Some(f),
                    Some(h) => {
                        for (name, v) in h.iter().zip(&f) {
                            match *name {
                                "RcvbufErrors" => rcv = v.parse().unwrap_or(0),
                                "SndbufErrors" => snd = v.parse().unwrap_or(0),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        // The host's load next to the process's own CPU: a loaded host is not a fair rig.
        let load1 = std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok());
        let cpus = std::thread::available_parallelism().map_or(0, |n| n.get());
        let (live, peak) = crate::heap::take();
        let mb = |b: usize| round1(b as f64 / 1048576.0);
        json!({"rss_mb": rss, "rss_anon_mb": rss_anon, "rss_file_mb": rss_file,
               "heap_live_mb": mb(live), "heap_peak_mb": mb(peak), "cpu_pct": cpu_pct, "threads": threads, "fds": fds,
               "udp_rcvbuf_err": rcv, "udp_sndbuf_err": snd, "load1": load1, "cpus": cpus})
    }
}

#[cfg(test)]
mod thread_count_tests {
    use super::*;

    #[test]
    fn abuse_threads_are_not_counted() {
        let names: Vec<String> = [
            "soak-rtc",
            "tokio-runtime-w",
            "abuse-victim",
            "abuse-reader",
            "abuse-sess",
        ]
        .iter()
        .map(|n| n.to_string())
        .collect();
        assert_eq!(peer_threads(&names), 2);
        assert_eq!(peer_threads(&[]), 0);
    }
}

#[cfg(test)]
mod freeze_tests {
    use super::*;

    /// Feeds one frame per gap (ms) and returns the freezes counted.
    fn freezes_of(gaps: &[u64]) -> u64 {
        let mut r = RecvStats::new("video", 90_000);
        let mut now = Instant::now();
        r.frame_done(now);
        for g in gaps {
            now += Duration::from_millis(*g);
            r.frame_done(now);
        }
        r.freezes
    }

    #[test]
    fn a_gap_needs_five_intervals_before_it_can_freeze() {
        assert_eq!(freezes_of(&[33, 33, 33, 33, 500]), 1); // four earlier and the gap: five
        assert_eq!(freezes_of(&[33, 33, 33, 500]), 0); // three earlier and the gap: too few
    }

    #[test]
    fn the_gap_counts_in_its_own_average() {
        let mut steady = vec![40u64; 29];
        steady.push(194); // average 45 with the gap in it: 194 < 45 + 150
        assert_eq!(freezes_of(&steady), 0);
        steady[29] = 196; // 196 >= 195
        assert_eq!(freezes_of(&steady), 1);
    }

    #[test]
    fn freeze_gaps_stay_in_the_average() {
        let mut series = vec![33u64; 29];
        series.push(600); // a freeze
        series.push(190); // 57 is the average with the freeze in the window: 190 < 207
        assert_eq!(freezes_of(&series), 1);
    }

    #[test]
    fn the_window_keeps_thirty_intervals() {
        let mut series = vec![200u64; 30]; // a slow stream: 200 ms is its normal
        series.extend([33; 30]); // the slow intervals have left the window
        series.push(190); // 29 intervals of 33 and the gap: 190 >= 38 + 150; a longer window would not freeze
        assert_eq!(freezes_of(&series), 1);
    }
}
