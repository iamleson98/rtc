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
        let mut m: Map<String, Value> = fields.as_object().cloned().unwrap_or_default();
        m.insert("ts".into(), json!(now_ms()));
        m.insert("impl".into(), json!("rtc"));
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

    fn threshold(&self) -> f64 {
        if self.intervals.is_empty() {
            return f64::INFINITY;
        }
        let avg = self.intervals.iter().sum::<f64>() / self.intervals.len() as f64;
        (3.0 * avg).max(avg + FREEZE_MIN_EXTRA_MS)
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
            if iv > self.threshold() {
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
            if o > self.threshold() {
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

impl ProcSampler {
    pub fn sample(&mut self) -> Value {
        let (mut rss, mut threads, mut fds, mut cpu_pct) = (0.0, 0u64, 0u64, 0.0);
        let (mut rcv, mut snd) = (0u64, 0u64);
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                let mut f = line.split_whitespace();
                match (f.next(), f.next()) {
                    (Some("VmRSS:"), Some(kb)) => {
                        rss = round1(kb.parse::<f64>().unwrap_or(0.0) / 1024.0)
                    }
                    (Some("Threads:"), Some(n)) => threads = n.parse().unwrap_or(0),
                    _ => {}
                }
            }
        }
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
        json!({"rss_mb": rss, "cpu_pct": cpu_pct, "threads": threads, "fds": fds,
               "udp_rcvbuf_err": rcv, "udp_sndbuf_err": snd})
    }
}
