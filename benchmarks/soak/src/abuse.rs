//! The abuse profile of the rtc peer (../README.md, "The abuse profile of the peers"). Mirrors
//! ../go/abuse.go; keep the two in step.
//!
//! Next to the measured call between the two peers (never touched by anything here) each peer runs
//! a victim service that accepts extra peer connections, and three attack workers that open such
//! connections to the other peer or throw datagrams at its media port:
//!
//! * `hostile`: one long-lived connection that carries one attack class after another;
//! * `churn`: many short connections, created and torn down (`conn-churn`, `join-leave`);
//! * `junk`: raw UDP from sockets of its own (`udp-junk`, `stun-flood`, `dtls-junk`).
//!
//! The schedule of every worker comes from the seed alone (`Rng`, the same generator as the pion
//! peer), and every window is an `attack` row in the JSONL.

use crate::stats::Logger;
use crate::{
    AUDIO_LEVEL_URI, Args, Filler, Peer, STOP, build_peer, host_candidate, read_frame, write_frame,
};
use bytes::{Bytes, BytesMut};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::{RTCPeerConnectionState, RTCSignalingState};
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::rtcp;
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtc::rtcp::raw_packet::RawPacket;
use rtc::rtcp::receiver_report::ReceiverReport;
use rtc::rtcp::reception_report::ReceptionReport;
use rtc::rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

type Res<T> = Result<T, Box<dyn std::error::Error>>;

static ABUSE_STOP: AtomicBool = AtomicBool::new(false);
static MADE: AtomicU64 = AtomicU64::new(0);
static CONNECTED: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);

fn stopped() -> bool {
    STOP.load(Ordering::Relaxed) || ABUSE_STOP.load(Ordering::Relaxed)
}

/// splitmix64: the same generator in the pion peer, so one seed is one schedule for both.
pub struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in lo..=hi.
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// True once per `period`; moves the timer on.
fn due(t: &mut Instant, now: Instant, period: Duration) -> bool {
    if *t > now {
        return false;
    }
    *t = now + period;
    true
}

/// Sleeps `d`, or until the run is over.
fn nap(d: Duration, end: Instant) {
    let until = (Instant::now() + d).min(end);
    while !stopped() && Instant::now() < until {
        thread::sleep(ms(50));
    }
}

pub struct Cfg {
    out: String,
    id: String,
    offerer: bool,
    seed: u64,
    listen: String,
    dial: String,
    end: Instant,
    media_ports: Vec<u16>,
    only: Vec<String>,
}

impl Cfg {
    pub fn new(a: &Args, end: Instant, media_ports: Vec<u16>) -> Self {
        let (host, port) = a.signal.rsplit_once(':').unwrap_or(("127.0.0.1", "7100"));
        let port: u16 = port.parse().unwrap_or(7100);
        let offerer = a.role == "offerer";
        let (mine, theirs) = if offerer { (1, 2) } else { (2, 1) };
        Cfg {
            out: a.out.clone(),
            id: a.id.clone(),
            offerer,
            seed: a.seed,
            listen: format!("{host}:{}", port + mine),
            dial: format!("{host}:{}", port + theirs),
            end,
            media_ports,
            only: a.only.clone(),
        }
    }

    fn rng(&self, worker: u64) -> Rng {
        Rng::new(self.seed ^ (if self.offerer { 1u64 } else { 2 }) << 56 ^ worker << 48)
    }

    /// Whether the attack class takes part (all of them unless `--only` names some).
    fn wants(&self, class: &str) -> bool {
        self.only.is_empty() || self.only.iter().any(|c| c == class)
    }

    fn live(&self) -> bool {
        !stopped() && Instant::now() < self.end
    }
}

/// The running workers; `stop` ends them (their open windows get an end row) and waits.
pub struct Abuse(Vec<JoinHandle<()>>);

impl Abuse {
    pub fn stop(self) {
        ABUSE_STOP.store(true, Ordering::Relaxed);
        let give_up = Instant::now() + Duration::from_secs(15);
        for h in self.0 {
            while !h.is_finished() && Instant::now() < give_up {
                thread::sleep(ms(20));
            }
            if h.is_finished() {
                let _ = h.join();
            }
        }
    }
}

pub fn start(cfg: Cfg) -> Abuse {
    let cfg = Arc::new(cfg);
    let mut hs = Vec::new();
    for (name, f) in [
        ("victim", victim_service as fn(Arc<Cfg>)),
        ("hostile", hostile_worker),
        ("churn", churn_worker),
        ("junk", junk_worker),
    ] {
        let c = cfg.clone();
        if let Ok(h) = thread::Builder::new().name(name.into()).spawn(move || f(c)) {
            hs.push(h);
        }
    }
    Abuse(hs)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    RtpJump,
    SsrcChange,
    PliFlood,
    NackFlood,
    BogusRtcp,
    RtpSize,
    RtcpGarbage,
    DcFlood,
    DcOversize,
    RenegoStorm,
    Glare,
    LateAnswer,
}

const HOSTILE: [Mode; 12] = [
    Mode::RtpJump,
    Mode::SsrcChange,
    Mode::PliFlood,
    Mode::NackFlood,
    Mode::BogusRtcp,
    Mode::RtpSize,
    Mode::RtcpGarbage,
    Mode::DcFlood,
    Mode::DcOversize,
    Mode::RenegoStorm,
    Mode::Glare,
    Mode::LateAnswer,
];

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Normal => "normal",
            Mode::RtpJump => "rtp-jump",
            Mode::SsrcChange => "ssrc-change",
            Mode::PliFlood => "pli-flood",
            Mode::NackFlood => "nack-flood",
            Mode::BogusRtcp => "bogus-rtcp",
            Mode::RtpSize => "rtp-size",
            Mode::RtcpGarbage => "rtcp-garbage",
            Mode::DcFlood => "dc-flood",
            Mode::DcOversize => "dc-oversize",
            Mode::RenegoStorm => "renego-storm",
            Mode::Glare => "glare",
            Mode::LateAnswer => "late-answer",
        }
    }

    /// Why this implementation cannot express the attack, if it cannot.
    fn unsupported(self) -> Option<&'static str> {
        None
    }
}

/// One framed control message of an extra connection (the signaling of the session).
#[derive(Serialize, Deserialize)]
struct Msg {
    t: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sdp: Option<RTCSessionDescription>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cands: Vec<RTCIceCandidateInit>,
}

impl Msg {
    fn new(t: &str, sdp: Option<RTCSessionDescription>, cands: Vec<RTCIceCandidateInit>) -> Self {
        Msg {
            t: t.into(),
            sdp,
            cands,
        }
    }
}

struct Out {
    id: RTCRtpSenderId,
    ssrc: u32,
    pt: u8,
    ext_id: Option<u8>,
}

#[derive(Clone, Copy)]
struct Pace {
    seq: u16,
    ts: u32,
}

/// An extra peer connection: audio, video and data both ways, plus whatever the mode does to it.
struct Sess {
    pc: RTCPeerConnection,
    sock: UdpSocket,
    local: SocketAddr,
    host: RTCIceCandidateInit,
    tcp: TcpStream,
    rx: Receiver<Msg>,
    polite: bool,
    cand_added: bool,
    connected: bool,
    dead: bool,
    mode: Mode,
    rng: Rng,
    fill: Filler,
    audio_id: RTCRtpSenderId,
    video_id: RTCRtpSenderId,
    audio: Option<Out>,
    video: Option<Out>,
    alt_ssrc: u32,
    use_alt: bool,
    a: Pace,
    v: Pace,
    frames: u64,
    t_audio: Instant,
    t_video: Instant,
    t_fast: Instant,
    t_slow: Instant,
    rx_video: Option<RTCRtpReceiverId>,
    rx_ssrc: u32,
    rx_seq: u16,
    dc_id: rtc::data_channel::RTCDataChannelId,
    dc_open: bool,
    extra_dcs: Vec<rtc::data_channel::RTCDataChannelId>,
    extra: Vec<RTCRtpSenderId>,
    pending: Option<Instant>,
    offer: Option<RTCSessionDescription>,
    old_offer: Option<RTCSessionDescription>,
    answer: Option<RTCSessionDescription>,
    old_answer: Option<RTCSessionDescription>,
    /// ok and refused counts of what the mode sent: rtp, rtcp, data channel, session descriptions.
    tally: [u64; 8],
}

impl Sess {
    fn new(tcp: TcpStream, polite: bool, seed: u64) -> Res<Sess> {
        tcp.set_nodelay(true)?;
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        let local = sock.local_addr()?;
        let host = host_candidate(local)?;
        let Peer {
            pc,
            audio,
            video,
            dc,
        } = build_peer(true, false)?;
        let mut rd = tcp.try_clone()?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            while let Ok(m) = read_frame::<Msg>(&mut rd) {
                if tx.send(m).is_err() {
                    break;
                }
            }
        });
        let now = Instant::now();
        Ok(Sess {
            pc,
            sock,
            local,
            host,
            tcp,
            rx,
            polite,
            cand_added: false,
            connected: false,
            dead: false,
            mode: Mode::Normal,
            rng: Rng::new(seed),
            fill: Filler(seed | 1),
            audio_id: audio,
            video_id: video,
            audio: None,
            video: None,
            alt_ssrc: 0,
            use_alt: false,
            a: Pace {
                seq: 1000,
                ts: 5000,
            },
            v: Pace {
                seq: 2000,
                ts: 9000,
            },
            frames: 0,
            t_audio: now,
            t_video: now,
            t_fast: now,
            t_slow: now,
            rx_video: None,
            rx_ssrc: 0,
            rx_seq: 0,
            dc_id: dc,
            dc_open: false,
            extra_dcs: Vec::new(),
            extra: Vec::new(),
            pending: None,
            offer: None,
            old_offer: None,
            answer: None,
            old_answer: None,
            tally: [0; 8],
        })
    }

    fn count(&mut self, kind: usize, ok: bool) {
        self.tally[kind * 2 + usize::from(!ok)] += 1;
    }

    /// What the window sent, as `kind ok/refused`, and the counts reset.
    fn take_tally(&mut self) -> String {
        let t = std::mem::take(&mut self.tally);
        format!(
            "rtp {}/{} rtcp {}/{} dc {}/{} sdp {}/{}",
            t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]
        )
    }

    fn send(&mut self, m: Msg) {
        if write_frame(&mut self.tcp, &m).is_err() {
            self.dead = true;
        }
    }

    fn state(&self) -> RTCSignalingState {
        self.pc.signaling_state()
    }

    /// Creates an offer, applies it and sends it. False when the library refuses.
    fn send_offer(&mut self, now: Instant, first: bool) -> bool {
        let Ok(offer) = self.pc.create_offer(None) else {
            self.count(3, false);
            return false;
        };
        let applied = self.pc.set_local_description(now, offer.clone());
        self.count(3, applied.is_ok());
        if applied.is_err() {
            return false;
        }
        let mut cands = Vec::new();
        if first {
            let _ = self.pc.add_local_candidate(self.host.clone());
            self.cand_added = true;
            cands.push(self.host.clone());
        }
        self.old_offer = self.offer.replace(offer.clone());
        self.pending = Some(now);
        self.send(Msg::new("offer", Some(offer), cands));
        true
    }

    fn rollback(&mut self, now: Instant) {
        if let Ok(rb) = RTCSessionDescription::rollback(None) {
            let _ = self.pc.set_local_description(now, rb);
        }
        self.pending = None;
    }

    fn on_msg(&mut self, now: Instant, m: Msg) {
        match (m.t.as_str(), m.sdp) {
            ("offer", Some(sd)) => {
                if self.polite && self.state() == RTCSignalingState::HaveLocalOffer {
                    self.rollback(now);
                }
                let applied = self.pc.set_remote_description(now, sd);
                self.count(3, applied.is_ok());
                if applied.is_err() {
                    return;
                }
                let first = !self.cand_added;
                if first {
                    let _ = self.pc.add_local_candidate(self.host.clone());
                    self.cand_added = true;
                }
                for c in m.cands {
                    let _ = self.pc.add_remote_candidate(c);
                }
                let Ok(answer) = self.pc.create_answer(None) else {
                    return;
                };
                if self.pc.set_local_description(now, answer.clone()).is_err() {
                    return;
                }
                self.old_answer = self.answer.replace(answer.clone());
                let cands = if first {
                    vec![self.host.clone()]
                } else {
                    Vec::new()
                };
                self.send(Msg::new("answer", Some(answer), cands));
            }
            ("answer", Some(sd)) => {
                let ok = self.pc.set_remote_description(now, sd).is_ok();
                self.count(3, ok);
                for c in m.cands {
                    let _ = self.pc.add_remote_candidate(c);
                }
                if ok {
                    self.pending = None;
                }
                if ok && self.mode == Mode::LateAnswer {
                    // The answer of the round before, and the offer of the round before again (once per
                    // round: the answer to that offer is refused, so it does not start another).
                    if let Some(old) = self.old_answer.clone() {
                        let ok = self.pc.set_remote_description(now, old).is_ok();
                        self.count(3, ok);
                    }
                    if let Some(old) = self.old_offer.clone() {
                        self.send(Msg::new("offer", Some(old), Vec::new()));
                    }
                }
            }
            ("glare", _) => {
                let _ = self.send_offer(now, false);
            }
            ("bye", _) => self.dead = true,
            _ => {}
        }
    }

    fn drain_msgs(&mut self, now: Instant) {
        loop {
            match self.rx.try_recv() {
                Ok(m) => self.on_msg(now, m),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.dead = true;
                    break;
                }
            }
        }
        if self
            .pending
            .is_some_and(|t| now > t + Duration::from_secs(3))
        {
            self.rollback(now);
        }
    }

    fn on_event(&mut self, event: RTCPeerConnectionEvent) {
        match event {
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(s) => match s {
                RTCPeerConnectionState::Connected => self.connected = true,
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => self.dead = true,
                _ => {}
            },
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(_)) => {
                self.dc_open = true
            }
            RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                if let Some(r) = self.pc.rtp_receiver(init.receiver_id)
                    && r.track().kind() == RtpCodecKind::Video
                {
                    self.rx_video = Some(init.receiver_id);
                }
            }
            _ => {}
        }
    }

    fn senders_ready(&mut self) {
        if self.audio.is_some() || !self.connected {
            return;
        }
        let read = |pc: &mut RTCPeerConnection, id: RTCRtpSenderId| -> Option<(Out, Vec<u32>)> {
            let mut s = pc.rtp_sender(id)?;
            let ssrcs: Vec<u32> = s.track().ssrcs().collect();
            let p = &s.get_parameters().rtp_parameters;
            let ext_id = p
                .header_extensions
                .iter()
                .find(|e| e.uri == AUDIO_LEVEL_URI)
                .map(|e| e.id as u8);
            Some((
                Out {
                    id,
                    ssrc: *ssrcs.first()?,
                    pt: p.codecs.first()?.payload_type,
                    ext_id,
                },
                ssrcs,
            ))
        };
        let (Some((a, _)), Some((v, vs))) = (
            read(&mut self.pc, self.audio_id),
            read(&mut self.pc, self.video_id),
        ) else {
            return;
        };
        self.alt_ssrc = vs.get(1).copied().unwrap_or(v.ssrc);
        self.audio = Some(a);
        self.video = Some(v);
    }

    /// Sends one RTP packet of `len` payload bytes and moves the sequence number on.
    fn rtp(&mut self, now: Instant, audio: bool, len: usize, marker: bool) {
        let Some(o) = (if audio { &self.audio } else { &self.video }).as_ref() else {
            return;
        };
        let (id, pt, ext) = (o.id, o.pt, o.ext_id);
        let ssrc = if !audio && self.use_alt {
            self.alt_ssrc
        } else {
            o.ssrc
        };
        let pace = if audio { &mut self.a } else { &mut self.v };
        let (seq, ts) = (pace.seq, pace.ts);
        pace.seq = pace.seq.wrapping_add(1);
        let mut p = rtc::rtp::Packet::default();
        p.header.version = 2;
        p.header.marker = marker;
        p.header.payload_type = pt;
        p.header.sequence_number = seq;
        p.header.timestamp = ts;
        p.header.ssrc = ssrc;
        p.payload = Bytes::from(self.fill.bytes(len));
        if audio && let Some(ext) = ext {
            let _ = p.header.set_extension(ext, Bytes::from(vec![0x80 | 40]));
        }
        if let Some(mut s) = self.pc.rtp_sender(id) {
            let ok = s.write_rtp(now, p).is_ok();
            self.count(0, ok);
        }
    }

    fn media(&mut self, now: Instant) {
        self.senders_ready();
        if self.audio.is_none() {
            return;
        }
        let sizes: [usize; 7] = [0, 1, 2, 100, 1188, 1400, 1450];
        while self.t_audio <= now {
            let len = if self.mode == Mode::RtpSize {
                sizes[self.rng.next() as usize % 7]
            } else {
                80
            };
            self.rtp(now, true, len, false);
            self.a.ts = self.a.ts.wrapping_add(960);
            self.t_audio += ms(20);
        }
        while self.t_video <= now {
            let key = self.frames.is_multiple_of(120);
            let n = if key { 6 } else { 1 };
            for i in 0..n {
                let len = if self.mode == Mode::RtpSize {
                    sizes[self.rng.next() as usize % 7]
                } else {
                    1000
                };
                self.rtp(now, false, len, i == n - 1);
            }
            self.frames += 1;
            self.v.ts = self.v.ts.wrapping_add(3000);
            self.t_video += Duration::from_nanos(33_333_333);
        }
    }

    fn victim_ssrc(&mut self) -> u32 {
        if self.rx_ssrc != 0 {
            return self.rx_ssrc;
        }
        if let Some(rid) = self.rx_video
            && let Some(r) = self.pc.rtp_receiver(rid)
            && let Some(s) = r.track().ssrcs().last()
        {
            self.rx_ssrc = s;
        }
        if self.rx_ssrc == 0 {
            self.rng.next() as u32
        } else {
            self.rx_ssrc
        }
    }

    /// Sends the packets as one compound datagram.
    fn write_rtcp(&mut self, now: Instant, pkts: Vec<Box<dyn rtcp::Packet>>) {
        let ok = if let Some(rid) = self.rx_video
            && let Some(mut r) = self.pc.rtp_receiver(rid)
        {
            r.write_rtcp(now, pkts).is_ok()
        } else if let Some(id) = self.video.as_ref().map(|v| v.id)
            && let Some(mut s) = self.pc.rtp_sender(id)
        {
            s.write_rtcp(now, pkts).is_ok()
        } else {
            false
        };
        self.count(1, ok);
    }

    fn dc_send(&mut self, now: Instant, len: usize) {
        let b = self.fill.bytes(len);
        if self.dc_open
            && let Some(mut dc) = self.pc.data_channel(self.dc_id)
        {
            let ok = dc.send(now, BytesMut::from(&b[..])).is_ok();
            self.count(2, ok);
        }
    }

    fn toggle_track(&mut self) {
        if self.extra.len() < 4 && (self.extra.is_empty() || self.rng.next().is_multiple_of(2)) {
            let ssrc = self.rng.next() as u32 | 1;
            let track = MediaStreamTrack::new(
                "soak".to_owned(),
                format!("extra-{ssrc}"),
                format!("extra-{ssrc}"),
                RtpCodecKind::Audio,
                vec![RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        ssrc: Some(ssrc),
                        ..Default::default()
                    },
                    codec: RTCRtpCodec {
                        mime_type:
                            rtc::peer_connection::configuration::media_engine::MIME_TYPE_OPUS
                                .to_owned(),
                        clock_rate: 48_000,
                        channels: 2,
                        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
                        rtcp_feedback: vec![],
                    },
                    ..Default::default()
                }],
            );
            if let Ok(id) = self.pc.add_track(track) {
                self.extra.push(id);
            }
        } else if let Some(id) = self.extra.pop() {
            let _ = self.pc.remove_track(id);
        }
    }

    /// What the mode does to the connection, on top of the normal media.
    fn hostile(&mut self, now: Instant) {
        match self.mode {
            Mode::Normal | Mode::RtpSize => {}
            Mode::RtpJump => {
                if due(&mut self.t_slow, now, ms(200)) {
                    let (j, t) = (
                        self.rng.range(1, 30_000) as u16,
                        self.rng.next() as u32 >> 1,
                    );
                    match self.rng.next() % 4 {
                        0 => {
                            self.v.seq = self.v.seq.wrapping_add(j);
                            self.v.ts = self.v.ts.wrapping_add(t);
                        }
                        1 => {
                            self.v.seq = self.v.seq.wrapping_sub(j);
                            self.v.ts = self.v.ts.wrapping_sub(t);
                        }
                        2 => {
                            self.a.seq = self.a.seq.wrapping_sub(j);
                            self.a.ts = self.a.ts.wrapping_add(t);
                        }
                        _ => self.v.seq = self.v.seq.wrapping_sub(1), // a duplicate
                    }
                }
            }
            Mode::SsrcChange => {
                if due(&mut self.t_slow, now, ms(1500)) {
                    self.use_alt = !self.use_alt;
                    if self.rng.next().is_multiple_of(2) {
                        self.v = Pace {
                            seq: self.rng.next() as u16,
                            ts: self.rng.next() as u32,
                        };
                    }
                }
            }
            Mode::PliFlood => {
                if due(&mut self.t_fast, now, ms(10)) {
                    let (media_ssrc, sender_ssrc) = (self.victim_ssrc(), self.rng.next() as u32);
                    let pkts: Vec<Box<dyn rtcp::Packet>> = (0..30)
                        .map(|_| {
                            Box::new(PictureLossIndication {
                                sender_ssrc,
                                media_ssrc,
                            }) as Box<dyn rtcp::Packet>
                        })
                        .collect();
                    self.write_rtcp(now, pkts);
                }
            }
            Mode::NackFlood => {
                if due(&mut self.t_fast, now, ms(10)) {
                    let media_ssrc = self.victim_ssrc();
                    let sender_ssrc = self.video.as_ref().map_or(1, |v| v.ssrc);
                    let nacks = (0..10)
                        .map(|i| NackPair {
                            packet_id: if i % 2 == 0 {
                                self.rx_seq.wrapping_sub(self.rng.range(0, 200) as u16)
                            } else {
                                self.rng.next() as u16
                            },
                            lost_packets: 0xFFFF,
                        })
                        .collect();
                    self.write_rtcp(
                        now,
                        vec![Box::new(TransportLayerNack {
                            sender_ssrc,
                            media_ssrc,
                            nacks,
                        })],
                    );
                }
            }
            Mode::BogusRtcp => {
                if due(&mut self.t_fast, now, ms(20)) {
                    let reports = (0..self.rng.range(0, 4))
                        .map(|_| ReceptionReport {
                            ssrc: self.rng.next() as u32,
                            fraction_lost: self.rng.next() as u8,
                            total_lost: self.rng.next() as u32 & 0xFF_FFFF,
                            last_sequence_number: self.rng.next() as u32,
                            jitter: self.rng.next() as u32,
                            last_sender_report: self.rng.next() as u32,
                            delay: self.rng.next() as u32,
                        })
                        .collect();
                    let bitrates = [0.0f32, 1.0, 64_000.0, 1e12, f32::MAX];
                    let ssrcs = (0..self.rng.range(0, 5))
                        .map(|_| self.rng.next() as u32)
                        .collect();
                    let mut twcc = vec![0x8F, 205, 0, 0];
                    let n = 8 + 4 * self.rng.range(0, 8) as usize;
                    twcc.extend(self.rng.bytes(n));
                    let words = (twcc.len() / 4 - 1) as u16;
                    twcc[2..4].copy_from_slice(&words.to_be_bytes());
                    let (a, b) = (self.rng.next() as u32, self.rng.next() as u32);
                    let pick = bitrates[self.rng.next() as usize % bitrates.len()];
                    // one datagram each: a packet the library cannot marshal must not take the others with it
                    self.write_rtcp(
                        now,
                        vec![Box::new(ReceiverReport {
                            ssrc: a,
                            reports,
                            ..Default::default()
                        })],
                    );
                    self.write_rtcp(
                        now,
                        vec![Box::new(ReceiverEstimatedMaximumBitrate {
                            sender_ssrc: b,
                            bitrate: pick,
                            ssrcs,
                        })],
                    );
                    self.write_rtcp(now, vec![Box::new(RawPacket(Bytes::from(twcc)))]);
                }
            }
            Mode::RtcpGarbage => {
                if due(&mut self.t_fast, now, ms(10)) {
                    let g = rtcp_garbage(&mut self.rng);
                    self.write_rtcp(now, vec![Box::new(RawPacket(Bytes::from(g)))]);
                }
            }
            Mode::DcFlood => {
                if due(&mut self.t_fast, now, ms(10)) {
                    for _ in 0..50 {
                        let n = self.rng.range(8, 64) as usize;
                        self.dc_send(now, n);
                    }
                }
                if self.connected && due(&mut self.t_slow, now, ms(500)) {
                    for _ in 0..5 {
                        if let Ok(dc) = self.pc.create_data_channel("storm", None) {
                            let id = dc.id();
                            self.extra_dcs.push(id);
                        }
                    }
                    while self.extra_dcs.len() > 30 {
                        let id = self.extra_dcs.remove(0);
                        if let Some(mut dc) = self.pc.data_channel(id) {
                            let _ = dc.close();
                        }
                    }
                }
            }
            Mode::DcOversize => {
                if due(&mut self.t_slow, now, ms(500)) {
                    let sizes = [
                        1024,
                        16_384,
                        65_535,
                        65_536,
                        131_072,
                        262_143,
                        262_144,
                        262_145,
                        1 << 20,
                    ];
                    let n = sizes[self.rng.next() as usize % sizes.len()];
                    self.dc_send(now, n);
                }
            }
            Mode::RenegoStorm | Mode::LateAnswer => {
                if self.pending.is_none() && due(&mut self.t_slow, now, ms(400)) {
                    self.toggle_track();
                    self.send_offer(now, false);
                }
            }
            Mode::Glare => {
                if self.pending.is_none() && due(&mut self.t_slow, now, ms(1000)) {
                    // The other side's offer is on its way while ours is pending.
                    self.send(Msg::new("glare", None, Vec::new()));
                    self.send_offer(now, false);
                }
            }
        }
    }

    /// Everything the pc has to say, then wait for a datagram (at most `wait`).
    fn pump(&mut self, now: Instant, wait: Duration, buf: &mut [u8]) {
        while let Some(e) = self.pc.poll_event() {
            self.on_event(e);
        }
        while let Some(TaggedRTCMessage { message, .. }) = self.pc.poll_read() {
            if let RTCMessage::RtpPacket(_, p) = message
                && p.header.payload_type == 96
            {
                self.rx_ssrc = p.header.ssrc;
                self.rx_seq = p.header.sequence_number;
            }
        }
        while let Some(m) = self.pc.poll_write() {
            let _ = self.sock.send_to(&m.message, m.transport.peer_addr);
        }
        let mut deadline = now + wait;
        if let Some(t) = self.pc.poll_timeout() {
            if t <= now {
                let _ = self.pc.handle_timeout(now);
                return;
            }
            deadline = deadline.min(t);
        }
        let _ = self.sock.set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_micros(500)),
        ));
        if let Ok((n, peer_addr)) = self.sock.recv_from(buf) {
            let _ = self.pc.handle_read(TaggedBytesMut {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr: self.local,
                    peer_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message: BytesMut::from(&buf[..n]),
            });
        }
    }

    /// Runs the connection in `mode` until `until`, the end of the run, or (with `until_connected`)
    /// the moment it is connected. A connection that fails or is closed by the other side is dead.
    fn run(&mut self, until: Instant, mode: Mode, until_connected: bool) {
        self.mode = mode;
        let mut buf = vec![0u8; 2048];
        loop {
            let now = Instant::now();
            if self.dead || stopped() || now >= until || (until_connected && self.connected) {
                return;
            }
            self.drain_msgs(now);
            self.media(now);
            self.hostile(now);
            self.pump(now, ms(5), &mut buf);
        }
    }

    fn close(mut self) {
        self.send(Msg::new("bye", None, Vec::new()));
        let _ = self.pc.close();
        let _ = self.tcp.shutdown(std::net::Shutdown::Both);
    }
}

/// An RTCP datagram that is wrong in one way or another.
fn rtcp_garbage(rng: &mut Rng) -> Vec<u8> {
    match rng.next() % 6 {
        0 => {
            let n = rng.range(4, 200) as usize;
            rng.bytes(n)
        }
        1 => {
            // a valid header whose length claims far more than is there
            let mut v = vec![0x80, rng.range(200, 210) as u8, 0xFF, 0xF0];
            v.extend(rng.bytes(12));
            v
        }
        2 => rng.bytes(3), // shorter than a header
        3 => {
            // a real PLI followed by garbage
            let mut v = vec![0x81, 206, 0, 2];
            v.extend(rng.bytes(8));
            let n = rng.range(1, 60) as usize;
            v.extend(rng.bytes(n));
            v
        }
        4 => vec![0; 64],
        _ => vec![0xFF; 64],
    }
}

fn dial(cfg: &Cfg, seed: u64, polite: bool) -> Option<Sess> {
    let addr: SocketAddr = cfg.dial.parse().ok()?;
    let give_up = Instant::now() + Duration::from_secs(30);
    while cfg.live() && Instant::now() < give_up {
        if let Ok(tcp) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
            return Sess::new(tcp, polite, seed).ok();
        }
        thread::sleep(ms(200));
    }
    None
}

/// Opens a connection to the other peer and brings it up; None when it does not connect in time.
fn establish(cfg: &Cfg, seed: u64, wait: Duration) -> Option<Sess> {
    MADE.fetch_add(1, Ordering::Relaxed);
    let Some(mut s) = dial(cfg, seed, false) else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    if !s.send_offer(Instant::now(), true) {
        FAILED.fetch_add(1, Ordering::Relaxed);
        s.close();
        return None;
    }
    s.run(Instant::now() + wait, Mode::Normal, true);
    if !s.connected {
        FAILED.fetch_add(1, Ordering::Relaxed);
        s.close();
        return None;
    }
    CONNECTED.fetch_add(1, Ordering::Relaxed);
    Some(s)
}

fn counters() -> String {
    format!(
        "made={} connected={} failed={}",
        MADE.load(Ordering::Relaxed),
        CONNECTED.load(Ordering::Relaxed),
        FAILED.load(Ordering::Relaxed)
    )
}

/// Accepts the extra connections of the other peer, one thread each.
fn victim_service(cfg: Arc<Cfg>) {
    let Ok(l) = TcpListener::bind(&cfg.listen) else {
        eprintln!("soak-rtc: abuse listener {} unavailable", cfg.listen);
        return;
    };
    let _ = l.set_nonblocking(true);
    let mut rng = cfg.rng(4);
    while !stopped() {
        match l.accept() {
            Ok((tcp, _)) => {
                let _ = tcp.set_nonblocking(false);
                let seed = rng.next();
                thread::spawn(move || {
                    if let Ok(mut s) = Sess::new(tcp, true, seed) {
                        s.run(
                            Instant::now() + Duration::from_secs(24 * 3600),
                            Mode::Normal,
                            false,
                        );
                        s.close();
                    }
                });
            }
            Err(_) => thread::sleep(ms(20)),
        }
    }
}

fn hostile_worker(cfg: Arc<Cfg>) {
    let Ok(mut log) = Logger::open(&cfg.out, &format!("{}-hostile", cfg.id)) else {
        return;
    };
    log.event("seed", &format!("hostile worker seed {}", cfg.seed));
    for m in HOSTILE {
        if let Some(why) = m.unsupported() {
            log.event("attack-unsupported", &format!("{}: {why}", m.name()));
        }
    }
    let modes: Vec<Mode> = HOSTILE
        .into_iter()
        .filter(|m| cfg.wants(m.name()))
        .collect();
    if modes.is_empty() {
        return;
    }
    let mut rng = cfg.rng(0);
    let mut sess: Option<Sess> = None;
    let mut n = 0u64;
    while cfg.live() {
        let idle = ms(rng.range(3000, 8000));
        let mode = modes[rng.next() as usize % modes.len()];
        let dur = ms(rng.range(8000, 20_000));
        let sub = rng.next();
        if sess.is_none() {
            sess = establish(&cfg, sub, Duration::from_secs(20));
            if sess.is_none() {
                nap(Duration::from_secs(2), cfg.end);
                continue;
            }
        }
        let Some(s) = sess.as_mut() else { continue };
        s.rng = Rng::new(sub);
        let _ = s.take_tally();
        s.run((Instant::now() + idle).min(cfg.end), Mode::Normal, false);
        if s.dead {
            if let Some(s) = sess.take() {
                s.close();
            }
            continue;
        }
        if mode.unsupported().is_some() {
            s.run((Instant::now() + dur).min(cfg.end), Mode::Normal, false);
            continue;
        }
        n += 1;
        let id = format!("{}-{}-{n}", cfg.id, mode.name());
        log.attack(
            &id,
            mode.name(),
            "start",
            cfg.seed,
            &format!("hostile connection, {} ms", dur.as_millis()),
        );
        s.run((Instant::now() + dur).min(cfg.end), mode, false);
        let died = if s.dead { "; the connection died" } else { "" };
        let sent = s.take_tally();
        log.attack(&id, mode.name(), "end", cfg.seed, &format!("{sent}{died}"));
        if s.dead
            && let Some(s) = sess.take()
        {
            s.close();
        }
    }
    if let Some(s) = sess {
        s.close();
    }
}

fn churn_worker(cfg: Arc<Cfg>) {
    let Ok(mut log) = Logger::open(&cfg.out, &format!("{}-churn", cfg.id)) else {
        return;
    };
    log.event("seed", &format!("churn worker seed {}", cfg.seed));
    let (conn, quick_ok) = (cfg.wants("conn-churn"), cfg.wants("join-leave"));
    if !conn && !quick_ok {
        return;
    }
    let mut rng = cfg.rng(1);
    let mut n = 0u64;
    while cfg.live() {
        nap(ms(rng.range(1000, 4000)), cfg.end);
        let quick = quick_ok && (!conn || rng.next().is_multiple_of(3));
        let (name, count) = if quick {
            ("join-leave", 20)
        } else {
            ("conn-churn", 8)
        };
        n += 1;
        let id = format!("{}-{name}-{n}", cfg.id);
        log.attack(
            &id,
            name,
            "start",
            cfg.seed,
            &format!("{count} connections"),
        );
        for _ in 0..count {
            if !cfg.live() {
                break;
            }
            let life = if quick {
                ms(rng.range(0, 800))
            } else {
                ms(rng.range(2000, 6000))
            };
            let seed = rng.next();
            if quick {
                // gone before the connection is up, most of the time
                MADE.fetch_add(1, Ordering::Relaxed);
                if let Some(mut s) = dial(&cfg, seed, false) {
                    if s.send_offer(Instant::now(), true) {
                        s.run(Instant::now() + life, Mode::Normal, false);
                    }
                    if s.connected {
                        CONNECTED.fetch_add(1, Ordering::Relaxed);
                    }
                    s.close();
                } else {
                    FAILED.fetch_add(1, Ordering::Relaxed);
                }
            } else if let Some(mut s) = establish(&cfg, seed, Duration::from_secs(10)) {
                s.run((Instant::now() + life).min(cfg.end), Mode::Normal, false);
                s.close();
            }
        }
        log.attack(&id, name, "end", cfg.seed, &counters());
        log.event("churn", &counters());
    }
}

fn junk_worker(cfg: Arc<Cfg>) {
    let Ok(mut log) = Logger::open(&cfg.out, &format!("{}-junk", cfg.id)) else {
        return;
    };
    log.event("seed", &format!("junk worker seed {}", cfg.seed));
    let classes: Vec<&str> = ["udp-junk", "stun-flood", "dtls-junk"]
        .into_iter()
        .filter(|c| cfg.wants(c))
        .collect();
    if classes.is_empty() {
        return;
    }
    let mut rng = cfg.rng(2);
    let mut n = 0u64;
    while cfg.live() {
        let w = junk_window(&mut rng, classes.len());
        nap(ms(w.pause), cfg.end);
        let class = classes[w.class];
        let until = (Instant::now() + ms(w.dur)).min(cfg.end);
        let mut rng = Rng::new(w.sub); // the packets never touch the schedule
        if !cfg.live() {
            break;
        }
        n += 1;
        let id = format!("{}-{class}-{n}", cfg.id);
        log.attack(
            &id,
            class,
            "start",
            cfg.seed,
            "from loopback sockets, about 2000 datagrams/s",
        );
        let targets = &cfg.media_ports;
        let socks: Vec<UdpSocket> = (0..if class == "stun-flood" { 200 } else { 4 })
            .filter_map(|_| UdpSocket::bind("127.0.0.1:0").ok())
            .collect();
        while !targets.is_empty() && !socks.is_empty() && !stopped() && Instant::now() < until {
            for _ in 0..20 {
                let pkt = match class {
                    "stun-flood" => stun_request(&mut rng),
                    "dtls-junk" => dtls_junk(&mut rng),
                    _ => {
                        let n = rng.range(1, 1400) as usize;
                        rng.bytes(n)
                    }
                };
                let s = &socks[rng.next() as usize % socks.len()];
                let port = targets[rng.next() as usize % targets.len()];
                let _ = s.send_to(&pkt, ("127.0.0.1", port));
            }
            thread::sleep(ms(10));
        }
        log.attack(&id, class, "end", cfg.seed, "");
    }
}

/// One junk window as the schedule draws it: the pause before it, the class (an index), how long
/// it lasts, and the seed of its packets. The packets come from their own generator, so the
/// number sent (wall-clock dependent) never shifts a later window.
struct JunkWindow {
    pause: u64,
    class: usize,
    dur: u64,
    sub: u64,
}

fn junk_window(rng: &mut Rng, classes: usize) -> JunkWindow {
    JunkWindow {
        pause: rng.range(5000, 15_000),
        class: rng.next() as usize % classes,
        dur: rng.range(8000, 20_000),
        sub: rng.next(),
    }
}

/// A STUN binding request with a username nobody knows and a made-up integrity attribute.
fn stun_request(rng: &mut Rng) -> Vec<u8> {
    let user = format!("{:08x}:{:08x}", rng.next() as u32, rng.next() as u32);
    let mut attrs = vec![0x00, 0x06, 0x00, user.len() as u8];
    attrs.extend(user.as_bytes());
    attrs.extend([0, 0, 0]); // pad 17 to 20
    attrs.extend([0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x1e, 0xff]); // PRIORITY
    attrs.extend([0x00, 0x08, 0x00, 0x14]); // MESSAGE-INTEGRITY
    attrs.extend(rng.bytes(20));
    let mut v = vec![0x00, 0x01];
    v.extend((attrs.len() as u16).to_be_bytes());
    v.extend([0x21, 0x12, 0xA4, 0x42]);
    v.extend(rng.bytes(12));
    v.extend(attrs);
    v
}

/// A DTLS record that opens like a ClientHello and goes wrong inside (or is another record type).
fn dtls_junk(rng: &mut Rng) -> Vec<u8> {
    let body = {
        let n = rng.range(20, 300) as usize;
        rng.bytes(n)
    };
    let len = &(body.len() as u32).to_be_bytes()[1..];
    let mut hs = vec![1];
    hs.extend(len);
    hs.extend([0, 0, 0, 0, 0]); // message_seq, fragment_offset
    hs.extend(len);
    hs.extend(&body);
    let kind = if rng.next().is_multiple_of(4) {
        [20u8, 21, 23][rng.next() as usize % 3]
    } else {
        22
    };
    let ver = if rng.next().is_multiple_of(2) {
        0xFF
    } else {
        0xFD
    };
    let mut v = vec![kind, 0xFE, ver, 0, 0];
    v.extend(rng.bytes(6));
    v.extend((hs.len() as u16).to_be_bytes());
    v.extend(hs);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(seed: u64, packets: usize) -> Vec<(u64, usize, u64)> {
        let mut rng = Rng::new(seed);
        (0..20)
            .map(|_| {
                let w = junk_window(&mut rng, 3);
                let mut pk = Rng::new(w.sub);
                for _ in 0..packets {
                    dtls_junk(&mut pk);
                    stun_request(&mut pk);
                }
                (w.pause, w.class, w.dur)
            })
            .collect()
    }

    #[test]
    fn junk_schedule_ignores_packet_count() {
        assert_eq!(schedule(7, 0), schedule(7, 5));
        assert_eq!(schedule(7, 5), schedule(7, 300));
        assert_ne!(schedule(7, 0), schedule(8, 0));
    }
}
