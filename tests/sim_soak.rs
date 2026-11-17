//! A seeded, simulated-time soak: two peers hold a call (audio, video and a data channel both
//! ways) through generated network weather (loss, bursts, bandwidth caps, outages) for minutes
//! of virtual time that pass in seconds of real time. Every failure names its seed, and the seed
//! replays the same network and the same sending pattern.
//!
//! Knobs (environment): `SIM_SOAK_SEEDS` how many seeds to run (default 8; 2 in a debug build,
//! where the crypto is an order of magnitude slower),
//! `SIM_SOAK_SEED_START` the first of them (default 1), `SIM_SOAK_SEED` to run just that one
//! seed, `SIM_SOAK_MINUTES` the virtual minutes of weather (default 20; 5 in a debug build; the
//! schedule ends with the phase that completes it, so a run can overshoot by a few minutes).
//!
//! What a seed draws is the network weather and the sizes and timings of what is sent. The
//! library draws its own randomness (certificates, ICE credentials, DTLS and SCTP initial values)
//! from the operating system, which a seed does not control.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::netsim::{self, Path, Phase};
use common::sim::{Rng, Sim};
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_keyframe_request_forwarding, register_default_interceptors,
};
use rtc::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_VP8, MediaEngine,
};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use rtc::statistics::StatsSelector;

const AUDIO_INTERVAL: Duration = Duration::from_millis(20);
/// 30 frames per second.
const VIDEO_INTERVAL: Duration = Duration::from_nanos(33_333_333);
const DATA_INTERVAL: Duration = Duration::from_millis(250);
const TICK: Duration = Duration::from_millis(50);
const KEYFRAME_INTERVAL: Duration = Duration::from_secs(10);
/// A receiver gives the retransmission of a missing packet this long before it decides the
/// picture is broken and asks for a keyframe.
const NACK_WAIT: Duration = Duration::from_millis(500);
/// A receiver that decoded nothing for this long asks for a keyframe.
const STALL: Duration = Duration::from_secs(1);
const PLI_INTERVAL: Duration = Duration::from_secs(1);

/// After an outage ends, audio is back within this: SRTP needs nothing but the
/// next datagram, so only the path delay and jitter stand in the way.
const AUDIO_BACK: Duration = Duration::from_secs(3);
/// Video is back (a complete keyframe decoded) within this: the receiver's next keyframe request
/// goes out within `PLI_INTERVAL`, the keyframe follows within a round trip, and a keyframe of
/// up to 25 packets crosses a clean path in well under a second.
const VIDEO_BACK: Duration = Duration::from_secs(5);
/// The data channel delivers again within this. Over 80 seeds SCTP resumed within about 3.3 s of
/// the path coming back after outages of 5, 30 and 60 s; this leaves three times that.
const DATA_BACK: Duration = Duration::from_secs(10);
/// How far behind the newest packet a delivered one may be: reordering and NACK retransmissions
/// span a round trip, far below this many packets at the rates sent.
const REORDER_DEPTH: u64 = 1000;

/// With the default 25 s failed timeout (5 s to disconnected, then 25 s) a 30 s outage ends the
/// ICE session for good; like the real soak's abuse profile, the peers here are patient enough
/// for the longest outage drawn (120 s), so every outage must be survivable.
const PATIENT_ICE_FAILED: Duration = Duration::from_secs(240);

const AUDIO_SSRC: [u32; 2] = [0xA000_0001, 0xB000_0001];
const VIDEO_SSRC: [u32; 2] = [0xA000_0002, 0xB000_0002];

type Check<T = ()> = Result<T, String>;

/// Tracks one RTP stream as the application sees it: sequence numbers and timestamps unwrapped,
/// duplicates and stale packets caught, wraps counted.
#[derive(Default)]
struct Stream {
    first_seq: Option<i64>,
    high_seq: i64,
    first_ts: i64,
    high_ts: i64,
    seen: BTreeSet<i64>,
    last_at: Option<Duration>,
    duplicates: u64,
}

impl Stream {
    /// Records an arrival and returns the unwrapped sequence number and the previous highest.
    ///
    /// A second copy of a packet is an error unless `retransmitted` (a NACK answer can land after
    /// the original that was merely late): then it is counted and `None` is returned.
    fn accept(
        &mut self,
        seq: u16,
        ts: u32,
        at: Duration,
        retransmitted: bool,
    ) -> Check<Option<(i64, Option<i64>)>> {
        self.last_at = Some(at);
        let Some(_) = self.first_seq else {
            let base = i64::from(seq) + (1 << 16);
            self.first_seq = Some(base);
            self.high_seq = base;
            self.first_ts = i64::from(ts) + (1 << 32);
            self.high_ts = self.first_ts;
            self.seen.insert(base);
            return Ok(Some((base, None)));
        };
        let ext = self.high_seq + i64::from(seq.wrapping_sub(self.high_seq as u16) as i16);
        let previous = self.high_seq;
        if previous - ext > REORDER_DEPTH as i64 {
            return Err(format!(
                "packet {ext} delivered {} behind the newest {previous}",
                previous - ext
            ));
        }
        if !self.seen.insert(ext) {
            if retransmitted {
                self.duplicates += 1;
                return Ok(None);
            }
            return Err(format!("packet {ext} (seq {seq}) delivered twice"));
        }
        if ext > previous {
            self.high_seq = ext;
            let ts_ext = self.high_ts + i64::from(ts.wrapping_sub(self.high_ts as u32) as i32);
            self.high_ts = self.high_ts.max(ts_ext);
        }
        if self.seen.len() > 4 * REORDER_DEPTH as usize {
            self.seen = self.seen.split_off(&(self.high_seq - REORDER_DEPTH as i64));
        }
        Ok(Some((ext, Some(previous))))
    }

    fn seq_wraps(&self) -> i64 {
        self.first_seq
            .map_or(0, |first| (self.high_seq >> 16) - (first >> 16))
    }

    fn ts_wraps(&self) -> i64 {
        (self.high_ts >> 32) - (self.first_ts >> 32)
    }
}

/// One video frame being put back together.
struct Frame {
    key: bool,
    count: u8,
    got: BTreeSet<u8>,
    first_ext: Option<i64>,
    started: Duration,
}

/// What a peer receives from the other one, and the part of a decoder's behaviour that matters:
/// it needs a keyframe first, and again whenever a packet is lost for good.
#[derive(Default)]
struct Receiver {
    audio: Stream,
    video: Stream,
    holes: BTreeMap<i64, Duration>,
    frames: BTreeMap<u32, Frame>,
    synced: bool,
    last_decoded: Option<Duration>,
    last_pli: Option<Duration>,
    video_receiver: Option<RTCRtpReceiverId>,
    keyframes_decoded: u64,
    data_next: u64,
    last_data: Option<Duration>,
}

/// What a peer sends, as the plan the seed drew.
struct Sender {
    audio: RTCRtpSenderId,
    video: RTCRtpSenderId,
    audio_pt: u8,
    video_pt: u8,
    audio_seq0: u16,
    audio_ts0: u32,
    video_seq0: u16,
    video_ts0: u32,
    audio_count: u32,
    video_packets: u32,
    frame: u32,
    key_wanted: bool,
    last_key: Option<Duration>,
    data_sent: u64,
    rng: Rng,
}

struct Node {
    sender: Sender,
    recv: Receiver,
    data_channel: Option<rtc::data_channel::RTCDataChannelId>,
    events: usize,
    stats_entries: usize,
}

/// Something the weather owes the call once an outage has ended.
struct Deadline {
    at: Duration,
    outage_end: Duration,
    what: &'static str,
}

fn peer() -> RTCPeerConnection {
    let mut media = MediaEngine::default();
    media.register_default_codecs().unwrap();
    let registry = configure_keyframe_request_forwarding(
        register_default_interceptors(Registry::new(), &mut media).unwrap(),
    );
    RTCPeerConnectionBuilder::new()
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_ice_timeouts(None, Some(PATIENT_ICE_FAILED), None)
                .build(),
        )
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .build(Instant::now())
        .unwrap()
}

fn track(kind: RtpCodecKind, ssrc: u32) -> MediaStreamTrack {
    let (mime_type, clock_rate, channels, id) = match kind {
        RtpCodecKind::Audio => (MIME_TYPE_OPUS, 48000, 2, "audio"),
        _ => (MIME_TYPE_VP8, 90000, 0, "video"),
    };
    MediaStreamTrack::new(
        "stream".to_owned(),
        id.to_owned(),
        id.to_owned(),
        kind,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: mime_type.to_owned(),
                clock_rate,
                channels,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }],
    )
}

fn payload_type(pc: &mut RTCPeerConnection, sender: RTCRtpSenderId) -> u8 {
    pc.rtp_sender(sender)
        .unwrap()
        .get_parameters()
        .rtp_parameters
        .codecs
        .first()
        .map(|c| c.payload_type)
        .unwrap()
}

struct Soak {
    seed: u64,
    sim: Sim,
    t0: Instant,
    path: Path,
    nodes: [Node; 2],
    deadlines: Vec<Deadline>,
    stats_baseline: Option<usize>,
    /// The phase in force, for failure messages.
    phase: String,
}

impl Soak {
    fn elapsed(&self) -> Duration {
        self.sim.now - self.t0
    }

    fn fail<T>(&self, what: impl std::fmt::Display) -> Check<T> {
        Err(format!(
            "seed={} at {:?} in {}: {what}",
            self.seed,
            self.elapsed(),
            self.phase
        ))
    }

    fn new(seed: u64) -> Check<Soak> {
        let mut rng = Rng::new(seed);
        let path = Path::draw(&mut rng);
        let mut sim = Sim::new(peer(), peer());
        let mut ids = vec![];
        for (i, is_a) in [(0, true), (1, false)] {
            let pc = &mut sim.side(is_a).pc;
            let audio = pc
                .add_track(track(RtpCodecKind::Audio, AUDIO_SSRC[i]))
                .unwrap();
            let video = pc
                .add_track(track(RtpCodecKind::Video, VIDEO_SSRC[i]))
                .unwrap();
            ids.push((audio, video));
        }
        sim.a.pc.create_data_channel("chat", None).unwrap();
        sim.link_a_to_b = Some(path.link(rng.next_u64()));
        sim.link_b_to_a = Some(path.link(rng.next_u64()));
        sim.negotiate(true);
        let connected = sim.run_until(Duration::from_secs(10), |s| {
            s.a.connected() && s.b.connected()
        });
        let t0 = sim.now;
        let mut nodes = vec![];
        for (i, is_a) in [(0, true), (1, false)] {
            let (audio, video) = ids[i];
            let pc = &mut sim.side(is_a).pc;
            // Sequence numbers start a few hundred packets and timestamps a few seconds short
            // of their wrap, as the real soak does, so every run crosses both.
            nodes.push(Node {
                sender: Sender {
                    audio,
                    video,
                    audio_pt: payload_type(pc, audio),
                    video_pt: payload_type(pc, video),
                    audio_seq0: 65535 - rng.range(100, 1000) as u16,
                    audio_ts0: u32::MAX - rng.range(1, 20) as u32 * 48_000,
                    video_seq0: 65535 - rng.range(100, 1000) as u16,
                    video_ts0: u32::MAX - rng.range(1, 20) as u32 * 90_000,
                    audio_count: 0,
                    video_packets: 0,
                    frame: 0,
                    key_wanted: true,
                    last_key: None,
                    data_sent: 0,
                    rng: Rng::new(rng.next_u64()),
                },
                recv: Receiver::default(),
                data_channel: None,
                events: 0,
                stats_entries: 0,
            });
        }
        let [a, b] = <[Node; 2]>::try_from(nodes).ok().unwrap();
        let mut soak = Soak {
            seed,
            sim,
            t0,
            path,
            nodes: [a, b],
            deadlines: vec![],
            stats_baseline: None,
            phase: String::new(),
        };
        if !connected {
            return soak.fail("the call did not connect within 10 s");
        }
        soak.settle_start()?;
        Ok(soak)
    }

    /// Waits for both data channels to open.
    fn settle_start(&mut self) -> Check {
        for _ in 0..200 {
            self.sim.run_for(TICK);
            self.pump()?;
            if self.nodes.iter().all(|n| n.data_channel.is_some()) {
                return Ok(());
            }
        }
        self.fail("the data channel did not open within 10 s")
    }

    /// Drains what the peers reported and delivered since the last call, checking as it goes.
    fn pump(&mut self) -> Check {
        let at = self.elapsed();
        for i in 0..2 {
            let side = self.sim.side(i == 0);
            let events = std::mem::take(&mut side.events);
            let messages = std::mem::take(&mut side.messages);
            for event in events {
                if !matches!(
                    event,
                    RTCPeerConnectionEvent::OnDataChannel(
                        RTCDataChannelEvent::OnBufferedAmountLow(_)
                            | RTCDataChannelEvent::OnBufferedAmountHigh(_)
                    )
                ) {
                    self.nodes[i].events += 1;
                }
                match event {
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init))
                        if init.ssrc == VIDEO_SSRC[1 - i] =>
                    {
                        self.nodes[i].recv.video_receiver = Some(init.receiver_id);
                    }
                    RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                        self.nodes[i].data_channel = Some(id);
                    }
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state)
                        if matches!(
                            state,
                            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
                        ) =>
                    {
                        return self.fail(format!("node {i} went {state:?} "));
                    }
                    _ => {}
                }
            }
            for message in messages {
                match message {
                    RTCMessage::RtpPacket(_, packet) => {
                        if let Err(e) = self.receive_rtp(i, &packet, at) {
                            return self.fail(format!("node {i}: {e}"));
                        }
                    }
                    RTCMessage::RtcpPacket(_, packets) => {
                        let asked = packets.iter().any(|p| {
                            p.as_any()
                                .downcast_ref::<PictureLossIndication>()
                                .is_some_and(|pli| pli.media_ssrc == VIDEO_SSRC[i])
                        });
                        if asked {
                            self.nodes[i].sender.key_wanted = true;
                        }
                    }
                    RTCMessage::DataChannelMessage(_, message) => {
                        let text = String::from_utf8_lossy(&message.data).into_owned();
                        let node = &mut self.nodes[i];
                        if text.parse::<u64>() != Ok(node.recv.data_next) {
                            let expected = node.recv.data_next;
                            return self.fail(format!(
                                "node {i} data channel delivered {text:?}, expected {expected} (reliable and ordered)"
                            ));
                        }
                        node.recv.data_next += 1;
                        node.recv.last_data = Some(at);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn receive_rtp(&mut self, i: usize, packet: &rtp::packet::Packet, at: Duration) -> Check {
        let from = &self.nodes[1 - i].sender;
        let (audio_seq0, audio_ts0) = (from.audio_seq0, from.audio_ts0);
        let (video_seq0, video_ts0) = (from.video_seq0, from.video_ts0);
        let header = &packet.header;
        let recv = &mut self.nodes[i].recv;
        if header.ssrc == AUDIO_SSRC[1 - i] {
            recv.audio
                .accept(header.sequence_number, header.timestamp, at, false)?;
            let counter = u32::from_be_bytes(packet.payload[..4].try_into().unwrap());
            if header.sequence_number != audio_seq0.wrapping_add(counter as u16)
                || header.timestamp != audio_ts0.wrapping_add(counter.wrapping_mul(960))
            {
                return Err(format!(
                    "audio packet {counter} arrived with another header"
                ));
            }
            return Ok(());
        }
        if header.ssrc != VIDEO_SSRC[1 - i] {
            return Err(format!("a packet of unknown ssrc {}", header.ssrc));
        }
        let Some((ext, previous)) =
            recv.video
                .accept(header.sequence_number, header.timestamp, at, true)?
        else {
            return Ok(());
        };
        let p = &packet.payload;
        let (key, index, count) = (p[0] == 1, p[1], p[2]);
        let frame_no = u32::from_be_bytes(p[3..7].try_into().unwrap());
        let counter = u32::from_be_bytes(p[7..11].try_into().unwrap());
        if header.sequence_number != video_seq0.wrapping_add(counter as u16)
            || header.timestamp != video_ts0.wrapping_add(frame_no.wrapping_mul(3000))
        {
            return Err(format!(
                "video packet {counter} arrived with another header"
            ));
        }
        match previous {
            Some(previous) if ext > previous => {
                for missing in previous + 1..ext {
                    recv.holes.insert(missing, at);
                }
            }
            _ => {
                recv.holes.remove(&ext);
            }
        }
        let frame = recv.frames.entry(frame_no).or_insert_with(|| Frame {
            key,
            count,
            got: BTreeSet::new(),
            first_ext: None,
            started: at,
        });
        frame.got.insert(index);
        if index == 0 {
            frame.first_ext = Some(ext);
        }
        if frame.got.len() == usize::from(frame.count) {
            let first = frame.first_ext.unwrap();
            let key = frame.key;
            recv.frames.remove(&frame_no);
            if key {
                recv.synced = true;
                recv.keyframes_decoded += 1;
                recv.holes.retain(|&h, _| h > first);
            }
            if recv.synced {
                recv.last_decoded = Some(at);
            }
        }
        Ok(())
    }

    fn send_audio(&mut self, i: usize) -> Check {
        let now = self.sim.now;
        let s = &mut self.nodes[i].sender;
        let n = s.audio_count;
        s.audio_count += 1;
        let mut payload = vec![0u8; 60];
        payload[..4].copy_from_slice(&n.to_be_bytes());
        let packet = rtp::packet::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: s.audio_pt,
                sequence_number: s.audio_seq0.wrapping_add(n as u16),
                timestamp: s.audio_ts0.wrapping_add(n.wrapping_mul(960)),
                ssrc: AUDIO_SSRC[i],
                ..Default::default()
            },
            payload: payload.into(),
        };
        let id = s.audio;
        match self
            .sim
            .side(i == 0)
            .pc
            .rtp_sender(id)
            .unwrap()
            .write_rtp(now, packet)
        {
            Ok(()) => Ok(()),
            Err(e) => self.fail(format!("node {i} could not send audio: {e}")),
        }
    }

    /// One frame: a keyframe of 15 to 25 packets when one was asked for (or is due), else a delta
    /// frame of 2 to 4, each packet 600 to 1100 bytes, about 0.6 Mbit/s all told.
    fn send_video(&mut self, i: usize) -> Check {
        let now = self.sim.now;
        let at = self.elapsed();
        let s = &mut self.nodes[i].sender;
        let since_key = s.last_key.map(|t| at - t);
        let due = since_key.is_none_or(|d| d >= KEYFRAME_INTERVAL);
        let asked = s.key_wanted && since_key.is_none_or(|d| d >= Duration::from_millis(300));
        let key = due || asked;
        if key {
            s.key_wanted = false;
            s.last_key = Some(at);
        }
        let count = if key {
            s.rng.range(15, 25)
        } else {
            s.rng.range(2, 4)
        } as u8;
        let frame = s.frame;
        s.frame += 1;
        let mut packets = vec![];
        for index in 0..count {
            let counter = s.video_packets;
            s.video_packets += 1;
            let mut payload = vec![0u8; s.rng.range(600, 1100) as usize];
            payload[0] = u8::from(key);
            payload[1] = index;
            payload[2] = count;
            payload[3..7].copy_from_slice(&frame.to_be_bytes());
            payload[7..11].copy_from_slice(&counter.to_be_bytes());
            packets.push(rtp::packet::Packet {
                header: rtp::header::Header {
                    version: 2,
                    marker: index + 1 == count,
                    payload_type: s.video_pt,
                    sequence_number: s.video_seq0.wrapping_add(counter as u16),
                    timestamp: s.video_ts0.wrapping_add(frame.wrapping_mul(3000)),
                    ssrc: VIDEO_SSRC[i],
                    ..Default::default()
                },
                payload: payload.into(),
            });
        }
        let id = s.video;
        for packet in packets {
            let sent = self
                .sim
                .side(i == 0)
                .pc
                .rtp_sender(id)
                .unwrap()
                .write_rtp(now, packet);
            if let Err(e) = sent {
                return self.fail(format!("node {i} could not send video: {e}"));
            }
        }
        Ok(())
    }

    fn send_data(&mut self, i: usize) -> Check {
        let now = self.sim.now;
        let node = &mut self.nodes[i];
        let (id, n) = (node.data_channel.unwrap(), node.sender.data_sent);
        node.sender.data_sent += 1;
        let sent = self
            .sim
            .side(i == 0)
            .pc
            .data_channel(id)
            .unwrap()
            .send_text(now, n.to_string());
        match sent {
            Ok(()) => Ok(()),
            Err(e) => self.fail(format!("node {i} could not send data message {n}: {e}")),
        }
    }

    /// What a decoder and its application do on their own clock: give up on packets that never
    /// came, notice a frozen picture, and ask for a keyframe (at most once a second).
    fn housekeeping(&mut self) -> Check {
        let at = self.elapsed();
        let now = self.sim.now;
        for i in 0..2 {
            let recv = &mut self.nodes[i].recv;
            let before = recv.holes.len();
            recv.holes.retain(|_, born| at - *born < NACK_WAIT);
            let mut broken = recv.holes.len() < before;
            broken |= recv.synced && recv.last_decoded.is_some_and(|t| at - t > STALL);
            recv.frames
                .retain(|_, f| at - f.started < Duration::from_secs(2));
            if broken {
                recv.synced = false;
            }
            if recv.synced || recv.last_pli.is_some_and(|t| at - t < PLI_INTERVAL) {
                continue;
            }
            let Some(receiver) = recv.video_receiver else {
                continue;
            };
            recv.last_pli = Some(at);
            let pli = PictureLossIndication {
                sender_ssrc: 0,
                media_ssrc: VIDEO_SSRC[1 - i],
            };
            let sent = self
                .sim
                .side(i == 0)
                .pc
                .rtp_receiver(receiver)
                .unwrap()
                .write_rtcp(now, vec![Box::new(pli)]);
            if let Err(e) = sent {
                return self.fail(format!("node {i} could not send a keyframe request: {e}"));
            }
        }
        Ok(())
    }

    fn check_deadlines(&mut self) -> Check {
        let at = self.elapsed();
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.deadlines)
            .into_iter()
            .partition(|d| d.at <= at);
        self.deadlines = later;
        for d in due {
            for i in 0..2 {
                let recv = &self.nodes[i].recv;
                let last = match d.what {
                    "audio" => recv.audio.last_at,
                    "video" => recv.last_decoded,
                    _ => recv.last_data,
                };
                if !last.is_some_and(|t| t > d.outage_end) {
                    return self.fail(format!(
                        "node {i} has received no {} since the outage ended at {:?} ({:?} ago; connection {:?}/{:?})",
                        d.what,
                        d.outage_end,
                        at - d.outage_end,
                        self.sim.a.pc.connection_state(),
                        self.sim.b.pc.connection_state(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Nothing may pile up: what is on the wire, the events a peer reports, and the number of
    /// entries in its statistics report (a stream or candidate leaking would grow it).
    fn check_growth(&mut self) -> Check {
        if self.sim.in_flight() > 1000 {
            return self.fail(format!("{} datagrams on the wire", self.sim.in_flight()));
        }
        let now = self.sim.now;
        for i in 0..2 {
            let entries = self
                .sim
                .side(i == 0)
                .pc
                .get_stats(now, StatsSelector::None)
                .len();
            self.nodes[i].stats_entries = entries;
            let baseline = *self.stats_baseline.get_or_insert(entries);
            if entries > baseline * 2 + 16 {
                return self.fail(format!(
                    "node {i} reports {entries} statistics entries (started at {baseline})"
                ));
            }
            if self.nodes[i].events > 200 {
                return self.fail(format!("node {i} reported {} events", self.nodes[i].events));
            }
        }
        Ok(())
    }

    fn set_phase(&mut self, phase: &Phase, start: Duration) {
        self.phase = format!("{phase:?} from {start:?}");
        if let Some(link) = self.sim.link_a_to_b.as_mut() {
            self.path.impair(link, phase.a_to_b);
        }
        if let Some(link) = self.sim.link_b_to_a.as_mut() {
            self.path.impair(link, phase.b_to_a);
        }
        if !phase.is_outage() {
            return;
        }
        let end = start + phase.duration;
        for (what, bound) in [
            ("audio", AUDIO_BACK),
            ("video", VIDEO_BACK),
            ("data", DATA_BACK),
        ] {
            self.deadlines.push(Deadline {
                at: end + bound,
                outage_end: end,
                what,
            });
        }
    }

    fn run(&mut self, phases: &[Phase]) -> Check<Report> {
        let origin = self.elapsed();
        let mut starts = vec![];
        let mut total = origin;
        for phase in phases {
            starts.push(total);
            total += phase.duration;
        }
        let end = total;
        let mut next_phase = 0;
        let (mut audio, mut video, mut data) = (origin, origin, origin);
        let mut tick = origin;
        let mut stats = origin + Duration::from_secs(30);
        let mut outages = 0;
        while self.elapsed() < end {
            let at = self.elapsed();
            if next_phase < phases.len() && at >= starts[next_phase] {
                let phase = phases[next_phase];
                outages += usize::from(phase.is_outage());
                self.set_phase(&phase, starts[next_phase]);
                next_phase += 1;
            }
            if at >= audio {
                audio += AUDIO_INTERVAL;
                for i in 0..2 {
                    self.send_audio(i)?;
                }
            }
            if at >= video {
                video += VIDEO_INTERVAL;
                for i in 0..2 {
                    self.send_video(i)?;
                }
            }
            if at >= data {
                data += DATA_INTERVAL;
                for i in 0..2 {
                    self.send_data(i)?;
                }
            }
            if at >= tick {
                tick += TICK;
                self.housekeeping()?;
                self.check_deadlines()?;
            }
            if at >= stats {
                stats += Duration::from_secs(10);
                self.check_growth()?;
            }
            let upcoming = starts.get(next_phase).copied().unwrap_or(end);
            let next = [audio, video, data, tick, upcoming]
                .into_iter()
                .min()
                .unwrap();
            self.sim.run_for(next.saturating_sub(self.elapsed()));
            self.pump()?;
        }
        self.finish(outages)
    }

    /// The weather has cleared. Sending stops, the data channel catches up, and every stream
    /// must have been alive until the end and have crossed its wraps.
    fn finish(&mut self, outages: usize) -> Check<Report> {
        let at = self.elapsed();
        for i in 0..2 {
            let recv = &self.nodes[i].recv;
            let age = |t: Option<Duration>| t.map_or(Duration::MAX, |t| at - t);
            if age(recv.audio.last_at) > Duration::from_secs(1) {
                return self.fail(format!(
                    "node {i} has heard no audio for {:?} at the end",
                    age(recv.audio.last_at)
                ));
            }
            if age(recv.last_decoded) > Duration::from_secs(3) {
                return self.fail(format!(
                    "node {i} has decoded no video for {:?} at the end",
                    age(recv.last_decoded)
                ));
            }
            if age(recv.last_data) > Duration::from_secs(10) {
                return self.fail(format!(
                    "node {i} has received no data for {:?} at the end",
                    age(recv.last_data)
                ));
            }
        }
        for _ in 0..(20_000 / 50) {
            self.sim.run_for(TICK);
            self.pump()?;
        }
        for i in 0..2 {
            let sent = self.nodes[1 - i].sender.data_sent;
            let got = self.nodes[i].recv.data_next;
            if got != sent {
                return self.fail(format!("node {i} received {got} of the {sent} data messages sent to it, 20 s after the weather cleared"));
            }
            if at > Duration::from_secs(180) {
                let recv = &self.nodes[i].recv;
                for (name, stream) in [("audio", &recv.audio), ("video", &recv.video)] {
                    if stream.seq_wraps() < 1 || stream.ts_wraps() < 1 {
                        return self.fail(format!(
                            "node {i} {name} crossed {} sequence and {} timestamp wraps",
                            stream.seq_wraps(),
                            stream.ts_wraps()
                        ));
                    }
                }
            }
        }
        Ok(Report {
            virtual_time: at,
            outages,
            keyframes: self.nodes[0].recv.keyframes_decoded + self.nodes[1].recv.keyframes_decoded,
        })
    }
}

struct Report {
    virtual_time: Duration,
    outages: usize,
    keyframes: u64,
}

fn run_seed(seed: u64, minutes: u64) -> Check<Report> {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut rng = Rng::new(seed ^ 0x5EED);
        let phases = netsim::schedule(&mut rng, Duration::from_secs(minutes * 60));
        Soak::new(seed)?.run(&phases)
    }));
    outcome.unwrap_or_else(|panic| {
        let what = panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default();
        Err(format!("seed={seed} panicked: {what}"))
    })
}

fn knob(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .map(|v| {
            v.parse()
                .unwrap_or_else(|_| panic!("{name} must be a number, got {v:?}"))
        })
        .unwrap_or(default)
}

#[test]
fn calls_survive_generated_network_weather() {
    let minutes = knob(
        "SIM_SOAK_MINUTES",
        if cfg!(debug_assertions) { 5 } else { 20 },
    );
    let seeds: Vec<u64> = match std::env::var("SIM_SOAK_SEED") {
        Ok(seed) => vec![seed.parse().expect("SIM_SOAK_SEED must be a number")],
        Err(_) => {
            let start = knob("SIM_SOAK_SEED_START", 1);
            (start..start + knob("SIM_SOAK_SEEDS", if cfg!(debug_assertions) { 2 } else { 8 }))
                .collect()
        }
    };
    let next = AtomicU64::new(0);
    let failures = Mutex::new(vec![]);
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..workers.min(seeds.len()) {
            scope.spawn(|| {
                while let Some(&seed) = seeds.get(next.fetch_add(1, Ordering::Relaxed) as usize) {
                    let started = Instant::now();
                    match run_seed(seed, minutes) {
                        Ok(r) => println!(
                            "seed={seed} ok: {:?} virtual, {} outages, {} keyframes decoded, {:?} real",
                            r.virtual_time,
                            r.outages,
                            r.keyframes,
                            started.elapsed()
                        ),
                        Err(e) => {
                            println!("{e}");
                            failures.lock().unwrap().push(e);
                        }
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().unwrap();
    assert!(
        failures.is_empty(),
        "{} of {} seeds failed; replay one with SIM_SOAK_SEED=<n> SIM_SOAK_MINUTES={minutes}:\n{}",
        failures.len(),
        seeds.len(),
        failures.join("\n")
    );
}
