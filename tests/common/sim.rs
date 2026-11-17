//! A deterministic in-memory network for two sans-I/O peer connections: datagrams cross
//! instantly, time is virtual and advances only to the next deadline, so a whole ICE + DTLS +
//! SCTP/SRTP session runs in milliseconds with no sockets and no sleeping.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::rtp_transceiver::RTCRtpSenderId;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};

/// Decides, per datagram, whether the network loses it: `(sent by a, datagram)`.
pub type DropFilter = Box<dyn FnMut(bool, &[u8]) -> bool>;

/// One peer and what it has reported so far.
pub struct Side {
    pub pc: RTCPeerConnection,
    pub addr: SocketAddr,
    /// Every event, in order, until drained by the test.
    pub events: Vec<RTCPeerConnectionEvent>,
    /// Every inbound message (RTP, RTCP, data channel), in order.
    pub messages: Vec<RTCMessage>,
    /// The next RTP sequence number per SSRC for [`Sim::send_video`], so successive calls keep
    /// counting (a repeat would be dropped by SRTP replay protection).
    pub next_seq: std::collections::HashMap<u32, u16>,
}

impl Side {
    pub fn connected(&self) -> bool {
        self.pc.connection_state() == RTCPeerConnectionState::Connected
    }
}

/// A small deterministic generator (xorshift64*), so a seed replays the same network.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        // SplitMix64 spreads nearby seeds apart, and the state must never be zero.
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Rng((z ^ (z >> 31)) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `[0, 1)`.
    pub fn chance(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in `[low, high]`.
    pub fn range(&mut self, low: u64, high: u64) -> u64 {
        low + self.next_u64() % (high - low + 1)
    }
}

/// Two-state burst loss (Gilbert-Elliott): the link moves between a good state that loses
/// nothing and a bad state that loses `loss_bad` of the datagrams, so losses come in runs.
#[derive(Clone, Copy)]
pub struct GilbertElliott {
    /// Chance per datagram of going from good to bad.
    pub to_bad: f64,
    /// Chance per datagram of going from bad to good; `1 / to_good` is the mean burst length.
    pub to_good: f64,
    pub loss_bad: f64,
}

/// A one-way bottleneck: datagrams queue behind each other, each taking `size / rate` to leave,
/// and arrive `delay` after they left. A datagram that would wait longer than `max_queue` in the
/// queue is dropped (tail drop), and `loss` drops a fraction at random first.
pub struct Link {
    pub bits_per_second: u64,
    pub delay: Duration,
    pub max_queue: Duration,
    /// Fraction of datagrams lost before they reach the queue, from the link's own generator.
    pub loss: f64,
    /// Bursty loss on top of `loss`.
    pub burst: Option<GilbertElliott>,
    /// Each datagram arrives up to this much later than `delay`, drawn uniformly; datagrams
    /// that draw different values overtake each other, which is how jitter reorders.
    pub jitter: Duration,
    /// Fraction of datagrams held back by `reorder_hold` on top of the jitter.
    pub reorder: f64,
    pub reorder_hold: Duration,
    /// While set the path is dead: every datagram handed to the link is lost.
    pub outage: bool,
    in_bad_state: bool,
    free_at: Option<Instant>,
    rng: Rng,
}

impl Link {
    pub fn new(bits_per_second: u64, delay: Duration, max_queue: Duration) -> Link {
        Link {
            bits_per_second,
            delay,
            max_queue,
            loss: 0.0,
            burst: None,
            jitter: Duration::ZERO,
            reorder: 0.0,
            reorder_hold: Duration::ZERO,
            outage: false,
            in_bad_state: false,
            free_at: None,
            rng: Rng::new(0),
        }
    }

    /// The same link with its generator seeded, so the losses and delays it draws replay.
    pub fn seeded(mut self, seed: u64) -> Link {
        self.rng = Rng::new(seed);
        self
    }

    fn lost_to_burst(&mut self) -> bool {
        let Some(ge) = self.burst else {
            return false;
        };
        let flip = if self.in_bad_state {
            ge.to_good
        } else {
            ge.to_bad
        };
        if self.rng.chance() < flip {
            self.in_bad_state = !self.in_bad_state;
        }
        self.in_bad_state && self.rng.chance() < ge.loss_bad
    }

    /// When a datagram of `len` bytes handed over at `now` arrives, or `None` if it is dropped.
    fn carry(&mut self, now: Instant, len: usize) -> Option<Instant> {
        if self.outage {
            return None;
        }
        if self.loss > 0.0 && self.rng.chance() < self.loss {
            return None;
        }
        if self.lost_to_burst() {
            return None;
        }
        let start = self.free_at.map_or(now, |t| t.max(now));
        if start - now > self.max_queue {
            return None;
        }
        let serialise = Duration::from_secs_f64(len as f64 * 8.0 / self.bits_per_second as f64);
        self.free_at = Some(start + serialise);
        let mut arrival = start + serialise + self.delay;
        if !self.jitter.is_zero() {
            arrival += self.jitter.mul_f64(self.rng.chance());
        }
        if self.reorder > 0.0 && self.rng.chance() < self.reorder {
            arrival += self.reorder_hold;
        }
        Some(arrival)
    }
}

struct InFlight {
    arrival: Instant,
    from_a: bool,
    datagram: Vec<u8>,
}

pub struct Sim {
    pub a: Side,
    pub b: Side,
    pub now: Instant,
    candidates_exchanged: bool,
    /// The bottleneck from `a` to `b` and from `b` to `a`; `None` delivers instantly.
    pub link_a_to_b: Option<Link>,
    pub link_b_to_a: Option<Link>,
    in_flight: Vec<InFlight>,
    /// While set, every datagram is dropped (a dead network path, as pion's vnet chunk filter).
    pub blackhole: bool,
    /// Called with `(sent by a, datagram)` for every datagram; returning `true` drops it.
    pub drop_if: Option<DropFilter>,
}

fn host_candidate(addr: SocketAddr) -> RTCIceCandidateInit {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .expect("a host candidate");
    RTCIceCandidate::from(&candidate)
        .to_json()
        .expect("candidate json")
}

impl Sim {
    pub fn new(a: RTCPeerConnection, b: RTCPeerConnection) -> Sim {
        Sim {
            a: Side {
                pc: a,
                addr: "10.0.0.1:5000".parse().unwrap(),
                events: vec![],
                messages: vec![],
                next_seq: Default::default(),
            },
            b: Side {
                pc: b,
                addr: "10.0.0.2:5000".parse().unwrap(),
                events: vec![],
                messages: vec![],
                next_seq: Default::default(),
            },
            now: Instant::now(),
            candidates_exchanged: false,
            link_a_to_b: None,
            link_b_to_a: None,
            in_flight: vec![],
            blackhole: false,
            drop_if: None,
        }
    }

    /// A full offer/answer exchange from `a` to `b` (or `b` to `a`), then the candidates the
    /// first time, then ICE, DTLS and SCTP run for up to a virtual second.
    pub fn negotiate(&mut self, a_offers: bool) {
        self.negotiate_with(a_offers, false);
    }

    /// A full offer/answer exchange from `a` to `b` and the candidates, without running the
    /// network afterwards.
    pub fn negotiate_without_waiting(&mut self) {
        self.negotiate_edited_inner(true, false, |sdp| sdp, false);
    }

    /// Like [`negotiate`](Self::negotiate); with `ice_restart` the offer restarts ICE and both
    /// sides learn each other's host candidate again for the new generation.
    pub fn negotiate_with(&mut self, a_offers: bool, ice_restart: bool) {
        self.negotiate_edited(a_offers, ice_restart, |sdp| sdp);
    }

    /// Like [`negotiate_with`](Self::negotiate_with), delivering the offer to the answerer after
    /// `edit_offer` rewrote its text (the offerer keeps the original as its local description).
    pub fn negotiate_edited(
        &mut self,
        a_offers: bool,
        ice_restart: bool,
        edit_offer: impl FnOnce(String) -> String,
    ) {
        self.negotiate_edited_inner(a_offers, ice_restart, edit_offer, true);
    }

    fn negotiate_edited_inner(
        &mut self,
        a_offers: bool,
        ice_restart: bool,
        edit_offer: impl FnOnce(String) -> String,
        run: bool,
    ) {
        let now = self.now;
        {
            let (offerer, answerer) = if a_offers {
                (&mut self.a, &mut self.b)
            } else {
                (&mut self.b, &mut self.a)
            };
            let options =
                ice_restart.then_some(rtc::peer_connection::configuration::RTCOfferOptions {
                    ice_restart: true,
                });
            let offer = offerer.pc.create_offer(options).expect("create_offer");
            offerer
                .pc
                .set_local_description(now, offer.clone())
                .expect("set local offer");
            let delivered = RTCSessionDescription::offer(edit_offer(offer.sdp.clone()))
                .expect("the edited offer parses");
            answerer
                .pc
                .set_remote_description(now, delivered)
                .expect("set remote offer");
            let answer = answerer.pc.create_answer(None).expect("create_answer");
            answerer
                .pc
                .set_local_description(now, answer.clone())
                .expect("set local answer");
            offerer
                .pc
                .set_remote_description(now, answer)
                .expect("set remote answer");
        }
        if !self.candidates_exchanged || ice_restart {
            self.exchange_candidates_now();
            if run {
                self.run_for(Duration::from_secs(1));
            }
        } else if run {
            self.run_for(Duration::from_secs(1));
        }
    }

    /// Tells each side the other's host candidate and lets ICE, DTLS and SCTP run for a virtual
    /// second. For a test that applied an offer and answer by hand.
    pub fn exchange_candidates(&mut self) {
        self.exchange_candidates_now();
        self.run_for(Duration::from_secs(1));
    }

    fn exchange_candidates_now(&mut self) {
        self.candidates_exchanged = true;
        let (ca, cb) = (host_candidate(self.a.addr), host_candidate(self.b.addr));
        self.a.pc.add_local_candidate(ca.clone()).unwrap();
        self.b.pc.add_local_candidate(cb.clone()).unwrap();
        self.a.pc.add_remote_candidate(cb).unwrap();
        self.b.pc.add_remote_candidate(ca).unwrap();
    }

    fn deliver(&mut self, from_a: bool, datagram: &[u8]) {
        let (src, dst) = if from_a {
            (&self.a, &mut self.b)
        } else {
            (&self.b, &mut self.a)
        };
        let _ = dst.pc.handle_read(TaggedBytesMut {
            now: self.now,
            transport: TransportContext {
                local_addr: dst.addr,
                peer_addr: src.addr,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(datagram),
        });
    }

    /// Moves datagrams, events and timers until nothing is left to do right now.
    fn settle(&mut self) {
        for _ in 0..10_000 {
            let mut moved = false;
            let now = self.now;
            if self.in_flight.iter().any(|f| f.arrival <= now) {
                let (mut due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.in_flight)
                    .into_iter()
                    .partition(|f| f.arrival <= now);
                self.in_flight = later;
                due.sort_by_key(|f| f.arrival);
                for f in due {
                    moved = true;
                    self.deliver(f.from_a, &f.datagram);
                }
            }
            for from_a in [true, false] {
                loop {
                    let (src, dst) = if from_a {
                        (&mut self.a, &mut self.b)
                    } else {
                        (&mut self.b, &mut self.a)
                    };
                    let Some(msg) = src.pc.poll_write() else {
                        break;
                    };
                    moved = true;
                    // Datagrams for an address the other side does not own go nowhere.
                    if self.blackhole || msg.transport.peer_addr != dst.addr {
                        continue;
                    }
                    if let Some(drop_if) = self.drop_if.as_mut()
                        && drop_if(from_a, &msg.message)
                    {
                        continue;
                    }
                    let link = if from_a {
                        self.link_a_to_b.as_mut()
                    } else {
                        self.link_b_to_a.as_mut()
                    };
                    if let Some(link) = link {
                        if let Some(arrival) = link.carry(self.now, msg.message.len()) {
                            self.in_flight.push(InFlight {
                                arrival,
                                from_a,
                                datagram: msg.message.to_vec(),
                            });
                        }
                        continue;
                    }
                    self.deliver(from_a, &msg.message);
                }
            }
            for side in [&mut self.a, &mut self.b] {
                while let Some(event) = side.pc.poll_event() {
                    moved = true;
                    side.events.push(event);
                }
                while let Some(TaggedRTCMessage { message, .. }) = side.pc.poll_read() {
                    moved = true;
                    side.messages.push(message);
                }
            }
            if !moved {
                return;
            }
        }
        panic!("the simulated network never went quiet");
    }

    /// Runs the network for `span` of virtual time, firing each side's timers when due.
    pub fn run_for(&mut self, span: Duration) {
        let end = self.now + span;
        let mut stalled = 0u32;
        loop {
            self.settle();
            let next = [
                self.a.pc.poll_timeout(),
                self.b.pc.poll_timeout(),
                self.in_flight.iter().map(|f| f.arrival).min(),
            ]
            .into_iter()
            .flatten()
            .min();
            match next {
                Some(t) if t <= end => {
                    if t <= self.now {
                        stalled += 1;
                        assert!(
                            stalled < 100_000,
                            "virtual time stopped: a timer keeps asking to fire at {t:?} (now {:?}); a {:?}, b {:?}, in flight {}",
                            self.now,
                            self.a.pc.poll_timeout(),
                            self.b.pc.poll_timeout(),
                            self.in_flight.len()
                        );
                    } else {
                        stalled = 0;
                    }
                    self.now = t.max(self.now);
                    let now = self.now;
                    let _ = self.a.pc.handle_timeout(now);
                    let _ = self.b.pc.handle_timeout(now);
                }
                _ => {
                    self.now = end;
                    self.settle();
                    return;
                }
            }
        }
    }

    /// Runs until `done` holds or `limit` of virtual time has passed; returns whether it held.
    pub fn run_until(&mut self, limit: Duration, mut done: impl FnMut(&mut Sim) -> bool) -> bool {
        let end = self.now + limit;
        while self.now < end {
            self.run_for(Duration::from_millis(50));
            if done(self) {
                return true;
            }
        }
        done(self)
    }
}

impl Side {
    /// How many `OnTrack(OnOpen)` events this side has reported.
    pub fn tracks_opened(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(_))))
            .count()
    }

    /// How many `OnTrack(OnClose)` events this side has reported.
    pub fn tracks_closed(&self) -> usize {
        self.events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(_))
                )
            })
            .count()
    }

    /// How many RTP packets this side has received.
    pub fn rtp_received(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| matches!(m, RTCMessage::RtpPacket(_, _)))
            .count()
    }

    /// How many `OnNegotiationNeeded` events this side has reported.
    pub fn negotiation_needed(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent))
            .count()
    }

    /// Sends one RTP packet from `sender` with the payload type negotiated for it.
    pub fn send_rtp(&mut self, now: Instant, sender: RTCRtpSenderId, ssrc: u32, seq: u16) {
        let payload_type = self
            .pc
            .rtp_sender(sender)
            .and_then(|mut s| {
                s.get_parameters()
                    .rtp_parameters
                    .codecs
                    .first()
                    .map(|c| c.payload_type)
            })
            .unwrap_or(96);
        self.pc
            .rtp_sender(sender)
            .expect("the sender exists")
            .write_rtp(
                now,
                rtp::packet::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        marker: true,
                        payload_type,
                        sequence_number: seq,
                        timestamp: u32::from(seq) * 3000,
                        ssrc,
                        ..Default::default()
                    },
                    payload: bytes::Bytes::from_static(&[0x10, 0x00, 0x00]),
                },
            )
            .expect("write_rtp");
    }
}

impl Sim {
    /// How many datagrams are on the wire right now.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    pub fn side(&mut self, a: bool) -> &mut Side {
        if a { &mut self.a } else { &mut self.b }
    }

    /// Sends `count` RTP packets from `sender` on side `a_sends`, one per 20 ms of virtual time.
    pub fn send_video(&mut self, a_sends: bool, sender: RTCRtpSenderId, ssrc: u32, count: u16) {
        for _ in 0..count {
            let now = self.now;
            let side = self.side(a_sends);
            let seq = side.next_seq.entry(ssrc).or_insert(0);
            let current = *seq;
            *seq = seq.wrapping_add(1);
            side.send_rtp(now, sender, ssrc, current);
            self.run_for(Duration::from_millis(20));
        }
    }
}
