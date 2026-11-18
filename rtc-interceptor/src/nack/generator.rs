//! NACK Generator Interceptor - Generates NACK requests for missing packets.

use super::receive_log::ReceiveLog;
use super::stream_supports_nack;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Decides which remote streams this generator tracks, on top of the NACK feedback check.
/// pion's `GeneratorStreamsFilter`.
pub type GeneratorStreamsFilter = Box<dyn Fn(&StreamInfo) -> bool + Send + Sync>;

/// Builder for the NackGeneratorInterceptor.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, Registry, NackGeneratorBuilder};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(Slot::NackGenerator, NackGeneratorBuilder::new()
///         .with_size(512)
///         .with_interval(Duration::from_millis(100))
///         .with_skip_last_n(2)
///         .with_rtt(Duration::from_millis(100))
///         .with_max_nacks_per_packet(10)
///         .build())
///     .build();
/// ```
pub struct NackGeneratorBuilder {
    /// Size of the receive log (must be power of 2: 64, 128, ..., 32768).
    size: u16,
    /// Interval between NACK generation cycles.
    interval: Duration,
    /// Number of most recent packets to skip when generating NACKs.
    skip_last_n: u16,
    /// Maximum number of NACKs to send per missing packet (0 = unlimited).
    max_nacks_per_packet: u16,
    /// Round-trip time assumed between asking for a packet and its repair arriving.
    rtt: Duration,
    /// Extra per-stream gate, applied on top of the NACK feedback check.
    streams_filter: Option<GeneratorStreamsFilter>,
}

/// libwebrtc's `kMaxNackRetries`: a packet still missing after this many requests is given up on.
const DEFAULT_MAX_NACKS_PER_PACKET: u16 = 10;

/// libwebrtc's `kDefaultRtt`: assumed until the application supplies a measured round trip.
const DEFAULT_RTT: Duration = Duration::from_millis(100);

impl Default for NackGeneratorBuilder {
    fn default() -> Self {
        Self {
            size: 512,
            interval: Duration::from_millis(100),
            skip_last_n: 0,
            max_nacks_per_packet: DEFAULT_MAX_NACKS_PER_PACKET,
            rtt: DEFAULT_RTT,
            streams_filter: None,
        }
    }
}

impl NackGeneratorBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the size of the receive log.
    ///
    /// Size must be a power of 2 between 64 and 32768 (inclusive).
    pub fn with_size(mut self, size: u16) -> Self {
        self.size = size;
        self
    }

    /// Set the interval between NACK generation cycles.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Set the number of most recent packets to skip when generating NACKs.
    ///
    /// This helps avoid generating NACKs for packets that are simply delayed
    /// and haven't arrived yet.
    pub fn with_skip_last_n(mut self, skip_last_n: u16) -> Self {
        self.skip_last_n = skip_last_n;
        self
    }

    /// Set the maximum number of NACKs to send per missing packet.
    ///
    /// A packet still missing after this many requests is given up on, so a path that cannot
    /// repair it is not asked forever. Defaults to 10, libwebrtc's `kMaxNackRetries`; set to 0
    /// for unlimited NACKs.
    pub fn with_max_nacks_per_packet(mut self, max: u16) -> Self {
        self.max_nacks_per_packet = max;
        self
    }

    /// Set the round-trip time assumed for a repair to arrive, used until a round trip is
    /// measured from RTCP reports.
    ///
    /// The NACK responder earlier in the chain measures it from receiver reports and passes it on
    /// as [`Attribute::RoundTripTime`](crate::Attribute::RoundTripTime); from then on that value
    /// replaces this one.
    ///
    /// A missing packet is asked for again only once this long has passed since it was last
    /// asked for: earlier than that, the first repair is still in flight and another request
    /// only makes the sender transmit the same packet twice. Defaults to 100 ms, libwebrtc's
    /// `kDefaultRtt`.
    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.rtt = rtt;
        self
    }

    /// Restrict which remote streams are tracked, on top of the NACK feedback check.
    ///
    /// pion's `GeneratorStreamsFilter`: the predicate returns `true` for streams that should
    /// generate NACKs. Without one, every stream negotiating `nack` feedback is tracked.
    pub fn with_streams_filter(mut self, filter: GeneratorStreamsFilter) -> Self {
        self.streams_filter = Some(filter);
        self
    }

    /// Build the interceptor, rejecting a buffer size that could never retransmit anything.
    ///
    /// pion fails construction with `ErrInvalidSize`; the infallible [`Self::build`] keeps its
    /// historic shape and instead yields an interceptor that tracks nothing, so callers that
    /// prefer a loud mistake use this.
    pub fn try_build(self) -> Result<NackGeneratorInterceptor, Error> {
        if !super::receive_log::is_valid_size(self.size) {
            return Err(Error::ErrNackInvalidSize);
        }
        Ok(self.build())
    }

    /// Build the interceptor.
    ///
    /// A size the receive log cannot hold (not a power of two in range) yields an interceptor
    /// that tracks no streams at all; [`Self::try_build`] turns the same configuration into an
    /// error instead.
    pub fn build(self) -> NackGeneratorInterceptor {
        NackGeneratorInterceptor::new(
            self.size,
            self.interval,
            self.skip_last_n,
            self.max_nacks_per_packet,
            self.rtt,
            self.streams_filter,
        )
    }
}

/// Interceptor that generates NACK requests for missing RTP packets.
///
/// This interceptor monitors incoming RTP packets on remote streams,
/// tracks which sequence numbers have been received, and periodically
/// generates RTCP TransportLayerNack packets for missing sequences.
pub struct NackGeneratorInterceptor {
    /// Configuration
    size: u16,
    interval: Duration,
    skip_last_n: u16,
    max_nacks_per_packet: u16,
    rtt: Duration,
    /// Round trip measured by the responder, once it has one; replaces `rtt`.
    measured_rtt: Option<Duration>,
    /// Extra per-stream gate from the builder, applied with the NACK feedback check.
    streams_filter: Option<GeneratorStreamsFilter>,

    /// Next timeout for NACK generation
    next_timeout: Option<Instant>,

    /// Sender SSRC for NACK packets
    sender_ssrc: u32,

    /// Receive logs per remote stream SSRC
    receive_logs: HashMap<u32, ReceiveLog>,

    /// When and how often each still-missing (SSRC, sequence number) was last asked for
    nack_states: HashMap<u32, HashMap<u16, NackState>>,

    /// Queue for outgoing NACK packets
    write_queue: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
}

/// What has been asked for so far about one missing packet.
struct NackState {
    /// When the packet was last named in a NACK.
    last_sent: Instant,
    /// How many NACKs have named it.
    count: u16,
}

impl NackGeneratorInterceptor {
    fn new(
        size: u16,
        interval: Duration,
        skip_last_n: u16,
        max_nacks_per_packet: u16,
        rtt: Duration,
        streams_filter: Option<GeneratorStreamsFilter>,
    ) -> Self {
        Self {
            read_queue: VecDeque::new(),
            size,
            interval,
            skip_last_n,
            max_nacks_per_packet,
            rtt,
            measured_rtt: None,
            streams_filter,
            next_timeout: None,
            sender_ssrc: rand::random(),
            receive_logs: HashMap::new(),
            nack_states: HashMap::new(),
            write_queue: VecDeque::new(),
        }
    }

    /// Generate NACKs for all streams with missing packets.
    fn generate_nacks(&mut self, now: Instant) {
        let rtt = self.measured_rtt.unwrap_or(self.rtt);
        for (&ssrc, receive_log) in &self.receive_logs {
            let missing = receive_log.missing_seq_numbers(self.skip_last_n);
            if missing.is_empty() {
                self.nack_states.remove(&ssrc);
                continue;
            }

            // Forget packets that arrived or fell out of the log, then pick the ones due: a
            // packet asked for less than one round trip ago has its repair still in flight, and
            // one asked for `max_nacks_per_packet` times is given up on.
            let state = self.nack_states.entry(ssrc).or_default();
            let still_missing: HashSet<u16> = missing.iter().copied().collect();
            state.retain(|seq, _| still_missing.contains(seq));

            let filtered: Vec<u16> = missing
                .iter()
                .copied()
                .filter(|&seq| {
                    let due = match state.get(&seq) {
                        None => true,
                        Some(sent) => {
                            now.saturating_duration_since(sent.last_sent) >= rtt
                                && (self.max_nacks_per_packet == 0
                                    || sent.count < self.max_nacks_per_packet)
                        }
                    };
                    if due {
                        let sent = state.entry(seq).or_insert(NackState {
                            last_sent: now,
                            count: 0,
                        });
                        sent.last_sent = now;
                        sent.count = sent.count.saturating_add(1);
                    }
                    due
                })
                .collect();

            if filtered.is_empty() {
                continue;
            }

            // Create NACK packet
            let nack = rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack {
                sender_ssrc: self.sender_ssrc,
                media_ssrc: ssrc,
                nacks: rtcp::transport_feedbacks::transport_layer_nack::nack_pairs_from_sequence_numbers(
                    &filtered,
                ),
            };

            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(nack)])),
            });
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for NackGeneratorInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // The responder times receiver reports against its sender reports and says so
        if let Some(Attribute::RoundTripTime { rtt }) = msg.message.get(&Attribute::RoundTripTime {
            rtt: Duration::ZERO,
        }) {
            self.measured_rtt = Some(*rtt);
        }

        // Track incoming RTP packets
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && let Some(receive_log) = self.receive_logs.get_mut(&rtp_packet.header.ssrc)
        {
            receive_log.add(rtp_packet.header.sequence_number);

            // Arm the NACK timer from the first tracked packet's instant. `None` means nothing is
            // scheduled, so the interceptor asks for no wake-up until a stream is actually flowing.
            if self.next_timeout.is_none() {
                self.next_timeout = Some(msg.now + self.interval);
            }
        }

        self.read_queue.push_back(msg);

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // First drain generated NACK packets
        if let Some(pkt) = self.write_queue.pop_front() {
            return Some(pkt);
        }
        None
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        if let Some(next_timeout) = self.next_timeout
            && now >= next_timeout
        {
            self.next_timeout = Some(now + self.interval);
            self.generate_nacks(now);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_timeout
    }
}

impl Interceptor for NackGeneratorInterceptor {
    fn writes_pass_through(&self) -> bool {
        true
    }

    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        let passes_filter = self
            .streams_filter
            .as_ref()
            .is_none_or(|filter| filter(info));
        if passes_filter
            && stream_supports_nack(info)
            && let Some(receive_log) = ReceiveLog::new(self.size)
        {
            self.receive_logs.insert(info.ssrc, receive_log);
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.receive_logs.remove(&info.ssrc);
        self.nack_states.remove(&info.ssrc);
    }

    fn bind_local_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
}
