//! NACK Responder Interceptor - Responds to NACK requests by retransmitting packets.

use super::rate_window::RateWindow;
use super::send_buffer::SendBuffer;
use super::stream_supports_nack;
use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::MarshalSize;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Decides which local streams this responder buffers, on top of the NACK feedback check.
/// pion's `ResponderStreamsFilter`.
pub type ResponderStreamsFilter = Box<dyn Fn(&StreamInfo) -> bool + Send + Sync>;

/// Builder for the NackResponderInterceptor.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, Registry, NackResponderBuilder};
///
/// let chain = Registry::new()
///     .with(Slot::NackResponder, NackResponderBuilder::new()
///         .with_size(1024)
///         .with_rtt(std::time::Duration::from_millis(100))
///         .build())
///     .build();
/// ```
pub struct NackResponderBuilder {
    /// Size of the send buffer (must be power of 2: 1, 2, 4, ..., 32768).
    size: u16,
    /// A packet already retransmitted within this long is not retransmitted again.
    rtt: Duration,
    /// Extra per-stream gate, applied on top of the NACK feedback check.
    streams_filter: Option<ResponderStreamsFilter>,
    /// Whether retransmissions are capped to a byte budget.
    budget: bool,
    /// Width of the sliding window the budget is counted over.
    budget_window: Duration,
    /// Age past which a buffered packet is no longer retransmitted; `None` keeps it until the
    /// buffer overwrites it.
    max_packet_age: Option<Duration>,
}

/// libwebrtc's `kRetransmitWindowSizeMs` and pion's retransmission window.
const DEFAULT_BUDGET_WINDOW: Duration = Duration::from_millis(500);

/// Span the stream's own send rate is measured over when no target bitrate is known.
const MEDIA_RATE_WINDOW: Duration = Duration::from_secs(1);

/// libwebrtc's `kDefaultRtt`: assumed until the application supplies a measured round trip.
const DEFAULT_RTT: Duration = Duration::from_millis(100);

impl Default for NackResponderBuilder {
    fn default() -> Self {
        Self {
            size: 1024,
            rtt: DEFAULT_RTT,
            streams_filter: None,
            budget: true,
            budget_window: DEFAULT_BUDGET_WINDOW,
            max_packet_age: None,
        }
    }
}

impl NackResponderBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the size of the send buffer.
    ///
    /// Size must be a power of 2 between 1 and 32768 (inclusive).
    /// Larger buffers can retransmit older packets but use more memory.
    pub fn with_size(mut self, size: u16) -> Self {
        self.size = size;
        self
    }

    /// Set the round-trip time assumed for a retransmission to reach the receiver, used until a
    /// round trip is measured from RTCP reports.
    ///
    /// Once a receiver report answers one of this responder's sender reports, the measured round
    /// trip (smoothed over reports) replaces this value for that stream, as in pion's responder.
    ///
    /// A packet that was retransmitted less than a round trip ago is not retransmitted again when
    /// it is requested once more: the first copy is still on its way, and a second one only
    /// adds load to a path that is already losing packets (libwebrtc skips these the same way).
    /// Defaults to 100 ms, libwebrtc's `kDefaultRtt`. Zero retransmits every request.
    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.rtt = rtt;
        self
    }

    /// Restrict which local streams are buffered, on top of the NACK feedback check.
    ///
    /// pion's `ResponderStreamsFilter`: the predicate returns `true` for streams whose packets
    /// should be kept for retransmission. Without one, every stream negotiating `nack`
    /// feedback is buffered.
    pub fn with_streams_filter(mut self, filter: ResponderStreamsFilter) -> Self {
        self.streams_filter = Some(filter);
        self
    }

    /// Turn the retransmission budget on or off. On by default.
    ///
    /// While on, the bytes re-sent in any [`window`](Self::with_retransmit_window) stay within a
    /// budget. The budget is the congestion controller's target bitrate once one has been seen
    /// going past ([`Attribute::TargetBitrateChanged`]), shared by every stream of the
    /// connection as libwebrtc's single retransmission rate limiter is. Until then each stream
    /// is held to its own send rate over the last second (unlimited during its first second,
    /// which has no rate to measure). The first packet of an empty window is always sent, so a
    /// quiet stream can still repair a single loss.
    ///
    /// A request is answered in order and stops at the first packet the budget refuses, as
    /// libwebrtc's `RTPSender::OnReceivedNack` does; the rest of the request is counted in
    /// [`NackResponderStats::budget_dropped_packets`]. The oldest packets of a request are
    /// therefore served first and the newest are the ones left unanswered.
    pub fn with_retransmit_budget(mut self, enabled: bool) -> Self {
        self.budget = enabled;
        self
    }

    /// Set the width of the window the retransmission budget is counted over.
    ///
    /// Defaults to 500 ms, libwebrtc's `kRetransmitWindowSizeMs`. The window is counted in
    /// slots of a tenth of its width, so it is rounded to a whole multiple of 10 ms, with a
    /// minimum of 10 ms.
    pub fn with_retransmit_window(mut self, window: Duration) -> Self {
        let tens_of_ms = ((window.as_millis() + 5) / 10).max(1) as u64;
        self.budget_window = Duration::from_millis(tens_of_ms * 10);
        self
    }

    /// Stop retransmitting packets older than `max_age`, or three round trips if that is longer.
    ///
    /// After an outage the send buffer still holds everything sent during it, and the receiver's
    /// requests would have it all re-sent although no receiver can still use those packets.
    /// libwebrtc's `RtpPacketHistory` drops them after `max(1 s, 3 x RTT)`; this is the same
    /// rule with the floor of your choosing. A skipped request is counted in
    /// [`NackResponderStats::stale_skipped_packets`]. Off by default, as in pion.
    pub fn with_max_packet_age(mut self, max_age: Duration) -> Self {
        self.max_packet_age = Some(max_age);
        self
    }

    /// Build the interceptor, rejecting a buffer size that could never retransmit anything.
    ///
    /// pion fails construction with `ErrInvalidSize`; the infallible [`Self::build`] keeps its
    /// historic shape and instead yields an interceptor that buffers nothing, so callers that
    /// prefer a loud mistake use this.
    pub fn try_build(self) -> Result<NackResponderInterceptor, Error> {
        if !super::send_buffer::is_valid_size(self.size) {
            return Err(Error::ErrNackInvalidSize);
        }
        Ok(self.build())
    }

    /// Build the interceptor.
    ///
    /// A size the send buffer cannot hold (not a power of two in range) yields an interceptor
    /// that buffers nothing; [`Self::try_build`] turns the same configuration into an error
    /// instead.
    pub fn build(self) -> NackResponderInterceptor {
        NackResponderInterceptor::new(
            self.size,
            self.rtt,
            self.streams_filter,
            self.budget.then_some(self.budget_window),
            self.max_packet_age,
        )
    }
}

/// Per-stream state for the responder.
struct LocalStream {
    /// Buffer of sent packets for retransmission.
    send_buffer: SendBuffer,
    /// RTX SSRC for RFC4588 retransmission (if configured).
    ssrc_rtx: Option<u32>,
    /// RTX payload type for RFC4588 retransmission (if configured).
    payload_type_rtx: Option<u8>,
    /// Sequence number counter for RTX packets.
    rtx_sequence_number: u16,
    /// When each buffered packet was last retransmitted, so a repeat request within one round
    /// trip can be ignored.
    last_retransmit: HashMap<u16, Instant>,
    /// The last few sender reports written on this stream, by the middle 32 bits of their NTP
    /// time (what a report block echoes back as its LSR) and when they went out.
    sent_reports: VecDeque<(u32, Instant)>,
    /// Round trip measured from receiver reports, smoothed; `None` until the first one.
    rtt: Option<Duration>,
    /// Bytes this stream sent over the last second (the budget's rate when no target is known).
    media: RateWindow,
    /// Bytes re-sent over the budget window.
    resent: RateWindow,
}

/// What the responder has done, for monitoring.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NackResponderStats {
    /// Packets re-sent in answer to NACKs.
    pub retransmitted_packets: u64,
    /// Bytes of those packets.
    pub retransmitted_bytes: u64,
    /// Requested packets left unanswered because the retransmission budget was spent.
    pub budget_dropped_packets: u64,
    /// Requested packets not re-sent because they were older than the maximum packet age.
    pub stale_skipped_packets: u64,
}

/// How many sender reports are remembered to match a report block's LSR against.
const SENT_REPORTS_KEPT: usize = 8;

/// Weight of a new round-trip sample in the smoothed value.
const RTT_SMOOTHING: f64 = 1.0 / 8.0;

/// Interceptor that responds to NACK requests by retransmitting packets.
///
/// This interceptor buffers outgoing RTP packets on local streams and
/// retransmits them when RTCP TransportLayerNack packets are received.
pub struct NackResponderInterceptor {
    /// Configuration
    size: u16,
    rtt: Duration,
    /// Extra per-stream gate from the builder, applied with the NACK feedback check.
    streams_filter: Option<ResponderStreamsFilter>,
    /// Width of the retransmission budget window; `None` when the budget is off.
    budget_window: Option<Duration>,
    /// See [`NackResponderBuilder::with_max_packet_age`].
    max_packet_age: Option<Duration>,
    /// The congestion controller's latest target, in bits per second.
    target_bitrate: Option<f64>,
    /// Bytes re-sent across all streams over the budget window; the budget while a target
    /// bitrate is known.
    resent: RateWindow,
    stats: NackResponderStats,

    /// Send buffers per local stream SSRC
    streams: HashMap<u32, LocalStream>,

    /// Queue for retransmitted packets
    write_queue: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
}

impl NackResponderInterceptor {
    fn new(
        size: u16,
        rtt: Duration,
        streams_filter: Option<ResponderStreamsFilter>,
        budget_window: Option<Duration>,
        max_packet_age: Option<Duration>,
    ) -> Self {
        Self {
            max_packet_age,
            budget_window,
            target_bitrate: None,
            resent: RateWindow::new(budget_window.unwrap_or(DEFAULT_BUDGET_WINDOW)),
            stats: NackResponderStats::default(),
            read_queue: VecDeque::new(),
            size,
            rtt,
            streams_filter,
            streams: HashMap::new(),
            write_queue: VecDeque::new(),
        }
    }

    /// What this responder has re-sent and refused so far.
    pub fn stats(&self) -> NackResponderStats {
        self.stats
    }

    /// Bytes that may be re-sent per budget window on a stream with the given send rate.
    ///
    /// `None` means no limit: with no target bitrate, the send rate is only trusted once the
    /// stream has been sending for the whole rate window, since a younger stream's rate says
    /// nothing about what it may re-send.
    fn budget_bytes(
        target_bitrate: Option<f64>,
        media: &mut RateWindow,
        now: Instant,
        window: Duration,
    ) -> Option<f64> {
        match target_bitrate {
            Some(bits_per_second) => Some(bits_per_second / 8.0 * window.as_secs_f64()),
            None if media.age(now) < MEDIA_RATE_WINDOW => None,
            None => {
                Some(media.sum(now) as f64 * window.as_secs_f64() / MEDIA_RATE_WINDOW.as_secs_f64())
            }
        }
    }

    /// Remember the sender reports in `packets`, so a later report block can be timed against them.
    fn record_sender_reports(&mut self, now: Instant, packets: &[Box<dyn rtcp::packet::Packet>]) {
        for packet in packets {
            if let Some(sr) = packet
                .as_any()
                .downcast_ref::<rtcp::sender_report::SenderReport>()
                && let Some(stream) = self.streams.get_mut(&sr.ssrc)
            {
                if stream.sent_reports.len() == SENT_REPORTS_KEPT {
                    stream.sent_reports.pop_front();
                }
                stream
                    .sent_reports
                    .push_back(((sr.ntp_time >> 16) as u32, now));
            }
        }
    }

    /// Time every report block in `packets` that answers one of our sender reports, fold the
    /// samples into the stream's smoothed round trip and return the latest smoothed value.
    ///
    /// The sample is the time since the sender report went out, less the delay the remote held it
    /// for (RFC 3550 section 6.4.1), which is what pion's responder measures too.
    fn measure_rtt(
        &mut self,
        now: Instant,
        packets: &[Box<dyn rtcp::packet::Packet>],
    ) -> Option<Duration> {
        let mut measured = None;
        for packet in packets {
            let any = packet.as_any();
            let blocks =
                if let Some(rr) = any.downcast_ref::<rtcp::receiver_report::ReceiverReport>() {
                    &rr.reports
                } else if let Some(sr) = any.downcast_ref::<rtcp::sender_report::SenderReport>() {
                    &sr.reports
                } else {
                    continue;
                };
            for block in blocks {
                if block.last_sender_report == 0 {
                    continue;
                }
                let Some(stream) = self.streams.get_mut(&block.ssrc) else {
                    continue;
                };
                let Some(&(_, sent_at)) = stream
                    .sent_reports
                    .iter()
                    .rev()
                    .find(|(lsr, _)| *lsr == block.last_sender_report)
                else {
                    continue;
                };
                let held = Duration::from_secs_f64(f64::from(block.delay) / 65536.0);
                let sample = now.saturating_duration_since(sent_at).saturating_sub(held);
                let smoothed = match stream.rtt {
                    None => sample,
                    Some(old) => Duration::from_secs_f64(
                        old.as_secs_f64() * (1.0 - RTT_SMOOTHING)
                            + sample.as_secs_f64() * RTT_SMOOTHING,
                    ),
                };
                stream.rtt = Some(smoothed);
                measured = Some(smoothed);
            }
        }
        measured
    }

    /// Handle a NACK request by queuing retransmissions.
    fn handle_nack(
        &mut self,
        now: Instant,
        nack: &rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack,
    ) {
        // Collect sequence numbers to retransmit
        let mut seqs_to_retransmit = Vec::new();

        for nack_pair in &nack.nacks {
            // Check the base packet ID
            seqs_to_retransmit.push(nack_pair.packet_id);

            // Check each bit in lost_packets bitmap
            for i in 0..16 {
                if nack_pair.lost_packets & (1 << i) != 0 {
                    let seq = nack_pair.packet_id.wrapping_add(i + 1);
                    seqs_to_retransmit.push(seq);
                }
            }
        }

        let Some(stream) = self.streams.get_mut(&nack.media_ssrc) else {
            return;
        };

        // Entries older than one round trip no longer suppress anything; dropping them keeps the
        // map to the packets that were retransmitted recently.
        let rtt = stream.rtt.unwrap_or(self.rtt);
        stream
            .last_retransmit
            .retain(|_, sent| now.saturating_duration_since(*sent) < rtt);

        // Queue retransmissions
        let requested = seqs_to_retransmit.len();
        for (index, seq) in seqs_to_retransmit.into_iter().enumerate() {
            let Some(original_packet) = stream.send_buffer.get(seq) else {
                continue;
            };

            // Too old for any receiver to still want, and past what the round trip could explain.
            if let Some(max_age) = self.max_packet_age
                && let Some(stored) = stream.send_buffer.stored_at(seq)
                && now.saturating_duration_since(stored) > max_age.max(rtt * 3)
            {
                self.stats.stale_skipped_packets += 1;
                continue;
            }

            // The copy sent less than one round trip ago has not had time to arrive and be
            // reported, so this request was made before it could have helped.
            if stream.last_retransmit.contains_key(&seq) {
                continue;
            }

            let size = original_packet.marshal_size()
                + if stream.ssrc_rtx.is_some() && stream.payload_type_rtx.is_some() {
                    2
                } else {
                    0
                };
            if let Some(window) = self.budget_window {
                let used = if self.target_bitrate.is_some() {
                    self.resent.sum(now)
                } else {
                    stream.resent.sum(now)
                };
                let budget =
                    Self::budget_bytes(self.target_bitrate, &mut stream.media, now, window);
                // An empty window always answers one request, so a quiet stream repairs a loss.
                if let Some(budget) = budget
                    && used > 0
                    && (used + size) as f64 > budget
                {
                    self.stats.budget_dropped_packets += (requested - index) as u64;
                    break;
                }
            }
            self.resent.add(now, size);
            stream.resent.add(now, size);
            self.stats.retransmitted_packets += 1;
            self.stats.retransmitted_bytes += size as u64;
            stream.last_retransmit.insert(seq, now);

            let packet = if let (Some(ssrc_rtx), Some(pt_rtx)) =
                (stream.ssrc_rtx, stream.payload_type_rtx)
            {
                // RFC4588: Create RTX packet
                // - Use RTX SSRC and payload type
                // - Prepend original sequence number (2 bytes big-endian) to payload
                // - Use separate RTX sequence number counter
                let original_seq = original_packet.header.sequence_number;

                // pion strips padding from the RTX copy: the P-bit comes off, and in the legacy
                // style — padding declared only by the P-bit, its count in the last payload
                // byte — that many bytes are trimmed from the end. A declared `padding_size`
                // already keeps the padding octets out of the payload, so only the flag needs
                // clearing (the fresh header below does).
                let mut trimmed = original_packet.payload.clone();
                if original_packet.header.padding
                    && original_packet.header.padding_size == 0
                    && !trimmed.is_empty()
                {
                    let padding_length = trimmed[trimmed.len() - 1] as usize;
                    // An overflowing count was never buffered on an RTX stream (see
                    // `handle_write`), so this cannot over-trim; it is checked again so the
                    // trimming arithmetic stays honest whatever future refactor does.
                    if padding_length <= trimmed.len() {
                        let keep = trimmed.len() - padding_length;
                        trimmed.truncate(keep);
                    }
                }

                let mut rtx_payload = Vec::with_capacity(2 + trimmed.len());
                rtx_payload.extend_from_slice(&original_seq.to_be_bytes());
                rtx_payload.extend_from_slice(&trimmed);

                let rtx_seq = stream.rtx_sequence_number;
                stream.rtx_sequence_number = stream.rtx_sequence_number.wrapping_add(1);

                rtp::Packet {
                    header: rtp::header::Header {
                        // Not left to `..Default::default()`: the default
                        // header is version 0, and receivers discard
                        // version != 2 before examining anything else, so a
                        // defaulted RTX packet is dropped on arrival and the
                        // NACKed gap never repairs.
                        version: 2,
                        ssrc: ssrc_rtx,
                        payload_type: pt_rtx,
                        sequence_number: rtx_seq,
                        timestamp: original_packet.header.timestamp,
                        marker: original_packet.header.marker,
                        ..Default::default()
                    },
                    payload: rtx_payload.into(),
                }
            } else {
                // No RTX: retransmit original packet as-is
                original_packet.clone()
            };

            // Tagged so a send history downstream counts it as new bytes on the wire rather
            // than as the original transmission. A bandwidth estimator that cannot tell the two
            // apart under-counts exactly when the path is lossy — it sees fewer bytes than are
            // really being sent, infers headroom, and raises the target during loss.
            self.write_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(packet)).with(Attribute::Retransmission),
            });
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for NackResponderInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        // Time receiver reports against our sender reports, and tell what follows about it
        if let Packet::Rtcp(ref rtcp_packets) = msg.message.packet
            && let Some(rtt) = self.measure_rtt(msg.now, rtcp_packets)
        {
            msg.message.add(Attribute::RoundTripTime { rtt });
        }

        if let Some(Attribute::TargetBitrateChanged { bits_per_second }) =
            msg.message.get(&Attribute::TargetBitrateChanged {
                bits_per_second: 0.0,
            })
        {
            self.target_bitrate = Some(*bits_per_second);
        }

        // Process NACK packets
        if let Packet::Rtcp(ref rtcp_packets) = msg.message.packet {
            for rtcp_packet in rtcp_packets {
                if let Some(nack) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>()
                {
                    self.handle_nack(msg.now, nack);
                }
            }
        }

        self.read_queue.push_back(msg);

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Remember outgoing sender reports, to time the receiver reports that answer them
        if let Packet::Rtcp(ref rtcp_packets) = msg.message.packet {
            self.record_sender_reports(msg.now, rtcp_packets);
        }

        // Buffer outgoing RTP packets
        if let Packet::Rtp(ref rtp_packet) = msg.message.packet
            && let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc)
        {
            // A padded packet whose legacy padding count overflows the payload cannot become an
            // RTX copy. pion's packet factory rejects it at buffer time (`errPaddingOverflow`)
            // and the write itself still succeeds, so it is simply never retransmitted. pion's
            // check runs two bytes further into the OSN-prefixed copy and over-trims there, a
            // bug not worth copying.
            let malformed_rtx_padding = stream.ssrc_rtx.is_some()
                && stream.payload_type_rtx.is_some()
                && rtp_packet.header.padding
                && rtp_packet.header.padding_size == 0
                && !rtp_packet.payload.is_empty()
                && rtp_packet.payload[rtp_packet.payload.len() - 1] as usize
                    > rtp_packet.payload.len();

            if !malformed_rtx_padding {
                // A reused sequence number is a new packet, whatever became of the old one.
                stream
                    .last_retransmit
                    .remove(&rtp_packet.header.sequence_number);
                stream.media.add(msg.now, rtp_packet.marshal_size());
                stream.send_buffer.add(rtp_packet.clone(), msg.now);
            }
        }

        self.write_queue.push_back(msg);

        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // First drain retransmitted packets
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for NackResponderInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        let passes_filter = self
            .streams_filter
            .as_ref()
            .is_none_or(|filter| filter(info));
        if passes_filter
            && stream_supports_nack(info)
            && let Some(send_buffer) = SendBuffer::new(self.size)
        {
            self.streams.insert(
                info.ssrc,
                LocalStream {
                    send_buffer,
                    ssrc_rtx: info.ssrc_rtx,
                    payload_type_rtx: info.payload_type_rtx,
                    rtx_sequence_number: 0,
                    last_retransmit: HashMap::new(),
                    sent_reports: VecDeque::new(),
                    rtt: None,
                    media: RateWindow::new(MEDIA_RATE_WINDOW),
                    resent: RateWindow::new(self.budget_window.unwrap_or(DEFAULT_BUDGET_WINDOW)),
                },
            );
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};

    const SSRC: u32 = 0x1234;

    fn responder(builder: NackResponderBuilder) -> NackResponderInterceptor {
        let mut r = builder.with_rtt(Duration::ZERO).build();
        r.bind_local_stream(&StreamInfo {
            ssrc: SSRC,
            rtcp_feedback: vec![crate::stream_info::RTCPFeedback {
                typ: "nack".to_string(),
                parameter: String::new(),
            }],
            ..Default::default()
        });
        r
    }

    /// 100 packets of 1,000 payload bytes (1,012 on the wire), one every 10 ms from `t0`.
    fn send_media(r: &mut NackResponderInterceptor, t0: Instant) {
        for seq in 0..100u16 {
            r.handle_write(TaggedPacket {
                now: t0 + Duration::from_millis(u64::from(seq) * 10),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        ssrc: SSRC,
                        sequence_number: seq,
                        ..Default::default()
                    },
                    payload: vec![0u8; 1000].into(),
                })),
            })
            .unwrap();
        }
        while r.poll_write().is_some() {}
    }

    /// Ask for every sequence number in `seqs` at `now`; returns how many came back.
    fn nack(r: &mut NackResponderInterceptor, now: Instant, seqs: std::ops::Range<u16>) -> usize {
        nack_ssrc(r, now, SSRC, seqs)
    }

    fn nack_ssrc(
        r: &mut NackResponderInterceptor,
        now: Instant,
        ssrc: u32,
        seqs: std::ops::Range<u16>,
    ) -> usize {
        let nacks = seqs
            .step_by(17)
            .map(|packet_id| NackPair {
                packet_id,
                lost_packets: 0xFFFF,
            })
            .collect();
        r.handle_read(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
                sender_ssrc: 1,
                media_ssrc: ssrc,
                nacks,
            })])),
        })
        .unwrap();
        while r.poll_read().is_some() {}
        let mut count = 0;
        while r.poll_write().is_some() {
            count += 1;
        }
        count
    }

    #[test]
    fn storm_is_held_to_the_media_rate() {
        let t0 = Instant::now();
        let mut r = responder(NackResponderBuilder::new());
        send_media(&mut r, t0);
        // 90 packets sent in the last second: half of that fits one window.
        let sent = nack(&mut r, t0 + Duration::from_millis(1000), 0..85);
        assert!((40..=45).contains(&sent), "sent {sent}");
        let stats = r.stats();
        assert_eq!(stats.retransmitted_packets, sent as u64);
        assert!(stats.budget_dropped_packets >= 40);
        assert!(stats.retransmitted_bytes <= 45_540);
    }

    #[test]
    fn request_within_budget_is_answered() {
        let t0 = Instant::now();
        let mut r = responder(NackResponderBuilder::new());
        send_media(&mut r, t0);
        assert_eq!(nack(&mut r, t0 + Duration::from_millis(1000), 10..11), 17);
        assert_eq!(r.stats().budget_dropped_packets, 0);
    }

    #[test]
    fn window_refills_after_its_width() {
        let t0 = Instant::now();
        let mut r = responder(NackResponderBuilder::new());
        send_media(&mut r, t0);
        let first = nack(&mut r, t0 + Duration::from_millis(1000), 0..85);
        // Inside the same window nothing more is answered.
        assert_eq!(nack(&mut r, t0 + Duration::from_millis(1100), 0..85), 0);
        // After it, the spent bytes have aged out and the budget is available again.
        let later = nack(&mut r, t0 + Duration::from_millis(1600), 0..85);
        assert!(first > 0 && later > 0, "{first} then {later}");
    }

    #[test]
    fn target_bitrate_sets_the_budget() {
        let t0 = Instant::now();
        let mut r = responder(NackResponderBuilder::new());
        send_media(&mut r, t0);
        // 80 kbit/s is 10,000 B/s: 5,000 B per window, four 1,012-byte packets.
        r.handle_read(TaggedPacket {
            now: t0 + Duration::from_millis(1000),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])).with(
                Attribute::TargetBitrateChanged {
                    bits_per_second: 80_000.0,
                },
            ),
        })
        .unwrap();
        assert_eq!(nack(&mut r, t0 + Duration::from_millis(1000), 0..85), 4);
    }

    #[test]
    fn target_budget_is_shared_by_all_streams() {
        let t0 = Instant::now();
        let mut r = responder(NackResponderBuilder::new());
        let second = SSRC + 1;
        r.bind_local_stream(&StreamInfo {
            ssrc: second,
            rtcp_feedback: vec![crate::stream_info::RTCPFeedback {
                typ: "nack".to_string(),
                parameter: String::new(),
            }],
            ..Default::default()
        });
        send_media(&mut r, t0);
        for seq in 0..100u16 {
            r.handle_write(TaggedPacket {
                now: t0 + Duration::from_millis(u64::from(seq) * 10),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        ssrc: second,
                        sequence_number: seq,
                        ..Default::default()
                    },
                    payload: vec![0u8; 1000].into(),
                })),
            })
            .unwrap();
        }
        while r.poll_write().is_some() {}
        let now = t0 + Duration::from_millis(1000);
        r.handle_read(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])).with(
                Attribute::TargetBitrateChanged {
                    bits_per_second: 80_000.0,
                },
            ),
        })
        .unwrap();
        // One 5,000-byte budget: four packets in all, not four per stream.
        let total = nack(&mut r, now, 0..85) + nack_ssrc(&mut r, now, second, 0..85);
        assert_eq!(total, 4);
    }

    #[test]
    fn stale_packets_are_not_resent() {
        let t0 = Instant::now();
        let mut r =
            responder(NackResponderBuilder::new().with_max_packet_age(Duration::from_secs(1)));
        send_media(&mut r, t0);
        // Packets 0..=9 left at t0..t0+90 ms; 95..=99 at t0+950..t0+990 ms. At t0+1.5 s the first
        // are over a second old and the last are not.
        let now = t0 + Duration::from_millis(1500);
        assert_eq!(nack_ssrc(&mut r, now, SSRC, 0..1), 0);
        assert_eq!(r.stats().stale_skipped_packets, 17);
        assert_eq!(nack_ssrc(&mut r, now, SSRC, 85..86), 15);
    }

    #[test]
    fn three_round_trips_outlast_the_max_age() {
        let t0 = Instant::now();
        let mut r =
            responder(NackResponderBuilder::new().with_max_packet_age(Duration::from_secs(1)));
        r.streams.get_mut(&SSRC).unwrap().rtt = Some(Duration::from_secs(2));
        send_media(&mut r, t0);
        // Packet 0 is 1.5 s old: past max_age, within 3 x 2 s.
        assert_eq!(
            nack_ssrc(&mut r, t0 + Duration::from_millis(1500), SSRC, 0..1),
            17
        );
        assert_eq!(r.stats().stale_skipped_packets, 0);
    }

    #[test]
    fn budget_can_be_switched_off() {
        let t0 = Instant::now();
        let mut r = responder(NackResponderBuilder::new().with_retransmit_budget(false));
        send_media(&mut r, t0);
        assert_eq!(nack(&mut r, t0 + Duration::from_millis(1000), 0..85), 85);
        assert_eq!(r.stats().budget_dropped_packets, 0);
    }
}
