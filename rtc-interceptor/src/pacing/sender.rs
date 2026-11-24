//! Smooths outgoing packets to a target rate.

use super::pacer::Pacer as LeakyBucket;
use crate::Interceptor;
use crate::StreamInfo;
use crate::{Attribute, Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use shared::hash::FastSet;
use shared::marshal::MarshalSize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Rate used when none is configured: 1 Mb/s.
pub const DEFAULT_BITRATE: f64 = 1_000_000.0;

/// Packets held before new ones are refused.
pub const DEFAULT_QUEUE_LIMIT: usize = 4096;

/// Burst window of the send-rate mode unless configured: 5 ms.
pub const DEFAULT_SEND_RATE_BURST_WINDOW: Duration = Duration::from_millis(5);

/// Multiplier of the send-rate mode unless configured.
pub const DEFAULT_SEND_RATE_MULTIPLIER: f64 = 2.0;

/// Width of one slot of the send-rate window.
const SLOT: Duration = Duration::from_millis(100);

/// Slots in the send-rate window: ten of 100 ms make about a second.
const SLOTS: usize = 10;

/// What sets the pace rate.
#[derive(Debug, Clone, Copy)]
enum PaceMode {
    /// Follow the congestion controller's target bitrate.
    FollowTarget,
    /// `multiplier` times the paced bytes sent over the last second, floored at `min_bitrate`.
    SendRate { multiplier: f64, min_bitrate: f64 },
}

/// Paced bits sent over roughly the last second, in fixed slots so nothing grows per packet.
#[derive(Debug, Clone, Default)]
struct SendRate {
    start: Option<Instant>,
    ids: [u64; SLOTS],
    bits: [f64; SLOTS],
}

impl SendRate {
    fn slot_id(&mut self, now: Instant) -> u64 {
        let start = *self.start.get_or_insert(now);
        (now.saturating_duration_since(start).as_millis() / SLOT.as_millis()) as u64
    }

    fn record(&mut self, now: Instant, bits: f64) {
        let id = self.slot_id(now);
        let index = (id % SLOTS as u64) as usize;
        if self.ids[index] != id {
            self.ids[index] = id;
            self.bits[index] = 0.0;
        }
        self.bits[index] += bits;
    }

    /// Bits per second over the slots still inside the window.
    fn bits_per_second(&mut self, now: Instant) -> f64 {
        let current = self.slot_id(now);
        let total: f64 = (0..SLOTS)
            .filter(|&i| self.ids[i] <= current && self.ids[i] + SLOTS as u64 > current)
            .map(|i| self.bits[i])
            .sum();
        total / (SLOT.as_secs_f64() * SLOTS as f64)
    }
}

/// Builder for [`PacerInterceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Slot, PacerBuilder, Registry};
///
/// let chain = Registry::new()
///     .with(Slot::Pacer, PacerBuilder::new().with_target_bitrate(2_000_000.0).build())
///     .build();
/// ```
pub struct PacerBuilder {
    bitrate: f64,
    burst_bits: Option<f64>,
    queue_limit: usize,
    mode: PaceMode,
    burst_window: Option<Duration>,
}

impl Default for PacerBuilder {
    fn default() -> Self {
        Self {
            bitrate: DEFAULT_BITRATE,
            burst_bits: None,
            queue_limit: DEFAULT_QUEUE_LIMIT,
            mode: PaceMode::FollowTarget,
            burst_window: None,
        }
    }
}

impl PacerBuilder {
    /// Create a builder with the default rate and queue limit.
    pub fn new() -> Self {
        Self::default()
    }

    /// The rate to pace at, in bits per second.
    pub fn with_target_bitrate(mut self, bits_per_second: f64) -> Self {
        self.bitrate = bits_per_second;
        self
    }

    /// How much may be released at once, in bits.
    ///
    /// Larger bursts smooth less but cost fewer wake-ups.
    pub fn with_burst_bits(mut self, burst_bits: f64) -> Self {
        self.burst_bits = Some(burst_bits);
        self
    }

    /// How many packets may be queued before new ones are refused.
    pub fn with_queue_limit(mut self, queue_limit: usize) -> Self {
        self.queue_limit = queue_limit;
        self
    }

    /// Pace at `multiplier` times the paced bytes sent over the last second instead of following
    /// the congestion controller's target (default multiplier 2.0).
    ///
    /// The pacer then never throttles the steady rate — whoever chooses the bitrate decides it —
    /// and only spreads bursts out. The rate is floored at [`PacerBuilder::with_min_bitrate`],
    /// which is also the rate before anything has been sent. Audio is sent unpaced and does not
    /// count towards the rate.
    pub fn with_send_rate_multiplier(mut self, multiplier: f64) -> Self {
        let min_bitrate = match self.mode {
            PaceMode::SendRate { min_bitrate, .. } => min_bitrate,
            PaceMode::FollowTarget => DEFAULT_BITRATE,
        };
        self.mode = PaceMode::SendRate {
            multiplier,
            min_bitrate,
        };
        self
    }

    /// The lowest rate the send-rate mode paces at, in bits per second (default 1 Mb/s).
    ///
    /// Enables the send-rate mode with the default multiplier if it is not on yet.
    pub fn with_min_bitrate(mut self, bits_per_second: f64) -> Self {
        let multiplier = match self.mode {
            PaceMode::SendRate { multiplier, .. } => multiplier,
            PaceMode::FollowTarget => DEFAULT_SEND_RATE_MULTIPLIER,
        };
        self.mode = PaceMode::SendRate {
            multiplier,
            min_bitrate: bits_per_second,
        };
        self
    }

    /// How much time at the pace rate one burst covers, floored at one packet.
    ///
    /// Defaults to 5 ms in the send-rate mode and 100 ms when following the target. Ignored when
    /// [`PacerBuilder::with_burst_bits`] is set.
    pub fn with_burst_window(mut self, window: Duration) -> Self {
        self.burst_window = Some(window);
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> PacerInterceptor {
        let (bitrate, window) = match self.mode {
            PaceMode::FollowTarget => (self.bitrate, self.burst_window),
            PaceMode::SendRate { min_bitrate, .. } => (
                min_bitrate,
                Some(self.burst_window.unwrap_or(DEFAULT_SEND_RATE_BURST_WINDOW)),
            ),
        };
        let mut bucket = LeakyBucket::new(bitrate);
        if let Some(window) = window {
            bucket = bucket.with_burst_window(window);
        }
        if let Some(burst_bits) = self.burst_bits {
            bucket = bucket.with_burst_bits(burst_bits);
        }
        PacerInterceptor::new(bucket, self.queue_limit, self.mode)
    }
}

/// Releases queued packets at a target rate rather than as fast as they arrive.
///
/// # Where this belongs in the chain
///
/// **Close to the wire, with every generator on the application side of it.** Everything after it
/// on the write path observes the *release* instant, so a send history goes there and records what
/// actually left; placed the other way round it would record the enqueue instant and charge this
/// queueing delay to the network.
///
/// Retransmissions, FEC repair packets and generated RTCP are all produced further out and reach
/// the pacer on the belt, so they are metered along with everything else. Under the nested chain
/// they bypassed it entirely.
///
/// # What is not paced
///
/// RTCP, and RTP of local audio streams (bound with an `audio/` MIME type), go straight out: audio
/// is small and latency-sensitive, and held behind a video backlog it would arrive late. This
/// holds in both modes — following the congestion controller's target and
/// [`PacerBuilder::with_send_rate_multiplier`] — and audio does not count towards the send rate
/// the second mode measures.
///
/// # Differences from upstream
///
/// - **No ticker and no goroutine.** Upstream runs a loop on a 5 ms `time.Ticker`; here the
///   budget is a pure function of the instants handed in, so a release schedule is reproducible
///   rather than merely eventually-correct.
/// - **Idle means idle.** `poll_timeout` returns `None` with nothing queued, so an idle
///   connection does not wake the whole chain at the pacing interval.
/// - **The deadline is when the head can afford to go**, not `now + interval`, so it always
///   advances — a deadline at or before the `now` just handed to `handle_timeout` is the
///   webrtc#862 busy-loop.
pub struct PacerInterceptor {
    pacer: LeakyBucket,
    queue: VecDeque<TaggedPacket>,
    queue_limit: usize,
    mode: PaceMode,
    /// Paced bits sent recently; feeds the send-rate mode.
    sent: SendRate,
    /// SSRCs of local audio streams, which skip the queue.
    audio_ssrcs: FastSet<u32>,
    /// Packets refused because the queue was full.
    dropped: u64,
    /// Packets the budget has released, waiting to join the belt.
    released: VecDeque<TaggedPacket>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
    /// Outbound packets ready for the next interceptor: what passed through, plus
    /// anything this one generated.
    write_queue: VecDeque<TaggedPacket>,
}

impl PacerInterceptor {
    fn new(pacer: LeakyBucket, queue_limit: usize, mode: PaceMode) -> Self {
        Self {
            mode,
            sent: SendRate::default(),
            audio_ssrcs: FastSet::default(),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            released: VecDeque::new(),
            pacer,
            queue: VecDeque::new(),
            queue_limit: queue_limit.max(1),
            dropped: 0,
        }
    }

    /// The pacing bucket, for a bandwidth estimator to drive.
    pub fn pacer(&self) -> &LeakyBucket {
        &self.pacer
    }

    /// The pacing bucket, mutably — this is where `set_target_bitrate` is reached.
    pub fn pacer_mut(&mut self) -> &mut LeakyBucket {
        &mut self.pacer
    }

    /// How many packets are waiting to be released.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// How many packets have been refused because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The size of a packet on the wire, in bits — the unit the budget is kept in.
    fn bits_of(packet: &TaggedPacket) -> f64 {
        match &packet.message.packet {
            Packet::Rtp(rtp) => (rtp.marshal_size() * 8) as f64,
            Packet::Rtcp(_) => 0.0,
        }
    }

    /// In the send-rate mode, set the rate from what was sent over the last second.
    fn update_rate(&mut self, now: Instant) {
        if let PaceMode::SendRate {
            multiplier,
            min_bitrate,
        } = self.mode
        {
            let rate = (self.sent.bits_per_second(now) * multiplier).max(min_bitrate);
            self.pacer.set_target_bitrate(rate);
        }
    }

    /// The instant the head of the queue can next be released.
    fn next_release(&self) -> Option<Instant> {
        let head = self.queue.front()?;
        self.pacer.releasable_at(Self::bits_of(head))
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for PacerInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // Follow the congestion controller's estimate.
        //
        // It arrives on the **read** leg because that is the only one it can cross on. The
        // controller is wire-most, so on the write leg it is the last interceptor to see a packet
        // and anything it attached would already have gone past here. On the read leg it is the
        // first, and this is downstream of it — so the feedback packet that produced the estimate
        // carries it here on its way to the application.
        //
        // Observed, not consumed: the packet carries on with the attribute attached, so anything
        // further along reads the same number.
        if matches!(self.mode, PaceMode::FollowTarget)
            && let Some(Attribute::TargetBitrateChanged { bits_per_second }) =
                msg.message.get(&Attribute::TargetBitrateChanged {
                    bits_per_second: 0.0,
                })
        {
            self.pacer.set_target_bitrate(*bits_per_second);
        }

        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        // No estimate is read here. It was, once — but the congestion controller sits wire-*ward*
        // of the pacer, so on the write leg it never sees a packet before this interceptor does and
        // the branch had no possible producer. If an application-set target is ever wanted it comes
        // back with its own `RTCEvent` variant, and a test.

        // RTCP is control traffic and mostly time-sensitive — feedback is only useful while it is
        // fresh — so it is not paced.
        if matches!(msg.message.packet, Packet::Rtcp(_)) {
            self.write_queue.push_back(msg);
            return Ok(());
        }

        // Audio is small and latency-sensitive: held behind a video backlog it arrives late, so it
        // goes out like RTCP and is not metered.
        if let Packet::Rtp(rtp) = &msg.message.packet
            && self.audio_ssrcs.contains(&rtp.header.ssrc)
        {
            self.write_queue.push_back(msg);
            return Ok(());
        }

        // Keeping the budget current at enqueue time is what lets `poll_timeout` compute a
        // deadline that is never in the past, even before the first `handle_timeout`.
        self.pacer.refill(msg.now);
        self.update_rate(msg.now);

        // Nothing waits ahead of it and the budget covers it: it leaves in the call that wrote it,
        // exactly as `handle_timeout(msg.now)` would let it, instead of waiting for a wake-up
        // that only exists to say so. Behind a backlog it takes its turn in the queue, so the
        // order within a stream never changes.
        let bits = Self::bits_of(&msg);
        if self.queue.is_empty() && self.pacer.can_release(bits) {
            self.pacer.consume(bits);
            self.sent.record(msg.now, bits);
            self.released.push_back(msg);
            return Ok(());
        }

        if self.queue.len() >= self.queue_limit {
            // Refuse the arrival rather than evicting something already queued: the queued
            // packets are older, and dropping one of those would put a hole in the middle of a
            // stream that the receiver would have to recover from.
            self.dropped += 1;
            // Refused, so it never leaves.
            return Ok(());
        }

        // Held: it leaves later, from `poll_write`, when the budget allows.
        self.queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<TaggedPacket> {
        // Unpaced traffic goes first — RTCP is only useful while it is fresh, and holding it
        // behind the budget would be pacing it after all.
        self.write_queue
            .pop_front()
            .or_else(|| self.released.pop_front())
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        self.pacer.refill(now);
        self.update_rate(now);

        while let Some(head) = self.queue.front() {
            let bits = Self::bits_of(head);
            if !self.pacer.can_release(bits) {
                break;
            }

            let mut packet = self.queue.pop_front().expect("front just checked");
            self.pacer.consume(bits);
            self.sent.record(now, bits);
            // Rule 3: the packet departs now. Anything below recording departure — the send
            // history congestion control reads — must see the release instant, not the enqueue
            // instant, or this queueing delay is charged to the network.
            packet.now = now;
            // Queued for `poll_write`, which puts it back on the belt so it traverses every
            // interceptor ahead — numbering, and the send history reading the release instant just set.
            self.released.push_back(packet);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.next_release()
    }
}

impl Interceptor for PacerInterceptor {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        if info.mime_type.to_ascii_lowercase().starts_with("audio/") {
            self.audio_ssrcs.insert(info.ssrc);
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.audio_ssrcs.remove(&info.ssrc);
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttributedPacket;
    use shared::TransportContext;

    /// 1500 bytes on the wire.
    const PACKET_BITS: f64 = 12_000.0;

    fn stream(ssrc: u32, mime_type: &str) -> StreamInfo {
        StreamInfo {
            ssrc,
            mime_type: mime_type.to_string(),
            ..Default::default()
        }
    }

    fn rtp(now: Instant, ssrc: u32, sequence_number: u16) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    ssrc,
                    sequence_number,
                    ..Default::default()
                },
                payload: vec![0u8; 1488].into(),
            })),
        }
    }

    fn sequence(packet: &TaggedPacket) -> u16 {
        match &packet.message.packet {
            Packet::Rtp(rtp) => rtp.header.sequence_number,
            Packet::Rtcp(_) => unreachable!("only RTP is written"),
        }
    }

    fn drain(pacer: &mut PacerInterceptor) -> Vec<u16> {
        std::iter::from_fn(|| pacer.poll_write())
            .map(|packet| sequence(&packet))
            .collect()
    }

    #[test]
    fn audio_goes_out_before_a_queued_video_backlog() {
        let now = Instant::now();
        let mut pacer = PacerBuilder::new().with_send_rate_multiplier(2.0).build();
        pacer.bind_local_stream(&stream(1, "video/VP8"));
        pacer.bind_local_stream(&stream(2, "audio/opus"));

        for seq in 0..5 {
            pacer.handle_write(rtp(now, 1, seq)).unwrap();
        }
        pacer.handle_write(rtp(now, 2, 100)).unwrap();

        // The budget covers the first video packet, which left when it was written; the audio
        // written after it still goes ahead of it, and the other four wait.
        assert_eq!(vec![100, 0], drain(&mut pacer));
        assert_eq!(4, pacer.queued());
    }

    #[test]
    fn unbinding_forgets_the_audio_ssrc() {
        let now = Instant::now();
        let mut pacer = PacerBuilder::new().with_send_rate_multiplier(2.0).build();
        let audio = stream(2, "audio/opus");
        pacer.bind_local_stream(&audio);
        pacer.unbind_local_stream(&audio);

        // The budget covers one packet: the first leaves, the second is held like any video.
        pacer.handle_write(rtp(now, 2, 1)).unwrap();
        pacer.handle_write(rtp(now, 2, 2)).unwrap();

        assert_eq!(vec![1], drain(&mut pacer));
        assert_eq!(1, pacer.queued(), "paced like anything else again");
    }

    #[test]
    fn the_pace_rate_follows_twice_the_send_rate() {
        let start = Instant::now();
        let mut pacer = PacerBuilder::new()
            .with_send_rate_multiplier(2.0)
            .with_min_bitrate(100_000.0)
            .build();
        assert_eq!(100_000.0, pacer.pacer().target_bitrate());

        // 50 packets over the first half second, released as the budget allows.
        for seq in 0..50 {
            pacer.handle_write(rtp(start, 1, seq)).unwrap();
        }
        let mut at = Duration::ZERO;
        while at < Duration::from_millis(500) {
            at += Duration::from_millis(1);
            pacer.handle_timeout(start + at).unwrap();
        }
        let sent_bits = (50 - pacer.queued()) as f64 * PACKET_BITS;
        assert!(sent_bits > 0.0);

        // Inside the window the rate is twice what went out, over one second.
        pacer
            .handle_timeout(start + Duration::from_millis(500))
            .unwrap();
        assert_eq!(2.0 * sent_bits, pacer.pacer().target_bitrate());

        // Two seconds on, the window is empty and the floor holds.
        pacer
            .handle_timeout(start + Duration::from_secs(3))
            .unwrap();
        assert_eq!(100_000.0, pacer.pacer().target_bitrate());
    }

    #[test]
    fn the_rate_never_falls_below_the_min_bitrate() {
        let now = Instant::now();
        let mut pacer = PacerBuilder::new().with_min_bitrate(3_000_000.0).build();
        pacer.handle_write(rtp(now, 1, 0)).unwrap();
        pacer.handle_timeout(now).unwrap();
        assert_eq!(3_000_000.0, pacer.pacer().target_bitrate());
    }

    #[test]
    fn the_send_rate_mode_ignores_the_congestion_target() {
        let now = Instant::now();
        let mut pacer = PacerBuilder::new().with_min_bitrate(500_000.0).build();
        let mut msg = TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])),
        };
        msg.message.add(Attribute::TargetBitrateChanged {
            bits_per_second: 9_000_000.0,
        });
        pacer.handle_read(msg).unwrap();
        assert_eq!(500_000.0, pacer.pacer().target_bitrate());
    }

    #[test]
    fn the_burst_is_five_milliseconds_of_the_rate() {
        // 8 Mb/s for 5 ms is 40 000 bits; the floor is one packet.
        let pacer = PacerBuilder::new().with_min_bitrate(8_000_000.0).build();
        assert_eq!(40_000.0, pacer.pacer().burst_bits());

        let slow = PacerBuilder::new().with_min_bitrate(100_000.0).build();
        assert_eq!(PACKET_BITS, slow.pacer().burst_bits());

        // The target-following mode keeps its 100 ms burst.
        let follow = PacerBuilder::new().with_target_bitrate(8_000_000.0).build();
        assert_eq!(800_000.0, follow.pacer().burst_bits());
    }

    #[test]
    fn a_backlog_leaves_in_five_millisecond_bursts() {
        let start = Instant::now();
        // 8 Mb/s: a burst is 40 000 bits, three whole packets.
        let mut pacer = PacerBuilder::new().with_min_bitrate(8_000_000.0).build();
        for seq in 0..20 {
            pacer.handle_write(rtp(start, 1, seq)).unwrap();
        }
        pacer.handle_timeout(start).unwrap();
        assert_eq!(3, drain(&mut pacer).len());
    }

    /// What a write to the pacer is in a replay: a run of packets, or a new target rate.
    enum Step {
        Write { ssrc: u32, first: u16, count: u16 },
        Rate(f64),
    }

    /// Plays `steps` against a pacer, firing each deadline it asks for before the step that comes
    /// after it, and returns what left as (sequence number, departure) in order. With `reference`
    /// the pacer is also woken at the instant of every write, which is what releasing at once is
    /// meant to be the same as.
    fn replay(
        mut pacer: PacerInterceptor,
        steps: &[(Duration, Step)],
        reference: bool,
    ) -> Vec<(u16, Duration)> {
        let start = Instant::now();
        let mut left = Vec::new();
        let collect = |pacer: &mut PacerInterceptor, left: &mut Vec<(u16, Duration)>| {
            while let Some(p) = pacer.poll_write() {
                left.push((sequence(&p), p.now.duration_since(start)));
            }
        };
        let fire_until = |pacer: &mut PacerInterceptor,
                          left: &mut Vec<(u16, Duration)>,
                          until: Option<Instant>| {
            for _ in 0..100_000 {
                let Some(due) = pacer
                    .poll_timeout()
                    .filter(|d| until.is_none_or(|u| *d <= u))
                else {
                    return;
                };
                pacer.handle_timeout(due).unwrap();
                collect(pacer, left);
            }
            panic!("the pacer never went quiet");
        };
        for (after, step) in steps {
            let at = start + *after;
            fire_until(&mut pacer, &mut left, Some(at));
            match *step {
                Step::Write { ssrc, first, count } => {
                    for n in 0..count {
                        pacer.handle_write(rtp(at, ssrc, first + n)).unwrap();
                        if reference {
                            pacer.handle_timeout(at).unwrap();
                        }
                        collect(&mut pacer, &mut left);
                    }
                }
                Step::Rate(bits_per_second) => {
                    pacer.pacer_mut().set_target_bitrate(bits_per_second);
                }
            }
        }
        fire_until(&mut pacer, &mut left, None);
        left
    }

    /// Frames of one to three packets every 33 ms, a keyframe of 40 packets, audio between, and
    /// (for a pacer that follows the target) the rate halved and raised again.
    fn a_stream_of_frames() -> Vec<(Duration, Step)> {
        let mut steps = Vec::new();
        let mut video = 0u16;
        for frame in 0..90u64 {
            let at = Duration::from_millis(frame * 33 + frame % 3);
            let count = match frame {
                15 => 40,
                _ => 1 + (frame % 3) as u16,
            };
            steps.push((
                at,
                Step::Write {
                    ssrc: 1,
                    first: video,
                    count,
                },
            ));
            video += count;
            steps.push((
                at + Duration::from_millis(7),
                Step::Write {
                    ssrc: 2,
                    first: 1000 + frame as u16,
                    count: 1,
                },
            ));
            if frame == 40 {
                steps.push((at + Duration::from_millis(9), Step::Rate(400_000.0)));
            }
            if frame == 60 {
                steps.push((at + Duration::from_millis(9), Step::Rate(6_000_000.0)));
            }
        }
        steps
    }

    fn bound(mut pacer: PacerInterceptor) -> PacerInterceptor {
        pacer.bind_local_stream(&stream(1, "video/VP8"));
        pacer.bind_local_stream(&stream(2, "audio/opus"));
        pacer
    }

    #[test]
    fn immediate_release_matches_the_timeout_schedule() {
        let send_rate = || {
            bound(
                PacerBuilder::new()
                    .with_send_rate_multiplier(2.0)
                    .with_min_bitrate(3_000_000.0)
                    .with_burst_window(Duration::from_millis(5))
                    .build(),
            )
        };
        let follow = || {
            bound(
                PacerBuilder::new()
                    .with_target_bitrate(1_500_000.0)
                    .with_burst_window(Duration::from_millis(5))
                    .build(),
            )
        };
        for (name, pacer) in [("send rate", send_rate as fn() -> _), ("target", follow)] {
            let steps = a_stream_of_frames();
            let now = replay(pacer(), &steps, false);
            let then = replay(pacer(), &steps, true);
            assert!(
                now.len() > 150,
                "{name}: the replay sent {} packets",
                now.len()
            );
            assert_eq!(
                then, now,
                "{name}: the same packets leave at the same instants"
            );
        }
    }

    #[test]
    fn a_packet_behind_a_backlog_waits_its_turn() {
        let start = Instant::now();
        let mut pacer = PacerBuilder::new().with_send_rate_multiplier(2.0).build();
        for seq in 0..4 {
            pacer.handle_write(rtp(start, 1, seq)).unwrap();
        }
        assert_eq!(vec![0], drain(&mut pacer));
        assert_eq!(3, pacer.queued());

        // Long enough for the budget to cover a packet again, without a timeout since: the new
        // packet still goes behind the three that wait, and nothing leaves before the timeout.
        let later = start + Duration::from_millis(20);
        pacer.handle_write(rtp(later, 1, 4)).unwrap();
        assert!(pacer.poll_write().is_none());
        assert_eq!(4, pacer.queued());

        let mut order = Vec::new();
        for _ in 0..8 {
            let Some(due) = pacer.poll_timeout() else {
                break;
            };
            pacer.handle_timeout(due.max(later)).unwrap();
            order.extend(drain(&mut pacer));
        }
        assert_eq!(vec![1, 2, 3, 4], order);
    }

    #[test]
    fn audio_written_after_video_is_not_held() {
        let now = Instant::now();
        let mut pacer = PacerBuilder::new().with_send_rate_multiplier(2.0).build();
        pacer.bind_local_stream(&stream(1, "video/VP8"));
        pacer.bind_local_stream(&stream(2, "audio/opus"));

        // One video packet leaves at once, three more queue, then a voice packet arrives.
        for seq in 0..4 {
            pacer.handle_write(rtp(now, 1, seq)).unwrap();
        }
        pacer.handle_write(rtp(now, 2, 100)).unwrap();

        assert_eq!(
            vec![100, 0],
            drain(&mut pacer),
            "voice goes first, unmetered"
        );
        assert_eq!(3, pacer.queued());
    }

    #[test]
    fn the_send_rate_counts_immediate_releases() {
        let start = Instant::now();
        let mut pacer = PacerBuilder::new()
            .with_send_rate_multiplier(2.0)
            .with_min_bitrate(10_000.0)
            .build();

        // The budget covers the packet: it leaves in the write, with no timeout.
        pacer.handle_write(rtp(start, 1, 0)).unwrap();
        assert_eq!(vec![0], drain(&mut pacer));
        assert_eq!(0, pacer.queued());

        // Twice what went out over the window.
        pacer
            .handle_timeout(start + Duration::from_millis(500))
            .unwrap();
        assert_eq!(
            2.0 * PACKET_BITS,
            pacer.pacer().target_bitrate(),
            "the packet that left at once is part of the rate"
        );
    }
}
