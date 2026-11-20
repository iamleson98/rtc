//! A sliding byte counter in fixed-size memory, for the retransmission budget.

use std::time::{Duration, Instant};

/// Buckets the window is cut into; the counter is exact to one bucket (a tenth of the window).
const BUCKETS: usize = 10;

/// Bytes seen over the last `window`, kept in [`BUCKETS`] time slots so memory does not depend
/// on the packet rate.
#[derive(Debug, Clone)]
pub(super) struct RateWindow {
    /// Width of one slot in milliseconds, at least 1.
    slot_ms: u64,
    /// First instant the window saw; slots are numbered from here.
    origin: Option<Instant>,
    /// Slot number and bytes, indexed by slot number modulo [`BUCKETS`].
    buckets: [(u64, usize); BUCKETS],
}

impl RateWindow {
    pub(super) fn new(window: Duration) -> Self {
        Self {
            slot_ms: (window.as_millis() as u64 / BUCKETS as u64).max(1),
            origin: None,
            buckets: [(0, 0); BUCKETS],
        }
    }

    fn slot(&mut self, now: Instant) -> u64 {
        let origin = *self.origin.get_or_insert(now);
        now.saturating_duration_since(origin).as_millis() as u64 / self.slot_ms
    }

    /// Record `bytes` at `now`.
    pub(super) fn add(&mut self, now: Instant, bytes: usize) {
        let slot = self.slot(now);
        let bucket = &mut self.buckets[(slot % BUCKETS as u64) as usize];
        if bucket.0 != slot {
            *bucket = (slot, 0);
        }
        bucket.1 += bytes;
    }

    /// How long ago the first byte was recorded; zero before any.
    pub(super) fn age(&self, now: Instant) -> Duration {
        self.origin.map_or(Duration::ZERO, |origin| {
            now.saturating_duration_since(origin)
        })
    }

    /// Bytes recorded in the window ending at `now`.
    pub(super) fn sum(&mut self, now: Instant) -> usize {
        let slot = self.slot(now);
        self.buckets
            .iter()
            .filter(|(s, _)| *s + BUCKETS as u64 > slot && *s <= slot)
            .map(|(_, bytes)| bytes)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_bytes_leave_the_window() {
        let t0 = Instant::now();
        let mut w = RateWindow::new(Duration::from_millis(500));
        w.add(t0, 100);
        w.add(t0 + Duration::from_millis(200), 50);
        assert_eq!(w.sum(t0 + Duration::from_millis(300)), 150);
        assert_eq!(w.sum(t0 + Duration::from_millis(520)), 50);
        assert_eq!(w.sum(t0 + Duration::from_millis(800)), 0);
    }
}
