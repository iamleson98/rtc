//! A fast hasher for the integer keys on the packet path: SSRCs, sequence numbers and the like.
//!
//! The standard hasher (SipHash) costs more than the map lookup it feeds, and these keys are a
//! single `u32`, `u16` or `u64`. [`FastBuildHasher`] mixes each written word with a multiply
//! (Fibonacci hashing) and finishes with a second multiply and a shift, because the hash table
//! picks its bucket from the low bits and its control byte from the high ones: a plain multiply
//! leaves the low bits as poor as the key's own, and a single fold of the high half onto the low
//! one still clumps strided keys (stride 16 put a fifth of the keys of a 4096-slot table in too few
//! buckets in a measurement), which sequence numbers stepping by a layer count would produce.
//!
//! The multiplier is random per process, so a remote peer who chooses SSRCs or sequence numbers
//! cannot aim them at one bucket. That is not a cryptographic guarantee, so the maps a peer can
//! insert into still carry their own bound on the number of entries.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::sync::OnceLock;

/// A `HashMap` that hashes with [`FastBuildHasher`]. Build it with `FastMap::default()`.
pub type FastMap<K, V> = HashMap<K, V, FastBuildHasher>;

/// A `HashSet` that hashes with [`FastBuildHasher`]. Build it with `FastSet::default()`.
pub type FastSet<K> = HashSet<K, FastBuildHasher>;

/// The 64-bit Fibonacci constant, `2^64 / phi`: the multiplier used when a fixed one is asked for.
pub const FIBONACCI: u64 = 0x9E37_79B9_7F4A_7C15;

/// The multiplier of the finishing step (a 64-bit odd constant with well-spread bits).
const FINISH: u64 = 0xD6E8_FEB8_6659_FD93;

/// Builds [`FastHasher`]s that share one multiplier.
#[derive(Clone, Copy, Debug)]
pub struct FastBuildHasher {
    multiplier: u64,
}

impl FastBuildHasher {
    /// A builder with a chosen multiplier, made odd so the multiply is a bijection on `u64`.
    ///
    /// For tests only, to get the same hashes every run or to try many multipliers: a chosen
    /// multiplier can be a weak one (a sparse one puts strided keys in one bucket), and the
    /// process-wide random one of [`Default`] is what keeps a peer from aiming keys at a bucket.
    #[cfg(test)]
    pub(crate) fn with_multiplier(multiplier: u64) -> Self {
        Self {
            multiplier: multiplier | 1,
        }
    }
}

impl Default for FastBuildHasher {
    /// The process-wide random multiplier, drawn on first use.
    fn default() -> Self {
        static MULTIPLIER: OnceLock<u64> = OnceLock::new();
        let multiplier = *MULTIPLIER.get_or_init(|| {
            // The top bit set and the low bit set: a multiplier with few significant bits
            // spreads small keys no better than the keys themselves.
            rand::random::<u64>() | 0x8000_0000_0000_0001
        });
        Self { multiplier }
    }
}

impl BuildHasher for FastBuildHasher {
    type Hasher = FastHasher;

    fn build_hasher(&self) -> FastHasher {
        FastHasher {
            state: 0,
            multiplier: self.multiplier,
        }
    }
}

/// The hasher [`FastBuildHasher`] builds.
#[derive(Clone, Copy, Debug)]
pub struct FastHasher {
    state: u64,
    multiplier: u64,
}

impl FastHasher {
    #[inline]
    fn add(&mut self, word: u64) {
        self.state = (self.state.rotate_left(26) ^ word).wrapping_mul(self.multiplier);
    }
}

impl Hasher for FastHasher {
    #[inline]
    fn finish(&self) -> u64 {
        let folded = (self.state ^ (self.state >> 32)).wrapping_mul(FINISH);
        folded ^ (folded >> 32)
    }

    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.add(u64::from_le_bytes(word));
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(u64::from(i));
    }

    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(u64::from(i));
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(u64::from(i));
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }

    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{BuildHasher, Hash};

    /// How many of `keys` land in each of `buckets` buckets, picking the bucket the way the hash
    /// table does: from the low bits.
    fn loads<K: Hash>(
        build: &FastBuildHasher,
        keys: impl Iterator<Item = K>,
        buckets: usize,
    ) -> Vec<u32> {
        let mut loads = vec![0u32; buckets];
        for key in keys {
            loads[(build.hash_one(key) as usize) & (buckets - 1)] += 1;
        }
        loads
    }

    /// Hashing `keys` spreads like random: with as many keys as buckets, the fullest bucket of a
    /// random assignment holds about 6 and the share of empty buckets is about 1/e.
    fn assert_spread(build: &FastBuildHasher, keys: impl Iterator<Item = u64>, what: &str) {
        let buckets = 4096;
        let loads = loads(build, keys.take(buckets), buckets);
        let fullest = *loads.iter().max().unwrap();
        let empty = loads.iter().filter(|&&n| n == 0).count() as f64 / buckets as f64;
        assert!(fullest <= 12, "{what}: fullest bucket holds {fullest}");
        assert!(
            (0.30..0.45).contains(&empty),
            "{what}: {empty:.3} of the buckets are empty"
        );
    }

    #[test]
    fn spreads_sequential_and_strided_keys() {
        let builders = [
            FastBuildHasher::with_multiplier(FIBONACCI),
            FastBuildHasher::default(),
        ];
        for build in &builders {
            assert_spread(build, 0..u64::MAX, "sequential");
            for stride in [2u64, 3, 4, 16, 256, 4096, 1 << 16, 1 << 24] {
                assert_spread(build, (0..u64::MAX).map(|i| i * stride), "strided");
            }
            // A 16-bit sequence number counting from a wrapped start.
            assert_spread(
                build,
                (0..u64::MAX).map(|i| (65_000 + i) & 0xffff),
                "wrapping sequence",
            );
            // SSRCs that differ only in their high bytes.
            assert_spread(build, (0..u64::MAX).map(|i| i << 20), "high-bit SSRCs");
        }
    }

    #[test]
    fn the_high_bits_that_pick_the_control_byte_are_spread_too() {
        let build = FastBuildHasher::with_multiplier(FIBONACCI);
        let mut seen = [0u32; 128];
        for key in 0..4096u64 {
            seen[(build.hash_one(key) >> 57) as usize] += 1;
        }
        assert!(seen.iter().all(|&n| n > 0), "some 7-bit tags never occur");
        assert!(*seen.iter().max().unwrap() <= 64);
    }

    #[test]
    fn a_tuple_key_hashes_both_halves() {
        let build = FastBuildHasher::with_multiplier(FIBONACCI);
        assert_ne!(build.hash_one((1u32, 2u16)), build.hash_one((2u32, 1u16)));
        assert_ne!(build.hash_one((1u32, 2u16)), build.hash_one((1u32, 3u16)));
    }

    /// The `(ssrc, sequence number)` keys the interceptors use spread like random whichever
    /// multiplier the process drew, not only for the fixed one the other tests use: the fullest
    /// bucket stays near what chance gives (about 6 for 4096 keys in 4096 buckets).
    #[test]
    fn tuple_keys_spread_under_any_random_multiplier() {
        type Keys = Box<dyn Fn() -> Box<dyn Iterator<Item = (u32, u16)>>>;
        let patterns: [(&str, Keys); 5] = [
            (
                "one stream, counting sequence",
                Box::new(|| Box::new((0..4096u32).map(|i| (0x1234_5678, i as u16)))),
            ),
            (
                "one sequence number, many SSRCs",
                Box::new(|| Box::new((0..4096u32).map(|i| (0x1000_0000 + i, 7u16)))),
            ),
            (
                "three layers, counting sequence",
                Box::new(|| {
                    Box::new((0..4096u32).map(|i| (0x1000_0000 + (i % 3) * 0x100, (i / 3) as u16)))
                }),
            ),
            (
                "strided SSRCs and sequence numbers",
                Box::new(|| Box::new((0..4096u32).map(|i| (i << 12, (i * 16) as u16)))),
            ),
            (
                "SSRCs in step with the sequence",
                Box::new(|| Box::new((0..4096u32).map(|i| (i, i as u16)))),
            ),
        ];
        for _ in 0..256 {
            let multiplier: u64 = rand::random();
            let build = FastBuildHasher::with_multiplier(multiplier);
            for (what, keys) in &patterns {
                let loads = loads(&build, keys(), 4096);
                let fullest = *loads.iter().max().unwrap();
                assert!(
                    fullest <= 14,
                    "{what}: fullest bucket holds {fullest} under multiplier {multiplier:#x}"
                );
            }
        }
    }

    #[test]
    fn behaves_as_a_map_and_a_set() {
        let mut map = FastMap::default();
        let mut set = FastSet::default();
        for i in 0..1000u32 {
            map.insert(i.wrapping_mul(0x0100_0193), i);
            set.insert(i as u16);
        }
        assert_eq!(map.len(), 1000);
        assert_eq!(set.len(), 1000);
        assert_eq!(map.get(&5u32.wrapping_mul(0x0100_0193)), Some(&5));
        assert!(!set.contains(&1000));
    }

    #[test]
    fn the_default_multiplier_is_fixed_for_the_process() {
        assert_eq!(
            FastBuildHasher::default().hash_one(7u32),
            FastBuildHasher::default().hash_one(7u32)
        );
    }
}
