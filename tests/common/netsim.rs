//! Seeded network weather for [`Sim`](super::sim::Sim): a base path (delay, jitter, reordering)
//! and a schedule of phases like the real soak's `benchmarks/soak/netem.sh` cycle: clean, random
//! loss, burst loss, a bandwidth cap, a short outage, and the recovery after it, with the odd
//! 30, 60 or 120 second outage. The same seed always draws the same weather.
#![allow(dead_code)]

use std::time::Duration;

use super::sim::{GilbertElliott, Link, Rng};

/// What one direction of the path suffers during a phase.
#[derive(Clone, Copy, Debug)]
pub enum Impairment {
    Clean,
    /// Uniform random loss of this fraction.
    Loss(f64),
    /// Gilbert-Elliott bursts: about 5 % lost, in runs of about 5 datagrams.
    Burst,
    /// A bandwidth cap, with the queue in front of it, and 80 ms more delay. The soak's senders
    /// do not adapt their rate, so the caps drawn stay above what they send (about 0.7 Mbit/s).
    Bandwidth(u64),
    /// Every datagram is lost.
    Outage,
}

/// How long a phase lasts and what each direction suffers meanwhile.
#[derive(Clone, Copy, Debug)]
pub struct Phase {
    pub name: &'static str,
    pub duration: Duration,
    pub a_to_b: Impairment,
    pub b_to_a: Impairment,
}

impl Phase {
    pub fn is_outage(&self) -> bool {
        matches!(self.a_to_b, Impairment::Outage) && matches!(self.b_to_a, Impairment::Outage)
    }
}

/// The path a seed lives on when nothing is wrong with it.
#[derive(Clone, Copy, Debug)]
pub struct Path {
    pub delay: Duration,
    pub jitter: Duration,
    pub reorder: f64,
}

const UNCAPPED: u64 = 1_000_000_000;
const QUEUE: Duration = Duration::from_millis(300);

impl Path {
    pub fn draw(rng: &mut Rng) -> Path {
        Path {
            delay: Duration::from_millis(rng.range(5, 60)),
            jitter: Duration::from_millis(rng.range(0, 8)),
            reorder: rng.chance() * 0.01,
        }
    }

    /// One direction of the path, clean, with its own generator.
    pub fn link(&self, seed: u64) -> Link {
        let mut link = Link::new(UNCAPPED, self.delay, QUEUE).seeded(seed);
        link.jitter = self.jitter;
        link.reorder = self.reorder;
        link.reorder_hold = Duration::from_millis(20);
        link
    }

    /// Puts `impairment` on `link`, replacing whatever the previous phase did to it.
    pub fn impair(&self, link: &mut Link, impairment: Impairment) {
        link.bits_per_second = UNCAPPED;
        link.delay = self.delay;
        link.loss = 0.0;
        link.burst = None;
        link.outage = false;
        match impairment {
            Impairment::Clean => {}
            Impairment::Loss(fraction) => link.loss = fraction,
            Impairment::Burst => {
                link.burst = Some(GilbertElliott {
                    to_bad: 0.0105,
                    to_good: 0.2,
                    loss_bad: 1.0,
                });
            }
            Impairment::Bandwidth(bps) => {
                link.bits_per_second = bps;
                link.delay = self.delay + Duration::from_millis(80);
            }
            Impairment::Outage => link.outage = true,
        }
    }
}

/// The phases of `span` of virtual time, drawn from `rng`. It opens clean, every outage is
/// followed by a clean recovery phase, and the last phase is clean so a run can settle.
pub fn schedule(rng: &mut Rng, span: Duration) -> Vec<Phase> {
    const RECOVERY: Duration = Duration::from_secs(90);
    let mut phases = vec![Phase {
        name: "clean",
        duration: Duration::from_secs(20),
        a_to_b: Impairment::Clean,
        b_to_a: Impairment::Clean,
    }];
    let mut total = phases[0].duration;
    let tail = Duration::from_secs(30);
    while total + tail < span {
        let roll = rng.range(0, 99);
        let length = Duration::from_secs(rng.range(15, 75));
        let mut phase = |name, duration, a_to_b, b_to_a| {
            let phase = Phase {
                name,
                duration,
                a_to_b,
                b_to_a,
            };
            total += duration;
            phase
        };
        // Loss, bursts and caps hit one direction now and then, as a real access link does.
        let one_way = rng.chance() < 0.2;
        let (hit_a, hit_b) = if one_way && rng.chance() < 0.5 {
            (true, false)
        } else if one_way {
            (false, true)
        } else {
            (true, true)
        };
        let pick = |impairment: Impairment, hit: bool| {
            if hit { impairment } else { Impairment::Clean }
        };
        match roll {
            0..=39 => phases.push(phase("clean", length, Impairment::Clean, Impairment::Clean)),
            40..=54 => {
                let loss = Impairment::Loss(0.01 + rng.chance() * 0.04);
                phases.push(phase("loss", length, pick(loss, hit_a), pick(loss, hit_b)));
            }
            55..=69 => phases.push(phase(
                "burst",
                length,
                pick(Impairment::Burst, hit_a),
                pick(Impairment::Burst, hit_b),
            )),
            70..=94 => {
                let cap = Impairment::Bandwidth(rng.range(1000, 2500) * 1000);
                phases.push(phase("bw", length, pick(cap, hit_a), pick(cap, hit_b)));
            }
            _ => {
                let outage = match rng.range(0, 99) {
                    0..=79 => 5,
                    80..=91 => 30,
                    92..=96 => 60,
                    _ => 120,
                };
                phases.push(phase(
                    "outage",
                    Duration::from_secs(outage),
                    Impairment::Outage,
                    Impairment::Outage,
                ));
                phases.push(phase(
                    "recover",
                    RECOVERY,
                    Impairment::Clean,
                    Impairment::Clean,
                ));
            }
        }
    }
    phases.push(Phase {
        name: "clean",
        duration: tail,
        a_to_b: Impairment::Clean,
        b_to_a: Impairment::Clean,
    });
    phases
}
