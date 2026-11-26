#!/usr/bin/env python3
"""Self-test of report.py on small generated runs: python3 -m unittest -v benchmarks/soak/test_report.py"""
import json
import math
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report  # noqa: E402

T0 = 1_700_000_000_000  # ms
STEP = 5  # s between samples


def ts(t):
    return T0 + int(t * 1000)


def phase(t, name, group="impaired"):
    return {"ts": ts(t), "impl": "netem", "arch": "x86_64", "kind": "phase", "id": "netem", "group": group, "name": name}


def event(impl, t, who, what, detail="", group="impaired", **more):
    return {"ts": ts(t), "impl": impl, "arch": "x86_64", "kind": "event", "id": who, "what": what, "detail": detail,
            "group": group, **more}


def track(impl, rid, group, end, flowing=lambda t: True, start=0, media="video", bytes_per_s=0, freezes=lambda t: 0,
          arch="x86_64", frames_of=lambda t: 150, freeze_ms=lambda t: 0):
    """recv rows every 5 s from start to end; counters grow while `flowing(t)` (`frames_of(t)` a step);
    `freezes` and `freeze_ms` give the cumulative counters."""
    rows, frames, packets, nbytes = [], 0, 0, 0
    t = start
    while t <= end:
        if flowing(t) and t > start:
            frames += frames_of(t)
            packets += 400
            nbytes += int(bytes_per_s * STEP)
        rows.append({"ts": ts(t), "impl": impl, "arch": arch, "kind": "recv", "id": rid, "media": media,
                     "group": group, "frames": frames, "freezes": freezes(t), "freeze_ms": freeze_ms(t), "packets": packets,
                     "lost": 0, "nack": 0, "pli": 0, "jitter_ms": 1.0, "rtt_ms": None, "audio_gap_ms": 0,
                     "bytes": nbytes, "duplicates": 0, "stalled": False})
        t += STEP
    return rows


def attack(t, aid, name, state, who=None, group="impaired", impl="abuse"):
    row = {"ts": ts(t), "impl": impl, "arch": "x86_64", "kind": "attack", "id": aid, "name": name, "state": state,
           "group": group, "seed": 7}
    if who is not None:
        row["who"] = who
    return row


def window(t0, t1, aid, name, who=None, group="impaired"):
    return [attack(t0, aid, name, "start", who, group), attack(t1, aid, name, "end", who, group)]


def proc(impl, end, cpu=50.0, rss=100.0, arch="x86_64"):
    return [{"ts": ts(t), "impl": impl, "arch": arch, "kind": "proc", "id": "sfu", "rss_mb": rss, "cpu_pct": cpu,
             "threads": 10, "fds": 20, "udp_rcvbuf_err": 0, "udp_sndbuf_err": 0} for t in range(0, end + 1, STEP)]


TIMELINE = [phase(0, "clean"), phase(60, "bw"), phase(120, "outage"), phase(125, "recover")]
END = 240
RULES = {"compare": [{"subject": "rtcd-rs", "baseline": "rtcd-go"}], "require_groups": ["clean", "impaired"],
         "min_clean_window_min": 1, "warmup_min": 0, "window_min": 1}


def side(impl, **kw):
    """A lesson-like run: a clean student, two impaired ones, the SFU process."""
    rows = list(TIMELINE) + proc(impl, END, **{k: kw[k] for k in ("cpu", "rss") if k in kw})
    rows += track(impl, "c01/video:teacher", "clean", END, bytes_per_s=kw.get("clean_bps", 200_000),
                  freezes=kw.get("clean_freezes", lambda t: 0), flowing=kw.get("clean_flow", lambda t: True),
                  freeze_ms=kw.get("clean_freeze_ms", lambda t: 0))
    rows += track(impl, "s17/video:teacher", "impaired", END, bytes_per_s=300_000,
                  flowing=lambda t: not (120 <= t < 125), **kw.get("impaired", {}))
    rows += kw.get("extra", [])
    return rows


def write(rows):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "x.jsonl")
    with open(p, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return p


def run_report(subject_rows, baseline_rows, rules=None):
    d = tempfile.mkdtemp()
    paths = [write(subject_rows), write(baseline_rows)]
    # One file per side, as the CI has them: the file name is the run.
    named = []
    for name, p in zip(("rtcd-rs-x86_64", "rtcd-go-x86_64"), paths):
        q = os.path.join(d, name + ".jsonl")
        os.rename(p, q)
        named.append(q)
    rules_path = os.path.join(d, "rules.json")
    with open(rules_path, "w") as f:
        json.dump(rules or RULES, f)
    status = report.main(["--rules", rules_path, "--out", os.path.join(d, "out")] + named)
    with open(os.path.join(d, "out", "summary.md")) as f:
        return status, f.read(), report.build_entities(report.load(named)), d


class Fixture(unittest.TestCase):
    def rows(self, **kw):
        """The subject's run with `extra` rows, and a plain baseline."""
        base = {k: v for k, v in kw.items() if k != "extra"}
        return side("rtcd-rs", **kw), side("rtcd-go", **base)


class PhaseAssignment(Fixture):
    def test_each_participant_follows_its_own_group(self):
        s, b = self.rows()
        _, _, ents, _ = run_report(s, b)
        e = next(e for e in ents if e.impl == "rtcd-rs")
        clean = next(x for x in e.series.values() if x.id.startswith("c01"))
        imp = next(x for x in e.series.values() if x.id.startswith("s17"))
        # The clean student is in `clean` whatever the network is doing to the others.
        self.assertEqual({i["phase"] for i in clean.ivs}, {"clean"})
        self.assertEqual({i["phase"] for i in imp.ivs}, {"clean", "bw", "outage", "recover"})
        self.assertEqual(next(i["phase"] for i in imp.ivs if 70 < i["t"] < 80), "bw")

    def test_receive_rate_is_per_participant_not_per_track(self):
        extra = track("rtcd-rs", "s17/screen:teacher", "impaired", END, bytes_per_s=100_000, media="video")
        s, b = self.rows(extra=extra)
        _, md, _, _ = run_report(s, b)
        # 300 + 100 kB/s on s17 = 3.2 Mbit/s in the bw phase; the baseline has one track (2.4).
        line = next(l for l in md.splitlines() if l.startswith("| impaired | bw | Receive Mbit/s per participant (mean)"))
        self.assertIn("| 3.20 |", line)


def lone_track(impl, start, **kw):
    """A lesson-like side whose only impaired receiver is the given track."""
    rows = list(TIMELINE) + proc(impl, END)
    rows += track(impl, "c01/video:teacher", "clean", END, bytes_per_s=200_000)
    return rows + track(impl, "s17/video:teacher", "impaired", END, start=start, bytes_per_s=300_000, **kw)


def lerp(t, t0, t1, total):
    """A counter that grows evenly from 0 at t0 to `total` at t1."""
    return total * min(max(t - t0, 0.0), t1 - t0) / (t1 - t0)


class OutageEpisode(Fixture):
    def side(self, impl, start):
        # A 4.9 s freeze from the outage's start; an open freeze counts at once, so it is booked
        # across the samples that see it.
        return lone_track(impl, start, flowing=lambda t: not (120 <= t < 125),
                          freeze_ms=lambda t: int(lerp(t, 120, 124.9, 4900)))

    def test_the_freeze_per_outage_does_not_depend_on_the_sampling_clock(self):
        code, md, ents, _ = run_report(self.side("rtcd-rs", 3.9), self.side("rtcd-go", 4.9))
        got = {e.impl: report.scope_metrics([e], "impaired", "outage", dict(report.DEFAULTS))["outage_freeze_ms"]
               for e in ents}
        self.assertAlmostEqual(got["rtcd-rs"], 4900, delta=49)
        self.assertAlmostEqual(got["rtcd-go"], 4900, delta=49)
        self.assertEqual(code, 0, md)


class FrozenStream(Fixture):
    def side(self, impl, fps, freezes_per_step, ms_per_step):
        """In the bw phase (60 to 120 s) the track plays `fps` frames a second and freezes
        `freezes_per_step` times and `ms_per_step` ms in every sample."""
        return lone_track(impl, 0, frames_of=lambda t: int(fps * 5) if 60 < t <= 120 else 150,
                          freezes=lambda t: int(lerp(t, 60, 120, 12 * freezes_per_step)),
                          freeze_ms=lambda t: int(lerp(t, 60, 120, 12 * ms_per_step)))

    def test_a_dead_baseline_does_not_make_a_live_stuttering_subject_breach(self):
        # The baseline froze once for 96 % of the phase at 1 fps; the subject plays 6 fps in many short freezes.
        code, md, _, _ = run_report(self.side("rtcd-rs", 6, 1, 1000), self.side("rtcd-go", 1, 0.084, 4800))
        self.assertEqual(code, 0, md)

    def test_a_subject_that_plays_less_and_freezes_longer_breaches(self):
        code, md, _, _ = run_report(self.side("rtcd-rs", 1, 0.084, 4800), self.side("rtcd-go", 6, 1, 1000))
        self.assertEqual(code, 1, md)
        self.assertIn("Video frames / s", md)


    def test_the_outage_phase_has_no_frame_rate(self):
        # Too few intervals for a rate; the outage is scored per episode.
        slow = lone_track("rtcd-rs", 0, frames_of=lambda t: 5 if 120 < t <= 125 else 150)
        code, md, _, _ = run_report(slow, lone_track("rtcd-go", 0))
        self.assertEqual(code, 0, md)
        self.assertNotIn("| impaired | outage | Video frames", md)
        self.assertIn("| impaired | bw | Video frames", md)


class AttackFrozenTime(Fixture):
    def side(self, impl, freezes, ms):
        """An innocent impaired receiver that freezes `freezes` times, `ms` ms in all, in a window (100 to 110 s)."""
        rows = list(TIMELINE) + proc(impl, END) + window(100, 110, "a1", "reorder", ["s17"])
        rows += track(impl, "c01/video:teacher", "clean", END, bytes_per_s=200_000)
        rows += track(impl, "s17/video:teacher", "impaired", END, bytes_per_s=300_000)
        return rows + track(impl, "s18/video:teacher", "impaired", END, bytes_per_s=300_000,
                            freezes=lambda t: int(lerp(t, 100, 110, freezes)),
                            freeze_ms=lambda t: int(lerp(t, 100, 110, ms)))

    def test_many_short_freezes_are_not_a_breach_when_the_frozen_time_is_less(self):
        code, md, _, _ = run_report(self.side("rtcd-rs", 4, 400), self.side("rtcd-go", 1, 4000), RULES)
        self.assertEqual(code, 0, md)
        self.assertIn("| reorder | Freeze ms / min (video) |", md)

    def test_more_frozen_time_breaches(self):
        code, md, _, _ = run_report(self.side("rtcd-rs", 4, 4000), self.side("rtcd-go", 1, 400), RULES)
        self.assertEqual(code, 1, md)
        self.assertIn("attack / reorder / Freeze ms / min (video)", md)


class Recovery(Fixture):
    def test_tracks_of_departed_participants_are_not_unrecovered(self):
        # s18's session is closed by the SFU during the outage: its track ends; s19 stays but never gets media back.
        gone = track("rtcd-rs", "s18/video:teacher", "impaired", 128)
        stuck = track("rtcd-rs", "s19/video:teacher", "impaired", END, flowing=lambda t: t < 120)
        ev = [event("rtcd-rs", 127, "s18", "error", "the SFU closed the session")]
        s, b = self.rows(extra=gone + stuck + ev)
        _, _, ents, _ = run_report(s, b)
        e = next(e for e in ents if e.impl == "rtcd-rs")
        rec = report.recoveries(e, "impaired", dict(report.DEFAULTS), report.departures(e))
        # s17 recovered within one sample, s19 never did, s18 is not a track that should have.
        self.assertEqual(len(rec), 2)
        self.assertEqual(sum(1 for x in rec if x == float("inf")), 1)
        m = report.scope_metrics([e], "impaired", None, dict(report.DEFAULTS))
        self.assertEqual((m["closes"], m["never"]), (1, 1))

    def test_unrecovered_seat_costs_downtime_until_the_end_of_the_run(self):
        ev = [event("rtcd-rs", 100, "s18", "error", "the SFU closed the session")]
        s, b = self.rows(extra=ev)
        _, _, ents, _ = run_report(s, b)
        e = next(e for e in ents if e.impl == "rtcd-rs")
        m = report.scope_metrics([e], "impaired", None, dict(report.DEFAULTS))
        self.assertAlmostEqual(m["downtime"], END - 100, delta=1)
        ev.append(event("rtcd-rs", 104, "s18", "rejoin", "connected again", downtime_ms=4000, attempts=1))
        s, b = self.rows(extra=ev)
        _, _, ents, _ = run_report(s, b)
        e = next(e for e in ents if e.impl == "rtcd-rs")
        m = report.scope_metrics([e], "impaired", None, dict(report.DEFAULTS))
        self.assertEqual((m["closes"], m["rejoins"]), (1, 1))
        self.assertAlmostEqual(m["downtime"], 4.0, delta=0.01)


class Compare(Fixture):
    def test_equal_runs_pass(self):
        s, b = self.rows()
        status, md, _, _ = run_report(s, b)
        self.assertEqual(status, 0, md)
        self.assertIn("gates held", md)

    def test_a_worse_subject_breaches(self):
        s, b = side("rtcd-rs", cpu=90.0), side("rtcd-go", cpu=50.0)
        status, md, _, _ = run_report(s, b)
        self.assertEqual(status, 1)
        self.assertIn("SFU CPU % of a core (mean)", md.split("## Breaches")[1].split("## ")[0])

    def test_within_the_ratio_passes_and_a_close_is_a_breach(self):
        s, b = side("rtcd-rs", cpu=60.0), side("rtcd-go", cpu=50.0)  # 60 <= 50 x 1.25 + 5
        self.assertEqual(run_report(s, b)[0], 0)
        close = [event("rtcd-rs", 70, "s17", "error", "the SFU closed the session"),
                 event("rtcd-rs", 72, "s17", "rejoin", "connected again", downtime_ms=2000, attempts=1)]
        status, md, _, _ = run_report(side("rtcd-rs", extra=close), side("rtcd-go"))
        self.assertEqual(status, 1)
        self.assertIn("SFU-closed sessions", md.split("## Breaches")[1].split("## ")[0])

    def test_a_better_subject_passes(self):
        close = [event("rtcd-go", 70, "s17", "error", "the SFU closed the session")]
        self.assertEqual(run_report(side("rtcd-rs"), side("rtcd-go", extra=close))[0], 0)

    def test_missing_baseline_fails_loudly(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "rtcd-rs-x86_64.jsonl")
        with open(p, "w") as f:
            for r in side("rtcd-rs"):
                f.write(json.dumps(r) + "\n")
        rules = os.path.join(d, "rules.json")
        with open(rules, "w") as f:
            json.dump(RULES, f)
        status = report.main(["--rules", rules, "--out", os.path.join(d, "out"), p])
        self.assertEqual(status, 1)
        with open(os.path.join(d, "out", "summary.md")) as f:
            self.assertIn("no baseline data on x86_64", f.read())

    def test_baseline_on_another_architecture_does_not_count(self):
        d = tempfile.mkdtemp()
        p, q = os.path.join(d, "rtcd-rs-x86_64.jsonl"), os.path.join(d, "rtcd-go-aarch64.jsonl")
        for path, rows in ((p, side("rtcd-rs")), (q, [dict(r, arch="aarch64") for r in side("rtcd-go")])):
            with open(path, "w") as f:
                for r in rows:
                    f.write(json.dumps(r) + "\n")
        rules = os.path.join(d, "rules.json")
        with open(rules, "w") as f:
            json.dump(RULES, f)
        self.assertEqual(report.main(["--rules", rules, "--out", os.path.join(d, "out"), p, q]), 1)


class CleanGroup(Fixture):
    def test_a_freeze_in_the_clean_group_fails_even_when_the_baseline_has_it_too(self):
        both = {"clean_freezes": lambda t: 1 if t > 100 else 0}
        status, md, _, _ = run_report(side("rtcd-rs", **both), side("rtcd-go", **both))
        self.assertEqual(status, 1)
        self.assertIn("clean group, subject Freezes (count) must be zero", md)

    def test_impaired_group_freezes_have_no_absolute_rule(self):
        imp = track("rtcd-rs", "s20/video:teacher", "impaired", END, freezes=lambda t: int(t // 10))
        impg = track("rtcd-go", "s20/video:teacher", "impaired", END, freezes=lambda t: int(t // 10))
        self.assertEqual(run_report(side("rtcd-rs", extra=imp), side("rtcd-go", extra=impg))[0], 0)

    def test_sfu_process_errors_fail(self):
        crash = [event("rtcd-rs", 200, "sfu", "error", "the SFU process is gone", group=None)]
        crash[0].pop("group")
        status, md, _, _ = run_report(side("rtcd-rs", extra=crash), side("rtcd-go"))
        self.assertEqual(status, 1)
        self.assertIn("SFU process errors", md)


class LessonEnd(Fixture):
    def test_receivers_stop_measuring_when_the_first_participant_stops(self):
        # The teacher stops at 200 s; the student's receiver sees nothing after that until its own
        # stop, which is the end of the lesson, not a stall of the server.
        rows = [r for r in side("rtcd-rs") if not (r["kind"] == "recv" and r["id"] == "s17/video:teacher")]
        tail = track("rtcd-rs", "s17/video:teacher", "impaired", END, flowing=lambda t: not (120 <= t < 125) and t < 200)
        rows += [dict(r, stalled=r["ts"] > ts(205)) for r in tail]
        rows += [event("rtcd-rs", 200, "c01", "leave", "stop", group="clean"),
                 event("rtcd-rs", 240, "s17", "leave", "stop")]
        status, md, _, _ = run_report(rows, side("rtcd-go"))
        self.assertEqual(status, 0, md)


class OutageDisconnects(Fixture):
    def test_an_ice_disconnect_the_outage_caused_is_not_counted(self):
        blip = [event("rtcd-rs", 124, "s17", "ice_state", "ice:disconnected"),
                event("rtcd-rs", 124.1, "s17", "ice_state", "ice:connected")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=blip), side("rtcd-go"))
        self.assertEqual(status, 0, md)

    def test_an_ice_disconnect_outside_the_outage_counts(self):
        blip = [event("rtcd-rs", 90, "s17", "ice_state", "ice:disconnected"),
                event("rtcd-rs", 91, "s17", "ice_state", "ice:connected")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=blip), side("rtcd-go"))
        self.assertEqual(status, 1)
        self.assertIn("ICE disconnects", md.split("## Breaches")[1].split("## ")[0])


    def test_an_ice_failure_in_an_outage_aimed_at_the_participant_is_not_counted(self):
        cut = window(80, 140, "o1", "outage-60", ["s17"]) + [
            event("rtcd-rs", 109, "s17", "ice_state", "ice:failed")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=cut), side("rtcd-go"))
        self.assertEqual(status, 0, md)

    def test_an_ice_failure_outside_its_own_outage_counts(self):
        cut = window(80, 140, "o1", "outage-60", ["s18"]) + [
            event("rtcd-rs", 109, "s17", "ice_state", "ice:failed")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=cut), side("rtcd-go"))
        self.assertEqual(status, 1)
        self.assertIn("ICE failures", md.split("## Breaches")[1].split("## ")[0])


class EarlyStop(Fixture):
    """A baseline killed part way (OOM, crash) is compared over the minutes it ran."""

    @staticmethod
    def stopped(t_end):
        gone = event("rtcd-go", t_end, "sfu", "error", "the SFU process is gone")
        gone.pop("group")
        return [r for r in side("rtcd-go") if r["ts"] <= ts(t_end)] + [gone]

    def test_what_the_subject_did_after_the_baseline_stopped_is_not_compared(self):
        late = [event("rtcd-rs", 200, "s17", "error", "the SFU closed the session")]
        status, md, _, _ = run_report(side("rtcd-rs", extra=late), self.stopped(100))
        self.assertEqual(status, 0, md)
        self.assertIn("the baseline stopped early", md)

    def test_what_the_subject_did_while_the_baseline_ran_is_still_compared(self):
        early = [event("rtcd-rs", 70, "s17", "error", "the SFU closed the session")]
        with mock.patch.object(report, "DEFAULT_CYCLE_S", 50):  # the baseline ran a whole cycle
            status, md, _, _ = run_report(side("rtcd-rs", extra=early), self.stopped(100))
        self.assertEqual(status, 1)
        self.assertIn("SFU-closed sessions", md.split("## Breaches")[1].split("## ")[0])

    # a freeze of a second every 5 s through the bw phase (cumulative counters)
    BW_FREEZES = {"impaired": {"freezes": lambda t: min(max(t - 60, 0), 60) // STEP,
                               "freeze_ms": lambda t: min(max(t - 60, 0), 60) // STEP * 1000}}

    def test_a_phase_seen_too_few_times_before_the_baseline_stopped_is_not_judged(self):
        _, md, _, _ = run_report(side("rtcd-rs", **self.BW_FREEZES), self.stopped(150))
        row = [l for l in md.splitlines() if l.startswith("| impaired | bw | Freezes / min (video) |")]
        self.assertTrue(row and row[0].endswith("| too few to judge |"), row)
        self.assertNotIn("impaired / bw / Freezes", md.split("## Breaches")[1].split("## ")[0])

    def test_the_same_phase_is_judged_when_the_baseline_ran_to_the_end(self):
        status, md, _, _ = run_report(side("rtcd-rs", **self.BW_FREEZES), side("rtcd-go"))
        self.assertEqual(status, 1, md)
        self.assertIn("impaired / bw / Freezes / min (video)", md)
        self.assertNotIn("too few to judge", md)

    def test_the_subjects_absolute_rules_cover_its_whole_run(self):
        late = {"clean_freezes": lambda t: 1 if t > 200 else 0}
        status, md, _, _ = run_report(side("rtcd-rs", **late), self.stopped(100))
        self.assertEqual(status, 1)
        self.assertIn("clean group, subject Freezes (count) must be zero", md)


class ShortBaseline(Fixture):
    """A baseline that stopped before one cycle has not been through what is compared."""

    @staticmethod
    def stopped(t_end):
        return EarlyStop.stopped(t_end)

    # the impaired and the clean student both freeze for good from t=70 (cumulative counters)
    FREEZE = {"clean_freezes": lambda t: max(t - 70, 0) // STEP * 2,
              "clean_freeze_ms": lambda t: max(t - 70, 0) // STEP * 2000,
              "impaired": {"freezes": lambda t: max(t - 70, 0) // STEP * 2,
                           "freeze_ms": lambda t: max(t - 70, 0) // STEP * 2000}}

    def test_nothing_is_judged_over_less_than_one_cycle(self):
        _, md, _, _ = run_report(side("rtcd-rs", **self.FREEZE), self.stopped(150))
        for scope, ph in (("clean", "all"), ("impaired", "all")):
            row = [l for l in md.splitlines() if l.startswith("| %s | %s | Freezes / min (video) |" % (scope, ph))]
            self.assertTrue(row and row[0].endswith("| too few to judge |"), (scope, row))
        self.assertNotIn("Freezes / min (video)", md.split("## Breaches")[1].split("## ")[0])

    def test_a_full_length_baseline_still_fails_a_real_regression_on_all_and_clean(self):
        status, md, _, _ = run_report(side("rtcd-rs", **self.FREEZE), side("rtcd-go"))
        self.assertEqual(status, 1, md)
        breaches = md.split("## Breaches")[1].split("## ")[0]
        self.assertIn("clean / all / Freezes / min (video)", breaches)
        self.assertIn("impaired / all / Freezes / min (video)", breaches)
        self.assertNotIn("too few to judge", md)

    def test_an_all_row_is_too_few_when_every_phase_in_it_is(self):
        rules = dict(RULES, compare=[{"subject": "rtcd-rs", "baseline": "rtcd-go"}])
        with mock.patch.object(report, "DEFAULT_CYCLE_S", 100):  # one cycle is shorter than the baseline's run
            _, md, _, _ = run_report(side("rtcd-rs", **self.FREEZE), self.stopped(150), rules)
        row = [l for l in md.splitlines() if l.startswith("| impaired | all | Freezes / min (video) |")]
        self.assertTrue(row and row[0].endswith("| too few to judge |"), row)

    def test_outage_audio_gap_is_left_to_the_recover_phase(self):
        audio = track("rtcd-rs", "s17/audio:teacher", "impaired", END, bytes_per_s=20_000, media="audio",
                      flowing=lambda t: not (120 <= t < 125))
        for r in audio:  # audio stops through the outage, as the subject's does and the baseline's does not
            r["audio_gap_ms"] = 4000 if 120 <= (r["ts"] - ts(0)) / 1000.0 < 130 else 0
        _, md, _, _ = run_report(side("rtcd-rs", extra=audio), side("rtcd-go"))
        row = [l for l in md.splitlines() if l.startswith("| impaired | outage | Audio gap %")]
        self.assertTrue(row and not row[0].rstrip("| ").endswith(("BREACH", "ok")), row)
        self.assertNotIn("impaired / outage / Audio gap", md.split("## Breaches")[1].split("## ")[0])


class CleanZeroPerPair(Fixture):
    def test_a_pair_may_leave_freezes_to_the_comparison(self):
        both = {"clean_freezes": lambda t: 1 if t > 100 else 0}
        rules = dict(RULES, compare=[{"subject": "rtcd-rs", "baseline": "rtcd-go",
                                      "clean_zero": ["stalls", "closes", "ice_disc"]}])
        status, md, _, _ = run_report(side("rtcd-rs", **both), side("rtcd-go", **both), rules)
        self.assertEqual(status, 0, md)
        self.assertNotIn("Freezes (count) must be zero", md)


class Attacks(Fixture):
    def ents(self, rows, impl="rtcd-rs"):
        _, _, ents, _ = run_report(rows, side("rtcd-go"))
        return [e for e in ents if e.impl == impl]

    def test_windows_are_parsed_and_an_unmatched_start_runs_to_the_end(self):
        rows = side("rtcd-rs", extra=window(100, 110, "a1", "pli-flood", ["s17"]) + [
            attack(200, "a2", "reorder", "start")])
        e = self.ents(rows)[0]
        w = {x["id"]: x for x in e.run.attacks}
        self.assertEqual((w["a1"]["name"], w["a1"]["start"], w["a1"]["end"], w["a1"]["who"]),
                         ("pli-flood", 100.0, 110.0, ["s17"]))
        self.assertEqual((w["a2"]["end"], w["a2"]["who"], w["a2"]["group"]), (float(END), [], "impaired"))

    def test_innocents_exclude_who_and_include_the_clean_group(self):
        hit = track("rtcd-rs", "s17/video:teacher", "impaired", END, bytes_per_s=300_000,
                    freezes=lambda t: 1 if t > 100 else 0)
        other = track("rtcd-rs", "s18/video:teacher", "impaired", END, freezes=lambda t: 2 if t > 100 else 0)
        base = side("rtcd-rs", extra=other)
        base = [r for r in base if not r["id"].startswith("s17")] + hit
        rows = base + window(100, 110, "a1", "reorder", ["s17"])
        e = self.ents(rows)[0]
        m = report.attack_metrics([e], lambda n: n == "reorder", dict(report.DEFAULTS))
        self.assertEqual(m["freezes"], 2)  # s18's, not s17's
        none = report.attack_metrics([e], lambda n: n == "reorder", dict(report.DEFAULTS), clean_only=True)
        self.assertEqual(none["freezes"], 0)

    def test_a_receiver_is_innocent_only_while_no_other_window_names_it(self):
        def ents(freezes):
            rows = lone_track("rtcd-rs", 0, freezes=freezes)
            rows += window(20, 100, "a1", "jitter", ["s18"]) + window(30, 40, "a2", "bw-flap", ["s17"])
            return self.ents(rows)
        count = lambda e: report.attack_metrics(e, lambda n: n == "jitter", dict(report.DEFAULTS))["freezes"]
        self.assertEqual(count(ents(lambda t: 1 if t >= 35 else 0)), 0)  # during bw-flap, which names s17
        self.assertEqual(count(ents(lambda t: (1 if t >= 35 else 0) + (1 if t >= 70 else 0))), 1)  # outside it

    def test_a_clean_freeze_fails_in_pli_flood_but_not_in_load_hold(self):
        freeze = {"clean_freezes": lambda t: 1 if t > 100 else 0}
        for name, status in (("pli-flood", 1), ("load-hold", 0)):
            win = window(100, 110, "a1", name)
            s = side("rtcd-rs", extra=win, **freeze)
            b = side("rtcd-go", extra=[dict(r, impl="abuse") for r in win], **freeze)
            code, md, _, _ = run_report(s, b)
            self.assertEqual(code, status, (name, md))
            if status:
                self.assertIn("clean group, subject Freezes (count) must be zero", md)

    def test_recover_s_is_the_time_from_the_end_until_the_innocents_flow_again(self):
        win = window(100, 110, "a1", "pli-flood", ["s17"])
        slow = {"clean_flow": lambda t: not 102 <= t < 135}
        e = self.ents(side("rtcd-rs", extra=win, **slow))[0]
        m = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual((m["recover_s"], m["never"]), (25.0, 0))
        e = self.ents(side("rtcd-rs", extra=win))[0]
        self.assertEqual(report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))["recover_s"], 0.0)
        stuck = {"clean_flow": lambda t: t < 102}
        e = self.ents(side("rtcd-rs", extra=win, **stuck))[0]
        m = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual((m["recover_s"], m["never"]), (float("inf"), 1))

    def late_outage_rows(self, wins, stalled=()):
        """An impaired receiver of a run with the outage at 250 s; `stalled` samples are flagged."""
        rows = [phase(0, "clean"), phase(250, "outage"), phase(400, "recover")] + proc("rtcd-rs", 500)
        rows += track("rtcd-rs", "s17/video:teacher", "impaired", 500, bytes_per_s=300_000,
                      flowing=lambda t: not 250 <= t < 400)
        for r in rows:
            if r["kind"] == "recv" and r["ts"] in {ts(t) for t in stalled}:
                r["stalled"] = True
        return rows + wins

    def test_an_attack_ending_before_an_outage_is_not_charged_with_it(self):
        win = window(20, 50, "a1", "pli-flood", ["s99"])
        e = self.ents(self.late_outage_rows(win))[0]
        m = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual((m["never"], m["recover_s"]), (0, 0.0))

    def test_overlapping_windows_of_one_class_count_a_stall_once(self):
        wins = window(20, 50, "a1", "reorder", ["s99"]) + window(25, 55, "a2", "reorder", ["s99"])
        e = self.ents(self.late_outage_rows(wins, stalled=(30, 35)))[0]
        m = report.attack_metrics([e], lambda n: n == "reorder", dict(report.DEFAULTS))
        self.assertEqual(m["stalls"], 1)

    def test_an_event_in_two_overlapping_windows_of_one_class_counts_once(self):
        wins = window(20, 50, "a1", "pli-flood", ["s99"]) + window(25, 55, "a2", "pli-flood", ["s99"])
        ev = [event("rtcd-rs", 30, "s17", "error", "the SFU closed the session")]
        e = self.ents(self.late_outage_rows(wins) + ev)[0]
        m = report.attack_metrics([e], lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual(m["closes"], 1)
        other = window(25, 55, "a2", "reorder", ["s99"])
        e = self.ents(self.late_outage_rows(window(20, 50, "a1", "pli-flood", ["s99"]) + other) + ev)[0]
        total = sum(report.attack_metrics([e], lambda n, c=c: n == c, dict(report.DEFAULTS))["closes"]
                    for c in ("pli-flood", "reorder"))
        self.assertEqual(total, 2)  # once per class

    def test_slow_recovery_breaches_equal_runs_pass(self):
        win = window(100, 110, "a1", "pli-flood", ["s17"])
        slow = {"clean_flow": lambda t: not 102 <= t < 135}
        code, md, _, _ = run_report(side("rtcd-rs", extra=win, **slow), side("rtcd-go", extra=win))
        self.assertEqual(code, 1)
        self.assertIn("Recovery after an attack", md.split("## Breaches")[1].split("## ")[0])
        self.assertIn("## Attack windows", md)
        self.assertIn("| pli-flood | a1 |", md)
        code, md, _, _ = run_report(side("rtcd-rs", extra=win, **slow), side("rtcd-go", extra=win, **slow))
        self.assertEqual(code, 0, md)  # equal runs hold, however slow

    def test_missing_baseline_fails_with_attacks(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "rtcd-rs-x86_64.jsonl")
        with open(p, "w") as f:
            for r in side("rtcd-rs", extra=window(100, 110, "a1", "reorder")):
                f.write(json.dumps(r) + "\n")
        rules = os.path.join(d, "rules.json")
        with open(rules, "w") as f:
            json.dump(RULES, f)
        self.assertEqual(report.main(["--rules", rules, "--out", os.path.join(d, "out"), p]), 1)

    def test_classes_after_the_baseline_server_stopped_are_not_compared(self):
        flood = window(100, 110, "a1", "pli-flood") + window(220, 230, "a2", "reorder")
        s = side("rtcd-rs", extra=flood)
        b = [r for r in side("rtcd-go", extra=[dict(r, impl="rtcd-go") for r in flood])
             if not (r["kind"] == "proc" and r["ts"] > ts(200))]
        _, md, _, _ = run_report(s, b)
        self.assertIn("| pli-flood | SFU-closed sessions | 0 | 0 | ok |", md)
        self.assertNotIn("| reorder | Freezes", md)
        self.assertIn("attack reorder | only the subject has it | both sides need it | n/a", md)

    def test_sfu_slopes_and_saturation(self):
        grow = [dict(r, threads=10 + (r["ts"] - T0) // 1000 // STEP, cpu_pct=200.0) for r in proc("rtcd-rs", END)]
        rows = [r for r in side("rtcd-rs") if r["kind"] != "proc"] + grow
        d = tempfile.mkdtemp()
        p = os.path.join(d, "rtcd-rs-x86_64.jsonl")
        with open(p, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        ents = report.build_entities(report.load([p]))
        m = report.sfu_metrics(ents, dict(report.DEFAULTS, warmup_min=0, rss_slope_min_span_min=1))
        self.assertAlmostEqual(m["threads_slope"], 720.0, delta=1)
        self.assertEqual((m["cpu_sat"], m["fds_slope"]), (100.0, 0.0))


class FreezeCountNeedsFreezeTime(unittest.TestCase):
    """A freeze-count breach stands only when the freeze time breaches its own limit."""

    def test_more_freezes_of_about_the_same_frozen_time_is_ok(self):
        rules = dict(report.DEFAULTS)
        # Both frozen nearly all minute; the subject 0.6 % more frozen, but it shows frames, so it freezes more often.
        s, b = {"freeze_ms": 48857}, {"freeze_ms": 48561}
        self.assertEqual(report.freezes_only_if_frozen("freeze_rate", "BREACH", s, b, rules), "ok")

    def test_the_raw_count_follows_the_same_rule(self):
        rules = dict(report.DEFAULTS)
        s, b = {"freeze_ms": 25859}, {"freeze_ms": 27375}
        self.assertEqual(report.freezes_only_if_frozen("freezes", "BREACH", s, b, rules), "ok")
        s, b = {"freeze_ms": 9000}, {"freeze_ms": 3000}
        self.assertEqual(report.freezes_only_if_frozen("freezes", "BREACH", s, b, rules), "BREACH")

    def test_more_freezes_and_breaching_freeze_time_stays_a_breach(self):
        rules = dict(report.DEFAULTS)
        s, b = {"freeze_ms": 9000}, {"freeze_ms": 3000}
        self.assertEqual(report.freezes_only_if_frozen("freeze_rate", "BREACH", s, b, rules), "BREACH")

    def test_other_metrics_are_untouched(self):
        self.assertEqual(report.freezes_only_if_frozen("freeze_ms", "BREACH", {"freeze_ms": 1}, {"freeze_ms": 2},
                                                       dict(report.DEFAULTS)), "BREACH")


if __name__ == "__main__":
    unittest.main()


def peer_pair(impl, off_every=5, ans_every=5, timeline=None, nack=(3, 3), retx=(2, 2), cpu=40.0, load=(1.0, 4), seed="7",
              start=0, stalled=()):
    """A call of two peers (offerer, answerer), one file: `*_every` is how often (s) each one's receiver
    gets a burst of packets (5: every sample); the counters are what each peer logs."""
    rows = list(TIMELINE if timeline is None else timeline)
    rows.append({"ts": ts(start), "impl": "run", "arch": "x86_64", "kind": "event", "id": "run", "what": "run",
                 "seed": seed, "profile": "call", "minutes": 4, "group": "impaired"})
    for k, (role, every) in enumerate((("offerer", off_every), ("answerer", ans_every))):
        pid = "%s-%s" % (impl, role)
        rec = track(impl, pid + "-video", "impaired", END, bytes_per_s=100_000, flowing=lambda t, e=every: t % e == 0)
        for r in rec:
            r["nack"] = nack[k]
            if r["ts"] in {ts(t) for t in stalled} and k == 0:
                r["stalled"] = True
        rows += rec
        rows += [{"ts": ts(t), "impl": impl, "arch": "x86_64", "kind": "proc", "id": pid, "rss_mb": 50.0, "cpu_pct": cpu,
                  "threads": 10, "fds": 20, "udp_rcvbuf_err": 0, "udp_sndbuf_err": 0, "load1": load[0], "cpus": load[1]}
                 for t in range(0, END + 1, STEP)]
        rows += [{"ts": ts(t), "impl": impl, "arch": "x86_64", "kind": "tx", "id": pid, "retx": retx[k] * t,
                  "rtp_pkts": 10 * t, "rtp_bytes": 1000 * t, "rtcp_pkts": t, "rtcp_bytes": 50 * t, "dtls_pkts": t,
                  "dtls_bytes": 100 * t, "stun_pkts": t, "stun_bytes": 20 * t, "other_pkts": 0, "other_bytes": 0}
                 for t in range(0, END + 1, STEP)]
    return rows


def validate(*files, rules=None):
    d = tempfile.mkdtemp()
    paths = []
    for name, rows in files:
        paths.append(os.path.join(d, name + ".jsonl"))
        with open(paths[-1], "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
    runs = report.load(paths)
    return report.validity(runs, report.build_entities(runs), dict(report.DEFAULTS, **(rules or {}))), runs, d


def failed_checks(val):
    return [v[1] for v in val if not v[3]]


class RunValidity(unittest.TestCase):
    def test_a_fair_pair_is_valid(self):
        val, _, _ = validate(("rtc-rtc", peer_pair("rtc")), ("pion-pion", peer_pair("pion")))
        self.assertEqual(failed_checks(val), [], val)

    def test_a_direction_starved_beyond_three_to_one_is_invalid(self):
        val, _, _ = validate(("rtc-rtc", peer_pair("rtc", ans_every=20)))  # 4:1
        self.assertEqual(failed_checks(val), ["video delivered, offerer vs answerer"])
        val, _, _ = validate(("rtc-rtc", peer_pair("rtc", ans_every=10)))  # 2:1
        self.assertEqual(failed_checks(val), [])

    def test_files_that_deliver_more_than_two_to_one_apart_are_invalid(self):
        val, _, _ = validate(("rtc-rtc", peer_pair("rtc")), ("pion-pion", peer_pair("pion", 15, 15)))
        self.assertEqual(failed_checks(val), ["total delivered packets, between files"])

    def test_a_counter_that_is_zero_on_one_side_is_invalid_where_the_path_is_impaired(self):
        val, _, _ = validate(("pion-pion", peer_pair("pion", nack=(3, 0))))
        self.assertEqual(failed_checks(val), ["nack counted on both sides"])
        val, _, _ = validate(("pion-pion", peer_pair("pion", retx=(2, 0))))
        self.assertEqual(failed_checks(val), ["retx counted on both sides"])
        clean = [phase(0, "clean")]
        val, _, _ = validate(("pion-pion", peer_pair("pion", nack=(3, 0), retx=(2, 0), timeline=clean)))
        self.assertEqual(failed_checks(val), [])

    def test_a_send_class_that_is_zero_on_one_side_is_invalid(self):
        rows = peer_pair("rtc")
        for r in rows:
            if r["kind"] == "tx" and r["id"] == "rtc-answerer":
                r["stun_pkts"] = 0
        val, _, _ = validate(("rtc-rtc", rows))
        self.assertEqual(failed_checks(val), ["stun_pkts counted on both sides"])

    def test_a_saturated_peer_or_a_loaded_host_is_invalid(self):
        val, _, _ = validate(("rtc-rtc", peer_pair("rtc", cpu=250.0)))
        self.assertEqual(sorted(failed_checks(val)), ["rtc-answerer CPU not saturated", "rtc-offerer CPU not saturated"])
        val, _, _ = validate(("rtc-rtc", peer_pair("rtc", load=(9.0, 4))))
        self.assertEqual(len(failed_checks(val)), 2)
        self.assertTrue(all("load average" in c for c in failed_checks(val)))

    def test_files_must_be_one_run(self):
        val, _, _ = validate(("rtc-rtc", peer_pair("rtc")), ("pion-pion", peer_pair("pion", seed="8")))
        self.assertEqual(failed_checks(val), ["one seed, profile and length"])
        val, _, _ = validate(("rtc-rtc", peer_pair("rtc")), ("pion-pion", peer_pair("pion", start=3 * 86400)))
        self.assertIn("started together", failed_checks(val))
        merged = peer_pair("rtc") + [r for r in peer_pair("rtc", seed="9") if r.get("what") == "run"]
        val, _, _ = validate(("rtc-rtc", merged))
        self.assertEqual(failed_checks(val), ["one run per file"])

    def test_an_invalid_run_gets_no_verdict_and_fails_the_gate(self):
        d = tempfile.mkdtemp()
        paths = []
        for name, rows in (("rtc-rtc", peer_pair("rtc", ans_every=20)), ("pion-pion", peer_pair("pion"))):
            paths.append(os.path.join(d, name + ".jsonl"))
            with open(paths[-1], "w") as f:
                f.writelines(json.dumps(r) + "\n" for r in rows)
        rules = os.path.join(d, "rules.json")
        with open(rules, "w") as f:
            json.dump({"compare": [{"subject": "rtc", "baseline": "pion"}]}, f)
        self.assertEqual(report.main(["--rules", rules, "--out", os.path.join(d, "out")] + paths), 1)
        with open(os.path.join(d, "out", "summary.md")) as f:
            md = f.read()
        self.assertTrue(md.splitlines()[0].startswith("# Soak report: INVALID RUN, no verdict (rtc-rtc: video delivered"), md[:200])
        self.assertIn("## Run validity", md)
        self.assertIn("## Sent by class", md)
        self.assertNotIn("Freezes / min", md)


class NetworkAttribution(unittest.TestCase):
    def ents(self, rows):
        _, runs, _ = validate(("rtc-rtc", rows))
        return report.build_entities(runs)

    def test_only_network_classes_are_charged_with_freezes_and_stalls(self):
        rows = peer_pair("rtc", timeline=[phase(0, "clean")], stalled=(30, 35))
        rows += window(20, 50, "a1", "pli-flood", ["s99"]) + window(20, 50, "a2", "reorder", ["s99"])
        e = [x for x in self.ents(rows) if x.impl == "rtc"]
        net = report.attack_metrics(e, lambda n: n == "reorder", dict(report.DEFAULTS))
        other = report.attack_metrics(e, lambda n: n == "pli-flood", dict(report.DEFAULTS))
        self.assertEqual(net["stalls"], 1)
        self.assertEqual([other[k] for k in ("stalls", "stall_max", "freezes", "freeze_rate", "freeze_ms")], [None] * 5)
        self.assertIsNotNone(other["closes"])

    def test_stalls_with_no_network_attack_active(self):
        timeline = [phase(0, "clean")]
        e = lambda rows: [x for x in self.ents(rows) if x.impl == "rtc"]
        rules = dict(report.DEFAULTS)
        quiet = peer_pair("rtc", timeline=timeline, stalled=(30, 35))
        self.assertEqual(report.quiet_stalls(e(quiet), rules), 1)
        with_net = quiet + window(20, 50, "a1", "jitter")
        self.assertEqual(report.quiet_stalls(e(with_net), rules), 0)
        with_junk = quiet + window(20, 50, "a1", "udp-junk")
        self.assertEqual(report.quiet_stalls(e(with_junk), rules), 1)
        shaped = peer_pair("rtc", timeline=[phase(0, "clean"), phase(25, "loss"), phase(60, "clean")], stalled=(30, 35))
        self.assertEqual(report.quiet_stalls(e(shaped), rules), 0)


def with_fields(rows, **fn):
    """The rows with extra fields: each value is a function of the row's time in seconds."""
    for r in rows:
        t = (r["ts"] - T0) / 1000.0
        for k, f in fn.items():
            r[k] = f(t)
    return rows


def entities(*files):
    """{name: Ent} of the files' single entity each (the file name is the entity's run)."""
    _, runs, _ = validate(*files)
    return report.build_entities(runs)


def meet_side(impl, delay=40.0, video_delay=60.0, concealed=0, fec=0):
    """A loss-sweep run of one impl: an impaired audio and video receiver with delay, and Chrome's audio
    counters (`concealed` samples and `fec` packets every 5 s)."""
    sweep = [phase(0, "clean"), phase(60, "loss10"), phase(120, "loss20"), phase(180, "loss30"), phase(240, "recover")]
    rows = list(sweep) + proc(impl, 300)
    aud = track(impl, "s01/audio:teacher", "impaired", 300, media="audio")
    with_fields(aud, delay_p50_ms=lambda t: delay + (t // 60) * 10, delay_p95_ms=lambda t: delay * 2 + (t // 60) * 10,
                concealed_samples=lambda t: int(concealed * (t // STEP)), concealment_events=lambda t: int(t // STEP),
                fec_packets=lambda t: int(fec * (t // STEP)))
    vid = track(impl, "s01/video:teacher", "impaired", 300)
    with_fields(vid, delay_p50_ms=lambda t: video_delay, delay_p95_ms=lambda t: video_delay * 2)
    return rows + aud + vid


class LossSweepAndDelay(unittest.TestCase):
    def metrics(self, rows, phase_name):
        ents = [e for e in entities(("x", rows))]
        return report.scope_metrics(ents, "impaired", phase_name, dict(report.DEFAULTS))

    def test_the_loss_sweep_phases_are_known_and_ordered(self):
        ents = entities(("x", meet_side("rtcd-rs")))
        self.assertEqual(report.phase_names(ents), ["clean", "loss10", "loss20", "loss30", "recover"])

    def test_delay_per_phase_audio_and_video(self):
        m = self.metrics(meet_side("rtcd-rs"), "loss20")  # minutes 2 to 3: audio p50 40 + 20 = 60, p95 80 + 20 = 100
        self.assertEqual((m["delay_audio_p50"], m["delay_audio_p95"]), (60.0, 100.0))
        self.assertEqual((m["delay_video_p50"], m["delay_video_p95"]), (60.0, 120.0))

    def test_delay_rows_are_report_only_and_gated_only_through_targets(self):
        status, md, _, _ = run_report(meet_side("rtcd-rs", delay=200.0, video_delay=900.0), meet_side("rtcd-go"),
                                      dict(RULES, require_groups=[]))
        self.assertEqual(status, 0)
        self.assertTrue(any(l.startswith("| impaired | loss10 | Audio delay p50 ms (report only) | 210.0 | 50.0 |  |")
                            for l in md.splitlines()))
        line = next(l for l in md.splitlines() if l.startswith("| impaired | loss10 | Video delay p50 ms"))
        self.assertTrue(line.endswith("| 900.0 | 60.0 |  |"), line)

    def test_concealment_percent_and_fec_packets(self):
        # 2400 samples per 5 s of 240000 played: 1 %.
        m = self.metrics(meet_side("rtcd-rs", concealed=2400, fec=3), "loss10")
        self.assertAlmostEqual(m["conceal_pct"], 1.0, places=6)
        self.assertEqual(m["fec_packets"], 36)  # 12 intervals in the minute

    def test_old_rows_have_none_of_the_new_metrics(self):
        s, _ = Fixture().rows()
        m = self.metrics(s, "bw")
        self.assertEqual([m[k] for k in ("delay_audio_p50", "delay_video_p95", "conceal_pct", "fec_packets")], [None] * 4)


def restart_run(impl, restart_at=102, down=(105, 125), extra=()):
    rows = [phase(0, "clean")] + proc(impl, END) + list(extra)
    rows.append(event(impl, restart_at, "run.sh", "sfu_restart", "1"))
    rows += track(impl, "s01/video:teacher", "impaired", END, flowing=lambda t: not (down[0] <= t < down[1]))
    rows += track(impl, "s02/video:teacher", "impaired", END)
    rows += track(impl, "s03/audio:teacher", "impaired", END, media="audio", flowing=lambda t: not (down[0] <= t < down[1] + 20))
    return rows


class SfuRestart(unittest.TestCase):
    def test_recovery_per_track(self):
        ents = entities(("x", restart_run("rtcd-rs")))
        (detail, t, secs), = report.restart_recovery(ents[0], dict(report.DEFAULTS))
        # The interrupted video resumes in the interval that starts at 120, ends at 125: 23 s after 102; the
        # untouched one in the interval 105-110 (the first that starts after the restart): 8 s; the audio 20 s later.
        self.assertEqual((detail, t, sorted(secs)), ("1", 102.0, [8.0, 23.0, 43.0]))

    def test_a_track_that_never_comes_back_is_never(self):
        rows = restart_run("rtcd-rs", down=(105, 500))
        ents = entities(("x", rows))
        (_, _, secs), = report.restart_recovery(ents[0], dict(report.DEFAULTS))
        self.assertEqual(sorted(secs), [8.0, math.inf, math.inf])

    def test_restart_recovery_is_a_target_metric(self):
        rules = dict(report.DEFAULTS)
        m = report.scope_metrics(entities(("x", restart_run("rtcd-rs"))), "impaired", None, rules)
        self.assertEqual((m["restart_recover_p95"], m["restart_recover_max"]), (43.0, 43.0))
        never = report.scope_metrics(entities(("x", restart_run("rtcd-rs", down=(105, 500)))), "impaired", None, rules)
        self.assertEqual(never["restart_recover_max"], math.inf)
        self.assertIsNone(report.scope_metrics(entities(("x", restart_run("rtcd-rs"))), "impaired", "clean", rules)["restart_recover_max"])
        _, md, _, _ = run_report(restart_run("rtcd-rs", down=(105, 500)), restart_run("rtcd-go"), dict(
            RULES, require_groups=[], targets=[{"name": "recover", "metric": "restart_recover_max", "max": 30}]))
        self.assertIn("recover | never | <= 30.0 | FAIL |", md)

    def test_a_rejoined_track_counts_across_its_epochs(self):
        rows = restart_run("rtcd-rs")
        old = [r for r in rows if r.get("id") == "s02/video:teacher"]
        rows = [r for r in rows if r not in old]
        rows += [r for r in old if (r["ts"] - T0) / 1000 <= 100]
        new = track("rtcd-rs", "s02/video:teacher#2", "impaired", END, start=130)
        rows += new
        ents = entities(("x", rows))
        (_, _, secs), = report.restart_recovery(ents[0], dict(report.DEFAULTS))
        # The new epoch's first interval starts at 130 and ends at 135: 33 s after the restart.
        self.assertEqual(sorted(secs), [23.0, 33.0, 43.0])
        gone = [r for r in rows if r.get("id") != "s02/video:teacher#2"]
        (_, _, secs), = report.restart_recovery(entities(("x", gone))[0], dict(report.DEFAULTS))
        self.assertEqual(len(secs), 2)  # the old series alone ended before the window: left out

    def test_the_grace_follows_recover_window_s(self):
        late = [event("rtcd-rs", 200, "sfu", "error", "the SFU exited")]
        for window, status in ((60, 1), (120, 0)):
            rules = dict(RULES, recover_window_s=window, require_groups=[])
            self.assertEqual(run_report(restart_run("rtcd-rs", extra=late), restart_run("rtcd-go"), rules)[0], status, window)

    def test_udp_counters_are_differenced_per_restart_segment(self):
        rows = restart_run("rtcd-rs")
        for r in rows:
            if r["kind"] == "proc":
                r["udp_rcvbuf_err"] = 7 + (r["ts"] - T0) // 5000 if r["ts"] - T0 < 102_000 else (r["ts"] - T0 - 102_000) // 5000
        ents = entities(("x", rows))
        self.assertEqual(report.sfu_metrics(ents, dict(report.DEFAULTS))["udp_err"], 20 + 27)

    def test_downtime_is_the_time_to_sfu_up(self):
        rows = restart_run("rtcd-rs") + [event("rtcd-rs", 109, "run.sh", "sfu_up", "1")]
        _, md, _, _ = run_report(rows, restart_run("rtcd-go"))
        self.assertIn("| 3 | 23.0 | 43.0 | 43.0 | 7.0 |", md)

    def test_the_table_has_p50_p95_max(self):
        _, md, _, _ = run_report(restart_run("rtcd-rs"), restart_run("rtcd-go"))
        self.assertIn("## SFU restart recovery", md)
        self.assertIn("| rtcd-rs-x86_64 | rtcd-rs | x86_64 | 1 | 1.7 | 3 | 23.0 | 43.0 | 43.0 |", md)

    def test_a_restart_in_its_event_is_not_a_crash_close_or_process_error(self):
        errs = [event("rtcd-rs", 104, "sfu", "error", "the SFU exited"),
                event("rtcd-rs", 106, "s01", "error", "the SFU closed the session"),
                event("rtcd-rs", 107, "s01", "error", "the signaling connection closed"),
                event("rtcd-rs", 108, "s01", "ice_state", "ice:disconnected")]
        rules = dict(report.DEFAULTS)
        with_restart = entities(("x", restart_run("rtcd-rs", extra=errs)))
        m = report.scope_metrics(with_restart, "impaired", None, rules)
        self.assertEqual([m[k] for k in ("closes", "sig_closes", "ice_disc", "downtime")], [0, 0, 0, 0.0])
        self.assertEqual(report.sfu_metrics(with_restart, rules)["sfu_errors"], 0)
        rows = [r for r in restart_run("rtcd-rs", extra=errs) if r.get("what") != "sfu_restart"]
        without = entities(("x", rows))
        m = report.scope_metrics(without, "impaired", None, rules)
        self.assertEqual([m[k] for k in ("closes", "sig_closes", "ice_disc")], [1, 1, 1])
        self.assertEqual(report.sfu_metrics(without, rules)["sfu_errors"], 1)

    def test_an_error_long_after_the_restart_still_counts(self):
        late = [event("rtcd-rs", 102 + report.DEFAULTS["recover_window_s"] + 30, "sfu", "error", "the SFU exited")]
        self.assertEqual(report.sfu_metrics(entities(("x", restart_run("rtcd-rs", extra=late))), dict(report.DEFAULTS))["sfu_errors"], 1)


class RestartIsBookedApart(unittest.TestCase):
    def rows(self, restart):
        rows = restart_run("rtcd-rs", down=(105, 125))
        if not restart:
            rows = [r for r in rows if r.get("what") != "sfu_restart"]
        for r in rows:
            if r.get("id") == "s01/video:teacher" and 105 <= (r["ts"] - T0) / 1000 < 125:
                r["stalled"] = True
                r["freezes"], r["freeze_ms"] = 1, 4000
            elif r.get("id") == "s01/video:teacher" and (r["ts"] - T0) / 1000 >= 125:
                r["freezes"], r["freeze_ms"] = 1, 4000
        return rows

    def test_stalls_and_freezes_in_the_span_are_not_in_the_phase_rows_but_in_the_table(self):
        rules = dict(report.DEFAULTS)
        plain = report.scope_metrics(entities(("x", self.rows(False))), "impaired", None, rules)
        self.assertEqual(plain["stalls"], 1)
        self.assertGreater(plain["freeze_ms"], 0)
        booked = report.scope_metrics(entities(("x", self.rows(True))), "impaired", None, rules)
        self.assertEqual(booked["stalls"], 0)
        self.assertEqual(booked["freeze_ms"], 0)
        _, md, _, _ = run_report(self.rows(True), self.rows(True))
        row = next(l for l in md.splitlines() if l.startswith("| rtcd-rs-x86_64 | rtcd-rs | x86_64 | 1 | 1.7 |"))
        self.assertTrue(row.endswith("| 1 | 4000 | 0 |"), row)


def client_proc(name, cpu, cores, end=100):
    return [{"ts": ts(t), "impl": "rtcd-rs", "arch": "x86_64", "kind": "proc", "id": "client:" + name, "cpu_pct": cpu(t),
             "cores": cores} for t in range(0, end, STEP)]


class MeetValidity(unittest.TestCase):
    def test_client_containers_leave_the_sfu_metrics_alone(self):
        ents = entities(("x", meet_side("rtcd-rs") + client_proc("c1", lambda t: 400.0, 2)))
        self.assertEqual(report.sfu_metrics(ents, dict(report.DEFAULTS))["cpu"], 50.0)

    def test_a_client_above_ninety_percent_of_its_cores_is_invalid(self):
        busy = lambda t: 190.0 if t < 20 else 50.0  # 4 of 20 samples above 90 % of 2 cores: 20 %
        val, _, _ = validate(("x", meet_side("rtcd-rs") + client_proc("c1", busy, 2)))
        self.assertEqual(failed_checks(val), ["client:c1 CPU within 90 % of its cores"])
        calm = lambda t: 150.0 if t < 5 else 50.0  # one of 20 samples: 5 %
        val, _, _ = validate(("x", meet_side("rtcd-rs") + client_proc("c1", calm, 2)))
        self.assertEqual(failed_checks(val), [])

    def test_delay_samples_outside_the_sane_range_are_invalid(self):
        rows = meet_side("rtcd-rs")
        val, _, _ = validate(("x", rows))
        self.assertEqual(failed_checks(val), [])
        for r in rows:
            if r.get("id") == "s01/video:teacher":
                r["delay_p95_ms"] = 9000.0  # a video timestamp rewritten on a layer switch: not judged
        val, _, _ = validate(("x", rows))
        self.assertEqual(failed_checks(val), [])
        bad = [r for r in rows if r.get("id") == "s01/audio:teacher"]
        for r in bad[::10]:
            r["delay_p95_ms"] = 5000.0  # an impaired group's multi-second delay (abuse scenes) is real
        val, _, _ = validate(("x", rows))
        self.assertEqual(failed_checks(val), [])
        for r in bad:
            r["group"] = "clean"
        for r in bad[::10]:
            r["delay_p95_ms"] = 5000.0
        val, _, _ = validate(("x", rows))
        self.assertEqual(failed_checks(val), ["delay samples within 0-2000 ms"])
        for r in bad:
            r["delay_p95_ms"] = None if r["delay_p95_ms"] == 5000.0 else r["delay_p95_ms"]
            r["delay_p50_ms"] = -5.0 if r["ts"] == bad[3]["ts"] else r["delay_p50_ms"]
        val, _, _ = validate(("x", rows))
        self.assertEqual(failed_checks(val), [])


class BaselineValidity(unittest.TestCase):
    def test_a_saturated_baseline_voids_its_pair_not_the_run(self):
        rules = dict(RULES, require_groups=[])
        status, md, _, _ = run_report(side("rtcd-rs"), side("rtcd-go", cpu=250.0), rules)
        self.assertEqual(status, 0)
        self.assertTrue(md.startswith("# Soak report\n"), md[:80])
        self.assertIn("| sfu CPU not saturated | 100.0 % of samples at or above 190 % | baseline INVALID |", md)
        self.assertIn("comparison with the baseline | baseline invalid (sfu CPU not saturated", md)
        self.assertNotIn("| Freezes / min (video) |", md)
        self.assertIn("subject SFU process errors (gone, crashed) must be zero | 0 | 0 | PASS |", md)

    def test_a_saturated_subject_still_voids_the_run(self):
        status, md, _, _ = run_report(side("rtcd-rs", cpu=250.0), side("rtcd-go"), dict(RULES, require_groups=[]))
        self.assertEqual(status, 1)
        self.assertTrue(md.startswith("# Soak report: INVALID RUN, no verdict (rtcd-rs-x86_64: sfu CPU"), md[:120])

    def test_an_invalid_baseline_does_not_hide_a_subject_that_breaks_its_target(self):
        rules = dict(RULES, require_groups=[], targets=[{"name": "t", "metric": "freeze_rate", "max": -1}])
        status, md, _, _ = run_report(side("rtcd-rs"), side("rtcd-go", cpu=250.0), rules)
        self.assertEqual(status, 1)
        self.assertIn("t | 0.00 | <= -1.00 | FAIL |", md)


class SlackOverride(Fixture):
    def test_slack_by_metric_key_tolerates_a_few_ice_disconnects(self):
        extra = [event("rtcd-rs", 30, "s17", "ice_state", "ice:disconnected")]
        s, b = self.rows(extra=extra)
        self.assertEqual(run_report(s, b)[0], 1)
        s, b = self.rows(extra=extra)
        self.assertEqual(run_report(s, b, dict(RULES, slack={"ice_disc": 2}))[0], 0)


class TargetRules(unittest.TestCase):
    def run_targets(self, targets, **kw):
        rules = dict(RULES, targets=targets, require_groups=[])
        status, md, _, _ = run_report(meet_side("rtcd-rs", **kw), meet_side("rtcd-go"), rules)
        return status, md

    def test_an_ungated_target_shows_pass_or_miss_and_never_fails(self):
        status, md = self.run_targets([
            {"name": "Meet audio delay p95 (loss10)", "metric": "delay_audio_p95", "phase": "loss10", "max": 100, "gated": False},
            {"name": "Meet audio delay p95 (loss30)", "metric": "delay_audio_p95", "phase": "loss30", "max": 100, "gated": False}])
        self.assertEqual(status, 0)
        self.assertIn("Meet audio delay p95 (loss10) | 90.0 | <= 100.0 | PASS (not gated) |", md)
        self.assertIn("Meet audio delay p95 (loss30) | 110.0 | <= 100.0 | MISS (not gated) |", md)
        self.assertNotIn("- MISS", md)

    def test_a_gated_target_fails_the_run(self):
        status, md = self.run_targets([{"name": "audio loss", "metric": "delay_audio_p50", "phase": "loss30", "max": 10}])
        self.assertEqual(status, 1)
        self.assertIn("audio loss | 70.0 | <= 10.0 | FAIL |", md)

    def test_a_target_without_data_is_not_applicable(self):
        status, md = self.run_targets([{"name": "concealed", "metric": "conceal_pct", "max": 1.0, "gated": False}])
        self.assertEqual(status, 0)
        self.assertIn("concealed | 0.00 | <= 1.00 | PASS (not gated) |", md)
        _, md2 = self.run_targets([{"name": "fec", "metric": "fec_packets", "min": 1, "scope": "nobody"}])
        self.assertIn("fec | - | >= 1 | n/a |", md2)
