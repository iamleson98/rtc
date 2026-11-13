package main

import (
	"fmt"
	"math"
	"sync"
	"time"
)

const (
	freezeWindow     = 30
	audioGapMs       = 60.0
	stalledAfterMs   = 2000.0
	freezeMinExtraMs = 150.0
)

// recvStats keeps the cumulative counters of one received track (README.md, kind recv).
type recvStats struct {
	mu    sync.Mutex
	log   *logger
	media string
	clock float64 // RTP clock rate in kHz

	started            bool
	baseExt, maxExt    uint32 // extended sequence numbers (cycles folded in)
	cycles             int
	lastTS             uint32
	tsWraps            int
	packets, frames    uint64
	freezes            uint64
	freezeMs, audioGap float64
	jitterTicks        float64
	prevTransit        float64
	lastArrival        time.Time
	lastFrame          time.Time
	intervals          []float64
	openAdded          float64
	openFreeze         bool
	stallSeen          bool
	lastPLI            time.Time
	startedAt          time.Time
}

func newRecvStats(l *logger, media string, clockRate uint32) *recvStats {
	return &recvStats{log: l, media: media, clock: float64(clockRate) / 1000}
}

func (r *recvStats) threshold() float64 {
	if len(r.intervals) == 0 {
		return math.Inf(1)
	}
	sum := 0.0
	for _, v := range r.intervals {
		sum += v
	}
	avg := sum / float64(len(r.intervals))
	return math.Max(3*avg, avg+freezeMinExtraMs)
}

// onPacket counts one received packet. It returns true when the track just came out of a freeze
// and a keyframe should be requested (at most once a second), as a decoder would.
func (r *recvStats) onPacket(now time.Time, seq uint16, ts uint32, marker bool) (pli bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.packets++
	newest := false
	if !r.started {
		r.started, newest = true, true
		r.baseExt, r.maxExt, r.lastTS, r.startedAt = uint32(seq), uint32(seq), ts, now
	} else if d := int16(seq - uint16(r.maxExt)); d > 0 {
		newest = true
		if seq < uint16(r.maxExt) {
			r.cycles++
			r.log.event("wrap", fmt.Sprintf("recv %s seq wrap #%d", r.media, r.cycles))
		}
		r.maxExt += uint32(d)
	}
	if newest {
		if ts < r.lastTS && int32(ts-r.lastTS) > 0 {
			r.tsWraps++
			r.log.event("wrap", fmt.Sprintf("recv %s ts wrap #%d", r.media, r.tsWraps))
		}
		if !r.lastArrival.IsZero() && (r.media == "audio" || ts != r.lastTS) {
			arrival := now.Sub(r.lastArrival).Seconds() * 1000 * r.clock
			dev := math.Abs(arrival - float64(int32(ts-r.lastTS)))
			r.jitterTicks += (dev - r.jitterTicks) / 16
		}
		r.lastTS = ts
	}
	if r.media == "audio" {
		r.frames++
		if !r.lastArrival.IsZero() {
			if g := now.Sub(r.lastArrival).Seconds() * 1000; g > audioGapMs {
				r.audioGap += g - r.openAdded
			}
		}
		r.openAdded = 0
	} else if marker {
		r.frames++
		if newest && r.frameDone(now) && now.Sub(r.lastPLI) > time.Second {
			r.lastPLI, pli = now, true
		}
	}
	if !r.lastArrival.IsZero() && now.Sub(r.lastArrival).Seconds()*1000 > stalledAfterMs {
		r.stallSeen = true
	}
	r.lastArrival = now
	return pli
}

func (r *recvStats) frameDone(now time.Time) (froze bool) {
	if !r.lastFrame.IsZero() {
		iv := now.Sub(r.lastFrame).Seconds() * 1000
		if iv > r.threshold() {
			froze = true
			if !r.openFreeze {
				r.freezes++
			}
			r.freezeMs += iv - r.openAdded
		}
		r.intervals = append(r.intervals, iv)
		if len(r.intervals) > freezeWindow {
			r.intervals = r.intervals[1:]
		}
	}
	r.openAdded, r.openFreeze = 0, false
	r.lastFrame = now
	return froze
}

// snapshot closes the gaps still open at now and returns the recv line fields.
func (r *recvStats) snapshot(now time.Time, nack, pli uint32, rtt any) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.media == "audio" && !r.lastArrival.IsZero() {
		if o := now.Sub(r.lastArrival).Seconds() * 1000; o > audioGapMs {
			r.audioGap += o - r.openAdded
			r.openAdded = o
		}
	}
	if r.media == "video" && !r.lastFrame.IsZero() {
		if o := now.Sub(r.lastFrame).Seconds() * 1000; o > r.threshold() {
			if !r.openFreeze {
				r.freezes++
				r.openFreeze = true
			}
			r.freezeMs += o - r.openAdded
			r.openAdded = o
		}
	}
	expected := uint64(r.maxExt-r.baseExt) + 1
	var lost uint64
	if r.started && expected > r.packets {
		lost = expected - r.packets
	}
	// Stalled: no media for more than 2 s at some point since the previous report.
	stalled := r.started && (r.stallSeen || now.Sub(r.lastArrival).Seconds()*1000 > stalledAfterMs)
	r.stallSeen = false
	return map[string]any{
		"media": r.media, "group": "impaired", "frames": r.frames, "freezes": r.freezes,
		"freeze_ms": int64(r.freezeMs), "packets": r.packets, "lost": lost, "nack": nack, "pli": pli,
		"jitter_ms": round1(r.jitterTicks / r.clock), "rtt_ms": rtt, "audio_gap_ms": int64(r.audioGap),
		"stalled": stalled,
	}
}
