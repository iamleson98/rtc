package main

import (
	"testing"
	"time"
)

// freezesOf feeds one frame per gap (ms) and returns the freezes counted.
func freezesOf(gaps ...int) uint64 {
	r := newRecvStats(nil, "video", 90000)
	now := time.Unix(0, 0)
	r.frameDone(now)
	for _, g := range gaps {
		now = now.Add(time.Duration(g) * time.Millisecond)
		r.frameDone(now)
	}
	return r.freezes
}

func repeat(v, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func TestAGapNeedsFiveIntervalsBeforeItCanFreeze(t *testing.T) {
	if got := freezesOf(33, 33, 33, 33, 500); got != 1 { // four earlier and the gap: five
		t.Errorf("five intervals: %d freezes, want 1", got)
	}
	if got := freezesOf(33, 33, 33, 500); got != 0 { // three earlier and the gap: too few
		t.Errorf("four intervals: %d freezes, want 0", got)
	}
}

func TestTheGapCountsInItsOwnAverage(t *testing.T) {
	steady := append(repeat(40, 29), 194) // average 45 with the gap in it: 194 < 45 + 150
	if got := freezesOf(steady...); got != 0 {
		t.Errorf("194 ms: %d freezes, want 0", got)
	}
	steady[29] = 196 // 196 >= 195
	if got := freezesOf(steady...); got != 1 {
		t.Errorf("196 ms: %d freezes, want 1", got)
	}
}

func TestFreezeGapsStayInTheAverage(t *testing.T) {
	series := append(repeat(33, 29), 600, 190) // 57 is the average with the freeze in the window: 190 < 207
	if got := freezesOf(series...); got != 1 {
		t.Errorf("%d freezes, want 1", got)
	}
}

func TestTheWindowKeepsThirtyIntervals(t *testing.T) {
	series := append(repeat(200, 30), repeat(33, 30)...) // a slow stream, then a fast one
	series = append(series, 190)                         // 29 intervals of 33 and the gap: 190 >= 38 + 150
	if got := freezesOf(series...); got != 1 {
		t.Errorf("%d freezes, want 1", got)
	}
}
