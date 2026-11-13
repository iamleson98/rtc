package main

import (
	"context"
	"encoding/json"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
)

const (
	audioLevelURI = "urn:ietf:params:rtp-hdrext:ssrc-audio-level"
	startSeq      = uint16(65536 - 300)
	startAudioTS  = uint32(1<<32 - 20*48000) // twenty seconds before the 32-bit wrap
	startVideoTS  = uint32(1<<32 - 20*90000)
	videoMTU      = 1200
	frameInterval = time.Second / 30
	keyframeEvery = 120 // frames: four seconds at 30 fps
	keyframeBytes = 24000
	interBytes    = 4875 // together about 1.2 Mbit/s with the keyframes
)

// extID finds the negotiated header-extension id for uri on a sender, or 0.
func extID(s *webrtc.RTPSender, uri string) uint8 {
	for _, e := range s.GetParameters().HeaderExtensions {
		if e.URI == uri {
			return uint8(e.ID)
		}
	}
	return 0
}

// drainRTCP reads a sender's RTCP (which also drives the NACK responder interceptor) and sets
// keyframe on a PLI or FIR.
func drainRTCP(s *webrtc.RTPSender, keyframe *atomic.Bool) {
	for {
		pkts, _, err := s.ReadRTCP()
		if err != nil {
			return
		}
		for _, p := range pkts {
			switch p.(type) {
			case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
				if keyframe != nil {
					keyframe.Store(true)
				}
			}
		}
	}
}

func sendAudio(ctx context.Context, l *logger, track *webrtc.TrackLocalStaticRTP, s *webrtc.RTPSender) {
	id := extID(s, audioLevelURI)
	rng := rand.New(rand.NewSource(1))
	seq, ts := startSeq, startAudioTS
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	payload := make([]byte, 80)
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		rng.Read(payload)
		p := &rtp.Packet{Header: rtp.Header{Version: 2, SequenceNumber: seq, Timestamp: ts, Marker: n == 0}, Payload: payload}
		if id != 0 {
			_ = p.Header.SetExtension(id, []byte{0x80 | byte(30+rng.Intn(30))})
		}
		if err := track.WriteRTP(p); err != nil {
			l.event("error", "audio write: "+err.Error())
		}
		seq++
		if seq == 0 {
			l.event("wrap", "send audio seq wrap")
		}
		ts += 960
		if ts < 960 {
			l.event("wrap", "send audio ts wrap")
		}
	}
}

func sendVideo(ctx context.Context, l *logger, track *webrtc.TrackLocalStaticRTP, keyframe *atomic.Bool) {
	rng := rand.New(rand.NewSource(2))
	pay := &codecs.VP8Payloader{EnablePictureID: true}
	seq, ts := startSeq, startVideoTS
	tick := time.NewTicker(frameInterval)
	defer tick.Stop()
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		key := n%keyframeEvery == 0 || keyframe.Swap(false)
		size := interBytes + rng.Intn(interBytes/2) - interBytes/4
		if key {
			size = keyframeBytes
		}
		frame := make([]byte, size)
		rng.Read(frame)
		frame[0] &^= 1 // VP8 frame tag bit 0: 0 is a keyframe
		if !key {
			frame[0] |= 1
		}
		parts := pay.Payload(videoMTU, frame)
		for i, part := range parts {
			p := &rtp.Packet{Header: rtp.Header{Version: 2, SequenceNumber: seq, Timestamp: ts, Marker: i == len(parts)-1}, Payload: part}
			if err := track.WriteRTP(p); err != nil {
				l.event("error", "video write: "+err.Error())
			}
			seq++
			if seq == 0 {
				l.event("wrap", "send video seq wrap")
			}
		}
		ts += 3000
		if ts < 3000 {
			l.event("wrap", "send video ts wrap")
		}
	}
}

// dcState carries the data-channel counters and the latencies of the current 5 s window.
type dcState struct {
	sent, recv atomic.Uint64
	lat        chan float64
}

func sendData(ctx context.Context, dc *webrtc.DataChannel, st *dcState) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for n := uint64(0); ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		msg, _ := json.Marshal(map[string]any{"n": n, "ts": time.Now().UnixMicro()})
		if dc.BufferedAmount() > 1<<20 {
			continue
		}
		if err := dc.Send(msg); err == nil {
			st.sent.Add(1)
		}
	}
}

func onData(st *dcState, msg webrtc.DataChannelMessage) {
	var m struct {
		TS int64 `json:"ts"`
	}
	if json.Unmarshal(msg.Data, &m) != nil {
		return
	}
	st.recv.Add(1)
	select {
	case st.lat <- float64(time.Now().UnixMicro()-m.TS) / 1000:
	default:
	}
}
