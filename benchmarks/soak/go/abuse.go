package main

// The abuse profile of the pion peer (../README.md, "The abuse profile of the peers"). Mirrors
// ../src/abuse.rs; keep the two in step.
//
// Next to the measured call between the two peers (never touched by anything here) each peer runs
// a victim service that accepts extra peer connections, and three attack workers that open such
// connections to the other peer or throw datagrams at its media port:
//
//   - hostile: one long-lived connection that carries one attack class after another;
//   - churn: many short connections, created and torn down (conn-churn, join-leave);
//   - junk: raw UDP from sockets of its own (udp-junk, stun-flood, dtls-junk).
//
// The schedule of every worker comes from the seed alone (rng, the same generator as the rtc
// peer), and every window is an attack row in the JSONL.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

type abuseOpts struct {
	enabled bool
	seed    uint64
	only    string
	out     string
	signal  string
}

var abuseMade, abuseConnected, abuseFailed atomic.Uint64

func counters() string {
	return fmt.Sprintf("made=%d connected=%d failed=%d", abuseMade.Load(), abuseConnected.Load(), abuseFailed.Load())
}

// rng is splitmix64: the same generator in the rtc peer, so one seed is one schedule for both.
type rng struct{ s uint64 }

func (r *rng) next() uint64 {
	r.s += 0x9E3779B97F4A7C15
	z := r.s
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// span is a number in lo..=hi.
func (r *rng) span(lo, hi uint64) uint64 { return lo + r.next()%(hi-lo+1) }

func (r *rng) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.next() >> 24)
	}
	return b
}

func ms(n uint64) time.Duration { return time.Duration(n) * time.Millisecond }

// due is true once per period; it moves the timer on.
func due(t *time.Time, now time.Time, period time.Duration) bool {
	if t.After(now) {
		return false
	}
	*t = now.Add(period)
	return true
}

type abuseCfg struct {
	ctx        context.Context
	out, id    string
	offerer    bool
	seed       uint64
	listen     string
	dial       string
	mediaPorts []uint16
	only       []string
}

func (c *abuseCfg) rng(worker uint64) *rng {
	role := uint64(2)
	if c.offerer {
		role = 1
	}
	return &rng{c.seed ^ role<<56 ^ worker<<48}
}

func (c *abuseCfg) live() bool { return c.ctx.Err() == nil }

// wants is whether the attack class takes part (all of them unless --only names some).
func (c *abuseCfg) wants(class string) bool {
	if len(c.only) == 0 {
		return true
	}
	for _, o := range c.only {
		if o == class {
			return true
		}
	}
	return false
}

// nap sleeps d, or until the run is over.
func (c *abuseCfg) nap(d time.Duration) {
	select {
	case <-c.ctx.Done():
	case <-time.After(d):
	}
}

type abusers struct {
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// stop ends the workers (their open windows get an end row) and waits for them.
func (a *abusers) stop() {
	a.cancel()
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
	}
}

func startAbuse(ctx context.Context, o abuseOpts, role, id string, remotePorts []uint16) *abusers {
	host, portStr, _ := net.SplitHostPort(o.signal)
	port, _ := strconv.Atoi(portStr)
	mine, theirs := 1, 2
	if role != "offerer" {
		mine, theirs = 2, 1
	}
	ctx, cancel := context.WithCancel(ctx)
	cfg := &abuseCfg{ctx: ctx, out: o.out, id: id, offerer: role == "offerer", seed: o.seed,
		listen: net.JoinHostPort(host, strconv.Itoa(port+mine)), dial: net.JoinHostPort(host, strconv.Itoa(port+theirs)),
		mediaPorts: remotePorts}
	if o.only != "" {
		cfg.only = strings.Split(o.only, ",")
	}
	a := &abusers{cancel: cancel}
	for _, f := range []func(*abuseCfg){victimService, hostileWorker, churnWorker, junkWorker} {
		a.wg.Add(1)
		go func() { defer a.wg.Done(); f(cfg) }()
	}
	return a
}

type mode int

const (
	modeNormal mode = iota
	modeRTPJump
	modeSSRCChange
	modePLIFlood
	modeNACKFlood
	modeBogusRTCP
	modeRTPSize
	modeRTCPGarbage
	modeDCFlood
	modeDCOversize
	modeRenegoStorm
	modeGlare
	modeLateAnswer
)

var hostile = []mode{modeRTPJump, modeSSRCChange, modePLIFlood, modeNACKFlood, modeBogusRTCP, modeRTPSize,
	modeRTCPGarbage, modeDCFlood, modeDCOversize, modeRenegoStorm, modeGlare, modeLateAnswer}

var modeNames = map[mode]string{modeNormal: "normal", modeRTPJump: "rtp-jump", modeSSRCChange: "ssrc-change",
	modePLIFlood: "pli-flood", modeNACKFlood: "nack-flood", modeBogusRTCP: "bogus-rtcp", modeRTPSize: "rtp-size",
	modeRTCPGarbage: "rtcp-garbage", modeDCFlood: "dc-flood", modeDCOversize: "dc-oversize",
	modeRenegoStorm: "renego-storm", modeGlare: "glare", modeLateAnswer: "late-answer"}

func (m mode) name() string { return modeNames[m] }

// unsupported is why this implementation cannot express the attack, if it cannot.
func (m mode) unsupported() string { return "" }

// msg is one framed control message of an extra connection (the signaling of the session).
type msg struct {
	T   string                     `json:"t"`
	SDP *webrtc.SessionDescription `json:"sdp,omitempty"`
}

// rawTrack is a static RTP track that also hands out its write stream, so a packet can carry any
// SSRC, sequence number, timestamp and size (TrackLocalStaticRTP rewrites SSRC and payload type).
type rawTrack struct {
	*webrtc.TrackLocalStaticRTP
	mu   sync.Mutex
	w    webrtc.TrackLocalWriter
	ssrc uint32
	pt   uint8
}

func (t *rawTrack) Bind(c webrtc.TrackLocalContext) (webrtc.RTPCodecParameters, error) {
	p, err := t.TrackLocalStaticRTP.Bind(c)
	if err == nil {
		t.mu.Lock()
		t.w, t.ssrc, t.pt = c.WriteStream(), uint32(c.SSRC()), uint8(p.PayloadType)
		t.mu.Unlock()
	}
	return p, err
}

func (t *rawTrack) stream() (webrtc.TrackLocalWriter, uint32, uint8) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.w, t.ssrc, t.pt
}

func newRawTrack(c webrtc.RTPCodecCapability, id string) (*rawTrack, error) {
	t, err := webrtc.NewTrackLocalStaticRTP(c, id, "soak")
	if err != nil {
		return nil, err
	}
	return &rawTrack{TrackLocalStaticRTP: t}, nil
}

type pace struct {
	seq uint16
	ts  uint32
}

// sess is an extra peer connection: audio, video and data both ways, plus whatever the mode does to it.
type sess struct {
	pc        *webrtc.PeerConnection
	conn      net.Conn
	wmu       sync.Mutex
	msgs      chan msg
	polite    bool
	firstDone bool
	connected atomic.Bool
	dead      atomic.Bool
	mode      mode
	rng       *rng
	audio     *rawTrack
	video     *rawTrack
	audioExt  uint8
	altSSRC   uint32
	useAlt    bool
	a, v      pace
	frames    uint64
	tAudio    time.Time
	tVideo    time.Time
	tFast     time.Time
	tSlow     time.Time
	rxSSRC    atomic.Uint32
	rxSeq     atomic.Uint32
	dc        *webrtc.DataChannel
	dcOpen    atomic.Bool
	extraDCs  []*webrtc.DataChannel
	extra     []*webrtc.RTPSender
	pending   time.Time
	offer     *webrtc.SessionDescription
	oldOffer  *webrtc.SessionDescription
	answer    *webrtc.SessionDescription
	oldAnswer *webrtc.SessionDescription
	// ok and refused counts of what the mode sent: rtp, rtcp, data channel, session descriptions.
	tally [8]uint64
}

func newSess(conn net.Conn, polite bool, seed uint64) (*sess, error) {
	pc, err := newPeerConnection(false)
	if err != nil {
		return nil, err
	}
	s := &sess{pc: pc, conn: conn, polite: polite, rng: &rng{seed}, msgs: make(chan msg, 64),
		a: pace{1000, 5000}, v: pace{2000, 9000}, altSSRC: uint32(seed>>8) | 1}
	now := time.Now()
	s.tAudio, s.tVideo, s.tFast, s.tSlow = now, now, now, now
	if s.audio, err = newRawTrack(opusCap, "audio"); err != nil {
		return nil, err
	}
	if s.video, err = newRawTrack(vp8Cap, "video"); err != nil {
		return nil, err
	}
	for _, t := range []*rawTrack{s.audio, s.video} {
		sender, err := pc.AddTrack(t)
		if err != nil {
			return nil, err
		}
		go drainRTCP(sender, nil)
		if t == s.audio {
			s.audioExt = extID(sender, audioLevelURI)
		}
	}
	neg, dcID := true, uint16(1)
	if s.dc, err = pc.CreateDataChannel("soak", &webrtc.DataChannelInit{Negotiated: &neg, ID: &dcID}); err != nil {
		return nil, err
	}
	s.dc.OnOpen(func() { s.dcOpen.Store(true) })
	pc.OnDataChannel(func(d *webrtc.DataChannel) { d.OnMessage(func(webrtc.DataChannelMessage) {}) })
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		switch st {
		case webrtc.PeerConnectionStateConnected:
			s.connected.Store(true)
		case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			s.dead.Store(true)
		}
	})
	pc.OnTrack(func(tr *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		for {
			p, _, err := tr.ReadRTP()
			if err != nil {
				return
			}
			if tr.Kind() == webrtc.RTPCodecTypeVideo {
				s.rxSSRC.Store(uint32(tr.SSRC()))
				s.rxSeq.Store(uint32(p.SequenceNumber))
			}
		}
	})
	go func() {
		defer close(s.msgs)
		for {
			var m msg
			if err := readJSONFrame(conn, &m); err != nil {
				return
			}
			s.msgs <- m
		}
	}()
	return s, nil
}

func (s *sess) count(kind int, err error) {
	i := kind * 2
	if err != nil {
		i++
	}
	s.tally[i]++
}

// takeTally is what the window sent, as `kind ok/refused`; the counts reset.
func (s *sess) takeTally() string {
	t := s.tally
	s.tally = [8]uint64{}
	return fmt.Sprintf("rtp %d/%d rtcp %d/%d dc %d/%d sdp %d/%d", t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7])
}

func (s *sess) send(m msg) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := writeJSONFrame(s.conn, m); err != nil {
		s.dead.Store(true)
	}
}

func (s *sess) state() webrtc.SignalingState { return s.pc.SignalingState() }

// local applies a created description and returns what to send: the first one waits for the
// gathered candidates (the SDP carries them), the later ones go as created.
func (s *sess) local(d webrtc.SessionDescription) (webrtc.SessionDescription, error) {
	if s.firstDone {
		return d, s.pc.SetLocalDescription(d)
	}
	gathered := webrtc.GatheringCompletePromise(s.pc)
	if err := s.pc.SetLocalDescription(d); err != nil {
		return d, err
	}
	<-gathered
	s.firstDone = true
	return *s.pc.LocalDescription(), nil
}

// sendOffer creates an offer, applies it and sends it. False when the library refuses.
func (s *sess) sendOffer(now time.Time) bool {
	offer, err := s.pc.CreateOffer(nil)
	if err != nil {
		s.count(3, err)
		return false
	}
	d, err := s.local(offer)
	s.count(3, err)
	if err != nil {
		return false
	}
	s.oldOffer, s.offer = s.offer, &d
	s.pending = now
	s.send(msg{T: "offer", SDP: &d})
	return true
}

func (s *sess) rollback() {
	_ = s.pc.SetLocalDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeRollback})
	s.pending = time.Time{}
}

func (s *sess) onMsg(now time.Time, m msg) {
	switch {
	case m.T == "offer" && m.SDP != nil:
		if s.polite && s.state() == webrtc.SignalingStateHaveLocalOffer {
			s.rollback()
		}
		err := s.pc.SetRemoteDescription(*m.SDP)
		s.count(3, err)
		if err != nil {
			return
		}
		answer, err := s.pc.CreateAnswer(nil)
		if err != nil {
			return
		}
		d, err := s.local(answer)
		if err != nil {
			return
		}
		s.oldAnswer, s.answer = s.answer, &d
		s.send(msg{T: "answer", SDP: &d})
	case m.T == "answer" && m.SDP != nil:
		err := s.pc.SetRemoteDescription(*m.SDP)
		s.count(3, err)
		if err == nil {
			s.pending = time.Time{}
		}
		if err == nil && s.mode == modeLateAnswer {
			// The answer of the round before, and the offer of the round before again (once per
			// round: the answer to that offer is refused, so it does not start another).
			if s.oldAnswer != nil {
				s.count(3, s.pc.SetRemoteDescription(*s.oldAnswer))
			}
			if s.oldOffer != nil {
				s.send(msg{T: "offer", SDP: s.oldOffer})
			}
		}
	case m.T == "glare":
		s.sendOffer(now)
	case m.T == "bye":
		s.dead.Store(true)
	}
}

func (s *sess) drain(now time.Time) {
	for {
		select {
		case m, ok := <-s.msgs:
			if !ok {
				s.dead.Store(true)
				return
			}
			s.onMsg(now, m)
			continue
		default:
		}
		break
	}
	if !s.pending.IsZero() && now.After(s.pending.Add(3*time.Second)) {
		s.rollback()
	}
}

// rtp sends one RTP packet of length payload bytes and moves the sequence number on.
func (s *sess) rtp(audio bool, length int, marker bool) {
	t, p := s.video, &s.v
	if audio {
		t, p = s.audio, &s.a
	}
	w, ssrc, pt := t.stream()
	if w == nil {
		return
	}
	if !audio && s.useAlt {
		ssrc = s.altSSRC
	}
	h := rtp.Header{Version: 2, Marker: marker, PayloadType: pt, SequenceNumber: p.seq, Timestamp: p.ts, SSRC: ssrc}
	p.seq++
	if audio && s.audioExt != 0 {
		_ = h.SetExtension(s.audioExt, []byte{0x80 | 40})
	}
	_, err := w.WriteRTP(&h, s.rng.bytes(length))
	s.count(0, err)
}

var rtpSizes = [7]int{0, 1, 2, 100, 1188, 1400, 1450}

func (s *sess) media(now time.Time) {
	if w, _, _ := s.audio.stream(); w == nil {
		return
	}
	for !s.tAudio.After(now) {
		length := 80
		if s.mode == modeRTPSize {
			length = rtpSizes[s.rng.next()%7]
		}
		s.rtp(true, length, false)
		s.a.ts += 960
		s.tAudio = s.tAudio.Add(20 * time.Millisecond)
	}
	for !s.tVideo.After(now) {
		n := 1
		if s.frames%120 == 0 {
			n = 6
		}
		for i := 0; i < n; i++ {
			length := 1000
			if s.mode == modeRTPSize {
				length = rtpSizes[s.rng.next()%7]
			}
			s.rtp(false, length, i == n-1)
		}
		s.frames++
		s.v.ts += 3000
		s.tVideo = s.tVideo.Add(33333333 * time.Nanosecond)
	}
}

func (s *sess) victimSSRC() uint32 {
	if v := s.rxSSRC.Load(); v != 0 {
		return v
	}
	return uint32(s.rng.next())
}

// writeRTCP sends the packets as one compound datagram.
func (s *sess) writeRTCP(pkts ...rtcp.Packet) { s.count(1, s.pc.WriteRTCP(pkts)) }

func (s *sess) dcSend(n int) {
	b := s.rng.bytes(n)
	if s.dcOpen.Load() && s.dc.BufferedAmount() < 4<<20 {
		s.count(2, s.dc.Send(b))
	}
}

func (s *sess) toggleTrack() {
	if len(s.extra) < 4 && (len(s.extra) == 0 || s.rng.next()%2 == 0) {
		ssrc := uint32(s.rng.next()) | 1
		t, err := newRawTrack(opusCap, fmt.Sprintf("extra-%d", ssrc))
		if err != nil {
			return
		}
		if sender, err := s.pc.AddTrack(t); err == nil {
			s.extra = append(s.extra, sender)
			go drainRTCP(sender, nil)
		}
	} else if n := len(s.extra); n > 0 {
		_ = s.pc.RemoveTrack(s.extra[n-1])
		s.extra = s.extra[:n-1]
	}
}

// hostile is what the mode does to the connection, on top of the normal media.
func (s *sess) hostile(now time.Time) {
	switch s.mode {
	case modeRTPJump:
		if due(&s.tSlow, now, ms(200)) {
			j, t := uint16(s.rng.span(1, 30000)), uint32(s.rng.next())>>1
			switch s.rng.next() % 4 {
			case 0:
				s.v.seq, s.v.ts = s.v.seq+j, s.v.ts+t
			case 1:
				s.v.seq, s.v.ts = s.v.seq-j, s.v.ts-t
			case 2:
				s.a.seq, s.a.ts = s.a.seq-j, s.a.ts+t
			default:
				s.v.seq-- // a duplicate
			}
		}
	case modeSSRCChange:
		if due(&s.tSlow, now, ms(1500)) {
			s.useAlt = !s.useAlt
			if s.rng.next()%2 == 0 {
				s.v = pace{uint16(s.rng.next()), uint32(s.rng.next())}
			}
		}
	case modePLIFlood:
		if due(&s.tFast, now, ms(10)) {
			media, sender := s.victimSSRC(), uint32(s.rng.next())
			pkts := make([]rtcp.Packet, 30)
			for i := range pkts {
				pkts[i] = &rtcp.PictureLossIndication{SenderSSRC: sender, MediaSSRC: media}
			}
			s.writeRTCP(pkts...)
		}
	case modeNACKFlood:
		if due(&s.tFast, now, ms(10)) {
			media := s.victimSSRC()
			_, sender, _ := s.video.stream()
			var nacks []rtcp.NackPair
			for i := 0; i < 10; i++ {
				id := uint16(s.rng.next())
				if i%2 == 0 {
					id = uint16(s.rxSeq.Load()) - uint16(s.rng.span(0, 200))
				}
				nacks = append(nacks, rtcp.NackPair{PacketID: id, LostPackets: 0xFFFF})
			}
			s.writeRTCP(&rtcp.TransportLayerNack{SenderSSRC: sender, MediaSSRC: media, Nacks: nacks})
		}
	case modeBogusRTCP:
		if due(&s.tFast, now, ms(20)) {
			var reports []rtcp.ReceptionReport
			for i := s.rng.span(0, 4); i > 0; i-- {
				reports = append(reports, rtcp.ReceptionReport{SSRC: uint32(s.rng.next()), FractionLost: uint8(s.rng.next()),
					TotalLost: uint32(s.rng.next()) & 0xFFFFFF, LastSequenceNumber: uint32(s.rng.next()), Jitter: uint32(s.rng.next()),
					LastSenderReport: uint32(s.rng.next()), Delay: uint32(s.rng.next())})
			}
			bitrates := []float32{0, 1, 64000, 1e12, 3.4028235e38}
			var ssrcs []uint32
			for i := s.rng.span(0, 5); i > 0; i-- {
				ssrcs = append(ssrcs, uint32(s.rng.next()))
			}
			twcc := []byte{0x8F, 205, 0, 0}
			twcc = append(twcc, s.rng.bytes(8+4*int(s.rng.span(0, 8)))...)
			binary.BigEndian.PutUint16(twcc[2:], uint16(len(twcc)/4-1))
			a, b := uint32(s.rng.next()), uint32(s.rng.next())
			pick := bitrates[s.rng.next()%uint64(len(bitrates))]
			// one datagram each: a packet the library cannot marshal must not take the others with it
			s.writeRTCP(&rtcp.ReceiverReport{SSRC: a, Reports: reports})
			s.writeRTCP(&rtcp.ReceiverEstimatedMaximumBitrate{SenderSSRC: b, Bitrate: pick, SSRCs: ssrcs})
			raw := rtcp.RawPacket(twcc)
			s.writeRTCP(&raw)
		}
	case modeRTCPGarbage:
		if due(&s.tFast, now, ms(10)) {
			raw := rtcp.RawPacket(rtcpGarbage(s.rng))
			s.writeRTCP(&raw)
		}
	case modeDCFlood:
		if due(&s.tFast, now, ms(10)) {
			for i := 0; i < 50; i++ {
				s.dcSend(int(s.rng.span(8, 64)))
			}
		}
		if s.connected.Load() && due(&s.tSlow, now, ms(500)) {
			for i := 0; i < 5; i++ {
				if d, err := s.pc.CreateDataChannel("storm", nil); err == nil {
					s.extraDCs = append(s.extraDCs, d)
				}
			}
			for len(s.extraDCs) > 30 {
				_ = s.extraDCs[0].Close()
				s.extraDCs = s.extraDCs[1:]
			}
		}
	case modeDCOversize:
		if due(&s.tSlow, now, ms(500)) {
			sizes := []int{1024, 16384, 65535, 65536, 131072, 262143, 262144, 262145, 1 << 20}
			s.dcSend(sizes[s.rng.next()%uint64(len(sizes))])
		}
	case modeRenegoStorm, modeLateAnswer:
		if s.pending.IsZero() && due(&s.tSlow, now, ms(400)) {
			s.toggleTrack()
			s.sendOffer(now)
		}
	case modeGlare:
		if s.pending.IsZero() && due(&s.tSlow, now, ms(1000)) {
			// The other side's offer is on its way while ours is pending.
			s.send(msg{T: "glare"})
			s.sendOffer(now)
		}
	}
}

// run runs the connection in the mode until `until`, the end of the run, or (untilConnected) the
// moment it is connected. A connection that fails or is closed by the other side is dead.
func (s *sess) run(ctx context.Context, until time.Time, m mode, untilConnected bool) {
	s.mode = m
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		now := time.Now()
		if s.dead.Load() || ctx.Err() != nil || !now.Before(until) || (untilConnected && s.connected.Load()) {
			return
		}
		s.drain(now)
		s.media(now)
		s.hostile(now)
		select {
		case <-tick.C:
		case <-ctx.Done():
		}
	}
}

func (s *sess) close() {
	s.send(msg{T: "bye"})
	_ = s.pc.Close()
	_ = s.conn.Close()
}

// rtcpGarbage is an RTCP datagram that is wrong in one way or another.
func rtcpGarbage(r *rng) []byte {
	switch r.next() % 6 {
	case 0:
		return r.bytes(int(r.span(4, 200)))
	case 1: // a valid header whose length claims far more than is there
		return append([]byte{0x80, byte(r.span(200, 210)), 0xFF, 0xF0}, r.bytes(12)...)
	case 2: // shorter than a header
		return r.bytes(3)
	case 3: // a real PLI followed by garbage
		v := append([]byte{0x81, 206, 0, 2}, r.bytes(8)...)
		return append(v, r.bytes(int(r.span(1, 60)))...)
	case 4:
		return make([]byte, 64)
	default:
		b := make([]byte, 64)
		for i := range b {
			b[i] = 0xFF
		}
		return b
	}
}

func dial(cfg *abuseCfg, seed uint64, polite bool) *sess {
	giveUp := time.Now().Add(30 * time.Second)
	for cfg.live() && time.Now().Before(giveUp) {
		if conn, err := net.DialTimeout("tcp", cfg.dial, time.Second); err == nil {
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			s, err := newSess(conn, polite, seed)
			if err != nil {
				_ = conn.Close()
				return nil
			}
			return s
		}
		cfg.nap(ms(200))
	}
	return nil
}

// establish opens a connection to the other peer and brings it up; nil when it does not connect in time.
func establish(cfg *abuseCfg, seed uint64, wait time.Duration) *sess {
	abuseMade.Add(1)
	s := dial(cfg, seed, false)
	if s == nil {
		abuseFailed.Add(1)
		return nil
	}
	if !s.sendOffer(time.Now()) {
		abuseFailed.Add(1)
		s.close()
		return nil
	}
	s.run(cfg.ctx, time.Now().Add(wait), modeNormal, true)
	if !s.connected.Load() {
		abuseFailed.Add(1)
		s.close()
		return nil
	}
	abuseConnected.Add(1)
	return s
}

// victimService accepts the extra connections of the other peer, one goroutine each.
func victimService(cfg *abuseCfg) {
	l, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		fmt.Printf("soak-pion: abuse listener %s unavailable\n", cfg.listen)
		return
	}
	go func() { <-cfg.ctx.Done(); _ = l.Close() }()
	r := cfg.rng(4)
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		seed := r.next()
		go func() {
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			s, err := newSess(conn, true, seed)
			if err != nil {
				_ = conn.Close()
				return
			}
			s.run(cfg.ctx, time.Now().Add(24*time.Hour), modeNormal, false)
			s.close()
		}()
	}
}

func hostileWorker(cfg *abuseCfg) {
	log, err := newLogger(cfg.out, cfg.id+"-hostile")
	if err != nil {
		return
	}
	log.event("seed", fmt.Sprintf("hostile worker seed %d", cfg.seed))
	var modes []mode
	for _, m := range hostile {
		if why := m.unsupported(); why != "" {
			log.event("attack-unsupported", m.name()+": "+why)
		}
		if cfg.wants(m.name()) {
			modes = append(modes, m)
		}
	}
	if len(modes) == 0 {
		return
	}
	r := cfg.rng(0)
	var s *sess
	n := 0
	for cfg.live() {
		idle := ms(r.span(3000, 8000))
		m := modes[r.next()%uint64(len(modes))]
		dur := ms(r.span(8000, 20000))
		sub := r.next()
		if s == nil {
			if s = establish(cfg, sub, 20*time.Second); s == nil {
				cfg.nap(2 * time.Second)
				continue
			}
		}
		s.rng = &rng{sub}
		s.takeTally()
		s.run(cfg.ctx, time.Now().Add(idle), modeNormal, false)
		if s.dead.Load() {
			s.close()
			s = nil
			continue
		}
		if m.unsupported() != "" {
			s.run(cfg.ctx, time.Now().Add(dur), modeNormal, false)
			continue
		}
		n++
		id := fmt.Sprintf("%s-%s-%d", cfg.id, m.name(), n)
		log.attack(id, m.name(), "start", cfg.seed, fmt.Sprintf("hostile connection, %d ms", dur.Milliseconds()))
		s.run(cfg.ctx, time.Now().Add(dur), m, false)
		detail := s.takeTally()
		if s.dead.Load() {
			detail += "; the connection died"
		}
		log.attack(id, m.name(), "end", cfg.seed, detail)
		if s.dead.Load() {
			s.close()
			s = nil
		}
	}
	if s != nil {
		s.close()
	}
}

func churnWorker(cfg *abuseCfg) {
	log, err := newLogger(cfg.out, cfg.id+"-churn")
	if err != nil {
		return
	}
	log.event("seed", fmt.Sprintf("churn worker seed %d", cfg.seed))
	conn, quickOK := cfg.wants("conn-churn"), cfg.wants("join-leave")
	if !conn && !quickOK {
		return
	}
	r := cfg.rng(1)
	n := 0
	for cfg.live() {
		cfg.nap(ms(r.span(1000, 4000)))
		quick := quickOK && (!conn || r.next()%3 == 0)
		name, count := "conn-churn", 8
		if quick {
			name, count = "join-leave", 20
		}
		n++
		id := fmt.Sprintf("%s-%s-%d", cfg.id, name, n)
		log.attack(id, name, "start", cfg.seed, fmt.Sprintf("%d connections", count))
		for i := 0; i < count && cfg.live(); i++ {
			var life time.Duration
			if quick {
				life = ms(r.span(0, 800))
			} else {
				life = ms(r.span(2000, 6000))
			}
			seed := r.next()
			if quick {
				// gone before the connection is up, most of the time
				abuseMade.Add(1)
				s := dial(cfg, seed, false)
				if s == nil {
					abuseFailed.Add(1)
					continue
				}
				if s.sendOffer(time.Now()) {
					s.run(cfg.ctx, time.Now().Add(life), modeNormal, false)
				}
				if s.connected.Load() {
					abuseConnected.Add(1)
				}
				s.close()
			} else if s := establish(cfg, seed, 10*time.Second); s != nil {
				s.run(cfg.ctx, time.Now().Add(life), modeNormal, false)
				s.close()
			}
		}
		log.attack(id, name, "end", cfg.seed, counters())
		log.event("churn", counters())
	}
}

func junkWorker(cfg *abuseCfg) {
	log, err := newLogger(cfg.out, cfg.id+"-junk")
	if err != nil {
		return
	}
	log.event("seed", fmt.Sprintf("junk worker seed %d", cfg.seed))
	var classes []string
	for _, c := range []string{"udp-junk", "stun-flood", "dtls-junk"} {
		if cfg.wants(c) {
			classes = append(classes, c)
		}
	}
	if len(classes) == 0 {
		return
	}
	r := cfg.rng(2)
	n := 0
	for cfg.live() {
		cfg.nap(ms(r.span(5000, 15000)))
		class := classes[r.next()%uint64(len(classes))]
		until := time.Now().Add(ms(r.span(8000, 20000)))
		if !cfg.live() {
			break
		}
		n++
		id := fmt.Sprintf("%s-%s-%d", cfg.id, class, n)
		log.attack(id, class, "start", cfg.seed, "from loopback sockets, about 2000 datagrams/s")
		count := 4
		if class == "stun-flood" {
			count = 200
		}
		var socks []*net.UDPConn
		for i := 0; i < count; i++ {
			if c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err == nil {
				socks = append(socks, c)
			}
		}
		for len(cfg.mediaPorts) > 0 && len(socks) > 0 && cfg.live() && time.Now().Before(until) {
			for i := 0; i < 20; i++ {
				var pkt []byte
				switch class {
				case "stun-flood":
					pkt = stunRequest(r)
				case "dtls-junk":
					pkt = dtlsJunk(r)
				default:
					pkt = r.bytes(int(r.span(1, 1400)))
				}
				c := socks[r.next()%uint64(len(socks))]
				port := cfg.mediaPorts[r.next()%uint64(len(cfg.mediaPorts))]
				_, _ = c.WriteToUDP(pkt, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
			}
			cfg.nap(10 * time.Millisecond)
		}
		for _, c := range socks {
			_ = c.Close()
		}
		log.attack(id, class, "end", cfg.seed, "")
	}
}

// stunRequest is a STUN binding request with a username nobody knows and a made-up integrity attribute.
func stunRequest(r *rng) []byte {
	user := fmt.Sprintf("%08x:%08x", uint32(r.next()), uint32(r.next()))
	attrs := append([]byte{0x00, 0x06, 0x00, byte(len(user))}, user...)
	attrs = append(attrs, 0, 0, 0)                                        // pad 17 to 20
	attrs = append(attrs, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x1e, 0xff) // PRIORITY
	attrs = append(attrs, 0x00, 0x08, 0x00, 0x14)                         // MESSAGE-INTEGRITY
	attrs = append(attrs, r.bytes(20)...)
	v := []byte{0x00, 0x01, byte(len(attrs) >> 8), byte(len(attrs)), 0x21, 0x12, 0xA4, 0x42}
	v = append(v, r.bytes(12)...)
	return append(v, attrs...)
}

// dtlsJunk is a DTLS record that opens like a ClientHello and goes wrong inside (or is another record type).
func dtlsJunk(r *rng) []byte {
	body := r.bytes(int(r.span(20, 300)))
	l := []byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs := append([]byte{1}, l...)
	hs = append(hs, 0, 0, 0, 0, 0) // message_seq, fragment_offset
	hs = append(hs, l...)
	hs = append(hs, body...)
	kind := byte(22)
	if r.next()%4 == 0 {
		kind = []byte{20, 21, 23}[r.next()%3]
	}
	ver := byte(0xFD)
	if r.next()%2 == 0 {
		ver = 0xFF
	}
	v := []byte{kind, 0xFE, ver, 0, 0}
	v = append(v, r.bytes(6)...)
	v = append(v, byte(len(hs)>>8), byte(len(hs)))
	return append(v, hs...)
}
