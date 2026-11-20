package main

import (
	"net"
	"reflect"
	"sync/atomic"

	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
)

// Datagram classes of what a peer puts on the wire (RFC 7983, RTP and RTCP told apart by RFC 5761).
// DTLS holds the SCTP of the data channel.
var txClasses = [...]string{"rtp", "rtcp", "dtls", "stun", "other"}

// txCounts counts what one peer sent: datagrams by class, the RTP packets that were retransmissions
// answering a NACK, and the NACKs it sent itself (pion's own stats leave NACKCount at zero).
type txCounts struct {
	pkts, bytes [len(txClasses)]atomic.Uint64
	retx, nacks atomic.Uint64
}

func (t *txCounts) add(d []byte) {
	class := 4
	if len(d) > 0 {
		switch b := d[0]; {
		case b <= 3:
			class = 3
		case b >= 20 && b <= 63:
			class = 2
		case b >= 128 && b <= 191:
			class = 0
			if len(d) > 1 && d[1] >= 192 && d[1] <= 223 {
				class = 1
			}
		}
	}
	t.pkts[class].Add(1)
	t.bytes[class].Add(uint64(len(d)))
}

func (t *txCounts) fields() map[string]any {
	out := map[string]any{"retx": t.retx.Load()}
	for i, name := range txClasses {
		out[name+"_pkts"] = t.pkts[i].Load()
		out[name+"_bytes"] = t.bytes[i].Load()
	}
	return out
}

// countingConn counts every datagram written through it.
type countingConn struct {
	net.PacketConn
	tx *txCounts
}

func (c countingConn) WriteTo(p []byte, a net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, a)
	if err == nil {
		c.tx.add(p)
	}
	return n, err
}

// countingFactory builds the interceptor that counts retransmissions and NACKs. The chain wraps each
// writer in registration order, so the retransmissions that the NACK responder writes pass through only
// the interceptors registered before it: this one is added before the default ones.
type countingFactory struct{ tx *txCounts }

func (f countingFactory) NewInterceptor(string) (interceptor.Interceptor, error) {
	return &counting{tx: f.tx}, nil
}

type counting struct {
	interceptor.NoOp
	tx *txCounts
}

func (c *counting) BindLocalStream(_ *interceptor.StreamInfo, w interceptor.RTPWriter) interceptor.RTPWriter {
	return interceptor.RTPWriterFunc(func(h *rtp.Header, payload []byte, a interceptor.Attributes) (int, error) {
		// The resend key's type is internal to the library; its name is the contract.
		for k := range a {
			if reflect.TypeOf(k).Name() == "ResendKey" {
				c.tx.retx.Add(1)
				break
			}
		}
		return w.Write(h, payload, a)
	})
}

func (c *counting) BindRTCPWriter(w interceptor.RTCPWriter) interceptor.RTCPWriter {
	return interceptor.RTCPWriterFunc(func(pkts []rtcp.Packet, a interceptor.Attributes) (int, error) {
		for _, p := range pkts {
			if _, ok := p.(*rtcp.TransportLayerNack); ok {
				c.tx.nacks.Add(1)
			}
		}
		return w.Write(pkts, a)
	})
}
