package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// procSampler reads this process's resource use from /proc (zeros where /proc is missing).
type procSampler struct {
	lastCPU  float64
	lastWall time.Time
}

func (p *procSampler) sample() map[string]any {
	out := map[string]any{"rss_mb": 0.0, "cpu_pct": 0.0, "threads": 0, "fds": 0, "udp_rcvbuf_err": 0, "udp_sndbuf_err": 0}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			switch f[0] {
			case "VmRSS:":
				kb, _ := strconv.ParseFloat(f[1], 64)
				out["rss_mb"] = round1(kb / 1024)
			case "Threads:":
				out["threads"], _ = strconv.Atoi(f[1])
			}
		}
	}
	if ents, err := os.ReadDir("/proc/self/fd"); err == nil {
		out["fds"] = len(ents)
	}
	if b, err := os.ReadFile("/proc/self/stat"); err == nil {
		s := string(b)
		if i := strings.LastIndexByte(s, ')'); i > 0 {
			f := strings.Fields(s[i+1:])
			if len(f) > 13 { // utime and stime are fields 14 and 15 of the whole line
				ut, _ := strconv.ParseFloat(f[11], 64)
				st, _ := strconv.ParseFloat(f[12], 64)
				cpu := (ut + st) / 100.0 // CLK_TCK is 100 on Linux
				now := time.Now()
				if !p.lastWall.IsZero() {
					out["cpu_pct"] = round1((cpu - p.lastCPU) / now.Sub(p.lastWall).Seconds() * 100)
				}
				p.lastCPU, p.lastWall = cpu, now
			}
		}
	}
	if b, err := os.ReadFile("/proc/net/snmp"); err == nil {
		var head []string
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || f[0] != "Udp:" {
				continue
			}
			if head == nil {
				head = f
				continue
			}
			for i, name := range head {
				v, _ := strconv.Atoi(f[i])
				switch name {
				case "RcvbufErrors":
					out["udp_rcvbuf_err"] = v
				case "SndbufErrors":
					out["udp_sndbuf_err"] = v
				}
			}
		}
	}
	return out
}
