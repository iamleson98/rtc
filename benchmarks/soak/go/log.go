package main

import (
	"encoding/json"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"
)

// arch is the machine architecture as uname -m prints it.
var arch = map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]

// logger appends JSONL lines in the schema of benchmarks/soak/README.md.
type logger struct {
	mu sync.Mutex
	f  *os.File
	id string
}

func newLogger(path, id string) (*logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &logger{f: f, id: id}, nil
}

func (l *logger) emit(kind, id string, kv map[string]any) { l.emitAs("pion", kind, id, kv) }

func (l *logger) emitAs(impl, kind, id string, kv map[string]any) {
	kv["ts"] = time.Now().UnixMilli()
	kv["impl"] = impl
	kv["arch"] = arch
	kv["kind"] = kind
	kv["id"] = id
	b, err := json.Marshal(kv)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(append(b, '\n'))
}

func (l *logger) event(what, detail string) {
	l.emit("event", l.id, map[string]any{"what": what, "detail": detail})
}

// percentile is the nearest-rank percentile of an unsorted slice; nil when it is empty.
func percentile(xs []float64, p float64) any {
	if len(xs) == 0 {
		return nil
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	i := int(float64(len(s))*p/100.0+0.999999) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(s) {
		i = len(s) - 1
	}
	return round1(s[i])
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// attack writes an `attack` window edge (README.md, kind attack) as the pseudo implementation
// `abuse`. who is the hostile connection, never a measured participant, so every measured receiver
// counts as innocent in the window.
func (l *logger) attack(id, name, state string, seed uint64, detail string) {
	l.emitAs("abuse", "attack", id, map[string]any{"name": name, "state": state, "group": "impaired",
		"who": []string{l.id + "-abuser"}, "seed": seed, "detail": detail})
}
