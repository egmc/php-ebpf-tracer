package pipeline

import (
	"testing"
	"time"

	"github.com/egmc/php-ebpf-tracer/internal/event"
)

type capture struct{ got []*Request }

func (c *capture) Export(r *Request) { c.got = append(c.got, r) }

const (
	traceHi = 0x0123456789abcdef
	traceLo = 0xfedcba9876543210
	rootID  = 0x1111111111111111
)

func startEvent(key uint64, startNS uint64) *event.Event {
	return &event.Event{
		Type:      event.TypeReqStart,
		PID:       uint32(key >> 32),
		TID:       uint32(key),
		TsStart:   startNS,
		TraceIDHi: traceHi,
		TraceIDLo: traceLo,
		SpanID:    rootID,
		URI:       "/slow",
		Method:    "GET",
		File:      "/app/index.php",
	}
}

func endEvent(key uint64, startNS, endNS uint64) *event.Event {
	e := startEvent(key, startNS)
	e.Type = event.TypeReqEnd
	e.TsEnd = endNS

	return e
}

func funcEvent(key, span, parent uint64, startNS, endNS uint64, name string, depth uint32) *event.Event {
	return &event.Event{
		Type:         event.TypeFunc,
		PID:          uint32(key >> 32),
		TID:          uint32(key),
		TsStart:      startNS,
		TsEnd:        endNS,
		TraceIDHi:    traceHi,
		TraceIDLo:    traceLo,
		SpanID:       span,
		ParentSpanID: parent,
		Func:         name,
		Depth:        depth,
	}
}

func TestExportThreshold(t *testing.T) {
	const ms = uint64(time.Millisecond)

	cases := []struct {
		name       string
		durationNS uint64
		minAllowed time.Duration
		wantExport bool
	}{
		{"slower than threshold", 250 * ms, 100 * time.Millisecond, true},
		{"exactly at threshold", 100 * ms, 100 * time.Millisecond, true},
		{"faster than threshold", 5 * ms, 100 * time.Millisecond, false},
		{"threshold disabled", 1, 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &capture{}
			agg := New(Config{MinDuration: tc.minAllowed}, sink)

			const key = uint64(4242)<<32 | 4242
			now := time.Now()
			agg.Handle(startEvent(key, 1_000_000), now)
			agg.Handle(endEvent(key, 1_000_000, 1_000_000+tc.durationNS), now)

			if got := len(sink.got) == 1; got != tc.wantExport {
				t.Fatalf("exported=%v, want %v (stats %+v)", got, tc.wantExport, agg.Stats())
			}
			if s := agg.Stats(); s.InFlight != 0 {
				t.Fatalf("in-flight state leaked: %d", s.InFlight)
			}
		})
	}
}

func TestExportedTraceShape(t *testing.T) {
	sink := &capture{}
	agg := New(Config{MinDuration: 10 * time.Millisecond}, sink)

	const key = uint64(7)<<32 | 7
	now := time.Now()
	agg.Handle(startEvent(key, 0), now)
	// root -> a -> b
	agg.Handle(funcEvent(key, 0xb, 0xa, 20, 80, "inner", 1), now)
	agg.Handle(funcEvent(key, 0xa, rootID, 10, 90, "outer", 0), now)
	agg.Handle(endEvent(key, 0, uint64(50*time.Millisecond)), now)

	if len(sink.got) != 1 {
		t.Fatalf("got %d traces, want 1", len(sink.got))
	}
	r := sink.got[0]

	if r.RootName() != "GET /slow" {
		t.Errorf("root name = %q", r.RootName())
	}
	if len(r.Spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(r.Spans))
	}
	// finalize must order parents before children.
	if r.Spans[0].Func != "outer" || r.Spans[1].Func != "inner" {
		t.Errorf("span order = %q, %q; want outer, inner", r.Spans[0].Func, r.Spans[1].Func)
	}
	if r.Spans[1].ParentID != 0xa {
		t.Errorf("inner parent = %#x, want 0xa", r.Spans[1].ParentID)
	}

	want := [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	if r.TraceID() != want {
		t.Errorf("trace id = %x, want %x", r.TraceID(), want)
	}
}

func TestFinalizeReparentsAroundDroppedSpans(t *testing.T) {
	sink := &capture{}
	agg := New(Config{MinSpanDuration: 50 * time.Nanosecond}, sink)

	const key = uint64(9)<<32 | 9
	now := time.Now()
	agg.Handle(startEvent(key, 0), now)
	// kept(0xa) -> dropped(0xb, 10ns) -> kept(0xc)
	agg.Handle(funcEvent(key, 0xc, 0xb, 30, 130, "grandchild", 2), now)
	agg.Handle(funcEvent(key, 0xb, 0xa, 20, 30, "tooShort", 1), now)
	agg.Handle(funcEvent(key, 0xa, rootID, 10, 200, "parent", 0), now)
	// A span whose parent was never reported at all.
	agg.Handle(funcEvent(key, 0xd, 0xdead, 40, 140, "orphan", 3), now)
	agg.Handle(endEvent(key, 0, 300), now)

	r := sink.got[0]
	byName := map[string]*Span{}
	for i := range r.Spans {
		byName[r.Spans[i].Func] = &r.Spans[i]
	}

	if _, ok := byName["tooShort"]; ok {
		t.Error("tooShort should have been dropped")
	}
	if got := byName["grandchild"].ParentID; got != 0xa {
		t.Errorf("grandchild re-parented to %#x, want 0xa", got)
	}
	if got := byName["orphan"].ParentID; got != rootID {
		t.Errorf("orphan re-parented to %#x, want root %#x", got, uint64(rootID))
	}
	if s := agg.Stats(); s.SpansDroppedShort != 1 {
		t.Errorf("SpansDroppedShort = %d, want 1", s.SpansDroppedShort)
	}
}

func TestSweepDropsAbandonedRequests(t *testing.T) {
	sink := &capture{}
	agg := New(Config{MaxRequestAge: time.Second}, sink)

	const key = uint64(11)<<32 | 11
	start := time.Now()
	agg.Handle(startEvent(key, 0), start)

	if n := agg.Sweep(start.Add(500 * time.Millisecond)); n != 0 {
		t.Fatalf("swept %d requests too early", n)
	}
	if n := agg.Sweep(start.Add(2 * time.Second)); n != 1 {
		t.Fatalf("swept %d requests, want 1", n)
	}
	if s := agg.Stats(); s.InFlight != 0 || s.RequestsExpired != 1 {
		t.Fatalf("unexpected stats %+v", s)
	}
}

func TestSpansFromOtherTraceAreRejected(t *testing.T) {
	sink := &capture{}
	agg := New(Config{}, sink)

	const key = uint64(13)<<32 | 13
	now := time.Now()
	agg.Handle(startEvent(key, 0), now)

	stale := funcEvent(key, 0xa, rootID, 10, 20, "stale", 0)
	stale.TraceIDHi = 0xdeadbeef // belongs to a previous request on a recycled pid
	agg.Handle(stale, now)

	agg.Handle(endEvent(key, 0, 100), now)

	if got := len(sink.got[0].Spans); got != 0 {
		t.Fatalf("got %d spans, want 0", got)
	}
	if s := agg.Stats(); s.SpansOrphaned != 1 {
		t.Fatalf("SpansOrphaned = %d, want 1", s.SpansOrphaned)
	}
}
