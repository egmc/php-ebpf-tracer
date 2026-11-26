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

func TestShortSpansDoNotUseUpCap(t *testing.T) {
	sink := &capture{}
	agg := New(Config{MinSpanDuration: 50 * time.Nanosecond, MaxSpansPerRequest: 3}, sink)

	const key = uint64(15)<<32 | 15
	now := time.Now()
	agg.Handle(startEvent(key, 0), now)
	// Far more short calls than the cap allows, then the slow call that
	// returns last, as a template render at the end of a request would.
	for i := uint64(0); i < 100; i++ {
		agg.Handle(funcEvent(key, 0x100+i, 0xa, 10+i, 11+i, "tiny", 1), now)
	}
	agg.Handle(funcEvent(key, 0xa, rootID, 5, 500, "slow", 0), now)
	agg.Handle(endEvent(key, 0, 1000), now)

	r := sink.got[0]
	if len(r.Spans) != 1 || r.Spans[0].Func != "slow" {
		t.Fatalf("spans = %+v, want only slow", r.Spans)
	}
	if r.Truncated {
		t.Error("trace marked truncated although no kept span hit the cap")
	}
	s := agg.Stats()
	if s.SpansDroppedShort != 100 || s.SpansDroppedCap != 0 || s.SpansBuffered != 1 {
		t.Errorf("stats = %+v, want 100 short, 0 cap, 1 buffered", s)
	}
}

func TestCapStillAppliesToKeptSpans(t *testing.T) {
	sink := &capture{}
	agg := New(Config{MinSpanDuration: 50 * time.Nanosecond, MaxSpansPerRequest: 2}, sink)

	const key = uint64(17)<<32 | 17
	now := time.Now()
	agg.Handle(startEvent(key, 0), now)
	for i := uint64(0); i < 5; i++ {
		agg.Handle(funcEvent(key, 0x10+i, rootID, i*100, i*100+90, "long", 0), now)
	}
	agg.Handle(endEvent(key, 0, 1000), now)

	r := sink.got[0]
	if len(r.Spans) != 2 || !r.Truncated {
		t.Fatalf("got %d spans truncated=%v, want 2 and truncated", len(r.Spans), r.Truncated)
	}
	if s := agg.Stats(); s.SpansDroppedCap != 3 {
		t.Errorf("SpansDroppedCap = %d, want 3", s.SpansDroppedCap)
	}
}

func TestForgottenDroppedParentFallsBackToRoot(t *testing.T) {
	sink := &capture{}
	// MaxSpansPerRequest 1 lets the request remember droppedPerSpan ids.
	agg := New(Config{MinSpanDuration: 50 * time.Nanosecond, MaxSpansPerRequest: 1}, sink)

	const key = uint64(19)<<32 | 19
	now := time.Now()
	agg.Handle(startEvent(key, 0), now)
	for i := uint64(0); i < droppedPerSpan; i++ {
		agg.Handle(funcEvent(key, 0x100+i, 0xa, 1, 2, "filler", 2), now)
	}
	// Kept child of a short span that no longer fits in the dropped map.
	agg.Handle(funcEvent(key, 0xc, 0xb, 30, 130, "child", 2), now)
	agg.Handle(funcEvent(key, 0xb, 0xa, 20, 30, "forgotten", 1), now)
	agg.Handle(endEvent(key, 0, 300), now)

	r := sink.got[0]
	if len(r.Spans) != 1 || r.Spans[0].Func != "child" {
		t.Fatalf("spans = %+v, want only child", r.Spans)
	}
	if got := r.Spans[0].ParentID; got != rootID {
		t.Errorf("child parent = %#x, want root %#x", got, uint64(rootID))
	}
}

func queryEvent(key, span, parent uint64, startNS, endNS uint64, kind uint8, sql string) *event.Event {
	e := funcEvent(key, span, parent, startNS, endNS, "", 0)
	e.Type = event.TypeQuery
	e.QueryKind = kind
	e.Query = sql
	e.QueryLen = uint32(len(sql))
	e.Conn = 0xc0

	return e
}

func TestQuerySpans(t *testing.T) {
	sink := &capture{}
	// A query shorter than -min-span is still kept.
	agg := New(Config{MinSpanDuration: time.Millisecond}, sink)

	const key = uint64(21)<<32 | 21
	now := time.Now()
	agg.Handle(startEvent(key, 0), now)
	agg.Handle(queryEvent(key, 0xb1, 0xa, 20, 30, event.QueryKindQuery, "SELECT 1"), now)
	failed := queryEvent(key, 0xb2, 0xa, 40, 50, event.QueryKindQuery, "SELEC 2")
	failed.Failed = true
	agg.Handle(failed, now)
	cut := queryEvent(key, 0xb3, 0xa, 60, 70, event.QueryKindQuery, "SELECT long")
	cut.QueryLen = 5000
	agg.Handle(cut, now)
	agg.Handle(funcEvent(key, 0xa, rootID, 10, uint64(5*time.Millisecond), "repo", 0), now)
	agg.Handle(endEvent(key, 0, uint64(10*time.Millisecond)), now)

	r := sink.got[0]
	if len(r.Spans) != 4 {
		t.Fatalf("got %d spans, want 4: %+v", len(r.Spans), r.Spans)
	}
	var qs []*Query
	for i := range r.Spans {
		s := &r.Spans[i]
		if s.Query == nil {
			continue
		}
		if s.ParentID != 0xa {
			t.Errorf("query parent = %#x, want 0xa", s.ParentID)
		}
		qs = append(qs, s.Query)
	}
	if len(qs) != 3 {
		t.Fatalf("got %d queries, want 3", len(qs))
	}
	if qs[0].Text != "SELECT 1" || qs[0].Failed || qs[0].Truncated || qs[0].Prepared {
		t.Errorf("query 1 = %+v", qs[0])
	}
	if !qs[1].Failed {
		t.Errorf("query 2 = %+v, want failed", qs[1])
	}
	if !qs[2].Truncated {
		t.Errorf("query 3 = %+v, want truncated", qs[2])
	}
	if s := agg.Stats(); s.Queries != 3 {
		t.Errorf("Queries = %d, want 3", s.Queries)
	}
}

func TestExecuteTakesSQLFromPrepare(t *testing.T) {
	sink := &capture{}
	agg := New(Config{}, sink)

	const key = uint64(23)<<32 | 23
	now := time.Now()
	exec := func(span uint64, conn uint64, id uint32) {
		e := queryEvent(key, span, rootID, span, span+5, event.QueryKindExecute, "")
		e.Conn = conn
		e.StmtID = id
		agg.Handle(e, now)
	}
	prepare := func(conn uint64, sql string) {
		e := queryEvent(key, 0, 0, 1, 1, event.QueryKindPrepare, sql)
		e.Conn = conn
		agg.Handle(e, now)
	}

	agg.Handle(startEvent(key, 0), now)
	prepare(0xc1, "select * from a where id = ?")
	exec(0x10, 0xc1, 1)
	prepare(0xc1, "select * from b")
	exec(0x20, 0xc1, 1) // the earlier statement again, not the pending prepare
	exec(0x30, 0xc1, 2) // claims "select * from b"
	prepare(0xc2, "select * from c")
	exec(0x40, 0xc1, 7) // unknown statement on a connection with nothing pending
	exec(0x50, 0xc2, 1) // same id on another connection
	agg.Handle(endEvent(key, 0, 1000), now)

	want := map[uint64]string{
		0x10: "select * from a where id = ?",
		0x20: "select * from a where id = ?",
		0x30: "select * from b",
		0x40: "",
		0x50: "select * from c",
	}
	r := sink.got[0]
	if len(r.Spans) != len(want) {
		t.Fatalf("got %d spans, want %d (prepares must not become spans)", len(r.Spans), len(want))
	}
	for _, s := range r.Spans {
		if got := s.Query.Text; got != want[s.SpanID] {
			t.Errorf("span %#x: SQL %q, want %q", s.SpanID, got, want[s.SpanID])
		}
		if !s.Query.Prepared {
			t.Errorf("span %#x not marked prepared", s.SpanID)
		}
	}
}
