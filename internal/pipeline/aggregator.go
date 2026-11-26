package pipeline

import (
	"log/slog"
	"time"

	"github.com/egmc/php-ebpf-tracer/internal/event"
)

// Config tunes buffering and the tail-sampling decision.
type Config struct {
	// MinDuration is the request__shutdown minus request__startup threshold.
	// Requests faster than this are discarded without ever reaching the
	// exporter. Zero exports everything.
	MinDuration time.Duration

	// MinSpanDuration drops individual function spans shorter than this,
	// re-parenting their children. The filter runs as each span arrives,
	// before MaxSpansPerRequest is checked, so dropped spans do not count
	// towards the cap. Zero keeps every span.
	MinSpanDuration time.Duration

	// MaxSpansPerRequest bounds the memory a single pathological request can
	// hold. Spans beyond the limit are counted and dropped.
	MaxSpansPerRequest int

	// MaxRequestAge discards buffered state for requests whose
	// request__shutdown never arrived.
	MaxRequestAge time.Duration

	Logger *slog.Logger
}

func (c *Config) setDefaults() {
	if c.MaxSpansPerRequest <= 0 {
		c.MaxSpansPerRequest = 5000
	}
	if c.MaxRequestAge <= 0 {
		c.MaxRequestAge = time.Minute
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// Stats is a snapshot of aggregator counters.
type Stats struct {
	RequestsStarted   uint64
	RequestsCompleted uint64
	RequestsExported  uint64
	RequestsBelowMin  uint64
	RequestsExpired   uint64
	RequestsUnknown   uint64 // shutdown without a matching startup
	SpansBuffered     uint64
	SpansDroppedShort uint64
	SpansDroppedCap   uint64
	SpansOrphaned     uint64
	Queries           uint64 // query spans buffered, included in SpansBuffered
	InFlight          int
}

// Sink receives requests that passed the export threshold.
type Sink interface {
	Export(*Request)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(*Request)

// Export implements Sink.
func (f SinkFunc) Export(r *Request) { f(r) }

// Aggregator turns the flat event stream into complete request traces.
//
// It is not safe for concurrent use: drive it from a single goroutine, which
// is also what keeps the hot path allocation free.
type Aggregator struct {
	cfg   Config
	log   *slog.Logger
	sink  Sink
	reqs  map[uint64]*Request
	seen  map[uint64]time.Time
	stats Stats
}

// New returns an Aggregator feeding completed traces to sink.
func New(cfg Config, sink Sink) *Aggregator {
	cfg.setDefaults()

	return &Aggregator{
		cfg:  cfg,
		log:  cfg.Logger,
		sink: sink,
		reqs: make(map[uint64]*Request),
		seen: make(map[uint64]time.Time),
	}
}

// Handle consumes one decoded event. The event is not retained.
func (a *Aggregator) Handle(ev *event.Event, now time.Time) {
	switch ev.Type {
	case event.TypeReqStart:
		a.onRequestStart(ev, now)
	case event.TypeFunc:
		a.onFunction(ev, now)
	case event.TypeQuery:
		a.onQuery(ev, now)
	case event.TypeReqEnd:
		a.onRequestEnd(ev)
	}
}

func (a *Aggregator) onRequestStart(ev *event.Event, now time.Time) {
	key := ev.Key()
	a.stats.RequestsStarted++
	a.reqs[key] = &Request{
		Key:        key,
		PID:        ev.PID,
		TID:        ev.TID,
		TraceIDHi:  ev.TraceIDHi,
		TraceIDLo:  ev.TraceIDLo,
		RootSpanID: ev.SpanID,
		StartNS:    ev.TsStart,
		File:       ev.File,
		URI:        ev.URI,
		Method:     ev.Method,
	}
	a.seen[key] = now
}

// request returns the in-flight request a span event belongs to, or nil.
func (a *Aggregator) request(ev *event.Event, now time.Time) *Request {
	r, ok := a.reqs[ev.Key()]
	if !ok {
		// The request started before the tracer attached, or its state was
		// already swept. Nothing to attach the span to.
		a.stats.SpansOrphaned++
		return nil
	}
	// A recycled pid could in principle land a span on the wrong request;
	// the kernel-generated trace id makes that detectable.
	if r.TraceIDHi != ev.TraceIDHi || r.TraceIDLo != ev.TraceIDLo {
		a.stats.SpansOrphaned++
		return nil
	}
	a.seen[r.Key] = now

	return r
}

// admit reports whether r has room for another span, marking the request
// truncated when it does not.
func (a *Aggregator) admit(r *Request) bool {
	if len(r.Spans) >= a.cfg.MaxSpansPerRequest {
		a.stats.SpansDroppedCap++
		r.Truncated = true
		return false
	}

	return true
}

func (a *Aggregator) onFunction(ev *event.Event, now time.Time) {
	r := a.request(ev, now)
	if r == nil {
		return
	}

	// Apply the duration filter before the span cap, so that a flood of
	// short calls cannot use up the budget and push the slow calls that
	// come later in the request out of the trace. Only the span's parent
	// is kept, so finalize can still re-attach any surviving children.
	if minNS := uint64(a.cfg.MinSpanDuration.Nanoseconds()); minNS > 0 &&
		(ev.TsEnd < ev.TsStart || ev.TsEnd-ev.TsStart < minNS) {
		a.stats.SpansDroppedShort++
		r.rememberDropped(ev.SpanID, ev.ParentSpanID, a.maxDropped())
		return
	}

	if !a.admit(r) {
		return
	}

	r.Spans = append(r.Spans, Span{
		SpanID:   ev.SpanID,
		ParentID: ev.ParentSpanID,
		Func:     ev.Func,
		Class:    ev.Class,
		File:     ev.File,
		Lineno:   ev.Lineno,
		Depth:    ev.Depth,
		StartNS:  ev.TsStart,
		EndNS:    ev.TsEnd,
	})
	a.stats.SpansBuffered++
}

// onQuery turns a mysqlnd query into a span. Queries are not subject to
// MinSpanDuration, but do count towards MaxSpansPerRequest.
func (a *Aggregator) onQuery(ev *event.Event, now time.Time) {
	r := a.request(ev, now)
	if r == nil {
		return
	}

	sql := preparedSQL{
		text:      ev.Query,
		truncated: int(ev.QueryLen) > len(ev.Query),
	}
	q := &Query{Failed: ev.Failed}

	switch ev.QueryKind {
	case event.QueryKindPrepare:
		r.notePrepare(ev.Conn, sql)
		return
	case event.QueryKindExecute:
		sql, _ = r.statementSQL(ev.Conn, ev.StmtID)
		q.Prepared = true
		q.StmtID = ev.StmtID
	case event.QueryKindQuery:
	default:
		return
	}
	q.Text = sql.text
	q.Truncated = sql.truncated

	if !a.admit(r) {
		return
	}
	r.Spans = append(r.Spans, Span{
		SpanID:   ev.SpanID,
		ParentID: ev.ParentSpanID,
		Depth:    ev.Depth,
		StartNS:  ev.TsStart,
		EndNS:    ev.TsEnd,
		Query:    q,
	})
	a.stats.SpansBuffered++
	a.stats.Queries++
}

// maxDropped bounds how many dropped span ids one request remembers for
// re-parenting. Past the limit, short spans are still dropped, and a child
// whose parent was forgotten attaches to the root instead.
func (a *Aggregator) maxDropped() int {
	return droppedPerSpan * a.cfg.MaxSpansPerRequest
}

const droppedPerSpan = 16

func (a *Aggregator) onRequestEnd(ev *event.Event) {
	key := ev.Key()
	r, ok := a.reqs[key]
	if !ok {
		// Startup was missed; export what the shutdown marker alone tells us.
		a.stats.RequestsUnknown++
		r = &Request{
			Key:        key,
			PID:        ev.PID,
			TID:        ev.TID,
			TraceIDHi:  ev.TraceIDHi,
			TraceIDLo:  ev.TraceIDLo,
			RootSpanID: ev.SpanID,
			StartNS:    ev.TsStart,
		}
	}
	delete(a.reqs, key)
	delete(a.seen, key)

	r.EndNS = ev.TsEnd
	r.File = ev.File
	r.URI = ev.URI
	r.Method = ev.Method
	r.DroppedFrames = ev.DroppedFrames
	r.Truncated = r.Truncated || ev.Truncated()

	a.stats.RequestsCompleted++

	// The tail-sampling decision: only requests slower than the threshold are
	// worth the bytes on the wire.
	if uint64(a.cfg.MinDuration.Nanoseconds()) > r.DurationNS() {
		a.stats.RequestsBelowMin++
		return
	}

	dropped := r.finalize(uint64(a.cfg.MinSpanDuration.Nanoseconds()))
	a.stats.SpansDroppedShort += uint64(dropped)
	a.stats.RequestsExported++

	a.sink.Export(r)
}

// Sweep discards buffered state for requests whose shutdown never arrived.
// Returns the number of requests dropped.
func (a *Aggregator) Sweep(now time.Time) int {
	n := 0
	for key, last := range a.seen {
		if now.Sub(last) <= a.cfg.MaxRequestAge {
			continue
		}
		if r, ok := a.reqs[key]; ok {
			a.log.Debug("dropping stale request",
				"pid", r.PID, "uri", r.URI, "spans", len(r.Spans))
		}
		delete(a.reqs, key)
		delete(a.seen, key)
		a.stats.RequestsExpired++
		n++
	}

	return n
}

// Stats returns a snapshot of the counters.
func (a *Aggregator) Stats() Stats {
	s := a.stats
	s.InFlight = len(a.reqs)

	return s
}
