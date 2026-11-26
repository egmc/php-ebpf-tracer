// Package pipeline buffers the spans of an in-flight PHP request and decides,
// once the request finishes, whether the trace is worth exporting.
package pipeline

import "sort"

// Span is one completed PHP userland function call, or a database query when
// Query is set.
type Span struct {
	SpanID   uint64
	ParentID uint64
	Func     string
	Class    string
	File     string
	Lineno   int32
	Depth    uint32
	StartNS  uint64
	EndNS    uint64

	// Query is set for a MySQL query; Func, Class, File and Lineno are then
	// empty.
	Query *Query
}

// Query describes a MySQL query issued through mysqlnd.
type Query struct {
	// Text is the SQL, possibly cut short; see Truncated. Empty for the
	// execute of a statement whose prepare was not seen.
	Text string
	// Truncated is set when Text is only the start of the SQL.
	Truncated bool
	// Prepared is set for the execute of a server-side prepared statement.
	Prepared bool
	StmtID   uint32
	// Failed is set when mysqlnd reported an error.
	Failed bool
}

// Name renders the span name, "Class::method" for methods and the bare
// function name otherwise.
func (s *Span) Name() string {
	if s.Class != "" {
		return s.Class + "::" + s.Func
	}

	return s.Func
}

// DurationNS is the wall time spent inside the call, children included.
func (s *Span) DurationNS() uint64 {
	if s.EndNS < s.StartNS {
		return 0
	}

	return s.EndNS - s.StartNS
}

// Request accumulates everything observed between request__startup and
// request__shutdown for one PHP process.
type Request struct {
	Key        uint64 // bpf_get_current_pid_tgid()
	PID        uint32
	TID        uint32
	TraceIDHi  uint64
	TraceIDLo  uint64
	RootSpanID uint64

	StartNS uint64
	EndNS   uint64

	File   string
	URI    string
	Method string

	// Truncated is set when the kernel side dropped frames for this request
	// (stack deeper than MAX_STACK_DEPTH, ring buffer full, or a bailout that
	// skipped function__return markers).
	Truncated     bool
	DroppedFrames uint32

	Spans []Span

	// prepared holds, per connection, the SQL of the last statement prepared
	// and not yet executed, and stmts the SQL of each statement once its first
	// execute claimed it. Statement ids are per connection, and PHP closes
	// statements at the end of a request, so both live as long as the request.
	prepared map[uint64]preparedSQL
	stmts    map[stmtKey]preparedSQL

	// dropped maps the id of each span discarded by the duration filter to
	// its parent id, so that finalize can walk past it. Spans return before
	// their callers, so when a child arrives it is not yet known whether
	// its parent will survive.
	dropped map[uint64]uint64
}

type stmtKey struct {
	conn uint64
	id   uint32
}

type preparedSQL struct {
	text      string
	truncated bool
}

// notePrepare records the SQL of a statement being prepared on conn.
func (r *Request) notePrepare(conn uint64, sql preparedSQL) {
	if r.prepared == nil {
		r.prepared = make(map[uint64]preparedSQL)
	}
	r.prepared[conn] = sql
}

// statementSQL returns the SQL of statement id on conn. The server assigns
// the id in its reply to the prepare, which the probes do not see, so the
// first execute of an id not seen before claims the SQL of the last prepare on
// that connection. MySQL never reuses a statement id within a connection, so a
// known id keeps its SQL.
func (r *Request) statementSQL(conn uint64, id uint32) (preparedSQL, bool) {
	key := stmtKey{conn, id}
	if sql, ok := r.stmts[key]; ok {
		return sql, true
	}
	sql, ok := r.prepared[conn]
	if !ok {
		return preparedSQL{}, false
	}
	delete(r.prepared, conn)
	if r.stmts == nil {
		r.stmts = make(map[stmtKey]preparedSQL)
	}
	r.stmts[key] = sql

	return sql, true
}

// rememberDropped records a span dropped by the duration filter. Once limit
// ids are held, further ids are forgotten.
func (r *Request) rememberDropped(id, parent uint64, limit int) {
	if r.dropped == nil {
		r.dropped = make(map[uint64]uint64)
	}
	if len(r.dropped) >= limit {
		return
	}
	r.dropped[id] = parent
}

// DurationNS is the request__startup to request__shutdown delta. This is the
// value the export threshold is applied to.
func (r *Request) DurationNS() uint64 {
	if r.EndNS < r.StartNS {
		return 0
	}

	return r.EndNS - r.StartNS
}

// TraceID renders the 128 bit trace id generated in the kernel.
func (r *Request) TraceID() [16]byte {
	var id [16]byte
	putUint64BE(id[0:8], r.TraceIDHi)
	putUint64BE(id[8:16], r.TraceIDLo)

	return id
}

// RootName is the OTLP name of the request span.
func (r *Request) RootName() string {
	switch {
	case r.Method != "" && r.URI != "":
		return r.Method + " " + r.URI
	case r.URI != "":
		return r.URI
	case r.File != "":
		return r.File
	default:
		return "php request"
	}
}

func putUint64BE(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

// finalize prepares the buffered spans for export:
//
//  1. spans shorter than minSpanNS are dropped and their children are
//     re-attached to the nearest surviving ancestor, so the tree stays
//     connected instead of collapsing onto the root. The Aggregator already
//     drops short spans on arrival and records them in r.dropped, which
//     this walk follows; the filter here only catches what is left;
//  2. spans whose parent never arrived (kernel-side drop, or a bailout that
//     unwound without firing function__return) are re-parented onto the root;
//  3. the result is ordered so that a parent always precedes its children,
//     which is what the exporter needs to build nested contexts.
//
// It returns the number of spans dropped by the duration filter.
func (r *Request) finalize(minSpanNS uint64) int {
	byID := make(map[uint64]*Span, len(r.Spans))
	for i := range r.Spans {
		byID[r.Spans[i].SpanID] = &r.Spans[i]
	}

	kept := make(map[uint64]bool, len(r.Spans))
	for i := range r.Spans {
		// Queries were asked for explicitly and are rarely the noise the
		// duration filter is for, so they are always kept.
		kept[r.Spans[i].SpanID] = r.Spans[i].Query != nil || r.Spans[i].DurationNS() >= minSpanNS
	}

	// Resolve each span id to the closest ancestor that survives, memoised so
	// a deep stack does not turn this into a quadratic walk.
	resolved := make(map[uint64]uint64, len(r.Spans))
	var effectiveParent func(id uint64) uint64
	effectiveParent = func(id uint64) uint64 {
		if id == r.RootSpanID || id == 0 {
			return r.RootSpanID
		}
		if v, ok := resolved[id]; ok {
			return v
		}
		var parent uint64
		if s, ok := byID[id]; ok {
			if kept[id] {
				resolved[id] = id
				return id
			}
			parent = s.ParentID
		} else if p, ok := r.dropped[id]; ok {
			// Dropped on arrival by the duration filter.
			parent = p
		} else {
			// Parent was never reported: attach to the root.
			resolved[id] = r.RootSpanID
			return r.RootSpanID
		}
		// Guard against a cycle from a recycled span id.
		resolved[id] = r.RootSpanID
		p := effectiveParent(parent)
		resolved[id] = p

		return p
	}

	out := r.Spans[:0]
	dropped := 0
	for i := range r.Spans {
		s := r.Spans[i]
		if !kept[s.SpanID] {
			dropped++
			continue
		}
		s.ParentID = effectiveParent(s.ParentID)
		out = append(out, s)
	}
	r.Spans = out
	r.dropped = nil
	r.prepared = nil
	r.stmts = nil

	// A callee always starts at or after its caller, so ordering by start time
	// (depth breaking ties for zero-cost frames) yields a valid topological
	// order.
	sort.SliceStable(r.Spans, func(i, j int) bool {
		if r.Spans[i].StartNS != r.Spans[j].StartNS {
			return r.Spans[i].StartNS < r.Spans[j].StartNS
		}

		return r.Spans[i].Depth < r.Spans[j].Depth
	})

	return dropped
}
