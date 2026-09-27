// Package pipeline buffers the spans of an in-flight PHP request and decides,
// once the request finishes, whether the trace is worth exporting.
package pipeline

import "sort"

// Span is one completed PHP userland function call.
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
	// Collapsed is set when the calls made by this function were suppressed
	// by a collapse rule, so its duration has no child spans to explain it.
	Collapsed bool
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
//     connected instead of collapsing onto the root;
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
		kept[r.Spans[i].SpanID] = r.Spans[i].DurationNS() >= minSpanNS
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
		s, ok := byID[id]
		if !ok {
			// Parent was never reported: attach to the root.
			resolved[id] = r.RootSpanID
			return r.RootSpanID
		}
		// Guard against a cycle from a recycled span id.
		resolved[id] = r.RootSpanID
		if kept[id] {
			resolved[id] = id
			return id
		}
		p := effectiveParent(s.ParentID)
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
