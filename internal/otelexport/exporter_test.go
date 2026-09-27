package otelexport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/egmc/php-ebpf-tracer/internal/pipeline"
)

// The kernel-generated ids must survive all the way into the exported spans,
// and the parent/child links must match the shadow stack.
func TestExportPreservesKernelIDs(t *testing.T) {
	ctx := context.Background()
	sink := tracetest.NewInMemoryExporter()

	exp, err := newWith(ctx, Config{ServiceName: "php-test"}, sink)
	if err != nil {
		t.Fatalf("newWith: %v", err)
	}
	t.Cleanup(func() { _ = exp.Shutdown(ctx) })

	const (
		rootID  = uint64(0x1000000000000001)
		outerID = uint64(0x2000000000000002)
		innerID = uint64(0x3000000000000003)
	)
	req := &pipeline.Request{
		PID:        4242,
		TraceIDHi:  0x0123456789abcdef,
		TraceIDLo:  0xfedcba9876543210,
		RootSpanID: rootID,
		StartNS:    1_000_000_000,
		EndNS:      1_250_000_000,
		URI:        "/slow",
		Method:     "GET",
		File:       "/app/index.php",
		Spans: []pipeline.Span{
			{SpanID: outerID, ParentID: rootID, Func: "handle_slow",
				StartNS: 1_010_000_000, EndNS: 1_240_000_000, Lineno: 77},
			{SpanID: innerID, ParentID: outerID, Func: "findAll", Class: "Repository",
				StartNS: 1_020_000_000, EndNS: 1_200_000_000, Depth: 1, Collapsed: true},
		},
	}

	exp.Export(req)
	if err := exp.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	spans := sink.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("got %d spans, want 3", len(spans))
	}

	byName := map[string]tracetest.SpanStub{}
	for _, s := range spans {
		byName[s.Name] = s
	}

	root, ok := byName["GET /slow"]
	if !ok {
		t.Fatalf("root span missing; got %v", spanNames(spans))
	}
	if got := root.SpanContext.TraceID().String(); got != "0123456789abcdeffedcba9876543210" {
		t.Errorf("trace id = %s", got)
	}
	if got := root.SpanContext.SpanID().String(); got != "1000000000000001" {
		t.Errorf("root span id = %s", got)
	}
	if got := root.EndTime.Sub(root.StartTime); got != 250*time.Millisecond {
		t.Errorf("root duration = %s, want 250ms", got)
	}

	outer := byName["handle_slow"]
	if got := outer.Parent.SpanID().String(); got != "1000000000000001" {
		t.Errorf("handle_slow parent = %s, want root", got)
	}

	inner := byName["Repository::findAll"]
	if got := inner.Parent.SpanID().String(); got != "2000000000000002" {
		t.Errorf("findAll parent = %s, want handle_slow", got)
	}
	if got := inner.SpanContext.TraceID(); got != root.SpanContext.TraceID() {
		t.Errorf("findAll trace id = %s, want %s", got, root.SpanContext.TraceID())
	}
	if !hasBoolAttr(inner, "php.collapsed") {
		t.Error("findAll is missing php.collapsed")
	}
	if hasBoolAttr(outer, "php.collapsed") {
		t.Error("handle_slow has php.collapsed, want it only on collapsed calls")
	}
	// Every span in the request shares one trace.
	for _, s := range spans {
		if s.SpanContext.TraceID() != root.SpanContext.TraceID() {
			t.Errorf("span %q has trace id %s", s.Name, s.SpanContext.TraceID())
		}
	}
}

// Two requests exported back to back must not bleed ids into each other.
func TestExportIsolatesConsecutiveTraces(t *testing.T) {
	ctx := context.Background()
	sink := tracetest.NewInMemoryExporter()

	exp, err := newWith(ctx, Config{ServiceName: "php-test"}, sink)
	if err != nil {
		t.Fatalf("newWith: %v", err)
	}
	t.Cleanup(func() { _ = exp.Shutdown(ctx) })

	for i := uint64(1); i <= 2; i++ {
		exp.Export(&pipeline.Request{
			TraceIDHi:  i,
			TraceIDLo:  i,
			RootSpanID: 0x100 + i,
			StartNS:    1_000_000_000,
			EndNS:      1_100_000_000,
			URI:        "/r",
			Method:     "GET",
			Spans: []pipeline.Span{
				{SpanID: 0x200 + i, ParentID: 0x100 + i, Func: "f",
					StartNS: 1_010_000_000, EndNS: 1_090_000_000},
			},
		})
	}
	if err := exp.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	traces := map[string]int{}
	for _, s := range sink.GetSpans() {
		traces[s.SpanContext.TraceID().String()]++
	}
	if len(traces) != 2 {
		t.Fatalf("got %d distinct traces, want 2: %v", len(traces), traces)
	}
	for id, n := range traces {
		if n != 2 {
			t.Errorf("trace %s has %d spans, want 2", id, n)
		}
	}
}

// A URL endpoint must keep its path (Grafana Cloud serves OTLP under /otlp)
// and carry the auth header.
func TestHTTPEndpointURLKeepsPathAndHeaders(t *testing.T) {
	ctx := context.Background()

	type hit struct{ path, auth string }
	hits := make(chan hit, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hits <- hit{r.URL.Path, r.Header.Get("Authorization")}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exp, err := New(ctx, Config{
		Protocol: ProtocolHTTP,
		Endpoint: srv.URL + "/otlp/v1/traces",
		Headers:  map[string]string{"Authorization": "Basic dXNlcjp0b2tlbg=="},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = exp.Shutdown(ctx) })

	exp.Export(&pipeline.Request{TraceIDHi: 1, TraceIDLo: 1, RootSpanID: 1,
		StartNS: 1_000_000_000, EndNS: 1_100_000_000, URI: "/r", Method: "GET"})
	if err := exp.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}

	got := <-hits
	if got.path != "/otlp/v1/traces" {
		t.Errorf("path = %q, want /otlp/v1/traces", got.path)
	}
	if got.auth != "Basic dXNlcjp0b2tlbg==" {
		t.Errorf("Authorization = %q", got.auth)
	}
}

func spanNames(spans tracetest.SpanStubs) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.Name)
	}

	return out
}

func hasBoolAttr(s tracetest.SpanStub, key string) bool {
	for _, kv := range s.Attributes {
		if string(kv.Key) == key {
			return kv.Value.AsBool()
		}
	}

	return false
}
