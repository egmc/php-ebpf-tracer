// Package otelexport turns finished PHP requests into OpenTelemetry traces and
// ships them over OTLP.
package otelexport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/egmc/php-ebpf-tracer/internal/monoclock"
	"github.com/egmc/php-ebpf-tracer/internal/pipeline"
)

// Protocol selects the OTLP transport.
type Protocol string

// Supported transports. ProtocolStdout is a debugging aid that prints spans
// instead of sending them anywhere.
const (
	ProtocolGRPC   Protocol = "grpc"
	ProtocolHTTP   Protocol = "http"
	ProtocolStdout Protocol = "stdout"
)

const instrumentationName = "github.com/egmc/php-ebpf-tracer"

// Config configures the OTLP pipeline.
type Config struct {
	// Protocol is grpc, http or stdout.
	Protocol Protocol
	// Endpoint is host:port or a full URL (scheme://host[:port][/path]) for
	// grpc/http. With a URL the scheme picks TLS and, for http, the path
	// replaces the default /v1/traces. Empty falls back to the standard
	// OTEL_EXPORTER_OTLP_* environment variables.
	Endpoint string
	// Insecure disables TLS for grpc/http. Ignored when Endpoint is a URL.
	Insecure bool
	// Headers are extra OTLP headers, e.g. authentication.
	Headers map[string]string

	ServiceName      string
	ServiceNamespace string
	ServiceVersion   string
	// ResourceAttributes are extra resource attributes as key=value strings.
	ResourceAttributes []string

	// QueueSize bounds the spans waiting in the batch span processor. A
	// request's spans are all handed over at once, so it should comfortably
	// exceed the largest request; spans that do not fit are silently dropped
	// by the SDK. 0 keeps the SDK default (2048).
	QueueSize int

	Clock  monoclock.Clock
	Logger *slog.Logger
}

func (c *Config) setDefaults() {
	if c.Protocol == "" {
		c.Protocol = ProtocolGRPC
	}
	if c.ServiceName == "" {
		c.ServiceName = "php"
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// Exporter builds OTel spans with kernel-generated ids and hands them to a
// BatchSpanProcessor.
type Exporter struct {
	cfg    Config
	log    *slog.Logger
	clock  monoclock.Clock
	tp     *sdktrace.TracerProvider
	tracer trace.Tracer

	// mu serialises span construction because ids are injected through the
	// provider-wide IDGenerator.
	mu  sync.Mutex
	gen *idInjector
}

// New builds the OTLP exporter and tracer provider.
func New(ctx context.Context, cfg Config) (*Exporter, error) {
	cfg.setDefaults()

	spanExporter, err := newSpanExporter(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return newWith(ctx, cfg, spanExporter)
}

// newWith is the seam the tests use to substitute an in-memory span exporter.
func newWith(ctx context.Context, cfg Config, spanExporter sdktrace.SpanExporter) (*Exporter, error) {
	cfg.setDefaults()

	res, err := newResource(ctx, cfg)
	if err != nil {
		return nil, err
	}

	var batchOpts []sdktrace.BatchSpanProcessorOption
	if cfg.QueueSize > 0 {
		batchOpts = append(batchOpts, sdktrace.WithMaxQueueSize(cfg.QueueSize))
	}

	gen := &idInjector{}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(spanExporter, batchOpts...),
		sdktrace.WithResource(res),
		sdktrace.WithIDGenerator(gen),
		// Sampling already happened in the aggregator, based on the
		// request__startup/request__shutdown delta.
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	return &Exporter{
		cfg:    cfg,
		log:    cfg.Logger,
		clock:  cfg.Clock,
		tp:     tp,
		tracer: tp.Tracer(instrumentationName),
		gen:    gen,
	}, nil
}

func newSpanExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	switch cfg.Protocol {
	case ProtocolStdout:
		return stdouttrace.New(stdouttrace.WithPrettyPrint())

	case ProtocolGRPC:
		opts := []otlptracegrpc.Option{}
		switch {
		case isURL(cfg.Endpoint):
			opts = append(opts, otlptracegrpc.WithEndpointURL(cfg.Endpoint))
		case cfg.Endpoint != "":
			opts = append(opts, otlptracegrpc.WithEndpoint(cfg.Endpoint))
			if cfg.Insecure {
				opts = append(opts, otlptracegrpc.WithInsecure())
			}
		case cfg.Insecure:
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
		}

		return otlptrace.New(ctx, otlptracegrpc.NewClient(opts...))

	case ProtocolHTTP:
		opts := []otlptracehttp.Option{}
		switch {
		case isURL(cfg.Endpoint):
			opts = append(opts, otlptracehttp.WithEndpointURL(cfg.Endpoint))
		case cfg.Endpoint != "":
			opts = append(opts, otlptracehttp.WithEndpoint(cfg.Endpoint))
			if cfg.Insecure {
				opts = append(opts, otlptracehttp.WithInsecure())
			}
		case cfg.Insecure:
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
		}

		return otlptrace.New(ctx, otlptracehttp.NewClient(opts...))

	default:
		return nil, fmt.Errorf("unknown OTLP protocol %q", cfg.Protocol)
	}
}

// isURL reports whether endpoint carries a scheme rather than being host:port.
func isURL(endpoint string) bool {
	return strings.Contains(endpoint, "://")
}

func newResource(ctx context.Context, cfg Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
		semconv.TelemetrySDKLanguageKey.String("php"),
		attribute.String("telemetry.instrumentation.source", "usdt-ebpf"),
	}
	if cfg.ServiceNamespace != "" {
		attrs = append(attrs, semconv.ServiceNamespace(cfg.ServiceNamespace))
	}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}
	for _, kv := range cfg.ResourceAttributes {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("resource attribute %q is not key=value", kv)
		}
		attrs = append(attrs, attribute.String(k, v))
	}

	return resource.New(ctx,
		resource.WithHost(),
		resource.WithProcessRuntimeName(),
		resource.WithAttributes(attrs...),
	)
}

// Export implements pipeline.Sink. Span and trace ids come from the kernel so
// that a future PHP-side extension can correlate against the same ids.
func (e *Exporter) Export(r *pipeline.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()

	traceID := trace.TraceID(r.TraceID())
	if !traceID.IsValid() {
		traceID = randomTraceID()
	}

	e.gen.traceID = traceID
	e.gen.spanID = spanIDFrom(r.RootSpanID)

	rootCtx, root := e.tracer.Start(context.Background(), r.RootName(),
		trace.WithNewRoot(),
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithTimestamp(e.clock.Time(r.StartNS)),
		trace.WithAttributes(e.rootAttributes(r)...),
	)
	// End the root first so it is the first span queued. If the batch
	// processor's queue overflows, the SDK drops the newest spans, and losing
	// a few leaf calls is far better than losing the request span that every
	// other span hangs off. The children only need rootCtx, which stays valid
	// after End.
	root.End(trace.WithTimestamp(e.clock.Time(r.EndNS)))

	// Parents are always created before their children: finalize() ordered the
	// slice by start time, and a callee cannot start before its caller.
	ctxByID := make(map[uint64]context.Context, len(r.Spans)+1)
	ctxByID[r.RootSpanID] = rootCtx

	for i := range r.Spans {
		s := &r.Spans[i]

		parentCtx, ok := ctxByID[s.ParentID]
		if !ok {
			parentCtx = rootCtx
		}

		e.gen.spanID = spanIDFrom(s.SpanID)
		childCtx, span := e.tracer.Start(parentCtx, s.Name(),
			trace.WithSpanKind(trace.SpanKindInternal),
			trace.WithTimestamp(e.clock.Time(s.StartNS)),
			trace.WithAttributes(spanAttributes(s)...),
		)
		ctxByID[s.SpanID] = childCtx
		span.End(trace.WithTimestamp(e.clock.Time(s.EndNS)))
	}

	e.log.Debug("exported trace",
		"trace_id", traceID.String(),
		"uri", r.URI,
		"pid", r.PID,
		"duration", time.Duration(r.DurationNS()),
		"spans", len(r.Spans))
}

func (e *Exporter) rootAttributes(r *pipeline.Request) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Int("process.pid", int(r.PID)),
		attribute.String("code.filepath", r.File),
		attribute.Int("php.spans.count", len(r.Spans)),
	}
	if r.Method != "" {
		attrs = append(attrs, semconv.HTTPRequestMethodKey.String(r.Method))
	}
	if r.URI != "" {
		attrs = append(attrs, semconv.URLPath(r.URI))
	}
	if r.Truncated {
		attrs = append(attrs,
			attribute.Bool("php.trace.truncated", true),
			attribute.Int64("php.frames.dropped", int64(r.DroppedFrames)))
	}

	return attrs
}

func spanAttributes(s *pipeline.Span) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("code.function", s.Func),
		attribute.String("code.filepath", s.File),
		attribute.Int("code.lineno", int(s.Lineno)),
		attribute.Int("php.call.depth", int(s.Depth)),
	}
	if s.Class != "" {
		attrs = append(attrs, attribute.String("code.namespace", s.Class))
	}

	return attrs
}

// Shutdown flushes pending spans and tears the provider down.
func (e *Exporter) Shutdown(ctx context.Context) error {
	return e.tp.Shutdown(ctx)
}

// ForceFlush pushes buffered spans out immediately.
func (e *Exporter) ForceFlush(ctx context.Context) error {
	return e.tp.ForceFlush(ctx)
}

// idInjector feeds pre-computed ids to the SDK. The SDK calls NewIDs/NewSpanID
// synchronously from within tracer.Start, so holding Exporter.mu across the
// field assignment and the Start call is enough to make this safe.
type idInjector struct {
	traceID trace.TraceID
	spanID  trace.SpanID
}

func (g *idInjector) NewIDs(context.Context) (trace.TraceID, trace.SpanID) {
	return g.traceID, g.spanID
}

func (g *idInjector) NewSpanID(context.Context, trace.TraceID) trace.SpanID {
	return g.spanID
}

func spanIDFrom(v uint64) trace.SpanID {
	var id trace.SpanID
	binary.BigEndian.PutUint64(id[:], v)
	if !id.IsValid() {
		_, _ = rand.Read(id[:])
	}

	return id
}

func randomTraceID() trace.TraceID {
	var id trace.TraceID
	_, _ = rand.Read(id[:])

	return id
}
