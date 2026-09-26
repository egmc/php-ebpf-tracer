// Command php-ebpf-tracer auto-instruments PHP through its USDT (DTrace)
// markers using eBPF, and exports the result as OpenTelemetry traces over
// OTLP.
//
// Requires a PHP built with --enable-dtrace, a Linux kernel with BPF ring
// buffer support (>= 5.8) and CAP_BPF/CAP_PERFMON (in practice: root or
// --privileged).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/egmc/php-ebpf-tracer/internal/bpftracer"
	"github.com/egmc/php-ebpf-tracer/internal/event"
	"github.com/egmc/php-ebpf-tracer/internal/monoclock"
	"github.com/egmc/php-ebpf-tracer/internal/otelexport"
	"github.com/egmc/php-ebpf-tracer/internal/pipeline"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)

	return nil
}

type options struct {
	bpfObject string
	binaries  stringList
	provider  string
	pid       int

	attachMode   string
	scanInterval time.Duration

	traceFunctions bool
	maxDepth       uint
	bpfMinFunc     time.Duration

	minDuration   time.Duration
	minSpan       time.Duration
	maxSpans      int
	maxRequestAge time.Duration
	sweepInterval time.Duration
	statsInterval time.Duration
	shutdownGrace time.Duration

	otlpProtocol string
	otlpEndpoint string
	otlpInsecure bool
	otlpHeaders  stringList

	serviceName      string
	serviceNamespace string
	serviceVersion   string
	resourceAttrs    stringList

	logLevel string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "php-ebpf-tracer: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() *options {
	o := &options{}

	flag.StringVar(&o.bpfObject, "bpf-object", envOr("PHP_TRACER_BPF_OBJECT", "build/php_tracer.bpf.o"),
		"path to the compiled php_tracer.bpf.o")
	flag.Var(&o.binaries, "binary",
		"PHP executable carrying the USDT notes; repeatable (default /usr/local/bin/php)")
	flag.StringVar(&o.provider, "provider", "php", "USDT provider name")
	flag.IntVar(&o.pid, "pid", -1, "restrict tracing to this pid (-1 = all processes)")
	flag.StringVar(&o.attachMode, "attach-mode", "auto",
		"how to bind probes: auto, global (single pid -1 attach) or scan (discover processes via /proc)")
	flag.DurationVar(&o.scanInterval, "scan-interval", 3*time.Second,
		"how often to look for new PHP processes in scan mode")

	flag.BoolVar(&o.traceFunctions, "trace-functions", true,
		"attach function__entry/function__return; disable for request-level spans only")
	flag.UintVar(&o.maxDepth, "max-depth", 32,
		"deepest PHP call depth that still produces a span")
	flag.DurationVar(&o.bpfMinFunc, "bpf-min-func", 0,
		"drop function spans shorter than this in the kernel (cheap, but children of a dropped span are re-parented onto the root)")

	flag.DurationVar(&o.minDuration, "min-duration", 100*time.Millisecond,
		"export a trace only when request__shutdown minus request__startup is at least this long (0 = export everything)")
	flag.DurationVar(&o.minSpan, "min-span", 0,
		"drop function spans shorter than this before exporting, re-parenting their children")
	flag.IntVar(&o.maxSpans, "max-spans", 5000, "maximum spans buffered per request")
	flag.DurationVar(&o.maxRequestAge, "max-request-age", time.Minute,
		"discard buffered requests whose request__shutdown never arrived")
	flag.DurationVar(&o.sweepInterval, "sweep-interval", 15*time.Second, "stale-state sweep interval")
	flag.DurationVar(&o.statsInterval, "stats-interval", 30*time.Second, "counter logging interval (0 = off)")
	flag.DurationVar(&o.shutdownGrace, "shutdown-grace", 10*time.Second, "time allowed to flush spans on exit")

	flag.StringVar(&o.otlpProtocol, "otlp-protocol", envOr("PHP_TRACER_OTLP_PROTOCOL", "grpc"),
		"OTLP transport: grpc, http or stdout")
	flag.StringVar(&o.otlpEndpoint, "otlp-endpoint", os.Getenv("PHP_TRACER_OTLP_ENDPOINT"),
		"OTLP endpoint as host:port (empty = use the OTEL_EXPORTER_OTLP_* environment variables)")
	flag.BoolVar(&o.otlpInsecure, "otlp-insecure", true, "disable TLS towards the OTLP endpoint")
	flag.Var(&o.otlpHeaders, "otlp-header", "extra OTLP header as key=value; repeatable")

	flag.StringVar(&o.serviceName, "service-name", envOr("OTEL_SERVICE_NAME", "php"), "service.name")
	flag.StringVar(&o.serviceNamespace, "service-namespace", "", "service.namespace")
	flag.StringVar(&o.serviceVersion, "service-version", "", "service.version")
	flag.Var(&o.resourceAttrs, "resource-attribute", "extra resource attribute as key=value; repeatable")

	flag.StringVar(&o.logLevel, "log-level", envOr("PHP_TRACER_LOG_LEVEL", "info"), "debug, info, warn or error")

	flag.Parse()

	if len(o.binaries) == 0 {
		o.binaries = stringList{envOr("PHP_TRACER_BINARY", "/usr/local/bin/php")}
	}

	return o
}

func run() error {
	o := parseFlags()

	log, err := newLogger(o.logLevel)
	if err != nil {
		return err
	}

	clock, err := monoclock.New()
	if err != nil {
		return fmt.Errorf("sample monotonic clock: %w", err)
	}

	headers, err := parseKeyValues(o.otlpHeaders)
	if err != nil {
		return fmt.Errorf("parse -otlp-header: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	exporter, err := otelexport.New(ctx, otelexport.Config{
		Protocol:           otelexport.Protocol(o.otlpProtocol),
		Endpoint:           o.otlpEndpoint,
		Insecure:           o.otlpInsecure,
		Headers:            headers,
		ServiceName:        o.serviceName,
		ServiceNamespace:   o.serviceNamespace,
		ServiceVersion:     o.serviceVersion,
		ResourceAttributes: o.resourceAttrs,
		Clock:              clock,
		Logger:             log,
	})
	if err != nil {
		return fmt.Errorf("set up OTLP exporter: %w", err)
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), o.shutdownGrace)
		defer cancel()
		if err := exporter.Shutdown(flushCtx); err != nil {
			log.Error("flush spans on shutdown", "error", err)
		}
	}()

	tracer, err := bpftracer.New(bpftracer.Config{
		ObjectPath:      o.bpfObject,
		Binaries:        o.binaries,
		Provider:        o.provider,
		PID:             o.pid,
		AttachMode:      bpftracer.AttachMode(o.attachMode),
		TraceFunctions:  o.traceFunctions,
		MaxDepth:        uint32(o.maxDepth),
		MinFuncDuration: o.bpfMinFunc,
		Logger:          log,
	})
	if err != nil {
		return err
	}
	defer tracer.Close()

	agg := pipeline.New(pipeline.Config{
		MinDuration:        o.minDuration,
		MinSpanDuration:    o.minSpan,
		MaxSpansPerRequest: o.maxSpans,
		MaxRequestAge:      o.maxRequestAge,
		Logger:             log,
	}, exporter)

	tracer.Start()

	log.Info("tracing PHP",
		"binaries", strings.Join(o.binaries, ","),
		"provider", o.provider,
		"pid", o.pid,
		"scanning", tracer.Scanning(),
		"attached_processes", tracer.AttachedProcesses(),
		"functions", o.traceFunctions,
		"min_duration", o.minDuration,
		"otlp", o.otlpProtocol,
		"endpoint", o.otlpEndpoint,
		"service", o.serviceName)

	return loop(ctx, o, log, tracer, agg)
}

func loop(ctx context.Context, o *options, log *slog.Logger, tracer *bpftracer.Tracer, agg *pipeline.Aggregator) error {
	sweep := time.NewTicker(o.sweepInterval)
	defer sweep.Stop()

	// In scan mode probes are bound per process, so new PHP workers have to be
	// picked up as they appear.
	scanInterval := o.scanInterval
	if !tracer.Scanning() || scanInterval <= 0 {
		scanInterval = time.Hour
	}
	scan := time.NewTicker(scanInterval)
	defer scan.Stop()

	statsInterval := o.statsInterval
	if statsInterval <= 0 {
		statsInterval = time.Hour
	}
	stats := time.NewTicker(statsInterval)
	defer stats.Stop()

	var (
		ev      event.Event
		decoded uint64
		bad     uint64
	)

	events := tracer.Events()
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down", "stats", fmt.Sprintf("%+v", agg.Stats()))
			return nil

		case raw, ok := <-events:
			if !ok {
				return errors.New("ring buffer closed unexpectedly")
			}
			if err := ev.Decode(raw); err != nil {
				bad++
				if bad <= 10 {
					log.Warn("decode ring buffer record", "error", err, "bytes", len(raw))
				}
				continue
			}
			decoded++
			agg.Handle(&ev, time.Now())

		case <-scan.C:
			if !tracer.Scanning() {
				continue
			}
			attached, detached, err := tracer.Rescan()
			if err != nil {
				log.Warn("scan for PHP processes", "error", err)
			}
			if attached > 0 || detached > 0 {
				log.Info("process attachments changed",
					"attached", attached, "detached", detached,
					"total", tracer.AttachedProcesses())
			}

		case now := <-sweep.C:
			if n := agg.Sweep(now); n > 0 {
				log.Debug("swept stale buffered requests", "count", n)
			}
			if n := tracer.SweepStale(monoclock.NowNS(), o.maxRequestAge); n > 0 {
				log.Debug("swept stale kernel request state", "count", n)
			}

		case <-stats.C:
			if o.statsInterval > 0 {
				s := agg.Stats()
				log.Info("stats",
					"events", decoded,
					"malformed", bad,
					"req_started", s.RequestsStarted,
					"req_completed", s.RequestsCompleted,
					"req_exported", s.RequestsExported,
					"req_below_min", s.RequestsBelowMin,
					"req_expired", s.RequestsExpired,
					"spans_buffered", s.SpansBuffered,
					"spans_dropped_short", s.SpansDroppedShort,
					"spans_dropped_cap", s.SpansDroppedCap,
					"spans_orphaned", s.SpansOrphaned,
					"in_flight", s.InFlight,
					"attached_processes", tracer.AttachedProcesses())
			}
		}
	}
}

func newLogger(level string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid -log-level %q", level)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	return log, nil
}

func parseKeyValues(items []string) (map[string]string, error) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(items))
	for _, item := range items {
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not key=value", item)
		}
		out[k] = v
	}

	return out, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
