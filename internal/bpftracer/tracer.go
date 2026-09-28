// Package bpftracer loads the USDT eBPF program, attaches it to a PHP binary
// and forwards ring buffer records to the rest of the pipeline.
package bpftracer

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// Probe names as they appear in the ELF SDT notes of a PHP built with
// --enable-dtrace. php-src writes them with double underscores
// (Zend/zend_dtrace.d), which DTrace renders as request-startup etc.
const (
	probeRequestStartup  = "request__startup"
	probeRequestShutdown = "request__shutdown"
	probeFunctionEntry   = "function__entry"
	probeFunctionReturn  = "function__return"
)

// Include path limits, mirroring MAX_INCLUDE_PATHS and MAX_FILE_LEN in
// bpf/php_tracer.h.
const (
	MaxIncludePaths = 8
	maxFileLen      = 128
)

// AttachAllPIDs attaches to every process mapping the target binary, present
// and future.
const AttachAllPIDs = -1

// AttachMode selects how probes are bound to PHP processes.
type AttachMode string

const (
	// AttachModeAuto tries a single global attach and falls back to scanning
	// when the kernel refuses it.
	AttachModeAuto AttachMode = "auto"
	// AttachModeGlobal attaches once with pid -1. Cheapest, catches
	// short-lived processes, but a position-independent executable needs BPF
	// cookie support (kernel >= 5.15).
	AttachModeGlobal AttachMode = "global"
	// AttachModeScan discovers matching processes through /proc and attaches
	// to each one individually. Works everywhere, but a process that starts
	// and exits between two scans is missed.
	AttachModeScan AttachMode = "scan"
)

// Config configures the eBPF side of the tracer.
type Config struct {
	// ObjectPath is the compiled php_tracer.bpf.o.
	ObjectPath string
	// Binaries are the PHP executables (or shared objects) carrying the USDT
	// notes, e.g. /usr/local/bin/php and /usr/local/sbin/php-fpm.
	Binaries []string
	// Provider is the USDT provider name, "php" for php-src.
	Provider string
	// PID restricts tracing to a single process, or AttachAllPIDs.
	PID int
	// AttachMode selects global versus per-process attachment.
	AttachMode AttachMode
	// TraceFunctions enables the function__entry/function__return probes.
	TraceFunctions bool
	// MaxDepth is the deepest PHP call depth that still produces a span.
	MaxDepth uint32
	// MinFuncDuration drops function spans shorter than this in the kernel.
	// Cheap, but children of a dropped span lose their parent and are
	// re-parented onto the request root; prefer the userspace filter unless
	// the event rate is a problem.
	MinFuncDuration time.Duration
	// IncludePaths are prefixes matched in the kernel against the file each
	// function is defined in. When set, only matching functions produce a
	// span; the callees of a skipped function are attached to its nearest
	// reported ancestor. Empty traces every file. At most MaxIncludePaths.
	IncludePaths []string

	// ProcRoot is the procfs mount used for process discovery.
	ProcRoot string

	Logger *slog.Logger
}

func (c *Config) setDefaults() {
	if c.Provider == "" {
		c.Provider = "php"
	}
	if c.PID == 0 {
		c.PID = AttachAllPIDs
	}
	if c.AttachMode == "" {
		c.AttachMode = AttachModeAuto
	}
	if c.MaxDepth == 0 {
		c.MaxDepth = 32
	}
	if c.ProcRoot == "" {
		c.ProcRoot = "/proc"
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// Tracer owns the loaded BPF object, its attachments and the ring buffer.
type Tracer struct {
	cfg      Config
	log      *slog.Logger
	module   *bpf.Module
	requests *bpf.BPFMap
	ring     *bpf.RingBuffer
	events   chan []byte

	// links is keyed by the pid the probes were attached with; AttachAllPIDs
	// for a global attach.
	links map[int][]*bpf.BPFLink
	// scanning is set when per-process discovery is in use.
	scanning bool
	closed   bool
}

// New loads the BPF object, applies the configuration to its .rodata globals
// and attaches every probe. The ring buffer is not polled until Start.
func New(cfg Config) (*Tracer, error) {
	cfg.setDefaults()

	if err := validateIncludePaths(cfg.IncludePaths); err != nil {
		return nil, err
	}

	if cfg.ObjectPath == "" {
		return nil, errors.New("bpftracer: ObjectPath is required")
	}
	if len(cfg.Binaries) == 0 {
		return nil, errors.New("bpftracer: at least one binary to attach to is required")
	}

	module, err := bpf.NewModuleFromFile(cfg.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("open BPF object %s: %w", cfg.ObjectPath, err)
	}

	t := &Tracer{
		cfg:    cfg,
		log:    cfg.Logger,
		module: module,
		events: make(chan []byte, 8192),
		links:  make(map[int][]*bpf.BPFLink),
	}

	// The module is owned by t from here on, so every failure below goes
	// through t.releaseUnstarted to avoid closing it twice.
	if err := t.load(); err != nil {
		t.releaseUnstarted()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) load() error {
	if err := t.initGlobals(); err != nil {
		return err
	}

	if err := t.module.BPFLoadObject(); err != nil {
		return fmt.Errorf("load BPF object: %w", err)
	}

	var err error
	if t.requests, err = t.module.GetMap("requests"); err != nil {
		return fmt.Errorf("find requests map: %w", err)
	}

	if err := t.attachInitial(); err != nil {
		return err
	}

	if t.ring, err = t.module.InitRingBuf("events", t.events); err != nil {
		return fmt.Errorf("init ring buffer: %w", err)
	}

	return nil
}

// initGlobals writes the configuration into .rodata. This must happen before
// the object is loaded so the verifier treats the values as constants.
func (t *Tracer) initGlobals() error {
	pid := uint32(0)
	if t.cfg.PID > 0 {
		pid = uint32(t.cfg.PID)
	}
	traceFunctions := uint8(0)
	if t.cfg.TraceFunctions {
		traceFunctions = 1
	}

	globals := []struct {
		name  string
		value any
	}{
		{"targ_pid", pid},
		{"max_depth", t.cfg.MaxDepth},
		{"min_func_ns", uint64(t.cfg.MinFuncDuration.Nanoseconds())},
		{"trace_functions", traceFunctions},
		{"n_include_paths", uint32(len(t.cfg.IncludePaths))},
		{"include_paths", includeSlots(t.cfg.IncludePaths)},
	}
	for _, g := range globals {
		if err := t.module.InitGlobalVariable(g.name, g.value); err != nil {
			return fmt.Errorf("set BPF global %s: %w", g.name, err)
		}
	}

	return nil
}

// validateIncludePaths rejects paths the BPF side cannot honour. The kernel
// reads at most maxFileLen-1 bytes of a path, so a longer prefix could never
// match.
func validateIncludePaths(paths []string) error {
	if len(paths) > MaxIncludePaths {
		return fmt.Errorf("bpftracer: at most %d include paths are supported, got %d",
			MaxIncludePaths, len(paths))
	}
	for _, p := range paths {
		if p == "" {
			return errors.New("bpftracer: empty include path")
		}
		if len(p) >= maxFileLen {
			return fmt.Errorf("bpftracer: include path %q is longer than %d bytes", p, maxFileLen-1)
		}
	}

	return nil
}

// includeSlots lays paths out as the NUL padded
// char[MaxIncludePaths][maxFileLen] array the BPF program expects.
func includeSlots(paths []string) []byte {
	slots := make([]byte, MaxIncludePaths*maxFileLen)
	for i, p := range paths {
		copy(slots[i*maxFileLen:], p)
	}

	return slots
}

func (t *Tracer) attachInitial() error {
	switch t.cfg.AttachMode {
	case AttachModeGlobal:
		return t.attachPID(t.cfg.PID)

	case AttachModeScan:
		t.scanning = true
		_, _, err := t.Rescan()

		return err

	case AttachModeAuto:
		if t.cfg.PID > 0 {
			return t.attachPID(t.cfg.PID)
		}
		err := t.attachPID(AttachAllPIDs)
		if err == nil {
			return nil
		}
		// Most likely a position-independent PHP binary on a kernel without
		// BPF cookie support, where libbpf cannot resolve marker addresses
		// without knowing a process' load base.
		t.log.Warn("global USDT attach failed, falling back to per-process scanning",
			"error", err)
		t.destroyLinksFor(AttachAllPIDs)
		t.scanning = true
		attached, _, scanErr := t.Rescan()
		if scanErr != nil {
			return scanErr
		}
		t.log.Info("attached by scanning /proc", "processes", attached)

		return nil

	default:
		return fmt.Errorf("unknown attach mode %q", t.cfg.AttachMode)
	}
}

type probe struct {
	prog string
	name string
}

func (t *Tracer) probes() []probe {
	probes := []probe{
		{"usdt_request_startup", probeRequestStartup},
		{"usdt_request_shutdown", probeRequestShutdown},
	}
	if t.cfg.TraceFunctions {
		probes = append(probes,
			probe{"usdt_function_entry", probeFunctionEntry},
			probe{"usdt_function_return", probeFunctionReturn},
		)
	}

	return probes
}

// attachPID wires every program to its USDT marker in every configured binary
// for one pid (or AttachAllPIDs). On failure nothing stays attached.
func (t *Tracer) attachPID(pid int) error {
	var links []*bpf.BPFLink

	for _, binary := range t.cfg.Binaries {
		for _, p := range t.probes() {
			prog, err := t.module.GetProgram(p.prog)
			if err != nil {
				destroyLinks(t.log, links)
				return fmt.Errorf("find BPF program %s: %w", p.prog, err)
			}

			link, err := prog.AttachUSDT(pid, binary, t.cfg.Provider, p.name)
			if err != nil {
				destroyLinks(t.log, links)
				return fmt.Errorf("attach %s:%s in %s for pid %d (is PHP built with --enable-dtrace?): %w",
					t.cfg.Provider, p.name, binary, pid, err)
			}
			links = append(links, link)
		}
	}

	t.links[pid] = append(t.links[pid], links...)
	t.log.Debug("attached USDT probes", "pid", pid, "links", len(links))

	return nil
}

// Rescan attaches to PHP processes that appeared since the last call and
// detaches from those that are gone. It is a no-op outside scan mode.
//
// Call it from the same goroutine that drains Events.
func (t *Tracer) Rescan() (attached, detached int, err error) {
	if !t.scanning {
		return 0, 0, nil
	}

	live, err := t.findProcesses()
	if err != nil {
		return 0, 0, err
	}

	for pid := range live {
		if _, ok := t.links[pid]; ok {
			continue
		}
		if err := t.attachPID(pid); err != nil {
			// The process may have exited mid-scan; retry on the next pass.
			t.log.Debug("attach to discovered process failed", "pid", pid, "error", err)
			continue
		}
		attached++
	}

	for pid := range t.links {
		if live[pid] {
			continue
		}
		t.destroyLinksFor(pid)
		detached++
	}

	return attached, detached, nil
}

// fileID identifies a file independently of the path it is reached through, so
// a process in another mount namespace still matches.
type fileID struct {
	dev uint64
	ino uint64
}

func statID(path string) (fileID, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileID{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, fmt.Errorf("unexpected stat type for %s", path)
	}

	return fileID{dev: uint64(st.Dev), ino: st.Ino}, nil
}

// findProcesses returns the pids whose executable is one of the configured
// binaries, matched by inode rather than by path.
func (t *Tracer) findProcesses() (map[int]bool, error) {
	targets := make(map[fileID]bool, len(t.cfg.Binaries))
	for _, binary := range t.cfg.Binaries {
		id, err := statID(binary)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", binary, err)
		}
		targets[id] = true
	}

	entries, err := os.ReadDir(t.cfg.ProcRoot)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", t.cfg.ProcRoot, err)
	}

	self := os.Getpid()
	out := make(map[int]bool)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		// os.Stat follows /proc/<pid>/exe to the executable itself.
		id, err := statID(filepath.Join(t.cfg.ProcRoot, e.Name(), "exe"))
		if err != nil {
			continue // exited, or not ours to look at
		}
		if targets[id] {
			out[pid] = true
		}
	}

	return out, nil
}

// Scanning reports whether per-process discovery is active, i.e. whether
// Rescan needs to be called periodically.
func (t *Tracer) Scanning() bool { return t.scanning }

// AttachedProcesses returns how many pids currently have probes attached.
func (t *Tracer) AttachedProcesses() int { return len(t.links) }

// Events returns the channel of raw ring buffer records. It is closed when the
// tracer shuts down.
func (t *Tracer) Events() <-chan []byte { return t.events }

// Start begins polling the ring buffer.
func (t *Tracer) Start() { t.ring.Poll(100) }

// Close stops polling, detaches every probe and releases the BPF object.
func (t *Tracer) Close() {
	if t.closed {
		return
	}
	t.closed = true

	if t.ring != nil {
		t.ring.Close() // also closes t.events
	}
	t.releaseUnstarted()
}

// releaseUnstarted tears down everything except the ring buffer. It is safe to
// call once, from Close or from the New error path.
func (t *Tracer) releaseUnstarted() {
	for pid := range t.links {
		t.destroyLinksFor(pid)
	}
	if t.module != nil {
		t.module.Close()
		t.module = nil
	}
}

func (t *Tracer) destroyLinksFor(pid int) {
	destroyLinks(t.log, t.links[pid])
	delete(t.links, pid)
}

func destroyLinks(log *slog.Logger, links []*bpf.BPFLink) {
	for _, link := range links {
		if err := link.Destroy(); err != nil {
			log.Debug("destroy BPF link", "error", err)
		}
	}
}

// SweepStale removes per-request state left behind by processes that died
// without firing request__shutdown (SIGKILL, OOM). Returns the number of
// entries deleted.
//
// nowNS must be a CLOCK_MONOTONIC reading, matching bpf_ktime_get_ns().
func (t *Tracer) SweepStale(nowNS uint64, maxAge time.Duration) int {
	if t.requests == nil {
		return 0
	}

	// start_ns is the first field of struct php_req_state.
	const offStartNS = 0

	cutoff := uint64(maxAge.Nanoseconds())
	var stale []uint64

	iter := t.requests.Iterator()
	for iter.Next() {
		raw := iter.Key()
		if len(raw) < 8 {
			continue
		}
		key := *(*uint64)(unsafe.Pointer(&raw[0]))

		value, err := t.requests.GetValue(unsafe.Pointer(&key))
		if err != nil || len(value) < offStartNS+8 {
			continue
		}
		startNS := *(*uint64)(unsafe.Pointer(&value[offStartNS]))
		if nowNS > startNS && nowNS-startNS > cutoff {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		t.log.Warn("iterate requests map", "error", err)
	}

	for i := range stale {
		if err := t.requests.DeleteKey(unsafe.Pointer(&stale[i])); err != nil {
			t.log.Warn("delete stale request state", "error", err)
		}
	}

	return len(stale)
}
