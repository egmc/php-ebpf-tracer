// Package event decodes the ring buffer records produced by
// bpf/php_tracer.bpf.c. It is deliberately free of cgo so the rest of the
// pipeline can be built and tested on any platform.
package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Event types, mirroring enum php_event_type in bpf/php_tracer.h.
const (
	TypeReqStart uint8 = 1
	TypeReqEnd   uint8 = 2
	TypeFunc     uint8 = 3
)

// Header flags, mirroring PHP_EV_F_* in bpf/php_tracer.h.
const (
	FlagTruncated uint8 = 0x01
	FlagCollapsed uint8 = 0x02
)

// Record sizes, mirroring bpf/php_tracer.h. Checked against every record the
// ring buffer hands us so a layout drift fails loudly instead of silently
// producing garbage spans.
const (
	sizeHdr       = 64
	sizeFuncEvent = 328
	sizeReqEvent  = 344
)

// Field offsets within a record.
const (
	offType         = 0
	offFlags        = 1
	offPID          = 4
	offTID          = 8
	offTsStart      = 16
	offTsEnd        = 24
	offTraceIDHi    = 32
	offTraceIDLo    = 40
	offSpanID       = 48
	offParentSpanID = 56

	offFuncLineno = 64
	offFuncDepth  = 68
	offFuncName   = 72
	offFuncClass  = 136
	offFuncFile   = 200

	offReqDropped = 64
	offReqEmitted = 68
	offReqFile    = 72
	offReqURI     = 200
	offReqMethod  = 328
)

// Event is the decoded form of a single ring buffer record. One Go struct
// covers both record shapes so the hot path can reuse a single value instead
// of allocating per event.
type Event struct {
	Type  uint8
	Flags uint8
	PID   uint32
	TID   uint32

	// Monotonic (CLOCK_MONOTONIC) nanosecond timestamps.
	TsStart uint64
	TsEnd   uint64

	TraceIDHi    uint64
	TraceIDLo    uint64
	SpanID       uint64
	ParentSpanID uint64

	// TypeFunc only.
	Lineno int32
	Depth  uint32
	Func   string
	Class  string

	// TypeReqStart / TypeReqEnd only.
	DroppedFrames uint32
	EmittedSpans  uint32
	URI           string
	Method        string

	// Set for every event type.
	File string
}

// Key identifies the PHP request this event belongs to. It is the raw
// bpf_get_current_pid_tgid() value used as the BPF hash map key.
func (e *Event) Key() uint64 {
	return uint64(e.PID)<<32 | uint64(e.TID)
}

// Truncated reports whether the request lost frames before this event.
func (e *Event) Truncated() bool { return e.Flags&FlagTruncated != 0 }

// Collapsed reports whether this function span matched a collapse rule, i.e.
// everything it called was suppressed in the kernel.
func (e *Event) Collapsed() bool { return e.Flags&FlagCollapsed != 0 }

// Decode parses a ring buffer record in place, overwriting every field.
func (e *Event) Decode(raw []byte) error {
	if len(raw) < sizeHdr {
		return fmt.Errorf("short record: %d bytes", len(raw))
	}

	*e = Event{
		Type:         raw[offType],
		Flags:        raw[offFlags],
		PID:          binary.LittleEndian.Uint32(raw[offPID:]),
		TID:          binary.LittleEndian.Uint32(raw[offTID:]),
		TsStart:      binary.LittleEndian.Uint64(raw[offTsStart:]),
		TsEnd:        binary.LittleEndian.Uint64(raw[offTsEnd:]),
		TraceIDHi:    binary.LittleEndian.Uint64(raw[offTraceIDHi:]),
		TraceIDLo:    binary.LittleEndian.Uint64(raw[offTraceIDLo:]),
		SpanID:       binary.LittleEndian.Uint64(raw[offSpanID:]),
		ParentSpanID: binary.LittleEndian.Uint64(raw[offParentSpanID:]),
	}

	switch e.Type {
	case TypeFunc:
		if len(raw) < sizeFuncEvent {
			return fmt.Errorf("short function record: %d bytes, want %d", len(raw), sizeFuncEvent)
		}
		e.Lineno = int32(binary.LittleEndian.Uint32(raw[offFuncLineno:]))
		e.Depth = binary.LittleEndian.Uint32(raw[offFuncDepth:])
		e.Func = cstr(raw[offFuncName:offFuncClass])
		e.Class = cstr(raw[offFuncClass:offFuncFile])
		e.File = cstr(raw[offFuncFile:sizeFuncEvent])

	case TypeReqStart, TypeReqEnd:
		if len(raw) < sizeReqEvent {
			return fmt.Errorf("short request record: %d bytes, want %d", len(raw), sizeReqEvent)
		}
		e.DroppedFrames = binary.LittleEndian.Uint32(raw[offReqDropped:])
		e.EmittedSpans = binary.LittleEndian.Uint32(raw[offReqEmitted:])
		e.File = cstr(raw[offReqFile:offReqURI])
		e.URI = cstr(raw[offReqURI:offReqMethod])
		e.Method = cstr(raw[offReqMethod:sizeReqEvent])

	default:
		return fmt.Errorf("unknown event type %d", e.Type)
	}

	return nil
}

// cstr converts a NUL-padded C string to a Go string.
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}

	return string(b)
}
