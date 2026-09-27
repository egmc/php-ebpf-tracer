package event

import (
	"encoding/binary"
	"testing"
)

// buildRecord lays out a record exactly the way the BPF program does, so a
// change to bpf/php_tracer.h that is not mirrored in event.go fails here.
func buildRecord(size int, typ uint8) []byte {
	raw := make([]byte, size)
	raw[offType] = typ
	raw[offFlags] = FlagTruncated
	binary.LittleEndian.PutUint32(raw[offPID:], 4242)
	binary.LittleEndian.PutUint32(raw[offTID:], 4243)
	binary.LittleEndian.PutUint64(raw[offTsStart:], 1_000)
	binary.LittleEndian.PutUint64(raw[offTsEnd:], 3_000)
	binary.LittleEndian.PutUint64(raw[offTraceIDHi:], 0xAABBCCDD11223344)
	binary.LittleEndian.PutUint64(raw[offTraceIDLo:], 0x5566778899AABBCC)
	binary.LittleEndian.PutUint64(raw[offSpanID:], 0xDEADBEEF)
	binary.LittleEndian.PutUint64(raw[offParentSpanID:], 0xFEEDFACE)

	return raw
}

func putCStr(raw []byte, off int, s string) {
	copy(raw[off:], s)
	raw[off+len(s)] = 0
}

func TestDecodeFunctionEvent(t *testing.T) {
	raw := buildRecord(sizeFuncEvent, TypeFunc)
	binary.LittleEndian.PutUint32(raw[offFuncLineno:], uint32(int32(41)))
	binary.LittleEndian.PutUint32(raw[offFuncDepth:], 3)
	putCStr(raw, offFuncName, "findAll")
	putCStr(raw, offFuncClass, "Repository")
	putCStr(raw, offFuncFile, "/app/index.php")

	var ev Event
	if err := ev.Decode(raw); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if ev.Type != TypeFunc {
		t.Errorf("Type = %d", ev.Type)
	}
	if !ev.Truncated() {
		t.Error("Truncated = false, want true")
	}
	if ev.Key() != uint64(4242)<<32|4243 {
		t.Errorf("Key = %#x", ev.Key())
	}
	if ev.Lineno != 41 || ev.Depth != 3 {
		t.Errorf("Lineno/Depth = %d/%d", ev.Lineno, ev.Depth)
	}
	if ev.Func != "findAll" || ev.Class != "Repository" || ev.File != "/app/index.php" {
		t.Errorf("strings = %q %q %q", ev.Func, ev.Class, ev.File)
	}
	if ev.TsEnd-ev.TsStart != 2_000 {
		t.Errorf("duration = %d", ev.TsEnd-ev.TsStart)
	}
	if ev.Collapsed() {
		t.Error("Collapsed = true, want false")
	}

	raw[offFlags] |= FlagCollapsed
	if err := ev.Decode(raw); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !ev.Collapsed() || !ev.Truncated() {
		t.Errorf("Collapsed/Truncated = %v/%v, want true/true", ev.Collapsed(), ev.Truncated())
	}
}

func TestDecodeRequestEvent(t *testing.T) {
	raw := buildRecord(sizeReqEvent, TypeReqEnd)
	binary.LittleEndian.PutUint32(raw[offReqDropped:], 7)
	binary.LittleEndian.PutUint32(raw[offReqEmitted:], 99)
	putCStr(raw, offReqFile, "/app/index.php")
	putCStr(raw, offReqURI, "/slow?x=1")
	putCStr(raw, offReqMethod, "GET")

	var ev Event
	if err := ev.Decode(raw); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if ev.DroppedFrames != 7 || ev.EmittedSpans != 99 {
		t.Errorf("counters = %d/%d", ev.DroppedFrames, ev.EmittedSpans)
	}
	if ev.URI != "/slow?x=1" || ev.Method != "GET" || ev.File != "/app/index.php" {
		t.Errorf("strings = %q %q %q", ev.URI, ev.Method, ev.File)
	}
}

func TestDecodeRejectsBadRecords(t *testing.T) {
	var ev Event

	if err := ev.Decode(make([]byte, 8)); err == nil {
		t.Error("short header accepted")
	}
	if err := ev.Decode(buildRecord(sizeHdr, TypeFunc)); err == nil {
		t.Error("truncated function record accepted")
	}
	if err := ev.Decode(buildRecord(sizeReqEvent, 99)); err == nil {
		t.Error("unknown event type accepted")
	}
}

// A NUL-terminated string that exactly fills its field must not overrun.
func TestDecodeFullWidthString(t *testing.T) {
	raw := buildRecord(sizeFuncEvent, TypeFunc)
	name := make([]byte, offFuncClass-offFuncName)
	for i := range name {
		name[i] = 'a'
	}
	copy(raw[offFuncName:], name)

	var ev Event
	if err := ev.Decode(raw); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(ev.Func) != len(name) {
		t.Errorf("len(Func) = %d, want %d", len(ev.Func), len(name))
	}
}
