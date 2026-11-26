package mysqlnd

import (
	"debug/elf"
	"os"
	"testing"
)

func TestFuncOffsetFollowsRelativeRelocation(t *testing.T) {
	img := &image{
		relative: map[uint64]uint64{0x353f8: 0x12660},
		progs: []*elf.Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Vaddr: 0, Off: 0, Filesz: 0xbcb0}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X,
				Vaddr: 0xc000, Off: 0xc000, Filesz: 0x1a679}},
		},
	}

	off, err := img.funcOffset(0x353f8)
	if err != nil {
		t.Fatalf("funcOffset: %v", err)
	}
	if off != 0x12660 {
		t.Errorf("offset = %#x, want 0x12660", off)
	}
}

func TestFileOffsetTranslatesShiftedSegment(t *testing.T) {
	img := &image{progs: []*elf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X,
			Vaddr: 0x401000, Off: 0x1000, Filesz: 0x2000}},
	}}

	off, err := img.fileOffset(0x401234)
	if err != nil {
		t.Fatalf("fileOffset: %v", err)
	}
	if off != 0x1234 {
		t.Errorf("offset = %#x, want 0x1234", off)
	}
}

func TestFileOffsetRejectsData(t *testing.T) {
	img := &image{progs: []*elf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W, Vaddr: 0x30000, Off: 0x30000, Filesz: 0x1000}},
	}}

	if _, err := img.fileOffset(0x30010); err == nil {
		t.Error("an address in a data segment was accepted")
	}
	if _, err := img.fileOffset(0x90000); err == nil {
		t.Error("an address outside every segment was accepted")
	}
}

// Resolves the mysqlnd installed on this host, if any. Set MYSQLND_SO to test
// a specific file.
func TestResolveInstalled(t *testing.T) {
	path := os.Getenv("MYSQLND_SO")
	if path == "" {
		var err error
		if path, err = Find(nil); err != nil {
			t.Skipf("no mysqlnd here: %v", err)
		}
	}

	o, err := Resolve(path)
	if err != nil {
		t.Fatalf("Resolve(%s): %v", path, err)
	}
	t.Logf("%s: query %#x, read_result_header %#x, stmt_prepare %#x, stmt_execute %#x",
		o.Path, o.ConnQuery, o.ReadResultHeader, o.StmtPrepare, o.StmtExecute)

	seen := map[uint64]bool{}
	for _, off := range []uint64{o.ConnQuery, o.ReadResultHeader, o.StmtPrepare, o.StmtExecute} {
		if off == 0 || seen[off] {
			t.Errorf("offsets are not distinct and non-zero: %+v", o)
		}
		seen[off] = true
	}
}
