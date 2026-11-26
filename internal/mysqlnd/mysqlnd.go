// Package mysqlnd finds the mysqlnd functions the query probes attach to.
//
// mysqlnd has no USDT markers, and distributions ship it stripped, so its
// functions have no symbols. They are reached through method tables, though,
// and those are exported: mysqlnd_mysqlnd_conn_data_methods and
// mysqlnd_mysqlnd_command_methods are arrays of function pointers whose order
// is fixed by mysqlnd_structs.h. Reading the right slots gives the functions'
// addresses without any debug information.
//
// The package is free of cgo so it can be tested anywhere.
package mysqlnd

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Offsets are file offsets of the probed functions within Path, which is what
// a uprobe attaches to.
type Offsets struct {
	Path string

	// ConnQuery is conn_data::query(conn, const char *query, size_t len).
	ConnQuery uint64
	// ReadResultHeader is conn_data::query_read_result_set_header(conn, stmt).
	ReadResultHeader uint64
	// StmtPrepare is command::stmt_prepare(conn, MYSQLND_CSTRING query).
	StmtPrepare uint64
	// StmtExecute is command::stmt_execute(conn, MYSQLND_CSTRING payload).
	StmtExecute uint64
}

// layout is the position of the probed methods in the two tables for one
// version of mysqlnd_structs.h. The table sizes identify the version: adding
// or removing a method changes them.
type layout struct {
	name string

	connDataSize     uint64
	connQuery        int
	readResultHeader int

	commandSize int
	stmtPrepare int
	stmtExecute int
}

// layouts lists the versions whose slots have been checked against
// mysqlnd_structs.h.
var layouts = []layout{
	{
		name:         "PHP 8.5",
		connDataSize: 0x200, connQuery: 3, readResultHeader: 40,
		commandSize: 0x98, stmtPrepare: 11, stmtExecute: 12,
	},
}

const (
	symConnData = "mysqlnd_mysqlnd_conn_data_methods"
	symCommand  = "mysqlnd_mysqlnd_command_methods"
)

// ErrNoTables is returned when a file does not export the method tables.
var ErrNoTables = errors.New("mysqlnd method tables not found")

// Resolve reads the method tables of the mysqlnd in path, which is either
// mysqlnd.so or a PHP binary with mysqlnd built in.
func Resolve(path string) (*Offsets, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		return nil, fmt.Errorf("%s: only little-endian 64-bit ELF is supported", path)
	}

	connData, command, err := findTables(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	var l *layout
	for i := range layouts {
		if layouts[i].connDataSize == connData.Size && uint64(layouts[i].commandSize) == command.Size {
			l = &layouts[i]
			break
		}
	}
	if l == nil {
		return nil, fmt.Errorf("%s: unsupported mysqlnd version (method tables of %d and %d bytes); "+
			"supported: %s", path, connData.Size, command.Size, supported())
	}

	img, err := newImage(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	o := &Offsets{Path: path}
	for _, slot := range []struct {
		dst   *uint64
		table elf.Symbol
		index int
		what  string
	}{
		{&o.ConnQuery, connData, l.connQuery, "conn_data::query"},
		{&o.ReadResultHeader, connData, l.readResultHeader, "conn_data::query_read_result_set_header"},
		{&o.StmtPrepare, command, l.stmtPrepare, "command::stmt_prepare"},
		{&o.StmtExecute, command, l.stmtExecute, "command::stmt_execute"},
	} {
		off, err := img.funcOffset(slot.table.Value + uint64(slot.index)*8)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", path, slot.what, err)
		}
		*slot.dst = off
	}

	return o, nil
}

func supported() string {
	names := make([]string, len(layouts))
	for i, l := range layouts {
		names[i] = l.name
	}

	return strings.Join(names, ", ")
}

// findTables looks the tables up in the dynamic symbols, where a shared
// object exports them, then in the full symbol table, which a PHP binary with
// mysqlnd built in may still have.
func findTables(f *elf.File) (connData, command elf.Symbol, err error) {
	var found int
	for _, get := range []func() ([]elf.Symbol, error){f.DynamicSymbols, f.Symbols} {
		syms, err := get()
		if err != nil {
			continue
		}
		for _, s := range syms {
			switch s.Name {
			case symConnData:
				connData = s
				found |= 1
			case symCommand:
				command = s
				found |= 2
			}
		}
		if found == 3 {
			return connData, command, nil
		}
	}

	return connData, command, ErrNoTables
}

// image answers what a pointer stored in the file points at.
type image struct {
	// relative maps the address of each R_*_RELATIVE relocation to its
	// addend. In a shared object or PIE every function pointer in a data
	// table is such a relocation, and the slot in the file holds nothing
	// useful.
	relative map[uint64]uint64
	sections []*elf.Section
	progs    []*elf.Prog
}

func newImage(f *elf.File) (*image, error) {
	img := &image{relative: map[uint64]uint64{}, sections: f.Sections, progs: f.Progs}

	var relativeType uint32
	switch f.Machine {
	case elf.EM_X86_64:
		relativeType = uint32(elf.R_X86_64_RELATIVE)
	case elf.EM_AARCH64:
		relativeType = uint32(elf.R_AARCH64_RELATIVE)
	default:
		return nil, fmt.Errorf("unsupported machine %s", f.Machine)
	}

	for _, s := range f.Sections {
		if s.Type != elf.SHT_RELA {
			continue
		}
		data, err := s.Data()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", s.Name, err)
		}
		for len(data) >= 24 {
			var r elf.Rela64
			r.Off = binary.LittleEndian.Uint64(data[0:])
			r.Info = binary.LittleEndian.Uint64(data[8:])
			r.Addend = int64(binary.LittleEndian.Uint64(data[16:]))
			data = data[24:]
			if elf.R_TYPE64(r.Info) == relativeType {
				img.relative[r.Off] = uint64(r.Addend)
			}
		}
	}

	return img, nil
}

// funcOffset returns the file offset of the function whose address is stored
// at slot, an address in the file's own address space.
func (img *image) funcOffset(slot uint64) (uint64, error) {
	addr, ok := img.relative[slot]
	if !ok {
		// A non-PIE executable stores absolute addresses directly.
		v, err := img.readUint64(slot)
		if err != nil {
			return 0, err
		}
		addr = v
	}
	if addr == 0 {
		return 0, errors.New("method slot is empty")
	}

	return img.fileOffset(addr)
}

// readUint64 reads 8 bytes at address addr from the section holding it.
func (img *image) readUint64(addr uint64) (uint64, error) {
	for _, s := range img.sections {
		if s.Type == elf.SHT_NOBITS || addr < s.Addr || addr+8 > s.Addr+s.Size {
			continue
		}
		var b [8]byte
		if _, err := s.ReadAt(b[:], int64(addr-s.Addr)); err != nil && err != io.EOF {
			return 0, err
		}

		return binary.LittleEndian.Uint64(b[:]), nil
	}

	return 0, fmt.Errorf("no section holds address %#x", addr)
}

// fileOffset converts the address of a function to its offset in the file,
// checking that it lies in an executable segment.
func (img *image) fileOffset(addr uint64) (uint64, error) {
	for _, p := range img.progs {
		if p.Type != elf.PT_LOAD || addr < p.Vaddr || addr >= p.Vaddr+p.Filesz {
			continue
		}
		if p.Flags&elf.PF_X == 0 {
			return 0, fmt.Errorf("address %#x is not in an executable segment", addr)
		}

		return addr - p.Vaddr + p.Off, nil
	}

	return 0, fmt.Errorf("address %#x is outside every loadable segment", addr)
}

// searchPatterns are where distributions and the php-src default install put
// shared extensions.
var searchPatterns = []string{
	"/usr/lib/php/*/mysqlnd.so",                  // Debian, Ubuntu
	"/usr/lib64/php/modules/mysqlnd.so",          // Fedora, RHEL
	"/usr/local/lib/php/extensions/*/mysqlnd.so", // php-src, official Docker images
}

// Find locates mysqlnd for the given PHP binaries: in a binary itself when
// mysqlnd is built in, otherwise as the one mysqlnd.so in the usual
// extension directories.
func Find(binaries []string) (string, error) {
	for _, b := range binaries {
		f, err := elf.Open(b)
		if err != nil {
			continue
		}
		_, _, err = findTables(f)
		f.Close()
		if err == nil {
			return b, nil
		}
	}

	seen := map[string]bool{}
	var candidates []string
	for _, pattern := range searchPatterns {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			real, err := filepath.EvalSymlinks(m)
			if err != nil || seen[real] {
				continue
			}
			if _, err := os.Stat(real); err != nil {
				continue
			}
			seen[real] = true
			candidates = append(candidates, m)
		}
	}
	sort.Strings(candidates)

	switch len(candidates) {
	case 0:
		return "", errors.New("mysqlnd.so not found and no PHP binary has mysqlnd built in; pass its path explicitly")
	case 1:
		return candidates[0], nil
	default:
		return "", fmt.Errorf("found several mysqlnd.so (%v); pass the one the traced PHP loads explicitly", candidates)
	}
}
