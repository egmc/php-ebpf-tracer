// Package bpfobj embeds the compiled BPF program, so the tracer ships as a
// single binary.
//
// php_tracer.bpf.o is a build product: `make` compiles bpf/php_tracer.bpf.c
// and copies the object here before building the Go code. A plain `go build`
// on a fresh checkout therefore fails with "no matching files found"; run
// `make` instead.
//
// The object is licensed GPL-2.0-only OR BSD-2-Clause, like its source.
package bpfobj

import _ "embed"

// Object is the contents of php_tracer.bpf.o.
//
//go:embed php_tracer.bpf.o
var Object []byte

// Name is the file name the object was compiled to, used by libbpf in log
// messages.
const Name = "php_tracer.bpf.o"
