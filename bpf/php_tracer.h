/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Wire format shared between the eBPF program (bpf/php_tracer.bpf.c) and the
 * Go decoder (internal/bpftracer/event.go).
 *
 * IMPORTANT: every change here must be mirrored in event.go. The layout is
 * little-endian / natural alignment, and is asserted at runtime by comparing
 * the record sizes reported by the ring buffer against sizeFuncEvent /
 * sizeReqEvent.
 */
#ifndef __PHP_TRACER_H
#define __PHP_TRACER_H

#define MAX_FUNC_LEN    64
#define MAX_CLASS_LEN   64
#define MAX_FILE_LEN    128
#define MAX_URI_LEN     128
#define MAX_METHOD_LEN  16

/* Maximum PHP userland call depth we keep per-request state for. Deeper
 * frames are counted but produce no span. Must stay a power of two: the BPF
 * program masks indices with frame_idx() so the verifier can prove they are
 * in range without relying on how clang orders the bounds check. */
#define MAX_STACK_DEPTH 128
_Static_assert((MAX_STACK_DEPTH & (MAX_STACK_DEPTH - 1)) == 0,
	       "MAX_STACK_DEPTH must be a power of two");

enum php_event_type {
	PHP_EV_REQ_START = 1,
	PHP_EV_REQ_END   = 2,
	PHP_EV_FUNC      = 3,
};

/* Include paths: when any are set, only functions defined in a file starting
 * with one of up to MAX_INCLUDE_PATHS prefixes produce a span. Patterns are
 * NUL padded and always shorter than MAX_FILE_LEN, since the kernel reads at
 * most MAX_FILE_LEN-1 bytes of a path. */
#define MAX_INCLUDE_PATHS 8

/* hdr.flags */
#define PHP_EV_F_TRUNCATED 0x01 /* frames were dropped while this request ran */

/* 64 bytes, 8-byte aligned. */
struct php_ev_hdr {
	__u8  type;  /* enum php_event_type */
	__u8  flags;
	__u16 pad0;
	__u32 pid;   /* tgid */
	__u32 tid;   /* thread id */
	__u32 pad1;
	__u64 ts_start; /* CLOCK_MONOTONIC ns, as returned by bpf_ktime_get_ns() */
	__u64 ts_end;
	__u64 trace_id_hi;
	__u64 trace_id_lo;
	__u64 span_id;
	__u64 parent_span_id;
};

/* 328 bytes */
struct php_func_event {
	struct php_ev_hdr hdr;
	__s32 lineno;
	__u32 depth;
	char  func[MAX_FUNC_LEN];
	char  cls[MAX_CLASS_LEN];
	char  file[MAX_FILE_LEN];
};

/* 344 bytes */
struct php_req_event {
	struct php_ev_hdr hdr;
	__u32 dropped_frames;
	__u32 emitted_spans;
	char  file[MAX_FILE_LEN];
	char  uri[MAX_URI_LEN];
	char  method[MAX_METHOD_LEN];
};

#endif /* __PHP_TRACER_H */
