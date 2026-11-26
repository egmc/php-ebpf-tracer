// SPDX-License-Identifier: GPL-2.0
/*
 * php_tracer.bpf.c -- USDT based auto-instrumentation for PHP.
 *
 * Attaches to the DTrace/USDT markers that php is compiled with when built
 * using --enable-dtrace (see Zend/zend_dtrace.d in php-src):
 *
 *   php:request__startup(char *request_file, char *request_uri, char *request_method)
 *   php:request__shutdown(char *request_file, char *request_uri, char *request_method)
 *   php:function__entry(char *function_name, char *request_file, int lineno,
 *                       char *classname, char *scope)
 *   php:function__return(char *function_name, char *request_file, int lineno,
 *                        char *classname, char *scope)
 *
 * A per-(tgid,tid) shadow stack turns the entry/return pairs into finished
 * spans, so userspace only ever sees completed spans with both timestamps.
 * Only the return probe pushes to the ring buffer, which halves the number of
 * records compared to forwarding raw entry/return events.
 *
 * No CO-RE relocations are used, so this object loads on kernels without BTF.
 */
#include <stdbool.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

#include "php_tracer.h"

char LICENSE[] SEC("license") = "GPL";

/* Index into php_req_state.frames. The barrier keeps clang from dropping the
 * mask: after a `d >= MAX_STACK_DEPTH` check it knows the mask is a no-op and
 * clang 21 then derives d - 1 from a register whose bounds the verifier has
 * lost, which the verifier rejects as an unbounded map access. */
static __always_inline __u32 frame_idx(__u32 d)
{
	barrier_var(d);
	return d & (MAX_STACK_DEPTH - 1);
}

/*
 * Configuration, populated from Go via Module.InitGlobalVariable() before the
 * object is loaded.
 */
const volatile __u32 targ_pid        = 0; /* 0 = every process */
const volatile __u32 max_depth       = 32; /* only emit spans shallower than this */
const volatile __u64 min_func_ns     = 0; /* drop function spans faster than this */
const volatile __u8  trace_functions = 1; /* 0 = request spans only */

/* Include paths, see MAX_INCLUDE_PATHS. Only the first n_include_paths slots
 * are used; 0 means every file is traced. */
const volatile __u32 n_include_paths = 0;
const volatile char  include_paths[MAX_INCLUDE_PATHS][MAX_FILE_LEN] = {};

struct php_frame {
	__u64 start_ns; /* 0 == frame is not reported as a span */
	/* The frame's own span when it is reported, otherwise the span of its
	 * nearest reported ancestor (or the root), so callees always find the
	 * right parent in frames[d-1]. */
	__u64 span_id;
};

struct php_req_state {
	__u64 start_ns;
	__u64 trace_id_hi;
	__u64 trace_id_lo;
	__u64 root_span_id;
	__u32 depth;   /* current call depth, may exceed MAX_STACK_DEPTH */
	__u32 dropped; /* frames/records lost for this request */
	__u32 emitted;
	__u8  flags;
	__u8  pad[7];
	struct php_frame frames[MAX_STACK_DEPTH];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);   /* bpf_get_current_pid_tgid() */
	__type(value, struct php_req_state);
} requests SEC(".maps");

/* struct php_req_state is far too large for the 512 byte BPF stack, so new
 * entries are staged in a per-CPU scratch slot before being inserted. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct php_req_state);
} state_scratch SEC(".maps");

static __always_inline __u64 rand_u64(void)
{
	__u64 hi = bpf_get_prandom_u32();
	__u64 lo = bpf_get_prandom_u32();

	return (hi << 32) | lo;
}

/* USDT arguments are char* into the traced process' address space. */
#define READ_USTR(dst, uptr)                                                   \
	do {                                                                   \
		(dst)[0] = '\0';                                               \
		if (uptr)                                                      \
			bpf_probe_read_user_str((dst), sizeof(dst),            \
						(const void *)(unsigned long)(uptr)); \
	} while (0)

/* Reports whether s starts with pat. pat is NUL padded, or unterminated when
 * it fills all len bytes. Stops at the first mismatch, so the bytes of s past
 * its own terminator are never compared against a live pattern byte. */
static __always_inline bool has_prefix(const char *s, const volatile char *pat,
				       int len)
{
	for (int i = 0; i < len; i++) {
		char c = pat[i];

		if (!c)
			return true;
		if (s[i] != c)
			return false;
	}

	return true;
}

/* Reports whether func is "main", the name PHP gives to the top-level code of
 * a script. Besides the entry script, which the request span already covers,
 * that is every include/require, which in practice is mostly class files
 * pulled in by the autoloader. */
static __always_inline bool is_main(long func)
{
	/* One byte longer than "main" + NUL, so a longer name that the read
	 * truncates to "main" does not also return 5. */
	char name[6];

	if (!func ||
	    bpf_probe_read_user_str(name, sizeof(name),
				    (const void *)(unsigned long)func) != 5)
		return false;

	return name[0] == 'm' && name[1] == 'a' && name[2] == 'i' && name[3] == 'n';
}

/* Reports whether a function defined in file should produce a span. */
static __always_inline bool path_included(long file)
{
	char path[MAX_FILE_LEN];

	if (!n_include_paths)
		return true;
	if (!file ||
	    bpf_probe_read_user_str(path, sizeof(path),
				    (const void *)(unsigned long)file) <= 1)
		return false;

	for (__u32 r = 0; r < MAX_INCLUDE_PATHS && r < n_include_paths; r++)
		if (has_prefix(path, include_paths[r], MAX_FILE_LEN))
			return true;

	return false;
}

static __always_inline void fill_hdr(struct php_ev_hdr *h, __u8 type, __u64 id,
				     const struct php_req_state *st)
{
	h->type = type;
	h->flags = st->flags;
	h->pad0 = 0;
	h->pid = id >> 32;
	h->tid = (__u32)id;
	h->pad1 = 0;
	h->trace_id_hi = st->trace_id_hi;
	h->trace_id_lo = st->trace_id_lo;
}

SEC("usdt")
int BPF_USDT(usdt_request_startup, long file, long uri, long method)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 zero = 0;
	struct php_req_state *st;
	struct php_req_event *e;

	if (targ_pid && tgid != targ_pid)
		return 0;

	st = bpf_map_lookup_elem(&state_scratch, &zero);
	if (!st)
		return 0;

	/* frames[] is left as-is: depth == 0 means nothing in it is live. */
	st->start_ns = bpf_ktime_get_ns();
	st->trace_id_hi = rand_u64();
	st->trace_id_lo = rand_u64();
	st->root_span_id = rand_u64();
	st->depth = 0;
	st->dropped = 0;
	st->emitted = 0;
	st->flags = 0;

	if (bpf_map_update_elem(&requests, &id, st, BPF_ANY))
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_hdr(&e->hdr, PHP_EV_REQ_START, id, st);
	e->hdr.ts_start = st->start_ns;
	e->hdr.ts_end = 0;
	e->hdr.span_id = st->root_span_id;
	e->hdr.parent_span_id = 0;
	e->dropped_frames = 0;
	e->emitted_spans = 0;
	READ_USTR(e->file, file);
	READ_USTR(e->uri, uri);
	READ_USTR(e->method, method);
	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("usdt")
int BPF_USDT(usdt_request_shutdown, long file, long uri, long method)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 now = bpf_ktime_get_ns();
	struct php_req_state *st;
	struct php_req_event *e;

	st = bpf_map_lookup_elem(&requests, &id);
	if (!st)
		return 0;

	/* Frames still open at shutdown mean php bailed out (zend_bailout /
	 * fatal error) and the matching function__return markers never fired.
	 * Their children were already emitted and become orphans that the
	 * aggregator re-parents onto the root span. */
	if (st->depth)
		st->flags |= PHP_EV_F_TRUNCATED;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		fill_hdr(&e->hdr, PHP_EV_REQ_END, id, st);
		e->hdr.ts_start = st->start_ns;
		e->hdr.ts_end = now;
		e->hdr.span_id = st->root_span_id;
		e->hdr.parent_span_id = 0;
		e->dropped_frames = st->dropped + st->depth;
		e->emitted_spans = st->emitted;
		READ_USTR(e->file, file);
		READ_USTR(e->uri, uri);
		READ_USTR(e->method, method);
		bpf_ringbuf_submit(e, 0);
	}

	bpf_map_delete_elem(&requests, &id);

	return 0;
}

SEC("usdt")
int BPF_USDT(usdt_function_entry, long func_name, long req_file, long lineno,
	     long classname, long scope)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct php_req_state *st;
	struct php_frame *f;
	__u32 d;

	if (!trace_functions)
		return 0;

	st = bpf_map_lookup_elem(&requests, &id);
	if (!st)
		return 0;

	d = st->depth;
	st->depth = d + 1;

	if (d >= MAX_STACK_DEPTH) {
		/* Too deep to track; the matching return decrements depth back
		 * into range so the shadow stack stays aligned. */
		st->dropped++;
		st->flags |= PHP_EV_F_TRUNCATED;
		return 0;
	}

	f = &st->frames[frame_idx(d)];
	f->start_ns = 0;
	if (d >= max_depth)
		return 0;

	/* is_main first: it reads 6 bytes, path_included up to 128. */
	if (is_main(func_name) || !path_included(req_file)) {
		/* Not reported: callees attach to the nearest reported ancestor. */
		f->span_id = st->root_span_id;
		if (d > 0)
			f->span_id = st->frames[frame_idx(d - 1)].span_id;
		return 0;
	}

	f->span_id = rand_u64();
	/* Taken last so the matching above is not billed to the span. */
	f->start_ns = bpf_ktime_get_ns();

	return 0;
}

SEC("usdt")
int BPF_USDT(usdt_function_return, long func_name, long req_file, long lineno,
	     long classname, long scope)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 now = bpf_ktime_get_ns();
	struct php_req_state *st;
	struct php_func_event *e;
	struct php_frame *f;
	__u64 parent;
	__u32 d;

	if (!trace_functions)
		return 0;

	st = bpf_map_lookup_elem(&requests, &id);
	if (!st)
		return 0;

	d = st->depth;
	if (d == 0)
		return 0; /* unbalanced return, e.g. probes enabled mid-call */
	d--;
	st->depth = d;

	if (d >= MAX_STACK_DEPTH)
		return 0; /* frame was never recorded */

	f = &st->frames[frame_idx(d)];
	if (!f->start_ns)
		return 0; /* deeper than max_depth, main or outside the include paths */

	if (min_func_ns && now - f->start_ns < min_func_ns) {
		/* Cheap volume control. Any children already emitted lose
		 * their parent and get re-parented onto the root span. */
		return 0;
	}

	parent = st->root_span_id;
	if (d > 0)
		parent = st->frames[frame_idx(d - 1)].span_id;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		st->dropped++;
		st->flags |= PHP_EV_F_TRUNCATED;
		return 0;
	}

	fill_hdr(&e->hdr, PHP_EV_FUNC, id, st);
	e->hdr.ts_start = f->start_ns;
	e->hdr.ts_end = now;
	e->hdr.span_id = f->span_id;
	e->hdr.parent_span_id = parent;
	e->lineno = (__s32)lineno;
	e->depth = d;
	READ_USTR(e->func, func_name);
	READ_USTR(e->cls, classname);
	READ_USTR(e->file, req_file);
	st->emitted++;
	bpf_ringbuf_submit(e, 0);

	return 0;
}

/*
 * MySQL queries, from uprobes on mysqlnd. mysqlnd has no USDT markers and is
 * usually stripped, but it exports its method tables, so userspace resolves the
 * functions below from those tables and attaches to their file offsets:
 *
 *   conn_data::query(conn, const char *query, size_t len)
 *       mysqli_query, PDO::query/exec and emulated prepares. Returns once the
 *       result header has been read.
 *   command::stmt_prepare(conn, MYSQLND_CSTRING query)
 *   command::stmt_execute(conn, MYSQLND_CSTRING payload)
 *       Native prepared statements. Both only send the command; the payload of
 *       COM_STMT_EXECUTE starts with the 4 byte statement id.
 *   conn_data::query_read_result_set_header(conn, stmt)
 *       Reads the response, so its return ends an execute.
 *
 * A MYSQLND_CSTRING is a 16 byte struct and is passed in the second and third
 * argument registers on x86_64 and arm64.
 */

/* Query in flight on a thread, from the entry probe to the one that ends it. */
struct php_query_pending {
	__u64 start_ns;
	__u64 span_id;
	__u64 parent_span_id;
	__u64 conn;
	__u64 query; /* user pointer, read when the query ends */
	__u32 query_len;
	__u32 stmt_id;
	__u32 depth;
	__u8  kind;
	__u8  pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64); /* bpf_get_current_pid_tgid() */
	__type(value, struct php_query_pending);
} queries SEC(".maps");

/* Returns the span a query issued now hangs under: the innermost frame on the
 * shadow stack. Frames below max_depth always carry a valid span_id, their own
 * or their nearest reported ancestor's; deeper ones are never written. */
static __always_inline __u64 current_parent(const struct php_req_state *st)
{
	__u32 d = st->depth;

	if (d > max_depth)
		d = max_depth;
	if (d > MAX_STACK_DEPTH)
		d = MAX_STACK_DEPTH;
	if (d == 0)
		return st->root_span_id;

	return st->frames[frame_idx(d - 1)].span_id;
}

/* Copies up to MAX_QUERY_LEN - 1 bytes of SQL. The text is length delimited,
 * not NUL terminated, so this cannot use bpf_probe_read_user_str. */
static __always_inline void read_query(char *dst, __u64 src, __u32 len)
{
	__u32 n = len;

	dst[0] = '\0';
	if (!src || !len)
		return;
	if (n > MAX_QUERY_LEN - 1)
		n = MAX_QUERY_LEN - 1;
	barrier_var(n);
	n &= MAX_QUERY_LEN - 1;
	if (bpf_probe_read_user(dst, n, (const void *)(unsigned long)src))
		n = 0;
	dst[n] = '\0';
}

static __always_inline void fill_query(struct php_query_event *e, __u64 id,
				       const struct php_req_state *st, __u8 kind)
{
	fill_hdr(&e->hdr, PHP_EV_QUERY, id, st);
	e->kind = kind;
	e->failed = 0;
	e->pad0 = 0;
	e->stmt_id = 0;
	e->query_len = 0;
	e->depth = st->depth;
	e->conn = 0;
}

static __always_inline int query_begin(__u8 kind, __u64 conn, __u64 query,
				       __u64 len, __u32 stmt_id)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct php_query_pending p = {};
	struct php_req_state *st;

	st = bpf_map_lookup_elem(&requests, &id);
	if (!st)
		return 0; /* not inside a traced request */

	p.span_id = rand_u64();
	p.parent_span_id = current_parent(st);
	p.conn = conn;
	p.query = query;
	p.query_len = len > 0xffffffff ? 0xffffffff : (__u32)len;
	p.stmt_id = stmt_id;
	p.depth = st->depth;
	p.kind = kind;
	p.start_ns = bpf_ktime_get_ns();
	bpf_map_update_elem(&queries, &id, &p, BPF_ANY);

	return 0;
}

/* Ends the query in flight on this thread if it is of the given kind. */
static __always_inline int query_end(__u8 kind, bool failed)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 now = bpf_ktime_get_ns();
	struct php_query_pending *p;
	struct php_query_event *e;
	struct php_req_state *st;

	p = bpf_map_lookup_elem(&queries, &id);
	if (!p || p->kind != kind)
		return 0;

	st = bpf_map_lookup_elem(&requests, &id);
	if (!st)
		goto out;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		st->dropped++;
		st->flags |= PHP_EV_F_TRUNCATED;
		goto out;
	}

	fill_query(e, id, st, kind);
	e->hdr.ts_start = p->start_ns;
	e->hdr.ts_end = now;
	e->hdr.span_id = p->span_id;
	e->hdr.parent_span_id = p->parent_span_id;
	e->failed = failed;
	e->stmt_id = p->stmt_id;
	e->query_len = p->query_len;
	e->depth = p->depth;
	e->conn = p->conn;
	/* Still valid: the caller owns the buffer until the call returns. */
	read_query(e->query, p->query, p->query_len);
	st->emitted++;
	bpf_ringbuf_submit(e, 0);

out:
	bpf_map_delete_elem(&queries, &id);

	return 0;
}

SEC("uprobe")
int BPF_UPROBE(uprobe_conn_query, void *conn, const char *query, __u64 len)
{
	return query_begin(PHP_Q_QUERY, (__u64)conn, (__u64)query, len, 0);
}

SEC("uretprobe")
int BPF_URETPROBE(uretprobe_conn_query, long ret)
{
	return query_end(PHP_Q_QUERY, ret != 0);
}

SEC("uprobe")
int BPF_UPROBE(uprobe_stmt_prepare, void *conn, const char *query, __u64 len)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct php_query_event *e;
	struct php_req_state *st;

	st = bpf_map_lookup_elem(&requests, &id);
	if (!st)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		st->dropped++;
		st->flags |= PHP_EV_F_TRUNCATED;
		return 0;
	}

	fill_query(e, id, st, PHP_Q_PREPARE);
	e->hdr.ts_start = bpf_ktime_get_ns();
	e->hdr.ts_end = e->hdr.ts_start;
	e->hdr.span_id = 0;
	e->hdr.parent_span_id = 0;
	e->query_len = len > 0xffffffff ? 0xffffffff : (__u32)len;
	e->conn = (__u64)conn;
	read_query(e->query, (__u64)query, e->query_len);
	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("uprobe")
int BPF_UPROBE(uprobe_stmt_execute, void *conn, const void *payload, __u64 len)
{
	__u32 stmt_id = 0;

	if (payload && len >= sizeof(stmt_id))
		bpf_probe_read_user(&stmt_id, sizeof(stmt_id), payload);

	return query_begin(PHP_Q_EXECUTE, (__u64)conn, 0, 0, stmt_id);
}

/* Sending failed: no response will be read for this execute. */
SEC("uretprobe")
int BPF_URETPROBE(uretprobe_stmt_execute, long ret)
{
	if (ret == 0)
		return 0;

	return query_end(PHP_Q_EXECUTE, true);
}

SEC("uretprobe")
int BPF_URETPROBE(uretprobe_read_result_header, long ret)
{
	return query_end(PHP_Q_EXECUTE, ret != 0);
}
