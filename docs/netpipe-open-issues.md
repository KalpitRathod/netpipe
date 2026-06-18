# netpipe — Open Issues After v0.1.1 Bug-Fix Pass

This document lists every issue that remains open after the comprehensive
bug-fix pass completed in v0.1.1.  See `docs/Issues-Triage.md` in the
repository for the full historical triage; this file is a curated
"what's left to do" list.

**Closed in v0.1.1**: Issues #1, #2, #3, #4, #5, #7, #8, #11 (partial),
plus 30+ additional audit findings.

**Still open**: 11 issues from the original triage + 14 additional
findings from the v0.1.1 audit = **25 open issues** total.

---

## A. Open Issues from the Original `docs/Issues-Triage.md`

### Issue #6 — AF_PACKET Ring Captures Fail Unintuitively on Non-Linux OS
- **File**: `src/source/np_source_ring.c`
- **Tag**: `known-limitation`
- **Severity**: Low
- **Description**: `--ring` utilizes Linux-specific `AF_PACKET` + `PACKET_MMAP`.
  Compilation is guarded with `#ifdef __linux__`, but compiling or running
  this option on other POSIX systems (macOS, FreeBSD) fails ungracefully.
- **Fix**: Return a clean, descriptive error message at runtime on
  unsupported platforms, instead of compile-time `#ifdef` failure.

### Issue #9 — Packet Scratch Allocator Exhaustion on Complex Protocols
- **File**: `src/packet/np_packet.c` (Lines 94–103)
- **Tag**: `known-limitation`, `good-first-issue`
- **Severity**: Low
- **Description**: Each packet has a static `scratch[8192]` buffer for
  protocol-decoded data. Deep HTTP headers or large DNS responses can
  exhaust it. Current code logs a warning and returns NULL.
- **Fix**: Add heap-fallback when scratch is exhausted; document the
  threshold; add a stat counter for scratch-miss events.

### Issue #10 — Manual CLI Argument Parsing (full refactor)
- **File**: `src/main.c`
- **Tag**: `tech-debt`
- **Severity**: Low
- **Description**: The CLI parser is a hand-rolled `argv` loop with
  nested `strcmp` calls. v0.1.1 added input validation (`parse_int`,
  `parse_u64`, `parse_port`) but the structure remains fragile.
- **Fix**: Refactor to `getopt_long` with a table-driven option spec.

### Issue #12 — Buffer Pool Exhausts Under Burst Traffic
- **File**: `src/bufpool/np_bufpool.c`
- **Tag**: `known-limitation`, `help-wanted`
- **Severity**: Medium
- **Description**: The pool has a fixed size; under traffic bursts with
  slow downstream processing, the pool is exhausted and packets fall
  back to heap allocation (or are dropped if heap is also exhausted).
  v0.1.1 added a `pkts_dropped` counter but no dynamic expansion.
- **Fix**: Implement dynamic chunk expansion under stress, with
  periodic shrinking back to the configured base size.

### Issue #13 — TAP/TUN Sink Generic Error on Permission Denial
- **File**: `src/sink/np_sink.c` (Lines 826–855)
- **Tag**: `good-first-issue`
- **Severity**: Low
- **Description**: Creating a TAP/TUN interface requires `CAP_NET_ADMIN`.
  When run as a normal user, the failure is a generic socket error.
- **Fix**: Catch `EPERM` explicitly and emit a clear
  "Run as root or grant CAP_NET_ADMIN" message.

### Issue #14 — PCAP-NG Sink Missing Interface Name + Statistics
- **File**: `src/sink/np_sink.c` (Lines 1034–1085)
- **Tag**: `known-limitation`
- **Severity**: Low
- **Description**: The PCAP-NG writer emits the minimum SHB + IDB + EPB.
  It does not include the host interface name, capture OS, or Interface
  Statistics Blocks (ISB).
- **Fix**: Add IDB options (if_name, if_os) and a final ISB at close.

### Issue #15 — HTTP Parser Missing PATCH/DELETE/OPTIONS Methods
- **File**: `src/demux/np_demux.c` (Lines 450–490)
- **Tag**: `bug`, `good-first-issue`
- **Severity**: Medium
- **Description**: The HTTP app-layer parser only checks for `GET`,
  `POST`, `PUT`. `PATCH`, `DELETE`, `OPTIONS`, `HEAD`, `CONNECT`,
  `TRACE` are not recognized as HTTP methods.
- **Fix**: Expand the method dictionary.  Easy first PR.

### Issue #16 — TLS Handshake Heuristic False-Positive on Raw TCP
- **File**: `src/demux/np_demux.c` (Lines 500–530)
- **Tag**: `bug`, `tech-debt`
- **Severity**: Medium
- **Description**: The TLS protocol decoder accepts any TCP payload
  starting with `0x16` or `0x17` followed by version `0x03` as TLS.
  Random binary TCP traffic can match this and be misclassified.
- **Fix**: Add record-length bounds validation + deeper handshake-type
  checks for `ct == 22`.

### Issue #17 — Token Bucket Rate Limiter Drift Under Low-Bandwidth Caps
- **File**: `src/processor/np_processor.c` (Lines 200–230)
- **Tag**: `known-limitation`
- **Severity**: Low
- **Description**: The rate limiter uses `usleep` for pacing; OS
  scheduling jitter causes drift at low-bandwidth caps (< 1000 B/s).
- **Fix**: Switch to `nanosleep` or `timerfd` for high-resolution pacing.

### Issue #18 — Pipeline Capture Loop Parallelism (clarified)
- **File**: `src/pipeline/np_pipeline.c`
- **Tag**: `tech-debt`
- **Severity**: Low (largely addressed in v0.1.1)
- **Description**: v0.1.0 already had parallel capture workers; v0.1.1
  added the mixed-linktype guard.  Remaining work: the synchronized
  queue currently drops at 10,000 packets; consider a configurable
  high-watermark + backpressure signal to sources.

### Issue #11 — Logging Thread Synchronization (RESOLVED, partial)
- **File**: `src/log/np_log.c`
- **Tag**: `tech-debt`
- **Severity**: Resolved
- **Note**: The mutex around `vfprintf` was already present in v0.1.0;
  v0.1.1 added the level bounds check, `localtime_r` return check, and
  `pthread_once` ordering fix.  Listed for completeness.

---

## B. Additional Open Findings from v0.1.1 Audit

These were identified during the v0.1.1 deep audit but deliberately
deferred — they are either low-impact, require design decisions, or
fall outside the "stabilization" scope of Phase 1.

### B1 — `dns_read_name` reports success on truncation
- **File**: `src/demux/np_demux.c:280-312`
- **Tag**: `bug`
- **Severity**: Medium
- **Description**: The DNS name decoder exits the walk loop without
  setting a terminator if the name runs off the end of the buffer.
  Returns a positive offset (treated as success) and the caller
  continues parsing from a bogus offset.
- **Fix**: Track a `truncated` flag; return -1 on incomplete names.

### B2 — `decode_dns` increments `num_answers` before validation
- **File**: `src/demux/np_demux.c:348`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: `num_answers++` happens before any of the subsequent
  bounds checks. A parse failure mid-answer leaves a phantom empty
  entry counted.
- **Fix**: Defer the increment until after all validation.

### B3 — `decode_http` status-code integer overflow
- **File**: `src/demux/np_demux.c:503-506`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: A malformed response with a 20-digit "status code"
  overflows the `int` accumulator (UB).
- **Fix**: Cap the digit count or use `strtol`-style clamping.

### B4 — `looks_like_tls` accepts any payload for non-handshake types
- **File**: `src/demux/np_demux.c:423-447`
- **Tag**: `bug` (heuristic weakness)
- **Severity**: Low
- **Description**: For `ct == 20` (CCS), `21` (Alert), `23`
  (ApplicationData), no payload validation is done.  False-positive
  vector but not a memory-safety bug.
- **Fix**: Require zero-length payload for CCS; minimum length checks
  for Alert (2 bytes) and ApplicationData (16-byte tag).

### B5 — `looks_like_mqtt` accepts truncated variable-length integer
- **File**: `src/demux/np_proto_extra.c:126-140`
- **Tag**: `bug` (heuristic weakness)
- **Severity**: Low
- **Description**: If the buffer is exhausted before 4 bytes of the
  MQTT remaining-length field are consumed AND the last byte had the
  continuation bit set, the function still returns `true`.
- **Fix**: Return false if the loop exits due to `i >= len` with the
  continuation bit still set.

### B6 — VXLAN inner frame not re-decoded
- **File**: `src/demux/np_proto_extra.c:235-243`
- **Tag**: `known-limitation` (documented)
- **Severity**: Low
- **Description**: VXLAN is tagged but the inner Ethernet frame is
  not re-entered into the demuxer, so nested protocols are invisible.
- **Fix**: Recurse into the inner frame (with a depth cap to prevent
  infinite loops on maliciously-crafted nesting).

### B7 — `dir_insert_seg` signed-integer UB when `lead == INT32_MIN`
- **File**: `src/processor/np_tcp_stream.c:372, 542`
- **Tag**: `bug`
- **Severity**: Low (unreachable with current segment-size limits)
- **Description**: `uint32_t clip = (uint32_t)(-lead)` overflows when
  `lead == INT32_MIN`.  Requires a 2 GB gap between `seq` and
  `next_seq`, which is impossible for a valid TCP segment.
- **Fix**: Compute the clip in unsigned: `uint32_t clip = d->next_seq - seq;`

### B8 — `last_exposed_len` is dead code in `tcp_direction_t`
- **File**: `src/processor/np_tcp_stream.c:200, 738`
- **Tag**: `tech-debt`
- **Severity**: Low
- **Description**: The field is written but never read after the
  Bug-2 optimization was reverted.  Misleading for readers.
- **Fix**: Remove the field and the write, or implement the
  optimization properly.

### B9 — GC never evicts flows with stuck out-of-order queues
- **File**: `src/processor/np_tcp_stream.c:615-634`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: `ctx_gc` only evicts as "stalled" if `nsegs == 0`.
  A half-open connection that received out-of-order segments
  (filling the queue up to 256) and then vanished without FIN/RST
  is never evicted — a slow memory leak.
- **Fix**: Also evict if `age > TCP_FLOW_LINGER_MS * N` regardless
  of `nsegs`, or track last-drain-progress time.

### B10 — `np_packet_clone` does not copy scratch contents
- **File**: `src/packet/np_packet.c:39-106`
- **Tag**: `tech-debt` (documented)
- **Severity**: Low
- **Description**: The clone's `scratch_used` is 0 and `layers[i].decoded`
  is NULL. Any decoded protocol struct (HTTP msg, DNS msg) on the source
  is lost on clone.
- **Fix**: Deep-copy the scratch region and fix up `decoded` pointers,
  or document loudly that clones must re-run the decoder.

### B11 — `np_packet_flow_hash` is a no-op wrapper
- **File**: `src/packet/np_packet.c:232-235`
- **Tag**: `tech-debt`
- **Severity**: Low
- **Description**: Function name implies it computes a 5-tuple hash,
  but it just returns `pkt->flow_id` (precomputed by the demuxer).
  Callers expecting a fresh hash get the stale value.
- **Fix**: Rename to `np_packet_flow_id`, or actually compute a hash
  from the layers.

### B12 — `np_bufpool_stats` reads fields without atomic guarantees
- **File**: `src/bufpool/np_bufpool.c` (now locks; comment remains)
- **Tag**: `tech-debt`
- **Severity**: Low (already mitigated in v0.1.1)
- **Description**: v0.1.1 added a lock around the stats reads.  A
  cleaner long-term fix is to declare the counters `_Atomic` so
  stats reads can be lock-free.
- **Fix**: Migrate to `_Atomic uint64_t` counters.

### B13 — `keylog_load` silently creates a useless processor on `fopen` failure
- **File**: `src/processor/np_tls_decrypt.c:340-352, 1429-1431`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: If the keylog file can't be opened, the processor
  is still created with an empty keylog. Every subsequent record
  fails decryption with only debug-level logging — no way for the
  caller to know the processor is inert.
- **Fix**: Have `keylog_load` return int (count or -1); have
  `np_processor_tls_decrypt` return NULL on failure.

### B14 — `keylog_parse_line` truncates lines longer than 1023 chars
- **File**: `src/processor/np_tls_decrypt.c:345-349`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: `char line[1024]` + `fgets` splits over-long lines.
  A malformed keylog with a huge hex blob would be parsed as two
  fragments, both rejected, and the legitimate secret on the next
  line could be missed.
- **Fix**: Use `getline()` for dynamic line length, or detect the
  missing `\n` and skip the continuation.

### B15 — HKDF-Expand counter is `uint8_t`, no overflow guard
- **File**: `src/processor/np_tls_decrypt.c:410, 438`
- **Tag**: `bug`
- **Severity**: Low (unreachable with current TLS key sizes)
- **Description**: RFC 5869 §2.3 caps HKDF-Expand at 255 blocks.
  If `out_len > 255 * hash_size` the counter wraps to 0 and
  produces incorrect output.  Unreachable for TLS (max 32-byte keys)
  but no assertion exists.
- **Fix**: `if (counter == 255) return false;` before `counter++`.

### B16 — `tls12_prf` casts `secret_len` to `int` without range check
- **File**: `src/processor/np_tls_decrypt.c:660, 668, 684`
- **Tag**: `bug`
- **Severity**: Low (unreachable for 48-byte TLS master secret)
- **Description**: `(int)secret_len` — if `secret_len > INT_MAX`,
  HMAC gets a negative length and fails.  Not currently reachable.
- **Fix**: `if (secret_len > INT_MAX) return false;` at entry.

### B17 — TLS 1.3 inner content-type strip range too narrow
- **File**: `src/processor/np_tls_decrypt.c:1354-1358`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: Only accepts inner types 20–23 (CCS, Alert,
  Handshake, ApplicationData).  TLS 1.3 also permits type 24
  (heartbeat, RFC 9266) and 26 (ack). For those, the trailing
  type byte is left in the plaintext, corrupting downstream by
  one byte per record.
- **Fix**: Use `if (inner_type >= 20 && inner_type <= 26)` or
  strip any non-zero byte.

### B18 — `tls_process` overwrites layer `data` but leaves `proto = NP_PROTO_TLS`
- **File**: `src/processor/np_tls_decrypt.c:1393-1399`
- **Tag**: `tech-debt`
- **Severity**: Low
- **Description**: After successful decryption, the app layer's
  `data`/`len` are repointed to the plaintext heap buffer, but
  `layers[i].proto` remains `NP_PROTO_TLS`. Downstream parsers
  dispatching on `proto` will treat plaintext HTTP/2 bytes as TLS.
- **Fix**: Set `pkt->layers[i].proto = NP_PROTO_HTTP` (or whatever
  the decrypted inner protocol is) when recognized, or document
  that downstream must check `stream_len > 0` rather than `proto`.

### B19 — `accumulated_len + pt_len` realloc size not checked for overflow
- **File**: `src/processor/np_tls_decrypt.c:1366`
- **Tag**: `bug`
- **Severity**: Low (impractical to reach)
- **Description**: `realloc(accumulated, accumulated_len + pt_len)`.
  Both are `size_t`; would need ~2^50 records in one packet to
  overflow.  Not reachable, but the pattern is unsafe in general.
- **Fix**: `if (accumulated_len > SIZE_MAX - pt_len) { free(plaintext); return NP_ERR_NOMEM; }`

### B20 — `queue_pop` timeout not monotonic
- **File**: `src/pipeline/np_pipeline.c:162-174`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: Each loop iteration recomputes `ts = now + timeout_ms`,
  so under repeated spurious wakeups the effective wait is unbounded.
- **Fix**: Compute the absolute deadline once outside the loop.

### B21 — `np_processor.c` integer overflow in `hex_encode` / `base64_encode`
- **File**: `src/processor/np_processor.c:176, 191`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: `size_t len = in_len * 2;` and `size_t len = 4 * ((in_len + 2) / 3);`
  overflow on 32-bit if `in_len` is near `SIZE_MAX`.  Bounded by
  `pkt->caplen` (uint32_t) in practice.
- **Fix**: `if (in_len > (SIZE_MAX - 1) / 2) return;`

### B22 — `np_processor.c` `rate_process` busy-spins at very low rates
- **File**: `src/processor/np_processor.c:104-110`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: If `needed` is tiny and `bytes_per_sec` is huge,
  `wait_s ≈ 0` and `ts.tv_nsec = 1000` (1µs).  The loop sleeps 1µs,
  re-checks, sleeps again — high CPU.
- **Fix**: Enforce a minimum sleep of 100µs or yield.

### B23 — `np_processor.c` `regex_replace_payload` limited to 9 capture groups
- **File**: `src/processor/np_processor.c:248, 250`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: `regmatch_t pmatch[10]` and `regexec(... 10, pmatch, 0)`
  silently fails for regexes with > 9 capture groups.
- **Fix**: Document the limit, or dynamically size `pmatch` from
  `re.re_nsub + 1`.

### B24 — `np_sink.c` `tuntap_sink_open` doesn't validate `p->dev` length
- **File**: `src/sink/np_sink.c:762`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: `strcpy(p->dev, ifr.ifr_name)` — `ifr.ifr_name` is
  `IFNAMSIZ` (16) bytes, `p->dev` is `IFNAMSIZ` bytes.  Safe in current
  code, but `strncpy` would be more defensive.
- **Fix**: Use `snprintf(p->dev, sizeof(p->dev), "%s", ifr.ifr_name)`.

### B25 — `np_sink.c` open functions don't validate `path` is non-NULL
- **File**: `src/sink/np_sink.c:108, 263, 313, 435, 1297`
- **Tag**: `bug`
- **Severity**: Low
- **Description**: `snprintf(p->path, sizeof(p->path), "%s", path)`
  with `path == NULL` is UB.  `np_sink_hex` and `np_sink_stats` already
  handle NULL; `np_sink_pcap`, `np_sink_json`, `np_sink_pcapng` don't.
- **Fix**: Add `if (!path) return NULL;` at the top of each constructor.

---

## Summary by Severity

| Severity | Count | Examples |
|----------|-------|----------|
| **Medium** | 4 | #15 (HTTP methods), #16 (TLS heuristic), #12 (pool exhaustion), B1 (DNS truncation) |
| **Low** | 19 | Most others — defense-in-depth, edge cases, hardening |
| **Tech-debt** | 5 | #10 (CLI refactor), #18 (queue backpressure), B8 (dead code), B11 (rename), B12 (atomics) |
| **Known-limitation** | 4 | #6 (non-Linux ring), #9 (scratch), #14 (PCAP-NG metadata), B6 (VXLAN recursion) |
| **Good-first-issue** | 3 | #9, #13, #15 — easy wins for new contributors |

## Suggested Triage Order

1. **Quick wins** (good-first-issues): #15 (HTTP methods), #13 (TAP/TUN EPERM), B25 (NULL path)
2. **Memory-safety sweep**: B1 (DNS truncation), B7 (TCP seq UB), B19 (realloc overflow), B21 (hex encode overflow)
3. **Hardening**: #16 (TLS heuristic), B4 (TLS payload validation), B5 (MQTT), B17 (TLS 1.3 inner type)
4. **Tech-debt cleanup**: #10 (getopt_long), B8 (dead code), B11 (rename), B12 (atomics)
5. **Feature gaps**: B6 (VXLAN recursion), #14 (PCAP-NG metadata), #6 (non-Linux ring)
6. **Performance**: #17 (rate limiter), #12 (pool expansion), B22 (busy-spin), B20 (queue timeout)
