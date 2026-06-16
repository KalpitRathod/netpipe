# Codebase Issues Triage & Backlog

This document tracks known bugs, architectural gaps, technical debt, and design limitations across the netpipe codebase. It serves as a backlog for contributors seeking good starting points or deep-dive improvements.

---

## Index of Issues

| # | Issue Title | Target File(s) | Primary Tag |
|---|-------------|----------------|-------------|
| 1 | [TCP Stream Reassembly Lacks Out-of-Order Segment Buffering](#1-tcp-stream-reassembly-lacks-out-of-order-segment-buffering) | `src/processor/np_tcp_stream.c` | `known-limitation` |
| 2 | [VLAN Tag (802.1Q / 802.1AD) Parsing Support is Missing](#2-vlan-tag-8021q--8021ad-parsing-support-is-missing) | `src/demux/np_demux.c` | `bug` |
| 3 | [IPv6 Extension Headers are Skipped During Demuxing](#3-ipv6-extension-headers-are-skipped-during-demuxing) | `src/demux/np_demux.c` | `bug` |
| 4 | [Global registry has no thread safety locks](#4-global-registry-has-no-thread-safety-locks) | `src/registry/np_registry.c` | `tech-debt` |
| 5 | [Flow Tracker Lacks Connection Expiration & Memory Reclamation](#5-flow-tracker-lacks-connection-expiration--memory-reclamation) | `src/processor/np_flow_tracker.c` | `bug` |
| 6 | [Zero-Copy AF_PACKET Ring Captures Fail Unintuitively on Non-Linux OS](#6-zero-copy-af_packet-ring-captures-fail-unintuitively-on-non-linux-os) | `src/source/np_source_ring.c` | `known-limitation` |
| 7 | [Socket Sink Lacks Reconnection Logic and Buffer Failover](#7-socket-sink-lacks-reconnection-logic-and-buffer-failover) | `src/sink/np_sink.c` | `tech-debt` |
| 8 | [Lua Processor Does Not Enforce Memory Limits on Script Runtime](#8-lua-processor-does-not-enforce-memory-limits-on-script-runtime) | `src/processor/np_lua.c` | `tech-debt` |
| 9 | [Exhaustion of Packet Scratch Allocator on Complex Protocols](#9-exhaustion-of-packet-scratch-allocator-on-complex-protocols) | `src/packet/np_packet.c` | `known-limitation` |
| 10| [Manual CLI Argument Parsing is Fragile and Monolithic](#10-manual-cli-argument-parsing-is-fragile-and-monolithic) | `src/main.c` | `tech-debt` |
| 11| [Logging Output lacks thread synchronization](#11-logging-output-lacks-thread-synchronization) | `src/log/np_log.c` | `tech-debt` |
| 12| [Pre-allocated Buffer Pool Exhausts Under Burst Traffic](#12-pre-allocated-buffer-pool-exhausts-under-burst-traffic) | `src/bufpool/np_bufpool.c` | `known-limitation` |
| 13| [TAP/TUN Sink fails with generic error when lacking permissions](#13-taptun-sink-fails-with-generic-error-when-lacking-permissions) | `src/sink/np_sink.c` | `good-first-issue` |
| 14| [Native PCAP-NG Sink does not write Interface Name or Statistics](#14-native-pcap-ng-sink-does-not-write-interface-name-or-statistics) | `src/sink/np_sink.c` | `known-limitation` |
| 15| [HTTP Parser misses standard PATCH/DELETE/OPTIONS methods](#15-http-parser-misses-standard-patchdeleteoptions-methods) | `src/demux/np_demux.c` | `bug` |
| 16| [TLS Handshake record heuristic can false-positive on TCP streams](#16-tls-handshake-record-heuristic-can-false-positive-on-tcp-streams) | `src/demux/np_demux.c` | `bug` |
| 17| [Token Bucket Rate Limiter accuracy drifts under low-bandwidth caps](#17-token-bucket-rate-limiter-accuracy-drifts-under-low-bandwidth-caps) | `src/processor/np_processor.c` | `known-limitation` |
| 18| [Pipeline runs capture loops sequentially rather than in parallel](#18-pipeline-runs-capture-loops-sequentially-rather-than-in-parallel) | `src/pipeline/np_pipeline.c` | `tech-debt` |

---

## Detailed Issues Backlog

### 1. TCP Stream Reassembly Lacks Out-of-Order Segment Buffering
* **File**: `src/processor/np_tcp_stream.c`
* **Tags**: `known-limitation`, `help-wanted`
* **Description**:
  The current TCP stream reassembly engine expects segments to arrive sequentially. If TCP segments arrive out of order, or if there is packet loss forcing retransmission, the reassembly logic fails to correctly merge the payload. We need to implement an interval-tree buffer or sorted sequence list to track gaps, handle overlapping segments, and reassemble out-of-order data before passing it to the application layer.

---

### 2. VLAN Tag (802.1Q / 802.1AD) Parsing Support is Missing
* **File**: `src/demux/np_demux.c`
* **Tags**: `bug`, `good-first-issue`
* **Description**:
  When processing traffic containing VLAN tags (EtherType `0x8100` or `0x88a8`), the protocol demuxer fails to offset the payload correctly. It tries to parse the VLAN header as an IP header, leading to corrupted parsing and dropped packets. We need to parse VLAN tags, extract the inner EtherType, and offset the protocol demux start index by 4 bytes per tag.

---

### 3. IPv6 Extension Headers are Skipped During Demuxing
* **File**: `src/demux/np_demux.c`
* **Tags**: `bug`, `known-limitation`
* **Description**:
  The IPv6 demuxer assumes the `Next Header` field points directly to a L4 protocol (like TCP or UDP). If the packet contains IPv6 extension headers (e.g., Hop-by-Hop options, Routing, Fragment, or Destination options), the demuxer fails. The demuxer should loop through known extension headers to find the actual L4 payload.

---

### 4. Global registry has no thread safety locks
* **File**: `src/registry/np_registry.c`
* **Tags**: `tech-debt`
* **Description**:
  Sinks, sources, and processors register themselves globally via constructors at startup. While this is currently static, future extensions could support runtime loading/unloading of plugins (such as shared libraries). The registry requires a read-write lock (`pthread_rwlock_t`) to prevent race conditions during concurrent plugin loading/unloading.

---

### 5. Flow Tracker Lacks Connection Expiration & Memory Reclamation
* **File**: `src/processor/np_flow_tracker.c`
* **Tags**: `bug`, `tech-debt`
* **Description**:
  The flow-tracker maintains per-5-tuple TCP/UDP/IP states in a hash map. However, closed or inactive connections are never expired or purged. On long captures, this causes indefinite memory growth (memory leak). We need to implement an idle timeout check to prune inactive flows from the hash table.

---

### 6. Zero-Copy AF_PACKET Ring Captures Fail Unintuitively on Non-Linux OS
* **File**: `src/source/np_source_ring.c`
* **Tags**: `known-limitation`
* **Description**:
  `--ring` utilizes Linux-specific zero-copy constructs (`AF_PACKET` + `PACKET_MMAP`). While compilation is guarded with `#ifdef __linux__`, compiling or running this option on other POSIX systems (like macOS or FreeBSD) fails ungracefully. We need to return a clean, descriptive error message at runtime on unsupported platforms.

---

### 7. Socket Sink Lacks Reconnection Logic and Buffer Failover
* **File**: `src/sink/np_sink.c` (Lines 939–968)
* **Tags**: `tech-debt`, `help-wanted`
* **Description**:
  If the remote socket listener disconnects while the socket sink is running, the write returns `NP_ERR_IO` and the pipeline terminates. The sink needs an auto-reconnect strategy (e.g., exponential backoff) and a small ring buffer to queue packets locally during brief network drops.

---

### 8. Lua Processor Does Not Enforce Memory Limits on Script Runtime
* **File**: `src/processor/np_lua.c`
* **Tags**: `tech-debt`
* **Description**:
  When executing user Lua scripts on every packet, memory allocations made inside the Lua VM can grow unbounded if the script contains leaks. We should use `lua_setallocf` to set a hard memory limit on the Lua state to prevent script bugs from crashing the main netpipe process.

---

### 9. Exhaustion of Packet Scratch Allocator on Complex Protocols
* **File**: `src/packet/np_packet.c` (Lines 94–103)
* **Tags**: `known-limitation`, `good-first-issue`
* **Description**:
  Each packet has a static scratchpad array (`scratch[2048]`) to allocate protocol-decoded data. For packets with extremely large application-layer payloads (e.g., deep HTTP headers or DNS records), the scratchpad can be exhausted. We need to handle allocation failures gracefully by logging a warning and falling back to temporary heap allocations if required.

---

### 10. Manual CLI Argument Parsing is Fragile and Monolithic
* **File**: `src/main.c` (Lines 290–390)
* **Tags**: `tech-debt`
* **Description**:
  The command-line parser manually loops through `argv` using nested `strcmp` calls. This makes adding new options complex and error-prone. The CLI parsing logic should be refactored into a structured table-driven parser or use `getopt_long`.

---

### 11. Logging Output lacks thread synchronization
* **File**: `src/log/np_log.c`
* **Tags**: `tech-debt`, `good-first-issue`
* **Description**:
  The logger writes messages directly to `stdout`/`stderr`. When running a multi-threaded pipeline, logging calls from different worker threads can interleave and garble the output. We should add a mutex around `vfprintf` calls in the logger implementation to synchronize writes.

---

### 12. Pre-allocated Buffer Pool Exhausts Under Burst Traffic
* **File**: `src/bufpool/np_bufpool.c`
* **Tags**: `known-limitation`, `help-wanted`
* **Description**:
  The zero-allocation `np_bufpool_t` maintains a fixed number of packet buffers. If the processing pipeline slows down during traffic bursts, the buffer pool is exhausted, leading to packet drops. We should implement a dynamic expansion mechanism where the pool can allocate additional chunks under stress, then scale back down.

---

### 13. TAP/TUN Sink fails with generic error when lacking permissions
* **File**: `src/sink/np_sink.c` (Lines 826–855)
* **Tags**: `good-first-issue`
* **Description**:
  Creating a virtual TAP/TUN interface requires administrative privileges (`CAP_NET_ADMIN` or root). When run as a normal user, the interface creation fails with a generic socket error. We should catch `EPERM` or check permissions at startup to give the user a clear error message.

---

### 14. Native PCAP-NG Sink does not write Interface Name or Statistics
* **File**: `src/sink/np_sink.c` (Lines 1034–1085)
* **Tags**: `known-limitation`
* **Description**:
  The native PCAP-NG writer writes the minimum required Section Header Block (SHB) and Interface Description Block (IDB). It does not include optional metadata like the host interface name, capture OS, or packet drop statistics in Interface Statistics Blocks (ISB).

---

### 15. HTTP Parser misses standard PATCH/DELETE/OPTIONS methods
* **File**: `src/demux/np_demux.c` (Lines 450–490)
* **Tags**: `bug`, `good-first-issue`
* **Description**:
  The app-layer HTTP parser uses basic string matches to check if a TCP payload starts with standard methods. It only checks for `GET`, `POST`, `PUT`. If it encounters `PATCH`, `DELETE`, or `OPTIONS`, it fails to identify the packet as HTTP. We should expand the method dictionary.

---

### 16. TLS Handshake record heuristic can false-positive on TCP streams
* **File**: `src/demux/np_demux.c` (Lines 500–530)
* **Tags**: `bug`, `tech-debt`
* **Description**:
  The TLS protocol decoder checks for a ContentType of `0x16` (Handshake) or `0x17` (Application Data) followed by version `0x03` at the beginning of the TCP payload. On raw TCP streams transmitting matching random bytes, this results in false-positive TLS decoding. We should add additional validation (like checking record length bounds).

---

### 17. Token Bucket Rate Limiter accuracy drifts under low-bandwidth caps
* **File**: `src/processor/np_processor.c` (Lines 200–230)
* **Tags**: `known-limitation`
* **Description**:
  The token bucket rate limiter uses standard microsecond sleeps (`usleep`) to limit throughput. Operating system scheduling jitter causes these sleeps to drift under low-bandwidth targets (e.g. capping at <1000 bytes/sec). We should use high-resolution POSIX timers (`nanosleep` or `timerfd`) to improve precision.

---

### 18. Pipeline runs capture loops sequentially rather than in parallel
* **File**: `src/pipeline/np_pipeline.c`
* **Tags**: `tech-debt`, `help-wanted`
* **Description**:
  Although the pipeline supports multiple sources, the execution loop processes them sequentially on a single thread. To achieve high throughput when capturing on multiple interfaces simultaneously, the pipeline needs to manage worker threads running each source in parallel, feeding a synchronized ring queue.
