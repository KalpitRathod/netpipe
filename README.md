# netpipe

> **FFmpeg for networking** — a Fabrice Bellard–inspired, modular,
> pipeline-driven packet processing tool written in pure C.

```
  ███╗   ██╗███████╗████████╗██████╗ ██╗██████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║   ██████╔╝██║██████╔╝█████╗
  ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██║██╔═══╝ ██╔══╝
  ██║ ╚████║███████╗   ██║   ██║     ██║██║     ███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝     ╚══════╝
  network processing pipeline  v0.1.0
```

---

## What is netpipe?

netpipe is a command-line network packet processing tool that works
**exactly like FFmpeg works for video**: you wire together **sources**,
**filters**, **processors**, and **sinks** into a pipeline, then run it.

If FFmpeg is the undisputed champion of media stream manipulation,
netpipe aims to be its networking equivalent — a universal packet
swiss-army knife that replaces the patchwork of `tcpdump | grep | awk`
pipelines with a single, composable, scriptable tool.

---

## How it compares to other tools

| Tool | netpipe equivalent | What it does |
|------|--------------------|--------------|
| `tcpdump` | `netpipe -i eth0 -f "tcp port 80"` | Filter live traffic |
| `wireshark/tshark` | `netpipe -r dump.pcap -fmt hex` | Deep packet inspection |
| `nc` (netcat) | roadmap: `-o socket://host:port` | Raw stream forwarding |
| `nmap` | roadmap: scanner processor | Port/host discovery |
| `curl` | roadmap: HTTP processor | HTTP-aware transforms |

netpipe's value over all of these is **composability**: you can
chain all of these behaviors in one pipeline.

---

## Philosophy: the Bellard method

netpipe is deliberately designed in the style of
**Fabrice Bellard** (creator of FFmpeg, QEMU, and TCC):

1. **Object-Oriented C via vtable structs** — no C++, no bloat.
   Every component (source, filter, sink) is a `struct` of function
   pointers, just like FFmpeg's `AVInputFormat`.

2. **Zero unnecessary dependencies** — libpcap for capture,
   pthreads for threading. Everything else is written from scratch.

3. **Custom buffer pool** — instead of `malloc()`/`free()` per packet,
   a reference-counted free-list pool (`np_bufpool_t`) inspired by
   FFmpeg's `AVBufferRef` is used. Buffers are recycled, not freed.

4. **Plugin self-registration** — every sink, source, and filter
   registers itself at startup via `__attribute__((constructor))`,
   exactly like FFmpeg's `av_register_all()`. No hardwired if-else
   chains in the core.

5. **epoll event loop** — `np_evloop_t` wraps Linux's `epoll(7)` with
   `timerfd` and `eventfd` wakeup support, ready for async I/O on
   tens-of-thousands of concurrent connections.

---

## Build

### Requirements

| Package | Purpose |
|---------|---------|
| GCC ≥ 9 or Clang ≥ 11 | C11 compiler |
| `libpcap-dev` | Packet capture |
| `libc` + pthreads | Everything else (already installed) |

```bash
# Install dependency (one time)
sudo apt install libpcap-dev          # Debian / Ubuntu
sudo dnf install libpcap-devel        # Fedora / RHEL
sudo pacman -S libpcap                # Arch Linux

# Build
make                   # optimised release build
make debug             # AddressSanitizer + UBSan
sudo make install      # install to /usr/local
make clean             # remove build/
```

Build outputs:
- `build/bin/netpipe`        — the CLI binary
- `build/lib/libnetpipe.a`   — static library for embedding

---

## Quick start

```bash
# 1. See what interfaces you can capture on
./build/bin/netpipe -D

# 2. Live capture on your WiFi adapter, hex-dump to terminal
sudo ./build/bin/netpipe -i wlo1 -fmt hex

# 3. Capture and save to a Wireshark-compatible pcap file
sudo ./build/bin/netpipe -i wlo1 -o session.pcap

# 4. Read that file back and print as JSON
./build/bin/netpipe -r session.pcap -fmt json

# 5. Filter only DNS queries, show live stats
sudo ./build/bin/netpipe -i wlo1 -proto dns -stats -

# 6. Stop automatically after 100 packets
sudo ./build/bin/netpipe -i wlo1 -c 100 -o top100.pcap
```

---

## Full CLI reference

```
Usage: netpipe [OPTIONS]

━━━ Input ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  -i <device>       Live capture on a network interface
                    (requires root/CAP_NET_RAW)
                    Example: -i eth0,  -i wlo1,  -i any

  -r <file.pcap>    Read packets from a .pcap file (no root needed)
                    Example: -r capture.pcap

  -D                List all available capture devices and exit

  -s <snaplen>      Maximum bytes captured per packet
                    Default: 65535 (full packet)

  -p                Disable promiscuous mode
                    By default netpipe puts the NIC in promisc mode
                    so it sees all frames, not just unicast to its MAC.

  -T <ms>           Read timeout for live capture in milliseconds
                    Default: 1000 ms

━━━ Filtering ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Multiple filters are ANDed together.

  -f <bpf-expr>     BPF (Berkeley Packet Filter) expression
                    Same syntax as tcpdump / Wireshark capture filters.
                    Examples:
                      -f "tcp port 443"
                      -f "udp port 53 and host 8.8.8.8"
                      -f "icmp"
                      -f "net 192.168.1.0/24"

  -proto <name>     Protocol filter. Matches packets containing
                    the named protocol anywhere in the layer stack.
                    Supported names:
                      eth    — Ethernet frames
                      arp    — ARP
                      ip     — IPv4  (alias: ipv4)
                      ip6    — IPv6  (alias: ipv6)
                      icmp   — ICMP / ICMPv6
                      tcp    — TCP
                      udp    — UDP
                      dns    — DNS (port 53, heuristic)
                      http   — HTTP (payload heuristic)
                      tls    — TLS/SSL (record header heuristic)

  -port <number>    Match packets whose TCP or UDP source OR destination
                    port equals <number>.
                    Example: -port 8080

  -host <ipv4>      Match packets whose IPv4 source OR destination
                    address equals <ipv4>.
                    Example: -host 192.168.1.1

━━━ Output ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  -o <file>         Write output to <file>.
                    If -fmt is not given, the format is inferred from
                    the file extension:
                      .pcap / .cap  →  pcap
                      .json         →  json
                      .txt / .hex   →  hex
                    Use -o /dev/null to discard without processing.

  -fmt <format>     Force output format. Overrides extension inference.
                    When -o is omitted, output goes to stdout.

                    Formats:
                      pcap    Wireshark-compatible binary pcap
                      json    Newline-delimited JSON (one object/packet)
                      hex     Human-readable hex dump with layer labels
                      stats   Periodic counter report
                      null    Discard (useful with -stats or processors)

  -stats <file>     Write a periodic statistics report to <file>.
                    Use '-' for stdout.  Reports every 5 seconds:
                      timestamp  pkts  bytes  TCP  UDP  ICMP  HTTP  DNS  TLS
                    Can be combined with any other -fmt / -o.

  -c <count>        Stop the pipeline after capturing <count> packets.
                    Example: -c 1000

━━━ Logging ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  -v                Enable DEBUG log level (verbose)
  -vv               Enable TRACE log level (very verbose, noisy)
  -q                Quiet — only WARN and ERROR messages
  -no-color         Disable ANSI colour output (useful for log files)

━━━ Misc ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  -h, --help        Print this help and exit
  --version         Print version string and exit
```

---

## Usage recipes

### Capture everything, save to pcap

```bash
sudo netpipe -i wlo1 -o full_capture.pcap
# Ctrl-C to stop — file is flushed cleanly
```

### Watch HTTP traffic in real time

```bash
sudo netpipe -i wlo1 -f "tcp port 80 or tcp port 8080" -fmt hex
```

### Capture only DNS and save as JSON for analysis

```bash
sudo netpipe -i wlo1 -proto dns -o dns_log.json
# Each line of dns_log.json is one packet:
# {"seq":1,"ts":"09:15:32.041","caplen":74,"wirelen":74,"flow_id":...,"layers":[...],"raw_hex":"..."}
```

### Monitor TLS handshakes

```bash
sudo netpipe -i wlo1 -proto tls -fmt hex -q
```

### Capture 500 packets, save pcap + show live stats

```bash
sudo netpipe -i wlo1 -c 500 -o session.pcap -stats -
```

### Analyse an existing pcap file (no root needed)

```bash
netpipe -r wireshark_dump.pcap -fmt hex | less
netpipe -r wireshark_dump.pcap -proto http -fmt json > http_flows.json
netpipe -r wireshark_dump.pcap -host 1.2.3.4 -o filtered.pcap
```

### Combine BPF + protocol + port filters

```bash
# Packets going to Google DNS from a specific host, TCP only:
sudo netpipe -i wlo1 \
    -f "host 8.8.8.8" \
    -proto tcp \
    -port 53 \
    -o google_dns_tcp.pcap
```

### Strip to raw performance stats (null sink)

```bash
sudo netpipe -i wlo1 -fmt null -stats - -q
# Only the stats ticker prints — maximum capture throughput
```

---

## Output format reference

### pcap

Standard libpcap format. Open in **Wireshark**, **tshark**, or any
other pcap-aware tool.

```bash
netpipe -r dump.pcap ...          # read
# or open directly in Wireshark GUI
```

### json (NDJSON)

One JSON object per line — trivially parsed by `jq`, Python, or
any log ingestion pipeline.

```json
{"seq":1,"ts":"09:15:32.041233","caplen":74,"wirelen":74,"flow_id":3145678,"layers":[{"proto":"ethernet","len":14},{"proto":"ipv4","len":20},{"proto":"udp","len":8},{"proto":"dns","len":32}],"raw_hex":"ffffffffffff..."}
```

Pipe into `jq` for rich queries:

```bash
netpipe -r dump.pcap -fmt json | jq 'select(.layers[].proto == "http")'
netpipe -r dump.pcap -fmt json | jq '.flow_id' | sort | uniq -c | sort -rn | head
```

### hex

Human-readable layer-annotated hex dump:

```
┌── Packet #1  ts=09:15:32.041233  cap=74  wire=74
│  Layer[0] Ethernet    len=14
│  Layer[1] IPv4        len=20
│  Layer[2] UDP         len=8
│  Layer[3] DNS         len=32
│  Raw (first 64 bytes):
│  ff ff ff ff ff ff 00 0c 29 3d a1 b2 08 00 45 00
│  00 3c 1a 2b 40 00 40 11 ...
└──
```

### stats

Periodic counter output (every 5 seconds):

```
[09:15:32] pkts=1204     bytes=983441      TCP=892    UDP=298    ICMP=14    HTTP=201   DNS=89     TLS=444
[09:15:37] pkts=2891     bytes=2341023     TCP=2109   UDP=671    ICMP=27    HTTP=498   DNS=181    TLS=1021
...
=== Final Stats ===
  Packets : 2891
  Bytes   : 2341023
  TCP     : 2109
  ...
```

---

## Architecture deep dive

### The pipeline model

```
┌──────────────┐     ┌──────────┐     ┌────────────────┐     ┌───────────────┐     ┌────────┐
│  Source(s)   │────▶│ Demuxer  │────▶│  Filter Chain  │────▶│ Processor Chain│────▶│ Sink(s)│
│  (pcap live  │     │ Ethernet │     │  BPF expression│     │  count limit   │     │  pcap  │
│   pcap file) │     │ →IP→TCP  │     │  proto/port    │     │  user callback │     │  json  │
└──────────────┘     │ →HTTP/DNS│     │  host/AND/OR   │     └───────────────┘     │  hex   │
                     └──────────┘     └────────────────┘                           │  stats │
                                                                                    └────────┘
```

Every stage communicates via `np_packet_t` — a layered packet struct
with a layer stack (up to 8 layers), convenience pointers (`pkt->eth`,
`pkt->net`, `pkt->transport`, `pkt->app`), and a scratch allocator for
decoded header structs.

### Component vtable design (Bellard style)

Every pluggable component is a `struct` + a matching `ops` struct of
function pointers. There is no inheritance, no virtual dispatch table
overhead — just plain C function pointers:

```c
// Adding a new source (e.g. TUN/TAP interface):
static const struct np_source_ops tuntap_ops = {
    .open  = tuntap_open,
    .next  = tuntap_next,
    .close = tuntap_close,
    .free  = tuntap_free,
};
// That's it. The pipeline doesn't need to change.
```

### Reference-counted buffer pool (`np_bufpool_t`)

Instead of allocating and freeing memory for every packet:

```
Traditional:  malloc(1500) → process → free(1500)   ← 2 syscalls per packet
netpipe:      pool_get()   → process → pool_return()  ← zero malloc after warmup
```

The pool is a pre-allocated slab of buffers. When a buffer's refcount
hits zero it returns to the free-list. Zero-copy cloning:

```c
np_buf_t *clone = np_buf_ref(original);  // just increments refcount
np_buf_unref(&clone);                    // returns to pool when last ref drops
```

### Plugin self-registration

Every module registers itself at startup without modifying `main.c`:

```c
// In np_sink_json.c:
static np_sink_desc_t _json_desc = {
    .name       = "json",
    .long_name  = "Newline-delimited JSON",
    .extensions = "json,ndjson",
    .create     = json_sink_create,
};
NP_REGISTER_SINK(_json_desc);   // ← calls np_registry_add_sink() before main()
```

### epoll event loop (`np_evloop_t`)

The async core for future raw-socket and TCP-stream modes:

```c
np_evloop_t *loop = np_evloop_create(128);
np_evloop_add(loop, sockfd, NP_EV_READ, on_data, ctx);
np_evloop_add_timer(loop, 5000, on_stats_tick, ctx);
np_evloop_run(loop);   // blocks; handles 10k+ fds without threads
```

Uses `epoll(7)` + `timerfd_create(2)` + `eventfd(2)` wakeup.

---

## Using netpipe as a C library

Link against `build/lib/libnetpipe.a`:

```bash
gcc myapp.c -Iinclude -Lbuild/lib -lnetpipe -lpcap -lpthread -o myapp
```

```c
#include "netpipe.h"

np_init();

np_pipeline_t *pl = np_pipeline_new();

// Source: live capture
np_pipeline_add_source(pl, np_source_live("wlo1", 65535, 1, 500));

// Filters: only HTTP
np_pipeline_add_filter(pl, np_filter_port(80));

// Custom processor callback
np_err_t my_handler(np_packet_t *pkt, void *ud) {
    if (pkt->app && pkt->app->proto == NP_PROTO_HTTP) {
        // pkt->app->data  = raw HTTP payload
        // pkt->app->len   = length
        // pkt->net->data  = raw IP header
        printf("HTTP %zu bytes\n", pkt->app->len);
    }
    return NP_OK;
}
np_pipeline_add_processor(pl, np_processor_fn(my_handler, NULL));

// Sinks
np_pipeline_add_sink(pl, np_sink_pcap("output.pcap"));
np_pipeline_add_sink(pl, np_sink_stats("-"));   // live stats to stdout

// Run (blocks until Ctrl-C or np_pipeline_stop())
np_pipeline_run(pl);

np_pipeline_free(pl);
np_cleanup();
```

---

## Project structure

```
netpipe/
├── include/
│   └── netpipe.h                  ← Public API (the only header you include)
│
├── src/
│   ├── main.c                     ← FFmpeg-style CLI
│   ├── np_global.c                ← np_init() / np_cleanup() / np_strerror()
│   │
│   ├── log/         np_log.[ch]   ← ANSI, thread-safe logger (6 levels)
│   │
│   ├── bufpool/     np_bufpool.[ch]  ← Ref-counted buffer pool (AVBufferRef)
│   │
│   ├── registry/    np_registry.[ch] ← Plugin self-registration system
│   │
│   ├── evloop/      np_evloop.[ch]   ← epoll + timerfd async event loop
│   │
│   ├── packet/      np_packet.[ch]  ← Packet alloc / layer stack / hex print
│   │
│   ├── demux/       np_demux.[ch]   ← Protocol demuxer
│   │                                   Ethernet → ARP / IPv4 / IPv6
│   │                                   → ICMP / TCP / UDP
│   │                                   → HTTP / DNS / TLS (heuristic)
│   │
│   ├── pipeline/    np_pipeline.[ch] ← Orchestration: source loop,
│   │                                   dispatch to filters/processors/sinks
│   │
│   ├── source/      np_source_pcap.c ← libpcap live + file source backend
│   │
│   ├── filter/      np_filter.c      ← BPF, proto, port, host + combinators
│   │
│   ├── sink/        np_sink.c        ← pcap / json / hex / stats / null sinks
│   │
│   └── processor/   np_processor.c   ← Callback processor
│
├── examples/
│   ├── example_http_monitor.c    ← Live HTTP line printer (library API demo)
│   └── example_dns_spy.c         ← DNS query decoder (library API demo)
│
├── Makefile
├── README.md
└── LICENSE (MIT)
```

---

## Sophistication & roadmap

### What's already implemented (sophisticated for a v0.1)

| Component | Bellard trait | Detail |
|-----------|--------------|--------|
| Vtable OO-C | ✅ | `np_source_ops`, `np_filter_ops`, `np_sink_ops`, `np_processor_ops` |
| Protocol demuxer | ✅ | 10 protocols, automatic heuristic detection, no config |
| Filter combinators | ✅ | `AND`, `OR`, `NOT` trees over any filter type |
| BPF integration | ✅ | Full libpcap BPF compiler (`pcap_open_dead` + `pcap_compile`) |
| Ref-counted buffer pool | ✅ | `np_bufpool_t` — slab alloc, zero-copy clone, pool-return |
| Plugin self-registration | ✅ | `NP_REGISTER_SINK` / `NP_REGISTER_SOURCE` / `NP_REGISTER_FILTER` |
| epoll event loop | ✅ | `np_evloop_t` with `timerfd` + `eventfd` wakeup |
| ANSI thread-safe logger | ✅ | 6 levels, colour, timestamped, `pthread_mutex` |
| Multiple simultaneous sinks | ✅ | pcap + json + stats all at once |
| Clean Ctrl-C handling | ✅ | `SIGINT` → `np_pipeline_stop()` → flush → close |
| Zero warnings strict build | ✅ | `-Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wconversion` |

### Planned (the roadmap to v1.0)

- [x] **TCP stream reassembly** — stitch fragments into byte streams
- [x] **Full HTTP/1.1 parser** — method, path, headers, body
- [x] **DNS response decoder** — extract A/AAAA/CNAME answers
- [ ] **TUN/TAP inject sink** — replay packets back into the kernel
- [ ] **Socket sink** — forward packets to a remote host (`-o socket://host:port`)
- [ ] **Rate-limiting processor** — token bucket, for traffic shaping
- [ ] **Payload transform processor** — regex_replace, base64, hex encode
- [ ] **Flow tracker** — maintain per-5-tuple state across packets
- [ ] **PCAP-NG write support** — the modern pcap format
- [ ] **Lua scripting processor** — `NP_REGISTER_PROCESSOR` from a .lua file
- [ ] **Parallel multi-interface capture** — fan-in from N interfaces
- [ ] **Ring-buffer / zero-copy capture** — `AF_PACKET` + `PACKET_MMAP`

---

## Compared to WireShark / tshark

netpipe is **not** a replacement for Wireshark's deep protocol
inspection. It is designed for:

- **Automated pipelines** — not a GUI
- **Stream transformation** — not just observation
- **Embedding** — `libnetpipe.a` in your own tools
- **Scripting** — simple BPF + protocol filters without Wireshark's
  display-filter language

Use Wireshark when you want to *explore* a capture interactively.
Use netpipe when you want to *process* packets programmatically.

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Acknowledgements

Design inspired by the architecture of
[FFmpeg](https://ffmpeg.org) — created by Fabrice Bellard.
