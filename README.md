# netpipe

> **FFmpeg for networking** — a modular, pipeline-driven network packet
> processing tool written in C.

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

## Philosophy

netpipe is designed exactly like FFmpeg — you wire together **sources**,
**filters**, **processors**, and **sinks** into a pipeline.
The command line flags mirror FFmpeg's:

| FFmpeg          | netpipe equivalent  | Meaning                         |
|-----------------|---------------------|---------------------------------|
| `-i input.mp4`  | `-r input.pcap`     | Read from file                  |
| `-f v4l2 -i /dev/video0` | `-i eth0` | Live capture            |
| `-vf "select=..."` | `-f "tcp port 80"` | BPF filter expression  |
| `-o output.mp4` | `-o capture.pcap`   | Write output                    |
| `-c:v copy`     | `-fmt json`         | Select output format            |

---

## Architecture

```
Source(s)
  │  live pcap (libpcap)
  │  offline .pcap file
  ▼
Demuxer                    ← auto-detects Ethernet→IP→TCP/UDP→App layers
  ▼
Filter Chain               ← BPF expression | proto | port | host | AND/OR/NOT
  ▼
Processor Chain            ← user callbacks, transforms
  ▼
Sink(s)
     pcap      → .pcap file  (Wireshark-compatible)
     json      → NDJSON stream
     hex       → human hex dump
     stats     → periodic counters
     null      → /dev/null
```

---

## Build

### Requirements

- GCC ≥ 9 or Clang ≥ 11
- libpcap development headers (`libpcap-dev` on Debian/Ubuntu)
- POSIX threads (`-lpthread`, already in glibc)

```bash
# Debian / Ubuntu
sudo apt install build-essential libpcap-dev

# Fedora / RHEL
sudo dnf install gcc libpcap-devel

# Arch
sudo pacman -S gcc libpcap
```

### Compile

```bash
make            # optimised release build
make debug      # with AddressSanitizer + UBSan
make install    # install to /usr/local (requires root)
make clean
```

The binary is placed at `build/bin/netpipe`.
A static library `build/lib/libnetpipe.a` is also built for embedding.

---

## Quick-start examples

```bash
# List available capture devices
netpipe -D

# Live capture on eth0, save to pcap
sudo netpipe -i eth0 -o capture.pcap

# Read a pcap, filter HTTP, dump hex to stdout
netpipe -r dump.pcap -f "tcp port 80" -fmt hex

# Live capture, filter by host, output JSON
sudo netpipe -i eth0 -host 192.168.1.1 -o traffic.json

# Monitor DNS queries with periodic stats
sudo netpipe -i eth0 -proto dns -stats - -fmt null

# Capture only 100 TCP packets to a pcap
sudo netpipe -i eth0 -proto tcp -c 100 -o top100.pcap

# TLS traffic analysis
sudo netpipe -i eth0 -proto tls -fmt json -o tls.json

# Multiple outputs: pcap + live stats
sudo netpipe -i eth0 -o session.pcap -stats stats.txt

# Quiet mode (only warnings/errors)
sudo netpipe -i eth0 -o out.pcap -q

# Debug mode (verbose)
sudo netpipe -r file.pcap -fmt hex -v
```

---

## CLI reference

```
Usage: netpipe [OPTIONS]

Input:
  -i <device>       Live capture on network interface (requires root)
  -r <file.pcap>    Read from pcap file
  -D                List available capture devices and exit
  -s <snaplen>      Snapshot length (default 65535)
  -p                Disable promiscuous mode
  -T <ms>           Read timeout in milliseconds (default 1000)

Filtering:
  -f <bpf-expr>     BPF filter expression  (e.g. "tcp port 80")
  -proto <name>     Protocol filter: eth, arp, ip, ip6, icmp, tcp, udp, dns, http, tls
  -port  <port>     Port filter (src or dst)
  -host  <ip>       Host filter (src or dst IPv4)

Output:
  -o <file>         Output file (format inferred from extension or -fmt)
  -fmt <format>     Output format: pcap (default), json, hex, stats, null
  -stats <file>     Write periodic statistics to file (use '-' for stdout)
  -c <count>        Stop after capturing N packets

Logging:
  -v                Verbose (DEBUG level)
  -vv               Very verbose (TRACE level)
  -q                Quiet (WARN level only)
  -no-color         Disable ANSI colours

Misc:
  -h, --help        Show this help
  --version         Print version and exit
```

---

## Using netpipe as a C library

```c
#include "netpipe.h"

np_init();
np_pipeline_t *pl = np_pipeline_new();

// Source
np_pipeline_add_source(pl, np_source_live("eth0", 65535, 1, 500));

// Filters
np_pipeline_add_filter(pl, np_filter_port(80));

// Custom processor
np_err_t my_handler(np_packet_t *pkt, void *ud) {
    if (pkt->app && pkt->app->proto == NP_PROTO_HTTP) {
        printf("HTTP! %zu bytes\n", pkt->app->len);
    }
    return NP_OK;
}
np_pipeline_add_processor(pl, np_processor_fn(my_handler, NULL));

// Sinks
np_pipeline_add_sink(pl, np_sink_pcap("output.pcap"));
np_pipeline_add_sink(pl, np_sink_stats("-"));     // live stats to stdout

np_pipeline_run(pl);    // blocks until done or Ctrl-C
np_pipeline_free(pl);
np_cleanup();
```

Link with:
```bash
gcc myapp.c -Iinclude -Lbuild/lib -lnetpipe -lpcap -lpthread -o myapp
```

---

## Protocol support

| Protocol | Detection     | Headers decoded |
|----------|---------------|-----------------|
| Ethernet | Link-layer    | src/dst MAC, ethertype, 802.1Q VLAN |
| ARP      | EtherType     | opcode, IPs |
| IPv4     | EtherType/raw | IHL, src/dst, protocol |
| IPv6     | EtherType/raw | next-header, src/dst |
| ICMP     | IP proto      | type/code |
| TCP      | IP proto      | ports, seq/ack, flags, options |
| UDP      | IP proto      | ports, length |
| DNS      | Port 53 / heuristic | QR, opcode, question name |
| HTTP     | Payload heuristic  | first request/response line |
| TLS      | Payload heuristic  | content type, record header |

---

## Output formats

| Format  | Extension | Description |
|---------|-----------|-------------|
| `pcap`  | `.pcap`   | Wireshark-compatible pcap |
| `json`  | `.json`   | Newline-delimited JSON (one object per packet) |
| `hex`   | `.txt`    | Human-readable hex dump with layer breakdown |
| `stats` | `.txt`    | Periodic counters: pkts/bytes/TCP/UDP/HTTP/DNS/TLS |
| `null`  | —         | Discard (useful with custom processors) |

---

## Project structure

```
netpipe/
├── include/
│   └── netpipe.h              # Public API
├── src/
│   ├── main.c                 # CLI
│   ├── np_global.c            # init / cleanup / strerror
│   ├── log/
│   │   ├── np_log.h
│   │   └── np_log.c           # ANSI thread-safe logger
│   ├── packet/
│   │   ├── np_packet.h
│   │   └── np_packet.c        # Packet alloc / clone / print
│   ├── demux/
│   │   ├── np_demux.h
│   │   └── np_demux.c         # Protocol demuxer
│   ├── pipeline/
│   │   ├── np_pipeline.h      # Internal ops vtables
│   │   └── np_pipeline.c      # Pipeline run loop
│   ├── source/
│   │   └── np_source_pcap.c   # libpcap live + file source
│   ├── filter/
│   │   └── np_filter.c        # BPF, proto, port, host, combinators
│   ├── sink/
│   │   └── np_sink.c          # pcap / json / hex / stats / null
│   └── processor/
│       └── np_processor.c     # Callback processor
├── examples/
│   ├── example_http_monitor.c
│   └── example_dns_spy.c
├── Makefile
└── README.md
```

---

## Roadmap

- [ ] IPv6 flow tracking
- [ ] TCP stream reassembly
- [ ] Full HTTP/1.1 header parsing
- [ ] DNS response A/AAAA record extraction
- [ ] PCAP-NG write support
- [ ] Replay sink (`-replay <iface>` to retransmit)
- [ ] Rate-limiting processor
- [ ] Lua scripting via plugin processor
- [ ] Ring-buffer capture mode
- [ ] Parallel multi-interface capture with fan-in

---

## License

MIT — see `LICENSE`.
