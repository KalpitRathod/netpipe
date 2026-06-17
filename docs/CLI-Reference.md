# CLI Reference

The `netpipe` command-line utility is a composable packet processing tool. You configure the capture pipeline via command-line options by specifying packet sources, filter rules, processing operations, and output sinks.

---

## Command Synopsis

```
netpipe [OPTIONS]
```

---

## Options Reference

### Input Options (Sources)
* `-i <device>`: Capture live traffic on the specified network interface (e.g., `eth0`, `wlo1`, `any`). Requires administrative privileges (`root` or `CAP_NET_RAW`).
* `--ring`: Use Linux zero-copy AF_PACKET + PACKET_MMAP ring-buffer capture (Linux only, requires root). Must be combined with `-i`.
* `-r <file.pcap>`: Read packets offline from a standard PCAP or PCAP-NG file. Does not require root.
* `-D`: List all available network interfaces on the host and exit.
* `-s <snaplen>`: Max bytes captured per packet. Default is `65535` (full packet).
* `-p`: Disable promiscuous mode. By default, live captures put the card in promiscuous mode to see all LAN frames.
* `-T <ms>`: Live capture packet buffer read timeout in milliseconds. Default is `1000`.

### Filtering Options
If multiple filters are specified, they are logically **ANDed** together.
* `-f "<bpf-expr>"`: Specify a Berkeley Packet Filter (BPF) expression (e.g., `"tcp port 443"`, `"udp port 53 and host 8.8.8.8"`).
* `-proto <name>`: Match packets containing the named protocol in their stack. Supported: `eth`, `arp`, `ip` (ipv4), `ip6` (ipv6), `icmp`, `tcp`, `udp`, `dns`, `http`, `tls`, `quic`, `dhcp`, `sip`, `mqtt`, `vxlan`.
* `-port <number>`: Match packets whose source or destination TCP/UDP port matches `<number>`.
* `-host <ip>`: Match packets whose source or destination IPv4 address matches `<ip>`.

### Processing Options
* `-proc tcp-stream`: Enable TCP stream reassembly. Implements per-flow, per-direction reassembly with out-of-order segment buffering, retransmission detection, hole-timeout gap flushing (1s), SYN/FIN/RST state machine, and RFC 793 sequence arithmetic. Populates `stream_data`/`stream_len` on each packet.
* `-proc flow-tracker`: Maintain per-5-tuple state across packets and print a summary table at shutdown. Includes automatic GC of idle flows (60s timeout).
* `-proc transform:<mode>`: Apply a transformation to the payload. Modes: `hex`, `base64`, `regex:pattern:replacement`.
* `-proc lua:<script.lua>`: Execute a Lua packet processing/filtering script. The script registers `init()`, `process(pkt)`, and `free()` callbacks via `NP_REGISTER_PROCESSOR()`. Return `false` from `process()` to drop the packet from downstream sinks.
* `-proc tls-decrypt:<keylog.txt>`: Decrypt TLS 1.2 and TLS 1.3 traffic inline using an NSS key-log file (`SSLKEYLOGFILE` format). Supports AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 cipher suites. Decrypted plaintext is placed in `stream_data` and the TLS layer's `data` pointer is redirected to the plaintext.
* `-rate <bps>`: Rate-limit output to N bytes per second (token bucket). Uses `nanosleep(2)` for high-resolution timing.

### Output Options (Sinks)
* `-o <file>`: Write output to `<file>`. Format is inferred from the file extension if `-fmt` is omitted (e.g., `.pcap` -> pcap, `.json` -> json). Use `-` for stdout.
  * `-o tap://<dev>`: Inject packets into a Linux TAP (Layer 2) virtual interface. Requires root or `CAP_NET_ADMIN`.
  * `-o tun://<dev>`: Inject packets into a Linux TUN (Layer 3) virtual interface. Requires root or `CAP_NET_ADMIN`.
  * `-o socket://<host:port>`: Forward raw PCAP stream to a remote host over TCP.
* `-fmt <format>`: Force a specific output format. Supported formats:
  * `pcap`: Standard binary PCAP.
  * `pcapng`: PCAP-NG with interface-description blocks.
  * `json`: Newline-delimited JSON (NDJSON), one object per line.
  * `hex`: Human-readable layer-annotated hex dump.
  * `pretty`: tshark-style single-line packet summaries.
  * `stats`: Periodic counter logs (every 5 seconds).
  * `null`: Discard packets (useful for benchmarking or processors).
* `-stats <file>`: Write a periodic statistics report to `<file>` (use `-` for stdout) every 5 seconds.
* `-c <count>`: Stop the pipeline after processing `<count>` packets.

### Logging Options
* `-v`: Enable verbose debug logging.
* `-vv`: Enable trace logging (extremely detailed/noisy).
* `-q`: Quiet mode. Suppress standard info/debug messages; log only warnings and errors.
* `-no-color`: Disable ANSI terminal coloring in logs.

### Miscellaneous Options
* `-h, --help`: Print help and exit.
* `--version`: Print version and exit.

---

## TLS Decryption

netpipe can decrypt TLS 1.2 and TLS 1.3 traffic inline if an NSS key-log file is provided. The key-log file is emitted by Chrome, Firefox, curl, OpenSSL, and other TLS implementations when the `SSLKEYLOGFILE` environment variable is set.

### Supported cipher suites

**TLS 1.3:**
- `TLS_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

**TLS 1.2 (GCM/ChaCha20):**
- `ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `RSA_WITH_AES_128_GCM_SHA256`
- `RSA_WITH_AES_256_GCM_SHA384`
- `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
- `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`

### Supported key-log record types
- `CLIENT_RANDOM` (TLS 1.2 master secret)
- `CLIENT_HANDSHAKE_TRAFFIC_SECRET` (TLS 1.3 client handshake)
- `SERVER_HANDSHAKE_TRAFFIC_SECRET` (TLS 1.3 server handshake)
- `CLIENT_TRAFFIC_SECRET_0` (TLS 1.3 client application)
- `SERVER_TRAFFIC_SECRET_0` (TLS 1.3 server application)

### Example

```bash
# Capture TLS traffic with key logging
SSLKEYLOGFILE=/tmp/keys.log curl https://example.com &

# Decrypt it on the fly
sudo netpipe -i eth0 -f "tcp port 443" \
    -proc tls-decrypt:/tmp/keys.log \
    -fmt json
```

---

## Lua Scripting

Lua scripts register a processor via `NP_REGISTER_PROCESSOR(table)`. The table may contain:

- `init()` — called once when the processor is created.
- `process(pkt)` — called for every packet. Return `true` to keep, or `false` to drop the packet from downstream sinks.
- `free()` — called once when the processor is freed.

The `pkt` table exposes fields like `proto`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `dns_query_name`, `raw_hex`, and `stream_hex`.

A production-ready DNS IDS script (`mitigate.lua`) is bundled and can be used as:

```bash
sudo netpipe -i eth0 -proc lua:mitigate.lua -fmt json
```

It detects:
- Long DNS qnames (≥ 50 chars) — typical of DNS-tunnel exfil.
- `exfil-payload` keyword in qname — explicit exfil pattern.
- `EXFIL_PAYLOAD` combination (long + exfil + dst=8.8.8.8) — highest-severity alert.
- DNS tunnel suspect — single label ≥ 30 chars of base32-style characters (no vowels).

---

## Practical CLI Recipes

### Live Capture to PCAP file
```bash
sudo netpipe -i eth0 -o capture.pcap
```

### Display HTTP Traffic in Hex Dump
```bash
sudo netpipe -i eth0 -f "tcp port 80" -fmt hex
```

### Log DNS Queries as JSON
```bash
sudo netpipe -i eth0 -proto dns -o dns.jsonl
```

### Read PCAP Offline and Filter by IP
```bash
netpipe -r capture.pcap -host 192.168.1.100 -fmt hex | less
```

### Discard Packets but Print Live Stats Every 5 Seconds
```bash
sudo netpipe -i eth0 -fmt null -stats -
```

### TCP Stream Reassembly with JSON Output
```bash
sudo netpipe -i wlo1 -proto http -proc tcp-stream -fmt json
```

### TLS Decryption
```bash
sudo netpipe -i eth0 -f "tcp port 443" \
    -proc tls-decrypt:/tmp/keys.log -fmt json
```

### Lua IDS (DNS exfil detection)
```bash
sudo netpipe -i eth0 -proc lua:mitigate.lua -fmt null
```

### Zero-copy Ring-Buffer Capture
```bash
sudo netpipe -i eth0 --ring -o capture.pcap
```

### Forward Packets to a Remote Collector
```bash
sudo netpipe -i eth0 -c 50 -o socket://192.168.1.10:9999
```

### Inject Packets into a TAP Interface
```bash
sudo netpipe -r cap.pcap -o tap://tap0 -rate 10000
```
