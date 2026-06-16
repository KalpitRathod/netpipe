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
* `-r <file.pcap>`: Read packets offline from a standard PCAP file. Does not require root.
* `-D`: List all available network interfaces on the host and exit.
* `-s <snaplen>`: Max bytes captured per packet. Default is `65535` (full packet).
* `-p`: Disable promiscuous mode. By default, live captures put the card in promiscuous mode to see all LAN frames.
* `-T <ms>`: Live capture packet buffer read timeout in milliseconds. Default is `1000`.

### Filtering Options
If multiple filters are specified, they are logically **ANDed** together.
* `-f "<bpf-expr>"`: Specify a Berkeley Packet Filter (BPF) expression (e.g., `"tcp port 443"`, `"udp port 53 and host 8.8.8.8"`).
* `-proto <name>`: Match packets containing the named protocol in their stack. Supported: `eth`, `arp`, `ip` (ipv4), `ip6` (ipv6), `icmp`, `tcp`, `udp`, `dns`, `http`, `tls`.
* `-port <number>`: Match packets whose source or destination TCP/UDP port matches `<number>`.
* `-host <ip>`: Match packets whose source or destination IPv4 address matches `<ip>`.

### Output Options (Sinks)
* `-o <file>`: Write output to `<file>`. Format is inferred from the file extension if `-fmt` is omitted (e.g., `.pcap` -> pcap, `.json` -> json).
* `-fmt <format>`: Force a specific output format. Supported formats:
  * `pcap`: Standard binary PCAP.
  * `json`: Newline-delimited JSON (NDJSON), one object per line.
  * `hex`: Human-readable layer-annotated hex dump.
  * `stats`: Periodic counter logs.
  * `null`: Discard packets (useful for benchmarking or processors).
* `-stats <file>`: Write a periodic statistics report to `<file>` (use `-` for stdout) every 5 seconds.
* `-c <count>`: Stop the pipeline after processing `<count>` packets.

### Logging Options
* `-v`: Enable verbose debug logging.
* `-vv`: Enable trace logging (extremely detailed/noisy).
* `-q`: Quiet mode. Suppress standard info/debug messages; log only warnings and errors.
* `-no-color`: Disable ANSI terminal coloring in logs.

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
