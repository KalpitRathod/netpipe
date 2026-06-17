# netpipe — Python Examples

All examples pipe netpipe's JSON output (`-fmt json`) into Python.
**No extra Python libraries needed** unless noted.

```
netpipe -i wlo1 -fmt json | python3 your_script.py
# or each script launches netpipe as a subprocess automatically
```

---

## How it works

```
netpipe -i wlo1 -fmt json -q
│
│  {"seq":1,"ts":"09:15:32.041","caplen":74,"wirelen":74,
│   "flow_id":3145678,
│   "layers":[
│     {"proto":"ethernet","len":14},
│     {"proto":"ipv4","len":20},
│     {"proto":"udp","len":8},
│     {"proto":"dns","len":32}
│   ],
│   "raw_hex":"ffffffffffff..."}
│
└──▶ Python reads one JSON object per line with json.loads()
```

Each packet is a Python dict. That's it — simple, composable, powerful.

---

## Examples

| File | What it does | Root needed? |
|------|-------------|:---:|
| `00_quickstart.py` | Print protocol stack of every packet | ✅ live / ❌ file |
| `01_dns_monitor.py` | Real-time DNS query monitor with DGA alerting | ✅ |
| `02_traffic_dashboard.py` | Live ANSI terminal dashboard with bar charts | ✅ |
| `03_http_sniffer.py` | HTTP request/response logger → JSONL | ✅ |
| `04_anomaly_detector.py` | Flood / port-scan / large-pkt / new-proto detection | ✅ |
| `05_pcap_report.py` | Offline PCAP → terminal report + HTML report | ❌ |
| `06_bandwidth_recorder.py` | Per-second bandwidth CSV + matplotlib plot | ✅ |
| `07_packet_firewall.py` | Passive policy firewall — alert on blocked IPs/ports | ✅ |
| `08_browser_spy.py` | Watch what sites your browser visits via DNS + TLS SNI | ✅ |
| `09_stream_follower.py` | Reassemble TCP fragments into readable streams | ✅ |
| `10_tls_capture.py` | Capture HTTPS traffic + export TLS session keys | ✅ |
| `11_tls_decryptor.py` | Decrypt a TLS capture using session keys (needs pyshark) | ❌ |
| `12_http_parser_demo.py` | Native C-level HTTP/1.1 parser — method, path, headers | ✅ |
| `13_dns_spy.py` | Native C-level DNS decoder — queries and A/AAAA answers | ✅ |
| `14_tun_replay.py` | Replay a pcap into the kernel via a TUN virtual interface | ✅ root |
| `15_socket_forward.py` | Forward raw capture as a PCAP stream over TCP | ✅ root |
| `16_payload_transform.py` | Demonstrate payload transform processor modes (hex/base64/regex) | ❌ file / ✅ live |
| `17_flow_tracker.py` | Track network sessions and print bidirectional flow statistics | ❌ file / ✅ live |
| `18_pcapng_writer.py` | Write captured packets to native PCAP-NG and verify file integrity | ❌ file / ✅ live |
| `19_lua_processor.py` | Run custom Lua scripts to hook into packet processing/filtering | ❌ file / ✅ live |
| `20_multi_interface_parallel.py` | Capture from multiple interfaces/files concurrently using threads | ❌ file / ✅ live |
| `21_zero_copy_ring.py` | High-performance zero-copy AF_PACKET + PACKET_MMAP capture | ❌ file / ✅ live |
| `22_tcp_stream_reassembly.py` | Reassemble TCP packets into application streams (`stream_hex`) | ❌ |
| `23_socket_forwarding.py` | Forward PCAP packet capture streams over a TCP socket interface | ❌ |
| `24_lua_pipeline.py` | Execute dynamic Lua scripts from Python for inline processing | ❌ |
| `25_protocol_stats.py` | Aggregate and chart traffic protocol distribution metrics | ❌ |
| `26_pcap_diff.py` | Side-by-side diffing of protocol signatures between two PCAPs | ❌ |
| `test_all_examples.py` | Smoke-test runner — verifies all examples run without crashing | ❌ |

---

## Quick usage

```bash
# Build netpipe first
cd /path/to/netpipe   # repo root
make
cd examples/python

# 0. See 20 packets from a file
python3 00_quickstart.py --file ../../test/sample.pcap

# 0. Live capture (needs root)
sudo python3 00_quickstart.py wlo1

# 1. Watch what DNS your system resolves
sudo python3 01_dns_monitor.py wlo1

# 2. Live protocol dashboard (updates every second)
sudo python3 02_traffic_dashboard.py wlo1

# 3. Log all HTTP requests to http_log.jsonl
sudo python3 03_http_sniffer.py wlo1

# 4. Detect anomalies
sudo python3 04_anomaly_detector.py wlo1

# 5. Analyse a pcap file, get HTML report
python3 05_pcap_report.py capture.pcap --out report.html
# open report.html in a browser

# 6. Record 60s of bandwidth to CSV, then plot
sudo python3 06_bandwidth_recorder.py wlo1 --duration 60 --plot
# requires: pip install matplotlib

# 7. Passive firewall monitor
sudo python3 07_packet_firewall.py wlo1 --log violations.jsonl

# 16. Payload transformations (hex/base64/regex)
python3 16_payload_transform.py --file ../../encrypted_traffic.pcap

# 17. Flow tracking and connection state monitoring
python3 17_flow_tracker.py --file ../../encrypted_traffic.pcap

# 18. Native PCAP-NG writing and verification
python3 18_pcapng_writer.py --file ../../encrypted_traffic.pcap

# 19. Lua scripting processor hook
python3 19_lua_processor.py --file ../../encrypted_traffic.pcap

# 20. Concurrent multi-source packet capture and fan-in
python3 20_multi_interface_parallel.py --file ../../encrypted_traffic.pcap

# 21. High-performance zero-copy PACKET_MMAP capture
python3 21_zero_copy_ring.py

# 22. TCP stream reassembly and HTTP payload extraction
python3 22_tcp_stream_reassembly.py

# 23. Forwarding captures over TCP sockets (PCAP & NDJSON)
python3 23_socket_forwarding.py

# 24. Executing dynamic Lua processing filters
python3 24_lua_pipeline.py

# 25. Traffic metrics and protocol statistics report
python3 25_protocol_stats.py

# 26. Packet-level protocol stack and signature comparison
python3 26_pcap_diff.py
```

---

## JSON packet format

```python
{
    "seq":     1,              # global packet sequence number
    "ts":      "09:15:32.041233",   # HH:MM:SS.microseconds
    "caplen":  74,             # bytes captured
    "wirelen": 74,             # bytes on wire
    "flow_id": 3145678,        # 5-tuple hash (src_ip, dst_ip, sport, dport, proto)
    "layers": [
        {"proto": "ethernet", "len": 14},
        {"proto": "ipv4",     "len": 20},
        {"proto": "udp",      "len": 8},
        {"proto": "dns",      "len": 32},
    ],
    "raw_hex": "ffffffffffff00..."  # first 32 bytes as hex string
}
```

### Layer protocol names

`ethernet`, `arp`, `ipv4`, `ipv6`, `icmp`, `tcp`, `udp`, `dns`, `http`, `tls`

### Useful one-liners

```python
import subprocess, json

# Stream packets from netpipe
def packets(interface=None, file=None, proto=None, port=None, count=None):
    cmd = ["../../build/bin/netpipe", "-fmt", "json", "-q"]
    if interface: cmd += ["-i", interface]
    if file:      cmd += ["-r", file]
    if proto:     cmd += ["-proto", proto]
    if port:      cmd += ["-port", str(port)]
    if count:     cmd += ["-c", str(count)]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True) as p:
        for line in p.stdout:
            try:    yield json.loads(line.strip())
            except: pass

# Count DNS packets
dns_count = sum(1 for pkt in packets(file="cap.pcap")
                if any(l["proto"] == "dns" for l in pkt["layers"]))

# Find largest packets
big = sorted(packets(file="cap.pcap"),
             key=lambda p: p["caplen"], reverse=True)[:5]

# All unique flow IDs
flows = {pkt["flow_id"] for pkt in packets(file="cap.pcap")}
print(f"{len(flows)} unique flows")
```

---

## Combining with other tools

```bash
# Feed netpipe JSON into jq
sudo netpipe -i wlo1 -fmt json -q | jq 'select(.layers[].proto == "dns")'

# Write to file, analyse later
sudo netpipe -i wlo1 -fmt json -q -c 10000 > packets.jsonl
python3 05_pcap_report.py --from-jsonl packets.jsonl  # (future feature)

# Save pcap AND stream JSON simultaneously
sudo netpipe -i wlo1 -o session.pcap -fmt json | python3 01_dns_monitor.py --stdin
```

---

## Requirements

- Python 3.8+
- `netpipe` binary at `../../build/bin/netpipe`
- Root / `CAP_NET_RAW` for live capture
- `matplotlib` only for `06_bandwidth_recorder.py --plot`
