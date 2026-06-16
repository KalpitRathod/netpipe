# Python Integration & Developer Guide

This guide explains how to interface the `netpipe` packet processing engine with Python. By combining `netpipe`'s high-performance C-core with Python's data analysis libraries, you can build custom protocol analyzers, real-time dashboards, statistical anomaly detectors, and stateful flow monitors.

---

## 1. Core Architecture & Streaming Basics

Instead of employing complex C bindings (such as `ctypes` or `Cython`), `netpipe` communicates with Python via **Newline-Delimited JSON (NDJSON)** streams. 

### Spawning the Pipeline
Python spawns `netpipe` as a subprocess using the `subprocess.Popen` API, redirects standard output to a pipe, and reads it line-by-line:

```python
import subprocess
import json

# Command to capture live traffic on eth0 and output NDJSON
cmd = ["netpipe", "-i", "eth0", "-fmt", "json", "-q"]

# Spawn the subprocess
proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

try:
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        
        # Parse packet dictionary
        pkt = json.loads(line)
        print(f"Captured packet #{pkt['seq']} - Size: {pkt['caplen']}B")
except KeyboardInterrupt:
    proc.terminate()
    proc.wait()
```

### Performance Considerations
1. **Use Quiet Mode (`-q`)**: Always supply the `-q` flag to `netpipe`. This prevents informational log messages from polluting standard error or being mixed into output.
2. **Buffer Overhead**: Parsing JSON in Python can become a bottleneck at high packet-per-second (PPS) rates. If your application drops packets under high load:
   - Use `netpipe` filtering options (e.g., `-port`, `-proto`, `-f`) to discard unwanted traffic at the fast C-level before it reaches Python.
   - Capture via Linux Zero-Copy Rings (`-proc ring` or the `np_source_ring` API).
   - Use multi-threading to move JSON parsing to a separate thread.

---

## 2. Decoding the JSON Packet Model

Every JSON packet emitted contains a set of base metadata, followed by optional protocol blocks decoded by `netpipe`'s native C analyzers.

```json
{
  "seq": 1045,
  "ts": "10:14:02.129384",
  "caplen": 66,
  "wirelen": 66,
  "flow_id": 3105942,
  "layers": [
    {"proto": "ethernet", "len": 14},
    {"proto": "ipv4", "len": 20},
    {"proto": "tcp", "len": 32}
  ],
  "raw_hex": "000c293da1b2005056c00008080045000034..."
}
```

### Protocol Parsing
The `"layers"` array represents the network stack order from L2 to L4/L7. You can check for a protocol's presence using a list comprehension:
```python
is_tcp = any(layer["proto"] == "tcp" for layer in pkt["layers"])
```

---

## 3. Advanced Integration Mechanics

### A. Manual Protocol Decoding from `raw_hex`
If you need to parse a protocol that is not natively decoded by `netpipe`, you can slice the `raw_hex` string.

For example, to extract UDP/TCP source and destination ports manually (assuming standard L2 Ethernet + L3 IPv4 header sizes):
```python
def get_ports_from_pkt(pkt):
    # Ethernet (14 bytes) + IPv4 (20 bytes) = 34 bytes offset
    try:
        raw_bytes = bytes.fromhex(pkt["raw_hex"])
        # Ports are located in the first 4 bytes of TCP/UDP headers
        src_port = int.from_bytes(raw_bytes[34:36], "big")
        dst_port = int.from_bytes(raw_bytes[36:38], "big")
        return src_port, dst_port
    except Exception:
        return None
```

### B. TCP Stream Reassembly
When you enable the TCP stream reassembler via `-proc tcp-stream`, `netpipe` outputs the cumulative payload buffer for a connection in the `"stream_hex"` key. 

To avoid printing duplicate historical data, your script must track a **cursor** for each `flow_id` indicating how many bytes have already been processed:

```python
flow_cursors = {}

# Inside your packet loop...
stream_hex = pkt.get("stream_hex")
if stream_hex:
    flow_id = pkt["flow_id"]
    payload_bytes = bytes.fromhex(stream_hex)
    
    # Get last read position
    cursor = flow_cursors.get(flow_id, 0)
    if len(payload_bytes) > cursor:
        new_data = payload_bytes[cursor:]
        print(f"[Flow {flow_id}] New bytes: {new_data}")
        flow_cursors[flow_id] = len(payload_bytes)
```

### C. Stateful Flow Tracking
The `"flow_id"` field is a 32-bit hash computed from the packet's 5-tuple. You can use this ID to associate packets and track session states (e.g. lifetimes or total volumes):

```python
from collections import defaultdict
import time

flows = defaultdict(lambda: {"start": time.time(), "pkts": 0, "bytes": 0})

# Inside packet loop...
fid = pkt["flow_id"]
flows[fid]["pkts"] += 1
flows[fid]["bytes"] += pkt["caplen"]
```

---

## 4. Reference Guide to all 22 Python Examples

The `examples/python/` directory contains program files showcasing these mechanics.

### Category 1: Foundational & Basics

#### `00_quickstart.py`
* **Purpose**: Spawns `netpipe`, reads JSON packets, and prints the protocol stack.
* **Usage**: `sudo python3 00_quickstart.py wlo1`

---

### Category 2: Protocol Analysis & Monitoring

#### `01_dns_monitor.py`
* **Purpose**: Monitors DNS query domains and alerts if a single domain is queried repeatedly (potential C2/DGA activity).
* **Usage**: `sudo python3 01_dns_monitor.py wlo1`

#### `03_http_sniffer.py`
* **Purpose**: Sniffs plain HTTP requests/responses on port 80 and logs them to a structured append-only JSONL file (`http_log.jsonl`).
* **Usage**: `sudo python3 03_http_sniffer.py wlo1`

#### `08_browser_spy.py`
* **Purpose**: Inspects plaintext DNS and TLS Server Name Indication (SNI) hostnames to track browser visits even over encrypted HTTPS connections.
* **Usage**: `sudo python3 08_browser_spy.py wlo1`

#### `10_tls_capture.py`
* **Purpose**: Inspects TLS ClientHello handshakes to parse and print negotiated TLS versions and cipher suites.
* **Usage**: `sudo python3 10_tls_capture.py wlo1`

#### `11_tls_decryptor.py`
* **Purpose**: Offline tool demonstrating how to use TLS keylog files to decrypt captured network payloads.
* **Usage**: `python3 11_tls_decryptor.py --file encrypted.pcap --keys sslkeylog.txt`

#### `12_http_parser_demo.py`
* **Purpose**: Demonstrates reading HTTP request methods, URIs, status codes, and HTTP headers natively extracted by the C core's built-in HTTP parser.
* **Usage**: `sudo python3 12_http_parser_demo.py wlo1`

#### `13_dns_spy.py`
* **Purpose**: Demonstrates reading query names, record classes, TTLs, and answer lists natively decoded by `netpipe`'s C core DNS parser.
* **Usage**: `sudo python3 13_dns_spy.py wlo1`

---

### Category 3: Traffic Dashboards & Visualizations

#### `02_traffic_dashboard.py`
* **Purpose**: Renders an interactive, real-time terminal dashboard containing live packet rates, total bandwidth statistics, and protocol breakdowns.
* **Usage**: `sudo python3 02_traffic_dashboard.py wlo1`

#### `05_pcap_report.py`
* **Purpose**: Performs offline PCAP analysis, prints terminal summaries, and generates a responsive, dark-mode HTML report containing charts and packet tables.
* **Usage**: `python3 05_pcap_report.py capture.pcap --out report.html`

#### `06_bandwidth_recorder.py`
* **Purpose**: Records capture throughput to a CSV file and optionally renders a live bandwidth trend line plot using `matplotlib`.
* **Usage**: `sudo python3 06_bandwidth_recorder.py wlo1 --duration 60 --plot`

---

### Category 4: Intrusion Detection & Policies

#### `04_anomaly_detector.py`
* **Purpose**: Monitors packet rates, L4 port distributions, and sizes to trigger alerts on Floods, Port Scans, Large Packets, and New Protocols.
* **Usage**: `sudo python3 04_anomaly_detector.py wlo1`

#### `07_packet_firewall.py`
* **Purpose**: Renders passive packet inspection against rulesets, logging alerts on blacklisted host addresses, UDP/TCP ports, or protocols.
* **Usage**: `sudo python3 07_packet_firewall.py wlo1 --log violations.jsonl`

---

### Category 5: Advanced Processing & Injection

#### `09_stream_follower.py`
* **Purpose**: Utilizes the native C stream reassembly processor to reconstruct and print TCP stream payloads (e.g. plaintext HTTP responses) in real time.
* **Usage**: `sudo python3 09_stream_follower.py wlo1`

#### `14_tun_replay.py`
* **Purpose**: Replays and injects captured PCAP packet data into a virtual TUN/TAP network interface (`tun0`) using the C core's virtual interface injector.
* **Usage**: `sudo python3 14_tun_replay.py --file capture.pcap --interface tun0`

#### `15_socket_forward.py`
* **Purpose**: Sets up a forwarding network socket sink (TCP/UDP) to transmit raw packets or JSON streams to a remote log server.
* **Usage**: `python3 15_socket_forward.py --file capture.pcap --host 192.168.1.50 --port 9999`

#### `16_payload_transform.py`
* **Purpose**: Showcases the C transform processor, executing payload regex string replacements, hex encoding, and Base64 translations on passing packets.
* **Usage**: `python3 16_payload_transform.py --file capture.pcap`

#### `17_flow_tracker.py`
* **Purpose**: Uses 5-tuple hash flow identifiers to monitor connection lifetimes and track bidirectional payload stats.
* **Usage**: `python3 17_flow_tracker.py --file capture.pcap`

#### `18_pcapng_writer.py`
* **Purpose**: Records captured network frames directly into native PCAP-NG blocks and verifies file structure integrity.
* **Usage**: `python3 18_pcapng_writer.py --file capture.pcap --out output.pcapng`

#### `19_lua_processor.py`
* **Purpose**: Feeds packet objects through custom Lua scripts embedded within the C processing pipeline to hook, log, or filter packets.
* **Usage**: `python3 19_lua_processor.py --file capture.pcap --script filter.lua`

---

### Category 6: Performance & Scaling

#### `20_multi_interface_parallel.py`
* **Purpose**: Launches concurrent subprocess threads to capture traffic from multiple network interfaces and combines them into a thread-safe queue.
* **Usage**: `python3 20_multi_interface_parallel.py --interfaces eth0,wlo1`

#### `21_zero_copy_ring.py`
* **Purpose**: Configures high-performance Linux zero-copy circular ring buffers (`PACKET_MMAP`) on raw AF_PACKET sockets to capture high-throughput networks.
* **Usage**: `sudo python3 21_zero_copy_ring.py --interface eth0`
