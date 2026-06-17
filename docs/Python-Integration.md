# Python Integration Guide

Rather than using complex C bindings (like `ctypes` or `cython`), `netpipe` provides a zero-dependency interface for Python applications: you spawn `netpipe` as a subprocess with the `-fmt json` option and read the output line-by-line.

```
netpipe [options] -fmt json -q | python3 my_script.py
```

Each packet is printed to stdout as a single JSON object per line (NDJSON). This provides a clean interface for scripting, data science, and pipeline automation.

---

## JSON Packet Schema

### 1. Standard Fields
Every JSON object emitted contains the following base keys:

| Key | Type | Description |
|---|---|---|
| `seq` | integer | Global sequence number, 1-indexed. |
| `ts` | string | Packet timestamp in format `HH:MM:SS.microseconds`. |
| `caplen` | integer | Number of captured bytes. |
| `wirelen` | integer | Original size of packet on the wire. |
| `flow_id` | integer | Unique flow hash computed from the connection's 5-tuple. |
| `layers` | array | Array of parsed layer objects, each containing `"proto"` and `"len"`. |
| `raw_hex` | string | Hexadecimal representation of the packet's starting bytes. |

Example base packet:
```json
{
  "seq": 104,
  "ts": "18:22:10.052419",
  "caplen": 66,
  "wirelen": 66,
  "flow_id": 3819402,
  "layers": [
    {"proto": "ethernet", "len": 14},
    {"proto": "ipv4", "len": 20},
    {"proto": "tcp", "len": 32}
  ],
  "raw_hex": "000c293da1b2005056c00008080045000034..."
}
```

---

### 2. DNS Fields
If the packet contains DNS traffic and is successfully parsed, a `"dns"` key is populated:

| Key | Type | Description |
|---|---|---|
| `is_response` | boolean | `false` for query, `true` for response. |
| `query` | object | (Present in query) Contains `"name"` (e.g. `"google.com"`) and `"type"` (e.g. `1`). |
| `answers` | array | (Present in response) List of answers, each with `"name"` and `"data"` (e.g., target CNAME or IP). |

Example DNS response object:
```json
{
  "seq": 234,
  "ts": "18:22:11.129381",
  "caplen": 142,
  "wirelen": 142,
  "flow_id": 4129481,
  "layers": [
    {"proto": "ethernet", "len": 14},
    {"proto": "ipv4", "len": 20},
    {"proto": "udp", "len": 8},
    {"proto": "dns", "len": 100}
  ],
  "dns": {
    "is_response": true,
    "answers": [
      {"name": "google.com", "data": "142.250.190.46"}
    ]
  },
  "raw_hex": "..."
}
```

---

### 3. HTTP Fields
If the packet contains HTTP/1.1 traffic and is successfully parsed, an `"http"` key is populated:

| Key | Type | Description |
|---|---|---|
| `method` | string | (Request only) Request method (e.g. `"GET"`, `"POST"`). |
| `path` | string | (Request only) Requested path (e.g. `"/index.html"`). |
| `status` | integer | (Response only) HTTP status code (e.g. `200`, `404`). |
| `phrase` | string | (Response only) HTTP status phrase (e.g. `"OK"`, `"Not Found"`). |
| `headers` | object | Dictionary of HTTP headers. |

Example HTTP Request:
```json
{
  "seq": 491,
  "ts": "18:22:15.582910",
  "caplen": 120,
  "wirelen": 120,
  "flow_id": 5104819,
  "layers": [
    {"proto": "ethernet", "len": 14},
    {"proto": "ipv4", "len": 20},
    {"proto": "tcp", "len": 32},
    {"proto": "http", "len": 54}
  ],
  "http": {
    "method": "GET",
    "path": "/api/v1/status",
    "headers": {
      "Host": "api.example.com",
      "User-Agent": "curl/7.88.1"
    }
  },
  "raw_hex": "..."
}
```

---

### 4. TCP Reassembled Stream Fields
If the TCP stream reassembly processor is active (via `-proc tcp-stream`), the cumulative stream bytes are exposed in `"stream_hex"`:

| Key | Type | Description |
|---|---|---|
| `stream_hex` | string | Cumulative hex representation of reassembled TCP stream bytes. |

---

## Python Integration Script Recipe

Below is a Python template that runs `netpipe` in a background subprocess, reads its JSON stdout stream, and processes HTTP requests:

```python
import subprocess
import json
import sys

# 1. Prepare command line
# -i: interface, -fmt: format, -q: suppress stderr logging
cmd = ["netpipe", "-i", "eth0", "-fmt", "json", "-q"]

# 2. Launch Subprocess
proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True
)

print("Listening for packets... Press Ctrl+C to terminate.")

try:
    # 3. Read Stream Line-by-Line
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        
        try:
            pkt = json.loads(line)
        except json.JSONDecodeError:
            continue
        
        # 4. Check for Decoded HTTP data
        http = pkt.get("http")
        if http and "method" in http:
            print(f"[{pkt['ts']}] HTTP Request: {http['method']} {http['path']} "
                  f"to Host: {http.get('headers', {}).get('Host', 'Unknown')}")

except KeyboardInterrupt:
    print("\nTerminating process...")
    proc.terminate()
    proc.wait()
    sys.exit(0)
```
