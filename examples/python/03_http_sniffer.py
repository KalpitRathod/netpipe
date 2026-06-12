#!/usr/bin/env python3
"""
examples/python/03_http_sniffer.py
────────────────────────────────────
Sniff HTTP requests in real time and log them to a file.

Extracts: timestamp, method, URL, Host header, response code, size.
Writes a structured log to http_log.jsonl (append mode).

Usage:
    sudo python3 03_http_sniffer.py wlo1
    sudo python3 03_http_sniffer.py wlo1 --port 8080 --log my_log.jsonl
"""

import subprocess, sys, json, argparse, re, signal, time
from datetime import datetime

NETPIPE = "../../build/bin/netpipe"

REQUEST_RE  = re.compile(
    rb"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP/[\d.]+\r?\n"
    rb"(.*?)\r?\n\r?\n",
    re.DOTALL
)
RESPONSE_RE = re.compile(rb"^HTTP/[\d.]+\s+(\d{3})")
HOST_RE     = re.compile(rb"Host:\s*(.+?)\r?\n", re.IGNORECASE)


def parse_http(raw_hex: str, caplen: int):
    """
    Attempt to extract HTTP layer from raw packet hex.
    Returns a dict with method/url/host or status_code, or None.
    """
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        return None

    # Try from various offsets (Eth+IP+TCP is typically 54 bytes but IHL can vary)
    for offset in (54, 66, 78, 42):
        payload = data[offset:]
        if len(payload) < 8:
            continue

        m = REQUEST_RE.match(payload)
        if m:
            method = m.group(1).decode("ascii", errors="replace")
            path   = m.group(2).decode("ascii", errors="replace")
            headers_raw = m.group(3)
            hm = HOST_RE.search(headers_raw)
            host = hm.group(1).decode("ascii", errors="replace").strip() if hm else ""
            return {"type": "request", "method": method, "path": path,
                    "host": host, "url": f"http://{host}{path}"}

        m = RESPONSE_RE.match(payload)
        if m:
            code = int(m.group(1))
            return {"type": "response", "status": code, "size": caplen}

    return None


def colour_status(code):
    if code < 300:   return f"\033[32m{code}\033[0m"
    elif code < 400: return f"\033[33m{code}\033[0m"
    else:            return f"\033[31m{code}\033[0m"


def colour_method(method):
    colours = {"GET":"\033[32m","POST":"\033[34m","PUT":"\033[33m",
                "DELETE":"\033[31m","PATCH":"\033[35m"}
    return f"{colours.get(method, '')}{method}\033[0m"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("interface", help="network interface")
    ap.add_argument("--port", "-p", type=int, default=80)
    ap.add_argument("--log", "-l", default="http_log.jsonl")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="suppress terminal output, just write log file")
    args = ap.parse_args()

    cmd = [NETPIPE, "-i", args.interface,
           "-port", str(args.port),
           "-fmt", "json", "-q"]

    if not args.quiet:
        print(f"\033[1mHTTP Sniffer\033[0m on {args.interface}:{args.port}  "
              f"→  {args.log}  (Ctrl-C to stop)\n")
        print(f"{'TIME':<10}  {'METHOD':<8}  {'STATUS':<8}  {'HOST + PATH'}")
        print("─" * 80)

    log_fh = open(args.log, "a")

    def stop(sig, frame):
        log_fh.flush()
        log_fh.close()
        sys.exit(0)
    signal.signal(signal.SIGINT, stop)

    with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True) as proc:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                pkt = json.loads(line)
            except json.JSONDecodeError:
                continue

            http = parse_http(pkt.get("raw_hex", ""), pkt["caplen"])
            if not http:
                continue

            ts   = pkt["ts"].split(".")[0]
            http["ts"]      = pkt["ts"]
            http["flow_id"] = pkt["flow_id"]
            http["caplen"]  = pkt["caplen"]

            # Write to log
            log_fh.write(json.dumps(http) + "\n")
            log_fh.flush()

            if not args.quiet:
                if http["type"] == "request":
                    print(f"{ts}  {colour_method(http['method']):<8}  "
                          f"{'→':<8}  {http['host']}{http['path']}")
                else:
                    print(f"{ts}  {'←':<8}  {colour_status(http['status']):<8}  "
                          f"{http['size']} bytes")

if __name__ == "__main__":
    main()
