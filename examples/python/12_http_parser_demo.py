#!/usr/bin/env python3
"""
examples/python/12_http_parser_demo.py
───────────────────────────────────────
Demonstrates the native HTTP/1.1 demuxer built into the C core.

Instead of looking at raw packet bytes or manually reassembling streams,
this script leverages the new C-level HTTP parser that natively extracts
methods, paths, status codes, and HTTP headers from live traffic.

Usage:
    sudo python3 12_http_parser_demo.py wlo1
    (Then run: curl http://neverssl.com)
"""

import subprocess, sys, json
import pathlib as _pl

_HERE = _pl.Path(__file__).resolve().parent
NETPIPE = str(next(
    (p for p in [
        _HERE / "../../build/bin/netpipe",
        _pl.Path("/usr/local/bin/netpipe"),
        _pl.Path("/usr/bin/netpipe"),
    ] if p.exists()), _HERE / "../../build/bin/netpipe"
))

def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 12_http_parser_demo.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    
    # We use -port 80 to capture standard plaintext HTTP traffic
    # The JSON sink natively outputs the 'http' dictionary if the demuxer successfully parsed it
    cmd = [NETPIPE, "-i", interface, "-port", "80", "-fmt", "json", "-q"]
    
    print(f"\033[1mNative HTTP/1.1 Parser Demo\033[0m on {interface}")
    print("Run \033[36mcurl http://neverssl.com\033[0m in another terminal to see HTTP objects natively decoded!")
    print("Waiting for HTTP data...\n")

    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as proc:
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    pkt = json.loads(line)
                except json.JSONDecodeError:
                    continue

                http_data = pkt.get("http")
                if not http_data:
                    continue

                flow_id = pkt["flow_id"]
                
                print(f"┌── \033[1;35mHTTP Layer Detected\033[0m (Flow: {flow_id}) ─────────────────────")
                
                if "method" in http_data:
                    # It's an HTTP Request
                    method = http_data["method"]
                    path = http_data["path"]
                    print(f"│ \033[1;36mRequest\033[0m : {method} {path}")
                elif "status" in http_data:
                    # It's an HTTP Response
                    status = http_data["status"]
                    phrase = http_data["phrase"]
                    color = "\033[1;32m" if status < 400 else "\033[1;31m"
                    print(f"│ \033[1;36mResponse\033[0m: {color}{status} {phrase}\033[0m")
                
                # Print Headers
                headers = http_data.get("headers", {})
                if headers:
                    print("│ \033[1;33mHeaders\033[0m :")
                    for k, v in headers.items():
                        print(f"│   {k}: {v}")
                
                print(f"└────────────────────────────────────────────────────────\n")

        except KeyboardInterrupt:
            print("\nStopped.")

if __name__ == "__main__":
    main()
