#!/usr/bin/env python3
"""
examples/python/13_dns_spy.py
───────────────────────────────────────
Demonstrates the native DNS decoder built into the C core.

Instead of parsing raw UDP payloads, this script asks the netpipe engine
for JSON formatted output and simply extracts the natively decoded
DNS queries and answers (A, AAAA, CNAME).

Usage:
    sudo python3 13_dns_spy.py wlo1
    (Then browse the web or run: ping google.com)
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
        print("Usage: sudo python3 13_dns_spy.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    
    # We use -proto dns to capture all DNS traffic (UDP/TCP, port 53)
    cmd = [NETPIPE, "-i", interface, "-proto", "dns", "-fmt", "json", "-q"]
    
    print(f"\033[1mNative DNS Spy\033[0m on {interface}")
    print("Run \033[36mping google.com\033[0m or browse the web to see DNS queries natively decoded!")
    print("Waiting for DNS data...\n")

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

                dns_data = pkt.get("dns")
                if not dns_data:
                    continue

                # It's a DNS Query or Response
                if not dns_data["is_response"]:
                    q = dns_data.get("query")
                    if q:
                        name = q.get("name", "Unknown")
                        type_ = "A/AAAA" if q.get("type") in [1, 28] else f"Type {q.get('type')}"
                        print(f"[\033[1;36mDNS Query\033[0m]    Who is \033[1;33m{name}\033[0m? ({type_})")
                else:
                    answers = dns_data.get("answers", [])
                    for ans in answers:
                        name = ans.get("name", "Unknown")
                        data = ans.get("data", "Unknown")
                        # Highlight resolved IPs
                        print(f"[\033[1;32mDNS Response\033[0m] \033[1;33m{name}\033[0m is at \033[1;37m{data}\033[0m")

        except KeyboardInterrupt:
            print("\nStopped.")

if __name__ == "__main__":
    main()
