#!/usr/bin/env python3
"""
examples/python/01_dns_monitor.py
───────────────────────────────────
Real-time DNS query monitor.

Shows every domain your machine looks up, who asked (flow_id),
and alerts when a domain appears more than N times (possible DGA / C2).

Usage:
    sudo python3 01_dns_monitor.py wlo1
    sudo python3 01_dns_monitor.py wlo1 --alert-threshold 5
"""

import subprocess, sys, json, argparse, re
from collections import Counter
from datetime import datetime

import pathlib as _pl
_HERE = _pl.Path(__file__).resolve().parent
NETPIPE = str(next(
    (p for p in [
        _HERE / "../../build/bin/netpipe",
        _pl.Path("/usr/local/bin/netpipe"),
        _pl.Path("/usr/bin/netpipe"),
    ] if p.exists()), _HERE / "../../build/bin/netpipe"
))

ALERT_COLOUR  = "\033[1;31m"  # bold red
INFO_COLOUR   = "\033[36m"    # cyan
RESET         = "\033[0m"

def decode_dns_name(raw_hex: str) -> str:
    """
    Decode the first DNS question name from a raw hex payload string.
    DNS payload starts after the 12-byte header (24 hex chars).
    """
    try:
        data = bytes.fromhex(raw_hex)
        # DNS header is 12 bytes; question section follows
        pos = 12
        labels = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:  # compression pointer
                break
            pos += 1
            labels.append(data[pos:pos+length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(labels) if labels else "(unknown)"
    except Exception:
        return "(parse error)"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("interface", help="network interface (e.g. wlo1)")
    ap.add_argument("--alert-threshold", "-a", type=int, default=10,
                    help="alert when a domain is queried this many times (default 10)")
    ap.add_argument("--show-responses", action="store_true",
                    help="also show DNS responses (not just queries)")
    args = ap.parse_args()

    cmd = [NETPIPE, "-i", args.interface, "-proto", "dns", "-fmt", "json", "-q"]
    print(f"\033[1mDNS Monitor\033[0m on {args.interface}  (Ctrl-C to stop)\n")
    print(f"{'TIME':<12}  {'TYPE':<6}  {'DOMAIN'}")
    print("─" * 60)

    query_counter: Counter = Counter()
    alerted: set = set()

    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True) as proc:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                pkt = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Find the DNS layer
            dns_layer = next((l for l in pkt["layers"] if l["proto"] == "dns"), None)
            if not dns_layer:
                continue

            raw_hex = pkt.get("raw_hex", "")
            # Determine query vs response from flags byte in DNS header
            # flags are bytes 2-3 of DNS payload
            # DNS payload starts inside the UDP payload; raw_hex is full frame
            # We parse raw_hex to find DNS data
            domain = decode_dns_name(raw_hex)

            # Detect query vs response:
            # In the raw_hex the DNS header starts after Eth(14)+IP(20)+UDP(8) = 42 bytes
            is_response = False
            try:
                eth_ip_udp = 14 + 20 + 8  # bytes
                flags_offset = eth_ip_udp * 2 + 4  # +4 hex chars for DNS ID
                flags = int(raw_hex[flags_offset:flags_offset+4], 16)
                is_response = bool(flags & 0x8000)
            except Exception:
                pass

            if is_response and not args.show_responses:
                continue

            ptype = "RESP " if is_response else "QUERY"
            ts    = pkt["ts"].split(".")[0]  # HH:MM:SS

            if not is_response:
                query_counter[domain] += 1
                count = query_counter[domain]

                # Alert on threshold breach
                if count >= args.alert_threshold and domain not in alerted:
                    alerted.add(domain)
                    print(f"\n{ALERT_COLOUR}⚠ ALERT: '{domain}' queried {count} times — possible DGA/C2!{RESET}\n")

                colour = ALERT_COLOUR if domain in alerted else INFO_COLOUR
                print(f"{ts:<12}  {colour}{ptype}{RESET}  {domain}  "
                      f"(\033[2m×{count}\033[0m)")
            else:
                print(f"{ts:<12}  {ptype}  {domain}")

if __name__ == "__main__":
    main()
