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

def decode_dns_name(raw: bytes, offset: int) -> str:
    """Decode a DNS wire-format name starting at `offset`."""
    labels = []
    visited = set()
    pos = offset
    try:
        while pos < len(raw):
            if pos in visited:
                break
            visited.add(pos)
            length = raw[pos]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:      # compression pointer
                if pos + 1 >= len(raw):
                    break
                ptr = ((length & 0x3F) << 8) | raw[pos + 1]
                pos = ptr
                continue
            pos += 1
            labels.append(raw[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
    except Exception:
        pass
    return ".".join(labels) if labels else ""

def extract_dns(raw_hex: str):
    """
    Extract DNS question names from a raw frame.
    Returns list of (name, is_response) tuples.
    """
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return []

    # DNS over UDP: Eth(14) + IP(20) + UDP(8) = offset 42
    dns_offsets = [42]
    # DNS over TCP (port 53): Eth(14)+IP(20)+TCP(20)+2-byte length prefix = 56
    dns_offsets.append(56)

    results = []
    for off in dns_offsets:
        if off + 12 >= len(raw):
            continue
        d = raw[off:]
        if len(d) < 12:
            continue
        flags     = (d[2] << 8) | d[3]
        qdcount   = (d[4] << 8) | d[5]
        is_resp   = bool(flags & 0x8000)
        if qdcount == 0 or qdcount > 16:
            continue
        name = decode_dns_name(d, 12)
        if name and "." in name:
            results.append((name, is_resp))
            break
    return results

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
            for domain, is_response in extract_dns(raw_hex):
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
