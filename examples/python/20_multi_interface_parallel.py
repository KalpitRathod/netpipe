#!/usr/bin/env python3
"""
examples/python/20_multi_interface_parallel.py
─────────────────────────────────────────────────────────
Parallel Multi-Interface Capture Integration Demo

Demonstrates how netpipe captures concurrently from multiple
sources using internal worker threads and fans the packets
into a single thread-safe event pipeline.

Usage:
  python3 20_multi_interface_parallel.py --file ../../encrypted_traffic.pcap
"""

import subprocess
import sys
import argparse
import pathlib as _pl

_HERE = _pl.Path(__file__).resolve().parent
NETPIPE = str(next(
    (p for p in [
        _HERE / "../../build/bin/netpipe",
        _pl.Path("/usr/local/bin/netpipe"),
        _pl.Path("/usr/bin/netpipe"),
    ] if p.exists()), _HERE / "../../build/bin/netpipe"
))

# ─── colours ─────────────────────────────────────────────────────────────────
B  = "\033[1m"; R  = "\033[0m"
CY = "\033[36m"; YL = "\033[33m"; GR = "\033[32m"; RD = "\033[31m"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("interfaces", nargs="*", help="live interfaces (e.g. eth0 wlan0)")
    ap.add_argument("--file", "-r", help="read from pcap file instead")
    args = ap.parse_args()

    target_args = []
    if args.file:
        # Replicate the single file twice to test parallel processing
        target_args = ["-r", args.file, "-r", args.file]
    elif args.interfaces:
        for val in args.interfaces:
            target_args += ["-i", val]
    else:
        # Fall back to encrypted_traffic.pcap in repo root if it exists
        fallback_pcap = _HERE / "../../encrypted_traffic.pcap"
        if fallback_pcap.exists():
            print(f"No inputs specified. Defaulting to dual file reader on: {fallback_pcap.name}")
            target_args = ["-r", str(fallback_pcap), "-r", str(fallback_pcap)]
        else:
            sys.exit("specify interfaces or --file")

    print(f"\n{B}┌────────────────────────────────────────────────────────────────┐{R}")
    print(f"{B}│{R}          netpipe Parallel Multi-Interface Capture Demo         {B}│{R}")
    print(f"{B}└────────────────────────────────────────────────────────────────┘{R}")

    # Run netpipe with multiple inputs (no -q so INFO level logs are printed to stderr)
    cmd = [NETPIPE] + target_args
    print(f"{YL}Running netpipe with parallel sources:{R}")
    print(f"Command: {' '.join(cmd)}\n")

    # Capture output
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # We can print a snippet of stdout to avoid flooding the terminal
    lines = res.stdout.splitlines()
    if len(lines) > 20:
        print("\n".join(lines[:10]))
        print(f"\n... [truncated {len(lines) - 20} lines of packet printout] ...\n")
        print("\n".join(lines[-10:]))
    else:
        print(res.stdout)
        
    print(f"{YL}--- Stderr output ---{R}")
    print(res.stderr)

    if res.returncode != 0:
        print(f"{RD}❌ netpipe failed with return code {res.returncode}{R}")
        sys.exit(res.returncode)

    # If we ran on the default dual encrypted_traffic.pcap, we expect exactly 74 packets (37 * 2)
    if not args.interfaces and (not args.file or "encrypted_traffic.pcap" in args.file):
        if "captured=74" in res.stderr and "processed=74" in res.stderr:
            print(f"{GR}✔ Parallel multi-source capture matched expected counts (74 packets from both files)!{R}")
            print(f"\n{B}{GR}★★★ MULTI-INTERFACE CAPTURE STATUS: 100% OPERATIONAL ★★★{R}\n")
        else:
            print(f"{RD}❌ Output did not match expected statistics (expected 74 packets, got: {res.stderr}).{R}")
            sys.exit(1)
    else:
        # General live or custom capture
        if "captured=" in res.stderr:
            print(f"{GR}✔ Parallel multi-source capture executed successfully!{R}")
            print(f"\n{B}{GR}★★★ MULTI-INTERFACE CAPTURE STATUS: 100% OPERATIONAL ★★★{R}\n")
        else:
            print(f"{RD}❌ Output did not match expected statistics.{R}")
            sys.exit(1)

if __name__ == "__main__":
    main()
