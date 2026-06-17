#!/usr/bin/env python3
"""
examples/python/17_flow_tracker.py
─────────────────────────────────────────────────────────
Flow Tracker and Connection State Monitoring Demo

Demonstrates how to run the netpipe flow tracker processor
(-proc flow-tracker) to track per-5-tuple network sessions,
monitor active connections, and extract flow durations, 
packet counts, byte counts, and observed TCP states.

Usage:
  python3 17_flow_tracker.py --file ../../encrypted_traffic.pcap
  sudo python3 17_flow_tracker.py wlo1
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
CY = "\033[36m"; YL = "\033[33m"; GR = "\033[32m"; RD = "\033[31m"; MG = "\033[35m"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("interface", nargs="?", help="live interface (e.g. wlo1)")
    ap.add_argument("--file", "-r", help="read from pcap file instead")
    args = ap.parse_args()

    # Default to sample pcap if no input is provided
    target_args = []
    if args.file:
        target_args = ["-r", args.file]
    elif args.interface:
        target_args = ["-i", args.interface]
    else:
        # Fall back to encrypted_traffic.pcap in repo root if it exists
        fallback_pcap = _HERE / "../../encrypted_traffic.pcap"
        if fallback_pcap.exists():
            print(f"No input specified. Defaulting to local file: {fallback_pcap.name}")
            target_args = ["-r", str(fallback_pcap)]
        else:
            sys.exit("specify an interface or --file")

    print(f"\n{B}┌────────────────────────────────────────────────────────────────┐{R}")
    print(f"{B}│{R}                netpipe Flow Tracker Processor Demo             {B}│{R}")
    print(f"{B}└────────────────────────────────────────────────────────────────┘{R}")

    # We use -fmt null so that netpipe does not print packets to stdout.
    # The flow tracker will print its final table to stdout when it finishes/exits.
    cmd = [NETPIPE, "-fmt", "null", "-proc", "flow-tracker"] + target_args
    print(f"{YL}Running command:{R} {' '.join(cmd)}\n")

    print(f"{B}--- Real-time Discovery Events (captured from stderr/stdout logs) ---{R}")

    try:
        # We start the process and read stdout/stderr line by line
        # Stderr contains the INFO logs for New Flow discovery.
        # Stdout contains the final summary table once closed.
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Print discovery events in real-time
        # Since the process runs until completion (PCAP exhausted or Ctrl-C),
        # we can read from stderr to watch for "New Flow Tracked:" lines.
        # We wait for the command to finish and then read all stdout for the table.
        stdout_data, stderr_data = proc.communicate()

        # Print real-time flow discovery logs nicely
        for line in stderr_data.splitlines():
            if "New Flow Tracked:" in line:
                # Highlight the new flow discovery
                parts = line.split("New Flow Tracked:")
                prefix = parts[0].strip()
                flow_info = parts[1].strip()
                print(f"{GR}⚡ New Session Tracked:{R} {CY}{flow_info}{R} ({prefix})")
            elif "pipeline running" in line or "pipeline stopped" in line:
                print(f"{YL}Info:{R} {line}")

        print(f"\n{B}--- Final Flow Summary Table ---{R}")
        if stdout_data.strip():
            print(stdout_data)
        else:
            print(f"{RD}No summary table printed. Did netpipe execute successfully?{R}")

    except FileNotFoundError:
        print(f"{RD}Error:{R} netpipe binary not found. Please compile it first using 'make' or 'make debug'.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nDemo interrupted.")

if __name__ == "__main__":
    main()
