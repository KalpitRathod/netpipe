#!/usr/bin/env python3
"""
examples/python/09_stream_follower.py
───────────────────────────────────────
Reassembles TCP fragments into continuous streams.
This script demonstrates the Deep Packet Inspection (DPI) capabilities
of the `netpipe` engine by using the C-level TCP stream processor.

Usage:
    sudo python3 09_stream_follower.py wlo1
    (Then run: curl http://neverssl.com)
"""

import subprocess, sys, json, os

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
        print("Usage: sudo python3 09_stream_follower.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    
    # We enable the TCP stream reassembler via -proc tcp-stream
    # We also filter by -port 80 to avoid showing encrypted HTTPS traffic which looks like garbled text!
    cmd = [NETPIPE, "-i", interface, "-port", "80", "-proc", "tcp-stream", "-fmt", "json", "-q"]
    
    print(f"\033[1mTCP Stream Follower\033[0m on {interface}")
    print("Run \033[36mcurl http://neverssl.com\033[0m in another terminal to see HTTP reassembly!")
    print("Waiting for TCP data...\n")

    # Keep track of how many bytes we have printed for each flow
    # to avoid printing the same historical stream buffer over and over.
    flow_cursors = {}

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

                stream_hex = pkt.get("stream_hex")
                if not stream_hex:
                    continue

                flow_id = pkt["flow_id"]
                
                # Decode the raw hex into an ASCII string
                try:
                    raw_bytes = bytes.fromhex(stream_hex)
                    text = raw_bytes.decode("ascii", errors="replace")
                except Exception:
                    continue

                # Only print the newly reassembled characters
                cursor = flow_cursors.get(flow_id, 0)
                if len(text) > cursor:
                    new_chunk = text[cursor:]
                    
                    # Print it nicely with the Flow ID as a prefix
                    for chunk_line in new_chunk.splitlines(keepends=True):
                        # Filter out completely garbled non-printable lines 
                        # to keep the terminal clean (e.g. from TLS encrypted streams)
                        printable = sum(1 for c in chunk_line if c.isprintable() or c in '\r\n\t')
                        if len(chunk_line) > 0 and printable / len(chunk_line) > 0.5:
                            print(f"\033[32m[Flow {flow_id}]\033[0m {chunk_line}", end="")
                    
                    # Update our cursor so we only print new data next time
                    flow_cursors[flow_id] = len(text)
                    sys.stdout.flush()

        except KeyboardInterrupt:
            print("\nStopped.")

if __name__ == "__main__":
    main()
