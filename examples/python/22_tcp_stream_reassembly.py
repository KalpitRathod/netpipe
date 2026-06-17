#!/usr/bin/env python3
"""
22_tcp_stream_reassembly.py — TCP stream reassembly via -proc tcp-stream

Demonstrates how netpipe's tcp-stream processor reconstructs a full
application-layer payload from individual TCP segments.  Runs offline
against the bundled HTTP fixture so no root is required.

What you will see
─────────────────
• The raw JSON record for the HTTP packet
• stream_hex decoded into readable ASCII
• The HTTP method, path, and headers extracted from the reassembled buffer

Run:
    python3 examples/python/22_tcp_stream_reassembly.py
"""

import subprocess
import json
import binascii
import sys
import os

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
BIN       = os.path.join(REPO_ROOT, "build", "bin", "netpipe")
FIXTURE   = os.path.join(REPO_ROOT, "tests", "fixtures", "ipv4_tcp_http.pcap")


def run_pipeline(*args):
    cmd = [BIN] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return result.stdout, result.stderr


def main():
    print("=" * 60)
    print(" netpipe — Example 22: TCP Stream Reassembly")
    print("=" * 60)

    # ── 1. Basic tcp-stream JSON output ──────────────────────────────
    print("\n[1] Raw JSON record with tcp-stream processor:\n")
    stdout, stderr = run_pipeline(
        "-r", FIXTURE,
        "-proc", "tcp-stream",
        "-fmt", "json"
    )

    packets = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    if not packets:
        print("ERROR: no JSON output from pipeline", file=sys.stderr)
        print("stderr:", stderr, file=sys.stderr)
        sys.exit(1)

    pkt = packets[0]
    print(json.dumps(pkt, indent=2))

    # ── 2. Decode stream_hex → ASCII payload ─────────────────────────
    print("\n[2] Decoded TCP stream payload (stream_hex → ASCII):\n")
    stream_hex = pkt.get("stream_hex", "")
    if stream_hex:
        try:
            raw_bytes = binascii.unhexlify(stream_hex)
            print(raw_bytes.decode("utf-8", errors="replace"))
        except Exception as e:
            print(f"  decode error: {e}")
    else:
        print("  (no stream_hex field — packet may not be TCP)")

    # ── 3. Extract HTTP fields from decoded app layer ─────────────────
    print("\n[3] HTTP fields from demuxer (zero-copy decode):\n")
    http = pkt.get("http", {})
    if http:
        for key, val in http.items():
            if isinstance(val, dict):
                print(f"  {key}:")
                for hname, hval in val.items():
                    print(f"    {hname}: {hval}")
            else:
                print(f"  {key}: {val}")
    else:
        print("  (no http field)")

    # ── 4. Chain: tcp-stream + flow-tracker ──────────────────────────
    print("\n[4] tcp-stream + flow-tracker chained — flow summary:\n")
    _, combined_out = run_pipeline(
        "-r", FIXTURE,
        "-proc", "tcp-stream",
        "-proc", "flow-tracker"
    )
    # flow summary goes to stderr
    stdout2, stderr2 = run_pipeline(
        "-r", FIXTURE,
        "-proc", "tcp-stream",
        "-proc", "flow-tracker",
        "-fmt", "null"
    )
    for line in stderr2.splitlines():
        if "FLOW" in line or "TCP" in line or "UDP" in line or "Total" in line:
            print(" ", line)

    print("\nDone.")


if __name__ == "__main__":
    main()
