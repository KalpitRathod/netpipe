#!/usr/bin/env python3
"""
examples/python/16_payload_transform.py
─────────────────────────────────────────────────────────
Payload Transformation Demo (Payload Transform Processor)

Demonstrates how to use the netpipe payload transform processor
(-proc transform:<hex|base64|regex:pat:rep>) to dynamically modify,
encode, or redact application layer payloads.

Runs netpipe as a subprocess, streams JSON packets, and showcases:
  1. Base64 transform mode and decoding it back in Python.
  2. Hex transform mode.
  3. Regex redact/replace transform mode.

Usage:
  python3 16_payload_transform.py --file ../../encrypted_traffic.pcap
  sudo python3 16_payload_transform.py wlo1
"""

import subprocess
import sys
import json
import argparse
import base64
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
R  = "\033[0m";  B  = "\033[1m"
CY = "\033[36m"; YL = "\033[33m"; GR = "\033[32m"; RD = "\033[31m"; MG = "\033[35m"

def run_transform_demo(cmd_args, title, mode):
    cmd = [NETPIPE, "-fmt", "json", "-q"] + cmd_args
    print(f"\n{B}=== {title} ==={R}")
    print(f"{YL}Running command:{R} {' '.join(cmd)}")

    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
            count = 0
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    pkt = json.loads(line)
                except json.JSONDecodeError:
                    continue

                count += 1
                protos = " → ".join(l["proto"] for l in pkt["layers"])
                print(f"\n[{GR}Packet #{pkt['seq']}{R}] Flow: {pkt['flow_id']} | Stack: {protos}")
                print(f"  Raw Hex (first 32 bytes): {CY}{pkt['raw_hex'][:64]}{R}")

                if "stream_hex" in pkt:
                    # Sinks format stream_data/stream_len as a hex string in JSON output
                    stream_hex = pkt["stream_hex"]
                    # Convert the hex representation back to bytes
                    transformed_bytes = bytes.fromhex(stream_hex)

                    print(f"  Transformed Hex         : {MG}{stream_hex[:120]}{'...' if len(stream_hex) > 120 else ''}{R}")
                    
                    if mode == "base64":
                        try:
                            # The transformed_bytes is the base64 string itself
                            b64_str = transformed_bytes.decode('utf-8', errors='ignore')
                            print(f"  Base64 Payload String   : {CY}{b64_str}{R}")
                            # Let's decode it back to show original bytes
                            decoded = base64.b64decode(b64_str)
                            print(f"  Decoded back to Hex     : {GR}{decoded.hex()[:120]}{'...' if len(decoded.hex()) > 120 else ''}{R}")
                        except Exception as e:
                            print(f"  Error decoding base64: {e}")
                    elif mode == "regex":
                        text = transformed_bytes.decode('utf-8', errors='ignore')
                        print(f"  Regex Replaced Text     : {CY}{text}{R}")
                    else:
                        print(f"  Transformed Raw Bytes   : {CY}{transformed_bytes.decode('utf-8', errors='ignore')[:120]}{R}")
                else:
                    print(f"  {RD}No transformed stream payload found (empty application payload){R}")

                if count >= 3:  # Show up to 3 packets for the demo
                    break
            
            # Clean stop of process
            proc.terminate()
    except FileNotFoundError:
        print(f"{RD}Error:{R} netpipe binary not found. Please compile it first using 'make' or 'make debug'.")
        sys.exit(1)

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
    print(f"{B}│{R}          netpipe Payload Transform Processor Demo              {B}│{R}")
    print(f"{B}└────────────────────────────────────────────────────────────────┘{R}")

    # Demo 1: Hex Transformation
    run_transform_demo(
        target_args + ["-proc", "transform:hex", "-c", "2"],
        "Demo 1: Hex Transform Mode (-proc transform:hex)",
        "hex"
    )

    # Demo 2: Base64 Transformation
    run_transform_demo(
        target_args + ["-proc", "transform:base64", "-c", "2"],
        "Demo 2: Base64 Transform Mode (-proc transform:base64)",
        "base64"
    )

    # Demo 3: Regex replacement to redact/replace TLS header (170303 in hex)
    # Note: Regex pattern matching on binary payload is possible via raw bytes,
    # but works best on text-based protocols (like DNS / HTTP).
    # Here, we replace \x17\x03\x03 (TLS Record Header) with "[TLS_HDR]"
    # We use printf to supply binary bytes to the regex processor
    binary_pattern = "\x17\x03\x03"
    run_transform_demo(
        target_args + ["-proc", f"transform:regex:{binary_pattern}:[REDACTED_TLS_HDR]", "-c", "2"],
        "Demo 3: Regex Replace Mode (-proc transform:regex:...)",
        "regex"
    )

if __name__ == "__main__":
    main()
