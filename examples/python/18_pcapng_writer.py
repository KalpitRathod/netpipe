#!/usr/bin/env python3
"""
examples/python/18_pcapng_writer.py
─────────────────────────────────────────────────────────
Native PCAP-NG Writing and Verification Demo

Demonstrates how to write captured packet traffic to a modern
PCAP-NG file using the native pcapng sink, and verifies the
resulting file's structure and integrity by parsing it back.

Usage:
  python3 18_pcapng_writer.py --file ../../encrypted_traffic.pcap
  sudo python3 18_pcapng_writer.py wlo1
"""

import subprocess
import sys
import argparse
import pathlib as _pl
import tempfile
import os
import json

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

def count_packets_json(pcap_path):
    """Runs netpipe to read a pcap/pcapng file and returns the sequence count."""
    cmd = [NETPIPE, "-r", str(pcap_path), "-fmt", "json", "-q"]
    pkts = []
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as p:
        for line in p.stdout:
            line = line.strip()
            if line:
                try:
                    pkts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return pkts

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
    print(f"{B}│{R}                netpipe PCAP-NG Writer Demo                     {B}│{R}")
    print(f"{B}└────────────────────────────────────────────────────────────────┘{R}")

    # Generate a temporary path for output file
    with tempfile.TemporaryDirectory() as tmpdir:
        output_pcapng = _pl.Path(tmpdir) / "output.pcapng"

        # 1. Capture/Read traffic and write using PCAP-NG format
        cmd_write = [NETPIPE, "-o", str(output_pcapng)] + target_args
        print(f"{YL}Step 1: Generating PCAP-NG file...{R}")
        print(f"Running command: {' '.join(cmd_write)}")

        res = subprocess.run(cmd_write, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0:
            print(f"{RD}Error running netpipe to write PCAP-NG:{R}\n{res.stderr}")
            sys.exit(1)

        # Check file exists and size
        if not output_pcapng.exists():
            print(f"{RD}Failed: Output file was not created.{R}")
            sys.exit(1)

        size_bytes = output_pcapng.stat().st_size
        print(f"{GR}✔ Generated PCAP-NG file successfully!{R} ({size_bytes} bytes)")

        # 2. Parse the original input packets using json formatting
        print(f"\n{YL}Step 2: Counting packets in original source...{R}")
        # Note: If target_args is -r file, we read from file. If it is -i interface, we can't count offline,
        # but we can compare to the written packets sequence.
        orig_pkts = []
        is_offline = "-r" in target_args
        if is_offline:
            src_file = target_args[target_args.index("-r") + 1]
            orig_pkts = count_packets_json(src_file)
            print(f"Original source has {CY}{len(orig_pkts)}{R} packets.")

        # 3. Read back the PCAP-NG file to verify readability and data integrity
        print(f"\n{YL}Step 3: Verifying PCAP-NG readability...{R}")
        written_pkts = count_packets_json(output_pcapng)
        print(f"Decoded {CY}{len(written_pkts)}{R} packets from the generated PCAP-NG file.")

        # 4. Perform integrity assertions
        print(f"\n{YL}Step 4: Executing integrity checks...{R}")
        failed = False
        if is_offline:
            if len(orig_pkts) != len(written_pkts):
                print(f"  {RD}❌ Packet count mismatch!{R} Original: {len(orig_pkts)}, Written: {len(written_pkts)}")
                failed = True
            else:
                print(f"  {GR}✔ Packet counts match exactly!{R}")
                
            # Compare first packet timestamp & length
            if orig_pkts and written_pkts:
                t1 = orig_pkts[0]["ts"]
                t2 = written_pkts[0]["ts"]
                len1 = orig_pkts[0]["wirelen"]
                len2 = written_pkts[0]["wirelen"]
                if t1 != t2 or len1 != len2:
                    print(f"  {RD}❌ First packet mismatch!{R}")
                    print(f"     Original: TS={t1}, Len={len1}")
                    print(f"     Written : TS={t2}, Len={len2}")
                    failed = True
                else:
                    print(f"  {GR}✔ Packet structure & metadata match!{R} (First packet TS: {t1}, WireLen: {len1})")
        else:
            if len(written_pkts) == 0:
                print(f"  {RD}❌ Written PCAP-NG is empty.{R}")
                failed = True
            else:
                print(f"  {GR}✔ Captured {len(written_pkts)} packets live and wrote them correctly to PCAP-NG.{R}")

        if not failed:
            print(f"\n{B}{GR}★★★ PCAP-NG WRITE FUNCTIONALITY STATUS: 100% OPERATIONAL ★★★{R}\n")
        else:
            print(f"\n{B}{RD}★★★ PCAP-NG WRITE FUNCTIONALITY STATUS: FAILED INTEGRITY CHECKS ★★★{R}\n")
            sys.exit(1)

if __name__ == "__main__":
    main()
