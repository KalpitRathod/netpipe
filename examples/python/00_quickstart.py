#!/usr/bin/env python3
"""
examples/python/00_quickstart.py
─────────────────────────────────
The absolute simplest way to use netpipe from Python.
Runs netpipe, reads JSON packets line-by-line, prints them.

Usage:
    sudo python3 00_quickstart.py wlo1
    python3 00_quickstart.py --file capture.pcap
"""

import subprocess, sys, json, argparse

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
    ap = argparse.ArgumentParser()
    ap.add_argument("interface", nargs="?", help="live interface (e.g. wlo1)")
    ap.add_argument("--file", "-r",         help="read from pcap file instead")
    ap.add_argument("--count", "-c", type=int, default=20, help="packet limit")
    args = ap.parse_args()

    cmd = [NETPIPE, "-fmt", "json", "-c", str(args.count)]
    if args.file:
        cmd += ["-r", args.file]
    elif args.interface:
        cmd += ["-i", args.interface]
    else:
        sys.exit("specify an interface or --file")

    print(f"Running: {' '.join(cmd)}\n")

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

            protos = " → ".join(l["proto"] for l in pkt["layers"])
            print(f"#{pkt['seq']:>5}  {pkt['ts']}  {pkt['caplen']:>5}B  {protos}")

if __name__ == "__main__":
    main()
