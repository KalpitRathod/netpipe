#!/usr/bin/env python3
"""
examples/python/04_anomaly_detector.py
────────────────────────────────────────
Simple statistical anomaly detector for live traffic.

Detects:
  • Port scan  — single flow_id hits > N distinct ports in a short window
  • Flood      — packet rate spikes beyond baseline × threshold
  • Large pkt  — any packet larger than threshold bytes
  • New proto  — a protocol appears for the first time (useful in locked-down nets)

Usage:
    sudo python3 04_anomaly_detector.py wlo1
    sudo python3 04_anomaly_detector.py wlo1 --flood-multiplier 5 --scan-threshold 15
"""

import subprocess, sys, json, argparse, time, signal, threading
from collections import defaultdict, deque

NETPIPE = "../../build/bin/netpipe"

RED    = "\033[1;31m"
YELLOW = "\033[1;33m"
GREEN  = "\033[32m"
RESET  = "\033[0m"
DIM    = "\033[2m"


def alert(category: str, msg: str):
    ts = time.strftime("%H:%M:%S")
    colour = RED if "FLOOD" in category or "SCAN" in category else YELLOW
    print(f"\n{colour}[{ts}] ⚠  {category}: {msg}{RESET}\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("interface")
    ap.add_argument("--flood-multiplier", type=float, default=4.0,
                    help="alert when pps exceeds baseline × this (default 4)")
    ap.add_argument("--scan-threshold",   type=int,   default=20,
                    help="alert when one flow hits this many unique ports (default 20)")
    ap.add_argument("--large-pkt",        type=int,   default=1400,
                    help="alert on packets larger than this many bytes (default 1400)")
    ap.add_argument("--window",           type=float, default=5.0,
                    help="sliding window in seconds for rate baseline (default 5)")
    args = ap.parse_args()

    cmd = [NETPIPE, "-i", args.interface, "-fmt", "json", "-q"]
    print(f"\033[1mAnomaly Detector\033[0m on {args.interface}  (Ctrl-C to stop)\n")

    # State
    pkt_times:   deque  = deque()                     # timestamps in window
    flow_ports:  dict   = defaultdict(set)            # flow_id → set of ports seen
    known_protos: set   = set()
    alerted_scans: set  = set()
    baseline_pps: float = 0.0
    flood_alerted: bool = False
    total: int = 0

    def get_ports_from_pkt(pkt):
        """Extract src/dst port from transport layer raw data."""
        transport = next(
            (l for l in pkt["layers"] if l["proto"] in ("tcp","udp")),
            None
        )
        if not transport:
            return []
        try:
            raw = bytes.fromhex(pkt["raw_hex"])
            # port offset depends on L2/L3 header sizes
            # Eth(14)+IP(20) = 34 bytes; ports are first 4 bytes of TCP/UDP
            src = int.from_bytes(raw[34:36], "big")
            dst = int.from_bytes(raw[36:38], "big")
            return [src, dst]
        except Exception:
            return []

    running = True
    def stop(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGINT, stop)

    with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True) as proc:
        for line in proc.stdout:
            if not running:
                break
            line = line.strip()
            if not line:
                continue
            try:
                pkt = json.loads(line)
            except json.JSONDecodeError:
                continue

            now   = time.monotonic()
            total += 1

            # ── sliding window packet rate ──────────────────────────────
            pkt_times.append(now)
            cutoff = now - args.window
            while pkt_times and pkt_times[0] < cutoff:
                pkt_times.popleft()

            current_pps = len(pkt_times) / args.window
            # Update baseline slowly
            baseline_pps = baseline_pps * 0.98 + current_pps * 0.02

            # ── FLOOD detection ─────────────────────────────────────────
            if (baseline_pps > 5 and
                    current_pps > baseline_pps * args.flood_multiplier):
                if not flood_alerted:
                    alert("FLOOD", f"{current_pps:.0f} pps "
                          f"(baseline {baseline_pps:.0f} pps, "
                          f"×{current_pps/baseline_pps:.1f})")
                    flood_alerted = True
            else:
                flood_alerted = False

            # ── LARGE PACKET ─────────────────────────────────────────────
            if pkt["caplen"] > args.large_pkt:
                alert("LARGE PKT",
                      f"{pkt['caplen']} bytes on flow {pkt['flow_id']}")

            # ── PORT SCAN ────────────────────────────────────────────────
            ports = get_ports_from_pkt(pkt)
            fid   = pkt["flow_id"]
            if ports:
                flow_ports[fid].update(ports)
                if (len(flow_ports[fid]) >= args.scan_threshold
                        and fid not in alerted_scans):
                    alerted_scans.add(fid)
                    alert("PORT SCAN",
                          f"flow {fid} touched {len(flow_ports[fid])} ports")

            # ── NEW PROTOCOL ──────────────────────────────────────────────
            for layer in pkt["layers"]:
                p = layer["proto"]
                if p not in ("ethernet","ipv4","ipv6","tcp","udp","arp") \
                        and p not in known_protos:
                    known_protos.add(p)
                    alert("NEW PROTO", f"first {p.upper()} packet seen")

            # ── Status line ───────────────────────────────────────────────
            if total % 100 == 0:
                protos = " ".join(known_protos)
                print(f"{DIM}[{time.strftime('%H:%M:%S')}]  "
                      f"pkts={total}  pps={current_pps:.0f}  "
                      f"base={baseline_pps:.0f}  protos={protos}{RESET}")

        proc.terminate()
    print(f"\nDone. Inspected {total} packets.")

if __name__ == "__main__":
    main()
