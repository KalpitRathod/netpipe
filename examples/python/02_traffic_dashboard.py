#!/usr/bin/env python3
"""
examples/python/02_traffic_dashboard.py
─────────────────────────────────────────
Live terminal protocol-breakdown dashboard.
Updates in-place every second using ANSI escape codes — no external
libraries required (pure stdlib).

Shows:
  • Total packets / bytes / packets-per-second
  • Per-protocol breakdown with ASCII bar charts
  • Top-10 flows by packet count
  • Last 5 packets

Usage:
    sudo python3 02_traffic_dashboard.py wlo1
"""

import subprocess, sys, json, time, threading, os, signal
from collections import defaultdict, deque

NETPIPE = "../../build/bin/netpipe"

# ── ANSI helpers ────────────────────────────────────────────────────────────
CLEAR_SCREEN = "\033[2J\033[H"
BOLD  = "\033[1m"
DIM   = "\033[2m"
CYAN  = "\033[36m"
GREEN = "\033[32m"
YELLOW= "\033[33m"
RED   = "\033[31m"
BLUE  = "\033[34m"
RESET = "\033[0m"

PROTO_COLOUR = {
    "tcp":  GREEN,  "udp":  CYAN,   "icmp": YELLOW,
    "http": BLUE,   "dns":  "\033[35m", "tls": RED,
    "ipv4": DIM,    "ipv6": DIM,    "ethernet": DIM,
}

def bar(value, total, width=20, colour=GREEN):
    filled = int(width * value / total) if total else 0
    return colour + "█" * filled + DIM + "░" * (width - filled) + RESET

# ── Shared state (written by reader thread, read by display thread) ──────────
lock   = threading.Lock()
stats  = defaultdict(int)   # proto → packet count
bytes_ = defaultdict(int)   # proto → bytes
flows  = defaultdict(int)   # flow_id → packet count
recent = deque(maxlen=5)    # last 5 packets
total_pkts  = 0
total_bytes = 0
start_time  = time.monotonic()
running     = True

# ── Reader thread ─────────────────────────────────────────────────────────────
def reader(proc):
    global total_pkts, total_bytes
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

        with lock:
            total_pkts  += 1
            total_bytes += pkt["caplen"]

            for layer in pkt["layers"]:
                p = layer["proto"]
                stats[p]  += 1
                bytes_[p] += layer["len"]

            flows[pkt["flow_id"]] += 1

            # summarise packet for recent list
            protos = " → ".join(l["proto"].upper() for l in pkt["layers"])
            recent.append(f"{pkt['ts']}  {pkt['caplen']:>5}B  {protos}")

# ── Display (main thread) ─────────────────────────────────────────────────────
def render():
    elapsed = time.monotonic() - start_time
    pps = total_pkts / elapsed if elapsed > 0.01 else 0
    bps = total_bytes / elapsed if elapsed > 0.01 else 0

    lines = []
    lines.append(f"{BOLD}{'─'*64}{RESET}")
    lines.append(f"{BOLD}  netpipe  ·  Live Traffic Dashboard{RESET}  "
                 f"{DIM}(Ctrl-C to stop){RESET}")
    lines.append(f"{'─'*64}")
    lines.append(f"  Packets   {BOLD}{total_pkts:>10,}{RESET}   "
                 f"({GREEN}{pps:>8.1f} pps{RESET})")
    lines.append(f"  Bytes     {BOLD}{total_bytes:>10,}{RESET}   "
                 f"({GREEN}{bps/1024:>8.1f} KB/s{RESET})")
    lines.append(f"{'─'*64}")
    lines.append(f"  {BOLD}Protocol breakdown{RESET}")

    # Sort by count descending
    top_protos = sorted(stats.items(), key=lambda x: -x[1])
    for proto, count in top_protos[:10]:
        col   = PROTO_COLOUR.get(proto, RESET)
        b     = bar(count, total_pkts, width=24, colour=col)
        pct   = 100 * count / total_pkts if total_pkts else 0
        lines.append(f"  {col}{proto:<12}{RESET} {b}  "
                     f"{count:>6,} pkts  ({pct:5.1f}%)")

    lines.append(f"{'─'*64}")
    lines.append(f"  {BOLD}Top flows (by flow_id hash){RESET}")
    top_flows = sorted(flows.items(), key=lambda x: -x[1])[:5]
    for fid, cnt in top_flows:
        lines.append(f"  flow {fid:>10}   {cnt:>6,} packets")

    lines.append(f"{'─'*64}")
    lines.append(f"  {BOLD}Recent packets{RESET}")
    for r in list(recent):
        lines.append(f"  {DIM}{r}{RESET}")

    lines.append(f"{'─'*64}")

    # Render atomically
    sys.stdout.write(CLEAR_SCREEN + "\n".join(lines) + "\n")
    sys.stdout.flush()

def main():
    global running
    if len(sys.argv) < 2:
        sys.exit(f"Usage: {sys.argv[0]} <interface>")

    iface = sys.argv[1]
    cmd   = [NETPIPE, "-i", iface, "-fmt", "json", "-q"]

    print(f"Starting netpipe on {iface}…")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)

    t = threading.Thread(target=reader, args=(proc,), daemon=True)
    t.start()

    def stop(sig, frame):
        global running
        running = False
        proc.terminate()

    signal.signal(signal.SIGINT, stop)

    while running:
        with lock:
            render()
        time.sleep(1.0)

    proc.wait()
    print("\nStopped.")

if __name__ == "__main__":
    main()
