#!/usr/bin/env python3
"""
examples/python/06_bandwidth_recorder.py
──────────────────────────────────────────
Records per-second bandwidth to a CSV file and optionally plots it.

Great for finding:
  • What time of day your network is busiest
  • Which process/flow is eating bandwidth
  • Bandwidth spikes during video calls / downloads

Usage:
    sudo python3 06_bandwidth_recorder.py wlo1 --duration 60
    sudo python3 06_bandwidth_recorder.py wlo1 --duration 60 --plot
    # (--plot requires: pip install matplotlib)
"""

import subprocess, sys, json, argparse, time, signal, csv
from collections import defaultdict
from pathlib import Path

NETPIPE = "../../build/bin/netpipe"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("interface")
    ap.add_argument("--duration", "-d", type=int, default=30,
                    help="recording duration in seconds (default 30)")
    ap.add_argument("--out", "-o",      default="bandwidth.csv")
    ap.add_argument("--plot",           action="store_true",
                    help="show matplotlib plot when done (requires matplotlib)")
    ap.add_argument("--proto",          default=None,
                    help="filter by protocol (e.g. tcp, udp, dns)")
    args = ap.parse_args()

    cmd = [NETPIPE, "-i", args.interface, "-fmt", "json", "-q"]
    if args.proto:
        cmd += ["-proto", args.proto]

    print(f"\033[1mBandwidth Recorder\033[0m on {args.interface}  "
          f"for {args.duration}s  →  {args.out}")
    print("─" * 50)

    # Per-second buckets
    bucket: dict = defaultdict(lambda: {"pkts": 0, "bytes": 0,
                                         "tcp": 0, "udp": 0, "dns": 0,
                                         "http": 0, "tls": 0})
    start = time.monotonic()
    last_print = start

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
            elapsed = time.monotonic() - start
            if elapsed > args.duration:
                break

            line = line.strip()
            if not line:
                continue
            try:
                pkt = json.loads(line)
            except json.JSONDecodeError:
                continue

            sec = int(elapsed)
            b   = bucket[sec]
            b["pkts"]  += 1
            b["bytes"] += pkt["caplen"]
            for layer in pkt["layers"]:
                p = layer["proto"]
                if p in b:
                    b[p] += 1

            # Print progress every second
            now = time.monotonic()
            if now - last_print >= 1.0:
                last_print = now
                bps = b["bytes"] / 1024
                bar = "█" * min(int(bps / 10), 40)
                print(f"  t={sec:>3}s  {bps:>7.1f} KB  {bar}")

        proc.terminate()

    # Write CSV
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "second","pkts","bytes_kb","tcp","udp","dns","http","tls"])
        w.writeheader()
        for sec in sorted(bucket.keys()):
            b = bucket[sec]
            w.writerow({
                "second":   sec,
                "pkts":     b["pkts"],
                "bytes_kb": round(b["bytes"] / 1024, 2),
                "tcp":      b["tcp"],
                "udp":      b["udp"],
                "dns":      b["dns"],
                "http":     b["http"],
                "tls":      b["tls"],
            })

    total_bytes = sum(b["bytes"] for b in bucket.values())
    total_pkts  = sum(b["pkts"]  for b in bucket.values())
    print(f"\n  Total: {total_pkts:,} pkts  {total_bytes/1024:.1f} KB")
    print(f"  CSV saved to: {args.out}")

    if args.plot:
        try:
            import matplotlib.pyplot as plt
            secs   = sorted(bucket.keys())
            bw_kb  = [bucket[s]["bytes"] / 1024 for s in secs]
            tcp_c  = [bucket[s]["tcp"]           for s in secs]
            udp_c  = [bucket[s]["udp"]           for s in secs]

            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 6),
                                            facecolor="#0f1117")
            for ax in (ax1, ax2):
                ax.set_facecolor("#1a1d27")
                ax.tick_params(colors="#64748b")
                for spine in ax.spines.values():
                    spine.set_edgecolor("#2d3748")

            ax1.fill_between(secs, bw_kb, alpha=0.7, color="#00d4ff")
            ax1.plot(secs, bw_kb, color="#00d4ff", linewidth=1.5)
            ax1.set_ylabel("KB/s", color="#e2e8f0")
            ax1.set_title(f"Bandwidth — {args.interface}", color="#e2e8f0")

            ax2.bar(secs, tcp_c, color="#22c55e", label="TCP", alpha=0.8)
            ax2.bar(secs, udp_c, color="#00d4ff", label="UDP",
                    bottom=tcp_c, alpha=0.8)
            ax2.set_xlabel("Seconds", color="#e2e8f0")
            ax2.set_ylabel("Packets", color="#e2e8f0")
            ax2.legend(facecolor="#1a1d27", labelcolor="#e2e8f0")

            plt.tight_layout()
            out_png = Path(args.out).with_suffix(".png")
            plt.savefig(out_png, dpi=150, facecolor="#0f1117")
            print(f"  Plot saved to: {out_png}")
            plt.show()

        except ImportError:
            print("  Install matplotlib to enable plotting:  pip install matplotlib")

if __name__ == "__main__":
    main()
