#!/usr/bin/env python3
"""
examples/python/14_tuntap_replay.py
─────────────────────────────────────────────────────────
TAP Injection & Packet Replay Demo

This script demonstrates the native TUN/TAP inject sink.  It replays
an existing PCAP file back into the Linux kernel through a virtual TAP
interface, rate-limited to 500 B/s so you can watch it in real time
with tshark.

What actually happens:
  1.  netpipe reads encrypted_traffic.pcap (captured during 10_tls_capture.py)
  2.  The token-bucket rate limiter paces the output to 500 bytes/sec
  3.  netpipe opens /dev/net/tun, asks the kernel to create tap0 with IFF_TAP
  4.  For every packet, it writes the raw Ethernet frame into the tap0 fd
  5.  The kernel treats those bytes identically to a physical NIC receiving them
  6.  tshark attaches to tap0 and proves the kernel sees real packets

Prerequisites:
  sudo python3 examples/python/10_tls_capture.py wlo1   # generate the pcap
  sudo python3 examples/python/14_tuntap_replay.py      # replay it

This is the foundation for:
  - VPN tunneling
  - Network simulation / traffic replay
  - Active Man-in-the-Middle (MitM) tools
"""

import subprocess, sys, time, os, signal
import pathlib as _pl

_HERE = _pl.Path(__file__).resolve().parent
NETPIPE = str(_HERE / "../../build/bin/netpipe")

RATE_BPS  = 500       # bytes per second — slow enough for tshark to attach
TSHARK_N  = 8         # how many packets tshark should capture

# ─── colours ─────────────────────────────────────────────────────────────────
R = "\033[0m";  B = "\033[1m";  CY = "\033[36m";  YL = "\033[33m"
GR = "\033[32m"; RD = "\033[31m"; MG = "\033[35m"


def cleanup_tap(dev: str) -> None:
    """Remove a stale TUN/TAP device so we can recreate it cleanly."""
    subprocess.run(["ip", "link", "del", dev], stderr=subprocess.DEVNULL)


def main() -> None:
    if os.geteuid() != 0:
        print(f"{RD}Error:{R} TUN/TAP and raw socket access require root. Run with sudo.")
        sys.exit(1)

    pcap_path = (_HERE / "../../encrypted_traffic.pcap").resolve()
    if not pcap_path.exists():
        print(f"{RD}Error:{R} {pcap_path} not found.")
        print(f"  Run first:  sudo python3 {_HERE}/10_tls_capture.py <iface>")
        sys.exit(1)

    pkt_count = int(subprocess.check_output(
        ["tshark", "-r", str(pcap_path), "-T", "fields", "-e", "frame.number"],
        stderr=subprocess.DEVNULL
    ).decode().strip().split("\n")[-1] or "0")

    print(f"\n{B}┌─  TAP Packet Replay Demo  ─────────────────────────────────────┐{R}")
    print(f"{B}│{R}  Source PCAP  : {CY}{pcap_path.name}{R}  ({pkt_count} packets)")
    print(f"{B}│{R}  Rate limit   : {YL}{RATE_BPS} B/s{R}  (token bucket)")
    print(f"{B}│{R}  Sink         : {MG}tap://tap0{R}  (Linux virtual interface)")
    print(f"{B}└────────────────────────────────────────────────────────────────┘{R}\n")

    # Remove any leftover tap0 from a previous run
    cleanup_tap("tap0")

    # ── 1. Start netpipe in background, injecting rate-limited packets ────────
    cmd = [NETPIPE, "-r", str(pcap_path), "-o", "tap://tap0", "-rate", str(RATE_BPS)]
    print(f"[{MG}netpipe{R}] {' '.join(cmd[1:])}")
    netpipe_proc = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)

    # ── 2. Wait until tap0 appears in the kernel ──────────────────────────────
    for attempt in range(20):
        time.sleep(0.1)
        result = subprocess.run(["ip", "link", "show", "tap0"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            break
    else:
        print(f"{RD}Error:{R} tap0 interface never appeared. Check that netpipe ran correctly.")
        netpipe_proc.terminate()
        sys.exit(1)

    subprocess.run(["ip", "link", "set", "tap0", "up"], check=True)
    print(f"[{GR}kernel{R}] tap0 is UP — kernel is now receiving injected packets\n")

    # ── 3. tshark reads from the kernel tap0 interface in real time ───────────
    print(f"[{CY}tshark{R}] capturing {TSHARK_N} packets on tap0:\n")
    print("─" * 70)
    try:
        subprocess.run(
            ["tshark", "-i", "tap0", "-c", str(TSHARK_N), "-n",
             "-T", "fields",
             "-e", "frame.time_relative",
             "-e", "ip.src", "-e", "ipv6.src",
             "-e", "ip.dst", "-e", "ipv6.dst",
             "-e", "_ws.col.Protocol",
             "-e", "frame.len",
             "-E", "separator=\t"],
            check=True,
        )
    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:
        print(f"{RD}tshark not found{R} — but netpipe is still injecting packets into tap0.\n"
              "  Install wireshark-common for tshark: sudo apt install wireshark-common")
    print("─" * 70)

    netpipe_proc.send_signal(signal.SIGINT)
    netpipe_proc.wait()

    print(f"\n{GR}{B}Success!{R} {pkt_count} packets replayed into the Linux kernel via tap0.")
    print(f"  The kernel processed each injected frame exactly as if it arrived from a physical NIC.")


if __name__ == "__main__":
    main()
