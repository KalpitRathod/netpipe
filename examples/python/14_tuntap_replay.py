#!/usr/bin/env python3
"""
examples/python/14_tuntap_replay.py
───────────────────────────────────────
Demonstrates the native TUN/TAP packet injection sink.

This script runs `netpipe` to read an existing PCAP file and output the
packets into a brand new virtual TAP interface (`tap0`).
It simultaneously runs `tcpdump` on the new `tap0` interface to prove
that the kernel is actually receiving the injected packets!

Usage:
    sudo python3 14_tuntap_replay.py
"""

import subprocess, sys, time, os
import pathlib as _pl

_HERE = _pl.Path(__file__).resolve().parent
# Force using the locally built netpipe, not a system-installed one that lacks new features
NETPIPE = str(_HERE / "../../build/bin/netpipe")

def main():
    if os.geteuid() != 0:
        print("Please run this script with sudo (TUN/TAP requires root permissions).")
        sys.exit(1)

    pcap_path = _HERE / "../../encrypted_traffic.pcap"
    
    if not pcap_path.exists():
        print(f"File not found: {pcap_path}")
        print("Please run `sudo python3 examples/python/10_tls_capture.py wlo1` first to capture some packets!")
        sys.exit(1)

    print(f"\033[1mTAP Replay Demo\033[0m")
    print(f"Replaying \033[36m{pcap_path.name}\033[0m into virtual interface \033[33mtap0\033[0m...\n")

    cmd_netpipe = [NETPIPE, "-r", str(pcap_path), "-o", "tap://tap0", "-rate", "500"]
    netpipe_proc = subprocess.Popen(cmd_netpipe)

    time.sleep(0.5)
    
    subprocess.run(["ip", "link", "set", "tap0", "up"], stderr=subprocess.DEVNULL)
    
    print("┌── \033[1;35mKernel tshark output on tap0\033[0m ─────────────────────")
    
    # Use tshark since tcpdump might not be installed (tshark is required for tls_decryptor anyway)
    cmd_tshark = ["tshark", "-i", "tap0", "-c", "5"] 
    try:
        subprocess.run(cmd_tshark, check=True)
    except subprocess.CalledProcessError:
        print("\033[1;31mFailed to run tshark on tap0.\033[0m")
    except FileNotFoundError:
        print("\033[1;31mtshark is not installed, but the replay is running in the background!\033[0m")

    print("└────────────────────────────────────────────────────────\n")
    
    netpipe_proc.terminate()
    netpipe_proc.wait()

if __name__ == "__main__":
    main()
