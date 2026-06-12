#!/usr/bin/env python3
"""
examples/python/10_tls_capture.py
───────────────────────────────────
Demonstrates capturing encrypted HTTPS traffic into a structured
PCAP format that can be decrypted later by any tool (like Wireshark).

It simultaneously generates the necessary TLS Session Keys using SSLKEYLOGFILE.

Usage:
    sudo python3 10_tls_capture.py wlo1
"""

import subprocess, sys, time, os
from pathlib import Path

_HERE = Path(__file__).resolve().parent
NETPIPE = str(next(
    (p for p in [
        _HERE / "../../build/bin/netpipe",
        Path("/usr/local/bin/netpipe"),
        Path("/usr/bin/netpipe"),
    ] if p.exists()), _HERE / "../../build/bin/netpipe"
))

def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 10_tls_capture.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    pcap_file = "encrypted_traffic.pcap"
    key_file = "tls_keys.log"

    # Clean up old files
    if os.path.exists(pcap_file): os.remove(pcap_file)
    if os.path.exists(key_file): os.remove(key_file)

    print(f"\033[1m[1]\033[0m Starting netpipe to capture structured PCAP on port 443...")
    # Run netpipe in the background
    # -o encrypted_traffic.pcap writes the raw, structured binary PCAP format
    cmd = [NETPIPE, "-i", interface, "-port", "443", "-o", pcap_file, "-q"]
    netpipe_proc = subprocess.Popen(cmd)
    
    # Give netpipe a second to start listening
    time.sleep(1)

    print(f"\033[1m[2]\033[0m Making a secure HTTPS request to https://example.com...")
    print(f"    (Forcing curl to log encryption keys to {key_file})")
    
    # We use curl with SSLKEYLOGFILE. This extracts the symmetric AES master secrets
    # before they are discarded, allowing us to decrypt the PCAP later!
    env = os.environ.copy()
    env["SSLKEYLOGFILE"] = key_file
    
    curl_cmd = ["curl", "-s", "https://example.com", "-o", "/dev/null"]
    subprocess.run(curl_cmd, env=env)

    # Wait a moment for traffic to finish writing
    time.sleep(1)
    
    print("\033[1m[3]\033[0m Stopping capture...")
    netpipe_proc.terminate()
    netpipe_proc.wait()

    print("\n\033[32mSuccess!\033[0m")
    print(f"Structured Traffic : \033[36m{pcap_file}\033[0m (Standard PCAP format)")
    print(f"Decryption Keys    : \033[36m{key_file}\033[0m")
    print("\nYou can now open this PCAP in Wireshark (Edit -> Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename)")
    print("OR you can run the decryption tool script:")
    print("  python3 examples/python/11_tls_decryptor.py encrypted_traffic.pcap tls_keys.log")

if __name__ == "__main__":
    main()
