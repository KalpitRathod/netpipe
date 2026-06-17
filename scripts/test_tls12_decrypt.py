#!/usr/bin/env python3
"""
test_tls12_decrypt.py
─────────────────────
End-to-end test for TLS 1.2 GCM decryption.

Verifies that netpipe can decrypt TLS 1.2 traffic from
encrypted_traffic.pcap using tls_keys.log, and that the decrypted
plaintext contains the expected HTTP response.
"""

import json
import os
import pathlib
import subprocess
import sys

REPO = pathlib.Path("/home/z/my-project/netpipe/netpipe-0.1.0")
NETPIPE = REPO / "build" / "bin" / "netpipe"
PCAP = REPO / "encrypted_traffic.pcap"
KEYLOG = REPO / "tls_keys.log"
LD_PATH = "/home/z/my-project/deps/local/lib"

GREEN = "\033[32m"
RED = "\033[31m"
BOLD = "\033[1m"
NC = "\033[0m"


def main():
    if not PCAP.exists() or not KEYLOG.exists():
        print(f"{RED}ERROR: TLS fixtures not found.{NC}")
        print(f"  Run: python3 /home/z/my-project/scripts/gen_tls_fixtures.py")
        sys.exit(1)

    print(f"{BOLD}=== TLS 1.2 + 1.3 Decryption End-to-End Test ==={NC}\n")

    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = LD_PATH

    cmd = [
        str(NETPIPE),
        "-r", str(PCAP),
        "-proc", f"tls-decrypt:{KEYLOG}",
        "-fmt", "json",
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=15)
    if proc.returncode != 0:
        print(f"{RED}netpipe exited with code {proc.returncode}{NC}")
        print(proc.stderr[-500:])
        sys.exit(1)

    # Parse JSON output and look for decrypted HTTP plaintext.
    tls12_found = False
    tls13_found = False
    total_decrypted = 0

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            pkt = json.loads(line)
        except json.JSONDecodeError:
            continue

        stream_hex = pkt.get("stream_hex", "")
        if not stream_hex:
            continue

        try:
            plaintext = bytes.fromhex(stream_hex)
        except ValueError:
            continue

        total_decrypted += 1

        # Check for HTTP plaintext (both TLS 1.2 and 1.3 should produce it).
        text = plaintext.decode("ascii", errors="replace")
        if "HTTP/1.0 200" in text or "HTTP/1.0 200 ok" in text.lower():
            # Determine which TLS version this is by looking at the packet's
            # source port (4433 = TLS 1.2, 4434 = TLS 1.3).
            raw_hex = pkt.get("raw_hex", "")
            if raw_hex:
                raw = bytes.fromhex(raw_hex)
                if len(raw) >= 38:
                    # TCP dest port is at offset 36-37 (after 14 eth + 20 ip).
                    dport = (raw[36] << 8) | raw[37]
                    sport = (raw[34] << 8) | raw[35]
                    if dport == 4433 or sport == 4433:
                        tls12_found = True
                        print(f"  TLS 1.2 decrypted: {text[:60]!r}")
                    elif dport == 4434 or sport == 4434:
                        tls13_found = True
                        print(f"  TLS 1.3 decrypted: {text[:60]!r}")

    print(f"\n  Total decrypted packets: {total_decrypted}")
    print(f"  TLS 1.2 HTTP plaintext: {'YES' if tls12_found else 'NO'}")
    print(f"  TLS 1.3 HTTP plaintext: {'YES' if tls13_found else 'NO'}")

    if tls12_found and tls13_found:
        print(f"\n  {GREEN}PASS{NC} — both TLS 1.2 and TLS 1.3 decrypted successfully")
        sys.exit(0)
    elif tls13_found:
        print(f"\n  {RED}FAIL{NC} — TLS 1.3 works but TLS 1.2 did not produce HTTP plaintext")
        sys.exit(1)
    else:
        print(f"\n  {RED}FAIL{NC} — no TLS decryption produced HTTP plaintext")
        sys.exit(1)


if __name__ == "__main__":
    main()
