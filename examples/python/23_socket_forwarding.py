#!/usr/bin/env python3
"""
23_socket_forwarding.py — Forward a PCAP replay over a TCP socket

Demonstrates netpipe's -o socket://host:port sink.  Starts a local
TCP server, replays tests/fixtures/all.pcap into it, then reads and
parses the received PCAP stream to confirm all 5 packets arrived
with valid headers.

No root required — replays from a file.

Run:
    python3 examples/python/23_socket_forwarding.py
"""

import subprocess
import socket
import struct
import threading
import os
import sys

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
BIN       = os.path.join(REPO_ROOT, "build", "bin", "netpipe")
FIXTURE   = os.path.join(REPO_ROOT, "tests", "fixtures", "all.pcap")

HOST  = "127.0.0.1"
PORT  = 19800
MAGIC = 0xa1b2c3d4  # little-endian PCAP magic


def parse_pcap_stream(data: bytes):
    """Parse a raw PCAP byte stream, return list of (caplen, ts_sec) tuples."""
    packets = []
    if len(data) < 24:
        return packets
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != MAGIC:
        print(f"  WARNING: unexpected magic 0x{magic:08x} (expected 0x{MAGIC:08x})")
        return packets
    pos = 24  # skip global header
    while pos + 16 <= len(data):
        ts_sec, ts_usec, caplen, origlen = struct.unpack_from("<IIII", data, pos)
        pos += 16 + caplen
        packets.append({"ts_sec": ts_sec, "caplen": caplen, "origlen": origlen})
    return packets


received_data = bytearray()
server_done   = threading.Event()


def server_thread():
    """Accept one connection, drain all data, signal done."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    srv.settimeout(5)
    try:
        conn, addr = srv.accept()
        conn.settimeout(2)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                received_data.extend(chunk)
        except socket.timeout:
            pass
        conn.close()
    except socket.timeout:
        print("  ERROR: no connection received within 5s", file=sys.stderr)
    finally:
        srv.close()
        server_done.set()


def main():
    print("=" * 60)
    print(" netpipe — Example 23: Socket Forwarding")
    print("=" * 60)

    # ── 1. Start the receiver ─────────────────────────────────────────
    print(f"\n[1] Starting TCP server on {HOST}:{PORT}...")
    t = threading.Thread(target=server_thread, daemon=True)
    t.start()

    import time; time.sleep(0.3)   # give server time to bind

    # ── 2. Run netpipe socket sink ────────────────────────────────────
    print(f"[2] Replaying {os.path.basename(FIXTURE)} → socket://{HOST}:{PORT}...")
    result = subprocess.run(
        [BIN, "-r", FIXTURE, "-o", f"socket://{HOST}:{PORT}"],
        capture_output=True, text=True, timeout=10
    )
    for line in result.stderr.splitlines():
        if "socket" in line.lower() or "pipeline" in line.lower():
            print("   ", line.strip())

    server_done.wait(timeout=5)

    # ── 3. Parse and display received PCAP ───────────────────────────
    print(f"\n[3] Received {len(received_data)} bytes — parsing PCAP stream:\n")
    pkts = parse_pcap_stream(bytes(received_data))
    if pkts:
        print(f"  {'#':<4}  {'caplen':>8}  {'origlen':>8}")
        print(f"  {'-'*4}  {'-'*8}  {'-'*8}")
        for i, p in enumerate(pkts, 1):
            print(f"  {i:<4}  {p['caplen']:>8}  {p['origlen']:>8}")
        print(f"\n  Total packets in stream : {len(pkts)}")
        total_bytes = sum(p["caplen"] for p in pkts)
        print(f"  Total payload bytes     : {total_bytes}")
    else:
        print("  No packets parsed — check server output above.")

    # ── 4. JSON forwarding mode ───────────────────────────────────────
    print("\n[4] JSON forwarding mode (socket receives NDJSON):\n")
    json_data = bytearray()

    def json_server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT + 1))
        srv.listen(1)
        srv.settimeout(5)
        try:
            conn, _ = srv.accept()
            conn.settimeout(2)
            try:
                while True:
                    c = conn.recv(4096)
                    if not c: break
                    json_data.extend(c)
            except socket.timeout:
                pass
            conn.close()
        except Exception:
            pass
        finally:
            srv.close()

    jt = threading.Thread(target=json_server, daemon=True)
    jt.start()
    import time; time.sleep(0.3)

    subprocess.run(
        [BIN, "-r", FIXTURE, "-o", f"socket://{HOST}:{PORT+1}", "-fmt", "json"],
        capture_output=True, timeout=10
    )
    jt.join(timeout=3)

    import json
    lines = json_data.decode("utf-8", errors="replace").strip().splitlines()
    print(f"  Received {len(lines)} NDJSON records:")
    for line in lines:
        try:
            obj = json.loads(line)
            proto = "unknown"
            if obj.get("layers"):
                proto = obj["layers"][-1].get("proto", "?")
            print(f"    seq={obj.get('seq')}  proto={proto}  caplen={obj.get('caplen')}")
        except Exception:
            pass

    print("\nDone.")


if __name__ == "__main__":
    main()
