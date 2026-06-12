#!/usr/bin/env python3
"""
examples/python/15_socket_forward.py
─────────────────────────────────────────────────────────
Remote Packet Forwarding Demo (Socket Sink)

Demonstrates the native socket:// sink.  The C engine sends a valid PCAP
stream (global header + per-packet records) over a TCP socket to any receiver.

Architecture of this demo:
  ┌──────────────────────────────────────────────────────────┐
  │  Live wlo1 capture                                       │
  │       netpipe -i <iface> -c <N> -o socket://127.0.0.1:9999  │
  └──────────────────────────────────────────────────────────┘
               │  TCP stream (valid PCAP binary)
               ▼
  ┌──────────────────────────────────────────────────────────┐
  │  Python mock "remote agent"                              │
  │       Receives bytes → saves to forwarded.pcap          │
  └──────────────────────────────────────────────────────────┘
               │
               ▼
       Open forwarded.pcap in Wireshark — it's a real pcap!

Usage:
  sudo python3 examples/python/15_socket_forward.py wlo1

Real-world use-cases:
  - Capture on a remote/cloud server and analyse locally in Wireshark
  - Stream packets to a SIEM (Security Information and Event Manager)
  - Pipe directly into tshark: sudo ./build/bin/netpipe -i wlo1 -c 20 \\
      -o socket://127.0.0.1:9999 | tshark -r -
"""

import subprocess, sys, time, os
import socket, threading
import struct, pathlib as _pl

_HERE = _pl.Path(__file__).resolve().parent
NETPIPE   = str(_HERE / "../../build/bin/netpipe")
OUT_PCAP  = (_HERE / "../../forwarded.pcap").resolve()
PORT      = 9999

# PCAP global header is 24 bytes; packet record header is 16 bytes
PCAP_GLOBAL_HDR_SIZE = 24
PCAP_PKT_HDR_SIZE    = 16
PCAP_MAGIC           = 0xa1b2c3d4

# ─── colours ─────────────────────────────────────────────────────────────────
R  = "\033[0m";  B  = "\033[1m"
CY = "\033[36m"; YL = "\033[33m"; GR = "\033[32m"; RD = "\033[31m"; MG = "\033[35m"


# ─── Remote Agent (receiver) ─────────────────────────────────────────────────

class RemoteAgent:
    """Receives a PCAP byte stream over TCP and saves it to a .pcap file."""

    def __init__(self, host: str, port: int, out_path: _pl.Path) -> None:
        self.host     = host
        self.port     = port
        self.out_path = out_path
        self._thread  = None
        self.bytes_rx = 0
        self.pkts_rx  = 0
        self.ready    = threading.Event()
        self.error    = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def join(self, timeout: float = 5.0) -> None:
        if self._thread:
            self._thread.join(timeout=timeout)

    def _serve(self) -> None:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(1)
            self.ready.set()
            print(f"[{CY}agent{R}] Listening on {self.host}:{self.port}...")

            conn, addr = srv.accept()
            print(f"[{CY}agent{R}] Connection from {addr[0]}:{addr[1]}")
            srv.close()

            buf = b""
            with open(self.out_path, "wb") as f:
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    buf += chunk
                    self.bytes_rx += len(chunk)

            conn.close()

            # Parse and count packets for the summary
            if len(buf) >= PCAP_GLOBAL_HDR_SIZE:
                magic = struct.unpack_from("<I", buf, 0)[0]
                swap  = (magic == 0xd4c3b2a1)  # big-endian pcap
                endian = ">" if swap else "<"
                pos = PCAP_GLOBAL_HDR_SIZE
                while pos + PCAP_PKT_HDR_SIZE <= len(buf):
                    _, _, caplen, _ = struct.unpack_from(f"{endian}IIII", buf, pos)
                    self.pkts_rx += 1
                    pos += PCAP_PKT_HDR_SIZE + caplen

        except Exception as exc:
            self.error = exc


# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> None:
    if os.geteuid() != 0:
        print(f"{RD}Error:{R} Live capture requires root. Run with sudo.")
        sys.exit(1)

    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface> [packet_count]")
        sys.exit(1)

    iface       = sys.argv[1]
    pkt_count   = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    print(f"\n{B}┌─  Remote Socket Forwarding Demo  ──────────────────────────────┐{R}")
    print(f"{B}│{R}  Interface    : {CY}{iface}{R}")
    print(f"{B}│{R}  Packet count : {YL}{pkt_count}{R}")
    print(f"{B}│{R}  Receiver     : {MG}127.0.0.1:{PORT}{R}  (mock remote agent)")
    print(f"{B}│{R}  Output file  : {GR}{OUT_PCAP.name}{R}")
    print(f"{B}└────────────────────────────────────────────────────────────────┘{R}\n")

    # ── 1. Start the receiving agent ──────────────────────────────────────────
    agent = RemoteAgent("127.0.0.1", PORT, OUT_PCAP)
    agent.start()
    if not agent.ready.wait(timeout=3.0):
        print(f"{RD}Error:{R} Agent failed to start listening.")
        sys.exit(1)

    # ── 2. Run netpipe — it automatically sends PCAP global + packet headers ─
    cmd = [NETPIPE, "-i", iface, "-c", str(pkt_count),
           "-o", f"socket://127.0.0.1:{PORT}", "-q"]
    print(f"[{MG}netpipe{R}] Capturing {pkt_count} packets on {iface}...\n"
          f"          (generate traffic — browse a site, run ping, etc.)\n")

    try:
        proc = subprocess.run(cmd, timeout=60)
        if proc.returncode != 0:
            print(f"{RD}netpipe exited with code {proc.returncode}{R}")
    except subprocess.TimeoutExpired:
        print(f"{RD}Timeout waiting for {pkt_count} packets. Check the interface name.{R}")
        sys.exit(1)

    # ── 3. Wait for agent to finish flushing ──────────────────────────────────
    agent.join(timeout=3.0)

    if agent.error:
        print(f"{RD}Agent error:{R} {agent.error}")
        sys.exit(1)

    # ── 4. Verify the file is a real PCAP by inspecting the magic bytes ───────
    valid_pcap = False
    if OUT_PCAP.exists() and OUT_PCAP.stat().st_size >= PCAP_GLOBAL_HDR_SIZE:
        with open(OUT_PCAP, "rb") as f:
            magic = struct.unpack("<I", f.read(4))[0]
        valid_pcap = magic in (0xa1b2c3d4, 0xd4c3b2a1)

    print(f"\n{'─'*70}")
    print(f"[{CY}agent{R}] Received {agent.bytes_rx:,} bytes → {agent.pkts_rx} packets")
    print(f"[{CY}agent{R}] Saved to {OUT_PCAP}")

    if valid_pcap:
        print(f"\n{GR}{B}✓  forwarded.pcap is a valid PCAP file!{R}")
        print(f"   Open it in Wireshark, or run:")
        print(f"   {CY}tshark -r {OUT_PCAP} -c 5{R}")
        print(f"\nReal-world usage — stream directly into tshark on another machine:")
        print(f"  Remote: {CY}nc -l -p 9999 | tshark -r -{R}")
        print(f"  Here:   {CY}sudo ./build/bin/netpipe -i {iface} -c {pkt_count} -o socket://REMOTE_IP:9999{R}")
    else:
        print(f"\n{RD}Warning:{R} The output file doesn't look like a valid PCAP.")
        print("  This may happen if no packets were captured.")


if __name__ == "__main__":
    main()
