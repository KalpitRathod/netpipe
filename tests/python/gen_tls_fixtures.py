#!/usr/bin/env python3
"""
gen_tls_fixtures.py
───────────────────
Generate `tls_keys.log` (NSS SSLKEYLOGFILE) and `encrypted_traffic.pcap`
for use by the netpipe TLS decryption test-suite and example scripts.

Strategy
────────
We cannot use AF_PACKET (requires CAP_NET_RAW which we don't have).
Instead, we run a Python TCP proxy that sits between OpenSSL s_client
and s_server, logging every byte that flows in each direction.  Both
s_client and s_server are invoked with `-keylog`, so we get a real
NSS-format keylog file alongside the captured wire bytes.

From the captured bytes we synthesise an Ethernet/IPv4/TCP PCAP file
containing the real TLS handshake and application-data records.

Output files:
    <REPO_ROOT>/tls_keys.log
    <REPO_ROOT>/encrypted_traffic.pcap
"""

import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import pathlib

REPO_ROOT = pathlib.Path(os.environ.get("NETPIPE_REPO_ROOT", "")).resolve() if os.environ.get("NETPIPE_REPO_ROOT") else pathlib.Path(__file__).resolve().parent.parent.parent
KEYLOG_PATH = REPO_ROOT / "tls_keys.log"
PCAP_PATH = REPO_ROOT / "encrypted_traffic.pcap"

CERT_PATH = pathlib.Path("/tmp/netpipe_tls_cert.pem")
KEY_PATH = pathlib.Path("/tmp/netpipe_tls_key.pem")

PCAP_MAGIC = 0xa1b2c3d4


def write_pcap_header(f):
    f.write(struct.pack("<IHHiIII",
                        PCAP_MAGIC, 2, 4,
                        0, 0, 65535, 1))  # linktype = Ethernet


def write_pcap_record(f, data, ts_sec, ts_usec):
    f.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)))
    f.write(data)


def generate_self_signed_cert():
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(KEY_PATH),
        "-out", str(CERT_PATH),
        "-days", "1", "-nodes",
        "-subj", "/CN=localhost",
    ]
    subprocess.run(cmd, check=True, capture_output=True)


def build_eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, payload,
                     seq, ack, flags=0x18):
    """Build an Ethernet/IPv4/TCP frame."""
    eth = (b'\x00\x11\x22\x33\x44\x55'
           b'\x66\x77\x88\x99\xaa\xbb'
           + struct.pack(">H", 0x0800))

    ip_total = 20 + 20 + len(payload)
    ip_hdr = struct.pack(">BBHHHBBH",
                         0x45, 0, ip_total,
                         0x1234, 0x4000,
                         64, 6, 0)
    ip_hdr += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)

    tcp_hdr = struct.pack(">HHIIBBHHH",
                          src_port, dst_port,
                          seq, ack,
                          (5 << 4), flags,
                          65535, 0, 0)

    return eth + ip_hdr + tcp_hdr + payload


def run_tcp_proxy(client_port, server_port, captured_c2s, captured_s2c):
    """Run a simple TCP proxy: listens on client_port, forwards to server_port.

    Bytes flowing client→server are appended to captured_c2s.
    Bytes flowing server→client are appended to captured_s2c.
    Returns when both sides close.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", client_port))
    listener.listen(1)
    listener.settimeout(10)

    try:
        client_sock, _ = listener.accept()
    finally:
        listener.close()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect(("127.0.0.1", server_port))

    stop = threading.Event()

    def forward(src, dst, capture_list):
        try:
            while not stop.is_set():
                data = src.recv(65535)
                if not data:
                    break
                capture_list.append(data)
                try:
                    dst.sendall(data)
                except OSError:
                    break
        except OSError:
            pass
        finally:
            try: src.shutdown(socket.SHUT_RD)
            except OSError: pass
            try: dst.shutdown(socket.SHUT_WR)
            except OSError: pass

    t1 = threading.Thread(target=forward, args=(client_sock, server_sock, captured_c2s))
    t2 = threading.Thread(target=forward, args=(server_sock, client_sock, captured_s2c))
    t1.start()
    t2.start()
    t1.join(timeout=15)
    t2.join(timeout=15)

    client_sock.close()
    server_sock.close()


def run_tls_exchange(tls_version, server_port, proxy_port):
    """Run one TLS exchange through a Python TCP proxy."""
    if tls_version == "1.2":
        tls_flag = "-tls1_2"
    elif tls_version == "1.3":
        tls_flag = "-tls1_3"
    else:
        raise ValueError(tls_version)

    # Start OpenSSL s_server.
    server_cmd = [
        "openssl", "s_server",
        "-accept", str(server_port),
        "-cert", str(CERT_PATH),
        "-key", str(KEY_PATH),
        "-keylogfile", str(KEYLOG_PATH),
        tls_flag,
        "-www",
        "-naccept", "1",   # exit after one connection
    ]
    server = subprocess.Popen(server_cmd,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    # Wait for the server to bind.
    time.sleep(0.6)

    captured_c2s = []
    captured_s2c = []

    # Start the proxy in a thread.
    proxy_thread = threading.Thread(
        target=run_tcp_proxy,
        args=(proxy_port, server_port, captured_c2s, captured_s2c),
    )
    proxy_thread.start()

    # Run the client against the proxy.
    client_cmd = [
        "openssl", "s_client",
        "-connect", f"127.0.0.1:{proxy_port}",
        "-keylogfile", str(KEYLOG_PATH),
        tls_flag,
        "-quiet",
        "-no_ign_eof",
    ]
    try:
        client = subprocess.Popen(client_cmd,
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        client.stdin.write(b"GET /secret/path HTTP/1.0\r\nHost: localhost\r\n\r\n")
        client.stdin.close()
        client.wait(timeout=10)
    except subprocess.TimeoutExpired:
        client.kill()

    proxy_thread.join(timeout=5)

    server.terminate()
    try:
        server.wait(timeout=2)
    except subprocess.TimeoutExpired:
        server.kill()

    return captured_c2s, captured_s2c


def split_tls_records(blob):
    """Split a blob of TLS bytes into individual TLS records.

    Each TLS record is:
      u8  content_type
      u16 version
      u16 length
      length bytes of payload
    """
    records = []
    off = 0
    while off + 5 <= len(blob):
        ct = blob[off]
        length = struct.unpack(">H", blob[off+3:off+5])[0]
        if off + 5 + length > len(blob):
            records.append(blob[off:])
            break
        records.append(blob[off:off+5+length])
        off += 5 + length
    if off < len(blob):
        records.append(blob[off:])
    return records


def synthesise_pcap(c2s_blobs, s2c_blobs, server_port):
    """Build PCAP frames from captured TLS record blobs."""
    src_ip = "127.0.0.1"
    dst_ip = "127.0.0.1"
    client_port = 49152
    seq_c = 1
    seq_s = 1

    frames = []

    # We interleave c2s and s2c blobs in the order they were captured.
    # Since the proxy captured them as separate lists, we just append
    # all c2s then all s2c (the order WITHIN each direction is preserved).
    # For a more realistic capture, we'd interleave by timestamp, but
    # for TLS decryption testing the order within a direction is what
    # matters.
    for blob in c2s_blobs:
        records = split_tls_records(blob)
        payload = b"".join(records)
        if not payload:
            continue
        frame = build_eth_ip_tcp(src_ip, dst_ip,
                                 client_port, server_port,
                                 payload, seq=seq_c, ack=seq_s,
                                 flags=0x18)
        seq_c += len(payload)
        frames.append(frame)
    for blob in s2c_blobs:
        records = split_tls_records(blob)
        payload = b"".join(records)
        if not payload:
            continue
        frame = build_eth_ip_tcp(dst_ip, src_ip,
                                 server_port, client_port,
                                 payload, seq=seq_s, ack=seq_c,
                                 flags=0x18)
        seq_s += len(payload)
        frames.append(frame)
    return frames


def main():
    print("[1/4] Generating self-signed cert…")
    generate_self_signed_cert()

    # Reset keylog file.
    KEYLOG_PATH.write_text("")

    print("[2/4] Capturing TLS 1.2 exchange…")
    c2s_12, s2c_12 = run_tls_exchange("1.2", server_port=4433, proxy_port=4443)
    print(f"        c2s={len(c2s_12)} blobs, s2c={len(s2c_12)} blobs")

    print("[3/4] Capturing TLS 1.3 exchange…")
    c2s_13, s2c_13 = run_tls_exchange("1.3", server_port=4434, proxy_port=4444)
    print(f"        c2s={len(c2s_13)} blobs, s2c={len(s2c_13)} blobs")

    print("[4/4] Synthesising PCAP…")
    frames_12 = synthesise_pcap(c2s_12, s2c_12, server_port=4433)
    frames_13 = synthesise_pcap(c2s_13, s2c_13, server_port=4434)
    all_frames = frames_12 + frames_13

    with open(PCAP_PATH, "wb") as f:
        write_pcap_header(f)
        ts_base = int(time.time())
        for i, frame in enumerate(all_frames):
            write_pcap_record(f, frame, ts_sec=ts_base, ts_usec=i * 1000)

    print(f"\n  done  {KEYLOG_PATH} ({KEYLOG_PATH.stat().st_size} bytes)")
    print(f"  done  {PCAP_PATH} ({PCAP_PATH.stat().st_size} bytes)")
    print(f"        {len(frames_12)} TLS 1.2 frames + {len(frames_13)} TLS 1.3 frames")

    print("\nKeylog sample (first 5 lines):")
    with open(KEYLOG_PATH) as f:
        for i, line in enumerate(f):
            if i >= 5: break
            line = line.rstrip()
            print(f"  {line[:80]}{'...' if len(line) > 80 else ''}")


if __name__ == "__main__":
    main()
