#!/usr/bin/env python3
"""
gen_tls12_fresh.py — generate a clean TLS 1.2 capture for decryption testing.

Uses Python's ssl module with keylog_filename to capture the master secret,
and a socketpair to capture the raw TLS bytes.  This avoids any issues with
the OpenSSL s_server/s_client proxy approach.
"""

import hashlib
import hmac
import os
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

REPO = pathlib.Path("/home/z/my-project/netpipe/netpipe-0.1.0")
KEYLOG = REPO / "tls12_keys.log"
PCAP = REPO / "tls12_traffic.pcap"
CERT = pathlib.Path("/tmp/netpipe_tls12_cert.pem")
KEY = pathlib.Path("/tmp/netpipe_tls12_key.pem")

def gen_cert():
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(KEY), "-out", str(CERT),
        "-days", "1", "-nodes", "-subj", "/CN=localhost",
    ], check=True, capture_output=True)

def write_pcap_header(f):
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

def write_pcap_record(f, data, ts_sec, ts_usec):
    f.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)))
    f.write(data)

def build_eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, payload, seq, ack, flags=0x18):
    eth = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb' + struct.pack(">H", 0x0800)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20+20+len(payload), 0x1234, 0x4000, 64, 6, 0)
    ip += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, seq, ack, (5<<4), flags, 65535, 0, 0)
    return eth + ip + tcp + payload

def main():
    print("[1/4] Generating cert...")
    gen_cert()
    KEYLOG.write_text("")

    print("[2/4] Running TLS 1.2 handshake...")
    raw_c, raw_s = socket.socketpair()

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    server_ctx.load_cert_chain(certfile=str(CERT), keyfile=str(KEY))
    server_ctx.keylog_filename = str(KEYLOG)

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    client_ctx.keylog_filename = str(KEYLOG)

    captured_c2s = []
    captured_s2c = []

    class Sniffer:
        def __init__(self, sock, on_send, on_recv):
            self._sock = sock; self._on_send = on_send; self._on_recv = on_recv
        def send(self, d): self._on_send(d); return self._sock.send(d)
        def sendall(self, d): self._on_send(d); return self._sock.sendall(d)
        def recv(self, n):
            d = self._sock.recv(n)
            if d: self._on_recv(d)
            return d
        def __getattr__(self, n): return getattr(self._sock, n)

    sniff_c = Sniffer(raw_c, lambda b: captured_c2s.append(b), lambda b: captured_s2c.append(b))
    sniff_s = Sniffer(raw_s, lambda b: captured_s2c.append(b), lambda b: captured_c2s.append(b))

    errors = []
    tls_s = [None]; tls_c = [None]

    def server_thread():
        try:
            tls_s[0] = server_ctx.wrap_socket(sniff_s, server_side=True)
            req = tls_s[0].recv(4096)
            tls_s[0].sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nHello")
            # Wait for client to read + close before we close.
            try:
                while tls_s[0].recv(4096): pass
            except: pass
            try: tls_s[0].close()
            except: pass
        except Exception as e:
            errors.append(f"server: {e!r}")

    def client_thread():
        try:
            tls_c[0] = client_ctx.wrap_socket(sniff_c, server_hostname="localhost")
            tls_c[0].sendall(b"GET /secret HTTP/1.0\r\nHost: localhost\r\n\r\n")
            resp = b""
            while True:
                chunk = tls_c[0].recv(4096)
                if not chunk: break
                resp += chunk
            if b"Hello" not in resp:
                errors.append(f"client: bad response {resp!r}")
            tls_c[0].close()
        except Exception as e:
            errors.append(f"client: {e!r}")

    t_s = threading.Thread(target=server_thread, daemon=True)
    t_c = threading.Thread(target=client_thread, daemon=True)
    t_s.start(); t_c.start()
    t_s.join(timeout=5); t_c.join(timeout=5)

    if errors:
        print(f"Errors: {errors}")
        sys.exit(1)

    try: tls_c[0].close()
    except: pass
    try: tls_s[0].close()
    except: pass

    print(f"  captured {len(captured_c2s)} c2s blobs, {len(captured_s2c)} s2c blobs")

    print("[3/4] Building PCAP...")
    src_ip = "127.0.0.1"; dst_ip = "127.0.0.1"
    client_port = 49152; server_port = 4433
    seq_c = 1; seq_s = 1
    frames = []
    for blob in captured_c2s:
        frames.append(build_eth_ip_tcp(src_ip, dst_ip, client_port, server_port, blob, seq_c, seq_s))
        seq_c += len(blob)
    for blob in captured_s2c:
        frames.append(build_eth_ip_tcp(dst_ip, src_ip, server_port, client_port, blob, seq_s, seq_c))
        seq_s += len(blob)

    with open(PCAP, "wb") as f:
        write_pcap_header(f)
        ts = int(time.time())
        for i, frame in enumerate(frames):
            write_pcap_record(f, frame, ts, i * 1000)

    print(f"  wrote {PCAP} ({PCAP.stat().st_size}B, {len(frames)} frames)")

    print("[4/4] Verifying decryption...")
    # Parse keylog
    ms = None; cr = None
    with open(KEYLOG) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3 and parts[0] == "CLIENT_RANDOM":
                cr = bytes.fromhex(parts[1]); ms = bytes.fromhex(parts[2]); break

    if ms is None:
        print("  ERROR: no CLIENT_RANDOM in keylog"); sys.exit(1)
    print(f"  client_random: {cr.hex()[:16]}...")
    print(f"  master_secret ({len(ms)}B): {ms.hex()[:16]}...")

    # Find ServerHello to get server_random + cipher
    server_random = None; cipher = None
    for i, (ts_s, ts_us, frame) in enumerate(_parse_pcap(PCAP)):
        if len(frame) < 54: continue
        if struct.unpack(">H", frame[12:14])[0] != 0x0800: continue
        if frame[23] != 6: continue
        tls = frame[54:]
        for ct, rec in _split_tls(tls):
            if ct != 22: continue
            frag = rec[5:]
            if not frag or frag[0] != 2: continue
            if len(frag) < 39: continue
            server_random = frag[6:38]
            sid_len = frag[38]
            cipher = struct.unpack(">H", frag[39+sid_len:41+sid_len])[0]
            break
        if server_random: break

    print(f"  server_random: {server_random.hex()[:16]}...")
    print(f"  cipher: 0x{cipher:04x}")

    # Derive keys
    hash_algo = "sha384" if cipher == 0xc030 else "sha256"
    key_len = 32 if cipher in (0xc030, 0xc02c, 0x009d, 0xcca8, 0xcca9) else 16
    seed = server_random + cr
    ls = b"key expansion" + seed
    kb_len = 2 * key_len + 8
    out = b""; a = ls
    while len(out) < kb_len:
        a = hmac.new(ms, a, hash_algo).digest()
        out += hmac.new(ms, a + ls, hash_algo).digest()
    kb = out[:kb_len]
    cw_key = kb[:key_len]; sw_key = kb[key_len:2*key_len]
    cw_iv = kb[2*key_len:2*key_len+4]; sw_iv = kb[2*key_len+4:2*key_len+8]

    print(f"  client_write_key: {cw_key.hex()[:32]}...")
    print(f"  server_write_key: {sw_key.hex()[:32]}...")

    # Try decrypting APPLICATION_DATA records
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    seq_c = 0; seq_s = 0
    for i, (ts_s, ts_us, frame) in enumerate(_parse_pcap(PCAP)):
        if len(frame) < 54: continue
        if struct.unpack(">H", frame[12:14])[0] != 0x0800: continue
        if frame[23] != 6: continue
        sp = struct.unpack(">H", frame[34:36])[0]
        dp = struct.unpack(">H", frame[36:38])[0]
        is_c2s = sp == client_port
        tls = frame[54:]
        for ct, rec in _split_tls(tls):
            if ct != 23: continue
            frag = rec[5:]
            if len(frag) < 24: continue
            en = frag[:8]; cwt = frag[8:]; cl = len(cwt) - 16
            ct_data = cwt[:cl]; tag = cwt[cl:]
            if is_c2s:
                nonce = cw_iv + en; key = cw_key; seq = seq_c
            else:
                nonce = sw_iv + en; key = sw_key; seq = seq_s
            aad = struct.pack(">Q", seq) + bytes([23, 0x03, 0x03]) + struct.pack(">H", cl)
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                pt = AESGCM(key).decrypt(nonce, ct_data + tag, aad)
                if is_c2s: seq_c += 1
                else: seq_s += 1
                preview = pt[:60].decode("ascii", errors="replace").replace("\r", "\\r").replace("\n", "\\n")
                print(f"  pkt {i+1} ({'c2s' if is_c2s else 's2c'}, seq={seq}): DECRYPTED {len(pt)}B — {preview!r}")
            except Exception as e:
                print(f"  pkt {i+1} ({'c2s' if is_c2s else 's2c'}, seq={seq}): FAILED — {e}")

def _parse_pcap(path):
    with open(path, "rb") as f:
        f.read(24)
        while True:
            rec = f.read(16)
            if len(rec) < 16: break
            ts_s, ts_u, il, ol = struct.unpack("<IIII", rec)
            yield (ts_s, ts_u, f.read(il))

def _split_tls(blob):
    records = []
    off = 0
    while off + 5 <= len(blob):
        ct = blob[off]
        length = struct.unpack(">H", blob[off+3:off+5])[0]
        if off + 5 + length > len(blob):
            records.append((ct, blob[off:])); break
        records.append((ct, blob[off:off+5+length]))
        off += 5 + length
    return records

if __name__ == "__main__":
    main()
