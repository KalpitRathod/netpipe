#!/usr/bin/env python3
"""
verify_tls12_keys.py
─────────────────────
Reference implementation of TLS 1.2 GCM key derivation per RFC 5246 §6.3
and RFC 5288 §3, used to verify netpipe's C implementation.

Reads tls_keys.log + extracts the TLS 1.2 master secret, then derives
the key_block and prints client_write_key, server_write_key,
client_write_IV, server_write_IV.

We then attempt to decrypt the first APPLICATION_DATA record from
encrypted_traffic.pcap using these keys.
"""

import hashlib
import hmac
import json
import os
import struct
import sys
import pathlib

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("pip3 install cryptography --break-system-packages")
    sys.exit(1)

REPO_ROOT = pathlib.Path(os.environ.get("NETPIPE_REPO_ROOT", "")).resolve() if os.environ.get("NETPIPE_REPO_ROOT") else pathlib.Path(__file__).resolve().parent.parent.parent
KEYLOG_PATH = REPO_ROOT / "tls_keys.log"
PCAP_PATH = REPO_ROOT / "encrypted_traffic.pcap"


def parse_keylog(path):
    """Parse NSS SSLKEYLOGFILE into {client_random_hex: {label: secret_bytes}}."""
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 3:
                continue
            label, cr_hex, sec_hex = parts
            cr = cr_hex.lower()
            out.setdefault(cr, {})[label] = bytes.fromhex(sec_hex)
    return out


def tls12_prf(secret, label, seed, out_len, hash_algo="sha256"):
    """TLS 1.2 PRF per RFC 5246 §5.

    PRF(secret, label, seed) = P_hash(secret, label + seed)
    P_hash(secret, seed) = HMAC(secret, A(1)+seed) || HMAC(secret, A(2)+seed) || ...
    A(0) = seed, A(i) = HMAC(secret, A(i-1))
    """
    ls = label.encode() + seed
    out = b""
    a = ls  # A(0)
    while len(out) < out_len:
        a = hmac.new(secret, a, hash_algo).digest()  # A(i) = HMAC(secret, A(i-1))
        out += hmac.new(secret, a + ls, hash_algo).digest()  # HMAC(secret, A(i)+ls)
    return out[:out_len]


def parse_pcap(path):
    with open(path, "rb") as f:
        header = f.read(24)
        magic = struct.unpack("<I", header[:4])[0]
        endian = "<" if magic == 0xa1b2c3d4 else ">"
        while True:
            rec = f.read(16)
            if len(rec) < 16: break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", rec)
            data = f.read(incl_len)
            yield (ts_sec, ts_usec, data)


def parse_tls_records(blob):
    records = []
    off = 0
    while off + 5 <= len(blob):
        ct = blob[off]
        length = struct.unpack(">H", blob[off+3:off+5])[0]
        if off + 5 + length > len(blob):
            records.append((ct, blob[off:]))
            break
        records.append((ct, blob[off:off+5+length]))
        off += 5 + length
    return records


def extract_client_random(rec):
    """From ClientHello record (type=22, handshake type=1)."""
    if rec[0] != 22: return None
    frag = rec[5:]
    if not frag or frag[0] != 1: return None
    if len(frag) < 38: return None
    return frag[6:38]


def extract_server_random_and_cipher(rec):
    """From ServerHello record (type=22, handshake type=2).
    Returns (server_random, cipher_suite, version_legacy)."""
    if rec[0] != 22: return None
    frag = rec[5:]
    if not frag or frag[0] != 2: return None
    if len(frag) < 38: return None
    server_random = frag[6:38]
    sid_len = frag[38]
    cipher_off = 39 + sid_len
    if len(frag) < cipher_off + 2: return None
    cipher = struct.unpack(">H", frag[cipher_off:cipher_off+2])[0]
    legacy_version = struct.unpack(">H", frag[3:5])[0]
    return (server_random, cipher, legacy_version)


def main():
    keylog = parse_keylog(KEYLOG_PATH)
    print(f"Loaded {len(keylog)} unique client_randoms from keylog\n")

    # Find the TLS 1.2 client_random (the one with a CLIENT_RANDOM record).
    tls12_cr = None
    tls12_master_secret = None
    for cr_hex, recs in keylog.items():
        if "CLIENT_RANDOM" in recs:
            tls12_cr = bytes.fromhex(cr_hex)
            tls12_master_secret = recs["CLIENT_RANDOM"]
            print(f"TLS 1.2 client_random: {cr_hex[:16]}...")
            print(f"  master_secret ({len(tls12_master_secret)}B): {tls12_master_secret.hex()[:32]}...")
            break

    if tls12_cr is None:
        print("No TLS 1.2 CLIENT_RANDOM record found in keylog")
        sys.exit(1)

    # Walk the PCAP to find the ServerHello for this flow.
    server_random = None
    cipher_suite = None
    for i, (ts_sec, ts_usec, frame) in enumerate(parse_pcap(PCAP_PATH)):
        if len(frame) < 14: continue
        ethertype = struct.unpack(">H", frame[12:14])[0]
        if ethertype != 0x0800: continue
        if len(frame) < 14 + 20 + 20: continue
        ip_proto = frame[14 + 9]
        if ip_proto != 6: continue  # TCP
        tls_blob = frame[14+20+20:]
        if not tls_blob: continue
        for ct, rec in parse_tls_records(tls_blob):
            if ct != 22: continue  # Handshake
            frag = rec[5:]
            if not frag: continue
            if frag[0] == 2:  # ServerHello
                result = extract_server_random_and_cipher(rec)
                if result:
                    sr, cipher, _ = result
                    # Check if this is the TLS 1.2 flow (cipher in 0xc0xx range).
                    if (cipher & 0xff00) != 0x1300:
                        server_random = sr
                        cipher_suite = cipher
                        print(f"\nServerHello (pkt {i+1}):")
                        print(f"  server_random: {sr.hex()[:32]}...")
                        print(f"  cipher_suite: 0x{cipher:04x}")
                        break
        if server_random is not None:
            break

    if server_random is None:
        print("No TLS 1.2 ServerHello found in PCAP")
        sys.exit(1)

    # Derive key_block.
    # Per RFC 5246 §6.3 + RFC 5288 §3 for GCM:
    #   key_block = PRF(master_secret, "key expansion",
    #                   server_random || client_random,
    #                   2 * key_len + 2 * 4)
    # Layout: client_write_key | server_write_key | client_write_IV | server_write_IV
    if cipher_suite in (0xc02f, 0xc02b, 0x009c):  # AES-128-GCM
        key_len = 16
        hash_algo = "sha256"
    elif cipher_suite in (0xc030, 0xc02c, 0x009d):  # AES-256-GCM-SHA384
        key_len = 32
        hash_algo = "sha384"
    elif cipher_suite in (0xcca8, 0xcca9):  # ChaCha20-Poly1305
        key_len = 32
        hash_algo = "sha256"
    else:
        print(f"Unsupported cipher suite: 0x{cipher_suite:04x}")
        sys.exit(1)

    seed = server_random + tls12_cr
    kb_len = 2 * key_len + 8
    key_block = tls12_prf(tls12_master_secret, "key expansion", seed, kb_len, hash_algo)

    client_write_key = key_block[:key_len]
    server_write_key = key_block[key_len:2*key_len]
    client_write_iv  = key_block[2*key_len:2*key_len+4]
    server_write_iv  = key_block[2*key_len+4:2*key_len+8]

    print(f"\nDerived key_block ({kb_len}B):")
    print(f"  client_write_key ({key_len}B): {client_write_key.hex()}")
    print(f"  server_write_key ({key_len}B): {server_write_key.hex()}")
    print(f"  client_write_IV  (4B): {client_write_iv.hex()}")
    print(f"  server_write_IV  (4B): {server_write_iv.hex()}")

    # Now find APPLICATION_DATA records on the TLS 1.2 flow and decrypt them.
    # The TLS 1.2 flow uses server port 4433 (from gen_tls_fixtures.py).
    # The TLS 1.3 flow uses server port 4434 — we must NOT try TLS 1.2 keys
    # on those packets.
    TLS12_SERVER_PORT = 4433
    print(f"\nSearching for APPLICATION_DATA records on TLS 1.2 flow (sport/dport={TLS12_SERVER_PORT})...")
    seq_c = 0
    seq_s = 0
    for i, (ts_sec, ts_usec, frame) in enumerate(parse_pcap(PCAP_PATH)):
        if len(frame) < 14: continue
        ethertype = struct.unpack(">H", frame[12:14])[0]
        if ethertype != 0x0800: continue
        if len(frame) < 14 + 20 + 20: continue
        ip_proto = frame[14 + 9]
        if ip_proto != 6: continue
        tcp_sport = struct.unpack(">H", frame[14+20:14+22])[0]
        tcp_dport = struct.unpack(">H", frame[14+22:14+24])[0]
        # Only process packets on the TLS 1.2 flow.
        if tcp_sport != TLS12_SERVER_PORT and tcp_dport != TLS12_SERVER_PORT:
            continue
        is_c2s = (tcp_sport > 1024 and tcp_dport < 1024) or (tcp_sport > tcp_dport)
        tls_blob = frame[14+20+20:]
        if not tls_blob: continue
        for ct, rec in parse_tls_records(tls_blob):
            if ct != 23: continue  # APPLICATION_DATA
            frag = rec[5:]
            if len(frag) < 24: continue
            # TLS 1.2 GCM: explicit_nonce(8) + ciphertext + tag(16)
            explicit_nonce = frag[:8]
            ciphertext_with_tag = frag[8:]
            ct_len = len(ciphertext_with_tag) - 16
            if ct_len <= 0: continue
            ciphertext = ciphertext_with_tag[:ct_len]
            tag = ciphertext_with_tag[ct_len:]
            # Build 12-byte nonce = implicit_IV(4) || explicit_nonce(8)
            if is_c2s:
                nonce = client_write_iv + explicit_nonce
                key = client_write_key
                seq = seq_c
            else:
                nonce = server_write_iv + explicit_nonce
                key = server_write_key
                seq = seq_s
            # AAD = seq(8) || type(1) || version(2) || plaintext_len(2)
            aad = struct.pack(">Q", seq) + bytes([23, 0x03, 0x03]) + struct.pack(">H", ct_len)
            try:
                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(nonce, ciphertext + tag, aad)
                if is_c2s:
                    seq_c += 1
                else:
                    seq_s += 1
                preview = plaintext[:80].decode("ascii", errors="replace").replace("\r", "\\r").replace("\n", "\\n")
                print(f"  pkt {i+1} ({'c2s' if is_c2s else 's2c'}, seq={seq}): DECRYPTED {len(plaintext)}B")
                print(f"    preview: {preview!r}")
            except Exception as e:
                print(f"  pkt {i+1} ({'c2s' if is_c2s else 's2c'}, seq={seq}): FAILED — {e}")
                print(f"    nonce: {nonce.hex()}")
                print(f"    aad:   {aad.hex()}")
                print(f"    key:   {key.hex()}")
                print(f"    ct_len: {ct_len}")

    print("\nDone.")


if __name__ == "__main__":
    main()
