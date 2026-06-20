#!/usr/bin/env python3
"""
verify_tls_fixtures.py
──────────────────────
Reference implementation that verifies the generated tls_keys.log +
encrypted_traffic.pcap are actually decryptable, using Python's ssl
module + cryptography library.

This serves two purposes:
1. Sanity-check that the generated fixtures are valid.
2. Provide a known-good reference for what netpipe's TLS decryption
   should produce.
"""

import os
import struct
import sys
import hashlib
import hmac
import pathlib

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("This script requires the 'cryptography' package:")
    print("  pip3 install cryptography --break-system-packages")
    sys.exit(1)

REPO_ROOT = pathlib.Path(os.environ.get("NETPIPE_REPO_ROOT", "")).resolve() if os.environ.get("NETPIPE_REPO_ROOT") else pathlib.Path(__file__).resolve().parent.parent.parent
KEYLOG_PATH = REPO_ROOT / "tls_keys.log"
PCAP_PATH = REPO_ROOT / "encrypted_traffic.pcap"


def parse_keylog(path):
    """Parse an NSS SSLKEYLOGFILE into a dict of dicts.

    Returns: { client_random_hex: { "CLIENT_RANDOM": hex, "CLIENT_HANDSHAKE_TRAFFIC_SECRET": hex, ... } }
    """
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
            if cr not in out:
                out[cr] = {}
            out[cr][label] = bytes.fromhex(sec_hex)
    return out


def hkdf_expand_label(secret, label, length, hash_algo="sha256"):
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1)."""
    full_label = b"tls13 " + label.encode()
    info = struct.pack(">H", length) + \
           bytes([len(full_label)]) + full_label + \
           b"\x00"  # empty context
    return hkdf_expand(secret, info, length, hash_algo)


def hkdf_expand(prk, info, length, hash_algo="sha256"):
    """HKDF-Expand (RFC 5869 §2.3)."""
    hash_len = hashlib.new(hash_algo).digest_size
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_algo).digest()
        okm += t
    return okm[:length]


def parse_pcap(path):
    """Parse a libpcap file and yield (ts_sec, ts_usec, ethertype, packet_bytes)."""
    with open(path, "rb") as f:
        header = f.read(24)
        magic, _, _, _, _, snaplen, linktype = struct.unpack("<IHHiIII", header)
        if magic == 0xa1b2c3d4:
            endian = "<"
        elif magic == 0xd4c3b2a1:
            endian = ">"
        else:
            raise ValueError(f"Unknown PCAP magic: {magic:08x}")
        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", rec_hdr)
            data = f.read(incl_len)
            yield (ts_sec, ts_usec, data)


def parse_tls_records(blob):
    """Split a blob of TLS bytes into individual records."""
    records = []
    off = 0
    while off + 5 <= len(blob):
        ct = blob[off]
        ver = struct.unpack(">H", blob[off+1:off+3])[0]
        length = struct.unpack(">H", blob[off+3:off+5])[0]
        if off + 5 + length > len(blob):
            records.append((ct, ver, blob[off:]))
            break
        records.append((ct, ver, blob[off:off+5+length]))
        off += 5 + length
    return records


def extract_client_random(rec):
    """Extract the 32-byte client_random from a ClientHello record."""
    frag = rec[5:]
    if not frag or frag[0] != 1:  # ClientHello
        return None
    # frag: type(1) + len(3) + version(2) + random(32)
    if len(frag) < 38:
        return None
    return frag[6:38]


def extract_server_hello_cipher(rec):
    """Extract cipher suite + version from ServerHello."""
    frag = rec[5:]
    if not frag or frag[0] != 2:  # ServerHello
        return None
    # frag: type(1) + len(3) + version(2) + random(32) + session_id_len(1) + session_id + cipher(2)
    if len(frag) < 38:
        return None
    sid_len = frag[38]
    cipher_off = 39 + sid_len
    if len(frag) < cipher_off + 2:
        return None
    cipher = struct.unpack(">H", frag[cipher_off:cipher_off+2])[0]
    legacy_version = struct.unpack(">H", frag[3:5])[0]
    # In TLS 1.3, the ServerHello's legacy_version is 0x0303 but the cipher is in 0x13xx.
    if (cipher & 0xff00) == 0x1300:
        version = "1.3"
    else:
        version = "1.2"
    return (cipher, version)


def hash_for_cipher(cipher):
    """Return the HKDF hash algorithm name for a TLS 1.3 cipher suite."""
    if cipher == 0x1301:
        return "sha256"  # AES-128-GCM
    elif cipher == 0x1302:
        return "sha384"  # AES-256-GCM
    elif cipher == 0x1303:
        return "sha256"  # ChaCha20-Poly1305
    # TLS 1.2 ciphers — not decryptable by this reference impl (needs full PRF).
    if cipher in (0xc02f, 0xc02b, 0x009c, 0xcca8, 0xcca9):
        return "sha256"
    if cipher in (0xc030, 0xc02c, 0x009d):
        return "sha384"
    raise ValueError(f"Unsupported cipher: 0x{cipher:04x}")


def key_len_for_cipher(cipher):
    if cipher in (0x1301,):
        return 16
    elif cipher in (0x1302, 0x1303):
        return 32
    raise ValueError()


def derive_key_iv(secret, cipher, hash_algo):
    key_len = key_len_for_cipher(cipher)
    key = hkdf_expand_label(secret, "key", key_len, hash_algo)
    iv = hkdf_expand_label(secret, "iv", 12, hash_algo)
    return key, iv


def build_nonce(iv, seq):
    """XOR the 12-byte IV with the 64-bit sequence number (right-aligned)."""
    seq_bytes = struct.pack(">Q", seq)
    nonce = bytearray(iv)
    for i in range(8):
        nonce[12 - 8 + i] ^= seq_bytes[i]
    return bytes(nonce)


def decrypt_record(key, iv, seq, ct, ciphertext):
    """Decrypt a TLS 1.3 record using AES-GCM."""
    nonce = build_nonce(iv, seq)
    aad = bytes([ct, 0x03, 0x03]) + struct.pack(">H", len(ciphertext))
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext
    except Exception:
        return None


def main():
    print(f"Loading keylog: {KEYLOG_PATH}")
    keylog = parse_keylog(KEYLOG_PATH)
    print(f"  loaded {len(keylog)} unique client_randoms")
    for cr, recs in keylog.items():
        print(f"    {cr[:16]}...: {list(recs.keys())}")

    print(f"\nReading PCAP: {PCAP_PATH}")
    packets = list(parse_pcap(PCAP_PATH))
    print(f"  {len(packets)} packets")

    # State per-flow (keyed by client_random)
    flows = {}  # client_random_hex -> { cipher, version, hs_key, hs_iv, app_key, app_iv, hs_seq, app_seq }

    for i, (ts_sec, ts_usec, frame) in enumerate(packets):
        # Skip non-Ethernet frames.
        if len(frame) < 14:
            continue
        ethertype = struct.unpack(">H", frame[12:14])[0]
        if ethertype != 0x0800:
            continue
        # Skip non-TCP.
        if len(frame) < 14 + 20 + 20:
            continue
        ip_proto = frame[14 + 9]
        if ip_proto != 6:  # TCP
            continue
        # Extract TCP src/dst ports.
        tcp_sport = struct.unpack(">H", frame[14+20:14+22])[0]
        tcp_dport = struct.unpack(">H", frame[14+22:14+24])[0]
        # Determine direction (heuristic: higher port = client).
        is_c2s = (tcp_sport > 1024 and tcp_dport < 1024) or (tcp_sport > tcp_dport)

        # TLS payload starts after Ethernet(14) + IPv4(20) + TCP(20).
        tls_blob = frame[14+20+20:]
        if not tls_blob:
            continue
        records = parse_tls_records(tls_blob)
        for ct, ver, rec in records:
            if ct == 0x16:  # Handshake
                frag = rec[5:]
                if not frag:
                    continue
                hs_type = frag[0]
                if hs_type == 1:  # ClientHello
                    cr = extract_client_random(rec)
                    if cr:
                        cr_hex = cr.hex()
                        if cr_hex not in flows and cr_hex in keylog:
                            flows[cr_hex] = {
                                "cr": cr,
                                "is_c2s_first_seen": is_c2s,
                                "client_port": tcp_sport if is_c2s else tcp_dport,
                                "server_port": tcp_dport if is_c2s else tcp_sport,
                            }
                            print(f"\n  pkt {i+1}: ClientHello, cr={cr_hex[:16]}...")
                elif hs_type == 2:  # ServerHello
                    result = extract_server_hello_cipher(rec)
                    if result:
                        cipher, version = result
                        # Find the flow this belongs to.
                        for cr_hex, flow in flows.items():
                            if "cipher" not in flow:
                                flow["cipher"] = cipher
                                flow["version"] = version
                                flow["hash_algo"] = hash_for_cipher(cipher)
                                # Derive keys.
                                recs = keylog[cr_hex]
                                if version == "1.3":
                                    if "CLIENT_HANDSHAKE_TRAFFIC_SECRET" in recs:
                                        k, iv = derive_key_iv(recs["CLIENT_HANDSHAKE_TRAFFIC_SECRET"],
                                                            cipher, flow["hash_algo"])
                                        flow["c_hs_key"], flow["c_hs_iv"] = k, iv
                                    if "SERVER_HANDSHAKE_TRAFFIC_SECRET" in recs:
                                        k, iv = derive_key_iv(recs["SERVER_HANDSHAKE_TRAFFIC_SECRET"],
                                                            cipher, flow["hash_algo"])
                                        flow["s_hs_key"], flow["s_hs_iv"] = k, iv
                                    if "CLIENT_TRAFFIC_SECRET_0" in recs:
                                        k, iv = derive_key_iv(recs["CLIENT_TRAFFIC_SECRET_0"],
                                                            cipher, flow["hash_algo"])
                                        flow["c_app_key"], flow["c_app_iv"] = k, iv
                                    if "SERVER_TRAFFIC_SECRET_0" in recs:
                                        k, iv = derive_key_iv(recs["SERVER_TRAFFIC_SECRET_0"],
                                                            cipher, flow["hash_algo"])
                                        flow["s_app_key"], flow["s_app_iv"] = k, iv
                                    flow["c_hs_seq"] = 0
                                    flow["s_hs_seq"] = 0
                                    flow["c_app_seq"] = 0
                                    flow["s_app_seq"] = 0
                                print(f"  pkt {i+1}: ServerHello, cipher=0x{cipher:04x} ver={version}, keys derived")
                                break
            elif ct == 0x17:  # ApplicationData
                # Find the flow this packet belongs to (by port).
                for cr_hex, flow in flows.items():
                    if "cipher" not in flow:
                        continue
                    if is_c2s:
                        if tcp_sport != flow["client_port"] or tcp_dport != flow["server_port"]:
                            continue
                    else:
                        if tcp_sport != flow["server_port"] or tcp_dport != flow["client_port"]:
                            continue
                    # Try handshake key first, then app key.
                    ciphertext = rec[5:]
                    candidates = []
                    if flow["version"] == "1.3":
                        if is_c2s:
                            if "c_hs_key" in flow:
                                candidates.append(("c_hs", flow["c_hs_key"], flow["c_hs_iv"], "c_hs_seq"))
                            if "c_app_key" in flow:
                                candidates.append(("c_app", flow["c_app_key"], flow["c_app_iv"], "c_app_seq"))
                        else:
                            if "s_hs_key" in flow:
                                candidates.append(("s_hs", flow["s_hs_key"], flow["s_hs_iv"], "s_hs_seq"))
                            if "s_app_key" in flow:
                                candidates.append(("s_app", flow["s_app_key"], flow["s_app_iv"], "s_app_seq"))
                    for name, key, iv, seq_name in candidates:
                        seq = flow[seq_name]
                        pt = decrypt_record(key, iv, seq, ct, ciphertext)
                        if pt is not None:
                            flow[seq_name] += 1
                            # Strip trailing content-type byte (TLS 1.3).
                            if flow["version"] == "1.3" and pt:
                                inner_type = pt[-1]
                                if 20 <= inner_type <= 23:
                                    pt = pt[:-1]
                            label_preview = pt[:60].decode("ascii", errors="replace").replace("\r", "\\r").replace("\n", "\\n")
                            print(f"  pkt {i+1}: decrypted with {name} (seq={seq}, {len(pt)}B): {label_preview!r}")
                            break
                    else:
                        print(f"  pkt {i+1}: FAILED to decrypt (tried {len(candidates)} keys, dir={'c2s' if is_c2s else 's2c'})")
                    break
    print("\nDone.")


if __name__ == "__main__":
    main()
