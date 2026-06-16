#!/usr/bin/env python3
"""
examples/python/08_browser_spy.py
───────────────────────────────────
Watch what websites your browser visits — even on HTTPS.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHY THE HTTP SNIFFER SHOWS NOTHING FOR GOOGLE:
────────────────────────────────────────────────────────────────
  • google.com always redirects to HTTPS (port 443, TLS-encrypted).
  • The HTTP sniffer watches port 80 (plain HTTP) — there is
    nothing there for modern sites.
  • The actual page content is encrypted and cannot be read.

WHAT CAN STILL BE SEEN (even on HTTPS):
────────────────────────────────────────────────────────────────
  1. DNS query  (port 53, always plaintext)
       → "who is resolving google.com?"

  2. TLS ClientHello SNI  (plaintext field INSIDE the TLS handshake)
       → "which hostname is the client connecting to?"
       → Visible even before any encryption is negotiated!

  3. TCP connection metadata
       → destination IP, port, timing, packet sizes

This script shows all three. Open any website in your browser
while this is running and you will see it immediately.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Usage:
    sudo python3 08_browser_spy.py wlo1
    sudo python3 08_browser_spy.py wlo1 --no-dns   # only TLS SNI
    sudo python3 08_browser_spy.py wlo1 --no-tls   # only DNS
"""

import subprocess, sys, json, argparse, signal, time
import pathlib as _pl
_HERE = _pl.Path(__file__).resolve().parent
NETPIPE = str(next(
    (p for p in [
        _HERE / "../../build/bin/netpipe",
        _pl.Path("/usr/local/bin/netpipe"),
        _pl.Path("/usr/bin/netpipe"),
    ] if p.exists()), _HERE / "../../build/bin/netpipe"
))

# ── ANSI ────────────────────────────────────────────────────────────────────
CYAN   = "\033[1;36m"
GREEN  = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE   = "\033[1;34m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── DNS name decoder ─────────────────────────────────────────────────────────
def decode_dns_name(raw: bytes, offset: int) -> str:
    """Decode a DNS wire-format name starting at `offset`."""
    labels = []
    visited = set()
    pos = offset
    try:
        while pos < len(raw):
            if pos in visited:
                break
            visited.add(pos)
            length = raw[pos]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:      # compression pointer
                if pos + 1 >= len(raw):
                    break
                ptr = ((length & 0x3F) << 8) | raw[pos + 1]
                pos = ptr
                continue
            pos += 1
            labels.append(raw[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
    except Exception:
        pass
    return ".".join(labels) if labels else ""


def extract_dns(raw_hex: str):
    """
    Extract DNS question names from a raw frame.
    Returns list of (name, is_response) tuples.
    """
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return []

    # DNS over UDP: Eth(14) + IP(20) + UDP(8) = offset 42
    dns_offsets = [42]
    # DNS over TCP (port 53): Eth(14)+IP(20)+TCP(20)+2-byte length prefix = 56
    dns_offsets.append(56)

    results = []
    for off in dns_offsets:
        if off + 12 >= len(raw):
            continue
        d = raw[off:]
        if len(d) < 12:
            continue
        flags     = (d[2] << 8) | d[3]
        qdcount   = (d[4] << 8) | d[5]
        is_resp   = bool(flags & 0x8000)
        if qdcount == 0 or qdcount > 16:
            continue
        name = decode_dns_name(d, 12)
        if name and "." in name:
            results.append((name, is_resp))
            break
    return results


# ── TLS SNI extractor ────────────────────────────────────────────────────────
def extract_tls_sni(raw_hex: str) -> str:
    """
    Parse TLS ClientHello and extract the SNI (Server Name Indication).
    SNI is in plaintext — it's how the server knows which certificate to send
    before any encryption is established.

    TLS record layout (after TCP payload):
      1B  content_type   (22 = handshake)
      2B  version
      2B  record_length
      1B  handshake_type (1 = ClientHello)
      3B  handshake_length
      2B  client_version
     32B  random
      1B  session_id_length
      ?B  session_id
      2B  cipher_suites_length
      ?B  cipher_suites
      1B  compression_methods_length
      ?B  compression_methods
      2B  extensions_length
      --- extensions ---
      each extension: 2B type + 2B length + ?B data
      SNI extension type = 0x0000
    """
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return ""

    # TCP payload starts at Eth(14)+IP(20)+TCP(20) = 54
    # But TCP header can be longer (options); try offsets 54, 66, 78
    for base in (54, 66, 78, 90):
        if base >= len(raw):
            continue
        d = raw[base:]
        try:
            # Check TLS record header
            if len(d) < 6:
                continue
            if d[0] != 22:                # content_type must be Handshake
                continue
            if d[1] not in (3,):          # major version must be 3 (TLS)
                continue
            if d[5] != 1:                 # handshake_type must be ClientHello
                continue

            pos = 9                       # skip record(5) + handshake_type(1) + length(3)
            if pos + 2 > len(d):
                continue
            pos += 2                      # skip client_version (2B)
            pos += 32                     # skip random (32B)
            if pos >= len(d): continue
            sid_len = d[pos]; pos += 1 + sid_len   # skip session_id
            if pos + 2 > len(d): continue
            cs_len = (d[pos] << 8) | d[pos+1]; pos += 2 + cs_len  # cipher suites
            if pos >= len(d): continue
            cm_len = d[pos]; pos += 1 + cm_len   # compression methods
            if pos + 2 > len(d): continue

            ext_total = (d[pos] << 8) | d[pos+1]; pos += 2
            ext_end   = pos + ext_total

            while pos + 4 <= ext_end and pos + 4 <= len(d):
                ext_type = (d[pos] << 8) | d[pos+1]
                ext_len  = (d[pos+2] << 8) | d[pos+3]
                pos += 4
                if ext_type == 0x0000:    # SNI extension
                    # SNI list: 2B list_len, 1B name_type, 2B name_len, ?B name
                    if pos + 5 <= len(d):
                        name_len = (d[pos+3] << 8) | d[pos+4]
                        name_start = pos + 5
                        if name_start + name_len <= len(d):
                            return d[name_start:name_start+name_len].decode(
                                "ascii", errors="replace")
                pos += ext_len
        except (IndexError, ValueError):
            continue
    return ""


# ── Main ────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Watch what sites your browser visits (DNS + TLS SNI)")
    ap.add_argument("interface", help="network interface e.g. wlo1")
    ap.add_argument("--no-dns", action="store_true", help="hide DNS events")
    ap.add_argument("--no-tls", action="store_true", help="hide TLS SNI events")
    ap.add_argument("--all-layers", action="store_true",
                    help="show every packet (very noisy)")
    args = ap.parse_args()

    # Capture both DNS and TLS on the same interface
    cmd = [NETPIPE, "-i", args.interface, "-fmt", "json", "-q"]

    print(f"""
{CYAN}{'━'*62}{RESET}
{CYAN}  Browser Spy  {RESET}— watching {args.interface}

  Open any website in your browser.
  You will see:
    {GREEN}[DNS]{RESET}  domain name lookups (plaintext, port 53)
    {YELLOW}[TLS]{RESET}  HTTPS site hostnames from the TLS handshake
         (visible even though traffic is encrypted!)

  {DIM}Content of HTTPS pages is fully encrypted — only the
  hostname (SNI) is exposed in the TLS ClientHello.{RESET}
{CYAN}{'━'*62}{RESET}

  {"TIME":<10}  {"TYPE":<6}  HOSTNAME
  {"────":<10}  {"────":<6}  ────────────────────────────────
""")

    seen_domains: set = set()
    total = 0
    running = True

    def stop(sig, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGINT, stop)

    with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True) as proc:
        for line in proc.stdout:
            if not running:
                break
            line = line.strip()
            if not line:
                continue
            try:
                pkt = json.loads(line)
            except json.JSONDecodeError:
                continue

            total += 1
            ts    = pkt["ts"].split(".")[0]
            protos = {l["proto"] for l in pkt["layers"]}
            raw   = pkt.get("raw_hex", "")

            # ── DNS ───────────────────────────────────────────────────
            if not args.no_dns and "dns" in protos:
                for name, is_resp in extract_dns(raw):
                    if not name or is_resp:
                        continue
                    tag = "NEW  " if name not in seen_domains else "     "
                    seen_domains.add(name)
                    print(f"  {ts:<10}  {GREEN}[DNS]{RESET}  {GREEN}{name}{RESET}  {DIM}{tag}{RESET}")

            # ── TLS SNI ──────────────────────────────────────────────
            if not args.no_tls and "tls" in protos:
                sni = extract_tls_sni(raw)
                if sni:
                    tag = "NEW  " if sni not in seen_domains else "     "
                    seen_domains.add(sni)
                    print(f"  {ts:<10}  {YELLOW}[TLS]{RESET}  {YELLOW}{sni}{RESET}  {DIM}{tag}{RESET}")

            # ── All layers (noisy debug mode) ─────────────────────────
            if args.all_layers:
                layers = " → ".join(l["proto"] for l in pkt["layers"])
                print(f"  {DIM}{ts}  {pkt['caplen']:>5}B  {layers}{RESET}")

    proc.terminate()
    print(f"\n  Captured {total} packets. Unique domains/hosts: {len(seen_domains)}")
    if seen_domains:
        print("\n  All seen:")
        for d in sorted(seen_domains):
            print(f"    {d}")

if __name__ == "__main__":
    main()
