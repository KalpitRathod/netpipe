#!/usr/bin/env python3
"""
test_mitigate_lua.py
────────────────────
End-to-end validation of the Lua IDS scenario (mitigate.lua).

Builds synthetic DNS PCAPs that exercise every detection rule in
mitigate.lua, runs them through `netpipe -proc lua:mitigate.lua`,
and asserts on the [!!!] LUA SECURITY ALERT lines that fire.

Detection rules exercised:
  1. long_dns_name  (qname >= 50 chars)
  2. exfil_keyword  (qname matches exfil[%-_]payload)
  3. EXFIL_PAYLOAD  (long + exfil pattern + dst=8.8.8.8)
  4. dns_tunnel_suspect (long single label + base32-ish pattern)
  5. dns_normal     (clean qname — must NOT fire alert)

Also verifies the DROP semantics: when process() returns false, the
pipeline drops the packet (it does NOT reach the JSON sink).
"""

import os
import struct
import subprocess
import sys
import pathlib
import tempfile
import re

REPO_ROOT = pathlib.Path("/home/z/my-project/netpipe/netpipe-0.1.0")
NETPIPE   = REPO_ROOT / "build" / "bin" / "netpipe"
MITIGATE  = REPO_ROOT / "mitigate.lua"
LD_PATH   = "/home/z/my-project/deps/local/lib"

# ─── PCAP builder ──────────────────────────────────────────────────────

PCAP_MAGIC = 0xa1b2c3d4

def write_pcap_header(f):
    f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))

def write_pcap_record(f, data, ts_sec=0, ts_usec=0):
    f.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)))
    f.write(data)

def dns_encode_name(name: str) -> bytes:
    """Encode a domain name as DNS labels: len+label ... 0."""
    out = b""
    for label in name.split("."):
        if not label: continue
        b = label.encode("ascii")
        out += bytes([len(b)]) + b
    out += b"\x00"
    return out

def build_dns_query(txid: int, qname: str, qtype: int = 1) -> bytes:
    """Build a DNS query payload (no IP/UDP headers)."""
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    q = dns_encode_name(qname) + struct.pack(">HH", qtype, 1)  # type, class IN
    return header + q

def build_udp_packet(src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int,
                     payload: bytes) -> bytes:
    """Build an Ethernet/IPv4/UDP frame."""
    eth = (b'\x00\x11\x22\x33\x44\x55'
           b'\x66\x77\x88\x99\xaa\xbb'
           + struct.pack(">H", 0x0800))

    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", src_port, dst_port, udp_len, 0) + payload

    ip_total = 20 + len(udp)
    ip_hdr = struct.pack(">BBHHHBBH",
                         0x45, 0, ip_total,
                         0x1234, 0x4000,
                         64, 17, 0)  # ttl, proto=UDP, checksum=0
    ip_hdr += bytes(int(x) for x in src_ip.split("."))
    ip_hdr += bytes(int(x) for x in dst_ip.split("."))

    return eth + ip_hdr + udp

def build_dns_pcap(queries):
    """Build a PCAP file containing the given DNS queries.

    `queries` is a list of (txid, src_ip, dst_ip, src_port, dst_port, qname).
    Returns the path to a temporary file.
    """
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="mitigate_test_")
    with os.fdopen(fd, "wb") as f:
        write_pcap_header(f)
        for i, (txid, sip, dip, sp, dp, qname) in enumerate(queries):
            dns = build_dns_query(txid, qname)
            pkt = build_udp_packet(sip, dip, sp, dp, dns)
            write_pcap_record(f, pkt, ts_sec=1000 + i, ts_usec=0)
    return path

# ─── Test cases ────────────────────────────────────────────────────────

# Each case: (name, list_of_queries, expected_alert_substrings, expected_drops)
# - expected_alert_substrings: substrings that MUST appear in netpipe's stderr
# - expected_drops: number of packets that should be DROPPED (not pass to sink)

CLEAN_SRC   = "10.0.0.1"
ATTACK_SRC  = "10.0.0.99"
DNS_SERVER  = "8.8.8.8"
OTHER_DNS   = "1.1.1.1"

TEST_CASES = [
    {
        "name": "clean DNS queries (no alerts)",
        "queries": [
            (0x1111, CLEAN_SRC, DNS_SERVER, 5000, 53, "example.com"),
            (0x2222, CLEAN_SRC, DNS_SERVER, 5001, 53, "www.wikipedia.org"),
            (0x3333, CLEAN_SRC, OTHER_DNS,  5002, 53, "google.com"),
        ],
        "must_have": [],
        "must_not_have": ["LUA SECURITY ALERT"],
        "expected_drops": 0,
    },
    {
        "name": "long DNS name (>= 50 chars)",
        "queries": [
            (0x4444, ATTACK_SRC, DNS_SERVER, 5003, 53,
             "this-is-a-very-long-domain-name-that-exceeds-fifty-characters.example.com"),
        ],
        "must_have": ["long_dns_name", "LUA SECURITY ALERT"],
        "must_not_have": [],
        "expected_drops": 1,
    },
    {
        "name": "exfil keyword in qname",
        "queries": [
            (0x5555, ATTACK_SRC, DNS_SERVER, 5004, 53,
             "exfil-payload-data.attacker.com"),
        ],
        "must_have": ["exfil_keyword", "LUA SECURITY ALERT"],
        "must_not_have": [],
        "expected_drops": 1,
    },
    {
        "name": "EXFIL_PAYLOAD (long + exfil + dst=8.8.8.8)",
        "queries": [
            (0x6666, ATTACK_SRC, DNS_SERVER, 5005, 53,
             "exfil-payload-data-that-is-also-very-long-and-suspicious.attacker.com"),
        ],
        "must_have": ["EXFIL_PAYLOAD", "LUA SECURITY ALERT"],
        "must_not_have": [],
        "expected_drops": 1,
    },
    {
        "name": "DNS tunnel suspect (long base32 single label)",
        "queries": [
            # Short total qname (< 50 chars) but with a 32-char base32
            # label (no vowels, all [a-z0-9]) — should trigger
            # dns_tunnel_suspect, NOT long_dns_name.
            (0x7777, ATTACK_SRC, DNS_SERVER, 5006, 53,
             "qzjqzjqzjqzjqzjqzjqzjqzjqzjqzjqz.xx.com"),
        ],
        "must_have": ["dns_tunnel_suspect", "LUA SECURITY ALERT"],
        "must_not_have": [],
        "expected_drops": 1,
    },
    {
        "name": "mixed: clean + attack in same capture",
        "queries": [
            (0x8888, CLEAN_SRC,  DNS_SERVER, 5007, 53, "example.com"),
            (0x9999, ATTACK_SRC, DNS_SERVER, 5008, 53,
             "exfil-payload-super-long-data-exfil-payload-test.attacker.com"),
            (0xAAAA, CLEAN_SRC,  DNS_SERVER, 5009, 53, "google.com"),
        ],
        "must_have": ["EXFIL_PAYLOAD", "LUA SECURITY ALERT"],
        "must_not_have": [],
        "expected_drops": 1,
    },
]

# ─── Runner ────────────────────────────────────────────────────────────

GREEN = "\033[32m"
RED = "\033[31m"
BOLD = "\033[1m"
NC = "\033[0m"

def run_mitigate(pcap_path):
    """Run netpipe with mitigate.lua against the given PCAP.

    Returns (combined_output, json_packet_count).

    Lua's `print` goes to stdout, netpipe's INFO logs go to stderr.
    We combine both so the test can search for alert substrings
    regardless of which stream they appear on.
    """
    cmd = [
        str(NETPIPE),
        "-r", str(pcap_path),
        "-proc", f"lua:{MITIGATE}",
        "-fmt", "json",
    ]
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = LD_PATH

    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=15)
    combined = proc.stdout + "\n" + proc.stderr
    # Count JSON packet lines on stdout.
    json_count = 0
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            json_count += 1
    return combined, json_count

def run_one_case(case):
    """Run one test case.  Returns (passed, message)."""
    pcap_path = build_dns_pcap(case["queries"])
    try:
        combined, json_count = run_mitigate(pcap_path)
    finally:
        os.unlink(pcap_path)

    # Check must_have substrings.
    for sub in case["must_have"]:
        if sub not in combined:
            return False, f"expected '{sub}' in output but didn't find it.\n--- output ---\n{combined}"

    # Check must_not_have substrings.
    for sub in case["must_not_have"]:
        if sub in combined:
            return False, f"did NOT expect '{sub}' in output but found it.\n--- output ---\n{combined}"

    # Check drop count: total queries - queries that reached JSON sink.
    expected_drops = case["expected_drops"]
    total_queries = len(case["queries"])
    expected_json_count = total_queries - expected_drops
    if json_count != expected_json_count:
        return False, (f"expected {expected_json_count} packets to reach JSON sink "
                       f"({total_queries} - {expected_drops} drops), got {json_count}.\n"
                       f"--- output ---\n{combined}")

    return True, "OK"

def main():
    if not NETPIPE.exists():
        print(f"{RED}ERROR: netpipe binary not found at {NETPIPE}{NC}")
        sys.exit(1)
    if not MITIGATE.exists():
        print(f"{RED}ERROR: mitigate.lua not found at {MITIGATE}{NC}")
        sys.exit(1)

    print(f"{BOLD}=== mitigate.lua end-to-end validation ==={NC}\n")
    print(f"netpipe: {NETPIPE}")
    print(f"script:  {MITIGATE}\n")

    passed = 0
    failed = 0
    for case in TEST_CASES:
        print(f"  [test] {case['name']}...", end="", flush=True)
        ok, msg = run_one_case(case)
        if ok:
            print(f" {GREEN}PASS{NC}")
            passed += 1
        else:
            print(f" {RED}FAIL{NC}")
            print(f"    {msg}")
            failed += 1

    print(f"\n{BOLD}Summary:{NC} {passed}/{len(TEST_CASES)} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
