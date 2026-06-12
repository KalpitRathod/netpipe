#!/usr/bin/env python3
"""
examples/python/07_packet_firewall.py
───────────────────────────────────────
Passive firewall logger — watches live traffic and alerts on policy violations.

Policies you define in a simple YAML-like dict:
  • Blocked IPs      — alert if traffic to/from blacklisted IPs
  • Blocked ports    — alert on connections to disallowed ports
  • Allowed hours    — alert if heavy traffic outside office hours
  • Proto whitelist  — alert on unexpected protocols (e.g. TLS on port 80)

NOTE: This is a PASSIVE monitor (read-only). It cannot block packets —
      that requires iptables/nftables. But this can DETECT and LOG violations
      so you can act (email alert, iptables rule, etc.)

Usage:
    sudo python3 07_packet_firewall.py wlo1
    sudo python3 07_packet_firewall.py wlo1 --log violations.jsonl
"""

import subprocess, sys, json, argparse, time, signal
from datetime import datetime

NETPIPE = "../../build/bin/netpipe"

# ── Policy definition ────────────────────────────────────────────────────────
POLICY = {
    # Alert if traffic involves any of these IPs
    "blocked_ips": {
        # "1.2.3.4",
        # "5.6.7.8",
    },

    # Alert on connections to these destination ports
    "blocked_ports": {
        23,    # Telnet — unencrypted
        # 21,    # FTP plain
        # 3389,  # RDP (alert if public)
    },

    # Alert on these protocol combinations (proto → disallowed_ports)
    "proto_port_violations": {
        # "tls": {80},        # TLS on plain-HTTP port is suspicious
        # "http": {443},      # plain HTTP on HTTPS port
    },

    # Alert if any packet arrives outside these hours (24h, local time)
    "allowed_hours": None,   # e.g. (8, 20) for 8am–8pm, None = always allowed
}

# ── Helpers ──────────────────────────────────────────────────────────────────
RED   = "\033[1;31m"
CYAN  = "\033[36m"
RESET = "\033[0m"
DIM   = "\033[2m"

def extract_ip(raw_hex):
    """Extract src and dst IPv4 from raw hex (offset 26 and 30 in Ethernet frame)."""
    try:
        raw = bytes.fromhex(raw_hex)
        if len(raw) < 34:
            return None, None
        def fmt(b): return ".".join(str(x) for x in b)
        return fmt(raw[26:30]), fmt(raw[30:34])
    except Exception:
        return None, None

def extract_ports(raw_hex):
    """Extract src/dst ports from TCP/UDP layer (bytes 34-37 in Ethernet frame)."""
    try:
        raw = bytes.fromhex(raw_hex)
        if len(raw) < 38:
            return None, None
        src = int.from_bytes(raw[34:36], "big")
        dst = int.from_bytes(raw[36:38], "big")
        return src, dst
    except Exception:
        return None, None

violations_seen = 0

def check_policy(pkt, log_fh):
    global violations_seen
    raw = pkt.get("raw_hex", "")
    protos = {l["proto"] for l in pkt["layers"]}
    src_ip, dst_ip = extract_ip(raw)
    src_port, dst_port = extract_ports(raw) if \
        ("tcp" in protos or "udp" in protos) else (None, None)

    now = datetime.now()
    ts  = now.strftime("%H:%M:%S")
    violations = []

    # Blocked IPs
    for ip in (src_ip, dst_ip):
        if ip and ip in POLICY["blocked_ips"]:
            violations.append({"rule": "BLOCKED_IP", "value": ip})

    # Blocked ports
    for port in (src_port, dst_port):
        if port and port in POLICY["blocked_ports"]:
            violations.append({"rule": "BLOCKED_PORT", "value": port})

    # Proto/port violations
    for proto, bad_ports in POLICY["proto_port_violations"].items():
        if proto in protos:
            for port in (src_port, dst_port):
                if port and port in bad_ports:
                    violations.append({"rule": "PROTO_PORT",
                                       "value": f"{proto} on port {port}"})

    # Time-based policy
    if POLICY["allowed_hours"]:
        lo, hi = POLICY["allowed_hours"]
        if not (lo <= now.hour < hi):
            violations.append({"rule": "OUT_OF_HOURS",
                               "value": f"{now.hour:02d}:{now.minute:02d}"})

    for v in violations:
        violations_seen += 1
        record = {
            "ts":       pkt["ts"],
            "rule":     v["rule"],
            "value":    str(v["value"]),
            "src_ip":   src_ip,
            "dst_ip":   dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protos":   list(protos),
            "flow_id":  pkt["flow_id"],
            "caplen":   pkt["caplen"],
        }
        if log_fh:
            log_fh.write(json.dumps(record) + "\n")
            log_fh.flush()

        print(f"\n{RED}[{ts}] 🚨 VIOLATION  {v['rule']}  →  {v['value']}{RESET}")
        print(f"     src={src_ip}:{src_port}  dst={dst_ip}:{dst_port}  "
              f"protos={','.join(protos)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("interface")
    ap.add_argument("--log", "-l", default=None,
                    help="write violations to this JSONL file")
    args = ap.parse_args()

    cmd = [NETPIPE, "-i", args.interface, "-fmt", "json", "-q"]

    print(f"\033[1mPassive Firewall Monitor\033[0m on {args.interface}  "
          f"(Ctrl-C to stop)")
    print(f"Policy: blocked_ports={POLICY['blocked_ports']}  "
          f"blocked_ips={POLICY['blocked_ips']}")
    if args.log:
        print(f"Logging violations to: {args.log}")
    print("─" * 60)

    log_fh = open(args.log, "a") if args.log else None
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
            check_policy(pkt, log_fh)

            if total % 500 == 0:
                print(f"{DIM}[{time.strftime('%H:%M:%S')}] "
                      f"inspected {total:,} packets  "
                      f"violations={violations_seen}{RESET}")

        proc.terminate()

    if log_fh:
        log_fh.close()
    print(f"\nDone. {total:,} packets inspected, {violations_seen} violations.")

if __name__ == "__main__":
    main()
