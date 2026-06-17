#!/usr/bin/env python3
"""
25_protocol_stats.py — Aggregate protocol statistics across a PCAP

Replays any PCAP through netpipe's JSON sink, then builds a rich
statistics report in Python: packet counts, byte totals, protocol
distribution, and average/min/max packet sizes — all without root.

Run:
    python3 examples/python/25_protocol_stats.py [path/to/capture.pcap]

If no file is given, uses tests/fixtures/all.pcap.
"""

import subprocess
import json
import sys
import os
from collections import defaultdict

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
BIN       = os.path.join(REPO_ROOT, "build", "bin", "netpipe")


def run_json_pipeline(pcap_path: str):
    """Stream JSON records from netpipe, return list of dicts."""
    result = subprocess.run(
        [BIN, "-r", pcap_path, "-fmt", "json"],
        capture_output=True, text=True, timeout=30
    )
    packets = []
    for line in result.stdout.splitlines():
        if line.startswith("{"):
            try:
                packets.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return packets


def highest_proto(pkt: dict) -> str:
    """Return the highest decoded protocol name."""
    layers = pkt.get("layers", [])
    if layers:
        return layers[-1].get("proto", "unknown")
    return "unknown"


def print_bar(label: str, value: int, total: int, width: int = 30):
    pct  = value / total if total else 0
    bars = int(pct * width)
    print(f"  {label:<10} {'█'*bars:<{width}} {value:>6}  ({pct*100:5.1f}%)")


def main():
    pcap = sys.argv[1] if len(sys.argv) > 1 else \
           os.path.join(REPO_ROOT, "tests", "fixtures", "all.pcap")

    if not os.path.exists(pcap):
        print(f"ERROR: file not found: {pcap}", file=sys.stderr)
        sys.exit(1)

    print("=" * 62)
    print(f" netpipe — Example 25: Protocol Statistics")
    print(f" File: {os.path.basename(pcap)}")
    print("=" * 62)

    print("\nRunning pipeline...", end="", flush=True)
    packets = run_json_pipeline(pcap)
    print(f" {len(packets)} packets\n")

    if not packets:
        print("No packets decoded.")
        return

    # ── Aggregation ───────────────────────────────────────────────────
    total_pkts  = len(packets)
    total_bytes = sum(p.get("caplen", 0) for p in packets)

    proto_pkts  = defaultdict(int)
    proto_bytes = defaultdict(int)
    sizes       = [p.get("caplen", 0) for p in packets]
    flows       = set(p.get("flow_id", 0) for p in packets)

    for pkt in packets:
        proto = highest_proto(pkt)
        cap   = pkt.get("caplen", 0)
        proto_pkts[proto]  += 1
        proto_bytes[proto] += cap

    # ── Report ────────────────────────────────────────────────────────
    print(f"  Total packets : {total_pkts}")
    print(f"  Total bytes   : {total_bytes:,}")
    print(f"  Unique flows  : {len(flows)}")
    print(f"  Avg pkt size  : {total_bytes / total_pkts:.1f} B")
    print(f"  Min pkt size  : {min(sizes)} B")
    print(f"  Max pkt size  : {max(sizes)} B")

    print(f"\n  Protocol distribution by packets:")
    print(f"  {'Proto':<10} {'Bar':<32} {'Pkts':>6}  {'Share':>6}")
    print(f"  {'-'*62}")
    for proto, count in sorted(proto_pkts.items(), key=lambda x: -x[1]):
        print_bar(proto, count, total_pkts)

    print(f"\n  Protocol distribution by bytes:")
    print(f"  {'Proto':<10} {'Bar':<32} {'Bytes':>6}  {'Share':>6}")
    print(f"  {'-'*62}")
    for proto, nbytes in sorted(proto_bytes.items(), key=lambda x: -x[1]):
        print_bar(proto, nbytes, total_bytes)

    # ── Per-flow breakdown ────────────────────────────────────────────
    print(f"\n  Per-flow packet counts:\n")
    flow_pkts  = defaultdict(int)
    flow_bytes = defaultdict(int)
    for pkt in packets:
        fid = pkt.get("flow_id", 0)
        flow_pkts[fid]  += 1
        flow_bytes[fid] += pkt.get("caplen", 0)

    print(f"  {'Flow ID':>12}  {'Pkts':>6}  {'Bytes':>8}")
    print(f"  {'-'*12}  {'-'*6}  {'-'*8}")
    for fid, cnt in sorted(flow_pkts.items(), key=lambda x: -x[1]):
        print(f"  {fid:>12}  {cnt:>6}  {flow_bytes[fid]:>8}")

    print("\nDone.")


if __name__ == "__main__":
    main()
