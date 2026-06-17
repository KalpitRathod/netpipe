#!/usr/bin/env python3
"""
26_pcap_diff.py — Compare two PCAPs and highlight differences

Replays two PCAP files through netpipe's JSON sink, then computes a
side-by-side diff of protocol stacks, flow IDs, and packet sizes.
Useful for regression testing — confirm a code change didn't alter
captured traffic semantics.

No root required.

Run:
    python3 examples/python/26_pcap_diff.py <file_a.pcap> <file_b.pcap>

    # With the bundled fixtures (trivially identical but shows the mechanism):
    python3 examples/python/26_pcap_diff.py \
        tests/fixtures/all.pcap tests/fixtures/all.pcap
"""

import subprocess
import json
import sys
import os
from dataclasses import dataclass, field
from typing import List, Dict

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
BIN       = os.path.join(REPO_ROOT, "build", "bin", "netpipe")

RED   = "\033[31m"
GREEN = "\033[32m"
CYAN  = "\033[36m"
BOLD  = "\033[1m"
NC    = "\033[0m"


@dataclass
class PacketSummary:
    seq:      int
    caplen:   int
    wirelen:  int
    flow_id:  int
    protos:   List[str] = field(default_factory=list)

    def signature(self) -> str:
        return f"{'+'.join(self.protos)}:{self.caplen}"


def load_pcap(path: str) -> List[PacketSummary]:
    """Run netpipe JSON pipeline on path, return PacketSummary list."""
    result = subprocess.run(
        [BIN, "-r", path, "-fmt", "json"],
        capture_output=True, text=True, timeout=30
    )
    summaries = []
    for line in result.stdout.splitlines():
        if not line.startswith("{"): continue
        try:
            obj = json.loads(line)
            protos = [l["proto"] for l in obj.get("layers", [])]
            summaries.append(PacketSummary(
                seq=obj.get("seq", 0),
                caplen=obj.get("caplen", 0),
                wirelen=obj.get("wirelen", 0),
                flow_id=obj.get("flow_id", 0),
                protos=protos,
            ))
        except (json.JSONDecodeError, KeyError):
            pass
    return summaries


def proto_dist(pkts: List[PacketSummary]) -> Dict[str, int]:
    d: Dict[str, int] = {}
    for p in pkts:
        top = p.protos[-1] if p.protos else "?"
        d[top] = d.get(top, 0) + 1
    return d


def print_side(label: str, pkts: List[PacketSummary]):
    print(f"\n  {BOLD}{label}{NC}")
    print(f"  {'#':<4}  {'protocols':<30}  {'caplen':>7}  {'flow_id':>12}")
    print(f"  {'-'*4}  {'-'*30}  {'-'*7}  {'-'*12}")
    for p in pkts:
        stack = " → ".join(p.protos)
        print(f"  {p.seq:<4}  {stack:<30}  {p.caplen:>7}  {p.flow_id:>12}")


def main():
    if len(sys.argv) < 3:
        a = os.path.join(REPO_ROOT, "tests", "fixtures", "all.pcap")
        b = os.path.join(REPO_ROOT, "tests", "fixtures", "all.pcap")
        print(f"Usage: {sys.argv[0]} <a.pcap> <b.pcap>")
        print(f"Using defaults: all.pcap vs all.pcap (identical — for demo)\n")
    else:
        a, b = sys.argv[1], sys.argv[2]

    for path in (a, b):
        if not os.path.exists(path):
            print(f"ERROR: {path} not found", file=sys.stderr)
            sys.exit(1)

    print("=" * 62)
    print(f" netpipe — Example 26: PCAP Diff")
    print("=" * 62)
    print(f"\n  A: {os.path.basename(a)}")
    print(f"  B: {os.path.basename(b)}")

    pkts_a = load_pcap(a)
    pkts_b = load_pcap(b)

    print_side(f"A — {len(pkts_a)} packets", pkts_a)
    print_side(f"B — {len(pkts_b)} packets", pkts_b)

    # ── Packet-count diff ─────────────────────────────────────────────
    print(f"\n{BOLD}  Packet count:{NC}")
    if len(pkts_a) == len(pkts_b):
        print(f"  {GREEN}✓  Same: {len(pkts_a)}{NC}")
    else:
        print(f"  {RED}✗  A={len(pkts_a)}  B={len(pkts_b)}  Δ={abs(len(pkts_a)-len(pkts_b))}{NC}")

    # ── Protocol distribution diff ────────────────────────────────────
    print(f"\n{BOLD}  Protocol distribution:{NC}")
    dist_a = proto_dist(pkts_a)
    dist_b = proto_dist(pkts_b)
    all_protos = sorted(set(list(dist_a) + list(dist_b)))
    print(f"  {'Proto':<12}  {'A':>5}  {'B':>5}  {'Δ':>5}")
    print(f"  {'-'*12}  {'-'*5}  {'-'*5}  {'-'*5}")
    diffs_found = 0
    for proto in all_protos:
        ca, cb = dist_a.get(proto, 0), dist_b.get(proto, 0)
        delta = cb - ca
        color = GREEN if delta == 0 else RED
        mark  = "✓" if delta == 0 else "✗"
        print(f"  {color}{mark} {proto:<10}  {ca:>5}  {cb:>5}  {delta:>+5}{NC}")
        if delta != 0:
            diffs_found += 1

    # ── Per-packet signature diff ─────────────────────────────────────
    print(f"\n{BOLD}  Per-packet signature diff (proto_stack:caplen):{NC}")
    max_len = max(len(pkts_a), len(pkts_b))
    any_diff = False
    for i in range(max_len):
        pa = pkts_a[i] if i < len(pkts_a) else None
        pb = pkts_b[i] if i < len(pkts_b) else None
        sa = pa.signature() if pa else "(missing)"
        sb = pb.signature() if pb else "(missing)"
        if sa == sb:
            print(f"  {GREEN}✓{NC}  [{i+1}] {sa}")
        else:
            print(f"  {RED}✗{NC}  [{i+1}] A={sa}  B={sb}")
            any_diff = True

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{BOLD}  Summary:{NC}")
    if not any_diff and diffs_found == 0:
        print(f"  {GREEN}✓  Files are semantically identical{NC}")
    else:
        if any_diff:
            print(f"  {RED}✗  Packet-level differences found{NC}")
        if diffs_found:
            print(f"  {RED}✗  {diffs_found} protocol distribution difference(s){NC}")

    print("\nDone.")


if __name__ == "__main__":
    main()
