#!/usr/bin/env python3
"""
27_pool_stats_monitor.py — Monitor netpipe's bufpool hit rate in real time.

This script launches netpipe with --show-pool-stats and parses the output
to verify the np_bufpool module (Fix #7 + Wiring #1) is working correctly.

A hit_rate of 100.0% means every packet buffer allocation was served from
the pre-allocated 128-slot slab — zero heap malloc calls after startup.
A hit_rate below 90% means the pool is too small for your workload;
consider increasing NP_PKT_POOL_SIZE in src/packet/np_packet.c.

Usage:
    sudo python3 27_pool_stats_monitor.py -i wlo1 -c 1000
    sudo python3 27_pool_stats_monitor.py -i wlo1 -c 50000 --warn-below 95

No external dependencies — just the Python standard library.
"""
import argparse
import re
import subprocess
import sys
import os

def parse_pool_stats(line):
    """Parse a bufpool stats line like:
    bufpool  cap=65536  slots=128  free=128  allocs=1018  misses=0  returns=1018  hit_rate=100.0%
    """
    pat = r'cap=(\d+)\s+slots=(\d+)\s+free=(\d+)\s+allocs=(\d+)\s+misses=(\d+)\s+returns=(\d+)\s+hit_rate=([\d.]+)%'
    m = re.search(pat, line)
    if not m:
        return None
    return {
        'cap': int(m.group(1)),
        'slots': int(m.group(2)),
        'free': int(m.group(3)),
        'allocs': int(m.group(4)),
        'misses': int(m.group(5)),
        'returns': int(m.group(6)),
        'hit_rate': float(m.group(7)),
    }

def main():
    parser = argparse.ArgumentParser(description='Monitor netpipe bufpool hit rate')
    parser.add_argument('-i', '--interface', default='wlo1', help='capture interface')
    parser.add_argument('-c', '--count', type=int, default=1000, help='packet count')
    parser.add_argument('--warn-below', type=float, default=90.0,
                        help='warn if hit_rate below this %% (default: 90)')
    parser.add_argument('-r', '--read', help='read from pcap file instead of live capture')
    parser.add_argument('--bin', default='./build/bin/netpipe', help='netpipe binary path')
    args = parser.parse_args()

    # Build the netpipe command
    cmd = [args.bin]
    if args.read:
        cmd += ['-r', args.read]
    else:
        cmd += ['-i', args.interface]
    cmd += ['-c', str(args.count), '-fmt', 'null', '--show-pool-stats', '-q']

    print(f"Running: {' '.join(cmd)}")
    print(f"Capturing {args.count} packets...")

    proc = subprocess.run(cmd, capture_output=True, text=True)
    output = proc.stdout + proc.stderr

    # Find the bufpool stats line
    stats = None
    for line in output.split('\n'):
        if 'bufpool' in line and 'hit_rate' in line:
            stats = parse_pool_stats(line)
            if stats:
                break

    if not stats:
        print("ERROR: no bufpool stats found in output")
        print("Raw output:")
        print(output)
        sys.exit(1)

    # Display the stats nicely
    print("\n" + "=" * 60)
    print("  PACKET BUFPOOL STATS  (np_bufpool module — Fix #7 + W1)")
    print("=" * 60)
    print(f"  Buffer capacity : {stats['cap']:>10,} bytes ({stats['cap']//1024} KB each)")
    print(f"  Pool slots      : {stats['slots']:>10,}")
    print(f"  Free slots      : {stats['free']:>10,}")
    print(f"  Allocations     : {stats['allocs']:>10,}")
    print(f"  Pool misses     : {stats['misses']:>10,}  (heap fallbacks)")
    print(f"  Returns         : {stats['returns']:>10,}")
    print(f"  Hit rate        : {stats['hit_rate']:>9.1f}%")
    print("=" * 60)

    # Verify the pool is working correctly
    print("\n  Analysis:")
    if stats['misses'] == 0:
        print(f"  ✓ Zero pool misses — 128-slot slab was sufficient")
    else:
        miss_pct = 100.0 * stats['misses'] / stats['allocs']
        print(f"  ⚠ {stats['misses']} pool misses ({miss_pct:.1f}%) — consider increasing NP_PKT_POOL_SIZE")

    if stats['allocs'] == stats['returns']:
        print(f"  ✓ All buffers returned (no leaks) — {stats['allocs']}/{stats['returns']}")
    else:
        print(f"  ✗ LEAK: {stats['allocs'] - stats['returns']} buffers not returned!")

    if stats['free'] == stats['slots']:
        print(f"  ✓ All {stats['slots']} slots back in free-list (clean shutdown)")
    else:
        print(f"  ⚠ {stats['slots'] - stats['free']} slots still in use at shutdown")

    if stats['hit_rate'] >= args.warn_below:
        print(f"  ✓ Hit rate {stats['hit_rate']}% >= {args.warn_below}% threshold — bufpool is effective")
        sys.exit(0)
    else:
        print(f"  ✗ Hit rate {stats['hit_rate']}% < {args.warn_below}% threshold — pool needs tuning")
        sys.exit(1)

if __name__ == '__main__':
    main()
