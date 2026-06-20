#!/usr/bin/env python3
"""
30_registry_explorer.py — Explore netpipe's plugin registry from Python.

This script demonstrates the np_registry module (Wiring #2) by:
  1. Running `netpipe --list-sinks` and `--list-sources` to enumerate
     registered plugins
  2. Parsing the output into structured data
  3. Verifying all expected built-ins are present
  4. Displaying which file extensions map to which sinks

This is useful for:
  - Verifying a custom plugin compiled and registered correctly
  - Discovering what sinks are available on a given netpipe build
  - Building tooling that auto-selects output format based on file extension

Usage:
    python3 30_registry_explorer.py
    python3 30_registry_explorer.py --bin /usr/local/bin/netpipe

No external dependencies — just the Python standard library.
"""
import argparse
import re
import subprocess
import sys
from collections import OrderedDict

def parse_registry_output(output):
    """Parse `netpipe --list-sinks` or `--list-sources` output.

    Expected format (with ANSI color codes stripped):
        Registered sinks:
          null                  Discard all packets (for benchmarking)  [.]
          stats                 Periodic (5-second) packet/byte counters  [.stats]
          ...

    Returns a list of dicts: {name, long_name, extensions}
    """
    # Strip ANSI escape codes
    output = re.sub(r'\x1b\[[0-9;]*m', '', output)

    entries = []
    for line in output.split('\n'):
        # Match lines like: "  json                  Newline-delimited JSON...  [.json,ndjson]"
        m = re.match(r'^\s+(\S+)\s{2,}(.+?)(?:\s+\[([^\]]*)\])?\s*$', line)
        if m:
            name = m.group(1)
            long_name = m.group(2).strip()
            extensions = m.group(3) if m.group(3) else ''
            # Don't treat the header line as an entry
            if name in ('Registered', 'sinks:', 'sources:'):
                continue
            entries.append({
                'name': name,
                'long_name': long_name,
                'extensions': [e.strip() for e in extensions.split(',') if e.strip()],
            })
    return entries

def run_netpipe(bin_path, flag):
    """Run netpipe with --list-sinks or --list-sources, return parsed entries."""
    cmd = [bin_path, flag]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return parse_registry_output(proc.stdout)

def main():
    parser = argparse.ArgumentParser(description='Explore netpipe plugin registry')
    parser.add_argument('--bin', default='./build/bin/netpipe', help='netpipe binary path')
    args = parser.parse_args()

    print(f"Exploring plugin registry of: {args.bin}")
    print("=" * 70)

    # Get sinks
    sinks = run_netpipe(args.bin, '--list-sinks')
    print(f"\n📊 Registered Sinks ({len(sinks)}):")
    print("-" * 70)
    print(f"  {'Name':<12} {'Extensions':<16} {'Description'}")
    print("-" * 70)
    for s in sinks:
        exts = ', '.join(s['extensions']) if s['extensions'] else '(none)'
        print(f"  {s['name']:<12} {exts:<16} {s['long_name']}")

    # Get sources
    sources = run_netpipe(args.bin, '--list-sources')
    print(f"\n📡 Registered Sources ({len(sources)}):")
    print("-" * 70)
    print(f"  {'Name':<12} {'Description'}")
    print("-" * 70)
    for s in sources:
        print(f"  {s['name']:<12} {s['long_name']}")

    # Verify expected built-ins
    print(f"\n✅ Verification:")
    expected_sinks = {'pcap', 'pcapng', 'json', 'hex', 'pretty', 'stats', 'null'}
    found_sinks = {s['name'] for s in sinks}
    missing_sinks = expected_sinks - found_sinks
    if not missing_sinks:
        print(f"  ✓ All {len(expected_sinks)} expected built-in sinks present")
    else:
        print(f"  ✗ Missing sinks: {missing_sinks}")

    expected_sources = {'live', 'file', 'ring'}
    found_sources = {s['name'] for s in sources}
    missing_sources = expected_sources - found_sources
    if not missing_sources:
        print(f"  ✓ All {len(expected_sources)} expected built-in sources present")
    else:
        print(f"  ✗ Missing sources: {missing_sources}")

    # Build extension → sink mapping
    print(f"\n📁 File Extension → Sink Mapping:")
    print("-" * 70)
    ext_map = OrderedDict()
    for s in sinks:
        for ext in s['extensions']:
            if ext:
                ext_map[ext] = s['name']
    for ext, sink in sorted(ext_map.items()):
        print(f"  .{ext:<10} → {sink}")

    # Suggest custom plugins
    print(f"\n💡 To add a custom plugin, create src/my_plugin.c with:")
    print("  #include \"registry/np_registry.h\"")
    print("  static np_sink_desc_t _my_desc = {")
    print("      .name = \"mysink\", .extensions = \"myx\", .create = my_create,")
    print("  };")
    print("  NP_REGISTER_SINK(_my_desc)")
    print("  Add 'src/my_plugin.c' to Makefile SRCS, rebuild, and it appears here.")

    # Exit non-zero if verification failed
    if missing_sinks or missing_sources:
        sys.exit(1)

if __name__ == '__main__':
    main()
