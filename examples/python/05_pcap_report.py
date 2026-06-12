#!/usr/bin/env python3
"""
examples/python/05_pcap_report.py
───────────────────────────────────
Offline PCAP analysis: read a .pcap file, produce a full HTML report.

Shows:
  • Summary stats
  • Protocol distribution (ASCII bar chart in terminal + table in HTML)
  • Top 10 talkers by flow_id
  • Timeline graph (packets per second, ASCII)
  • Full packet table (first 200 packets)

Usage:
    python3 05_pcap_report.py capture.pcap
    python3 05_pcap_report.py capture.pcap --out report.html
"""

import subprocess, sys, json, argparse, time, math
from collections import defaultdict, Counter
from pathlib import Path

import pathlib as _pl
_HERE = _pl.Path(__file__).resolve().parent
NETPIPE = str(next(
    (p for p in [
        _HERE / "../../build/bin/netpipe",
        _pl.Path("/usr/local/bin/netpipe"),
        _pl.Path("/usr/bin/netpipe"),
    ] if p.exists()), _HERE / "../../build/bin/netpipe"
))

# ── Terminal helpers ─────────────────────────────────────────────────────────
BOLD  = "\033[1m"
CYAN  = "\033[36m"
GREEN = "\033[32m"
RESET = "\033[0m"
DIM   = "\033[2m"

def hbar(val, total, width=30):
    filled = int(width * val / total) if total else 0
    return "█" * filled + "░" * (width - filled)

# ── Read all packets from file ───────────────────────────────────────────────
def read_pcap(path):
    cmd = [NETPIPE, "-r", path, "-fmt", "json", "-q"]
    packets = []
    with subprocess.Popen(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True) as proc:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                packets.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return packets

# ── Analysis ─────────────────────────────────────────────────────────────────
def analyse(packets):
    proto_count  = Counter()
    proto_bytes  = Counter()
    flow_count   = Counter()
    flow_bytes   = Counter()
    size_hist    = [0] * 10   # 0-100, 101-200, ..., 901-1000, 1001+
    second_count = defaultdict(int)

    for pkt in packets:
        cap = pkt["caplen"]
        fid = pkt["flow_id"]
        flow_count[fid] += 1
        flow_bytes[fid] += cap

        bucket = min(cap // 100, 9)
        size_hist[bucket] += 1

        # Parse timestamp HH:MM:SS.usec → seconds since start (relative)
        ts_parts = pkt["ts"].split(":")
        try:
            sec = int(ts_parts[0]) * 3600 + int(ts_parts[1]) * 60 + float(ts_parts[2])
            second_count[int(sec)] += 1
        except Exception:
            pass

        for layer in pkt["layers"]:
            proto_count[layer["proto"]] += 1
            proto_bytes[layer["proto"]] += layer["len"]

    return {
        "proto_count":  proto_count,
        "proto_bytes":  proto_bytes,
        "flow_count":   flow_count,
        "flow_bytes":   flow_bytes,
        "size_hist":    size_hist,
        "second_count": second_count,
    }

# ── Terminal report ──────────────────────────────────────────────────────────
def print_terminal_report(packets, stats):
    total_pkts  = len(packets)
    total_bytes = sum(p["caplen"] for p in packets)

    print(f"\n{BOLD}{'━'*60}{RESET}")
    print(f"{BOLD}  PCAP Analysis Report{RESET}")
    print(f"{'━'*60}")
    print(f"  Total packets : {BOLD}{total_pkts:,}{RESET}")
    print(f"  Total bytes   : {BOLD}{total_bytes:,}{RESET}  "
          f"({total_bytes/1024:.1f} KB)")
    if packets:
        print(f"  First packet  : {packets[0]['ts']}")
        print(f"  Last packet   : {packets[-1]['ts']}")
    print()

    # Protocol breakdown
    print(f"{BOLD}  Protocol Breakdown{RESET}")
    for proto, cnt in stats["proto_count"].most_common(10):
        byt = stats["proto_bytes"][proto]
        pct = 100 * cnt / total_pkts if total_pkts else 0
        bar = hbar(cnt, total_pkts, 25)
        print(f"  {CYAN}{proto:<12}{RESET} {GREEN}{bar}{RESET} "
              f"{cnt:>6,} pkts  {pct:5.1f}%  {byt/1024:8.1f} KB")
    print()

    # Packet size histogram
    print(f"{BOLD}  Packet Size Distribution{RESET}")
    labels = ["0-100","101-200","201-300","301-400","401-500",
              "501-600","601-700","701-800","801-900","901+"]
    mx = max(stats["size_hist"]) or 1
    for label, count in zip(labels, stats["size_hist"]):
        bar = hbar(count, mx, 20)
        print(f"  {label:<10} {GREEN}{bar}{RESET} {count:>6,}")
    print()

    # Top flows
    print(f"{BOLD}  Top 10 Flows (by packet count){RESET}")
    for fid, cnt in stats["flow_count"].most_common(10):
        byt = stats["flow_bytes"][fid]
        print(f"  flow {fid:>10}  {cnt:>6,} pkts  {byt/1024:8.1f} KB")
    print(f"{'━'*60}\n")

# ── HTML report ──────────────────────────────────────────────────────────────
def write_html(path, pcap_file, packets, stats):
    total_pkts  = len(packets)
    total_bytes = sum(p["caplen"] for p in packets)

    # Proto rows
    proto_rows = ""
    for proto, cnt in stats["proto_count"].most_common():
        pct  = 100 * cnt / total_pkts if total_pkts else 0
        byt  = stats["proto_bytes"][proto]
        proto_rows += (
            f"<tr><td>{proto}</td><td>{cnt:,}</td>"
            f"<td><div class='bar' style='width:{pct:.1f}%'></div>{pct:.1f}%</td>"
            f"<td>{byt/1024:.1f} KB</td></tr>\n"
        )

    # Flow rows
    flow_rows = ""
    for fid, cnt in stats["flow_count"].most_common(10):
        byt = stats["flow_bytes"][fid]
        flow_rows += (
            f"<tr><td>{fid}</td><td>{cnt:,}</td>"
            f"<td>{byt/1024:.1f} KB</td></tr>\n"
        )

    # Packet table (first 200)
    pkt_rows = ""
    for pkt in packets[:200]:
        protos = " → ".join(l["proto"] for l in pkt["layers"])
        pkt_rows += (
            f"<tr><td>{pkt['seq']}</td><td>{pkt['ts']}</td>"
            f"<td>{pkt['caplen']}</td><td>{pkt['wirelen']}</td>"
            f"<td>{pkt['flow_id']}</td><td>{protos}</td></tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>netpipe — {Path(pcap_file).name}</title>
<style>
  :root{{--bg:#0f1117;--card:#1a1d27;--accent:#00d4ff;--text:#e2e8f0;--dim:#64748b;--green:#22c55e}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}}
  h1{{color:var(--accent);font-size:1.8rem;margin-bottom:.25rem}}
  h2{{color:var(--accent);font-size:1.1rem;margin:1.5rem 0 .75rem;border-bottom:1px solid #2d3748;padding-bottom:.4rem}}
  .subtitle{{color:var(--dim);margin-bottom:2rem}}
  .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}}
  .card{{background:var(--card);border:1px solid #2d3748;border-radius:12px;padding:1.25rem;text-align:center}}
  .card .val{{font-size:1.8rem;font-weight:700;color:var(--accent)}}
  .card .lbl{{color:var(--dim);font-size:.8rem;margin-top:.25rem}}
  table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:12px;overflow:hidden;margin-bottom:2rem}}
  th{{background:#1e2235;color:var(--dim);font-size:.75rem;text-transform:uppercase;padding:.6rem 1rem;text-align:left}}
  td{{padding:.55rem 1rem;border-top:1px solid #2d3748;font-size:.85rem;font-family:monospace}}
  tr:hover td{{background:#1e2235}}
  .bar{{height:8px;background:var(--green);border-radius:4px;display:inline-block;min-width:2px;vertical-align:middle;margin-right:6px}}
  .footer{{color:var(--dim);font-size:.8rem;margin-top:2rem}}
</style>
</head>
<body>
<h1>🌐 netpipe — Packet Analysis Report</h1>
<p class="subtitle">File: <strong>{Path(pcap_file).name}</strong> &nbsp;·&nbsp; Generated by netpipe v0.1.0</p>

<div class="cards">
  <div class="card"><div class="val">{total_pkts:,}</div><div class="lbl">Total Packets</div></div>
  <div class="card"><div class="val">{total_bytes/1024:.1f}</div><div class="lbl">Total KB</div></div>
  <div class="card"><div class="val">{len(stats['proto_count'])}</div><div class="lbl">Protocols Seen</div></div>
  <div class="card"><div class="val">{len(stats['flow_count'])}</div><div class="lbl">Unique Flows</div></div>
  <div class="card"><div class="val">{packets[0]['ts'] if packets else '—'}</div><div class="lbl">First Packet</div></div>
</div>

<h2>Protocol Breakdown</h2>
<table><thead><tr><th>Protocol</th><th>Packets</th><th>Share</th><th>Bytes</th></tr></thead>
<tbody>{proto_rows}</tbody></table>

<h2>Top 10 Flows</h2>
<table><thead><tr><th>Flow ID</th><th>Packets</th><th>Bytes</th></tr></thead>
<tbody>{flow_rows}</tbody></table>

<h2>First 200 Packets</h2>
<table>
<thead><tr><th>#</th><th>Timestamp</th><th>Cap</th><th>Wire</th><th>Flow</th><th>Layers</th></tr></thead>
<tbody>{pkt_rows}</tbody></table>

<p class="footer">Generated by netpipe · MIT License · github.com/you/netpipe</p>
</body></html>"""

    Path(path).write_text(html)
    print(f"HTML report written to: {BOLD}{path}{RESET}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap",           help="input .pcap file")
    ap.add_argument("--out",  "-o",   default="report.html")
    ap.add_argument("--no-html",      action="store_true")
    args = ap.parse_args()

    print(f"Reading {args.pcap}…")
    t0 = time.monotonic()
    packets = read_pcap(args.pcap)
    elapsed = time.monotonic() - t0
    print(f"Loaded {len(packets):,} packets in {elapsed:.2f}s")

    stats = analyse(packets)
    print_terminal_report(packets, stats)

    if not args.no_html:
        write_html(args.out, args.pcap, packets, stats)

if __name__ == "__main__":
    main()
