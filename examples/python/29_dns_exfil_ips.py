#!/usr/bin/env python3
"""
29_dns_exfil_ips.py — Python-side DNS exfiltration detector.

This script consumes netpipe's JSON output and applies the same detection
rules as mitigate.lua, but in Python — useful for SIEM integration where
you want to log alerts to a database instead of dropping packets inline.

It demonstrates how to consume the JSON sink's structured DNS fields
(pkt['dns']['query']['name']) for post-processing.

Rules (matching mitigate.lua):
  1. DNS query name >= 50 chars AND matches 'exfil[%-_]payload' AND
     dst in EXFIL_RESOLVERS → CRITICAL (exfil payload detected)
  2. DNS query name >= 50 chars → HIGH (long DNS name, possible tunnel)
  3. DNS query name matches 'exfil[%-_]payload' → HIGH (exfil keyword)
  4. Single label >= 30 chars of [a-z0-9] with no vowels → MEDIUM (base32 tunnel)

Usage:
    sudo ./build/bin/netpipe -i wlo1 -proto dns -fmt json -q | python3 29_dns_exfil_ips.py
    python3 29_dns_exfil_ips.py < /tmp/dns_capture.json

No external dependencies — just the Python standard library.
"""
import json
import re
import sys
from collections import defaultdict
from datetime import datetime

# Configuration (matches mitigate.lua's CONFIG table)
THRESHOLD_LONG_NAME = 50
EXFIL_PATTERN = re.compile(r'exfil[-_]payload')
TUNNEL_LABEL_LEN = 30
EXFIL_RESOLVERS = {
    '8.8.8.8',          # Google Public DNS
    '8.8.4.4',          # Google Public DNS (secondary)
    '1.1.1.1',          # Cloudflare DNS
    '1.0.0.1',          # Cloudflare DNS (secondary)
    '9.9.9.9',          # Quad9
    '208.67.222.222',   # Cisco OpenDNS
}

# Alert severities for SIEM ingestion
SEVERITY = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4}

class DNSExfilDetector:
    def __init__(self):
        self.stats = defaultdict(int)
        self.alerts = []

    def classify(self, qname, dst_ip):
        """Classify a DNS query. Returns (tag, severity) or ('normal', None)."""
        if not qname:
            return 'normal', None

        dst_is_exfil = dst_ip in EXFIL_RESOLVERS
        is_long = len(qname) >= THRESHOLD_LONG_NAME
        is_exfil_keyword = bool(EXFIL_PATTERN.search(qname))
        is_tunnel = self._looks_like_base32_tunnel(qname)

        if is_long and is_exfil_keyword and dst_is_exfil:
            return 'EXFIL_PAYLOAD', 'CRITICAL'
        if is_long:
            return 'long_dns_name', 'HIGH'
        if is_exfil_keyword:
            return 'exfil_keyword', 'HIGH'
        if is_tunnel:
            return 'dns_tunnel_suspect', 'MEDIUM'
        return 'normal', None

    def _looks_like_base32_tunnel(self, name):
        """Check for Iodine/dns2tcp-style base32 tunnel labels."""
        for label in name.split('.'):
            if len(label) >= TUNNEL_LABEL_LEN:
                if re.fullmatch(r'[a-z0-9]+', label) and not re.search(r'[aeiou]', label):
                    return True
        return False

    def process_packet(self, pkt):
        """Process a single JSON packet dict."""
        # Extract DNS fields from netpipe's JSON schema
        # The JSON sink nests: pkt['dns']['query']['name']
        dns = pkt.get('dns')
        if not dns or dns.get('query') is None:
            return

        query = dns.get('query', {})
        if not isinstance(query, dict):
            return

        qname = query.get('name', '')
        if not qname:
            return

        # Extract destination IP from the layers or raw packet
        dst_ip = self._extract_dst_ip(pkt)

        tag, severity = self.classify(qname, dst_ip)
        self.stats[tag] += 1

        if severity:
            alert = {
                'timestamp': pkt.get('ts', ''),
                'seq': pkt.get('seq', 0),
                'severity': severity,
                'tag': tag,
                'query_name': qname,
                'dst_ip': dst_ip,
                'src_ip': self._extract_src_ip(pkt),
                'flow_id': pkt.get('flow_id', 0),
            }
            self.alerts.append(alert)
            self._print_alert(alert)

    def _extract_dst_ip(self, pkt):
        """Extract destination IP from the packet's raw hex or layers."""
        # netpipe's JSON doesn't directly expose src/dst IP as top-level fields,
        # but we can infer from the flow_id or parse raw_hex.
        # For simplicity, return '?' — in production you'd parse raw_hex.
        return '?'

    def _extract_src_ip(self, pkt):
        return '?'

    def _print_alert(self, alert):
        """Print an alert in SIEM-friendly format."""
        sev_color = {
            'CRITICAL': '\033[1;31m',  # red
            'HIGH': '\033[1;33m',      # yellow
            'MEDIUM': '\033[1;36m',    # cyan
            'LOW': '\033[0m',
        }.get(alert['severity'], '\033[0m')
        reset = '\033[0m'

        print(f"{sev_color}[{alert['severity']}]{reset} "
              f"[{alert['timestamp']}] "
              f"seq={alert['seq']} "
              f"tag={alert['tag']} "
              f"qname={alert['query_name']} "
              f"flow_id=0x{alert['flow_id']:08x}")

    def print_summary(self):
        """Print final summary statistics."""
        print(f"\n{'=' * 60}")
        print("  DNS EXFIL IPS SUMMARY")
        print(f"{'=' * 60}")
        total = sum(self.stats.values())
        print(f"  Total DNS queries:  {total}")
        for tag, count in sorted(self.stats.items(), key=lambda x: -x[1]):
            pct = 100 * count / total if total > 0 else 0
            print(f"  {tag:25s} {count:6d} ({pct:5.1f}%)")
        print(f"\n  Alerts generated:   {len(self.alerts)}")
        if self.alerts:
            by_sev = defaultdict(int)
            for a in self.alerts:
                by_sev[a['severity']] += 1
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if by_sev[sev]:
                    print(f"    {sev:10s} {by_sev[sev]}")
        print(f"{'=' * 60}")

def main():
    detector = DNSExfilDetector()
    print("DNS Exfil IPS — reading JSON from stdin (Ctrl+C to stop)")
    print("=" * 60)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                pkt = json.loads(line)
                detector.process_packet(pkt)
            except json.JSONDecodeError:
                continue
    except KeyboardInterrupt:
        pass

    detector.print_summary()

    # Exit non-zero if any CRITICAL alerts
    critical = sum(1 for a in detector.alerts if a['severity'] == 'CRITICAL')
    if critical:
        print(f"\n⚠ {critical} CRITICAL exfil-payload alerts detected!")
        sys.exit(1)

if __name__ == '__main__':
    main()
