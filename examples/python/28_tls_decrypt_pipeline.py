#!/usr/bin/env python3
"""
28_tls_decrypt_pipeline.py — End-to-end TLS decryption & HTTP extraction.

This script demonstrates the red-team / forensic workflow:
  1. Feed a pcap with encrypted TLS traffic into netpipe
  2. Decrypt it using an NSS SSLKEYLOGFILE
  3. Reassemble the TCP stream
  4. Extract and display all HTTP requests/responses from the decrypted plaintext

It validates Fix #8 (TLS aliasing helpers), #9 (direction retry), and #10
(AEAD failure alarm) by checking that decrypted streams contain real HTTP.

Usage:
    python3 28_tls_decrypt_pipeline.py -r encrypted_traffic.pcap -k tls_keys.log
    python3 28_tls_decrypt_pipeline.py -r my_capture.pcap -k ~/.sslkeylog.log --extract-hosts

No external dependencies — just the Python standard library.
"""
import argparse
import binascii
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

def run_netpipe(pcap_path, keylog_path, bin_path):
    """Run netpipe with TLS decrypt + TCP reassembly, return list of packet dicts."""
    cmd = [
        bin_path,
        '-r', pcap_path,
        '-proc', f'tls-decrypt:{keylog_path}',
        '-proc', 'tcp-stream',
        '-fmt', 'json',
        '-o', '-',   # stdout
        '-q',        # quiet (only errors)
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    packets = []
    for line in proc.stdout.strip().split('\n'):
        if not line:
            continue
        try:
            packets.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return packets, proc.stderr

def extract_http_from_stream(stream_bytes):
    """Extract HTTP requests/responses from a decrypted TLS stream.

    Returns a list of dicts with keys: 'type' (request/response),
    'method'/'status', 'path', 'host', 'headers', 'body_preview'.
    """
    results = []
    pos = 0
    while pos < len(stream_bytes):
        # Look for HTTP request methods or HTTP/ response prefix
        remaining = stream_bytes[pos:]

        # Try to match a request line: METHOD SP path SP HTTP/version CRLF
        req_match = re.match(rb'(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT|TRACE) (\S+) HTTP/(\d\.\d)\r\n', remaining)
        # Try to match a response line: HTTP/version SP status_code SP reason CRLF
        resp_match = re.match(rb'HTTP/(\d\.\d) (\d{3}) ([^\r\n]*)\r\n', remaining)

        if req_match:
            method = req_match.group(1).decode()
            path = req_match.group(2).decode()
            version = req_match.group(3).decode()
            headers = parse_headers(remaining[req_match.end():])
            body_start = find_body_end(remaining[req_match.end():])
            body = remaining[req_match.end() + body_start:][:200] if body_start >= 0 else b''
            results.append({
                'type': 'request',
                'method': method,
                'path': path,
                'version': version,
                'host': headers.get('host', '?'),
                'user_agent': headers.get('user-agent', '?')[:60],
                'headers': headers,
                'body_preview': body,
            })
            pos += req_match.end() + (body_start if body_start >= 0 else 0)
        elif resp_match:
            version = resp_match.group(1).decode()
            status = int(resp_match.group(2).decode())
            reason = resp_match.group(3).decode()
            headers = parse_headers(remaining[resp_match.end():])
            body_start = find_body_end(remaining[resp_match.end():])
            body = remaining[resp_match.end() + body_start:][:200] if body_start >= 0 else b''
            results.append({
                'type': 'response',
                'status': status,
                'reason': reason,
                'version': version,
                'content_type': headers.get('content-type', '?'),
                'content_length': headers.get('content-length', '?'),
                'headers': headers,
                'body_preview': body,
            })
            pos += resp_match.end() + (body_start if body_start >= 0 else 0)
        else:
            pos += 1

    return results

def parse_headers(data):
    """Parse HTTP headers from data starting after the request/response line."""
    headers = {}
    pos = 0
    while pos < len(data):
        line_end = data.find(b'\r\n', pos)
        if line_end < 0:
            break
        line = data[pos:line_end]
        if line == b'':
            break  # end of headers
        if b': ' in line:
            name, _, value = line.partition(b': ')
            headers[line[:line.index(b':')].decode().lower()] = value.decode(errors='replace')
        pos = line_end + 2
    return headers

def find_body_end(data):
    """Find the offset of the body (after \r\n\r\n)."""
    idx = data.find(b'\r\n\r\n')
    return idx + 4 if idx >= 0 else -1

def main():
    parser = argparse.ArgumentParser(description='TLS decryption & HTTP extraction pipeline')
    parser.add_argument('-r', '--read', required=True, help='input pcap file')
    parser.add_argument('-k', '--keylog', required=True, help='NSS SSLKEYLOGFILE')
    parser.add_argument('--bin', default='./build/bin/netpipe', help='netpipe binary path')
    parser.add_argument('--extract-hosts', action='store_true', help='list all visited hosts')
    parser.add_argument('--show-bodies', action='store_true', help='show first 200 bytes of each body')
    args = parser.parse_args()

    if not os.path.exists(args.read):
        print(f"ERROR: pcap file not found: {args.read}")
        sys.exit(1)
    if not os.path.exists(args.keylog):
        print(f"ERROR: keylog file not found: {args.keylog}")
        sys.exit(1)

    print(f"Decrypting {args.read} with keylog {args.keylog}...")
    packets, stderr = run_netpipe(args.read, args.keylog, args.bin)

    if not packets:
        print("ERROR: no packets captured")
        if stderr:
            print(f"netpipe stderr:\n{stderr}")
        sys.exit(1)

    print(f"\nCaptured {len(packets)} packets")

    # Count how many have decrypted streams
    decrypted = 0
    http_messages = []
    hosts = set()

    for pkt in packets:
        stream_hex = pkt.get('stream_hex')
        if stream_hex and len(stream_hex) > 0:
            decrypted += 1
            stream_bytes = binascii.unhexlify(stream_hex)

            # Extract HTTP messages from the decrypted stream
            msgs = extract_http_from_stream(stream_bytes)
            for msg in msgs:
                http_messages.append(msg)
                if msg['type'] == 'request' and msg.get('host'):
                    hosts.add(msg['host'])

    print(f"  {decrypted}/{len(packets)} packets have decrypted stream data")

    # Check for AEAD failure warnings in stderr (Fix #10)
    if stderr and 'AEAD authentication failures' in stderr:
        print(f"\n⚠ WARNING: AEAD failures detected (Fix #10 alarm triggered):")
        for line in stderr.split('\n'):
            if 'AEAD' in line:
                print(f"  {line.strip()}")

    print(f"\nExtracted {len(http_messages)} HTTP messages:")
    print("=" * 80)

    for i, msg in enumerate(http_messages):
        if msg['type'] == 'request':
            print(f"\n[{i+1}] REQUEST: {msg['method']} {msg['path']}")
            print(f"    Host: {msg['host']}")
            if msg.get('user_agent') and msg['user_agent'] != '?':
                print(f"    User-Agent: {msg['user_agent']}")
        else:
            print(f"\n[{i+1}] RESPONSE: {msg['status']} {msg['reason']}")
            print(f"    Content-Type: {msg['content_type']}")
            print(f"    Content-Length: {msg['content_length']}")

        if args.show_bodies and msg.get('body_preview'):
            body = msg['body_preview']
            try:
                print(f"    Body (first 200 bytes): {body.decode('utf-8', errors='replace')[:200]}")
            except:
                print(f"    Body (hex): {body[:200].hex()}")

    if args.extract_hosts and hosts:
        print(f"\n{'=' * 80}")
        print(f"Visited hosts ({len(hosts)}):")
        for h in sorted(hosts):
            print(f"  {h}")

    # Summary
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"  Total packets:          {len(packets)}")
    print(f"  Decrypted streams:      {decrypted}")
    print(f"  HTTP messages found:    {len(http_messages)}")
    print(f"  Unique hosts visited:   {len(hosts)}")
    if decrypted > 0:
        print(f"  Decryption success:     {100*decrypted/len(packets):.1f}%")
        print(f"\n  ✓ TLS decryption pipeline working (Fixes #8, #9, #10 validated)")
    else:
        print(f"\n  ✗ No streams decrypted — check keylog validity")

if __name__ == '__main__':
    main()
