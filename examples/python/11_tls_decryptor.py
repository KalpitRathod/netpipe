#!/usr/bin/env python3
"""
examples/python/11_tls_decryptor.py
─────────────────────────────────────
Decrypts the structured PCAP traffic captured by netpipe using the
provided TLS session keys.

We use the native `pyshark` library (a python wrapper around Wireshark's
decryption engine) instead of shelling out to the tshark CLI.

Usage:
    python3 11_tls_decryptor.py encrypted_traffic.pcap tls_keys.log
"""

import sys
import os

try:
    import pyshark
except ImportError:
    print("\033[31mError: 'pyshark' is not installed.\033[0m")
    print("This script relies on the Wireshark decryption engine to parse TLS 1.3 records.")
    print("\nPlease install it by running:")
    print("  \033[1mpip3 install pyshark --break-system-packages\033[0m")
    print("\n(Note: you still need tshark installed on your system: sudo apt install tshark)")
    sys.exit(1)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 11_tls_decryptor.py <capture.pcap> <sslkeylog.txt>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    key_file = sys.argv[2]

    if not os.path.exists(pcap_file):
        print(f"File not found: {pcap_file}")
        sys.exit(1)
    if not os.path.exists(key_file):
        print(f"File not found: {key_file}")
        sys.exit(1)

    print(f"Decrypting \033[36m{pcap_file}\033[0m using keys from \033[36m{key_file}\033[0m...\n")

    # Load the capture using pyshark, injecting the TLS keys
    # We filter for http or http2 traffic.
    capture = pyshark.FileCapture(
        pcap_file,
        display_filter="http or http2",
        override_prefs={'tls.keylog_file': os.path.abspath(key_file)}
    )

    found_traffic = False

    try:
        for pkt in capture:
            found_traffic = True
            
            # Find the IP layer
            ip_layer = None
            if hasattr(pkt, 'ip'):
                ip_layer = pkt.ip
            elif hasattr(pkt, 'ipv6'):
                ip_layer = pkt.ipv6
            
            src_ip = ip_layer.src if ip_layer else "Unknown"
            dst_ip = ip_layer.dst if ip_layer else "Unknown"
            
            print("━" * 80)
            print(f"\033[1m[{pkt.sniff_time}] {src_ip} ➔ {dst_ip}\033[0m")

            # Check if it's HTTP/1.1
            if hasattr(pkt, 'http'):
                http = pkt.http
                if hasattr(http, 'request_method') and hasattr(http, 'request_uri'):
                    print(f"\033[32mHTTP/1.1 REQUEST: {http.request_method} {http.request_uri}\033[0m")
                    if hasattr(http, 'host'):
                        print(f"Host: {http.host}")
                elif hasattr(http, 'response_code'):
                    print(f"\033[34mHTTP/1.1 RESPONSE: {http.response_code}\033[0m")
                
                # Check for decrypted payload
                if hasattr(http, 'file_data'):
                    print("\nDecrypted Payload:")
                    data_str = str(http.file_data)
                    
                    # pyshark returns hex strings separated by colons
                    if ":" in data_str:
                        try:
                            data_str = bytes.fromhex(data_str.replace(":", "")).decode("ascii", errors="ignore")
                        except Exception:
                            pass
                    
                    if len(data_str) > 500:
                        data_str = data_str[:500] + " ... [TRUNCATED]"
                    
                    # Highlight password string for the extreme test demo
                    data_str = data_str.replace("password", "\033[41;97m password \033[0m")
                    print(data_str)

            # Check if it's HTTP/2
            elif hasattr(pkt, 'http2'):
                print(f"\033[35mHTTP/2 Decrypted Frame\033[0m")
                http2 = pkt.http2
                
                # Print headers if available
                if hasattr(http2, 'header'):
                    headers = http2.header if isinstance(http2.header, list) else [http2.header]
                    for h in headers:
                        if hasattr(h, 'name') and hasattr(h, 'value'):
                            print(f"  {h.name}: {h.value}")

                # Print data payload if available
                if hasattr(http2, 'data_data'):
                    print("\nDecrypted HTTP/2 Data Payload (Hex):")
                    data_hex = str(http2.data_data)
                    payload_str = data_hex[:200] + "..." if len(data_hex) > 200 else data_hex
                    
                    try:
                        decoded = bytes.fromhex(payload_str.replace(":", "")).decode('ascii', errors='ignore')
                        if "password=" in decoded:
                            decoded = decoded.replace("password=", "\033[41;97m password= \033[0m")
                            print("\033[33m(Decoded ASCII):\033[0m " + decoded)
                        else:
                            print(payload_str)
                    except Exception:
                        print(payload_str)

    except Exception as e:
        print(f"\033[31mError reading packet: {e}\033[0m")
    finally:
        capture.close()

    if not found_traffic:
        print("No decrypted HTTP/HTTP2 traffic found. Are you sure the keys match the PCAP?")

    print("\n\033[1mDecryption Complete.\033[0m")

if __name__ == "__main__":
    main()
