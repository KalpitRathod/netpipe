#!/usr/bin/env python3
"""
examples/python/11_tls_decryptor.py
─────────────────────────────────────
Decrypts the structured PCAP traffic captured by netpipe using the
provided TLS session keys. It parses the decrypted streams and 
outputs them in a readable structured format (JSON).

Usage:
    python3 11_tls_decryptor.py encrypted_traffic.pcap tls_keys.log
"""

import sys
import json
import subprocess
import os

def check_tshark():
    try:
        subprocess.run(["tshark", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def install_tshark_prompt():
    print("\033[31mError: 'tshark' is not installed.\033[0m")
    print("This script relies on the Wireshark decryption engine (tshark) to parse the TLS 1.3 records.")
    print("\nPlease install it by running:")
    print("  \033[1msudo apt-get update && sudo apt-get install -y tshark\033[0m")
    print("\n(When asked if non-superusers should be able to capture packets, you can answer Yes or No).")
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

    if not check_tshark():
        install_tshark_prompt()

    print(f"Decrypting \033[36m{pcap_file}\033[0m using keys from \033[36m{key_file}\033[0m...\n")

    # Command to decrypt and output as structured JSON
    # We use Wireshark's exact TLS decryption engine.
    cmd = [
        "tshark",
        "-r", pcap_file,
        "-o", f"tls.keylog_file:{key_file}",
        "-Y", "http or http2", # Filter only the decrypted application traffic
        "-T", "json",          # Output structured JSON
        "-x"                   # Include the raw decrypted hex payload
    ]

    print("\033[90mRunning: " + " ".join(cmd) + "\033[0m\n")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        print(f"Failed to run tshark: {e}")
        sys.exit(1)

    if not result.stdout.strip():
        print("No decrypted HTTP/HTTP2 traffic found. Are you sure the keys match the PCAP?")
        sys.exit(0)

    try:
        packets = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("Failed to parse tshark JSON output.")
        sys.exit(1)

    # Process and nicely format the decrypted output
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        
        # Check if it's HTTP/1.1 or HTTP/2
        http_layer = layers.get("http")
        http2_layer = layers.get("http2")

        frame_info = layers.get("frame", {})
        time = frame_info.get("frame.time", "Unknown Time")
        
        ip_layer = layers.get("ip", layers.get("ipv6", {}))
        src_ip = ip_layer.get("ip.src", ip_layer.get("ipv6.src", "Unknown"))
        dst_ip = ip_layer.get("ip.dst", ip_layer.get("ipv6.dst", "Unknown"))

        print("━" * 80)
        print(f"\033[1m[{time}] {src_ip} ➔ {dst_ip}\033[0m")
        
        if http_layer:
            method = http_layer.get("http.request.method")
            uri = http_layer.get("http.request.uri")
            host = http_layer.get("http.host")
            status = http_layer.get("http.response.code")
            
            if method and uri:
                print(f"\033[32mHTTP/1.1 REQUEST: {method} {uri}\033[0m")
                if host: print(f"Host: {host}")
            elif status:
                print(f"\033[34mHTTP/1.1 RESPONSE: {status}\033[0m")

            file_data = http_layer.get("http.file_data")
            if file_data:
                print("\nDecrypted Payload:")
                # Truncate if it's too long
                data_str = str(file_data)
                if len(data_str) > 500:
                    data_str = data_str[:500] + " ... [TRUNCATED]"
                
                # Highlight password string for the extreme test demo
                data_str = data_str.replace("password=", "\033[41;97m password= \033[0m")
                print(data_str)

        elif http2_layer:
            # HTTP2 parsing can be nested and complex in tshark json
            print(f"\033[35mHTTP/2 Decrypted Frame\033[0m")
            # We'll just print a summary
            headers = http2_layer.get("http2.header", [])
            if isinstance(headers, dict):
                headers = [headers]
                
            for h in headers:
                name = h.get("http2.header.name", "")
                val = h.get("http2.header.value", "")
                if name and val:
                    print(f"  {name}: {val}")
                    
            data = http2_layer.get("http2.data.data")
            if data:
                print("\nDecrypted HTTP/2 Data Payload (Hex):")
                payload_str = data[:200] + "..." if len(data) > 200 else data
                # Attempt to decode hex for the extreme test demo just in case
                try:
                    decoded = bytes.fromhex(payload_str.replace(":", "")).decode('ascii', errors='ignore')
                    if "password=" in decoded:
                        decoded = decoded.replace("password=", "\033[41;97m password= \033[0m")
                        print("\033[33m(Decoded ASCII):\033[0m " + decoded)
                    else:
                        print(payload_str)
                except Exception:
                    print(payload_str)

    print("\n\033[1mDecryption Complete.\033[0m")

if __name__ == "__main__":
    main()
