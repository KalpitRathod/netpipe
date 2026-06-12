#!/usr/bin/env python3
"""
examples/python/15_socket_forward.py
───────────────────────────────────────
Demonstrates the native Socket Sink for remote packet forwarding.

This script sets up a simple local TCP server to simulate a remote agent
(like a cloud server or a different machine). 
It then runs `netpipe` to capture 10 live packets and forward them over
the `socket://` output sink directly into our Python server.

Usage:
    sudo python3 15_socket_forward.py wlo1
"""

import subprocess, sys, time, os
import socket
import threading
import pathlib as _pl

_HERE = _pl.Path(__file__).resolve().parent
NETPIPE = str(_HERE / "../../build/bin/netpipe")
PORT = 9999

def mock_remote_agent():
    """A tiny TCP server that receives raw bytes and writes them to a pcap file."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("127.0.0.1", PORT))
        server.listen(1)
        print(f"[\033[36mRemote Agent\033[0m] Listening on port {PORT}...")
    except Exception as e:
        print(f"Failed to start server: {e}")
        return

    conn, addr = server.accept()
    print(f"[\033[36mRemote Agent\033[0m] Connection established from {addr}!")
    
    out_file = _HERE / "../../forwarded.pcap"
    bytes_received = 0
    
    with open(out_file, "wb") as f:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            f.write(data)
            bytes_received += len(data)
            
    print(f"[\033[36mRemote Agent\033[0m] Stream closed. Received {bytes_received} bytes.")
    print(f"[\033[36mRemote Agent\033[0m] Saved to \033[33m{out_file.name}\033[0m")
    
    conn.close()
    server.close()

def main():
    if os.geteuid() != 0:
        print("Please run this script with sudo.")
        sys.exit(1)

    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface>")
        sys.exit(1)
        
    interface = sys.argv[1]

    print(f"\033[1mSocket Forwarding Demo\033[0m")
    
    # Start the remote agent listener in a background thread
    agent_thread = threading.Thread(target=mock_remote_agent, daemon=True)
    agent_thread.start()
    
    # Give the server a moment to start listening
    time.sleep(0.5)
    
    print(f"\n[\033[35mnetpipe\033[0m] Capturing 10 packets on {interface} and forwarding to socket://127.0.0.1:{PORT} ...")
    
    cmd_netpipe = [
        NETPIPE, 
        "-i", interface, 
        "-c", "10", 
        "-o", f"socket://127.0.0.1:{PORT}",
        "-q"
    ]
    
    try:
        subprocess.run(cmd_netpipe, check=True)
        print("[\033[35mnetpipe\033[0m] Capture complete.")
    except subprocess.CalledProcessError:
        print("\033[1;31mnetpipe failed to run or connect.\033[0m")
        
    # Wait for the agent to finish writing the file
    agent_thread.join(timeout=2.0)
    
    print("\n\033[1;32mSuccess!\033[0m You can now open forwarded.pcap in Wireshark.")

if __name__ == "__main__":
    main()
