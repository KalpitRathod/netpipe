#!/usr/bin/env python3
"""
examples/python/test_examples.py
───────────────────────────────────
Test runner to verify all Python examples compile and run cleanly.
Checks that there are no SyntaxErrors, ImportErrors, or unhandled crashes.
"""

import os
import sys
import subprocess
import pathlib as _pl

_HERE = _pl.Path(__file__).resolve().parent

# List of all example scripts to test
SCRIPTS = [
    "00_quickstart.py",
    "01_dns_monitor.py",
    "02_traffic_dashboard.py",
    "03_http_sniffer.py",
    "04_anomaly_detector.py",
    "05_pcap_report.py",
    "06_bandwidth_recorder.py",
    "07_packet_firewall.py",
    "08_browser_spy.py",
    "09_stream_follower.py",
    "10_tls_capture.py",
    "11_tls_decryptor.py",
    "12_http_parser_demo.py",
    "13_dns_spy.py",
    "14_tun_replay.py",
    "15_socket_forward.py",
    "16_payload_transform.py",
    "17_flow_tracker.py",
    "18_pcapng_writer.py",
    "19_lua_processor.py",
    "20_multi_interface_parallel.py",
    "21_zero_copy_ring.py",
]

def test_script(script_name: str):
    path = _HERE / script_name
    if not path.exists():
        return False, f"File {script_name} does not exist"

    # We run the script with either --help or no arguments to trigger usage validation.
    # We want to make sure it doesn't throw a Python exception/traceback.
    args = [sys.executable, str(path)]
    
    # Special args to check help or valid mock inputs
    if script_name in ["00_quickstart.py", "16_payload_transform.py"]:
        # These can run directly with our sample pcap file
        sample_pcap = _HERE / "../../encrypted_traffic.pcap"
        args += ["--file", str(sample_pcap), "--count", "1"]
    elif script_name in ["17_flow_tracker.py", "18_pcapng_writer.py", "19_lua_processor.py", "20_multi_interface_parallel.py"]:
        sample_pcap = _HERE / "../../encrypted_traffic.pcap"
        args += ["--file", str(sample_pcap)]
    elif script_name == "05_pcap_report.py":
        sample_pcap = _HERE / "../../encrypted_traffic.pcap"
        args += [str(sample_pcap), "--no-html"]
    elif script_name == "11_tls_decryptor.py":
        sample_pcap = _HERE / "../../encrypted_traffic.pcap"
        sample_keys = _HERE / "../../tls_keys.log"
        args += [str(sample_pcap), str(sample_keys)]
    elif script_name in ["01_dns_monitor.py", "03_http_sniffer.py", "04_anomaly_detector.py", 
                         "07_packet_firewall.py", "06_bandwidth_recorder.py", "08_browser_spy.py"]:
        # These use argparse and require an interface, so we can test with --help
        args += ["--help"]

    # Run the subprocess
    res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
    
    # Check for tracebacks in stdout/stderr
    all_output = res.stdout + "\n" + res.stderr
    if "Traceback (most recent call last):" in all_output:
        return False, f"Python Exception / Traceback found:\n{all_output}"
    
    # If the script exits with code 0 or successfully prints usage/help, it is considered working
    if res.returncode not in [0, 1, 2]:
        return False, f"Unexpected return code {res.returncode}. Output:\n{all_output}"

    return True, "Success"

def main():
    print(f"\033[1mTesting all Python examples in examples/python...\033[0m\n")
    
    passed_count = 0
    failed_count = 0

    for script in SCRIPTS:
        print(f"Testing {script:<30}...", end="", flush=True)
        ok, msg = test_script(script)
        if ok:
            print(f" [\033[32mOK\033[0m]")
            passed_count += 1
        else:
            print(f" [\033[31mFAILED\033[0m]")
            print(f"\033[31mError details:\033[0m\n{msg}\n")
            failed_count += 1

    print(f"\n\033[1mSummary:\033[0m Passed: {passed_count} / {len(SCRIPTS)} | Failed: {failed_count}")
    if failed_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
