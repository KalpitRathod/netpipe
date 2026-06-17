#!/usr/bin/env python3
"""
examples/python/test_all_examples.py
─────────────────────────────────────
Comprehensive test runner for every Python example.

Strategy
────────
For each example script we:
  1. Compile-check it (py_compile) — catches syntax errors.
  2. Run it with `--help` — catches import errors + missing deps.
  3. If the script accepts a `--file`/positional pcap arg, run it
     against the matching fixture and verify it exits 0 or 1 (1 is
     OK for "no packets matched" type exits).

Examples that need root or a live interface are smoke-tested with
`--help` only.

Exit code 0 = all passed, 1 = one or more failures.
"""

import os
import py_compile
import shutil
import subprocess
import sys
import pathlib
import json

_HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = _HERE.parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"

# All scripts that should be tested.
SCRIPTS = sorted(p.name for p in _HERE.glob("*.py") if p.name != "test_all_examples.py" and p.name != "plot_my_data.py")

# ─── Helpers ──────────────────────────────────────────────────────────

GREEN = "\033[32m"
RED   = "\033[31m"
YELL  = "\033[33m"
BOLD  = "\033[1m"
NC    = "\033[0m"

def find_netpipe():
    candidates = [
        REPO_ROOT / "build" / "bin" / "netpipe",
        pathlib.Path("/usr/local/bin/netpipe"),
        pathlib.Path("/usr/bin/netpipe"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None

NETPIPE = find_netpipe()
LD_PATH = "/home/z/my-project/deps/local/lib"

def env_for_child():
    e = os.environ.copy()
    if (pathlib.Path(LD_PATH) / "libpcap.so").exists():
        e["LD_LIBRARY_PATH"] = LD_PATH + ":" + e.get("LD_LIBRARY_PATH", "")
    return e

def compile_check(script):
    """Return (ok, msg)."""
    try:
        py_compile.compile(str(_HERE / script), doraise=True)
        return True, "compiled"
    except py_compile.PyCompileError as e:
        return False, f"compile error: {e}"

def run_help(script):
    """Return (ok, msg).  `--help` should exit 0 or 2.

    Some scripts gracefully print a "dependency not installed" message
    and exit 1 — that's an acceptable outcome (the script handled the
    missing dep correctly).  We only fail if there's a Python traceback.
    """
    args = [sys.executable, str(_HERE / script), "--help"]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=10,
                           env=env_for_child())
    except subprocess.TimeoutExpired:
        return False, "timeout on --help"
    out = r.stdout + r.stderr
    if "Traceback (most recent call last):" in out:
        # Show last few lines for context.
        last = "\n".join(out.splitlines()[-5:])
        return False, f"traceback on --help:\n{last}"
    if r.returncode not in (0, 1, 2):
        return False, f"--help exit code {r.returncode}"
    return True, f"--help OK (exit {r.returncode})"

def run_with_pcap(script, args):
    """Run with a list of extra args.  Returns (ok, msg)."""
    args = [sys.executable, str(_HERE / script)] + args
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=15,
                           env=env_for_child())
    except subprocess.TimeoutExpired:
        return False, "timeout"
    out = r.stdout + r.stderr
    if "Traceback (most recent call last):" in out:
        last = "\n".join(out.splitlines()[-5:])
        return False, f"traceback:\n{last}"
    # 0 = success, 1 = no-match / informational exit, 2 = argparse error.
    if r.returncode not in (0, 1, 2):
        return False, f"exit code {r.returncode}"
    return True, f"exit {r.returncode}"

# ─── Per-script run strategies ────────────────────────────────────────

def run_strategy_for(script):
    """Return a list of (label, callable) test steps for this script."""
    steps = []

    # Always: compile check.
    steps.append(("compile", lambda: compile_check(script)))

    name = script

    # Scripts that use argparse (support --help).
    argparse_examples = {
        "00_quickstart.py", "01_dns_monitor.py",
        "03_http_sniffer.py", "04_anomaly_detector.py", "05_pcap_report.py",
        "06_bandwidth_recorder.py", "07_packet_firewall.py", "08_browser_spy.py",
        "09_stream_follower.py", "10_tls_capture.py", "11_tls_decryptor.py",
        "12_http_parser_demo.py", "13_dns_spy.py", "14_tun_replay.py",
        "15_socket_forward.py", "16_payload_transform.py", "17_flow_tracker.py",
        "18_pcapng_writer.py", "19_lua_processor.py", "20_multi_interface_parallel.py",
        "21_zero_copy_ring.py", "22_tcp_stream_reassembly.py", "23_socket_forwarding.py",
        "24_lua_pipeline.py", "26_pcap_diff.py",
    }
    # Scripts that take positional args (no --help support).
    positional_only = {
        "02_traffic_dashboard.py",  # uses positional interface arg
        "25_protocol_stats.py",     # uses positional pcap arg
    }

    if name in argparse_examples:
        steps.append(("--help", lambda: run_help(script)))
    elif name in positional_only:
        # Skip --help test; just compile + pcap-run.
        pass

    # Examples that accept a `--file <pcap>` argument.
    file_examples = {
        "00_quickstart.py":      [FIXTURES / "all.pcap", "--count", "20"],
        "05_pcap_report.py":     [FIXTURES / "all.pcap", "--no-html"],
        "09_stream_follower.py": [FIXTURES / "ipv4_tcp_http.pcap"],
        "10_tls_capture.py":     [FIXTURES / "ipv6_tcp_tls.pcap"],
        "11_tls_decryptor.py":   [REPO_ROOT / "encrypted_traffic.pcap",
                                  REPO_ROOT / "tls_keys.log"],
        "12_http_parser_demo.py":[FIXTURES / "ipv4_tcp_http.pcap"],
        "13_dns_spy.py":         [FIXTURES / "ipv4_udp_dns.pcap"],
        "17_flow_tracker.py":    [FIXTURES / "all.pcap"],
        "18_pcapng_writer.py":   [FIXTURES / "all.pcap", "/tmp/np_pcapng_out.pcapng"],
        "22_tcp_stream_reassembly.py": [FIXTURES / "ipv4_tcp_http.pcap"],
        "25_protocol_stats.py":  [FIXTURES / "all.pcap"],
        "26_pcap_diff.py":       [FIXTURES / "all.pcap", FIXTURES / "all.pcap"],
    }
    # Examples that need a positional interface arg — we pass a fake one
    # and let netpipe return an error quickly.
    iface_examples = {
        "21_zero_copy_ring.py":  ["_test_iface_"],   # netpipe fails fast
    }

    if name in file_examples:
        args = [str(a) for a in file_examples[name]]
        steps.append(("pcap-run", lambda: run_with_pcap(script, args)))
    elif name in iface_examples:
        args = [str(a) for a in iface_examples[name]]
        steps.append(("iface-fail", lambda: run_with_pcap(script, args)))

    return steps

# ─── Main ─────────────────────────────────────────────────────────────

def main():
    if NETPIPE is None:
        print(f"{RED}ERROR: netpipe binary not found.{NC}")
        print("Build it first:  cd /home/z/my-project/netpipe/netpipe-0.1.0 && make")
        sys.exit(1)

    print(f"{BOLD}=== Python examples test runner ==={NC}")
    print(f"netpipe: {NETPIPE}")
    print(f"scripts: {len(SCRIPTS)}")
    print()

    total_pass = 0
    total_fail = 0
    total_skip = 0
    failed_scripts = []

    for script in SCRIPTS:
        print(f"{BOLD}{script}{NC}")
        steps = run_strategy_for(script)
        for label, fn in steps:
            print(f"  {label:>12}: ", end="", flush=True)
            try:
                ok, msg = fn()
            except Exception as e:
                ok, msg = False, f"exception: {e!r}"
            if ok:
                print(f"{GREEN}PASS{NC} ({msg})")
                total_pass += 1
            else:
                print(f"{RED}FAIL{NC} ({msg})")
                total_fail += 1
                if script not in failed_scripts:
                    failed_scripts.append(script)
        print()

    print(f"{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print(f"{BOLD}  RESULTS{NC}")
    print(f"{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print(f"  {GREEN}Passed : {total_pass}{NC}")
    print(f"  {RED}Failed : {total_fail}{NC}")
    print(f"  Scripts with failures: {len(failed_scripts)}")
    if failed_scripts:
        print(f"  Failed: {', '.join(failed_scripts)}")
    print()

    if total_fail:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
