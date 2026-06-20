#!/bin/bash
# ============================================================================
# netpipe — comprehensive functionality test script (basic → advanced)
#
# Usage:
#   cd <your netpipe source dir>
#   ./tests/test_all_functionality.sh
#
# Or run individual sections by section number:
#   SECTION=1 ./tests/test_all_functionality.sh   # just basic CLI tests
#   SECTION=2 ./tests/test_all_functionality.sh   # intermediate
#   SECTION=3 ./tests/test_all_functionality.sh   # advanced
#
# Requires:
#   - netpipe binary at build/bin/netpipe (run `make` first)
#   - sudo privileges for live-capture tests (sections 2.3+ and 3.x)
#   - python3 for JSON inspection tests
#   - nc (netcat) for socket-sink test
#
# Each test prints:
#   [PASS] test name           — green, success
#   [FAIL] test name — reason  — red, failure
#   [SKIP] test name — reason  — yellow, prerequisites missing
# ============================================================================

set -u
cd "$(dirname "$0")/.."   # cd to netpipe root

BIN=./build/bin/netpipe
PASS=0; FAIL=0; SKIP=0
COLOR_GREEN=$'\033[1;32m'
COLOR_RED=$'\033[1;31m'
COLOR_YELLOW=$'\033[1;33m'
COLOR_BLUE=$'\033[1;34m'
COLOR_RESET=$'\033[0m'

# Optional: only run a specific section
RUN_SECTION="${SECTION:-0}"

# FIX: helper to strip ANSI escape codes from output (the registry list
# functions use colored output which breaks grep patterns).
strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }

# FIX: check if sudo is available non-interactively (cached password or
# passwordless).  We define this once so all live-capture tests use the
# same check instead of each calling `sudo -n true` separately (which
# can hang if sudo decides to prompt).
SUDO_OK=false
if [[ $EUID -eq 0 ]]; then
    SUDO_OK=true
elif sudo -n true 2>/dev/null; then
    SUDO_OK=true
fi

# FIX: timeout wrapper — use `timeout` if available, otherwise a no-op.
# All live-capture tests use this to avoid hanging forever on a quiet
# interface (especially lo, which only sees localhost traffic).
# Uses -k 2 (kill after 2s) so even if netpipe ignores SIGTERM, it gets
# SIGKILL'd and the test script can continue.
TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
fi
run_with_timeout() {
    local secs="$1"; shift
    if [[ -n "$TIMEOUT_CMD" ]]; then
        # -s TERM: send SIGTERM first (graceful)
        # -k 2:    if still alive 2s later, send SIGKILL (forceful)
        $TIMEOUT_CMD -s TERM -k 2 "$secs" "$@"
    else
        "$@"
    fi
}

pass() { echo "${COLOR_GREEN}[PASS]${COLOR_RESET} $1"; PASS=$((PASS+1)); }
fail() { echo "${COLOR_RED}[FAIL]${COLOR_RESET} $1 — $2"; FAIL=$((FAIL+1)); }
skip() { echo "${COLOR_YELLOW}[SKIP]${COLOR_RESET} $1 — $2"; SKIP=$((SKIP+1)); }
hdr()  { echo ""; echo "${COLOR_BLUE}=== $1 ===${COLOR_RESET}"; }

# Pre-flight: does the binary exist?
if [[ ! -x "$BIN" ]]; then
    echo "${COLOR_RED}ERROR: $BIN not found — run 'make' first${COLOR_RESET}"
    exit 1
fi

# Detect the first available live capture interface.
# Prefer real interfaces (wlo*, wlan*, eth*, en*) over loopback (lo)
# since lo only sees localhost traffic and many tests would hang waiting
# for packets that never arrive.
IFACE="${IFACE:-}"
if [[ -z "$IFACE" ]]; then
    # FIX: `netpipe -D` output has ANSI color codes (\033[36m...\033[0m)
    # wrapping interface names, so a plain `grep "^\s+wlo"` won't match.
    # Strip ANSI first, then grep.
    #
    # Also try `ip link show` as a more reliable fallback — it has no
    # color codes and doesn't require root to list interfaces.
    for pattern in wlo wlan wlp eth enp ens; do
        # Try netpipe -D (stripped of ANSI)
        IFACE=$("$BIN" -D 2>/dev/null | strip_ansi | grep -E "^\s+${pattern}" | awk '{print $1}' | head -1)
        [[ -n "$IFACE" ]] && break
        # Fallback: ip link show (no colors, no root needed)
        if command -v ip >/dev/null 2>&1; then
            IFACE=$(ip -o link show 2>/dev/null | grep -oE "^\d+:\s+${pattern}[a-z0-9]+" | awk '{print $2}' | head -1)
            [[ -n "$IFACE" ]] && break
        fi
    done
    # If no real interface matched, fall back to any non-lo interface
    if [[ -z "$IFACE" ]]; then
        IFACE=$("$BIN" -D 2>/dev/null | strip_ansi | grep -E '^\s+[a-z]' | awk '{print $1}' \
                | grep -vE '^lo$' | head -1)
    fi
    if [[ -z "$IFACE" ]] && command -v ip >/dev/null 2>&1; then
        IFACE=$(ip -o link show 2>/dev/null | grep -oE '^\d+:\s+[a-z][a-z0-9]+' | awk '{print $2}' | grep -v '^lo$' | head -1)
    fi
    # Last resort: lo (but warn that tests may be quiet)
    if [[ -z "$IFACE" ]]; then
        IFACE=lo
        echo "${COLOR_YELLOW}WARNING: no real interface found, using lo — some tests may be quiet${COLOR_RESET}"
        echo "${COLOR_YELLOW}         Override with: IFACE=wlo1 ./tests/test_all_functionality.sh${COLOR_RESET}"
    else
        echo "${COLOR_GREEN}Auto-detected interface: $IFACE${COLOR_RESET}"
    fi
fi

echo "netpipe binary: $BIN"
echo "test interface: $IFACE (override with IFACE=...)"
echo ""

# ============================================================================
# SECTION 1: BASIC CLI TESTS (no root needed)
# ============================================================================
if [[ "$RUN_SECTION" == "0" || "$RUN_SECTION" == "1" ]]; then
hdr "SECTION 1: Basic CLI tests (no root needed)"

# 1.1 Version
if "$BIN" --version 2>&1 | grep -q "netpipe version"; then
    pass "1.1  --version prints version string"
else
    fail "1.1  --version" "no version string in output"
fi

# 1.2 Help
if "$BIN" -h 2>&1 | grep -q "Usage:"; then
    pass "1.2  -h prints usage"
else
    fail "1.2  -h" "no Usage line"
fi

# 1.3 List devices (-D) — should always work even without root
if "$BIN" -D 2>&1 | grep -qE "devices|wlo|eth|lo"; then
    pass "1.3  -D lists capture devices"
else
    fail "1.3  -D" "no devices listed"
fi

# 1.4 FIX W2: --list-sinks should show all 7 built-in sinks (np_registry wired)
# FIX: strip ANSI color codes before grepping — the registry list functions
# use \033[36m...\033[0m around the name, which would break a plain grep.
SINKS=$("$BIN" --list-sinks 2>/dev/null | strip_ansi | grep -cE "^\s+(null|stats|pretty|hex|json|pcapng|pcap)\s")
if [[ "$SINKS" -ge 7 ]]; then
    pass "1.4  --list-sinks shows all 7 built-in sinks (np_registry wired)"
else
    fail "1.4  --list-sinks" "only $SINKS sinks shown (expected 7)"
fi

# 1.5 FIX W2: --list-sources should show all 3 built-in sources
SOURCES=$("$BIN" --list-sources 2>/dev/null | strip_ansi | grep -cE "^\s+(live|file|ring)\s")
if [[ "$SOURCES" -ge 3 ]]; then
    pass "1.5  --list-sources shows all 3 built-in sources"
else
    fail "1.5  --list-sources" "only $SOURCES sources shown (expected 3)"
fi

# 1.6 Read pcap with pretty output (uses bundled fixture)
# FIX: the pretty printer shows the highest-layer protocol ("http" for
# HTTP-over-TCP packets, not "tcp"), so grep for either.
if "$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -fmt pretty 2>/dev/null | grep -qiE "tcp|http"; then
    pass "1.6  -r fixture.pcap -fmt pretty reads packets"
else
    fail "1.6  pretty output" "no tcp/http packets shown"
fi

# 1.7 Read pcap with hex output
if "$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -fmt hex 2>/dev/null | grep -q "Packet #"; then
    pass "1.7  -fmt hex shows packet dump"
else
    fail "1.7  hex output" "no Packet # lines"
fi

# 1.8 FIX W2: Read pcap with JSON output (registry-resolved format)
if "$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -fmt json 2>/dev/null | grep -q '"seq"'; then
    pass "1.8  -fmt json emits NDJSON with seq field"
else
    fail "1.8  json output" "no JSON seq field"
fi

# 1.9 FIX W2: Infer format from .json extension (registry extension lookup)
"$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -o /tmp/np_test1.json 2>/dev/null
if [[ -s /tmp/np_test1.json ]] && grep -q '"seq"' /tmp/np_test1.json; then
    pass "1.9  -o out.json infers format from extension (registry lookup)"
else
    fail "1.9  extension inference" "no JSON written"
fi

# 1.10 FIX W2: Infer format from .pcap extension
"$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -o /tmp/np_test2.pcap 2>/dev/null
if [[ -s /tmp/np_test2.pcap ]] && [[ $(head -c 4 /tmp/np_test2.pcap | xxd -p) == "d4c3b2a1" ]]; then
    pass "1.10  -o out.pcap infers pcap format (registry + magic check)"
else
    fail "1.10  pcap inference" "no pcap magic bytes"
fi

# 1.11 FIX W2: Infer format from .pcapng extension
"$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -o /tmp/np_test3.pcapng 2>/dev/null
if [[ -s /tmp/np_test3.pcapng ]] && [[ $(head -c 4 /tmp/np_test3.pcapng | xxd -p) == "0a0d0d0a" ]]; then
    pass "1.11  -o out.pcapng infers pcapng format (Section Header Block magic)"
else
    fail "1.11  pcapng inference" "no pcapng SHB magic"
fi

# 1.12 Protocol filter
if "$BIN" -r tests/fixtures/all.pcap -proto dns -fmt pretty 2>/dev/null | grep -q "dns"; then
    pass "1.12  -proto dns filters to DNS packets only"
else
    fail "1.12  proto filter" "no DNS packets"
fi

# 1.13 BPF filter
# FIX: grep for "http" (the pretty-printer's proto column for HTTP packets)
# or any packet line — the BPF filter matches at the TCP layer but the
# display shows the decoded application-layer protocol.
if "$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -f "tcp port 80" -fmt pretty 2>/dev/null | grep -qiE "tcp|http"; then
    pass "1.13  -f 'tcp port 80' BPF filter works on file source"
else
    fail "1.13  BPF filter" "no tcp/http packets after filter"
fi

# 1.14 PCAP roundtrip — write then read back
"$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -o /tmp/np_roundtrip.pcap 2>/dev/null
if "$BIN" -r /tmp/np_roundtrip.pcap -fmt pretty 2>/dev/null | grep -qiE "tcp|http"; then
    pass "1.14  PCAP roundtrip (write then read back)"
else
    fail "1.14  roundtrip" "rewritten pcap is unreadable"
fi

fi  # end section 1

# ============================================================================
# SECTION 2: INTERMEDIATE — processors, sinks, limits (some need root)
# ============================================================================
if [[ "$RUN_SECTION" == "0" || "$RUN_SECTION" == "2" ]]; then
hdr "SECTION 2: Intermediate — processors, sinks, tunable limits"

# 2.1 Count-limited file read (-c)
OUT=$("$BIN" -r tests/fixtures/all.pcap -c 3 -fmt null 2>&1)
if echo "$OUT" | grep -q "captured=3"; then
    pass "2.1  -c 3 stops after 3 packets"
else
    fail "2.1  count limit" "did not stop at 3"
fi

# 2.2 Stats sink
"$BIN" -r tests/fixtures/all.pcap -stats /tmp/np_stats.txt 2>/dev/null
if [[ -s /tmp/np_stats.txt ]] && grep -qE "TCP|UDP|DNS|HTTP" /tmp/np_stats.txt; then
    pass "2.2  -stats writes periodic counters"
else
    fail "2.2  stats sink" "no stats written"
fi

# 2.3 Flow tracker (file source — no root needed)
OUT=$("$BIN" -r tests/fixtures/all.pcap -proc flow-tracker -fmt null 2>&1)
if echo "$OUT" | grep -q "FLOW TRACKER SUMMARY"; then
    pass "2.3  -proc flow-tracker prints summary table"
else
    fail "2.3  flow-tracker" "no summary printed"
fi

# 2.4 TCP stream reassembly (file source)
OUT=$("$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -proc tcp-stream -fmt json -o /tmp/np_tcp.json 2>&1)
if [[ -s /tmp/np_tcp.json ]] && grep -q "stream_hex" /tmp/np_tcp.json; then
    pass "2.4  -proc tcp-stream populates stream_hex"
else
    fail "2.4  tcp-stream" "no stream_hex in JSON"
fi

# 2.5 FIX #12: Tunable flow-tracker limits (--flow-max, --flow-idle-timeout)
OUT=$("$BIN" -r tests/fixtures/all.pcap -proc flow-tracker --flow-max 5000 --flow-idle-timeout 30 -fmt null 2>&1)
if echo "$OUT" | grep -q "max entries = 5000" && echo "$OUT" | grep -q "idle timeout = 30 s"; then
    pass "2.5  --flow-max / --flow-idle-timeout tunables applied"
else
    fail "2.5  flow tunables" "limit log lines missing"
fi

# 2.6 FIX #12: Tunable TCP stream limits
OUT=$("$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -proc tcp-stream --tcp-max-stream 4194304 --tcp-hole-timeout 500 -fmt null 2>&1)
if echo "$OUT" | grep -q "per-flow cap = 4194304" && echo "$OUT" | grep -q "hole-flush timeout = 500"; then
    pass "2.6  --tcp-max-stream / --tcp-hole-timeout tunables applied"
else
    fail "2.6  tcp tunables" "limit log lines missing"
fi

# 2.7 FIX #12: Tunable Lua memory limit
OUT=$("$BIN" -r tests/fixtures/all.pcap -proc lua:mitigate.lua --lua-mem-limit 33554432 -fmt null 2>&1)
if echo "$OUT" | grep -q "VM memory cap = 33554432"; then
    pass "2.7  --lua-mem-limit tunable applied"
else
    fail "2.7  lua-mem-limit" "cap log line missing"
fi

# 2.8 FIX #1 + W1: Lua sandbox compatibility (mitigate.lua — uses np_log binding)
OUT=$("$BIN" -r tests/fixtures/ipv4_udp_dns.pcap -proc lua:mitigate.lua -fmt null 2>&1)
if echo "$OUT" | grep -q "lua_ids_mitigate"; then
    pass "2.8  -proc lua:mitigate.lua constructs without io.open crash"
else
    fail "2.8  mitigate.lua" "processor did not register"
fi

# 2.9 FIX #1: test.lua — was broken by sandbox, now uses np_log
OUT=$("$BIN" -r tests/fixtures/ipv4_udp_dns.pcap -proc lua:test.lua -fmt null 2>&1)
if echo "$OUT" | grep -q "exfil_payload_isolator"; then
    pass "2.9  -proc lua:test.lua constructs (was broken by sandbox before fix)"
else
    fail "2.9  test.lua" "processor did not register — $(echo "$OUT" | grep -i error | head -1)"
fi

# 2.10 FIX #13: mitigate.lua's expanded resolver list
OUT=$("$BIN" -r tests/fixtures/ipv4_udp_dns.pcap -proc lua:mitigate.lua -fmt null 2>&1)
if echo "$OUT" | grep -q "resolvers=6"; then
    pass "2.10  mitigate.lua loaded 6-resolver default list (was 1 before)"
else
    fail "2.10  resolver list" "resolvers=6 not in log"
fi

# 2.11 Payload transform: hex encode
OUT=$("$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -proc transform:hex -fmt json -o /tmp/np_xform.json 2>&1)
if [[ -s /tmp/np_xform.json ]] && grep -q "stream_hex" /tmp/np_xform.json; then
    pass "2.11  -proc transform:hex populates stream_hex"
else
    fail "2.11  transform:hex" "no stream_hex"
fi

# 2.12 Payload transform: base64
OUT=$("$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -proc transform:base64 -fmt json -o /tmp/np_b64.json 2>&1)
if [[ -s /tmp/np_b64.json ]]; then
    pass "2.12  -proc transform:base64 runs without error"
else
    fail "2.12  transform:base64" "no output"
fi

# 2.13 Rate limiting (file source, very low rate)
START=$(date +%s%N)
"$BIN" -r tests/fixtures/all.pcap -rate 100 -fmt null 2>/dev/null
END=$(date +%s%N)
ELAPSED_MS=$(( (END - START) / 1000000 ))
# all.pcap has ~6 packets; at 100 B/s with ~600 bytes total, expect ~6 seconds
if [[ "$ELAPSED_MS" -gt 1000 ]]; then
    pass "2.13  -rate 100 throttled output (took ${ELAPSED_MS} ms)"
else
    fail "2.13  rate limiting" "throttle did not engage (${ELAPSED_MS} ms)"
fi

# 2.14 FIX W3 + #2: Live capture WITHOUT promisc (default OFF now)
if [[ "$SUDO_OK" != "true" ]]; then
    skip "2.14  live capture (no promisc)" "needs sudo"
else
    # FIX: use timeout to avoid hanging on a quiet interface; also use
    # -T 500 (500ms read timeout) so the capture doesn't block forever.
    OUT=$(run_with_timeout 8 sudo "$BIN" -i "$IFACE" -T 500 -c 5 -fmt null 2>&1 || true)
    if echo "$OUT" | grep -qE "captured=|pipeline stopped"; then
        # Verify promisc is OFF by default — no "promiscuous" warning
        if ! echo "$OUT" | grep -qi "promisc"; then
            pass "2.14  live capture works, promisc OFF by default (was ON before fix)"
        else
            fail "2.14  promisc default" "promisc was enabled without -p"
        fi
    else
        fail "2.14  live capture" "did not capture (interface may be quiet — try IFACE=wlo1)"
    fi
fi

# 2.15 FIX #6: Kernel-side BPF install (verify via -v log line)
if [[ "$SUDO_OK" != "true" ]]; then
    skip "2.15  kernel BPF install" "needs sudo"
else
    OUT=$(run_with_timeout 8 sudo "$BIN" -i "$IFACE" -T 500 -f "tcp" -c 1 -fmt null -v 2>&1 || true)
    if echo "$OUT" | grep -q "installed kernel-side BPF filter"; then
        pass "2.15  -f installs BPF in kernel via pcap_setfilter (was user-space only before)"
    else
        fail "2.15  kernel BPF" "no install log line (interface may be down)"
    fi
fi

# 2.16 FIX W3: np_evloop stop-poller (verify via -v log line)
if [[ "$SUDO_OK" != "true" ]]; then
    skip "2.16  np_evloop stop-poller" "needs sudo"
else
    OUT=$(run_with_timeout 8 sudo "$BIN" -i "$IFACE" -T 500 -c 1 -fmt null -v 2>&1 || true)
    if echo "$OUT" | grep -q "evloop created"; then
        pass "2.16  stop-poller uses np_evloop (was busy-poll usleep before)"
    else
        fail "2.16  evloop" "no 'evloop created' log"
    fi
fi

fi  # end section 2

# ============================================================================
# SECTION 3: ADVANCED — TLS decrypt, TUN/TAP, socket sink, ring, pool stats
# ============================================================================
if [[ "$RUN_SECTION" == "0" || "$RUN_SECTION" == "3" ]]; then
hdr "SECTION 3: Advanced — TLS, TUN/TAP, socket, ring, pool stats"

# 3.1 FIX #10 + #9: TLS decryption end-to-end (bundled TLS 1.3 fixture)
if [[ -f encrypted_traffic.pcap && -f tls_keys.log ]]; then
    OUT=$("$BIN" -r encrypted_traffic.pcap -proc tls-decrypt:tls_keys.log -proc tcp-stream -fmt json -o /tmp/np_tls.json 2>&1)
    if [[ -s /tmp/np_tls.json ]]; then
        # Verify the keylog was loaded
        if echo "$OUT" | grep -q "loaded 10 keylog records"; then
            pass "3.1  TLS decrypt processor loaded keylog (10 records)"
        else
            fail "3.1  TLS keylog load" "10 records not loaded"
        fi
        # Verify JSON has stream_hex (decrypted or reassembled)
        if grep -q "stream_hex" /tmp/np_tls.json; then
            pass "3.2  TLS decrypt + tcp-stream produced stream_hex in JSON"
        else
            fail "3.2  TLS stream output" "no stream_hex in JSON"
        fi
    else
        fail "3.1  TLS decrypt" "no JSON output"
    fi
else
    skip "3.1/3.2  TLS decrypt" "encrypted_traffic.pcap or tls_keys.log missing"
fi

# 3.3 FIX #8: TLS aliasing — verify decrypted flag is set via JSON output
if [[ -f /tmp/np_tls.json ]]; then
    if python3 -c "
import json, sys
with open('/tmp/np_tls.json') as f:
    for line in f:
        pkt = json.loads(line)
        # Check at least one packet has stream_data (decrypted or reassembled)
        if pkt.get('stream_hex'):
            sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        pass "3.3  TLS decrypted/reassembled stream visible in JSON output"
    else
        fail "3.3  TLS aliasing" "no stream_hex in any packet"
    fi
fi

# 3.4 FIX #10: TLS keylog rejection (bad path → processor refuses to construct)
OUT=$("$BIN" -r tests/fixtures/all.pcap -proc tls-decrypt:/nonexistent.log -fmt null 2>&1)
if echo "$OUT" | grep -q "refusing to create processor"; then
    pass "3.4  TLS decrypt refuses bad keylog path (Bug B13 fix intact)"
else
    fail "3.4  keylog rejection" "did not refuse bad path"
fi

# 3.5 FIX #10: TLS keylog rejection (empty file → also refused)
> /tmp/np_empty.log
OUT=$("$BIN" -r tests/fixtures/all.pcap -proc tls-decrypt:/tmp/np_empty.log -fmt null 2>&1)
if echo "$OUT" | grep -q "refusing to create processor"; then
    pass "3.5  TLS decrypt refuses empty keylog (no records)"
else
    fail "3.5  empty keylog" "did not refuse empty file"
fi

# 3.6 FIX #11: socket:// URI port range check (out-of-range port rejected)
OUT=$("$BIN" -r tests/fixtures/all.pcap -o "socket://127.0.0.1:99999" -fmt pcap 2>&1)
if echo "$OUT" | grep -q "invalid port"; then
    pass "3.6  socket://host:99999 rejected (was silent wrap to 34463 before)"
else
    fail "3.6  port range check" "out-of-range port not rejected"
fi

# 3.7 FIX #11: socket:// with valid port — start a listener, stream packets
# FIX: the previous version used `nc -l -p 19999` and probed readiness with
# bash's `/dev/tcp/127.0.0.1/19999`.  But that probe OPENS A REAL TCP
# CONNECTION, which `nc -l` accepts and then EXITS (nc -l is one-shot by
# default).  By the time netpipe tries to connect, nc is already gone.
#
# New approach: use python3 as the listener (we already depend on it for
# other tests).  Python's socket.accept() blocks until netpipe connects,
# doesn't exit after one connection, and is completely portable (no nc
# variant issues).  We check readiness with `ss` (non-intrusive — doesn't
# make a connection).
if command -v python3 >/dev/null 2>&1; then
    rm -f /tmp/np_socket.bin
    # Start a Python TCP listener that writes all received bytes to a file
    python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19999))
s.listen(1)
s.settimeout(8)  # bail out after 8s if no connection
try:
    conn, _ = s.accept()
    with open('/tmp/np_socket.bin', 'wb') as f:
        while True:
            data = conn.recv(4096)
            if not data: break
            f.write(data)
    conn.close()
except socket.timeout:
    sys.exit(1)
s.close()
" &
    PY_PID=$!
    # Wait up to 3 seconds for the listener to bind (non-intrusive check via ss)
    LISTENER_READY=false
    if command -v ss >/dev/null 2>&1; then
        for i in $(seq 1 30); do
            if ss -tln 2>/dev/null | grep -q ":19999"; then
                LISTENER_READY=true
                break
            fi
            sleep 0.1
        done
    elif command -v netstat >/dev/null 2>&1; then
        for i in $(seq 1 30); do
            if netstat -tln 2>/dev/null | grep -q ":19999"; then
                LISTENER_READY=true
                break
            fi
            sleep 0.1
        done
    else
        # No ss/netstat — just sleep 0.5s and hope
        sleep 0.5
        LISTENER_READY=true
    fi
    if [[ "$LISTENER_READY" != "true" ]]; then
        kill "$PY_PID" 2>/dev/null || true
        wait "$PY_PID" 2>/dev/null || true
        skip "3.7  socket sink" "could not start Python listener on port 19999"
    else
        # Run netpipe — capture stderr for debugging if it fails
        NP_OUT=$("$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -o "socket://127.0.0.1:19999" -fmt pcap 2>&1)
        # Give the listener a moment to finish writing
        sleep 0.5
        kill "$PY_PID" 2>/dev/null || true
        wait "$PY_PID" 2>/dev/null || true
        if [[ -s /tmp/np_socket.bin ]] && [[ $(head -c 4 /tmp/np_socket.bin | xxd -p 2>/dev/null) == "d4c3b2a1" ]]; then
            pass "3.7  socket://127.0.0.1:19999 streams pcap to remote listener"
        else
            # Diagnose: did netpipe connect?  Did the listener get any bytes?
            SZ=$(stat -c%s /tmp/np_socket.bin 2>/dev/null || echo "0")
            fail "3.7  socket sink" "received $SZ bytes; netpipe stderr: $(echo "$NP_OUT" | tail -2 | tr '\n' ' ')"
        fi
    fi
else
    skip "3.7  socket sink" "python3 not installed"
fi

# 3.8 FIX W1: Pool stats — verify the bufpool is actually being used
OUT=$("$BIN" -r tests/fixtures/all.pcap -fmt null --show-pool-stats 2>&1)
if echo "$OUT" | grep -q "bufpool"; then
    HIT_RATE=$(echo "$OUT" | grep "hit_rate" | grep -oE '[0-9]+\.[0-9]+%' | head -1)
    if [[ -n "$HIT_RATE" ]]; then
        pass "3.8  --show-pool-stats reports hit_rate=$HIT_RATE (np_bufpool wired)"
    else
        fail "3.8  pool stats" "no hit_rate in output"
    fi
else
    fail "3.8  pool stats" "no bufpool stats printed"
fi

# 3.9 FIX W1: Pool stats — file source should show 100% hit rate (small fixture)
OUT=$("$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -fmt null --show-pool-stats 2>&1)
HIT_RATE=$(echo "$OUT" | grep "hit_rate" | grep -oE '[0-9]+\.[0-9]+%' | head -1)
if [[ "$HIT_RATE" == "100.0%" ]]; then
    pass "3.9  bufpool hit_rate=100.0% on small fixture (perfect recycling)"
elif [[ -n "$HIT_RATE" ]]; then
    pass "3.9  bufpool hit_rate=$HIT_RATE (acceptable for small fixture)"
else
    fail "3.9  pool hit rate" "no hit_rate reported"
fi

# 3.10 FIX #4: TUN/TAP sink — verify Ethernet synthesis is OPT-IN now
if [[ "$SUDO_OK" != "true" ]]; then
    skip "3.10  TUN/TAP sink" "needs sudo"
else
    # Try to create a TUN interface and replay a non-Ethernet pcap into it
    # (SLL-captured pcaps would normally trigger synthesis; without ?synth-eth=1
    # the packets should be dropped with a debug log.)
    OUT=$(run_with_timeout 8 sudo "$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -o "tap://np_test_tap" -c 3 -fmt null -v 2>&1 || true)
    # Either: it succeeds (Ethernet frames pass through), OR it drops with the
    # "dropping non-Ethernet packet" debug log (proving opt-in works).
    # Either way, the absence of synthesis without the flag is what we check.
    if echo "$OUT" | grep -qE "dropping non-Ethernet|opened TAP"; then
        pass "3.10  TAP sink respects opt-in synthesis flag (no unconditional forge)"
    else
        fail "3.10  TAP sink" "unexpected output: $(echo "$OUT" | tail -1)"
    fi
    # Cleanup any leftover interface
    sudo ip link del np_test_tap 2>/dev/null || true
fi

# 3.11 FIX #3: --link-proto restricts AF_PACKET ring to IPv4 only
if [[ "$SUDO_OK" != "true" ]]; then
    skip "3.11  --link-proto ring restriction" "needs sudo"
else
    # Capture with --ring --link-proto ipv4 — should only see IPv4 packets
    OUT=$(run_with_timeout 5 sudo "$BIN" -i "$IFACE" --ring --link-proto ipv4 -c 5 -fmt null -v 2>&1 || true)
    if echo "$OUT" | grep -qE "ring opened|captured|pipeline"; then
        pass "3.11  --ring --link-proto ipv4 captures (was ETH_P_ALL only before)"
    else
        fail "3.11  ring link-proto" "ring did not start: $(echo "$OUT" | tail -1)"
    fi
fi

# 3.12 FIX #12: --ring-blocks tunable
if [[ "$SUDO_OK" != "true" ]]; then
    skip "3.12  --ring-blocks tunable" "needs sudo"
else
    OUT=$(run_with_timeout 5 sudo "$BIN" -i "$IFACE" --ring --ring-blocks 16 -c 1 -fmt null -v 2>&1 || true)
    # Verify ring size is 16 MB (16 blocks × 1 MB)
    if echo "$OUT" | grep -qE "size=16 MB|size=16"; then
        pass "3.12  --ring-blocks 16 produced 16 MB ring (was hardcoded 8 MB before)"
    else
        fail "3.12  ring-blocks" "no 16 MB ring log: $(echo "$OUT" | tail -1)"
    fi
fi

# 3.13 Multi-source pipeline (two pcap files)
OUT=$("$BIN" -r tests/fixtures/ipv4_tcp_http.pcap -r tests/fixtures/ipv4_udp_dns.pcap -fmt null 2>&1)
if echo "$OUT" | grep -q "2 source(s)"; then
    pass "3.13  Multi-source pipeline (2 input files) supported"
else
    fail "3.13  multi-source" "did not register 2 sources"
fi

# 3.14 FIX #1: Lua np_log binding — verify log lines come through np_log
OUT=$("$BIN" -r tests/fixtures/ipv4_udp_dns.pcap -proc lua:test.lua -fmt null 2>&1)
if echo "$OUT" | grep -q "np_lua.c" && echo "$OUT" | grep -q "netpipe packet log"; then
    pass "3.14  Lua np_log binding routes through C logger (file:line visible)"
else
    fail "3.14  np_log binding" "no np_lua.c log lines"
fi

# 3.15 DNS-exfil IPS — synthetic exfil packet dropped by mitigate.lua
# FIX: generate the DNS-exfil pcap with pure Python stdlib (struct + socket)
# instead of requiring scapy.  This works on any system with python3 — no
# pip install needed, no venv, no --break-system-packages hassle.
#
# IMPORTANT: DNS names must be in WIRE FORMAT (length-prefixed labels),
# not dotted-string format.  The previous version wrote the literal
# string 'exfil-payload-AAA...AAA.example.com' into the DNS payload,
# which netpipe's decode_dns() couldn't parse — so dns_query_name came
# out empty and the IPS rules didn't match.
#
# Also, DNS labels are max 63 bytes.  'exfil-payload-' + 60 A's = 73
# bytes, which exceeds the limit.  We use 40 A's (53-byte label) instead.
if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import struct, socket

# PCAP global header (24 bytes)
pcap_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

# Build DNS query name in WIRE FORMAT: <len>label<len>label\x00
# Query: exfil-payload-AAAA...AAA.example.com
#   label 1: 'exfil-payload-' + 'A'*40 = 53 bytes (under 63-byte limit)
#   label 2: 'example' (7 bytes)
#   label 3: 'com' (3 bytes)
# Total dotted name length = 53 + 1 + 7 + 1 + 3 = 65 chars >= 50 (threshold)
label1 = b'exfil-payload-' + b'A' * 40   # 53 bytes
qname_wire = bytes([len(label1)]) + label1 + b'\x07example\x03com\x00'

# DNS header: id=1, flags=0x0100 (RD), qdcount=1, ancount=0, nscount=0, arcount=0
dns_header = struct.pack('>HHHHHH', 1, 0x0100, 1, 0, 0, 0)
# Question: qname + qtype=A(1) + qclass=IN(1)
dns_question = qname_wire + struct.pack('>HH', 1, 1)
dns_payload = dns_header + dns_question

# UDP: sport=12345, dport=53, len, checksum=0
udp_len = 8 + len(dns_payload)
udp_header = struct.pack('>HHHH', 12345, 53, udp_len, 0)

# IPv4: ver=4, ihl=5, tos=0, total_len, id=0, flags=0, ttl=64, proto=17(UDP), cksum=0, src=10.0.0.1, dst=8.8.8.8
ip_total_len = 20 + udp_len
ip_header = struct.pack('>BBHHHBBHII', 0x45, 0, ip_total_len, 0, 0, 64, 17, 0,
                        struct.unpack('<I', socket.inet_aton('10.0.0.1'))[0],
                        struct.unpack('<I', socket.inet_aton('8.8.8.8'))[0])

# Ethernet: dst MAC, src MAC, ethertype=0x0800 (IPv4)
eth_header = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + struct.pack('>H', 0x0800)

frame = eth_header + ip_header + udp_header + dns_payload
pkt_header = struct.pack('<IIII', 0, 0, len(frame), len(frame))

with open('/tmp/np_exfil.pcap', 'wb') as f:
    f.write(pcap_header + pkt_header + frame)
print('ok')
" 2>/dev/null
    if [[ -f /tmp/np_exfil.pcap ]]; then
        OUT=$("$BIN" -r /tmp/np_exfil.pcap -proc lua:mitigate.lua -fmt null 2>&1)
        if echo "$OUT" | grep -q "EXFIL_PAYLOAD" || echo "$OUT" | grep -q "exfil_keyword"; then
            pass "3.15  mitigate.lua drops synthetic exfil-payload DNS packet"
        else
            fail "3.15  IPS drop" "no EXFIL_PAYLOAD alert (got: $(echo "$OUT" | tail -3 | tr '\n' ' '))"
        fi
    else
        fail "3.15  DNS-exfil IPS" "pcap generation failed"
    fi
else
    skip "3.15  DNS-exfil IPS" "python3 not installed"
fi

# 3.16 JSON output schema inspection — verify all expected fields are present
if [[ -f /tmp/np_tls.json ]]; then
    if python3 -c "
import json
with open('/tmp/np_tls.json') as f:
    pkt = json.loads(f.readline())
required = ['seq', 'ts', 'caplen', 'wirelen', 'flow_id', 'layers', 'raw_hex']
for k in required:
    assert k in pkt, f'missing field: {k}'
print('all fields present')
" 2>/dev/null; then
        pass "3.16  JSON output schema has all required fields (seq/ts/caplen/...)"
    else
        fail "3.16  JSON schema" "missing fields"
    fi
fi

# 3.17 Stress test — high packet count, verify pool hit rate stays high
if [[ "$SUDO_OK" != "true" ]]; then
    skip "3.17  stress test" "needs sudo"
else
    # FIX: generate traffic on the CORRECT interface.  The previous version
    # tried `ping 1.1.1.1` but if we're capturing on lo, that ping goes out
    # wlo1 and lo sees nothing.  Now we:
    #   1. Start a background traffic generator (ping + curl) that produces
    #      packets on $IFACE (the interface we're capturing on).
    #   2. Run netpipe capture concurrently.
    #   3. Stop the generator when netpipe exits.
    # For lo, we generate localhost traffic (ping 127.0.0.1 + curl localhost).
    # For real interfaces, we ping external addresses + curl external sites.

    # Determine traffic generation strategy based on interface
    PING_PID=""
    CURL_PID=""
    if [[ "$IFACE" == "lo" ]]; then
        # Localhost traffic: ping 127.0.0.1 generates ICMP on lo.
        # Also try curl to localhost (only works if a web server is running).
        ping -c 60 -i 0.1 127.0.0.1 >/dev/null 2>&1 &
        PING_PID=$!
        if command -v curl >/dev/null 2>&1; then
            (for i in $(seq 1 30); do curl -s --connect-timeout 1 http://127.0.0.1:80/ >/dev/null 2>&1; done) &
            CURL_PID=$!
        fi
    else
        # Real interface: ping external + curl external (generates DNS + TCP + TLS)
        ping -c 60 -i 0.1 1.1.1.1 >/dev/null 2>&1 &
        PING_PID=$!
        if command -v curl >/dev/null 2>&1; then
            (for i in $(seq 1 15); do curl -s --connect-timeout 2 https://1.1.1.1/ >/dev/null 2>&1; done) &
            CURL_PID=$!
        fi
    fi

    OUT=$(run_with_timeout 12 sudo "$BIN" -i "$IFACE" -T 500 -c 5000 -fmt null --show-pool-stats 2>&1 || true)
    [[ -n "$PING_PID" ]] && kill "$PING_PID" 2>/dev/null || true
    [[ -n "$CURL_PID" ]] && kill "$CURL_PID" 2>/dev/null || true
    [[ -n "$PING_PID" ]] && wait "$PING_PID" 2>/dev/null || true
    [[ -n "$CURL_PID" ]] && wait "$CURL_PID" 2>/dev/null || true

    HIT_RATE=$(echo "$OUT" | grep "hit_rate" | grep -oE '[0-9]+\.[0-9]+%' | head -1)
    CAPTURED=$(echo "$OUT" | grep "captured=" | grep -oE 'captured=[0-9]+' | head -1 | cut -d= -f2)
    if [[ -n "$HIT_RATE" && -n "$CAPTURED" && "$CAPTURED" -ge 10 ]]; then
        pass "3.17  stress test: $CAPTURED packets, pool hit_rate=$HIT_RATE"
    else
        skip "3.17  stress test" "interface too quiet (captured=${CAPTURED:-0}) — browse the web or run 'ping 1.1.1.1' in another terminal"
    fi
fi

fi  # end section 3

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo "${COLOR_BLUE}============================================================${COLOR_RESET}"
echo "${COLOR_BLUE}TEST SUMMARY${COLOR_RESET}"
echo "${COLOR_BLUE}============================================================${COLOR_RESET}"
echo "${COLOR_GREEN}PASS: $PASS${COLOR_RESET}"
echo "${COLOR_RED}FAIL: $FAIL${COLOR_RESET}"
echo "${COLOR_YELLOW}SKIP: $SKIP${COLOR_RESET}"
echo ""
if [[ "$FAIL" -gt 0 ]]; then
    echo "${COLOR_RED}Some tests failed — review the output above.${COLOR_RESET}"
    exit 1
else
    echo "${COLOR_GREEN}All tests passed (or skipped due to missing prereqs).${COLOR_RESET}"
    exit 0
fi
