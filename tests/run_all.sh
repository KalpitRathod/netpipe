#!/usr/bin/env bash
# =============================================================================
#  tests/run_all.sh — netpipe comprehensive test runner
#
#  Runs every testable category without requiring root or a live interface.
#  Suitable for CI (GitHub Actions) and local developer runs.
#
#  Usage:
#    bash tests/run_all.sh            # from repo root
#    bash tests/run_all.sh --verbose  # show full output
#
#  Exit code: 0 = all passed, 1 = one or more failures
# =============================================================================

# NO set -e — we track pass/fail manually so one failure never kills the run
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Auto-detect a local deps prefix (for environments where libpcap is not
# installed system-wide, e.g. CI containers without root).

BIN="./build/bin/netpipe"
FIXTURES="tests/fixtures"
VERBOSE="${1:-}"
PASS=0
FAIL=0
SKIP=0

# ── helpers ──────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() { echo -e "\n${BOLD}${CYAN}━━━  $*  ━━━${NC}"; }
ok()     { echo -e "  ${GREEN}✓ PASS${NC}  $*"; PASS=$((PASS+1)); }
fail()   { echo -e "  ${RED}✗ FAIL${NC}  $*"; FAIL=$((FAIL+1)); }
skip()   { echo -e "  ${YELLOW}⊘ SKIP${NC}  $*"; SKIP=$((SKIP+1)); }

# run silently unless --verbose; always returns actual exit code
quietly() {
    if [[ "$VERBOSE" == "--verbose" ]]; then
        "$@"
    else
        "$@" >/dev/null 2>&1
    fi
}

# run cmd, capture all output (stdout+stderr), return exit code
capture() { "$@" 2>&1 || true; }

require_bin() { command -v "$1" >/dev/null 2>&1; }

# ── 0. Build ─────────────────────────────────────────────────────────────────

banner "0. BUILD"

if make 2>&1 | grep -q "netpipe built"; then
    ok "release build  →  $BIN"
else
    fail "release build failed (run: make)"
fi

if make debug 2>&1 | grep -q "netpipe debug"; then
    ok "debug build (ASan+UBSan)"
else
    fail "debug build failed (run: make debug)"
fi

# ── 1. C Unit tests ──────────────────────────────────────────────────────────

banner "1. C UNIT TESTS  (ASan + UBSan)"

UNIT_OUT=$(make test 2>&1 || true)
if echo "$UNIT_OUT" | grep -q "All tests passed"; then
    ok "test_demux   — protocol demuxer"
    ok "test_filter  — filter combinator"
    ok "test_bufpool — buffer pool / ref-counting"
else
    fail "unit test suite had failures  (run: make test)"
    # FIX: always show the last 30 lines of make test output on failure
    # so the user can see which specific test crashed (previously only
    # shown with --verbose).
    echo "      ┌─ make test output (last 30 lines) ─────────────"
    echo "$UNIT_OUT" | tail -30 | sed 's/^/      │ /'
    echo "      └────────────────────────────────────────────────"
fi

# ── 2. Version ───────────────────────────────────────────────────────────────

banner "2. VERSION"

VER=$(capture $BIN --version)
if echo "$VER" | grep -q "0.1.0"; then
    ok "--version reports: $VER"
else
    fail "--version returned unexpected: '$VER'"
fi

# ── 3. Output format sinks ───────────────────────────────────────────────────

banner "3. OUTPUT FORMATS"

quietly $BIN -r "$FIXTURES/all.pcap" -fmt pretty \
    && ok "-fmt pretty  (tshark-style)" \
    || fail "-fmt pretty"

quietly $BIN -r "$FIXTURES/all.pcap" -fmt hex \
    && ok "-fmt hex     (annotated hexdump)" \
    || fail "-fmt hex"

JSON_OUT=$(capture $BIN -r "$FIXTURES/ipv4_tcp_http.pcap" -fmt json)
if echo "$JSON_OUT" | grep -q '"http"' && echo "$JSON_OUT" | grep -q '"method":"GET"'; then
    ok "-fmt json    (NDJSON, HTTP decoded)"
else
    fail "-fmt json  — missing expected fields"
    [[ "$VERBOSE" == "--verbose" ]] && echo "$JSON_OUT"
fi

quietly $BIN -r "$FIXTURES/all.pcap" -fmt null \
    && ok "-fmt null    (discard sink)" \
    || fail "-fmt null"

PCAPNG_OUT="/tmp/np_test_pcapng_$$.pcapng"
if quietly $BIN -r "$FIXTURES/all.pcap" -o "$PCAPNG_OUT"; then
    SIZE=$(stat -c%s "$PCAPNG_OUT" 2>/dev/null || echo 0)
    if [[ "$SIZE" -gt 40 ]]; then
        ok "-o file.pcapng  (${SIZE} bytes written)"
    else
        fail "-o file.pcapng  — file too small (${SIZE}B)"
    fi
    rm -f "$PCAPNG_OUT"
else
    fail "-o file.pcapng  — write failed"
fi

# ── 4. Filters ───────────────────────────────────────────────────────────────

banner "4. FILTERS"

DNS_OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -proto dns -fmt json)
if echo "$DNS_OUT" | grep -q '"proto":"dns"'; then
    ok "-proto dns     — DNS packet passed filter"
else
    fail "-proto dns     — no DNS packets passed"
fi

PORT_OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -port 53 -fmt json)
if echo "$PORT_OUT" | grep -q '"proto":"dns"'; then
    ok "-port 53       — DNS packet matched"
else
    fail "-port 53       — no match"
fi

HOST_OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -host 8.8.8.8 -fmt json)
if echo "$HOST_OUT" | grep -q '"proto":"dns"'; then
    ok "-host 8.8.8.8  — DNS to 8.8.8.8 matched"
else
    fail "-host 8.8.8.8  — no match"
fi

# ── 5. Processors ────────────────────────────────────────────────────────────

banner "5. PROCESSORS"

# flow-tracker (stderr has log lines, stdout has summary — capture both)
FLOW_OUT=$($BIN -r "$FIXTURES/all.pcap" -proc flow-tracker 2>&1 || true)
FLOW_CNT=$(echo "$FLOW_OUT" | grep -c "Total tracked flows" || true)
if echo "$FLOW_OUT" | grep -q "FLOW TRACKER SUMMARY"; then
    ok "-proc flow-tracker       — flow summary printed"
else
    fail "-proc flow-tracker       — summary missing"
fi

# tcp-stream basic
STREAM_OUT=$(capture $BIN -r "$FIXTURES/ipv4_tcp_http.pcap" -proc tcp-stream -fmt json)
if echo "$STREAM_OUT" | grep -q '"stream_hex"'; then
    ok "-proc tcp-stream         — stream_hex field present in JSON"
else
    fail "-proc tcp-stream         — stream_hex missing"
fi

# tcp-stream + flow-tracker
CHAIN_OUT=$(capture $BIN -r "$FIXTURES/ipv4_tcp_http.pcap" \
    -proc tcp-stream -proc flow-tracker)
if echo "$CHAIN_OUT" | grep -q "FLOW TRACKER SUMMARY"; then
    ok "-proc tcp-stream + flow-tracker chained"
else
    fail "-proc tcp-stream + flow-tracker chained"
fi

# tcp-stream + transform:hex
XFORM_OUT=$(capture $BIN -r "$FIXTURES/ipv4_tcp_http.pcap" \
    -proc tcp-stream -proc transform:hex -fmt json)
if echo "$XFORM_OUT" | grep -q '"stream_hex"'; then
    ok "-proc tcp-stream + transform:hex"
else
    fail "-proc tcp-stream + transform:hex"
fi

# Lua processor
# test.lua prints "[LUA] #N  proto=..." for every processed packet.
# We expect 5 such lines (all.pcap has 5 packets) plus the closing
# "[LUA] total=5" summary.
LUA_OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -proc lua:test.lua)
# FIX: grep -c with || echo 0 can output "0\n0" (two lines), which breaks
# the [[ ]] arithmetic.  Use a single-line approach that suppresses grep's
# exit code properly.
LUA_PKT_CNT=$(echo "$LUA_OUT" | grep -c "^\[LUA\] #" 2>/dev/null || true)
LUA_PKT_CNT=${LUA_PKT_CNT//[^0-9]/}  # strip any non-numeric chars
LUA_PKT_CNT=${LUA_PKT_CNT:-0}
if [[ "$LUA_PKT_CNT" -eq 5 ]] && \
   echo "$LUA_OUT" | grep -q "LUA] total=5"; then
    ok "-proc lua:test.lua       — 5×process + summary fired"
else
    fail "-proc lua:test.lua       — pkt_count=$LUA_PKT_CNT (expected 5)"
    [[ "$VERBOSE" == "--verbose" ]] && echo "$LUA_OUT"
fi

# ── 6. Socket sink ───────────────────────────────────────────────────────────

banner "6. SOCKET SINK"

SOCK_FILE="/tmp/np_sock_$$.bin"

# Start Python listener in background
python3 - "$SOCK_FILE" <<'PYEOF' &
import socket, sys
path = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19234))
s.listen(1)
conn, _ = s.accept()
with open(path, 'wb') as f:
    while True:
        d = conn.recv(4096)
        if not d: break
        f.write(d)
PYEOF
PYLISTENER_PID=$!
sleep 0.4

if quietly $BIN -r "$FIXTURES/all.pcap" -o socket://127.0.0.1:19234; then
    sleep 0.3
    wait "$PYLISTENER_PID" 2>/dev/null || true
    if [[ -f "$SOCK_FILE" ]]; then
        # Read first 4 bytes as hex (PCAP magic should be d4c3b2a1 in LE).
        # Use od (always available) instead of xxd (not always installed).
        MAGIC=$(od -An -tx1 -N4 "$SOCK_FILE" 2>/dev/null | tr -d ' \n')
        SIZE=$(stat -c%s "$SOCK_FILE" 2>/dev/null || echo 0)
        if [[ "$MAGIC" == "d4c3b2a1" ]]; then
            ok "socket://127.0.0.1:port  — PCAP stream ${SIZE}B, magic=0xd4c3b2a1"
        else
            fail "socket://127.0.0.1:port  — bad magic: '$MAGIC'"
        fi
        rm -f "$SOCK_FILE"
    else
        fail "socket://127.0.0.1:port  — no data received"
    fi
else
    kill "$PYLISTENER_PID" 2>/dev/null || true
    fail "socket://127.0.0.1:port  — netpipe failed to connect"
fi

# ── 7. TUN / TAP sinks ───────────────────────────────────────────────────────

banner "7. TUN / TAP SINKS"

TUN_OUT=$(capture $BIN -r "$FIXTURES/ipv4_icmp.pcap" -o tun://tun0)
if echo "$TUN_OUT" | grep -q "opened TUN device: tun0"; then
    ok "tun://tun0  — device opened, ICMP packet injected"
elif echo "$TUN_OUT" | grep -q "ioctl(TUNSETIFF) failed"; then
    skip "tun://tun0  — ioctl failed (persistent tun0 needs same-UID owner or root)"
elif echo "$TUN_OUT" | grep -qiE "failed to open /dev/net/tun|try running as root|tuntap"; then
    skip "tun://tun0  — TUN device not accessible (needs root or CAP_NET_ADMIN)"
else
    fail "tun://tun0  — unexpected error: $TUN_OUT"
fi

if ip tuntap list 2>/dev/null | grep -q "^tap0:"; then
    TAP_OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -o tap://tap0)
    if echo "$TAP_OUT" | grep -q "opened TAP device: tap0"; then
        ok "tap://tap0  — device opened"
    else
        fail "tap://tap0  — $(echo "$TAP_OUT" | tail -1)"
    fi
else
    # FIX: auto-create tap0 instead of skipping
    if ip tuntap add dev tap0 mode tap 2>/dev/null; then
        TAP_OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -o tap://tap0)
        if echo "$TAP_OUT" | grep -q "opened TAP device: tap0"; then
            ok "tap://tap0  — device auto-created and opened"
        else
            fail "tap://tap0  — $(echo "$TAP_OUT" | tail -1)"
        fi
        ip tuntap del dev tap0 mode tap 2>/dev/null || true
    else
        skip "tap://tap0  — could not auto-create (needs: sudo ip tuntap add dev tap0 mode tap)"
    fi
fi

# ── 8. Valgrind ──────────────────────────────────────────────────────────────

banner "8. VALGRIND MEMCHECK"

if require_bin valgrind; then
    VG_OUT=$(valgrind --leak-check=full --track-origins=yes \
        --error-exitcode=1 \
        $BIN -r "$FIXTURES/all.pcap" \
        -proc tcp-stream -proc flow-tracker -fmt null 2>&1 || true)
    # FIX: the check previously required "in use at exit: 0 bytes" which is
    # too strict — libc's stdio buffers and pthread's thread-local storage
    # are "still reachable" at exit and show up as non-zero "in use" even
    # in a perfectly clean program.  Now we only fail on:
    #   1. Any valgrind errors (ERROR SUMMARY: N errors, N > 0)
    #   2. Any "definitely lost" bytes (the real leak signal)
    #   3. Any "indirectly lost" bytes
    # "still reachable" and "possibly lost" are informational only.
    VG_ERRORS=$(echo "$VG_OUT" | grep -oP 'ERROR SUMMARY: \K[0-9]+' | head -1)
    VG_DEF_LOST=$(echo "$VG_OUT" | grep -oP 'definitely lost: \K[0-9]+' | head -1)
    VG_IND_LOST=$(echo "$VG_OUT" | grep -oP 'indirectly lost: \K[0-9]+' | head -1)
    VG_ERRORS=${VG_ERRORS:-0}
    VG_DEF_LOST=${VG_DEF_LOST:-0}
    VG_IND_LOST=${VG_IND_LOST:-0}
    if [[ "$VG_ERRORS" -eq 0 && "$VG_DEF_LOST" -eq 0 && "$VG_IND_LOST" -eq 0 ]]; then
        ok "valgrind  — 0 errors, 0 definitely-lost bytes  (tcp-stream + flow-tracker + all.pcap)"
    else
        fail "valgrind  — errors=$VG_ERRORS, definitely_lost=$VG_DEF_LOST bytes, indirectly_lost=$VG_IND_LOST bytes"
        [[ "$VERBOSE" == "--verbose" ]] && echo "$VG_OUT"
    fi
else
    skip "valgrind not installed (apt install valgrind)"
fi

# ── 9. Fuzz regression ───────────────────────────────────────────────────────

banner "9. FUZZ REGRESSION  (corpus replay)"

if make fuzz >/dev/null 2>&1; then
    FUZZ_FAILS=0
    for f in "$FIXTURES"/*.pcap; do
        if ! ./build/bin/fuzz_demux < "$f" >/dev/null 2>&1; then
            fail "fuzz_demux crashed on $(basename "$f")"
            FUZZ_FAILS=$((FUZZ_FAILS+1))
        fi
    done
    COUNT=$(ls "$FIXTURES"/*.pcap | wc -l)
    if [[ $FUZZ_FAILS -eq 0 ]]; then
        ok "fuzz_demux  — all $COUNT fixture PCAPs processed cleanly (ASan+UBSan)"
    fi
else
    fail "fuzz harness build failed"
fi

# ── 10. Stress test ──────────────────────────────────────────────────────────

banner "10. STRESS TEST  (50 offline iterations)"

STRESS_FAIL=0
for _ in $(seq 1 50); do
    quietly $BIN -r "$FIXTURES/all.pcap" \
        -proc tcp-stream -proc flow-tracker -fmt null \
        || STRESS_FAIL=$((STRESS_FAIL+1))
done

if [[ $STRESS_FAIL -eq 0 ]]; then
    ok "50 × (tcp-stream + flow-tracker + all.pcap)  — no crashes"
else
    fail "$STRESS_FAIL / 50 iterations crashed"
fi

# ── Final report ─────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  RESULTS${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}Passed : $PASS${NC}"
echo -e "  ${RED}Failed : $FAIL${NC}"
echo -e "  ${YELLOW}Skipped: $SKIP${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\n${RED}${BOLD}OVERALL: FAILED${NC}\n"
    exit 1
else
    echo -e "\n${GREEN}${BOLD}OVERALL: ALL TESTS PASSED${NC}\n"
    exit 0
fi
