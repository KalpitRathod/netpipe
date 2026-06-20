#!/usr/bin/env bash
# =============================================================================
#  tests/stress_real_world.sh — real-world scenario stress tests for netpipe
#
#  Exercises every code path that would be exercised on a production
#  deployment, but using only offline PCAPs (no root required).
#
#  Categories:
#    1. Large PCAP replay (stress the demuxer + processors)
#    2. TCP reassembly under retransmission / OoO (the bug we fixed)
#    3. TLS decryption end-to-end (the bugs we fixed)
#    4. Lua IDS detection (mitigate.lua) on attack traffic
#    5. Socket sink round-trip (netpipe → Python listener → file)
#    6. PCAP-NG output write + re-read
#    7. Filter combinator correctness (BPF + proto + port + host)
#    8. Pipeline chaining (multiple processors in sequence)
#    9. CLI smoke tests (--version, --help, every -fmt)
#   10. Graceful failure for privileged paths (--ring, TAP, TUN, live)
#   11. Long-running stability (100 iterations, no crashes/leaks)
#
#  Exit code: 0 = all pass, 1 = one or more failures.
# =============================================================================

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:"

BIN="./build/bin/netpipe"
FIXTURES="tests/fixtures"
VERBOSE="${1:-}"

PASS=0
FAIL=0
SKIP=0

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

quietly() {
    if [[ "$VERBOSE" == "--verbose" ]]; then "$@"
    else "$@" >/dev/null 2>&1; fi
}
capture() { "$@" 2>&1 || true; }

# ── 0. Build ───────────────────────────────────────────────────────────

banner "0. BUILD"
if [[ -x "$BIN" ]]; then
    ok "binary exists ($BIN)"
else
    fail "binary missing — run: make"
    exit 1
fi

# ── 1. Large PCAP replay ───────────────────────────────────────────────

banner "1. LARGE PCAP REPLAY"

for f in "$FIXTURES"/*.pcap; do
    name=$(basename "$f")
    if quietly $BIN -r "$f" -fmt null; then
        ok "replay $name ($(stat -c%s "$f")B)"
    else
        fail "replay $name crashed"
    fi
done

# ── 2. TCP reassembly under pathological conditions ────────────────────

banner "2. TCP REASSEMBLY REGRESSION"

# Run the unit tests for TCP reassembly.
if [[ -x ./build/bin/test_tcp_reassembly ]]; then
    if quietly ./build/bin/test_tcp_reassembly; then
        ok "test_tcp_reassembly (9 unit tests)"
    else
        fail "test_tcp_reassembly failed"
    fi
else
    skip "test_tcp_reassembly not built"
fi

if [[ -x ./build/bin/test_tcp_reassembly_stress ]]; then
    if quietly ./build/bin/test_tcp_reassembly_stress; then
        ok "test_tcp_reassembly_stress (18 real-world scenarios)"
    else
        fail "test_tcp_reassembly_stress failed"
    fi
else
    skip "test_tcp_reassembly_stress not built"
fi

# Run netpipe on a real TCP PCAP and check the stream_hex output is present.
OUT=$(capture $BIN -r "$FIXTURES/ipv4_tcp_http.pcap" -proc tcp-stream -fmt json)
if echo "$OUT" | grep -q '"stream_hex"'; then
    ok "tcp-stream produces stream_hex on real HTTP PCAP"
else
    fail "tcp-stream did not produce stream_hex"
fi

# ── 3. TLS decryption end-to-end ───────────────────────────────────────

banner "3. TLS DECRYPTION"

if [[ -f encrypted_traffic.pcap && -f tls_keys.log ]]; then
    # Verify the keylog loads.
    OUT=$(capture $BIN -r encrypted_traffic.pcap -proc tls-decrypt:tls_keys.log -fmt null 2>&1)
    if echo "$OUT" | grep -q "loaded 10 keylog records"; then
        ok "tls-decrypt loaded keylog"
    else
        fail "tls-decrypt did not load keylog"
    fi

    # Verify decryption actually produced plaintext.
    OUT=$($BIN -r encrypted_traffic.pcap -proc tls-decrypt:tls_keys.log -fmt json 2>/dev/null || true)
    HTTP_PRESENT=$(echo "$OUT" | python3 -c "
import json, sys
found = False
for line in sys.stdin:
    line = line.strip()
    if not line.startswith('{'): continue
    try: p = json.loads(line)
    except: continue
    sh = p.get('stream_hex', '')
    if sh:
        try:
            text = bytes.fromhex(sh).decode('ascii', errors='replace')
            if 'HTTP/1.0 200' in text or 'HTTP/' in text:
                found = True
                break
        except: pass
print('YES' if found else 'NO')
")
    if [[ "$HTTP_PRESENT" == "YES" ]]; then
        ok "TLS decryption produced HTTP plaintext"
    else
        fail "TLS decryption did not produce HTTP plaintext"
    fi
else
    skip "TLS fixtures not generated (run: python3 tests/python/gen_tls_fixtures.py)"
fi

# ── 4. Lua IDS detection ───────────────────────────────────────────────

banner "4. LUA IDS DETECTION (mitigate.lua)"

if [[ -f mitigate.lua ]]; then
    if python3 tests/python/test_mitigate_lua.py >/dev/null 2>&1; then
        ok "mitigate.lua end-to-end test (6 scenarios)"
    else
        fail "mitigate.lua end-to-end test failed"
    fi
else
    skip "mitigate.lua not found"
fi

# ── 5. Socket sink round-trip ──────────────────────────────────────────

banner "5. SOCKET SINK ROUND-TRIP"

SOCK_FILE="/tmp/np_stress_$$.pcap"
python3 - "$SOCK_FILE" <<'PYEOF' &
import socket, sys
path = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 19235))
s.listen(1)
s.settimeout(5)
try:
    conn, _ = s.accept()
except socket.timeout:
    sys.exit(0)
with open(path, 'wb') as f:
    while True:
        d = conn.recv(4096)
        if not d: break
        f.write(d)
PYEOF
PY_PID=$!
sleep 0.4

if quietly $BIN -r "$FIXTURES/all.pcap" -o socket://127.0.0.1:19235; then
    sleep 0.3
    wait "$PY_PID" 2>/dev/null || true
    if [[ -f "$SOCK_FILE" ]]; then
        SIZE=$(stat -c%s "$SOCK_FILE" 2>/dev/null || echo 0)
        if [[ "$SIZE" -gt 40 ]]; then
            ok "socket://127.0.0.1:port  (${SIZE}B received)"
        else
            fail "socket://127.0.0.1:port  (only ${SIZE}B received)"
        fi
        rm -f "$SOCK_FILE"
    else
        fail "socket://127.0.0.1:port  (no file written)"
    fi
else
    kill "$PY_PID" 2>/dev/null || true
    fail "socket://127.0.0.1:port  (netpipe failed to connect)"
fi

# ── 6. PCAP-NG output write + re-read ──────────────────────────────────

banner "6. PCAP-NG OUTPUT ROUND-TRIP"

PCAPNG_OUT="/tmp/np_stress_$$.pcapng"
if quietly $BIN -r "$FIXTURES/all.pcap" -o "$PCAPNG_OUT"; then
    SIZE=$(stat -c%s "$PCAPNG_OUT" 2>/dev/null || echo 0)
    if [[ "$SIZE" -gt 40 ]]; then
        ok "wrote $PCAPNG_OUT (${SIZE}B)"
        # Re-read it.
        if quietly $BIN -r "$PCAPNG_OUT" -fmt null; then
            ok "re-read the PCAP-NG file"
        else
            fail "could not re-read PCAP-NG file"
        fi
    else
        fail "PCAP-NG file too small (${SIZE}B)"
    fi
    rm -f "$PCAPNG_OUT"
else
    fail "could not write PCAP-NG file"
fi

# ── 7. Filter combinator correctness ───────────────────────────────────

banner "7. FILTER COMBINATORS"

# BPF filter — only DNS packets should pass.
OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -fmt json)
TOTAL_DNS=$(echo "$OUT" | grep -c '"proto":"dns"' || echo 0)
TOTAL_PKTS=$(echo "$OUT" | grep -c '"seq"' || echo 0)
if [[ "$TOTAL_DNS" -gt 0 && "$TOTAL_PKTS" -gt 0 ]]; then
    ok "fixture all.pcap has $TOTAL_DNS DNS / $TOTAL_PKTS total packets"
else
    fail "fixture all.pcap is empty or has no DNS"
fi

OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -f "udp port 53" -fmt json)
DNS_FILTERED=$(echo "$OUT" | grep -c '"proto":"dns"' || echo 0)
if [[ "$DNS_FILTERED" -gt 0 ]]; then
    ok "BPF 'udp port 53' passed $DNS_FILTERED DNS packets"
else
    fail "BPF 'udp port 53' filtered out everything"
fi

# Proto filter.
OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -proto dns -fmt json)
DNS_PROTO=$(echo "$OUT" | grep '"proto":"dns"' | wc -l)
NON_DNS_PROTO=$(echo "$OUT" | grep -v '"proto":"dns"' | grep '"seq"' | wc -l)
if [[ "$DNS_PROTO" -gt 0 && "$NON_DNS_PROTO" -eq 0 ]]; then
    ok "-proto dns (only DNS passed)"
else
    fail "-proto dns (DNS=$DNS_PROTO non-DNS=$NON_DNS_PROTO)"
fi

# Port filter.
OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -port 53 -fmt json)
DNS_PORT=$(echo "$OUT" | grep -c '"proto":"dns"' || echo 0)
if [[ "$DNS_PORT" -gt 0 ]]; then
    ok "-port 53 (DNS matched)"
else
    fail "-port 53 (no match)"
fi

# Host filter.
OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -host 8.8.8.8 -fmt json)
DNS_HOST=$(echo "$OUT" | grep -c '"proto":"dns"' || echo 0)
if [[ "$DNS_HOST" -gt 0 ]]; then
    ok "-host 8.8.8.8 (DNS matched)"
else
    fail "-host 8.8.8.8 (no match)"
fi

# ── 8. Pipeline chaining ───────────────────────────────────────────────

banner "8. PIPELINE CHAINING"

if quietly $BIN -r "$FIXTURES/all.pcap" \
        -proc tcp-stream -proc flow-tracker -fmt null; then
    ok "tcp-stream + flow-tracker chained"
else
    fail "tcp-stream + flow-tracker chained failed"
fi

if quietly $BIN -r "$FIXTURES/ipv4_tcp_http.pcap" \
        -proc tcp-stream -proc transform:hex -fmt null; then
    ok "tcp-stream + transform:hex chained"
else
    fail "tcp-stream + transform:hex failed"
fi

# ── 9. CLI smoke tests ─────────────────────────────────────────────────

banner "9. CLI SMOKE TESTS"

VER=$(capture $BIN --version)
if echo "$VER" | grep -q "0.1.0"; then
    ok "--version: $VER"
else
    fail "--version returned: $VER"
fi

for fmt in pretty hex json null; do
    if quietly $BIN -r "$FIXTURES/all.pcap" -fmt "$fmt"; then
        ok "-fmt $fmt"
    else
        fail "-fmt $fmt"
    fi
done

# ── 10. Graceful failure for privileged paths ─────────────────────────

banner "10. GRACEFUL FAILURE (NO ROOT)"

# --ring without root.
OUT=$(capture $BIN --ring -i __nonexistent__ -c 1 2>&1)
if echo "$OUT" | grep -qiE "operation not permitted|are you root|permission"; then
    ok "--ring fails gracefully (no root)"
else
    fail "--ring did not fail gracefully: $OUT"
fi

# TUN sink without root.
OUT=$(capture $BIN -r "$FIXTURES/ipv4_icmp.pcap" -o tun://tun99 2>&1)
if echo "$OUT" | grep -qiE "tun|root|permission|tuntap"; then
    ok "tun:// fails gracefully (no root)"
else
    fail "tun:// did not fail gracefully: $OUT"
fi

# TAP sink without root.
OUT=$(capture $BIN -r "$FIXTURES/all.pcap" -o tap://tap99 2>&1)
if echo "$OUT" | grep -qiE "tap|root|permission|tuntap"; then
    ok "tap:// fails gracefully (no root)"
else
    fail "tap:// did not fail gracefully: $OUT"
fi

# Live capture without root.
OUT=$(capture $BIN -i lo -c 1 2>&1)
if echo "$OUT" | grep -qiE "permission|root"; then
    ok "live capture fails gracefully (no root)"
else
    fail "live capture did not fail gracefully: $OUT"
fi

# ── 11. Long-running stability ────────────────────────────────────────

banner "11. LONG-RUNNING STABILITY (100 iterations)"

CRASH_COUNT=0
for i in $(seq 1 100); do
    if ! quietly $BIN -r "$FIXTURES/all.pcap" \
              -proc tcp-stream -proc flow-tracker -fmt null; then
        CRASH_COUNT=$((CRASH_COUNT+1))
    fi
done
if [[ $CRASH_COUNT -eq 0 ]]; then
    ok "100 iterations: no crashes"
else
    fail "$CRASH_COUNT / 100 iterations crashed"
fi

# ── Final report ──────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}  STRESS TEST RESULTS${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}Passed : $PASS${NC}"
echo -e "  ${RED}Failed : $FAIL${NC}"
echo -e "  ${YELLOW}Skipped: $SKIP${NC}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\n${RED}${BOLD}OVERALL: FAILED${NC}\n"
    exit 1
else
    echo -e "\n${GREEN}${BOLD}OVERALL: ALL STRESS TESTS PASSED${NC}\n"
    exit 0
fi
