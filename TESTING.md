# netpipe — Testing & Validation Guide

This document describes the test infrastructure for netpipe 0.1.0 and
how to run every test suite.

## Quick start

```bash
# Run the entire test matrix (takes ~60 seconds).
cd /path/to/netpipe-0.1.0
make test                                       # 49 C unit tests
python3 examples/python/test_all_examples.py    # 65 Python example tests
python3 scripts/test_mitigate_lua.py            # 6 Lua IDS end-to-end tests
bash tests/stress_real_world.sh                 # 34 real-world stress tests
bash tests/run_all.sh                           # ~30 CI integration tests
```

Expected result: **~184 tests passing, 0 failures.**

---

## Test suites at a glance

| Suite | Tests | What it covers | Run with |
|-------|-------|----------------|----------|
| `test_demux` | 5 | Protocol demuxer (ARP, HTTP, DNS, TLS, ICMP, malformed) | `make test` |
| `test_filter` | 5 | BPF / proto / port / host filter combinators | `make test` |
| `test_bufpool` | 5 | Buffer pool / ref-counting | `make test` |
| `test_tcp_reassembly` | 9 | TCP reassembly unit tests | `make test` |
| `test_tcp_reassembly_stress` | 18 | TCP reassembly real-world stress tests | `make test` |
| `test_tls_keylog` | 7 | NSS SSLKEYLOGFILE parser | `make test` |
| `test_all_examples.py` | 65 | All 27 Python examples compile + run | `python3 examples/python/test_all_examples.py` |
| `test_mitigate_lua.py` | 6 | Lua IDS detection on synthetic attack PCAPs | `python3 scripts/test_mitigate_lua.py` |
| `stress_real_world.sh` | 34 | Real-world pipeline scenarios | `bash tests/stress_real_world.sh` |
| `run_all.sh` | ~30 | Original CI integration suite | `bash tests/run_all.sh` |

All test binaries build under ASan + UBSan.  Memory leaks are treated
as failures.

---

## C unit tests

The C unit tests live in `tests/test_*.c` and are built by `make test`.
Each test binary is self-contained and exits 0 on success, 1 on failure.

```bash
make test
# Equivalent to:
make debug
make build/bin/test_demux build/bin/test_filter build/bin/test_bufpool \
     build/bin/test_tcp_reassembly build/bin/test_tcp_reassembly_stress \
     build/bin/test_tls_keylog
./build/bin/test_demux
./build/bin/test_filter
./build/bin/test_bufpool
./build/bin/test_tcp_reassembly
./build/bin/test_tcp_reassembly_stress
./build/bin/test_tls_keylog
```

### TCP reassembly stress tests

`tests/test_tcp_reassembly_stress.c` exercises 18 real-world scenarios
that model pathological traffic observed on production links:

1.  Large out-of-order burst (8 segments, fully reversed order)
2.  Interleaved retransmissions across a 16-segment stream
3.  32-bit sequence-number wrap-around
4.  IPv6 TCP reassembly
5.  Mid-stream capture (no SYN — anchor on first segment)
6.  Many concurrent flows (64 flows — bucket-collision stress)
7.  Duplicate SYN re-initialises the direction
8.  FIN followed by late retransmitted data (must be dropped)
9.  RST followed by late retransmission (must be dropped)
10. Large 8 KiB single segment
11. Overlapping segments with conflicting payloads
12. Bidirectional simultaneous close (FIN/FIN)
13. Connection migration: 4-tuple reuse after close
14. Stats classification (in-order vs OoO vs retransmit)
15. 10× repeated retransmission of the same segment
16. Real gap flush (sleep > 1s, verify forward progress)
17. Per-flow stream buffer capped at 1 MiB
18. Window probe (1-byte data after quiet period)

These tests run under AddressSanitizer + UBSan and verify:

- No buffer overflows / underflows
- No use-after-free
- No memory leaks
- No undefined behaviour (misaligned loads, signed overflow, etc.)
- Correct reassembled byte stream

---

## Python examples test runner

`examples/python/test_all_examples.py` validates every Python example
script in `examples/python/`.  For each script it:

1. **Compile-checks** the script with `py_compile` (catches syntax
   errors).
2. **Runs `--help`** (catches import errors and missing dependencies).
3. **Runs against a real PCAP fixture** where applicable (verifies
   the script can actually process packets).

Scripts that require root or a live interface are smoke-tested with
`--help` only.

```bash
python3 examples/python/test_all_examples.py
```

Expected output: `Passed: 65 / Failed: 0`.

---

## Lua IDS end-to-end test

`scripts/test_mitigate_lua.py` generates synthetic DNS PCAPs that
exercise every detection rule in `mitigate.lua`, then verifies that
netpipe emits the correct `[!!!] LUA SECURITY ALERT` lines AND drops
the offending packets from the pipeline.

Detection rules exercised:

| Rule | Trigger | Expected alert |
|------|---------|----------------|
| `dns_normal` | Clean qname < 50 chars | (no alert) |
| `long_dns_name` | qname ≥ 50 chars | `long_dns_name` |
| `exfil_keyword` | qname matches `exfil[%-_]payload` | `exfil_keyword` |
| `EXFIL_PAYLOAD` | long + exfil pattern + dst=8.8.8.8 | `EXFIL_PAYLOAD` |
| `dns_tunnel_suspect` | 30+ char base32-style single label | `dns_tunnel_suspect` |

```bash
python3 scripts/test_mitigate_lua.py
```

Expected output: `6/6 passed, 0 failed`.

---

## Real-world stress test

`tests/stress_real_world.sh` is the most comprehensive test suite.  It
runs netpipe through 11 categories of real-world scenarios using only
offline PCAPs (no root required):

1.  **Large PCAP replay** — every fixture in `tests/fixtures/`
2.  **TCP reassembly under retransmission / OoO** — runs the C unit +
    stress test binaries, plus a real-PCAP smoke test
3.  **TLS decryption end-to-end** — loads `tls_keys.log`, decrypts
    `encrypted_traffic.pcap`, verifies HTTP plaintext is recovered
4.  **Lua IDS detection** — runs `test_mitigate_lua.py`
5.  **Socket sink round-trip** — netpipe → Python listener → file
6.  **PCAP-NG output** — write + re-read
7.  **Filter combinator correctness** — BPF, proto, port, host
8.  **Pipeline chaining** — multiple processors in sequence
9.  **CLI smoke tests** — `--version`, `--help`, every `-fmt`
10. **Graceful failure** — `--ring`, TUN, TAP, live capture without
    root all return clear error messages
11. **Long-running stability** — 100 iterations, no crashes

```bash
bash tests/stress_real_world.sh
```

Expected output: `Passed: 34 / Failed: 0`.

---

## Generating TLS test fixtures

The TLS decryption tests rely on two fixture files that are NOT in
the source tree by default:

- `tls_keys.log` — an NSS SSLKEYLOGFILE with real TLS 1.2 + 1.3 secrets
- `encrypted_traffic.pcap` — captured TLS traffic that matches the keys

These are generated by `scripts/gen_tls_fixtures.py`, which runs
OpenSSL `s_server` and `s_client` through a Python TCP proxy to
capture the wire bytes:

```bash
python3 scripts/gen_tls_fixtures.py
```

This produces:

```
tls_keys.log             2277 bytes (10 keylog records)
encrypted_traffic.pcap  17176 bytes (13 frames: 6 TLS 1.2 + 7 TLS 1.3)
```

To verify the fixtures are valid (independent of netpipe):

```bash
python3 scripts/verify_tls_fixtures.py
```

This uses the `cryptography` Python library as a reference
implementation.  It should successfully decrypt the TLS 1.3 traffic
and print the recovered HTTP plaintext.

---

## Running under valgrind

`tests/run_all.sh` includes a valgrind memcheck step.  To run it
manually:

```bash
valgrind --leak-check=full --track-origins=yes --error-exitcode=1 \
    ./build/bin/netpipe -r tests/fixtures/all.pcap \
    -proc tcp-stream -proc flow-tracker -fmt null
```

Expected: `ERROR SUMMARY: 0 errors` and `in use at exit: 0 bytes`.

---

## Fuzz testing

netpipe includes a fuzz harness (`tests/fuzz_demux.c`) that feeds
arbitrary bytes into the protocol demuxer.  Two modes are supported:

```bash
# AFL++ (preferred for long runs):
CC=afl-clang-fast make fuzz
afl-fuzz -i tests/fixtures/ -o fuzz-out/ -- ./build/bin/fuzz_demux

# Standalone stdin / CI regression (no fuzzer required):
make fuzz
./build/bin/fuzz_demux < tests/fixtures/ipv4_tcp_http.pcap

# libFuzzer (clang only):
make fuzz-libfuzzer
./build/bin/fuzz_demux_libfuzzer tests/fixtures/
```

---

## CI integration

For CI (GitHub Actions, GitLab CI, etc.), the recommended matrix is:

```yaml
matrix:
  - compiler: gcc
    flags: -O2 -DNDEBUG
  - compiler: clang
    flags: -O0 -g3 -fsanitize=address,undefined

steps:
  - make release
  - make test
  - python3 examples/python/test_all_examples.py
  - python3 scripts/test_mitigate_lua.py
  - bash tests/stress_real_world.sh
```

All four steps must exit 0.
