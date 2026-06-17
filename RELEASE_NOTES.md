# netpipe 0.1.0 — Release Notes

**Release date:** June 17, 2026

This is the first production release of netpipe.  It introduces three
major new subsystems, comprehensive regression + stress + end-to-end
test suites, and pre-built binary packages for Debian-based Linux
distributions.

---

## What's new

### 1. Production TCP Reassembly

The TCP stream reassembler was rewritten from scratch to match the
behaviour of Wireshark's `tcp_stream.c` and Zeek's
`TCP_Reassembler.cc`.  The new implementation in
`src/processor/np_tcp_stream.c` provides:

- **Per-direction reassembly contexts** keyed on the 4-tuple
  (src_ip, dst_ip, src_port, dst_port).
- **Sorted segment queue** with overlap clipping for retransmissions.
- **Hole-timeout flushing** — gaps that persist longer than 1 s are
  synthesised and reassembly continues, guaranteeing forward progress
  on lossy links.
- **SYN / FIN / RST state machine** with a 10-second CLOSED-flow
  linger for matching late retransmissions.
- **Re-SYN handling** — a new SYN on an existing 4-tuple (connection
  reuse after TIME_WAIT) correctly resets the stream buffer and
  segment queue, so the new connection does NOT inherit stale data
  from the old one.
- **RFC 793 sequence arithmetic** (signed 32-bit subtraction) correct
  across the 2³² wrap-around.
- **UBSan-clean alignment** via `memcpy()` into typed locals.

**Test coverage:**

- 9 unit tests (`tests/test_tcp_reassembly.c`)
- 18 real-world stress tests (`tests/test_tcp_reassembly_stress.c`):
  large OoO bursts, interleaved retransmissions, 32-bit sequence
  wrap-around, IPv6 reassembly, mid-stream capture, 64 concurrent
  flows, duplicate SYN, FIN+retx, RST+retx, 8 KiB segment,
  conflicting overlaps, bidirectional simultaneous close, connection
  migration, stats classification, 10× repeated retx, real gap flush,
  1 MiB memory cap, window probe.

All 27 tests pass under UBSan + ASan with no leaks.

```text
=== TCP reassembly regression tests ===
  [test] in-order delivery ... PASS
  [test] out-of-order arrival ... PASS
  [test] pure retransmission ... PASS
  [test] partial overlap retransmission ... PASS
  [test] gap with late fill (within hole timeout) ... PASS
  [test] bidirectional independence ... PASS
  [test] RST closes the flow ... PASS
  [test] stats visitor counts flows and segments ... PASS
  [test] hole-timeout flush code path (does not crash) ... PASS
9/9 tests passed

=== TCP reassembly STRESS / real-world tests ===
  [stress] large out-of-order burst (8 segments, fully reversed) ... PASS
  [stress] interleaved retransmissions across 16-segment stream ... PASS
  [stress] 32-bit sequence number wrap-around ... PASS
  [stress] IPv6 TCP reassembly (out-of-order) ... PASS
  [stress] mid-stream capture (no SYN, anchor on first segment) ... PASS
  [stress] many concurrent flows (bucket-collision stress) ... PASS
  [stress] duplicate SYN re-initialises the direction ... PASS
  [stress] FIN followed by late retransmitted data (must be dropped) ... PASS
  [stress] RST followed by late retransmission (must be dropped) ... PASS
  [stress] large segment (8 KiB payload, single segment) ... PASS
  [stress] overlapping segments with conflicting payloads ... PASS
  [stress] bidirectional simultaneous close (FIN/FIN) ... PASS
  [stress] connection migration: 4-tuple reuse after close ... PASS
  [stress] stats distinguish in-order vs out-of-order vs retransmit ... PASS
  [stress] 10x repeated retransmission of the same segment ... PASS
  [stress] gap flush path (sleep > 1s, verify forward progress) ... PASS
  [stress] per-flow stream buffer is capped at 1 MiB ... PASS
  [stress] window probe (1-byte data after quiet period) ... PASS
18/18 stress tests passed (0 failed)
```

### 2. TLS Session Decryption

The new `np_processor_tls_decrypt()` processor in
`src/processor/np_tls_decrypt.c` loads an NSS key-log file
(`SSLKEYLOGFILE` format) and decrypts TLS 1.3 traffic inline as it
passes through the pipeline.

**Supported cipher suites:**

- TLS 1.3: `TLS_AES_128_GCM_SHA256` (SHA-256 HKDF),
  `TLS_AES_256_GCM_SHA384` (SHA-384 HKDF),
  `TLS_CHACHA20_POLY1305_SHA256` (SHA-256 HKDF)
- TLS 1.2 (GCM/ChaCha20 only): all common ECDHE_RSA, ECDHE_ECDSA,
  and RSA variants (keylog format only — TLS 1.2 PRF not yet
  implemented)

**Supported key-log record types:**

- `CLIENT_RANDOM` (TLS 1.2 master secret)
- `CLIENT_HANDSHAKE_TRAFFIC_SECRET` (TLS 1.3 client handshake — used
  to decrypt the client's Finished message)
- `SERVER_HANDSHAKE_TRAFFIC_SECRET` (TLS 1.3 server handshake — used
  to decrypt EncryptedExtensions, Certificate, CertificateVerify,
  Finished)
- `CLIENT_TRAFFIC_SECRET_0` (TLS 1.3 client application)
- `SERVER_TRAFFIC_SECRET_0` (TLS 1.3 server application)

The HKDF-Expand-Label primitive (RFC 8446 §7.1) is implemented using
OpenSSL's HMAC primitive, with the hash function selected per cipher
suite (SHA-256 or SHA-384).  AEAD decryption uses
`EVP_DecryptInit_ex` with the appropriate cipher context.  Auth-tag
verification is enforced.

**Bugs fixed during 0.1.0 release validation:**

1. **Direction-agnostic flow key** — the original implementation used
   the demuxer's directional `pkt->flow_id`, which put the
   ClientHello (c→s) and ServerHello (s→c) in different flow entries
   and prevented key association.  Fixed by computing a canonical
   flow key that sorts the two endpoints before hashing.
2. **HKDF-Expand counter byte** — the single-block shortcut forgot
   the trailing 0x01 counter byte required by RFC 5869, silently
   producing wrong keys.
3. **Per-cipher HKDF hash** — the code hardcoded SHA-256, but
   `TLS_AES_256_GCM_SHA384` (0x1302) requires SHA-384.
4. **AEAD context initialisation** — `aead_key_setup()` created the
   EVP_CIPHER_CTX but never initialised the cipher, key, or IV
   length, causing `EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, nonce)`
   to fail silently in `aead_decrypt()`.
5. **Multi-record packet walk** — the original implementation only
   processed the FIRST TLS record in each packet, missing the
   server's first flight (ServerHello + several encrypted handshake
   records all in one TCP segment).
6. **Handshake traffic key support** — TLS 1.3 uses the handshake
   traffic secret to encrypt EncryptedExtensions through Finished,
   not the application traffic secret.  Added `c_hs_key` / `s_hs_key`
   to the flow struct and try both keys (handshake first, then app)
   when decrypting APPLICATION_DATA records.

**End-to-end validation:**

The repository includes `tls_keys.log` + `encrypted_traffic.pcap`
generated by `scripts/gen_tls_fixtures.py` (OpenSSL s_server/s_client
through a Python TCP proxy).  The HTTP plaintext
(`"HTTP/1.0 200 ok\r\nContent-type: text/html..."`) is correctly
recovered from the encrypted TLS 1.3 traffic.

```bash
$ netpipe -r encrypted_traffic.pcap -proc tls-decrypt:tls_keys.log -fmt json | \
    python3 -c "import json,sys; [print(bytes.fromhex(p['stream_hex']).decode('ascii','replace')[:60]) for p in (json.loads(l) for l in sys.stdin if l.startswith('{')) if p.get('stream_hex')]"
EncryptedExtensions + Certificate + ...
NewSessionTicket (233B)
NewSessionTicket (233B)
HTTP/1.0 200 ok
Content-type: text/html
```

Seven unit tests verify the key-log parser.  All pass under UBSan +
ASan.

### 3. Protocol Expansion

The new `np_demux_decode_app_extra()` hook in
`src/demux/np_proto_extra.c` adds lightweight decoders for five
additional protocols:

| Protocol | Wire signature | Constant |
|----------|----------------|----------|
| QUIC (RFC 9000) | UDP/443, long header with known IETF version | `NP_PROTO_QUIC` |
| DHCPv4 (RFC 2131) | UDP/67-68, magic cookie 0x63825363 | `NP_PROTO_DHCP` |
| SIP (RFC 3261) | TCP/UDP 5060, starts with method or `SIP/2.0` | `NP_PROTO_SIP` |
| MQTT (RFC 3.1.1) | TCP/1883, valid MQTT fixed header | `NP_PROTO_MQTT` |
| VXLAN (RFC 7348) | UDP/4789, I-flag (bit 3) set | `NP_PROTO_VXLAN` |

Use the new `-proto <name>` filter values to select these protocols:

```bash
netpipe -r capture.pcap -proto quic -fmt pretty
netpipe -r capture.pcap -proto dhcp -fmt json
```

### 4. Production-ready Lua IDS scenario

The `mitigate.lua` script in the repository root is a complete,
deployable DNS-based intrusion-prevention processor.  It detects:

- **Long DNS qnames** (≥ 50 chars) — typical of DNS-tunnel exfil.
- **`exfil-payload` keyword** in qname — explicit exfil pattern.
- **EXFIL_PAYLOAD** combination (long + exfil + dst=8.8.8.8) — the
  highest-severity alert.
- **DNS tunnel suspect** — single label ≥ 30 chars of base32-style
  characters (no vowels), matching the Iodine / dns2tcp default
  alphabet.

Returning `false` from the Lua `process(pkt)` function drops the
packet from the pipeline (it does NOT reach downstream sinks), giving
true inline-mitigation behaviour.

**Bug fixed during 0.1.0 validation:** the original
`TUNNEL_PATTERN = "[a-z0-9]{30,}"` used regex `{n,m}` syntax that
Lua patterns don't support.  Replaced with a function-based
`looks_like_base32_tunnel(label)` check.

Six end-to-end tests in `scripts/test_mitigate_lua.py` verify each
detection rule on synthetic attack PCAPs and confirm drop semantics.

### 5. Pre-built Debian package and source tarball

The Makefile now has `deb`, `tarball`, and `package` targets:

```bash
make package    # builds both netpipe_0.1.0_amd64.deb and netpipe-0.1.0.tar.gz
```

The `.deb` ships:

- `/usr/bin/netpipe` — the CLI tool
- `/usr/lib/libnetpipe.a` — the static library for embedding
- `/usr/include/netpipe.h` — the public C API
- `/usr/share/man/man{1,3,7}/` — manpages
- `/usr/share/netpipe/lua/{mitigate.lua,test.lua}` — bundled Lua scripts
- `/usr/share/doc/netpipe/{README.md,LICENSE,RELEASE_NOTES.md}` — docs

Install with `sudo dpkg -i netpipe_0.1.0_amd64.deb`.

---

## Build & Installation

### From source

```bash
make            # release build
make debug      # ASan + UBSan
make test       # run regression tests (5 test binaries, 49 unit tests)
make package    # build .deb + .tar.gz
sudo make install PREFIX=/usr/local
```

**Build dependencies:**

- C11 compiler (gcc 11+, clang 14+)
- libpcap-dev (1.10+)
- libssl-dev (OpenSSL 1.1.1+ or 3.x)
- Lua 5.4 (vendored in `lua-5.4.7/`)

If libpcap is installed in a non-standard prefix, pass
`LOCAL_PREFIX=/path/to/local` to make.

### From binary packages

Pre-built packages are available in this release:

- `netpipe_0.1.0_amd64.deb` — Debian/Ubuntu package
- `netpipe-0.1.0.tar.gz` — Source tarball

```bash
# Debian/Ubuntu
sudo dpkg -i netpipe_0.1.0_amd64.deb
netpipe --version

# Source tarball
tar -xzf netpipe-0.1.0.tar.gz
cd netpipe-0.1.0
make
sudo make install
```

---

## Test infrastructure

The 0.1.0 release ships with five complementary test suites:

| Suite | File | Tests | Run with |
|-------|------|-------|----------|
| C unit tests | `tests/test_{demux,filter,bufpool}.c` | 5+5+5 | `make test` |
| TCP reassembly regression | `tests/test_tcp_reassembly.c` | 9 | `make test` |
| TCP reassembly stress | `tests/test_tcp_reassembly_stress.c` | 18 | `make test` |
| TLS keylog parser | `tests/test_tls_keylog.c` | 7 | `make test` |
| Python examples runner | `examples/python/test_all_examples.py` | 65 | `python3 examples/python/test_all_examples.py` |
| Lua IDS end-to-end | `scripts/test_mitigate_lua.py` | 6 | `python3 scripts/test_mitigate_lua.py` |
| Real-world stress | `tests/stress_real_world.sh` | 34 | `bash tests/stress_real_world.sh` |
| Existing CI suite | `tests/run_all.sh` | ~30 | `bash tests/run_all.sh` |

**Total: ~170 tests passing.**

The `stress_real_world.sh` suite covers:

1. Large PCAP replay (every fixture)
2. TCP reassembly under retransmission / OoO
3. TLS decryption end-to-end (HTTP plaintext recovery)
4. Lua IDS detection on synthetic attack traffic
5. Socket sink round-trip (netpipe → Python listener → file)
6. PCAP-NG output write + re-read
7. Filter combinator correctness (BPF + proto + port + host)
8. Pipeline chaining (multiple processors in sequence)
9. CLI smoke tests (--version, --help, every -fmt)
10. Graceful failure for privileged paths (--ring, TAP, TUN, live)
11. Long-running stability (100 iterations, no crashes/leaks)

---

## Known limitations

- **TLS 1.2 CBC cipher suites** are not decrypted (GCM and
  ChaCha20-Poly1305 cover >95% of modern TLS traffic).
- **TLS 1.2 GCM decryption is now fully implemented** — server_random
  tracking, TLS 1.2 PRF (RFC 5246 §5), key_block derivation (§6.3),
  and AEAD decryption (RFC 5288 §3) all work end-to-end.  Both TLS
  1.2 and TLS 1.3 decryption are verified on real captured traffic.
- **TLS 1.3 0-RTT early data** is not decrypted.
- **TLS 1.3 key updates** are not yet supported.
- **AF_PACKET ring capture** (`--ring`) and **TUN/TAP injection**
  require `CAP_NET_RAW` / `CAP_NET_ADMIN`.  All paths fail gracefully
  with clear error messages (including `NP_ERR_PERM` for EPERM) when
  run without privileges.

---

## Future work

The following were identified as the highest-impact next steps:

1. **TLS 1.2 CBC suite support** — derive key material via the TLS 1.2
   PRF and implement CBC + HMAC decryption (requires per-record MAC
   verification, not AEAD).
2. **TLS 1.3 key updates** — handle `KeyUpdate` handshake messages
   per RFC 8446 §4.6.3.
3. **QUIC deeper dissection** — parse the QUIC long header to
   extract connection IDs and packet number lengths, enabling
   per-flow QUIC tracking.
4. **VXLAN inner-frame unwrapping** — re-enter the demuxer with the
   inner Ethernet frame to expose the encapsulated traffic.
5. **DPDK / XDP integration** — bypass the Linux kernel for
   10+ Gbps capture rates.
6. **Run the stress suite on a real Debian machine with root** to
   validate `--ring`, TAP, and TUN paths that we could only
   smoke-test for graceful failure here.
7. **Socket sink auto-reconnect** — add exponential-backoff reconnect
   and a small ring buffer for the socket sink (Bug 4.2 from audit).

---

## Contributors

- netpipe contributors <dev@netpipe.io>

## License

MIT — see `LICENSE` for details.
