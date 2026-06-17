/*
 * fuzz_demux.c — fuzzing harness for the netpipe protocol demuxer
 *
 * Build modes
 * ───────────
 * 1. AFL++ (preferred for long runs):
 *      CC=afl-clang-fast make fuzz
 *    Then run:
 *      afl-fuzz -i tests/fixtures/ -o fuzz-out/ -- ./build/bin/fuzz_demux
 *
 * 2. libFuzzer (clang only, good for quick CI):
 *      make fuzz-libfuzzer
 *    Then run:
 *      ./build/bin/fuzz_demux_libfuzzer tests/fixtures/
 *
 * 3. Standalone stdin mode (no fuzzer, for regression/CI):
 *      make fuzz
 *      ./build/bin/fuzz_demux < tests/fixtures/ipv4_tcp_http.pcap
 *
 * Design
 * ──────
 * The harness feeds arbitrary bytes to np_demux_packet() across all four
 * supported link types in sequence. This exercises every parser branch in
 * np_demux.c: Ethernet, raw/loopback, Linux SLL, IPv4, IPv6, TCP, UDP,
 * ICMP, HTTP, DNS, and TLS — without requiring a live network or a valid
 * pcap wrapper around the input.
 *
 * The harness is intentionally minimal: it must never crash, call abort(),
 * or leak memory regardless of what bytes arrive. All return values from
 * np_demux_packet() are acceptable (NP_OK, NP_ERR_PROTO, etc.). The only
 * invalid outcome is an AddressSanitizer/UBSan report or a hang.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "netpipe.h"
#include "demux/np_demux.h"
#include "packet/np_packet.h"

/* Maximum input size we'll attempt to demux.  Matches snaplen default. */
#define MAX_INPUT 65535

/*
 * Core fuzz function — called by both the AFL persistent-mode loop
 * and the LLVMFuzzerTestOneInput entry point.
 */
static void fuzz_one(const uint8_t *data, size_t size)
{
    if (size == 0 || size > MAX_INPUT) return;

    /*
     * Exercise all four link types with the same raw bytes.  A real packet
     * would only be valid for one, but the parser must not crash on any.
     */
    static const np_linktype_t link_types[] = {
        NP_LINK_ETHERNET,
        NP_LINK_RAW,
        NP_LINK_LOOPBACK,
        NP_LINK_LINUX_SLL,
    };

    for (size_t li = 0; li < sizeof(link_types)/sizeof(link_types[0]); li++) {
        np_packet_t *pkt = np_packet_alloc(size);
        if (!pkt) continue;

        memcpy(pkt->raw, data, size);
        pkt->caplen  = (uint32_t)size;
        pkt->wirelen = (uint32_t)size;

        /* Return value is intentionally ignored — any error code is valid */
        np_demux_packet(pkt, link_types[li]);

        np_packet_free(pkt);
    }
}

/* ------------------------------------------------------------------ */
/*  AFL++ persistent-mode entry point                                  */
/* ------------------------------------------------------------------ */

#ifdef __AFL_HAVE_MANUAL_CONTROL
/*
 * AFL++ persistent mode: the fuzzer reuses the same process across many
 * iterations, avoiding fork() overhead.  __AFL_FUZZ_TESTCASE_BUF and
 * __AFL_FUZZ_TESTCASE_LEN are provided by AFL++ instrumentation.
 */
__AFL_FUZZ_INIT();

int main(void)
{
    np_init();
    __AFL_INIT();

    uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        fuzz_one(buf, len);
    }

    np_cleanup();
    return 0;
}

/* ------------------------------------------------------------------ */
/*  libFuzzer entry point (clang -fsanitize=fuzzer)                    */
/* ------------------------------------------------------------------ */

#elif defined(LIBFUZZER)

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc; (void)argv;
    np_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_one(data, size);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Standalone stdin mode — for regression testing in CI               */
/* ------------------------------------------------------------------ */

#else

int main(void)
{
    np_init();

    uint8_t buf[MAX_INPUT];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n > 0) {
        fuzz_one(buf, (size_t)n);
    }

    np_cleanup();
    return 0;
}

#endif /* __AFL_HAVE_MANUAL_CONTROL / LIBFUZZER */
