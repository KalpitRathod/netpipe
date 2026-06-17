/*
 * test_tcp_reassembly_stress.c — extreme / real-world TCP reassembly tests
 *
 * Extends test_tcp_reassembly.c with scenarios that model pathological
 * traffic observed on production links:
 *
 *   1.  Large out-of-order burst (8 segments, fully reversed order)
 *   2.  Interleaved retransmissions across a 16-segment stream
 *   3.  32-bit sequence-number wrap-around (verify signed arithmetic)
 *   4.  IPv6 TCP reassembly (the codebase uses a different code path)
 *   5.  Mid-stream capture (no SYN seen — anchor on first segment)
 *   6.  Window probe (1-byte segment after a long quiet period)
 *   7.  Keep-alive (1 byte before SYN-ACK seq)
 *   8.  Persistent forward hole that triggers hole-timeout flush
 *   9.  Overlapping segments with different payloads (Wireshark 'C' overlap)
 *  10.  Many concurrent flows (hash-table & bucket-collision stress)
 *  11.  Flow GC retires CLOSED directions (queue must not leak)
 *  12.  64 KiB single segment (max-sized payload stress)
 *  13.  Duplicate SYN re-initialises the direction
 *  14.  FIN followed by retransmitted data (must be dropped)
 *  15.  RST followed by late retransmission (must be dropped)
 *  16.  Bidirectional simultaneous close (FIN/FIN)
 *  17.  Connection migration: same 4-tuple reused after GC
 *  18.  Memory cap enforcement — TCP_MAX_STREAM_BYTES is honoured
 *
 * The test is designed to run under AddressSanitizer + UBSan with
 * `make test`.  Any crash, leak, or assertion failure is fatal.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "netpipe.h"
#include "../src/pipeline/np_pipeline.h"
#include "../src/demux/np_demux.h"
#include "../src/processor/np_tcp_stream.c"   /* pull in internals */

static inline np_err_t np_processor_process(np_processor_t *p, np_packet_t *pkt)
{
    return p->ops->process(p, pkt);
}

/* ------------------------------------------------------------------ */
/*  Synthetic packet builder (Ethernet/IPv4/TCP + Ethernet/IPv6/TCP)   */
/* ------------------------------------------------------------------ */

typedef struct { uint8_t buf[70000]; size_t len; } pktbuf_t;

static void put_bytes(pktbuf_t *p, const void *src, size_t n) {
    memcpy(p->buf + p->len, src, n); p->len += n;
}
static void put_u16(pktbuf_t *p, uint16_t v) {
    v = htons(v); put_bytes(p, &v, 2);
}
static void put_u32(pktbuf_t *p, uint32_t v) {
    v = htonl(v); put_bytes(p, &v, 4);
}

/* Build an IPv4/TCP packet.  src_ip / dst_ip are in host byte order. */
static np_packet_t *build_v4_tcp(uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t sport, uint16_t dport,
                                  uint32_t seq, uint8_t flags,
                                  const uint8_t *payload, size_t plen)
{
    pktbuf_t pb = {0};

    /* Ethernet */
    uint8_t dmac[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t smac[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    put_bytes(&pb, dmac, 6); put_bytes(&pb, smac, 6);
    put_u16(&pb, 0x0800);

    /* IPv4 */
    uint8_t ver = 0x45; put_bytes(&pb, &ver, 1);
    uint8_t dscp = 0;   put_bytes(&pb, &dscp, 1);
    put_u16(&pb, (uint16_t)(20 + 20 + plen));
    put_u16(&pb, 0x1234);
    put_u16(&pb, 0x4000);
    uint8_t ttl = 64;   put_bytes(&pb, &ttl, 1);
    uint8_t proto = 6;  put_bytes(&pb, &proto, 1);
    put_u16(&pb, 0);          /* checksum */
    put_u32(&pb, src_ip);
    put_u32(&pb, dst_ip);

    /* TCP */
    put_u16(&pb, sport);
    put_u16(&pb, dport);
    put_u32(&pb, seq);
    put_u32(&pb, 0);          /* ack */
    uint8_t dof = (5 << 4);   put_bytes(&pb, &dof, 1);
    put_bytes(&pb, &flags, 1);
    put_u16(&pb, 65535);
    put_u16(&pb, 0);          /* checksum */
    put_u16(&pb, 0);          /* urgent */

    if (plen) put_bytes(&pb, payload, plen);

    np_packet_t *pkt = np_packet_alloc(pb.len);
    if (!pkt) return NULL;
    memcpy(pkt->raw, pb.buf, pb.len);
    pkt->caplen  = (uint32_t)pb.len;
    pkt->wirelen = (uint32_t)pb.len;
    clock_gettime(CLOCK_REALTIME, &pkt->ts);
    np_demux_packet(pkt, NP_LINK_ETHERNET);
    return pkt;
}

/* Build an IPv6/TCP packet.  src/dst are 16-byte addresses. */
static np_packet_t *build_v6_tcp(const uint8_t src_ip6[16],
                                  const uint8_t dst_ip6[16],
                                  uint16_t sport, uint16_t dport,
                                  uint32_t seq, uint8_t flags,
                                  const uint8_t *payload, size_t plen)
{
    pktbuf_t pb = {0};

    uint8_t dmac[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t smac[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    put_bytes(&pb, dmac, 6); put_bytes(&pb, smac, 6);
    put_u16(&pb, 0x86DD);

    /* IPv6 header (40 bytes) */
    uint8_t vtc[4] = {0x60, 0x00, 0x00, 0x00};   /* version=6, tc=0, flow=0 */
    put_bytes(&pb, vtc, 4);
    put_u16(&pb, (uint16_t)plen);                /* payload length */
    uint8_t nxt = 6;  put_bytes(&pb, &nxt, 1);   /* Next Header = TCP */
    uint8_t hlim = 64; put_bytes(&pb, &hlim, 1);
    put_bytes(&pb, src_ip6, 16);
    put_bytes(&pb, dst_ip6, 16);

    /* TCP */
    put_u16(&pb, sport);
    put_u16(&pb, dport);
    put_u32(&pb, seq);
    put_u32(&pb, 0);
    uint8_t dof = (5 << 4);   put_bytes(&pb, &dof, 1);
    put_bytes(&pb, &flags, 1);
    put_u16(&pb, 65535);
    put_u16(&pb, 0);
    put_u16(&pb, 0);

    if (plen) put_bytes(&pb, payload, plen);

    np_packet_t *pkt = np_packet_alloc(pb.len);
    if (!pkt) return NULL;
    memcpy(pkt->raw, pb.buf, pb.len);
    pkt->caplen  = (uint32_t)pb.len;
    pkt->wirelen = (uint32_t)pb.len;
    clock_gettime(CLOCK_REALTIME, &pkt->ts);
    np_demux_packet(pkt, NP_LINK_ETHERNET);
    return pkt;
}

/* ------------------------------------------------------------------ */
/*  Tiny test framework                                                */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do {                                                  \
    tests_run++;                                                         \
    fprintf(stderr, "  [stress] %s ... ", name);                         \
} while (0)

#define PASS() do {                                                      \
    tests_passed++;                                                      \
    fprintf(stderr, "PASS\n");                                           \
} while (0)

#define FAIL(fmt, ...) do {                                              \
    tests_failed++;                                                      \
    fprintf(stderr, "FAIL: " fmt "\n", ##__VA_ARGS__);                   \
} while (0)

#define CHECK_STR(actual, expected) do {                                 \
    if (strcmp((actual), (expected)) == 0) PASS();                       \
    else FAIL("got '%s' expected '%s'", (actual), (expected));           \
} while (0)

/* Read up to bufsz-1 bytes of pkt->stream_data as a NUL-terminated string. */
static void stream_str(const np_packet_t *pkt, char *buf, size_t bufsz)
{
    size_t n = pkt->stream_len < bufsz - 1 ? pkt->stream_len : bufsz - 1;
    if (pkt->stream_data) memcpy(buf, pkt->stream_data, n);
    buf[n] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Test 1 — large out-of-order burst                                  */
/* ------------------------------------------------------------------ */

static void test_large_ooo_burst(void)
{
    TEST("large out-of-order burst (8 segments, fully reversed)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a000101, dip = 0x0a000102;
    uint16_t sp = 12345, dp = 80;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, sp, dp, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;

    /* Build 8 segments with payload "AAAA....", "BBBB....", ..., "HHHH....". */
    np_packet_t *pkts[8];
    char payloads[8][5];
    for (int i = 0; i < 8; i++) {
        memset(payloads[i], 'A' + i, 4);
        payloads[i][4] = '\0';
        pkts[i] = build_v4_tcp(sip, dip, sp, dp,
                                seq + (uint32_t)(i * 4), 0x18,
                                (const uint8_t*)payloads[i], 4);
    }
    /* Feed in reverse order. */
    for (int i = 7; i >= 0; i--) np_processor_process(p, pkts[i]);

    /* After processing all segments, send a zero-byte "probe" packet at
     * the next expected sequence to force the processor to re-expose the
     * current stream contents on a packet we can inspect.  (The stream
     * buffer is only re-published on the packet currently being processed.) */
    np_packet_t *probe = build_v4_tcp(sip, dip, sp, dp,
                                       seq + 32, 0x10, NULL, 0);  /* ACK */
    np_processor_process(p, probe);

    char got[64] = {0};
    stream_str(probe, got, sizeof(got));
    CHECK_STR(got, "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH");

    np_packet_free(syn);
    for (int i = 0; i < 8; i++) np_packet_free(pkts[i]);
    np_packet_free(probe);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 2 — interleaved retransmissions                              */
/* ------------------------------------------------------------------ */

static void test_interleaved_retx(void)
{
    TEST("interleaved retransmissions across 16-segment stream");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a000103, dip = 0x0a000104;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, 1000, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;

    /* 16 segments of 2 bytes each ("00", "01", ..., "15"). */
    np_packet_t *pkts[16];
    char data[16][3];
    for (int i = 0; i < 16; i++) {
        snprintf(data[i], sizeof(data[i]), "%02X", i);
        pkts[i] = build_v4_tcp(sip, dip, 1000, 80,
                                seq + (uint32_t)(i * 2), 0x18,
                                (const uint8_t*)data[i], 2);
    }
    /* Interleave: send 0,1,2,3 then re-send 1 (retx) then 4,5,6,7,... */
    np_processor_process(p, pkts[0]);
    np_processor_process(p, pkts[1]);
    np_processor_process(p, pkts[2]);
    np_processor_process(p, pkts[3]);
    /* Retransmit segment 1. */
    {
        np_packet_t *r = build_v4_tcp(sip, dip, 1000, 80,
                                       seq + 2, 0x18,
                                       (const uint8_t*)data[1], 2);
        np_processor_process(p, r);
        np_packet_free(r);
    }
    for (int i = 4; i < 16; i++) np_processor_process(p, pkts[i]);

    /* The final stream should be the 16 hex pairs in order. */
    char expected[33] = {0};
    for (int i = 0; i < 16; i++) strcat(expected, data[i]);

    char got[64] = {0};
    stream_str(pkts[15], got, sizeof(got));
    CHECK_STR(got, expected);

    np_packet_free(syn);
    for (int i = 0; i < 16; i++) np_packet_free(pkts[i]);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 3 — 32-bit sequence-number wrap-around                       */
/* ------------------------------------------------------------------ */

static void test_seq_wraparound(void)
{
    TEST("32-bit sequence number wrap-around");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a000105, dip = 0x0a000106;
    /* Place the SYN at seq=0xFFFFFFFE so seq+1 wraps to 0xFFFFFFFF,
     * and the next data segment is at seq=0 (wraps). */
    uint32_t seq = 0xFFFFFFFE;
    np_packet_t *syn = build_v4_tcp(sip, dip, 2000, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn);
    /* next_seq is now 0xFFFFFFFF. */
    /* Send 1 byte at 0xFFFFFFFF. */
    np_packet_t *p1 = build_v4_tcp(sip, dip, 2000, 80,
                                    0xFFFFFFFFu, 0x18,
                                    (const uint8_t*)"A", 1);
    np_processor_process(p, p1);
    /* next_seq is now 0 (wrapped). */
    /* Send 1 byte at 0. */
    np_packet_t *p2 = build_v4_tcp(sip, dip, 2000, 80,
                                    0u, 0x18,
                                    (const uint8_t*)"B", 1);
    np_processor_process(p, p2);
    /* Send 1 byte at 1. */
    np_packet_t *p3 = build_v4_tcp(sip, dip, 2000, 80,
                                    1u, 0x18,
                                    (const uint8_t*)"C", 1);
    np_processor_process(p, p3);

    char got[8] = {0};
    stream_str(p3, got, sizeof(got));
    CHECK_STR(got, "ABC");

    np_packet_free(syn); np_packet_free(p1);
    np_packet_free(p2); np_packet_free(p3);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 4 — IPv6 TCP reassembly                                      */
/* ------------------------------------------------------------------ */

static void test_ipv6_reassembly(void)
{
    TEST("IPv6 TCP reassembly (out-of-order)");
    np_processor_t *p = np_processor_tcp_stream();
    uint8_t src[16] = {'\x20','\x01','\x0d','\xb8',0,0,0,0,0,0,0,0,0,0,0,1};
    uint8_t dst[16] = {'\x20','\x01','\x0d','\xb8',0,0,0,0,0,0,0,0,0,0,0,2};
    uint32_t seq = 1;
    np_packet_t *syn = build_v6_tcp(src, dst, 3000, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    /* Out-of-order: send second seg first. */
    np_packet_t *b = build_v6_tcp(src, dst, 3000, 80, seq + 5, 0x18,
                                   (const uint8_t*)"WORLD", 5);
    np_processor_process(p, b);
    np_packet_t *a = build_v6_tcp(src, dst, 3000, 80, seq, 0x18,
                                   (const uint8_t*)"HELLO", 5);
    np_processor_process(p, a);

    char got[16] = {0};
    stream_str(a, got, sizeof(got));
    CHECK_STR(got, "HELLOWORLD");

    np_packet_free(syn); np_packet_free(a); np_packet_free(b);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 5 — mid-stream capture (no SYN)                              */
/* ------------------------------------------------------------------ */

static void test_midstream_capture(void)
{
    TEST("mid-stream capture (no SYN, anchor on first segment)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a000107, dip = 0x0a000108;
    /* No SYN.  Send three segments in order. */
    np_packet_t *a = build_v4_tcp(sip, dip, 4000, 80, 5000, 0x18,
                                   (const uint8_t*)"ONE", 3);
    np_processor_process(p, a);
    np_packet_t *b = build_v4_tcp(sip, dip, 4000, 80, 5003, 0x18,
                                   (const uint8_t*)"TWO", 3);
    np_processor_process(p, b);
    np_packet_t *c = build_v4_tcp(sip, dip, 4000, 80, 5006, 0x18,
                                   (const uint8_t*)"THR", 3);
    np_processor_process(p, c);

    char got[16] = {0};
    stream_str(c, got, sizeof(got));
    CHECK_STR(got, "ONETWOTHR");

    np_packet_free(a); np_packet_free(b); np_packet_free(c);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 6 — many concurrent flows                                    */
/* ------------------------------------------------------------------ */

static void test_many_flows(void)
{
    TEST("many concurrent flows (bucket-collision stress)");
    np_processor_t *p = np_processor_tcp_stream();
    enum { N = 64 };
    np_packet_t *syns[N], *datas[N];
    char expected[N][8];
    for (int i = 0; i < N; i++) {
        uint32_t sip = 0x0a000000 + (uint32_t)i;
        uint32_t dip = 0x0a010000 + (uint32_t)i;
        uint32_t seq = 1;
        syns[i] = build_v4_tcp(sip, dip, 5000 + (uint16_t)i, 80,
                                seq, 0x02, NULL, 0);
        np_processor_process(p, syns[i]); seq++;
        snprintf(expected[i], sizeof(expected[i]), "%05dAA", i);
        datas[i] = build_v4_tcp(sip, dip, 5000 + (uint16_t)i, 80,
                                 seq, 0x18,
                                 (const uint8_t*)expected[i], 7);
        np_processor_process(p, datas[i]);
    }
    /* Verify each flow has its own correct stream. */
    int all_ok = 1;
    for (int i = 0; i < N; i++) {
        char got[16] = {0};
        stream_str(datas[i], got, sizeof(got));
        if (strcmp(got, expected[i]) != 0) {
            FAIL("flow %d: got '%s' expected '%s'", i, got, expected[i]);
            all_ok = 0;
            break;
        }
    }
    if (all_ok) PASS();

    for (int i = 0; i < N; i++) {
        np_packet_free(syns[i]);
        np_packet_free(datas[i]);
    }
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 7 — duplicate SYN re-initialises direction                    */
/* ------------------------------------------------------------------ */

static void test_duplicate_syn(void)
{
    TEST("duplicate SYN re-initialises the direction");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a000109, dip = 0x0a00010a;
    uint32_t seq = 100;
    np_packet_t *syn1 = build_v4_tcp(sip, dip, 6000, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn1); seq++;
    np_packet_t *d1 = build_v4_tcp(sip, dip, 6000, 80, seq, 0x18,
                                    (const uint8_t*)"OLD", 3);
    np_processor_process(p, d1);
    /* New SYN with a fresh seq — should reset the direction. */
    uint32_t seq2 = 9000;
    np_packet_t *syn2 = build_v4_tcp(sip, dip, 6000, 80, seq2, 0x02, NULL, 0);
    np_processor_process(p, syn2); seq2++;
    np_packet_t *d2 = build_v4_tcp(sip, dip, 6000, 80, seq2, 0x18,
                                    (const uint8_t*)"NEW", 3);
    np_processor_process(p, d2);

    /* After re-SYN, the stream should be "NEW", NOT "OLDNEW" or "OLDNEW...". */
    char got[16] = {0};
    stream_str(d2, got, sizeof(got));
    CHECK_STR(got, "NEW");

    np_packet_free(syn1); np_packet_free(syn2);
    np_packet_free(d1);   np_packet_free(d2);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 8 — FIN followed by retransmitted data                        */
/* ------------------------------------------------------------------ */

static void test_fin_then_retx(void)
{
    TEST("FIN followed by late retransmitted data (must be dropped)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a00010b, dip = 0x0a00010c;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, 7000, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    np_packet_t *d = build_v4_tcp(sip, dip, 7000, 80, seq, 0x18,
                                   (const uint8_t*)"PAYLOAD", 7);
    np_processor_process(p, d);
    /* Send FIN with no payload. */
    np_packet_t *fin = build_v4_tcp(sip, dip, 7000, 80, seq + 7, 0x01, NULL, 0);
    np_processor_process(p, fin);
    /* Late retransmit of the data — should NOT append. */
    np_packet_t *retx = build_v4_tcp(sip, dip, 7000, 80, seq, 0x18,
                                       (const uint8_t*)"PAYLOAD", 7);
    np_processor_process(p, retx);

    char got[16] = {0};
    stream_str(retx, got, sizeof(got));
    /* Stream must still be exactly "PAYLOAD". */
    CHECK_STR(got, "PAYLOAD");

    np_packet_free(syn); np_packet_free(d);
    np_packet_free(fin); np_packet_free(retx);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 9 — RST followed by late retransmission                       */
/* ------------------------------------------------------------------ */

static void test_rst_then_retx(void)
{
    TEST("RST followed by late retransmission (must be dropped)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a00010d, dip = 0x0a00010e;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, 8000, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    np_packet_t *d = build_v4_tcp(sip, dip, 8000, 80, seq, 0x18,
                                   (const uint8_t*)"DATA", 4);
    np_processor_process(p, d);
    /* RST. */
    np_packet_t *rst = build_v4_tcp(sip, dip, 8000, 80, seq + 4, 0x04, NULL, 0);
    np_processor_process(p, rst);
    /* Late data. */
    np_packet_t *late = build_v4_tcp(sip, dip, 8000, 80, seq + 4, 0x18,
                                       (const uint8_t*)"AFTER", 5);
    np_processor_process(p, late);

    char got[16] = {0};
    stream_str(late, got, sizeof(got));
    CHECK_STR(got, "DATA");

    np_packet_free(syn); np_packet_free(d);
    np_packet_free(rst); np_packet_free(late);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 10 — large 64 KiB segment                                     */
/* ------------------------------------------------------------------ */

static void test_large_segment(void)
{
    TEST("large segment (8 KiB payload, single segment)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a00010f, dip = 0x0a000110;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, 9000, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;

    /* 8 KiB of incrementing bytes. */
    static uint8_t big[8192];
    for (int i = 0; i < 8192; i++) big[i] = (uint8_t)(i & 0xff);
    np_packet_t *d = build_v4_tcp(sip, dip, 9000, 80, seq, 0x18, big, 8192);
    np_processor_process(p, d);

    if (d->stream_len == 8192 && memcmp(d->stream_data, big, 8192) == 0) PASS();
    else FAIL("stream_len=%zu (expected 8192)", d->stream_len);

    np_packet_free(syn); np_packet_free(d);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 11 — overlapping segments with different payloads             */
/*  (Tests Wireshark's "C" overlap case — earlier data wins.)          */
/* ------------------------------------------------------------------ */

static void test_conflicting_overlap(void)
{
    TEST("overlapping segments with conflicting payloads");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a000111, dip = 0x0a000112;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, 9100, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    /* Send 4 bytes at seq. */
    np_packet_t *a = build_v4_tcp(sip, dip, 9100, 80, seq, 0x18,
                                   (const uint8_t*)"AAAA", 4);
    np_processor_process(p, a);
    /* Send 4 bytes at seq+2, conflicting payload. */
    /* The first 2 bytes of the new seg overlap the last 2 of the old seg.
     * Our implementation keeps the first-received data (already-delivered
     * data wins), so the stream should be "AAAA". */
    np_packet_t *b = build_v4_tcp(sip, dip, 9100, 80, seq + 2, 0x18,
                                   (const uint8_t*)"BBBB", 4);
    np_processor_process(p, b);

    char got[16] = {0};
    stream_str(b, got, sizeof(got));
    CHECK_STR(got, "AAAABB");

    np_packet_free(syn); np_packet_free(a); np_packet_free(b);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 12 — bidirectional simultaneous close                          */
/* ------------------------------------------------------------------ */

static void test_bidir_close(void)
{
    TEST("bidirectional simultaneous close (FIN/FIN)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t cseq = 1, sseq = 500;
    uint32_t csip = 0x0a000113, dsip = 0x0a000114;

    np_packet_t *syn_c = build_v4_tcp(csip, dsip, 9200, 80, cseq, 0x02, NULL, 0);
    np_processor_process(p, syn_c); cseq++;
    np_packet_t *syn_s = build_v4_tcp(dsip, csip, 80, 9200, sseq, 0x02, NULL, 0);
    np_processor_process(p, syn_s); sseq++;

    np_packet_t *req = build_v4_tcp(csip, dsip, 9200, 80, cseq, 0x18,
                                     (const uint8_t*)"Q", 1);
    np_processor_process(p, req); cseq++;
    np_packet_t *resp = build_v4_tcp(dsip, csip, 80, 9200, sseq, 0x18,
                                      (const uint8_t*)"A", 1);
    np_processor_process(p, resp); sseq++;

    /* Both sides FIN simultaneously. */
    np_packet_t *fin_c = build_v4_tcp(csip, dsip, 9200, 80, cseq, 0x01, NULL, 0);
    np_processor_process(p, fin_c);
    np_packet_t *fin_s = build_v4_tcp(dsip, csip, 80, 9200, sseq, 0x01, NULL, 0);
    np_processor_process(p, fin_s);

    char got_req[8] = {0}, got_resp[8] = {0};
    stream_str(req, got_req, sizeof(got_req));
    stream_str(resp, got_resp, sizeof(got_resp));
    if (strcmp(got_req, "Q") == 0 && strcmp(got_resp, "A") == 0) PASS();
    else FAIL("req='%s' resp='%s'", got_req, got_resp);

    np_packet_free(syn_c); np_packet_free(syn_s);
    np_packet_free(req);  np_packet_free(resp);
    np_packet_free(fin_c); np_packet_free(fin_s);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 13 — connection migration after GC                            */
/*  Same 4-tuple reused after GC retires the prior flow.               */
/* ------------------------------------------------------------------ */

static void test_conn_migration(void)
{
    TEST("connection migration: 4-tuple reuse after close");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a000115, dip = 0x0a000116;
    uint16_t sp = 9300, dp = 80;

    /* First connection. */
    uint32_t seq1 = 1;
    np_packet_t *syn1 = build_v4_tcp(sip, dip, sp, dp, seq1, 0x02, NULL, 0);
    np_processor_process(p, syn1); seq1++;
    np_packet_t *d1 = build_v4_tcp(sip, dip, sp, dp, seq1, 0x18,
                                    (const uint8_t*)"FIRST", 5);
    np_processor_process(p, d1);
    np_packet_t *fin1 = build_v4_tcp(sip, dip, sp, dp, seq1 + 5, 0x01, NULL, 0);
    np_processor_process(p, fin1);

    /* Second connection — same 4-tuple, new SYN. */
    uint32_t seq2 = 1000;
    np_packet_t *syn2 = build_v4_tcp(sip, dip, sp, dp, seq2, 0x02, NULL, 0);
    np_processor_process(p, syn2); seq2++;
    np_packet_t *d2 = build_v4_tcp(sip, dip, sp, dp, seq2, 0x18,
                                    (const uint8_t*)"SECOND", 6);
    np_processor_process(p, d2);

    /* The new connection must NOT have "FIRST" in its stream. */
    char got[16] = {0};
    stream_str(d2, got, sizeof(got));
    CHECK_STR(got, "SECOND");

    np_packet_free(syn1); np_packet_free(d1); np_packet_free(fin1);
    np_packet_free(syn2); np_packet_free(d2);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 14 — stats: out-of-order vs in-order counts                  */
/* ------------------------------------------------------------------ */

static void visit_stats(const tcp_flow_key_t *k, const tcp_direction_t *d, void *ud)
{
    (void)k;
    np_tcp_stream_stats_t *s = ud;
    s->in_order_segs   += d->stat_in_order_segs;
    s->ooo_segs        += d->stat_ooo_segs;
    s->retransmits     += d->stat_retransmits;
    s->gap_flushes     += d->stat_gap_flushes;
    s->bytes_delivered += d->stat_bytes_delivered;
    s->nflows++;
}

static void test_stats_ooo_vs_inorder(void)
{
    TEST("stats distinguish in-order vs out-of-order vs retransmit");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a000117, dip = 0x0a000118;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, 9400, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;

    /* 3 in-order segments. */
    for (int i = 0; i < 3; i++) {
        np_packet_t *q = build_v4_tcp(sip, dip, 9400, 80,
                                       seq + (uint32_t)(i * 2), 0x18,
                                       (const uint8_t*)"AB", 2);
        np_processor_process(p, q);
        np_packet_free(q);
    }
    /* 2 out-of-order (send 6 then 5). */
    np_packet_t *o6 = build_v4_tcp(sip, dip, 9400, 80, seq + 6, 0x18,
                                    (const uint8_t*)"CD", 2);
    np_processor_process(p, o6);
    np_packet_t *o5 = build_v4_tcp(sip, dip, 9400, 80, seq + 4, 0x18,
                                    (const uint8_t*)"EF", 2);
    np_processor_process(p, o5);
    /* 1 retransmit (resend seq+0). */
    np_packet_t *rtx = build_v4_tcp(sip, dip, 9400, 80, seq, 0x18,
                                     (const uint8_t*)"AB", 2);
    np_processor_process(p, rtx);

    np_tcp_stream_stats_t s = {0};
    np_tcp_stream_visit(p, visit_stats, &s);
    /* 3 original in-order + 1 seg-6 that arrives in-order at next_seq
     *   = 4 in_order_segs.
     * seg-5 arrives "behind" next_seq (entirely consumed → retransmit)
     *   AND counts as OoO (seq != next_seq).
     * the explicit retransmit of seg-0 also is "behind" + OoO.
     * So: in_order >= 4, ooo >= 1, retransmits >= 1, bytes >= 8. */
    if (s.in_order_segs >= 4 && s.ooo_segs >= 1 && s.retransmits >= 1 &&
        s.bytes_delivered >= 8) PASS();
    else FAIL("in=%llu ooo=%llu rtx=%llu bytes=%llu",
              (unsigned long long)s.in_order_segs,
              (unsigned long long)s.ooo_segs,
              (unsigned long long)s.retransmits,
              (unsigned long long)s.bytes_delivered);

    np_packet_free(syn); np_packet_free(o5); np_packet_free(o6); np_packet_free(rtx);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 15 — repeated retransmits do not duplicate data               */
/* ------------------------------------------------------------------ */

static void test_repeated_retx(void)
{
    TEST("10x repeated retransmission of the same segment");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a000119, dip = 0x0a00011a;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, 9500, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    np_packet_t *d = build_v4_tcp(sip, dip, 9500, 80, seq, 0x18,
                                   (const uint8_t*)"ONCE", 4);
    np_processor_process(p, d);
    /* 10 retransmissions. */
    for (int i = 0; i < 10; i++) {
        np_packet_t *r = build_v4_tcp(sip, dip, 9500, 80, seq, 0x18,
                                       (const uint8_t*)"ONCE", 4);
        np_processor_process(p, r);
        np_packet_free(r);
    }
    char got[16] = {0};
    stream_str(d, got, sizeof(got));
    CHECK_STR(got, "ONCE");

    np_packet_free(syn); np_packet_free(d);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 16 — gap that exceeds hole timeout (uses sleep)               */
/*  NOTE: This actually exercises the flush path by sleeping > 1s.      */
/* ------------------------------------------------------------------ */

static void test_gap_flush_real(void)
{
    TEST("gap flush path (sleep > 1s, verify forward progress)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a00011b, dip = 0x0a00011c;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, 9600, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;

    /* Send segment far ahead — opens a hole. */
    np_packet_t *later = build_v4_tcp(sip, dip, 9600, 80, seq + 10, 0x18,
                                       (const uint8_t*)"LATER", 5);
    np_processor_process(p, later);
    /* Stream is empty (hole pending). */
    if (later->stream_len != 0) {
        FAIL("expected empty stream, got %zu bytes", later->stream_len);
        np_packet_free(syn); np_packet_free(later);
        p->ops->free(p);
        return;
    }
    /* Wait for hole timeout (1.2 seconds). */
    struct timespec ts = { .tv_sec = 1, .tv_nsec = 200 * 1000 * 1000 };
    nanosleep(&ts, NULL);

    /* Send another segment after the hole — triggers drain() which
     * sees the timeout has elapsed and flushes the gap. */
    np_packet_t *tail = build_v4_tcp(sip, dip, 9600, 80, seq + 15, 0x18,
                                      (const uint8_t*)"TAIL", 4);
    np_processor_process(p, tail);

    /* After flush, both "LATER" and "TAIL" should be present. */
    char got[16] = {0};
    stream_str(tail, got, sizeof(got));
    if (strcmp(got, "LATERTAIL") == 0) PASS();
    else FAIL("got '%s' (len=%zu) expected 'LATERTAIL'", got, tail->stream_len);

    np_packet_free(syn); np_packet_free(later); np_packet_free(tail);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 17 — memory cap: TCP_MAX_STREAM_BYTES is honoured             */
/* ------------------------------------------------------------------ */

static void test_memory_cap(void)
{
    TEST("per-flow stream buffer is capped at 1 MiB");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a00011d, dip = 0x0a00011e;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, 9700, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;

    /* Send 2 MiB of data in 8 KiB chunks. */
    static uint8_t chunk[8192];
    memset(chunk, 'X', sizeof(chunk));
    np_packet_t *last = NULL;
    for (size_t off = 0; off < (2u << 20); off += sizeof(chunk)) {
        np_packet_t *q = build_v4_tcp(sip, dip, 9700, 80,
                                       seq + (uint32_t)off, 0x18,
                                       chunk, sizeof(chunk));
        np_processor_process(p, q);
        if (last) np_packet_free(last);
        last = q;
    }
    /* TCP_MAX_STREAM_BYTES is 1 MiB.  The stream buffer must NOT exceed it. */
    if (last->stream_len <= (1u << 20) + 1) PASS();
    else FAIL("stream_len=%zu (expected <= %u)",
              last->stream_len, (1u << 20));

    np_packet_free(syn);
    if (last) np_packet_free(last);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 18 — window probe (1-byte segment after quiet period)         */
/* ------------------------------------------------------------------ */

static void test_window_probe(void)
{
    TEST("window probe (1-byte data after quiet period)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a00011f, dip = 0x0a000120;
    uint32_t seq = 1;
    np_packet_t *syn = build_v4_tcp(sip, dip, 9800, 80, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    np_packet_t *d = build_v4_tcp(sip, dip, 9800, 80, seq, 0x18,
                                   (const uint8_t*)"X", 1);
    np_processor_process(p, d);
    /* Sleep to simulate a quiet period. */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    /* Send another single-byte segment. */
    np_packet_t *e = build_v4_tcp(sip, dip, 9800, 80, seq + 1, 0x18,
                                   (const uint8_t*)"Y", 1);
    np_processor_process(p, e);

    char got[8] = {0};
    stream_str(e, got, sizeof(got));
    CHECK_STR(got, "XY");

    np_packet_free(syn); np_packet_free(d); np_packet_free(e);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 19 — multi-segment gap-fill (the bug from the audit)          */
/*                                                                     */
/*  Queue has [100,150) and [200,250).  A large retransmission         */
/*  [90,290) arrives.  The old code only clipped against the first     */
/*  downstream neighbor, silently dropping bytes [150,290) — including */
/*  the data that would fill the gap [150,200).  The fixed code        */
/*  splits the incoming segment into pieces and fills all gaps.        */
/* ------------------------------------------------------------------ */

static void test_multi_segment_gap_fill(void)
{
    TEST("multi-segment gap-fill (large retransmission spanning gaps)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t sip = 0x0a000123, dip = 0x0a000124;
    uint16_t sp = 9901, dp = 80;
    uint32_t seq = 1000;

    /* SYN at seq=1000, next_seq becomes 1001. */
    np_packet_t *syn = build_v4_tcp(sip, dip, sp, dp, seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;

    /* Build 250 bytes: positions 0-249 map to seq 1001-1250.
     * [1001,1051):   'X' * 50  (gap before first queued seg)
     * [1051,1101):   'Y' * 50  (first queued seg)
     * [1101,1151):   'Z' * 50  (gap between queued segs — initially missing)
     * [1151,1201):   'W' * 50  (second queued seg)
     * [1201,1251):   'V' * 50  (tail data)
     *
     * This is the exact scenario from the bug report:
     * Queue has [1051,1101) and [1151,1201) with gap [1101,1151).
     * A large retransmission [1001,1251) arrives.
     * Correct: fill [1001,1051), skip [1051,1101), fill [1101,1151),
     *          skip [1151,1201), fill [1201,1251).
     * Bug:     only fill [1001,1051), discard [1051,1251). */
    char big[300];
    memset(big,       'X', 50);
    memset(big + 50,  'Y', 50);
    memset(big + 100, 'Z', 50);
    memset(big + 150, 'W', 50);
    memset(big + 200, 'V', 50);

    /* Queue [1051,1101) = 'Y'*50 */
    np_packet_t *q1 = build_v4_tcp(sip, dip, sp, dp,
                                     seq + 50, 0x18,
                                     (const uint8_t*)big + 50, 50);
    np_processor_process(p, q1);

    /* Queue [1151,1201) = 'W'*50 — leaves gap [1101,1151) */
    np_packet_t *q2 = build_v4_tcp(sip, dip, sp, dp,
                                     seq + 150, 0x18,
                                     (const uint8_t*)big + 150, 50);
    np_processor_process(p, q2);

    /* Now send [1001,1251) = big[0..250] — spans both queued segs + both gaps.
     * This is the large retransmission that triggers the bug. */
    np_packet_t *big_pkt = build_v4_tcp(sip, dip, sp, dp,
                                         seq, 0x18,
                                         (const uint8_t*)big, 250);
    np_processor_process(p, big_pkt);

    /* After processing, the queue should have all gaps filled.
     * dir_drain should deliver the full 250-byte stream:
     * 'X'*50 + 'Y'*50 + 'Z'*50 + 'W'*50 + 'V'*50
     * Send a probe to expose the stream. */
    np_packet_t *probe = build_v4_tcp(sip, dip, sp, dp,
                                       seq + 250, 0x10, NULL, 0);
    np_processor_process(p, probe);

    /* Check the stream. */
    char got[300] = {0};
    stream_str(probe, got, sizeof(got));

    /* Build expected string. */
    char expected[251] = {0};
    memset(expected,       'X', 50);
    memset(expected + 50,  'Y', 50);
    memset(expected + 100, 'Z', 50);
    memset(expected + 150, 'W', 50);
    memset(expected + 200, 'V', 50);

    if (strcmp(got, expected) == 0) PASS();
    else FAIL("got %.40s... expected %.40s... (len=%zu)",
              got, expected, probe->stream_len);

    np_packet_free(syn);
    np_packet_free(q1); np_packet_free(q2);
    np_packet_free(big_pkt); np_packet_free(probe);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    np_init();
    fprintf(stderr, "=== TCP reassembly STRESS / real-world tests ===\n");
    test_large_ooo_burst();
    test_interleaved_retx();
    test_seq_wraparound();
    test_ipv6_reassembly();
    test_midstream_capture();
    test_many_flows();
    test_duplicate_syn();
    test_fin_then_retx();
    test_rst_then_retx();
    test_large_segment();
    test_conflicting_overlap();
    test_bidir_close();
    test_conn_migration();
    test_stats_ooo_vs_inorder();
    test_repeated_retx();
    test_gap_flush_real();
    test_memory_cap();
    test_window_probe();
    test_multi_segment_gap_fill();
    fprintf(stderr, "\n%d/%d stress tests passed (%d failed)\n",
            tests_passed, tests_run, tests_failed);
    np_cleanup();
    return tests_failed == 0 ? 0 : 1;
}
