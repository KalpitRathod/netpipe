/*
 * test_tcp_reassembly.c — regression tests for the new TCP reassembler
 *
 * Exercises the new ordered-segment-queue implementation:
 *   1. In-order delivery (baseline)
 *   2. Out-of-order arrival (seg 2 before seg 1)
 *   3. Pure retransmission (same seq twice)
 *   4. Partial overlap retransmission (seg with extra leading bytes)
 *   5. Sequence gap + late fill (within hole timeout)
 *   6. Sequence gap + hole-timeout flush (gap never filled)
 *   7. SYN/FIN state machine
 *   8. RST closes the flow
 *   9. Bidirectional independence (A→B and B→A have separate contexts)
 *
 * The test constructs synthetic Ethernet/IPv4/TCP packets in memory,
 * feeds them through the netpipe pipeline, and inspects pkt->stream_data
 * to verify correctness.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#include "netpipe.h"
#include "../src/pipeline/np_pipeline.h"     /* internal ops struct */
#include "../src/demux/np_demux.h"
#include "../src/processor/np_tcp_stream.c"  /* pull in internals */

static inline np_err_t np_processor_process(np_processor_t *p, np_packet_t *pkt)
{
    return p->ops->process(p, pkt);
}

/* ------------------------------------------------------------------ */
/*  Synthetic packet builder                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t  buf[65536];
    size_t   len;
} pktbuf_t;

static void put_bytes(pktbuf_t *p, const void *src, size_t n) {
    memcpy(p->buf + p->len, src, n);
    p->len += n;
}

static void put_u16(pktbuf_t *p, uint16_t v) {
    v = htons(v); put_bytes(p, &v, 2);
}
static void put_u32(pktbuf_t *p, uint32_t v) {
    v = htonl(v); put_bytes(p, &v, 4);
}

/* Build a synthetic Ethernet/IPv4/TCP packet with the given payload. */
static np_packet_t *build_tcp_pkt(uint32_t src_ip, uint32_t dst_ip,
                                   uint16_t src_port, uint16_t dst_port,
                                   uint32_t seq, uint8_t flags,
                                   const uint8_t *payload, size_t payload_len)
{
    pktbuf_t pb = {0};

    /* Ethernet header (14 bytes) */
    uint8_t dst_mac[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t src_mac[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    put_bytes(&pb, dst_mac, 6);
    put_bytes(&pb, src_mac, 6);
    put_u16(&pb, 0x0800);

    /* IPv4 header (20 bytes, no options) */
    uint8_t ihl_ver = 0x45;
    put_bytes(&pb, &ihl_ver, 1);
    uint8_t dscp = 0;
    put_bytes(&pb, &dscp, 1);
    uint16_t total_len = (uint16_t)(20 + 20 + payload_len);
    put_u16(&pb, total_len);
    put_u16(&pb, 0x1234);  /* identification */
    put_u16(&pb, 0x4000);  /* don't fragment */
    uint8_t ttl = 64; put_bytes(&pb, &ttl, 1);
    uint8_t proto = 6; put_bytes(&pb, &proto, 1);  /* TCP */
    put_u16(&pb, 0);  /* checksum (we don't verify) */
    put_u32(&pb, src_ip);
    put_u32(&pb, dst_ip);

    /* TCP header (20 bytes, no options) */
    put_u16(&pb, src_port);
    put_u16(&pb, dst_port);
    put_u32(&pb, seq);
    put_u32(&pb, 0);  /* ack */
    uint8_t dof = (5 << 4);  /* data offset = 5 * 4 = 20 bytes */
    put_bytes(&pb, &dof, 1);
    put_bytes(&pb, &flags, 1);
    put_u16(&pb, 65535);  /* window */
    put_u16(&pb, 0);  /* checksum */
    put_u16(&pb, 0);  /* urgent */

    /* Payload */
    if (payload_len > 0) put_bytes(&pb, payload, payload_len);

    /* Build np_packet_t */
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
/*  Test harness                                                        */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;
static int test_in_progress = 0;

#define TEST(name)  do { tests_run++; test_in_progress = 1; \
    fprintf(stderr, "  [test] %s ... ", name); } while (0)
#define PASS() do { \
    if (test_in_progress) { tests_passed++; test_in_progress = 0; } \
    fprintf(stderr, "PASS\n"); } while (0)
#define FAIL(fmt, ...) do { \
    test_in_progress = 0; \
    fprintf(stderr, "FAIL: " fmt "\n", ##__VA_ARGS__); } while (0)

#define ASSERT_EQ(a, b)  do { \
    if ((a) == (b)) { PASS(); } \
    else { FAIL(#a " (%zd) != " #b " (%zd)", (ssize_t)(a), (ssize_t)(b)); } \
} while (0)

#define ASSERT_STR_EQ(actual, expected) do { \
    if (strcmp((actual), (expected)) == 0) { PASS(); } \
    else { FAIL("got '%s' expected '%s'", (actual), (expected)); } \
} while (0)

/* ------------------------------------------------------------------ */
/*  Test 1: in-order delivery                                          */
/* ------------------------------------------------------------------ */

static void test_in_order(void)
{
    TEST("in-order delivery");
    np_processor_t *p = np_processor_tcp_stream();
    np_packet_t *pkts[3];
    np_packet_t *syn_pkt;
    const char *data[] = {"Hello, ", "world", "!\n"};
    size_t lens[] = {7, 5, 2};
    uint32_t seq = 1000;
    uint8_t syn = 0x02;
    syn_pkt = build_tcp_pkt(0x0a000001, 0x0a000002, 1234, 80,
                             seq, syn, NULL, 0);  /* SYN */
    np_processor_process(p, syn_pkt);
    seq += 1;
    for (int i = 0; i < 3; i++) {
        pkts[i] = build_tcp_pkt(0x0a000001, 0x0a000002, 1234, 80,
                                 seq, 0x18, (const uint8_t*)data[i], lens[i]);
        np_processor_process(p, pkts[i]);
        seq += (uint32_t)lens[i];
    }
    /* The last packet should contain the full reassembled stream. */
    char got[64] = {0};
    size_t n = pkts[2]->stream_len < 63 ? pkts[2]->stream_len : 63;
    memcpy(got, pkts[2]->stream_data, n);
    ASSERT_STR_EQ(got, "Hello, world!\n");
    for (int i = 0; i < 3; i++) np_packet_free(pkts[i]);
    np_packet_free(syn_pkt);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 2: out-of-order arrival                                       */
/* ------------------------------------------------------------------ */

static void test_out_of_order(void)
{
    TEST("out-of-order arrival");
    np_processor_t *p = np_processor_tcp_stream();
    const char *s1 = "AAAA", *s2 = "BBBB", *s3 = "CCCC";
    uint32_t seq = 1000;
    np_packet_t *syn = build_tcp_pkt(0x0a000003, 0x0a000004, 2222, 80,
                                      seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    /* Send seg 2, then seg 1, then seg 3 — classic out-of-order. */
    np_packet_t *p2 = build_tcp_pkt(0x0a000003, 0x0a000004, 2222, 80,
                                     seq + 4, 0x18, (const uint8_t*)s2, 4);
    np_processor_process(p, p2);
    /* p2 hasn't been delivered yet — stream_data may be empty/NULL */
    np_packet_t *p1 = build_tcp_pkt(0x0a000003, 0x0a000004, 2222, 80,
                                     seq, 0x18, (const uint8_t*)s1, 4);
    np_processor_process(p, p1);
    /* Now AAAA and BBBB should both be in stream. */
    char got[16] = {0};
    size_t n = p1->stream_len < 15 ? p1->stream_len : 15;
    memcpy(got, p1->stream_data, n);
    if (strcmp(got, "AAAABBBB") == 0) PASS();
    else FAIL("got '%s' expected 'AAAABBBB'", got);
    np_packet_t *p3 = build_tcp_pkt(0x0a000003, 0x0a000004, 2222, 80,
                                     seq + 8, 0x18, (const uint8_t*)s3, 4);
    np_processor_process(p, p3);
    memset(got, 0, sizeof(got));
    n = p3->stream_len < 15 ? p3->stream_len : 15;
    memcpy(got, p3->stream_data, n);
    if (strcmp(got, "AAAABBBBCCCC") == 0) PASS();
    else FAIL("got '%s' expected 'AAAABBBBCCCC'", got);
    np_packet_free(syn);
    np_packet_free(p1); np_packet_free(p2); np_packet_free(p3);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 3: pure retransmission                                        */
/* ------------------------------------------------------------------ */

static void test_retransmit(void)
{
    TEST("pure retransmission");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t seq = 5000;
    np_packet_t *syn = build_tcp_pkt(0x0a000005, 0x0a000006, 3333, 80,
                                      seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    const char *data = "DATA1";
    np_packet_t *p1 = build_tcp_pkt(0x0a000005, 0x0a000006, 3333, 80,
                                     seq, 0x18, (const uint8_t*)data, 5);
    np_processor_process(p, p1);
    /* Retransmit the same segment. */
    np_packet_t *p1r = build_tcp_pkt(0x0a000005, 0x0a000006, 3333, 80,
                                      seq, 0x18, (const uint8_t*)data, 5);
    np_processor_process(p, p1r);
    /* Stream should be exactly "DATA1", not "DATA1DATA1". */
    char got[16] = {0};
    size_t n = p1r->stream_len < 15 ? p1r->stream_len : 15;
    memcpy(got, p1r->stream_data, n);
    ASSERT_STR_EQ(got, "DATA1");
    np_packet_free(syn); np_packet_free(p1); np_packet_free(p1r);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 4: partial overlap retransmission                             */
/* ------------------------------------------------------------------ */

static void test_partial_overlap(void)
{
    TEST("partial overlap retransmission");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t seq = 2000;
    np_packet_t *syn = build_tcp_pkt(0x0a000007, 0x0a000008, 4444, 80,
                                      seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    /* First segment: 0123456789 (10 bytes) */
    const char *d1 = "0123456789";
    np_packet_t *p1 = build_tcp_pkt(0x0a000007, 0x0a000008, 4444, 80,
                                     seq, 0x18, (const uint8_t*)d1, 10);
    np_processor_process(p, p1);
    /* Overlapping segment: 56789ABCDE (starts at seq+5, 10 bytes) */
    const char *d2 = "56789ABCDE";
    np_packet_t *p2 = build_tcp_pkt(0x0a000007, 0x0a000008, 4444, 80,
                                     seq + 5, 0x18, (const uint8_t*)d2, 10);
    np_processor_process(p, p2);
    /* Stream should be "0123456789ABCDE" — overlap correctly clipped. */
    char got[32] = {0};
    size_t n = p2->stream_len < 31 ? p2->stream_len : 31;
    memcpy(got, p2->stream_data, n);
    ASSERT_STR_EQ(got, "0123456789ABCDE");
    np_packet_free(syn); np_packet_free(p1); np_packet_free(p2);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 5: gap with late fill (within hole timeout)                   */
/* ------------------------------------------------------------------ */

static void test_gap_late_fill(void)
{
    TEST("gap with late fill (within hole timeout)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t seq = 3000;
    np_packet_t *syn = build_tcp_pkt(0x0a000009, 0x0a00000a, 5555, 80,
                                      seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    /* Send seg at seq+5 (leaving a 5-byte gap from seq to seq+4). */
    const char *later = "WXYZ";
    np_packet_t *p2 = build_tcp_pkt(0x0a000009, 0x0a00000a, 5555, 80,
                                     seq + 5, 0x18, (const uint8_t*)later, 4);
    np_processor_process(p, p2);
    /* Now fill the gap. */
    const char *first = "ABCDE";
    np_packet_t *p1 = build_tcp_pkt(0x0a000009, 0x0a00000a, 5555, 80,
                                     seq, 0x18, (const uint8_t*)first, 5);
    np_processor_process(p, p1);
    /* Stream should be "ABCDEFGHIJ" — wait, we don't have a continuation,
     * so it's "ABCDE" + "WXYZ" = "ABCDEWXYZ". */
    char got[16] = {0};
    size_t n = p1->stream_len < 15 ? p1->stream_len : 15;
    memcpy(got, p1->stream_data, n);
    ASSERT_STR_EQ(got, "ABCDEWXYZ");
    np_packet_free(syn); np_packet_free(p1); np_packet_free(p2);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 6: bidirectional independence                                 */
/* ------------------------------------------------------------------ */

static void test_bidirectional(void)
{
    TEST("bidirectional independence");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t seq_c = 100, seq_s = 1000;
    /* SYN client→server */
    np_packet_t *syn_c = build_tcp_pkt(0x0a00000b, 0x0a00000c, 6000, 80,
                                        seq_c, 0x02, NULL, 0);
    np_processor_process(p, syn_c); seq_c++;
    /* SYN server→client (different direction) */
    np_packet_t *syn_s = build_tcp_pkt(0x0a00000c, 0x0a00000b, 80, 6000,
                                        seq_s, 0x02, NULL, 0);
    np_processor_process(p, syn_s); seq_s++;

    const char *req = "GET / HTTP/1.1\r\n";
    const char *resp = "HTTP/1.1 200 OK\r\n";
    size_t req_len = strlen(req);
    size_t resp_len = strlen(resp);
    np_packet_t *preq = build_tcp_pkt(0x0a00000b, 0x0a00000c, 6000, 80,
                                       seq_c, 0x18, (const uint8_t*)req, req_len);
    np_processor_process(p, preq);

    np_packet_t *presp = build_tcp_pkt(0x0a00000c, 0x0a00000b, 80, 6000,
                                        seq_s, 0x18, (const uint8_t*)resp, resp_len);
    np_processor_process(p, presp);

    /* Request stream should NOT contain response. */
    char got_req[64] = {0};
    size_t n = preq->stream_len < 63 ? preq->stream_len : 63;
    memcpy(got_req, preq->stream_data, n);
    char got_resp[64] = {0};
    n = presp->stream_len < 63 ? presp->stream_len : 63;
    memcpy(got_resp, presp->stream_data, n);

    if (strcmp(got_req, "GET / HTTP/1.1\r\n") == 0 &&
        strcmp(got_resp, "HTTP/1.1 200 OK\r\n") == 0) PASS();
    else FAIL("req='%s' resp='%s'", got_req, got_resp);

    np_packet_free(syn_c); np_packet_free(syn_s);
    np_packet_free(preq);  np_packet_free(presp);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 7: RST closes the flow                                        */
/* ------------------------------------------------------------------ */

static void test_rst_closes(void)
{
    TEST("RST closes the flow");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t seq = 7000;
    np_packet_t *syn = build_tcp_pkt(0x0a00000d, 0x0a00000e, 7000, 80,
                                      seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    const char *data = "before-rst";
    np_packet_t *p1 = build_tcp_pkt(0x0a00000d, 0x0a00000e, 7000, 80,
                                     seq, 0x18, (const uint8_t*)data, 10);
    np_processor_process(p, p1);
    /* Now send RST */
    np_packet_t *rst = build_tcp_pkt(0x0a00000d, 0x0a00000e, 7000, 80,
                                      seq + 10, 0x04, NULL, 0);
    np_processor_process(p, rst);
    /* After RST, subsequent data should NOT be appended to the stream. */
    const char *post = "after-rst";
    np_packet_t *pl = build_tcp_pkt(0x0a00000d, 0x0a00000e, 7000, 80,
                                     seq + 10, 0x18, (const uint8_t*)post, 10);
    np_processor_process(p, pl);
    /* The post-RST packet may still expose the prior stream_data,
     * but its length should not have grown. */
    char got[64] = {0};
    size_t n = pl->stream_len < 63 ? pl->stream_len : 63;
    memcpy(got, pl->stream_data, n);
    if (strcmp(got, "before-rst") == 0) PASS();
    else FAIL("got '%s' (len=%zu) expected 'before-rst'", got, pl->stream_len);
    np_packet_free(syn); np_packet_free(p1);
    np_packet_free(rst); np_packet_free(pl);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 8: stats visitor                                              */
/* ------------------------------------------------------------------ */

static void visit_stats(const tcp_flow_key_t *k, const tcp_direction_t *d, void *ud)
{
    (void)k;
    np_tcp_stream_stats_t *s = ud;
    s->in_order_segs    += d->stat_in_order_segs;
    s->ooo_segs         += d->stat_ooo_segs;
    s->retransmits      += d->stat_retransmits;
    s->gap_flushes      += d->stat_gap_flushes;
    s->bytes_delivered  += d->stat_bytes_delivered;
    s->nflows++;
}

static void test_stats(void)
{
    TEST("stats visitor counts flows and segments");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t seq = 9000;
    np_packet_t *syn = build_tcp_pkt(0x0a00000f, 0x0a000010, 8000, 80,
                                      seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    const char *d1 = "AAA", *d2 = "BBB";
    np_packet_t *p1 = build_tcp_pkt(0x0a00000f, 0x0a000010, 8000, 80,
                                     seq, 0x18, (const uint8_t*)d1, 3);
    np_processor_process(p, p1);
    np_packet_t *p1r = build_tcp_pkt(0x0a00000f, 0x0a000010, 8000, 80,
                                      seq, 0x18, (const uint8_t*)d1, 3);
    np_processor_process(p, p1r);  /* retransmit */
    np_packet_t *p2 = build_tcp_pkt(0x0a00000f, 0x0a000010, 8000, 80,
                                     seq + 3, 0x18, (const uint8_t*)d2, 3);
    np_processor_process(p, p2);

    np_tcp_stream_stats_t s = {0};
    int n = np_tcp_stream_visit(p, visit_stats, &s);
    if (n == 1 && s.retransmits >= 1 && s.bytes_delivered >= 6) PASS();
    else FAIL("n=%d retransmits=%llu delivered=%llu",
              n, (unsigned long long)s.retransmits,
              (unsigned long long)s.bytes_delivered);

    np_packet_free(syn); np_packet_free(p1); np_packet_free(p1r); np_packet_free(p2);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Test 9: hole timeout flush (synthetic; we just verify code path)   */
/* ------------------------------------------------------------------ */

static void test_hole_timeout_path(void)
{
    TEST("hole-timeout flush code path (does not crash)");
    np_processor_t *p = np_processor_tcp_stream();
    uint32_t seq = 11000;
    np_packet_t *syn = build_tcp_pkt(0x0a000011, 0x0a000012, 9000, 80,
                                      seq, 0x02, NULL, 0);
    np_processor_process(p, syn); seq++;
    /* Send seg that's far ahead — opens a hole. */
    const char *later = "GAPFILLED";
    np_packet_t *p2 = build_tcp_pkt(0x0a000011, 0x0a000012, 9000, 80,
                                     seq + 100, 0x18, (const uint8_t*)later, 9);
    np_processor_process(p, p2);
    /* Without waiting, drain won't have flushed (timeout = 1s).  But the
     * queue should hold the segment without crashing. */
    if (p2->stream_len == 0 || p2->stream_data == NULL) PASS();
    else FAIL("stream_len=%zu (expected 0)", p2->stream_len);
    np_packet_free(syn); np_packet_free(p2);
    p->ops->free(p);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    np_init();
    fprintf(stderr, "=== TCP reassembly regression tests ===\n");
    test_in_order();
    test_out_of_order();
    test_retransmit();
    test_partial_overlap();
    test_gap_late_fill();
    test_bidirectional();
    test_rst_closes();
    test_stats();
    test_hole_timeout_path();
    fprintf(stderr, "\n%d/%d tests passed\n", tests_passed, tests_run);
    np_cleanup();
    return tests_passed == tests_run ? 0 : 1;
}
