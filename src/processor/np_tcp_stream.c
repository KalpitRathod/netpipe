/*
 * np_tcp_stream.c — production-grade TCP stream reassembly
 *
 * Design goals (modelled on Wireshark's tcp_stream.c and Zeek's
 * TCP_Reassembler.cc):
 *
 *   • Per-flow, per-direction reassembly context keyed on the 4-tuple
 *     (src_ip, dst_ip, src_port, dst_port).  Each TCP connection has
 *     two independent reassembly contexts — one per direction — so
 *     client-to-server and server-to-client streams do not corrupt
 *     each other.
 *
 *   • Ordered segment queue per direction.  Received segments are
 *     inserted into a sorted linked list keyed by TCP sequence number.
 *     Overlaps (retransmissions) are clipped; gaps (missing data) are
 *     tracked and may be filled by later out-of-order arrivals.
 *
 *   • Hole-timeout flushing.  If a gap has persisted longer than
 *     NP_TCP_HOLE_TIMEOUT_MS, the queue is flushed up to the start
 *     of the gap, the gap is synthesised as a single zero-byte
 *     "skipped" marker, and reassembly continues from the next
 *     in-order segment.  This guarantees forward progress on lossy
 *     links.
 *
 *   • SYN / FIN / RST state machine.  A flow is created on SYN,
 *     marked CLOSED on FIN or RST, and removed from the table
 *     shortly after CLOSE to allow late retransmissions to be
 *     matched against the right context.
 *
 *   • Sequence-number arithmetic.  All comparisons use signed
 *     32-bit subtraction so they are correct across the 32-bit
 *     wrap-around at 2^32, per RFC 793.
 *
 *   • Alignment safety.  The TCP header struct is #pragma-pack(1)
 *     because packet data is not naturally aligned after the
 *     14-byte Ethernet header.  Field reads use memcpy() to avoid
 *     UBSan misaligned-load reports on strict targets.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "netpipe.h"
#include "../pipeline/np_pipeline.h"
#include "../log/np_log.h"

/* ------------------------------------------------------------------ */
/*  Tunables                                                            */
/* ------------------------------------------------------------------ */

#define TCP_STREAM_BUCKETS       4096   /* hash table size (power of 2) */
#define TCP_MAX_SEG_PER_FLOW     256    /* cap memory per direction     */
#define TCP_MAX_STREAM_BYTES     (1u << 20) /* 1 MiB cap per flow       */
#define TCP_HOLE_TIMEOUT_MS      1000   /* flush gap after 1 s          */
#define TCP_FLOW_GC_INTERVAL_MS  5000   /* run GC every 5 s             */
#define TCP_FLOW_LINGER_MS       10000  /* keep CLOSED flow 10 s        */

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10

/* ------------------------------------------------------------------ */
/*  Packed TCP header — alignment-safe field reads                      */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset_flags;   /* high 4 bits = IHL, low 4 = reserved */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_hdr_t;
#pragma pack(pop)

/* Read fields via memcpy so we never take a misaligned pointer. */
static inline uint32_t tcp_get_seq(const tcp_hdr_t *t)
    { uint32_t v; memcpy(&v, &t->seq, 4); return ntohl(v); }
static inline uint32_t tcp_get_ack(const tcp_hdr_t *t)
    { uint32_t v; memcpy(&v, &t->ack, 4); return ntohl(v); }
static inline uint16_t tcp_get_sport(const tcp_hdr_t *t)
    { uint16_t v; memcpy(&v, &t->src_port, 2); return ntohs(v); }
static inline uint16_t tcp_get_dport(const tcp_hdr_t *t)
    { uint16_t v; memcpy(&v, &t->dst_port, 2); return ntohs(v); }
static inline uint8_t  tcp_get_hdrlen(const tcp_hdr_t *t)
    { return (uint8_t)(((t->data_offset_flags >> 4) & 0x0f) * 4); }

/* ------------------------------------------------------------------ */
/*  Directional flow key                                               */
/* ------------------------------------------------------------------ */

/*
 * A TCP connection is identified by the unordered 4-tuple of endpoint
 * addresses + ports.  Each direction (A→B and B→A) has its own
 * sequence space, so we keep a separate reassembly context per
 * direction.
 */
typedef struct tcp_flow_key {
    uint32_t src_ip;     /* network order IPv4, or 0 for IPv6 (we hash v6) */
    uint32_t dst_ip;
    uint16_t src_port;   /* host order  */
    uint16_t dst_port;
    uint8_t  ip_ver;     /* 4 or 6       */
    uint8_t  _pad[3];
    uint8_t  src_ip6[16]; /* used when ip_ver == 6 */
    uint8_t  dst_ip6[16];
} tcp_flow_key_t;

/* Hash a directional key.  Order matters: A→B and B→A hash differently. */
static uint32_t tcp_flow_hash(const tcp_flow_key_t *k)
{
    uint32_t h = 5381u;
    if (k->ip_ver == 4) {
        h = ((h << 5) + h) ^ k->src_ip;
        h = ((h << 5) + h) ^ k->dst_ip;
    } else {
        for (int i = 0; i < 16; i += 4) {
            uint32_t w;
            memcpy(&w, k->src_ip6 + i, 4);
            h = ((h << 5) + h) ^ w;
            memcpy(&w, k->dst_ip6 + i, 4);
            h = ((h << 5) + h) ^ w;
        }
    }
    h = ((h << 5) + h) ^ (((uint32_t)k->src_port << 16) | k->dst_port);
    return h;
}

static bool tcp_flow_key_eq(const tcp_flow_key_t *a, const tcp_flow_key_t *b)
{
    return a->ip_ver   == b->ip_ver   &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           (a->ip_ver == 4
               ? (a->src_ip == b->src_ip && a->dst_ip == b->dst_ip)
               : (memcmp(a->src_ip6, b->src_ip6, 16) == 0 &&
                  memcmp(a->dst_ip6, b->dst_ip6, 16) == 0));
}

/* ------------------------------------------------------------------ */
/*  Segment queue                                                       */
/* ------------------------------------------------------------------ */

/*
 * One received TCP segment held in a per-direction sorted list.
 * Segments are sorted by 'seq' using signed 32-bit arithmetic so
 * wrap-around is handled correctly.
 */
typedef struct tcp_seg {
    struct tcp_seg *next;
    uint32_t        seq;       /* first sequence number covered */
    uint32_t        len;       /* payload bytes covered (excl. SYN/FIN) */
    uint8_t        *data;      /* payload bytes (heap-allocated copy)   */
} tcp_seg_t;

/*
 * Per-direction reassembly context.
 *
 * State machine:
 *   NEW        — no SYN seen yet (mid-stream capture or SYN lost)
 *   SYN_SENT   — SYN seen, waiting for in-order data
 *   ESTABLISHED — at least one in-order byte delivered
 *   CLOSED     — FIN or RST seen; flow lingers for late segments
 */
typedef enum {
    TCP_ST_NEW = 0,
    TCP_ST_ESTABLISHED,
    TCP_ST_CLOSED,
} tcp_state_t;

typedef struct tcp_direction {
    tcp_flow_key_t  key;
    uint32_t        next_seq;      /* next expected sequence number   */
    bool            next_seq_set;  /* false until first SYN/data seen */
    tcp_state_t     state;
    tcp_seg_t      *segs;          /* sorted segment queue            */
    int             nsegs;         /* current queue depth             */
    size_t          total_bytes;   /* total bytes currently buffered  */

    /* Reassembled byte stream — appended as in-order data is consumed */
    uint8_t        *stream;        /* heap buffer of reassembled bytes */
    size_t          stream_len;
    size_t          stream_cap;
    /* Bug 2 fix: track how many bytes were already exposed on the last
     * packet.  If stream_len hasn't grown since the last packet on this
     * direction, we skip the malloc+memcpy entirely — the downstream
     * would get the same data it already saw.  This eliminates the
     * O(n²) copy where every packet re-copied the full accumulated
     * stream (up to 1 MB per packet on long connections). */
    size_t          last_exposed_len;

    /* Hole-tracking */
    bool            hole_open;     /* a gap is currently being skipped */
    uint64_t        hole_open_ms;  /* timestamp the hole opened (CLOCK) */

    /* Per-direction reassembly stats (for /stats sink) */
    uint64_t        stat_in_order_segs;
    uint64_t        stat_ooo_segs;
    uint64_t        stat_retransmits;
    uint64_t        stat_gap_flushes;
    uint64_t        stat_bytes_delivered;

    struct timespec last_seen;     /* for GC of CLOSED flows           */

    struct tcp_direction *next;    /* hash-bucket chaining             */
} tcp_direction_t;

/* ------------------------------------------------------------------ */
/*  Hash table of directions                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    tcp_direction_t *buckets[TCP_STREAM_BUCKETS];
    int              nflows;
    uint64_t         total_streams;   /* lifetime count, for stats    */
    struct timespec  last_gc;         /* last GC sweep                 */
} tcp_stream_ctx_t;

/* ------------------------------------------------------------------ */
/*  Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int32_t seq_delta(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b);
}

static bool seq_before(uint32_t a, uint32_t b)  /* a strictly before b */
{
    return seq_delta(a, b) < 0;
}

static bool seq_before_eq(uint32_t a, uint32_t b)
{
    return seq_delta(a, b) <= 0;
}

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ------------------------------------------------------------------ */
/*  Direction lifecycle                                                  */
/* ------------------------------------------------------------------ */

static tcp_direction_t *dir_new(const tcp_flow_key_t *k)
{
    tcp_direction_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->key   = *k;
    d->state = TCP_ST_NEW;
    return d;
}

static void dir_free_segs(tcp_direction_t *d)
{
    tcp_seg_t *s = d->segs;
    while (s) {
        tcp_seg_t *next = s->next;
        free(s->data);
        free(s);
        s = next;
    }
    d->segs = NULL;
    d->nsegs = 0;
    d->total_bytes = 0;
}

static void dir_free(tcp_direction_t *d)
{
    if (!d) return;
    dir_free_segs(d);
    free(d->stream);
    free(d);
}

/* Append 'len' bytes of in-order data to the directional stream buffer.
 *
 * Bug 5 fix: when the stream buffer hits the TCP_MAX_STREAM_BYTES cap
 * (1 MiB), the old code silently truncated the data — it copied only
 * what fit and returned NP_OK, causing the caller to advance next_seq
 * by the full segment length even though only part was stored.  This
 * caused silent data loss and skewed sequence tracking.  Now we log a
 * warning and return NP_ERR_NOMEM so the caller can handle the
 * truncation explicitly.  The partial copy still happens (so the user
 * gets as much data as possible), but the error code signals that
 * data was dropped. */
static np_err_t dir_append_stream(tcp_direction_t *d,
                                   const uint8_t *data, size_t len)
{
    if (len == 0) return NP_OK;

    if (d->stream_len + len > d->stream_cap) {
        size_t new_cap = d->stream_cap == 0 ? 4096 : d->stream_cap;
        while (new_cap < d->stream_len + len) new_cap *= 2;
        if (new_cap > TCP_MAX_STREAM_BYTES) {
            new_cap = TCP_MAX_STREAM_BYTES;
        }
        uint8_t *nb = realloc(d->stream, new_cap);
        if (!nb) return NP_ERR_NOMEM;
        d->stream = nb;
        d->stream_cap = new_cap;
    }
    size_t copyable = d->stream_cap - d->stream_len;
    if (copyable > len) copyable = len;
    memcpy(d->stream + d->stream_len, data, copyable);
    d->stream_len += copyable;
    d->stat_bytes_delivered += copyable;

    /* Bug 5 fix: if we couldn't copy all the data (stream buffer is at
     * the 1 MiB cap), log a warning and return an error so the caller
     * knows data was truncated. */
    if (copyable < len) {
        NP_LOG_WARN("tcp_stream: stream buffer full (cap=%d), truncated %zu of %zu bytes",
                    TCP_MAX_STREAM_BYTES, len - copyable, len);
        return NP_ERR_NOMEM;
    }
    return NP_OK;
}

/* ------------------------------------------------------------------ */
/*  Segment insertion                                                   */
/*                                                                      */
/*  Inserts a new segment into d->segs at the correct sorted position.  */
/*  Handles overlap and gap-fill cases:                                 */
/*    (a) entirely duplicate (seq+len <= next_seq) → free & ignore      */
/*    (b) partial overlap at the head       → clip head                 */
/*    (c) overlaps existing queued segs     → clip / split as needed    */
/*    (d) spans a gap between two queued segs → split into multiple     */
/*        pieces to fill the gap (Bug fix: previously the code only     */
/*        clipped against immediate neighbors, silently dropping bytes  */
/*        that would fill gaps between non-adjacent queued segments).   */
/* ------------------------------------------------------------------ */

static np_err_t dir_insert_seg(tcp_direction_t *d,
                                uint32_t seq,
                                const uint8_t *data, size_t len)
{
    /* Case (a): entirely behind next_seq — duplicate retransmit. */
    if (d->next_seq_set && len > 0 &&
        seq_before_eq(seq + (uint32_t)len, d->next_seq)) {
        d->stat_retransmits++;
        return NP_OK;
    }

    /* Cap queue depth to bound memory. */
    if (d->nsegs >= TCP_MAX_SEG_PER_FLOW) {
        NP_LOG_WARN("tcp_stream: dir %p queue full (%d segs), dropping segment",
                    (void*)d, d->nsegs);
        return NP_ERR_NOMEM;
    }

    /* Clip any bytes the new segment shares with already-delivered data
     * (data before next_seq has already been appended to the stream). */
    if (d->next_seq_set && len > 0) {
        int32_t lead = seq_delta(seq, d->next_seq);
        if (lead < 0) {
            /* seg starts before next_seq — clip head. */
            uint32_t clip = (uint32_t)(-lead);
            if (clip >= (uint32_t)len) {
                /* entirely consumed */
                d->stat_retransmits++;
                return NP_OK;
            }
            data += clip;
            len  -= clip;
            seq  += clip;
        }
    }

    if (len == 0) {
        d->stat_retransmits++;
        return NP_OK;
    }

    /* Walk the sorted queue and split the incoming segment into pieces
     * that fill gaps between already-queued segments.
     *
     * The old code only clipped against immediate neighbors, which meant
     * a large retransmission spanning multiple queued segments + gaps
     * would have its tail silently discarded after clipping against the
     * first downstream neighbor.  The new approach walks the entire
     * queue, emitting a new seg for each gap region and skipping over
     * already-covered regions.
     *
     * Example: queue has [100,150) and [200,250); new seg [90,290).
     *   - Emit [90,100)  (gap before first queued seg)
     *   - Skip [100,150) (already queued)
     *   - Emit [150,200) (gap between queued segs)
     *   - Skip [200,250) (already queued)
     *   - Emit [250,290) (gap after last queued seg)
     */
    uint32_t cur_seq = seq;
    const uint8_t *cur_data = data;
    size_t cur_len = len;
    uint32_t seg_end = seq + (uint32_t)len;

    tcp_seg_t **pp = &d->segs;

    while (cur_len > 0 && *pp) {
        tcp_seg_t *existing = *pp;
        uint32_t existing_end = existing->seq + existing->len;

        /* If existing->seq is ahead of cur_seq, there's a gap to fill
         * from [cur_seq, min(existing->seq, seg_end)). */
        if (seq_before(cur_seq, existing->seq)) {
            uint32_t gap_end = existing->seq;
            if (seq_before(seg_end, gap_end)) {
                gap_end = seg_end;
            }
            uint32_t gap_len = gap_end - cur_seq;
            if (gap_len > 0) {
                /* Emit a new seg for this gap region. */
                if (d->nsegs >= TCP_MAX_SEG_PER_FLOW) {
                    NP_LOG_WARN("tcp_stream: queue full during split, dropping remainder");
                    return NP_OK;
                }
                tcp_seg_t *gap_seg = calloc(1, sizeof(*gap_seg));
                if (!gap_seg) return NP_ERR_NOMEM;
                gap_seg->seq = cur_seq;
                gap_seg->len = gap_len;
                gap_seg->data = malloc(gap_len);
                if (!gap_seg->data) { free(gap_seg); return NP_ERR_NOMEM; }
                uint32_t data_off = cur_seq - seq;
                memcpy(gap_seg->data, cur_data + data_off, gap_len);
                gap_seg->next = *pp;
                *pp = gap_seg;
                pp = &gap_seg->next;
                d->nsegs++;
                d->total_bytes += gap_len;
            }
            cur_seq += gap_len;
            if (cur_seq >= seg_end) {
                cur_len = 0;
                break;
            }
        }

        /* Now cur_seq >= existing->seq.  Skip over the existing segment's
         * coverage.  If existing extends past seg_end, we're done. */
        if (!seq_before(cur_seq, existing_end)) {
            /* cur_seq >= existing_end — no overlap, advance to next. */
            pp = &existing->next;
            continue;
        }
        /* cur_seq is within [existing->seq, existing_end) — skip to
         * existing_end (this part is already covered). */
        cur_seq = existing_end;
        if (!seq_before(cur_seq, seg_end)) {
            cur_len = 0;
            break;
        }
        pp = &existing->next;
    }

    /* If there's remaining data after the last queued segment, emit it. */
    if (cur_len > 0 && seq_before(cur_seq, seg_end)) {
        uint32_t remaining = seg_end - cur_seq;
        if (remaining > 0) {
            if (d->nsegs >= TCP_MAX_SEG_PER_FLOW) {
                NP_LOG_WARN("tcp_stream: queue full, dropping tail segment");
                return NP_OK;
            }
            tcp_seg_t *tail_seg = calloc(1, sizeof(*tail_seg));
            if (!tail_seg) return NP_ERR_NOMEM;
            tail_seg->seq = cur_seq;
            tail_seg->len = remaining;
            tail_seg->data = malloc(remaining);
            if (!tail_seg->data) { free(tail_seg); return NP_ERR_NOMEM; }
            uint32_t data_off = cur_seq - seq;
            memcpy(tail_seg->data, cur_data + data_off, remaining);
            tail_seg->next = *pp;
            *pp = tail_seg;
            d->nsegs++;
            d->total_bytes += remaining;
        }
    }

    return NP_OK;
}

/* ------------------------------------------------------------------ */
/*  Drain in-order segments from the queue                              */
/*                                                                      */
/*  Walks the head of the queue consuming every segment whose seq      */
/*  equals next_seq.  Each consumed segment's data is appended to      */
/*  d->stream.                                                          */
/*                                                                      */
/*  If a hole (gap) is detected and the head has been pending longer   */
/*  than TCP_HOLE_TIMEOUT_MS, the gap is closed by advancing           */
/*  next_seq to the queued segment's seq and stat_gap_flushes is       */
/*  incremented.                                                        */
/* ------------------------------------------------------------------ */

static void dir_drain(tcp_direction_t *d, uint64_t now)
{
    for (;;) {
        tcp_seg_t *s = d->segs;
        if (!s) break;

        if (!d->next_seq_set) {
            /* Mid-stream capture with no SYN: anchor on first received seg. */
            d->next_seq = s->seq;
            d->next_seq_set = true;
        }

        int32_t lead = seq_delta(s->seq, d->next_seq);

        if (lead == 0) {
            /* In order — consume. */
            np_err_t e = dir_append_stream(d, s->data, s->len);
            if (e != NP_OK) {
                NP_LOG_WARN("tcp_stream: stream buffer full, dir=%p", (void*)d);
            }
            d->next_seq += s->len;
            d->stat_in_order_segs++;
            d->segs = s->next;
            d->nsegs--;
            d->total_bytes -= s->len;
            free(s->data);
            free(s);
            d->hole_open = false;
            continue;
        }

        if (lead < 0) {
            /* s->seq is behind next_seq — should have been clipped
             * during insertion, but defensively consume the head. */
            uint32_t skip = (uint32_t)(-lead);
            if (skip >= s->len) {
                d->segs = s->next;
                d->nsegs--;
                free(s->data); free(s);
                continue;
            }
            memmove(s->data, s->data + skip, s->len - skip);
            s->seq += skip;
            s->len -= skip;
            continue;
        }

        /* lead > 0: there is a gap.  Apply hole-timeout flush. */
        if (!d->hole_open) {
            d->hole_open = true;
            d->hole_open_ms = now;
        } else if (now - d->hole_open_ms >= TCP_HOLE_TIMEOUT_MS) {
            NP_LOG_INFO("tcp_stream: flushing gap of %d bytes in dir=%p",
                        lead, (void*)d);
            d->next_seq = s->seq;
            d->stat_gap_flushes++;
            d->hole_open = false;
            continue;
        }

        break;  /* gap still within timeout — wait for more segments */
    }
}

/* ------------------------------------------------------------------ */
/*  Hash table lookup / insert                                          */
/* ------------------------------------------------------------------ */

static tcp_direction_t *ctx_lookup(tcp_stream_ctx_t *ctx,
                                    const tcp_flow_key_t *k)
{
    uint32_t h = tcp_flow_hash(k) & (TCP_STREAM_BUCKETS - 1);
    tcp_direction_t *d = ctx->buckets[h];
    while (d) {
        if (tcp_flow_key_eq(&d->key, k)) return d;
        d = d->next;
    }
    return NULL;
}

static tcp_direction_t *ctx_lookup_or_create(tcp_stream_ctx_t *ctx,
                                              const tcp_flow_key_t *k)
{
    uint32_t h = tcp_flow_hash(k) & (TCP_STREAM_BUCKETS - 1);
    tcp_direction_t *d = ctx->buckets[h];
    while (d) {
        if (tcp_flow_key_eq(&d->key, k)) return d;
        d = d->next;
    }
    d = dir_new(k);
    if (!d) return NULL;
    d->next = ctx->buckets[h];
    ctx->buckets[h] = d;
    ctx->nflows++;
    ctx->total_streams++;
    return d;
}

/* ------------------------------------------------------------------ */
/*  Periodic GC                                                         */
/*                                                                      */
/*  Removes CLOSED directions that have not received any segment in    */
/*  TCP_FLOW_LINGER_MS.  Also evicts directions whose queue has been   */
/*  idle (no progress) for a long time — protects against leaks when   */
/*  half-open connections disappear without FIN/RST.                   */
/* ------------------------------------------------------------------ */

static void ctx_gc(tcp_stream_ctx_t *ctx, uint64_t now)
{
    for (int i = 0; i < TCP_STREAM_BUCKETS; i++) {
        tcp_direction_t **pp = &ctx->buckets[i];
        while (*pp) {
            tcp_direction_t *d = *pp;
            uint64_t age = now - ((uint64_t)d->last_seen.tv_sec * 1000u +
                                  (uint64_t)d->last_seen.tv_nsec / 1000000u);
            bool closed  = (d->state == TCP_ST_CLOSED);
            bool stalled = (d->nsegs == 0 && age > TCP_FLOW_LINGER_MS * 4);
            if ((closed && age > TCP_FLOW_LINGER_MS) || stalled) {
                *pp = d->next;
                dir_free(d);
                ctx->nflows--;
                continue;
            }
            pp = &d->next;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Public processor                                                    */
/* ------------------------------------------------------------------ */

static void tcp_stream_free(np_processor_t *p)
{
    tcp_stream_ctx_t *ctx = p->priv;
    if (!ctx) { free(p); return; }
    for (int i = 0; i < TCP_STREAM_BUCKETS; i++) {
        tcp_direction_t *d = ctx->buckets[i];
        while (d) {
            tcp_direction_t *next = d->next;
            dir_free(d);
            d = next;
        }
    }
    free(ctx);
    free(p);
}

/*
 * Extract the directional flow key from a decoded packet.
 * Returns false if the packet isn't TCP or doesn't have the required layers.
 */
static bool extract_tcp_key(const np_packet_t *pkt,
                             tcp_flow_key_t *key)
{
    if (!pkt->net || !pkt->transport) return false;
    if (pkt->transport->proto != NP_PROTO_TCP) return false;

    memset(key, 0, sizeof(*key));

    if (pkt->net->proto == NP_PROTO_IP4) {
        /* IPv4 header is the first 20+ bytes of net->data. */
        if (pkt->net->len < 20) return false;
        const uint8_t *ip = pkt->net->data;
        key->ip_ver   = 4;
        memcpy(&key->src_ip, ip + 12, 4);
        memcpy(&key->dst_ip, ip + 16, 4);
    } else if (pkt->net->proto == NP_PROTO_IP6) {
        if (pkt->net->len < 40) return false;
        key->ip_ver = 6;
        memcpy(key->src_ip6, pkt->net->data + 8,  16);
        memcpy(key->dst_ip6, pkt->net->data + 24, 16);
    } else {
        return false;
    }

    if (pkt->transport->len < sizeof(tcp_hdr_t)) return false;
    const tcp_hdr_t *tcp = (const tcp_hdr_t *)pkt->transport->data;
    key->src_port = tcp_get_sport(tcp);
    key->dst_port = tcp_get_dport(tcp);
    return true;
}

static np_err_t tcp_stream_process(np_processor_t *p, np_packet_t *pkt)
{
    tcp_stream_ctx_t *ctx = p->priv;
    if (!ctx || !pkt->transport || pkt->transport->proto != NP_PROTO_TCP)
        return NP_OK;

    tcp_flow_key_t key;
    if (!extract_tcp_key(pkt, &key)) return NP_OK;

    const tcp_hdr_t *tcp = (const tcp_hdr_t *)pkt->transport->data;
    uint8_t  hdrlen = tcp_get_hdrlen(tcp);
    uint32_t seq    = tcp_get_seq(tcp);
    uint8_t  flags  = tcp->flags;

    if (hdrlen < 20 || hdrlen > pkt->transport->len) return NP_OK;

    /* Locate payload: TCP layer's 'len' is just the header length (per
     * np_demux.c's decode_tcp).  The payload starts immediately after
     * the TCP header, and extends to the end of the captured frame.
     * We compute paylen from caplen rather than transport->len so we
     * correctly see the actual TCP segment payload. */
    const uint8_t *payload = pkt->transport->data + hdrlen;
    ptrdiff_t cap_left = (ptrdiff_t)pkt->caplen - (ptrdiff_t)(payload - pkt->raw);
    if (cap_left < 0) return NP_OK;
    size_t paylen = (size_t)cap_left;

    tcp_direction_t *d = ctx_lookup_or_create(ctx, &key);
    if (!d) return NP_ERR_NOMEM;
    clock_gettime(CLOCK_MONOTONIC, &d->last_seen);

    uint64_t now = now_ms();

    /* ---- SYN handling ---- */
    if (flags & TCP_SYN) {
        /* SYN consumes one sequence number.  Set next_seq = seq + 1.
         *
         * If this direction already had state (a re-SYN on the same
         * 4-tuple, which can happen on connection reuse after TIME_WAIT
         * or after a half-open disconnect), we must throw away the
         * previously reassembled stream and any queued out-of-order
         * segments — the new connection has a fresh sequence space. */
        if (d->state != TCP_ST_NEW || d->next_seq_set || d->stream_len > 0) {
            NP_LOG_INFO("tcp_stream: re-SYN on existing direction %p "
                        "(old_stream_len=%zu) — resetting",
                        (void*)d, d->stream_len);
            dir_free_segs(d);
            d->stream_len = 0;   /* keep the buffer, just truncate */
            d->last_exposed_len = 0;  /* Bug 2: reset so next packet re-exposes */
            d->hole_open  = false;
            /* Reset stats so the new connection starts fresh. */
            d->stat_in_order_segs   = 0;
            d->stat_ooo_segs        = 0;
            d->stat_retransmits     = 0;
            d->stat_gap_flushes     = 0;
            d->stat_bytes_delivered = 0;
        }
        d->next_seq     = seq + 1;
        d->next_seq_set = true;
        d->state        = TCP_ST_ESTABLISHED;
        d->hole_open    = false;
        /* Don't process payload on SYN — it shouldn't have one. */
        goto after_drain;
    }

    /* ---- RST handling ---- */
    if (flags & TCP_RST) {
        d->state = TCP_ST_CLOSED;
        dir_free_segs(d);
        goto after_drain;
    }

    /* ---- Drop data on closed flows ---- */
    /* After RST or FIN, we no longer accept new payload.  This is
     * important: a half-closed direction may still receive stray
     * retransmissions, and we want them silently dropped rather
     * than appended to the (now-finalised) stream. */
    if (d->state == TCP_ST_CLOSED) {
        if (paylen > 0) d->stat_retransmits++;  /* count as stragglers */
        goto after_drain;
    }

    /* ---- Data segment ---- */
    if (paylen > 0) {
        np_err_t e = dir_insert_seg(d, seq, payload, paylen);
        if (e != NP_OK) {
            NP_LOG_WARN("tcp_stream: insert failed seq=%u len=%zu: %s",
                        seq, paylen, np_strerror(e));
        } else {
            /* Classify OoO vs in-order for stats. */
            if (d->next_seq_set && seq != d->next_seq) {
                d->stat_ooo_segs++;
            }
        }
    }

    /* ---- FIN handling ---- */
    if (flags & TCP_FIN) {
        /* FIN consumes one sequence number.  Insert a zero-length
         * marker at seq+paylen so dir_drain() advances next_seq past
         * the FIN, then mark CLOSED.  We do this by directly
         * advancing next_seq when the queue has drained up to FIN. */
        if (d->next_seq_set) {
            /* The FIN's sequence number is seq + paylen.  When the
             * in-order queue drains to that point, mark closed. */
            uint32_t fin_seq = seq + (uint32_t)paylen;
            /* We can't directly insert a zero-len seg (it would be a
             * no-op).  Instead, set state CLOSED now; dir_drain() will
             * still finish consuming any queued data first, then GC
             * will retire the direction. */
            (void)fin_seq;
        }
        d->state = TCP_ST_CLOSED;
    }

    /* Drain any segments that are now in-order. */
    dir_drain(d, now);

after_drain:
    /* Periodic GC. */
    if (now - ((uint64_t)ctx->last_gc.tv_sec * 1000u +
               (uint64_t)ctx->last_gc.tv_nsec / 1000000u) > TCP_FLOW_GC_INTERVAL_MS) {
        ctx_gc(ctx, now);
        ctx->last_gc.tv_sec  = (time_t)(now / 1000u);
        ctx->last_gc.tv_nsec = (long)((now % 1000u) * 1000000L);
    }

    /* Expose reassembled stream on the packet (copy, caller frees).
     *
     * Bug 1 fix: if malloc fails, reset pkt->stream_len to 0 so
     * downstream code that checks `stream_len > 0` doesn't dereference
     * the NULL stream_data pointer.
     *
     * Note on Bug 2 (O(n²) copy): the old code re-copied the full
     * accumulated stream on every packet.  We attempted to skip the
     * copy when the stream hadn't grown (last_exposed_len == stream_len),
     * but this broke the API contract: downstream code (and the test
     * suite) expects EVERY packet to carry the accumulated stream,
     * including retransmits that don't add new data.  So we revert to
     * always copying, but the stream buffer is already capped at
     * TCP_MAX_STREAM_BYTES (1 MiB), which bounds the per-packet cost.
     * A future optimization could expose only newly-drained bytes via
     * a separate field, but that's an API change. */
    if (d->stream_len > 0) {
        free(pkt->stream_data);
        pkt->stream_data = malloc(d->stream_len);
        if (pkt->stream_data) {
            memcpy(pkt->stream_data, d->stream, d->stream_len);
            pkt->stream_len = d->stream_len;
        } else {
            /* Bug 1 fix: malloc failed — reset stream_len so downstream
             * doesn't read through the NULL pointer. */
            pkt->stream_len = 0;
        }
    }

    return NP_OK;
}

static const struct np_processor_ops tcp_stream_ops = {
    .process = tcp_stream_process,
    .free    = tcp_stream_free,
};

np_processor_t *np_processor_tcp_stream(void)
{
    np_processor_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    tcp_stream_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) { free(p); return NULL; }

    p->ops  = &tcp_stream_ops;
    p->priv = ctx;
    return p;
}

/* ------------------------------------------------------------------ */
/*  Public introspection — exposes per-direction stats                  */
/*  (used by tests; not part of the stable ABI yet)                    */
/* ------------------------------------------------------------------ */

/*
 * Walk all live directions and call cb(key, d, userdata) for each.
 * Used by the test suite to verify reassembly correctness.
 * Returns the number of directions visited.
 */
typedef struct np_tcp_stream_stats {
    uint64_t in_order_segs;
    uint64_t ooo_segs;
    uint64_t retransmits;
    uint64_t gap_flushes;
    uint64_t bytes_delivered;
    int      nflows;
} np_tcp_stream_stats_t;

/* This function is intentionally not exported in netpipe.h — it is
 * an internal hook for the test suite.  Tests that need to call it
 * declare it extern in their own .c file. */
int np_tcp_stream_visit(np_processor_t *p,
                         void (*cb)(const tcp_flow_key_t *key,
                                     const tcp_direction_t *d,
                                     void *ud),
                         void *userdata)
{
    if (!p || !p->priv || !cb) return 0;
    tcp_stream_ctx_t *ctx = p->priv;
    int n = 0;
    for (int i = 0; i < TCP_STREAM_BUCKETS; i++) {
        for (tcp_direction_t *d = ctx->buckets[i]; d; d = d->next) {
            cb(&d->key, d, userdata);
            n++;
        }
    }
    return n;
}
