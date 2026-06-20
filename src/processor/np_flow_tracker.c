#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "netpipe.h"
#include "../pipeline/np_pipeline.h"
#include "../log/np_log.h"

#define FLOW_BUCKETS 1024
#define FLOW_MAX_ENTRIES 1000000   /* Bug FT2 fix: hard cap against SYN-flood OOM */
#define FLOW_IDLE_TIMEOUT_S   60   /* evict flows idle > 60 s */
#define FLOW_GC_INTERVAL      1024 /* sweep every 1024 packets */

#pragma pack(push, 1)

typedef struct {
    uint8_t  version_ihl;
    uint8_t  dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} ip4_hdr_t;

typedef struct {
    uint32_t vcf;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
} ip6_hdr_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset_flags;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_hdr_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_hdr_t;

#pragma pack(pop)

typedef struct {
    uint8_t ip_ver;      /* 4 or 6 */
    uint8_t proto;       /* IPPROTO_TCP, IPPROTO_UDP, etc. */
    union {
        struct {
            struct in_addr low;
            struct in_addr high;
        } v4;
        struct {
            struct in6_addr low;
            struct in6_addr high;
        } v6;
    } ip;
    uint16_t port_low;
    uint16_t port_high;
} flow_key_t;

typedef struct {
    uint64_t pkts_l2h;
    uint64_t bytes_l2h;
    uint64_t pkts_h2l;
    uint64_t bytes_h2l;
    struct timespec first_seen;        /* capture timestamp (pkt->ts) — display only */
    struct timespec first_seen_wall;   /* Bug FT3 fix: wall-clock first-seen, for duration */
    struct timespec last_seen;         /* wall-clock last-seen (CLOCK_REALTIME) */
    uint8_t tcp_flags_seen;
} flow_stats_t;

typedef struct flow_node {
    flow_key_t key;
    flow_stats_t stats;
    struct flow_node *next;
} flow_node_t;

typedef struct {
    flow_node_t    *buckets[FLOW_BUCKETS];
    pthread_mutex_t lock;
    uint64_t        total_flows;
    uint64_t        sweep_counter;   /* for periodic GC (Bug 2.1) */
    uint64_t        flows_dropped;   /* Bug FT2 fix: count flows rejected due to cap */

    /* FIX (issue: hardcoded FLOW_MAX_ENTRIES / FLOW_IDLE_TIMEOUT_S):
     * tunable per-instance limits set by np_processor_flow_tracker_ex().
     * Zero means "use the historical default". */
    uint32_t        max_entries;
    uint32_t        idle_timeout_s;
} flow_tracker_ctx_t;

#define FLOW_GC_INTERVAL      1024 /* sweep every 1024 packets */

/* FIX (issue: hardcoded limits): per-instance tunable accessors. */
static inline uint32_t flow_max_entries(const flow_tracker_ctx_t *ctx) {
    return ctx && ctx->max_entries ? ctx->max_entries
                                   : (uint32_t)FLOW_MAX_ENTRIES;
}
static inline uint32_t flow_idle_timeout_s(const flow_tracker_ctx_t *ctx) {
    return ctx && ctx->idle_timeout_s ? ctx->idle_timeout_s
                                      : (uint32_t)FLOW_IDLE_TIMEOUT_S;
}

/* Helper to compare flow keys */
static bool flow_key_match(const flow_key_t *a, const flow_key_t *b)
{
    if (a->ip_ver != b->ip_ver || a->proto != b->proto) return false;
    if (a->port_low != b->port_low || a->port_high != b->port_high) return false;

    if (a->ip_ver == 4) {
        return (a->ip.v4.low.s_addr == b->ip.v4.low.s_addr &&
                a->ip.v4.high.s_addr == b->ip.v4.high.s_addr);
    } else {
        return (memcmp(&a->ip.v6.low, &b->ip.v6.low, 16) == 0 &&
                memcmp(&a->ip.v6.high, &b->ip.v6.high, 16) == 0);
    }
}

/* djb2 hash helper for flow key */
static uint32_t flow_key_hash(const flow_key_t *key)
{
    uint32_t h = 5381;
    h = ((h << 5) + h) + key->ip_ver;
    h = ((h << 5) + h) + key->proto;
    h = ((h << 5) + h) + key->port_low;
    h = ((h << 5) + h) + key->port_high;

    if (key->ip_ver == 4) {
        h = ((h << 5) + h) + (key->ip.v4.low.s_addr & 0xFF);
        h = ((h << 5) + h) + ((key->ip.v4.low.s_addr >> 8) & 0xFF);
        h = ((h << 5) + h) + ((key->ip.v4.low.s_addr >> 16) & 0xFF);
        h = ((h << 5) + h) + ((key->ip.v4.low.s_addr >> 24) & 0xFF);
        h = ((h << 5) + h) + (key->ip.v4.high.s_addr & 0xFF);
        h = ((h << 5) + h) + ((key->ip.v4.high.s_addr >> 8) & 0xFF);
        h = ((h << 5) + h) + ((key->ip.v4.high.s_addr >> 16) & 0xFF);
        h = ((h << 5) + h) + ((key->ip.v4.high.s_addr >> 24) & 0xFF);
    } else {
        for (int i = 0; i < 16; i++) {
            h = ((h << 5) + h) + key->ip.v6.low.s6_addr[i];
            h = ((h << 5) + h) + key->ip.v6.high.s6_addr[i];
        }
    }
    return h;
}

/* Format byte counts nicely */
static void format_bytes(uint64_t bytes, char *buf, size_t size)
{
    if (bytes < 1024) {
        snprintf(buf, size, "%lu B", (unsigned long)bytes);
    } else if (bytes < 1024 * 1024) {
        snprintf(buf, size, "%.1f KB", (double)bytes / 1024.0);
    } else {
        snprintf(buf, size, "%.1f MB", (double)bytes / (1024.0 * 1024.0));
    }
}

/* Format IPv6 addresses cleanly by omitting leading/trailing zeros if possible */
static void format_ip_port(const flow_key_t *key, bool high, char *buf, size_t size)
{
    char ip_str[64];
    uint16_t port;

    if (key->ip_ver == 4) {
        inet_ntop(AF_INET, high ? &key->ip.v4.high : &key->ip.v4.low, ip_str, sizeof(ip_str));
        port = high ? key->port_high : key->port_low;
        snprintf(buf, size, "%s:%u", ip_str, port);
    } else {
        inet_ntop(AF_INET6, high ? &key->ip.v6.high : &key->ip.v6.low, ip_str, sizeof(ip_str));
        port = high ? key->port_high : key->port_low;
        snprintf(buf, size, "[%s]:%u", ip_str, port);
    }
}

static void flow_tracker_free(np_processor_t *p)
{
    flow_tracker_ctx_t *ctx = p->priv;
    if (!ctx) return;

    pthread_mutex_lock(&ctx->lock);

    /* Print a gorgeous summary table of all tracked flows */
    printf("\n%s", "\033[1m=========================================================================================================\033[0m\n");
    printf("%s", "                                        \033[1;36mFLOW TRACKER SUMMARY\033[0m\n");
    printf("%s", "=========================================================================================================\n");
    printf("%-5s  %-32s  %-32s  %-14s  %-14s  %-8s\n",
           "PROTO", "LOW ENDPOINT", "HIGH ENDPOINT", "PKTS(L->H/H->L)", "BYTES(L->H/H->L)", "DURATION");
    printf("%s", "---------------------------------------------------------------------------------------------------------\n");

    for (int i = 0; i < FLOW_BUCKETS; i++) {
        flow_node_t *node = ctx->buckets[i];
        while (node) {
            flow_node_t *next = node->next;

            char low_endpoint[64];
            char high_endpoint[64];
            format_ip_port(&node->key, false, low_endpoint, sizeof(low_endpoint));
            format_ip_port(&node->key, true, high_endpoint, sizeof(high_endpoint));

            char bytes_lh_str[32];
            char bytes_hl_str[32];
            format_bytes(node->stats.bytes_l2h, bytes_lh_str, sizeof(bytes_lh_str));
            format_bytes(node->stats.bytes_h2l, bytes_hl_str, sizeof(bytes_hl_str));

            char pkts_str[32];
            char bytes_str[64];
            snprintf(pkts_str, sizeof(pkts_str), "%lu/%lu", (unsigned long)node->stats.pkts_l2h, (unsigned long)node->stats.pkts_h2l);
            snprintf(bytes_str, sizeof(bytes_str), "%s/%s", bytes_lh_str, bytes_hl_str);

            /* Bug FT3 fix: use wall-clock for both endpoints of the
             * duration calculation.  Using capture-timestamp for
             * first_seen and wall-clock for last_seen produced
             * multi-year "durations" on pcap replay. */
            double duration = (double)(node->stats.last_seen.tv_sec - node->stats.first_seen_wall.tv_sec) +
                              (double)(node->stats.last_seen.tv_nsec - node->stats.first_seen_wall.tv_nsec) / 1000000000.0;
            if (duration < 0) duration = 0;

            const char *proto_name = (node->key.proto == IPPROTO_TCP) ? "TCP" :
                                     (node->key.proto == IPPROTO_UDP) ? "UDP" : "IP";

            char tcp_flags_buf[64] = "";
            if (node->key.proto == IPPROTO_TCP) {
                snprintf(tcp_flags_buf, sizeof(tcp_flags_buf), " [%s%s%s%s]",
                         (node->stats.tcp_flags_seen & 0x02) ? "S" : "",
                         (node->stats.tcp_flags_seen & 0x10) ? "A" : "",
                         (node->stats.tcp_flags_seen & 0x01) ? "F" : "",
                         (node->stats.tcp_flags_seen & 0x04) ? "R" : "");
            }

            printf("%-5s  %-32s  %-32s  %-14s  %-14s  %7.3fs%s\n",
                   proto_name, low_endpoint, high_endpoint, pkts_str, bytes_str, duration, tcp_flags_buf);

            free(node);
            node = next;
        }
        ctx->buckets[i] = NULL;
    }

    printf("%s", "=========================================================================================================\n");
    printf("Total tracked flows: \033[1;32m%lu\033[0m",
           (unsigned long)ctx->total_flows);
    if (ctx->flows_dropped > 0) {
        printf("  (\033[1;31m%lu dropped due to %u-entry cap\033[0m)",
               (unsigned long)ctx->flows_dropped, flow_max_entries(ctx));
    }
    printf("\n\n");

    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
    free(p);
}

static np_err_t flow_tracker_process(np_processor_t *p, np_packet_t *pkt)
{
    flow_tracker_ctx_t *ctx = p->priv;
    if (!ctx || !pkt->net || !pkt->net->data) {
        return NP_OK;
    }

    /* Bug FT1 fix: bounds-check the network + transport layers BEFORE
     * casting their data pointers to packed-struct headers.  A malformed
     * packet (or a demuxer that sets len shorter than the struct) would
     * otherwise trigger an out-of-bounds read. */
    if (pkt->net->proto == NP_PROTO_IP4) {
        if (pkt->net->len < sizeof(ip4_hdr_t)) return NP_OK;
    } else if (pkt->net->proto == NP_PROTO_IP6) {
        if (pkt->net->len < sizeof(ip6_hdr_t)) return NP_OK;
    } else {
        return NP_OK;
    }
    if (pkt->transport && pkt->transport->data) {
        if (pkt->transport->proto == NP_PROTO_TCP &&
            pkt->transport->len < sizeof(tcp_hdr_t)) return NP_OK;
        if (pkt->transport->proto == NP_PROTO_UDP &&
            pkt->transport->len < sizeof(udp_hdr_t)) return NP_OK;
    }

    flow_key_t key;
    memset(&key, 0, sizeof(key));

    /* Bug: removed unused `is_ipv6` variable.  Both flags were computed
     * but only `is_ipv4` is used below — the IPv6 branch is selected
     * implicitly by `if (is_ipv4) ... else ...`. */
    bool is_ipv4 = (pkt->net->proto == NP_PROTO_IP4);

    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t tcp_flags = 0;
    uint8_t proto_val = 0;

    if (is_ipv4) {
        key.ip_ver = 4;
        const ip4_hdr_t *ip = (const ip4_hdr_t *)pkt->net->data;
        proto_val = ip->protocol;

        struct in_addr src_ip, dst_ip;
        src_ip.s_addr = ip->src;
        dst_ip.s_addr = ip->dst;

        if (src_ip.s_addr < dst_ip.s_addr) {
            key.ip.v4.low = src_ip;
            key.ip.v4.high = dst_ip;
        } else {
            key.ip.v4.low = dst_ip;
            key.ip.v4.high = src_ip;
        }
    } else {
        key.ip_ver = 6;
        const ip6_hdr_t *ip6 = (const ip6_hdr_t *)pkt->net->data;
        /* Bug 2.2: ip6->next_header is the raw next-header field from
         * the fixed IPv6 header.  If extension headers (Hop-by-Hop,
         * Routing, DestOpts, Fragment) are present, this field holds
         * the extension-header type, NOT the L4 protocol.  The demuxer
         * already walked the extension chain and found the real L4
         * protocol — we should use pkt->transport->proto instead. */
        if (pkt->transport) {
            if (pkt->transport->proto == NP_PROTO_TCP) {
                proto_val = 6;  /* IPPROTO_TCP */
            } else if (pkt->transport->proto == NP_PROTO_UDP) {
                proto_val = 17; /* IPPROTO_UDP */
            } else {
                proto_val = ip6->next_header;  /* ICMPv6, etc. */
            }
        } else {
            /* Bug FT4 fix: when there is no transport layer (e.g.
             * fragmented IPv6 packet whose L4 header isn't in this
             * fragment), proto_val would be set to the extension
             * header type (e.g. 44 = Fragment Header), splitting one
             * flow into many.  Skip these packets entirely. */
            return NP_OK;
        }

        struct in6_addr src_ip, dst_ip;
        memcpy(&src_ip, ip6->src, 16);
        memcpy(&dst_ip, ip6->dst, 16);

        if (memcmp(&src_ip, &dst_ip, 16) < 0) {
            key.ip.v6.low = src_ip;
            key.ip.v6.high = dst_ip;
        } else {
            key.ip.v6.low = dst_ip;
            key.ip.v6.high = src_ip;
        }
    }

    key.proto = proto_val;

    if (pkt->transport) {
        if (pkt->transport->proto == NP_PROTO_TCP) {
            const tcp_hdr_t *tcp = (const tcp_hdr_t *)pkt->transport->data;
            src_port = ntohs(tcp->src_port);
            dst_port = ntohs(tcp->dst_port);
            tcp_flags = tcp->flags;
        } else if (pkt->transport->proto == NP_PROTO_UDP) {
            const udp_hdr_t *udp = (const udp_hdr_t *)pkt->transport->data;
            src_port = ntohs(udp->src_port);
            dst_port = ntohs(udp->dst_port);
        }
    }

    /* Assign low/high ports in direction-independent manner */
    bool is_low_to_high = true;
    if (is_ipv4) {
        const ip4_hdr_t *ip = (const ip4_hdr_t *)pkt->net->data;
        if (ip->src < ip->dst) {
            key.port_low = src_port;
            key.port_high = dst_port;
            is_low_to_high = true;
        } else if (ip->src > ip->dst) {
            key.port_low = dst_port;
            key.port_high = src_port;
            is_low_to_high = false;
        } else {
            if (src_port <= dst_port) {
                key.port_low = src_port;
                key.port_high = dst_port;
                is_low_to_high = true;
            } else {
                key.port_low = dst_port;
                key.port_high = src_port;
                is_low_to_high = false;
            }
        }
    } else {
        const ip6_hdr_t *ip6 = (const ip6_hdr_t *)pkt->net->data;
        int cmp = memcmp(ip6->src, ip6->dst, 16);
        if (cmp < 0) {
            key.port_low = src_port;
            key.port_high = dst_port;
            is_low_to_high = true;
        } else if (cmp > 0) {
            key.port_low = dst_port;
            key.port_high = src_port;
            is_low_to_high = false;
        } else {
            if (src_port <= dst_port) {
                key.port_low = src_port;
                key.port_high = dst_port;
                is_low_to_high = true;
            } else {
                key.port_low = dst_port;
                key.port_high = src_port;
                is_low_to_high = false;
            }
        }
    }

    /* Find or insert flow */
    uint32_t h = flow_key_hash(&key);
    int bucket = (int)(h % FLOW_BUCKETS);

    pthread_mutex_lock(&ctx->lock);

    /* Bug 2.1: periodic GC to evict idle flows and prevent unbounded
     * memory growth on long captures.  Every FLOW_GC_INTERVAL packets,
     * we sweep the current bucket (localized, cheap) and evict any flow
     * whose last_seen is older than the configured idle timeout.
     *
     * Bug 15 fix: use wall-clock time (time(NULL)) instead of the
     * packet's capture timestamp.  The old code used pkt->ts.tv_sec,
     * which for a pcap file replay could be hours old (causing
     * premature eviction) or all the same (causing flows to never
     * be evicted).  For live capture, using packet timestamps meant
     * GC stopped when traffic stopped.  Wall-clock time is correct
     * in both cases. */
    uint32_t idle_to = flow_idle_timeout_s(ctx);   /* FIX: tunable */
    uint32_t max_flows = flow_max_entries(ctx);    /* FIX: tunable */
    ctx->sweep_counter++;
    if ((ctx->sweep_counter % FLOW_GC_INTERVAL) == 0) {
        time_t now_sec = time(NULL);
        int sweep_bucket = (int)(ctx->sweep_counter % FLOW_BUCKETS);
        flow_node_t **pp = &ctx->buckets[sweep_bucket];
        while (*pp) {
            flow_node_t *n = *pp;
            double age = difftime(now_sec, n->stats.last_seen.tv_sec);
            if (age > (double)idle_to) {
                *pp = n->next;
                free(n);
                ctx->total_flows--;
            } else {
                pp = &n->next;
            }
        }
    }

    /* Bug FT2 fix: hard cap on total flows.  Under a SYN flood with
     * random source IPs, new flows are created faster than the
     * per-bucket sweep can evict them (the sweep only touches 1/1024
     * of buckets per packet).  Without a cap, the table grows until
     * OOM.  When the cap is hit, we trigger an immediate FULL sweep
     * across all buckets; if that doesn't free enough, we drop the
     * new flow (counted for stats) and continue. */
    flow_node_t *node = ctx->buckets[bucket];
    while (node) {
        if (flow_key_match(&node->key, &key)) {
            break;
        }
        node = node->next;
    }

    if (!node) {
        if (ctx->total_flows >= max_flows) {
            /* Emergency full sweep */
            time_t now_sec = time(NULL);
            for (int i = 0; i < FLOW_BUCKETS; i++) {
                flow_node_t **pp = &ctx->buckets[i];
                while (*pp) {
                    flow_node_t *n = *pp;
                    double age = difftime(now_sec, n->stats.last_seen.tv_sec);
                    if (age > (double)idle_to) {
                        *pp = n->next;
                        free(n);
                        ctx->total_flows--;
                    } else {
                        pp = &n->next;
                    }
                }
            }
        }

        if (ctx->total_flows >= max_flows) {
            /* Still at cap after sweep — drop the new flow rather than OOM. */
            ctx->flows_dropped++;
            pthread_mutex_unlock(&ctx->lock);
            return NP_OK;
        }

        node = calloc(1, sizeof(*node));
        if (!node) {
            pthread_mutex_unlock(&ctx->lock);
            return NP_ERR_NOMEM;
        }
        node->key = key;
        node->stats.first_seen = pkt->ts;
        clock_gettime(CLOCK_REALTIME, &node->stats.first_seen_wall);
        node->next = ctx->buckets[bucket];
        ctx->buckets[bucket] = node;
        ctx->total_flows++;

        /* Log the discovery of a new flow */
        char low_str[64];
        char high_str[64];
        format_ip_port(&key, false, low_str, sizeof(low_str));
        format_ip_port(&key, true, high_str, sizeof(high_str));
        const char *proto_name = (key.proto == IPPROTO_TCP) ? "TCP" :
                                 (key.proto == IPPROTO_UDP) ? "UDP" : "IP";
        NP_LOG_INFO("New Flow Tracked: %s %s <-> %s", proto_name, low_str, high_str);
    }

    /* Bug 3 fix: write WALL-CLOCK time (CLOCK_REALTIME) to last_seen,
     * not the packet's capture timestamp.  The GC sweep compares
     * last_seen against time(NULL) (wall clock), so mixing the two
     * caused immediate eviction on pcap replays (where pkt->ts is the
     * original capture time, potentially years in the past) and
     * prevented eviction on live captures when traffic stopped.
     * first_seen is kept as pkt->ts for reporting purposes (it's the
     * packet's actual capture time, which is what users expect to see
     * in flow summaries).  first_seen_wall is used for duration math. */
    clock_gettime(CLOCK_REALTIME, &node->stats.last_seen);
    if (is_low_to_high) {
        node->stats.pkts_l2h++;
        node->stats.bytes_l2h += pkt->caplen;
    } else {
        node->stats.pkts_h2l++;
        node->stats.bytes_h2l += pkt->caplen;
    }

    if (key.proto == IPPROTO_TCP) {
        node->stats.tcp_flags_seen |= tcp_flags;
    }

    pthread_mutex_unlock(&ctx->lock);

    return NP_OK;
}

static const struct np_processor_ops flow_tracker_ops = {
    .process = flow_tracker_process,
    .free    = flow_tracker_free,
};

np_processor_t *np_processor_flow_tracker(void)
{
    return np_processor_flow_tracker_ex(0, 0);
}

np_processor_t *np_processor_flow_tracker_ex(uint32_t max_entries,
                                              uint32_t idle_timeout_s)
{
    np_processor_t *p = malloc(sizeof(*p));
    if (!p) return NULL;

    flow_tracker_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        free(p);
        return NULL;
    }

    /* FIX (issue: hardcoded FLOW_MAX_ENTRIES / FLOW_IDLE_TIMEOUT_S):
     * store the caller-supplied values; the accessor functions fall
     * back to the historical defaults when these are 0. */
    ctx->max_entries    = max_entries;
    ctx->idle_timeout_s = idle_timeout_s;
    if (max_entries != 0) {
        NP_LOG_INFO("flow_tracker: max entries = %u (default 1,000,000)",
                    max_entries);
    }
    if (idle_timeout_s != 0) {
        NP_LOG_INFO("flow_tracker: idle timeout = %u s (default 60)",
                    idle_timeout_s);
    }

    pthread_mutex_init(&ctx->lock, NULL);

    p->ops = &flow_tracker_ops;
    p->priv = ctx;

    return p;
}
