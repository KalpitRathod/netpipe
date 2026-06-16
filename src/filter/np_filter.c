/*
 * np_filter.c — filter implementations: BPF wrapper, proto, port, host, combinators
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"
#include "../pipeline/np_pipeline.h"

/* ------------------------------------------------------------------ */
/*  BPF filter (delegates to libpcap's BPF engine)                     */
/* ------------------------------------------------------------------ */

typedef struct {
    struct bpf_program prog;
    bool               compiled;
} bpf_priv_t;

static bool bpf_match(np_filter_t *f, const np_packet_t *pkt)
{
    bpf_priv_t *p = f->priv;
    if (!p->compiled) return true;
    struct pcap_pkthdr hdr = {
        .caplen = pkt->caplen,
        .len    = pkt->wirelen,
    };
    hdr.ts.tv_sec  = pkt->ts.tv_sec;
    hdr.ts.tv_usec = (suseconds_t)(pkt->ts.tv_nsec / 1000);
    return bpf_filter(p->prog.bf_insns, pkt->raw,
                      hdr.len, hdr.caplen) != 0;
}

static void bpf_free(np_filter_t *f)
{
    bpf_priv_t *p = f->priv;
    if (p->compiled) pcap_freecode(&p->prog);
    free(p);
    free(f);
}

static const struct np_filter_ops bpf_ops = { .match = bpf_match, .free = bpf_free };

np_filter_t *np_filter_bpf(const char *expr)
{
    bpf_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    pcap_t *dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (!dead) { free(p); return NULL; }
    int rc = pcap_compile(dead, &p->prog, expr, 1, PCAP_NETMASK_UNKNOWN);
    pcap_close(dead);
    if (rc != 0) {
        NP_LOG_ERROR("BPF compile failed: '%s'", expr);
        free(p);
        return NULL;
    }
    p->compiled = true;

    np_filter_t *f = calloc(1, sizeof(*f));
    if (!f) { pcap_freecode(&p->prog); free(p); return NULL; }
    f->ops  = &bpf_ops;
    f->priv = p;
    return f;
}

/* ------------------------------------------------------------------ */
/*  Protocol filter                                                     */
/* ------------------------------------------------------------------ */

typedef struct { np_proto_t proto; } proto_priv_t;

static bool proto_match(np_filter_t *f, const np_packet_t *pkt)
{
    proto_priv_t *p = f->priv;
    for (int i = 0; i < pkt->nlayers; i++)
        if (pkt->layers[i].proto == p->proto) return true;
    return false;
}
static void proto_free(np_filter_t *f) { free(f->priv); free(f); }
static const struct np_filter_ops proto_ops = { .match = proto_match, .free = proto_free };

np_filter_t *np_filter_proto(np_proto_t proto)
{
    proto_priv_t *p = malloc(sizeof(*p)); if (!p) return NULL;
    p->proto = proto;
    np_filter_t *f = calloc(1, sizeof(*f)); if (!f) { free(p); return NULL; }
    f->ops = &proto_ops; f->priv = p;
    return f;
}

/* ------------------------------------------------------------------ */
/*  Port filter                                                         */
/* ------------------------------------------------------------------ */

typedef struct { uint16_t port; } port_priv_t;

static bool port_match(np_filter_t *f, const np_packet_t *pkt)
{
    port_priv_t *p = f->priv;
    if (!pkt->transport) return false;

    const uint8_t *d = pkt->transport->data;
    size_t          l = pkt->transport->len;

    if (l < 4) return false;
    uint16_t sp = (uint16_t)((d[0] << 8) | d[1]);
    uint16_t dp = (uint16_t)((d[2] << 8) | d[3]);
    return sp == p->port || dp == p->port;
}
static void port_free(np_filter_t *f) { free(f->priv); free(f); }
static const struct np_filter_ops port_ops = { .match = port_match, .free = port_free };

np_filter_t *np_filter_port(uint16_t port)
{
    port_priv_t *p = malloc(sizeof(*p)); if (!p) return NULL;
    p->port = port;
    np_filter_t *f = calloc(1, sizeof(*f)); if (!f) { free(p); return NULL; }
    f->ops = &port_ops; f->priv = p;
    return f;
}

/* ------------------------------------------------------------------ */
/*  Host filter (IPv4 only for now)                                     */
/* ------------------------------------------------------------------ */

typedef struct { uint32_t addr; } host_priv_t;

static bool host_match(np_filter_t *f, const np_packet_t *pkt)
{
    host_priv_t *p = f->priv;
    if (!pkt->net || pkt->net->proto != NP_PROTO_IP4) return false;

    const uint8_t *ip = pkt->net->data;
    if (pkt->net->len < 20) return false;

    uint32_t src = ((uint32_t)ip[12] << 24) | ((uint32_t)ip[13] << 16) | ((uint32_t)ip[14] << 8) | ip[15];
    uint32_t dst = ((uint32_t)ip[16] << 24) | ((uint32_t)ip[17] << 16) | ((uint32_t)ip[18] << 8) | ip[19];
    return src == p->addr || dst == p->addr;
}
static void host_free(np_filter_t *f) { free(f->priv); free(f); }
static const struct np_filter_ops host_ops = { .match = host_match, .free = host_free };

np_filter_t *np_filter_host(const char *host)
{
    struct in_addr addr;
    if (inet_aton(host, &addr) == 0) {
        NP_LOG_ERROR("invalid host address: %s", host);
        return NULL;
    }
    host_priv_t *p = malloc(sizeof(*p)); if (!p) return NULL;
    p->addr = ntohl(addr.s_addr);
    np_filter_t *f = calloc(1, sizeof(*f)); if (!f) { free(p); return NULL; }
    f->ops = &host_ops; f->priv = p;
    return f;
}

/* ------------------------------------------------------------------ */
/*  Combinators: AND, OR, NOT                                           */
/* ------------------------------------------------------------------ */

typedef struct { np_filter_t *a, *b; } comb_priv_t;

static bool and_match(np_filter_t *f, const np_packet_t *pkt)
{
    comb_priv_t *p = f->priv;
    return p->a->ops->match(p->a, pkt) && p->b->ops->match(p->b, pkt);
}
static bool or_match(np_filter_t *f, const np_packet_t *pkt)
{
    comb_priv_t *p = f->priv;
    return p->a->ops->match(p->a, pkt) || p->b->ops->match(p->b, pkt);
}
static void comb_free(np_filter_t *f)
{
    comb_priv_t *p = f->priv;
    np_filter_free(p->a);
    np_filter_free(p->b);
    free(p); free(f);
}
static const struct np_filter_ops and_ops = { .match = and_match, .free = comb_free };
static const struct np_filter_ops or_ops  = { .match = or_match,  .free = comb_free };

static np_filter_t *comb_new(const struct np_filter_ops *ops,
                               np_filter_t *a, np_filter_t *b)
{
    comb_priv_t *p = malloc(sizeof(*p)); if (!p) return NULL;
    p->a = a; p->b = b;
    np_filter_t *f = calloc(1, sizeof(*f)); if (!f) { free(p); return NULL; }
    f->ops = ops; f->priv = p;
    return f;
}

np_filter_t *np_filter_and(np_filter_t *a, np_filter_t *b) { return comb_new(&and_ops, a, b); }
np_filter_t *np_filter_or (np_filter_t *a, np_filter_t *b) { return comb_new(&or_ops,  a, b); }

typedef struct { np_filter_t *inner; } not_priv_t;
static bool not_match(np_filter_t *f, const np_packet_t *pkt)
{
    not_priv_t *p = f->priv;
    return !p->inner->ops->match(p->inner, pkt);
}
static void not_free(np_filter_t *f)
{
    not_priv_t *p = f->priv;
    np_filter_free(p->inner);
    free(p); free(f);
}
static const struct np_filter_ops not_ops = { .match = not_match, .free = not_free };

np_filter_t *np_filter_not(np_filter_t *a)
{
    not_priv_t *p = malloc(sizeof(*p)); if (!p) return NULL;
    p->inner = a;
    np_filter_t *f = calloc(1, sizeof(*f)); if (!f) { free(p); return NULL; }
    f->ops = &not_ops; f->priv = p;
    return f;
}

void np_filter_free(np_filter_t *f)
{
    if (f && f->ops && f->ops->free) f->ops->free(f);
}
