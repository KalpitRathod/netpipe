/*
 * np_packet.c — packet lifecycle and helpers
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "np_packet.h"

/* ------------------------------------------------------------------ */
/*  Alloc / free / clone                                                */
/* ------------------------------------------------------------------ */

np_packet_t *np_packet_alloc(size_t caplen)
{
    np_packet_t *pkt = calloc(1, sizeof(*pkt));
    if (!pkt) return NULL;

    pkt->raw = malloc(caplen);
    if (!pkt->raw) { free(pkt); return NULL; }

    pkt->caplen = (uint32_t)caplen;
    return pkt;
}

void np_packet_free(np_packet_t *pkt)
{
    if (!pkt) return;
    free(pkt->raw);
    if (pkt->stream_data) free(pkt->stream_data);
    free(pkt);
}

np_packet_t *np_packet_clone(const np_packet_t *src)
{
    if (!src) return NULL;
    np_packet_t *dst = np_packet_alloc(src->caplen);
    if (!dst) return NULL;

    memcpy(dst->raw, src->raw, src->caplen);

    dst->ts      = src->ts;
    dst->wirelen = src->wirelen;
    dst->caplen  = src->caplen;
    dst->seq     = src->seq;
    dst->flow_id = src->flow_id;

    /* Layers point into raw — re-map offsets */
    dst->nlayers = src->nlayers;
    for (int i = 0; i < src->nlayers; i++) {
        dst->layers[i].proto   = src->layers[i].proto;
        dst->layers[i].len     = src->layers[i].len;
        /* offset from original raw base */
        ptrdiff_t off = src->layers[i].data - src->raw;
        dst->layers[i].data    = dst->raw + off;
        dst->layers[i].decoded = NULL; /* scratch not cloned */
    }

    /* Restore convenience pointers */
    dst->eth       = src->eth       ? dst->layers + (src->eth       - src->layers) : NULL;
    dst->net       = src->net       ? dst->layers + (src->net       - src->layers) : NULL;
    dst->transport = src->transport ? dst->layers + (src->transport - src->layers) : NULL;
    dst->app       = src->app       ? dst->layers + (src->app       - src->layers) : NULL;

    /* Copy user metadata and reserved fields for ABI stability */
    dst->user_data = src->user_data;
    memcpy(dst->reserved, src->reserved, sizeof(dst->reserved));

    return dst;
}

/* ------------------------------------------------------------------ */
/*  Layer stack                                                         */
/* ------------------------------------------------------------------ */

np_layer_t *np_packet_push_layer(np_packet_t *pkt,
                                  np_proto_t proto,
                                  const uint8_t *data,
                                  size_t len)
{
    if (pkt->nlayers >= NP_MAX_LAYERS) {
        NP_LOG_WARN("layer stack full (max %d)", NP_MAX_LAYERS);
        return NULL;
    }
    np_layer_t *l   = &pkt->layers[pkt->nlayers++];
    l->proto        = proto;
    l->data         = data;
    l->len          = len;
    l->decoded      = NULL;
    return l;
}

void *np_packet_scratch_alloc(np_packet_t *pkt, size_t size)
{
    size_t remaining = sizeof(pkt->scratch) - pkt->scratch_used;
    if (size > remaining) return NULL;
    void *ptr = pkt->scratch + pkt->scratch_used;
    pkt->scratch_used += size;
    /* align to 8 bytes */
    pkt->scratch_used = (pkt->scratch_used + 7) & ~(size_t)7;
    return ptr;
}

/* ------------------------------------------------------------------ */
/*  Utilities                                                           */
/* ------------------------------------------------------------------ */

void np_packet_ts_str(const np_packet_t *pkt, char *buf, size_t bufsz)
{
    struct tm tm;
    localtime_r(&pkt->ts.tv_sec, &tm);
    snprintf(buf, bufsz, "%02d:%02d:%02d.%06ld",
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             (long)(pkt->ts.tv_nsec / 1000));
}

static const char *proto_name(np_proto_t p)
{
    switch (p) {
    case NP_PROTO_ETH:  return "Ethernet";
    case NP_PROTO_ARP:  return "ARP";
    case NP_PROTO_IP4:  return "IPv4";
    case NP_PROTO_IP6:  return "IPv6";
    case NP_PROTO_ICMP: return "ICMP";
    case NP_PROTO_TCP:  return "TCP";
    case NP_PROTO_UDP:  return "UDP";
    case NP_PROTO_DNS:  return "DNS";
    case NP_PROTO_HTTP: return "HTTP";
    case NP_PROTO_TLS:  return "TLS";
    default:            return "Unknown";
    }
}

void np_packet_print(const np_packet_t *pkt, FILE *fp)
{
    char ts[32];
    np_packet_ts_str(pkt, ts, sizeof(ts));

    fprintf(fp, "┌── Packet #%lu  ts=%s  cap=%u  wire=%u\n",
            (unsigned long)pkt->seq, ts, pkt->caplen, pkt->wirelen);

    for (int i = 0; i < pkt->nlayers; i++) {
        const np_layer_t *l = &pkt->layers[i];
        fprintf(fp, "│  Layer[%d] %-10s  len=%-6zu\n",
                i, proto_name(l->proto), l->len);
    }

    /* hex dump of first 64 bytes */
    fprintf(fp, "│  Raw (first 64 bytes):\n│  ");
    size_t dump = pkt->caplen < 64 ? pkt->caplen : 64;
    for (size_t i = 0; i < dump; i++) {
        fprintf(fp, "%02x ", pkt->raw[i]);
        if ((i + 1) % 16 == 0) fprintf(fp, "\n│  ");
    }
    fprintf(fp, "\n");

    if (pkt->stream_data && pkt->stream_len > 0) {
        fprintf(fp, "│  Stream/Transformed Payload (len=%zu):\n│  ", pkt->stream_len);
        bool is_printable = true;
        for (size_t i = 0; i < pkt->stream_len; i++) {
            uint8_t c = pkt->stream_data[i];
            if ((c < 32 || c > 126) && c != '\t' && c != '\n' && c != '\r') {
                is_printable = false;
                break;
            }
        }
        if (is_printable) {
            size_t p_len = pkt->stream_len < 1000 ? pkt->stream_len : 1000;
            fwrite(pkt->stream_data, 1, p_len, fp);
            if (pkt->stream_len > 1000) fprintf(fp, "... [truncated]");
            fprintf(fp, "\n");
        } else {
            size_t p_len = pkt->stream_len < 256 ? pkt->stream_len : 256;
            for (size_t i = 0; i < p_len; i++) {
                fprintf(fp, "%02x ", pkt->stream_data[i]);
                if ((i + 1) % 16 == 0) fprintf(fp, "\n│  ");
            }
            if (pkt->stream_len > 256) fprintf(fp, "... [truncated]");
            fprintf(fp, "\n");
        }
    }

    fprintf(fp, "└──\n");
}

/* djb2-based 5-tuple hash — filled in by the protocol decoder */
uint32_t np_packet_flow_hash(const np_packet_t *pkt)
{
    return pkt->flow_id;
}
