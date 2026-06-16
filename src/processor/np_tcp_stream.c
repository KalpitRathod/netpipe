#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "netpipe.h"
#include "../pipeline/np_pipeline.h"
#include "../log/np_log.h"

#define STREAM_BUCKETS 1024

/* Minimal TCP header needed for sequence numbers */
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

typedef struct stream_node {
    uint32_t flow_id;
    uint32_t expected_seq;
    uint8_t *buf;
    size_t   buf_len;
    size_t   buf_cap;
    struct stream_node *next;
} stream_node_t;

typedef struct {
    stream_node_t *buckets[STREAM_BUCKETS];
    uint64_t       total_streams;
} tcp_stream_ctx_t;

static void tcp_stream_free(np_processor_t *p)
{
    tcp_stream_ctx_t *ctx = p->priv;
    if (!ctx) return;
    for (int i = 0; i < STREAM_BUCKETS; i++) {
        stream_node_t *node = ctx->buckets[i];
        while (node) {
            stream_node_t *next = node->next;
            free(node->buf);
            free(node);
            node = next;
        }
    }
    free(ctx);
    free(p);
}

static np_err_t tcp_stream_process(np_processor_t *p, np_packet_t *pkt)
{
    tcp_stream_ctx_t *ctx = p->priv;
    if (!ctx || !pkt->transport || pkt->transport->proto != NP_PROTO_TCP) {
        return NP_OK; /* Not TCP */
    }

    const tcp_hdr_t *tcp = (const tcp_hdr_t *)pkt->transport->data;
    uint32_t seq = ntohl(tcp->seq);
    uint8_t flags = tcp->flags;

    /* Calculate TCP payload offset */
    const uint8_t *payload = pkt->transport->data + pkt->transport->len;
    ptrdiff_t offset = payload - pkt->raw;
    if (offset < 0 || (size_t)offset >= pkt->caplen) return NP_OK; /* No payload or malformed */
    size_t payload_len = pkt->caplen - (size_t)offset;

    if (payload_len == 0 && !(flags & 0x02)) {
        return NP_OK; /* No data, not SYN */
    }

    /* Find stream */
    uint32_t h = pkt->flow_id;
    int bucket = h % STREAM_BUCKETS;
    stream_node_t *node = ctx->buckets[bucket];
    while (node) {
        if (node->flow_id == h) break;
        node = node->next;
    }

    if (!node) {
        /* New stream */
        node = calloc(1, sizeof(*node));
        if (!node) return NP_ERR_NOMEM;
        node->flow_id = h;
        node->expected_seq = seq;
        node->next = ctx->buckets[bucket];
        ctx->buckets[bucket] = node;
        ctx->total_streams++;
    }

    if (flags & 0x02) { /* SYN */
        node->expected_seq = seq + 1;
        return NP_OK;
    }

    if (payload_len > 0) {
        if (seq == node->expected_seq || node->buf_len == 0) {
            /* In order, or first packet of mid-stream capture */
            if (node->buf_len + payload_len > node->buf_cap) {
                size_t new_cap = node->buf_cap == 0 ? 4096 : node->buf_cap * 2;
                while (new_cap < node->buf_len + payload_len) new_cap *= 2;
                uint8_t *new_buf = realloc(node->buf, new_cap);
                if (!new_buf) return NP_ERR_NOMEM;
                node->buf = new_buf;
                node->buf_cap = new_cap;
            }
            memcpy(node->buf + node->buf_len, payload, payload_len);
            node->buf_len += payload_len;
            node->expected_seq = (uint32_t)(seq + payload_len);
        } else if ((int32_t)(seq - node->expected_seq) > 0) {
            /* Gap detected - append anyway to keep stream alive (basic reassembly) */
            node->expected_seq = (uint32_t)(seq + payload_len);
            if (node->buf_len + payload_len > node->buf_cap) {
                size_t new_cap = node->buf_cap == 0 ? 4096 : node->buf_cap * 2;
                while (new_cap < node->buf_len + payload_len) new_cap *= 2;
                uint8_t *new_buf = realloc(node->buf, new_cap);
                if (!new_buf) return NP_ERR_NOMEM;
                node->buf = new_buf;
                node->buf_cap = new_cap;
            }
            memcpy(node->buf + node->buf_len, payload, payload_len);
            node->buf_len += payload_len;
        }
    }

    /* Expose current reassembled stream context via np_packet_t */
    if (node->buf_len > 0) {
        free(pkt->stream_data);  /* release any existing buffer before overwriting */
        pkt->stream_data = malloc(node->buf_len);
        if (pkt->stream_data) {
            memcpy(pkt->stream_data, node->buf, node->buf_len);
            pkt->stream_len = node->buf_len;
        }
    }

    /* Cleanup on FIN or RST */
    if ((flags & 0x01) || (flags & 0x04)) {
        stream_node_t **iter = &ctx->buckets[bucket];
        while (*iter) {
            if (*iter == node) {
                *iter = node->next;
                break;
            }
            iter = &(*iter)->next;
        }
        free(node->buf);
        free(node);
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
    if (!ctx) {
        free(p);
        return NULL;
    }
    
    p->ops  = &tcp_stream_ops;
    p->priv = ctx;
    return p;
}
