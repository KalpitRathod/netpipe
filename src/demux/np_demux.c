/*
 * np_demux.c — incremental protocol demuxer
 *
 * Ethernet → ARP / IPv4 / IPv6
 *              ↓
 *           ICMP / TCP / UDP
 *                    ↓
 *                DNS / HTTP / TLS
 */

#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"
#include "np_demux.h"

/* ------------------------------------------------------------------ */
/*  Packed protocol structs (avoid system header portability issues)    */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

typedef struct {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
} eth_hdr_t;

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
    uint32_t vcf;          /* version(4) + traffic class(8) + flow label(20) */
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

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_hdr_t;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  djb2 hash helpers for flow ID                                       */
/* ------------------------------------------------------------------ */

static inline uint32_t hash_u32(uint32_t h, uint32_t v)
{
    h ^= (v & 0xff);         h = (h << 5) + h;
    h ^= ((v >> 8)  & 0xff); h = (h << 5) + h;
    h ^= ((v >> 16) & 0xff); h = (h << 5) + h;
    h ^= ((v >> 24) & 0xff); h = (h << 5) + h;
    return h;
}

static inline uint32_t hash_u16(uint32_t h, uint16_t v)
{
    h ^= (v & 0xff);         h = (h << 5) + h;
    h ^= ((v >> 8) & 0xff);  h = (h << 5) + h;
    return h;
}

/* ------------------------------------------------------------------ */
/*  Layer decoders                                                      */
/* ------------------------------------------------------------------ */

static np_err_t decode_eth(np_packet_t *pkt,
                            const uint8_t *data, size_t len)
{
    if (len < sizeof(eth_hdr_t)) {
        NP_LOG_DEBUG("Ethernet frame too short (%zu)", len);
        return NP_ERR_PROTO;
    }
    const eth_hdr_t *eth = (const eth_hdr_t *)data;
    np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_ETH, data, sizeof(eth_hdr_t));
    if (!l) return NP_ERR_GENERIC;
    pkt->eth = l;

    uint16_t et = ntohs(eth->ethertype);

    /* skip 802.1Q vlan tags */
    const uint8_t *payload = data + sizeof(eth_hdr_t);
    size_t         paylen  = len  - sizeof(eth_hdr_t);
    if (et == 0x8100 && paylen >= 4) {
        uint16_t v;
        memcpy(&v, payload + 2, sizeof(v));
        et      = ntohs(v);
        payload += 4;
        paylen  -= 4;
    }

    switch (et) {
    case 0x0800: return NP_OK; /* IPv4 handled by caller */
    case 0x86DD: return NP_OK; /* IPv6 handled by caller */
    case 0x0806: {
        /* ARP — just tag it, no deeper parsing */
        np_layer_t *al = np_packet_push_layer(pkt, NP_PROTO_ARP, payload, paylen);
        if (al) pkt->net = al;
        return NP_OK;
    }
    default:
        NP_LOG_TRACE("unknown ethertype 0x%04x", et);
        return NP_OK;
    }
}

static np_err_t decode_ip4(np_packet_t *pkt,
                            const uint8_t *data, size_t len)
{
    if (len < sizeof(ip4_hdr_t)) return NP_ERR_PROTO;
    const ip4_hdr_t *ip = (const ip4_hdr_t *)data;
    if ((ip->version_ihl >> 4) != 4) return NP_ERR_PROTO;
    uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
    if (ihl < 20 || ihl > len) return NP_ERR_PROTO;

    np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_IP4, data, ihl);
    if (!l) return NP_ERR_GENERIC;
    pkt->net = l;

    /* seed flow hash with src/dst IP */
    uint32_t h = 5381;
    h = hash_u32(h, ntohl(ip->src));
    h = hash_u32(h, ntohl(ip->dst));
    h ^= ip->protocol;
    pkt->flow_id = h;

    return NP_OK;
}

static np_err_t decode_ip6(np_packet_t *pkt,
                            const uint8_t *data, size_t len)
{
    if (len < sizeof(ip6_hdr_t)) return NP_ERR_PROTO;
    const ip6_hdr_t *ip6 = (const ip6_hdr_t *)data;
    uint8_t version = (uint8_t)(ntohl(ip6->vcf) >> 28);
    if (version != 6) return NP_ERR_PROTO;

    np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_IP6, data, sizeof(ip6_hdr_t));
    if (!l) return NP_ERR_GENERIC;
    pkt->net = l;

    /* basic flow hash from first 4 bytes of src+dst */
    uint32_t h = 5381;
    uint32_t src_w, dst_w;
    memcpy(&src_w, ip6->src, sizeof(src_w));
    memcpy(&dst_w, ip6->dst, sizeof(dst_w));
    h = hash_u32(h, src_w);
    h = hash_u32(h, dst_w);
    h ^= ip6->next_header;
    pkt->flow_id = h;

    return NP_OK;
}

static np_err_t decode_tcp(np_packet_t *pkt,
                            const uint8_t *data, size_t len)
{
    if (len < sizeof(tcp_hdr_t)) return NP_ERR_PROTO;
    const tcp_hdr_t *tcp = (const tcp_hdr_t *)data;
    uint8_t hdrlen = ((tcp->data_offset_flags >> 4) & 0x0f) * 4;
    if (hdrlen < 20 || hdrlen > len) return NP_ERR_PROTO;

    np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_TCP, data, hdrlen);
    if (!l) return NP_ERR_GENERIC;
    pkt->transport = l;

    uint16_t sp = ntohs(tcp->src_port);
    uint16_t dp = ntohs(tcp->dst_port);
    pkt->flow_id = hash_u16(hash_u16(pkt->flow_id, sp), dp);

    return NP_OK;
}

static np_err_t decode_udp(np_packet_t *pkt,
                            const uint8_t *data, size_t len)
{
    if (len < sizeof(udp_hdr_t)) return NP_ERR_PROTO;
    const udp_hdr_t *udp = (const udp_hdr_t *)data;

    np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_UDP, data, sizeof(udp_hdr_t));
    if (!l) return NP_ERR_GENERIC;
    pkt->transport = l;

    uint16_t sp = ntohs(udp->src_port);
    uint16_t dp = ntohs(udp->dst_port);
    pkt->flow_id = hash_u16(hash_u16(pkt->flow_id, sp), dp);

    return NP_OK;
}

static bool looks_like_dns(const uint8_t *payload, size_t len,
                           uint16_t src_port, uint16_t dst_port)
{
    if (src_port == 53 || dst_port == 53) return true;
    if (len >= sizeof(dns_hdr_t)) {
        const dns_hdr_t *d = (const dns_hdr_t *)payload;
        uint16_t flags = ntohs(d->flags);
        uint16_t opcode = (flags >> 11) & 0x0f;
        if (opcode <= 2 && ntohs(d->qdcount) <= 16) return true;
    }
    return false;
}

static int dns_read_name(const uint8_t *payload, size_t len, size_t offset, char *out, size_t out_max)
{
    size_t out_idx = 0;
    size_t og_offset = offset;
    bool jumped = false;
    int jumps = 0;
    
    while (offset < len) {
        uint8_t l = payload[offset];
        if (l == 0) {
            if (!jumped) og_offset = offset + 1;
            break;
        }
        if ((l & 0xC0) == 0xC0) {
            if (offset + 1 >= len) return -1;
            uint16_t ptr = (uint16_t)(((l & 0x3F) << 8) | payload[offset + 1]);
            if (!jumped) og_offset = offset + 2;
            offset = ptr;
            jumped = true;
            jumps++;
            if (jumps > 5) return -1; /* avoid loops */
            continue;
        }
        
        offset++;
        if (offset + l > len) return -1;
        
        if (out_idx > 0 && out_idx < out_max) out[out_idx++] = '.';
        
        for (int i = 0; i < l; i++) {
            if (out_idx < out_max - 1) {
                out[out_idx++] = (char)payload[offset + (size_t)i];
            }
        }
        offset += l;
        if (!jumped) og_offset = offset;
    }
    
    if (out_idx < out_max) out[out_idx] = '\0';
    return (int)og_offset;
}

static void decode_dns(np_packet_t *pkt, np_layer_t *layer)
{
    np_dns_msg_t *msg = np_packet_scratch_alloc(pkt, sizeof(np_dns_msg_t));
    if (!msg) return;
    memset(msg, 0, sizeof(*msg));
    
    const uint8_t *p = layer->data;
    size_t len = layer->len;
    
    if (len < sizeof(dns_hdr_t)) return;
    const dns_hdr_t *d = (const dns_hdr_t *)p;
    
    msg->id = ntohs(d->id);
    uint16_t flags = ntohs(d->flags);
    msg->is_response = (flags & 0x8000) != 0;
    msg->rcode = flags & 0x0f;
    
    int qdcount = ntohs(d->qdcount);
    int ancount = ntohs(d->ancount);
    
    size_t offset = sizeof(dns_hdr_t);
    
    if (qdcount > 0) {
        int next_off = dns_read_name(p, len, offset, msg->query_name, sizeof(msg->query_name));
        if (next_off < 0) return;
        offset = (size_t)next_off;
        
        if (offset + 4 > len) return;
        msg->query_type = (uint16_t)(((uint16_t)p[offset] << 8) | p[offset + 1]);
        offset += 4;
    }
    
    for (int i = 0; i < ancount && msg->num_answers < NP_MAX_DNS_ANSWERS && offset < len; i++) {
        np_dns_answer_t *ans = &msg->answers[msg->num_answers++];
        
        int next_off = dns_read_name(p, len, offset, ans->name, sizeof(ans->name));
        if (next_off < 0) break;
        offset = (size_t)next_off;
        
        if (offset + 10 > len) break;
        ans->type = (uint16_t)(((uint16_t)p[offset] << 8) | p[offset + 1]);
        ans->class_ = (uint16_t)(((uint16_t)p[offset + 2] << 8) | p[offset + 3]);
        ans->ttl = ((uint32_t)p[offset + 4] << 24) | ((uint32_t)p[offset + 5] << 16) |
                   ((uint32_t)p[offset + 6] << 8)  |  (uint32_t)p[offset + 7];
        ans->data_len = (uint16_t)(((uint16_t)p[offset + 8] << 8) | p[offset + 9]);
        offset += 10;
        
        if (offset + ans->data_len > len) break;
        
        if (ans->type == 1 && ans->data_len == 4) {
            snprintf(ans->rdata_str, sizeof(ans->rdata_str), "%u.%u.%u.%u",
                     p[offset], p[offset+1], p[offset+2], p[offset+3]);
        } else if (ans->type == 28 && ans->data_len == 16) {
            snprintf(ans->rdata_str, sizeof(ans->rdata_str),
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     p[offset], p[offset+1], p[offset+2], p[offset+3],
                     p[offset+4], p[offset+5], p[offset+6], p[offset+7],
                     p[offset+8], p[offset+9], p[offset+10], p[offset+11],
                     p[offset+12], p[offset+13], p[offset+14], p[offset+15]);
        } else if (ans->type == 5) {
            dns_read_name(p, len, offset, ans->rdata_str, sizeof(ans->rdata_str));
        } else {
            snprintf(ans->rdata_str, sizeof(ans->rdata_str), "<type %d>", ans->type);
        }
        
        offset += ans->data_len;
    }
    
    layer->decoded = msg;
}

static bool looks_like_http(const uint8_t *payload, size_t len)
{
    if (len < 8) return false;
    /* request */
    if (memcmp(payload, "GET ",     4) == 0) return true;
    if (memcmp(payload, "POST ",    5) == 0) return true;
    if (memcmp(payload, "PUT ",     4) == 0) return true;
    if (memcmp(payload, "HEAD ",    5) == 0) return true;
    if (memcmp(payload, "DELETE ",  7) == 0) return true;
    if (memcmp(payload, "OPTIONS",  7) == 0) return true;
    if (memcmp(payload, "PATCH ",   6) == 0) return true;
    /* response */
    if (memcmp(payload, "HTTP/",    5) == 0) return true;
    return false;
}

static bool looks_like_tls(const uint8_t *payload, size_t len)
{
    if (len < 5) return false;
    uint8_t ct = payload[0];
    uint8_t maj = payload[1], min = payload[2];
    /* TLS content types: 20=change_cipher, 21=alert, 22=handshake, 23=app */
    return (ct >= 20 && ct <= 23) && maj == 3 && min <= 4;
}

static const uint8_t *find_crlf(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i+1] == '\n') return buf + i;
    }
    return NULL;
}

static const uint8_t *find_char(const uint8_t *buf, size_t len, char c) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == c) return buf + i;
    }
    return NULL;
}

static void decode_http(np_packet_t *pkt, np_layer_t *layer)
{
    np_http_msg_t *msg = np_packet_scratch_alloc(pkt, sizeof(np_http_msg_t));
    if (!msg) return;
    memset(msg, 0, sizeof(*msg));
    
    const uint8_t *p = layer->data;
    size_t len = layer->len;
    
    const uint8_t *crlf = find_crlf(p, len);
    if (!crlf) return;
    
    size_t line_len = (size_t)(crlf - p);
    msg->is_request = (line_len < 5 || memcmp(p, "HTTP/", 5) != 0);
    
    if (msg->is_request) {
        const uint8_t *sp1 = find_char(p, line_len, ' ');
        if (sp1) {
            msg->method.str = (const char *)p;
            msg->method.len = (size_t)(sp1 - p);
            
            const uint8_t *sp2 = find_char(sp1 + 1, line_len - (size_t)(sp1 + 1 - p), ' ');
            if (sp2) {
                msg->path.str = (const char *)(sp1 + 1);
                msg->path.len = (size_t)(sp2 - (sp1 + 1));
                msg->version.str = (const char *)(sp2 + 1);
                msg->version.len = (size_t)(crlf - (sp2 + 1));
            }
        }
    } else {
        const uint8_t *sp1 = find_char(p, line_len, ' ');
        if (sp1) {
            msg->version.str = (const char *)p;
            msg->version.len = (size_t)(sp1 - p);
            
            const uint8_t *sp2 = find_char(sp1 + 1, line_len - (size_t)(sp1 + 1 - p), ' ');
            if (sp2) {
                int code = 0;
                for (const uint8_t *c = sp1 + 1; c < sp2; c++) {
                    if (*c >= '0' && *c <= '9') code = code * 10 + (*c - '0');
                }
                msg->status_code = code;
                msg->status_phrase.str = (const char *)(sp2 + 1);
                msg->status_phrase.len = (size_t)(crlf - (sp2 + 1));
            }
        }
    }
    
    p = crlf + 2;
    len -= (size_t)(p - layer->data);
    
    while (len > 0) {
        crlf = find_crlf(p, len);
        if (!crlf) break;
        
        if (crlf == p) {
            p = crlf + 2;
            len -= 2;
            msg->body = p;
            msg->body_len = len;
            break;
        }
        
        if (msg->num_headers < NP_MAX_HTTP_HEADERS) {
            size_t hlen = (size_t)(crlf - p);
            const uint8_t *colon = find_char(p, hlen, ':');
            if (colon) {
                np_http_header_t *h = &msg->headers[msg->num_headers++];
                h->name.str = (const char *)p;
                h->name.len = (size_t)(colon - p);
                
                const uint8_t *v = colon + 1;
                while (v < crlf && (*v == ' ' || *v == '\t')) v++;
                h->value.str = (const char *)v;
                h->value.len = (size_t)(crlf - v);
            }
        }
        
        len -= (size_t)(crlf + 2 - p);
        p = crlf + 2;
    }
    
    layer->decoded = msg;
}

static np_err_t decode_app(np_packet_t *pkt,
                           const uint8_t *payload, size_t len,
                           uint16_t src_port, uint16_t dst_port,
                           np_proto_t transport_proto)
{
    if (len == 0) return NP_OK;

    np_proto_t app_proto = NP_PROTO_RAW;

    if (transport_proto == NP_PROTO_UDP &&
        looks_like_dns(payload, len, src_port, dst_port)) {
        app_proto = NP_PROTO_DNS;
    } else if (transport_proto == NP_PROTO_TCP) {
        if (looks_like_tls(payload, len)) {
            app_proto = NP_PROTO_TLS;
        } else if (looks_like_http(payload, len)) {
            app_proto = NP_PROTO_HTTP;
        } else if ((src_port == 53 || dst_port == 53) &&
                   looks_like_dns(payload, len, src_port, dst_port)) {
            app_proto = NP_PROTO_DNS;
        }
    }

    if (app_proto != NP_PROTO_RAW) {
        np_layer_t *l = np_packet_push_layer(pkt, app_proto, payload, len);
        if (l) {
            pkt->app = l;
            if (app_proto == NP_PROTO_HTTP) decode_http(pkt, l);
            else if (app_proto == NP_PROTO_DNS) decode_dns(pkt, l);
        }
    }

    return NP_OK;
}

/* ------------------------------------------------------------------ */
/*  Main entry point                                                    */
/* ------------------------------------------------------------------ */

np_err_t np_demux_packet(np_packet_t *pkt, np_linktype_t linktype)
{
    const uint8_t *data = pkt->raw;
    size_t         len  = pkt->caplen;

    if (!data || len == 0) return NP_ERR_PROTO;

    /* ---- link layer ---- */
    const uint8_t *net_data = NULL;
    size_t         net_len  = 0;
    uint8_t        ip_proto = 0;

    switch (linktype) {
    case NP_LINK_ETHERNET: {
        np_err_t e = decode_eth(pkt, data, len);
        if (e != NP_OK) return e;

        if (len < sizeof(eth_hdr_t)) return NP_ERR_PROTO;
        const eth_hdr_t *eth = (const eth_hdr_t *)data;
        uint16_t et = ntohs(eth->ethertype);

        const uint8_t *after_eth = data + sizeof(eth_hdr_t);
        size_t         after_len = len  - sizeof(eth_hdr_t);
        /* skip vlan */
        if (et == 0x8100 && after_len >= 4) {
            et        = ntohs(*(const uint16_t *)(after_eth + 2));
            after_eth += 4;
            after_len -= 4;
        }
        if (et == 0x0800) {
            decode_ip4(pkt, after_eth, after_len);
            if (after_len >= sizeof(ip4_hdr_t)) {
                const ip4_hdr_t *ip = (const ip4_hdr_t *)after_eth;
                uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
                if (after_len >= ihl) {
                    net_data = after_eth + ihl;
                    net_len  = after_len - ihl;
                    ip_proto = ip->protocol;
                }
            }
        } else if (et == 0x86DD) {
            decode_ip6(pkt, after_eth, after_len);
            if (after_len >= sizeof(ip6_hdr_t)) {
                const ip6_hdr_t *ip6 = (const ip6_hdr_t *)after_eth;
                net_data = after_eth + sizeof(ip6_hdr_t);
                net_len  = after_len - sizeof(ip6_hdr_t);
                ip_proto = ip6->next_header;
            }
        }
        break;
    }
    case NP_LINK_LINUX_SLL: {
        if (len < 16) return NP_ERR_PROTO;
        uint16_t et = ntohs(*(const uint16_t *)(data + 14));
        const uint8_t *after_eth = data + 16;
        size_t         after_len = len  - 16;
        if (et == 0x0800) {
            decode_ip4(pkt, after_eth, after_len);
            if (after_len >= sizeof(ip4_hdr_t)) {
                const ip4_hdr_t *ip = (const ip4_hdr_t *)after_eth;
                uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
                if (after_len >= ihl) {
                    net_data = after_eth + ihl;
                    net_len  = after_len - ihl;
                    ip_proto = ip->protocol;
                }
            }
        } else if (et == 0x86DD) {
            decode_ip6(pkt, after_eth, after_len);
            if (after_len >= sizeof(ip6_hdr_t)) {
                const ip6_hdr_t *ip6 = (const ip6_hdr_t *)after_eth;
                net_data = after_eth + sizeof(ip6_hdr_t);
                net_len  = after_len - sizeof(ip6_hdr_t);
                ip_proto = ip6->next_header;
            }
        }
        break;
    }
    case NP_LINK_LOOPBACK:
    case NP_LINK_RAW:
        /* Skip 4-byte loopback header if present */
        if (linktype == NP_LINK_LOOPBACK && len >= 4) {
            data += 4; len -= 4;
        }
        if (len >= sizeof(ip4_hdr_t)) {
            uint8_t ver = (data[0] >> 4) & 0x0f;
            if (ver == 4) {
                decode_ip4(pkt, data, len);
                const ip4_hdr_t *ip = (const ip4_hdr_t *)data;
                uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
                if (len >= ihl) {
                    net_data = data + ihl;
                    net_len  = len  - ihl;
                    ip_proto = ip->protocol;
                }
            } else if (ver == 6) {
                decode_ip6(pkt, data, len);
                const ip6_hdr_t *ip6 = (const ip6_hdr_t *)data;
                net_data = data + sizeof(ip6_hdr_t);
                net_len  = len  - sizeof(ip6_hdr_t);
                ip_proto = ip6->next_header;
            }
        }
        break;
    default:
        break;
    }

    if (!net_data || net_len == 0) return NP_OK;

    /* ---- transport layer ---- */
    uint16_t src_port = 0, dst_port = 0;
    np_proto_t tproto = NP_PROTO_RAW;

    switch (ip_proto) {
    case IPPROTO_TCP: {
        decode_tcp(pkt, net_data, net_len);
        if (net_len >= sizeof(tcp_hdr_t)) {
            const tcp_hdr_t *tcp = (const tcp_hdr_t *)net_data;
            src_port = ntohs(tcp->src_port);
            dst_port = ntohs(tcp->dst_port);
            uint8_t hdrlen = ((tcp->data_offset_flags >> 4) & 0x0f) * 4;
            net_data += hdrlen;
            net_len   = (net_len > hdrlen) ? net_len - hdrlen : 0;
            tproto = NP_PROTO_TCP;
        }
        break;
    }
    case IPPROTO_UDP: {
        decode_udp(pkt, net_data, net_len);
        if (net_len >= sizeof(udp_hdr_t)) {
            const udp_hdr_t *udp = (const udp_hdr_t *)net_data;
            src_port = ntohs(udp->src_port);
            dst_port = ntohs(udp->dst_port);
            net_data += sizeof(udp_hdr_t);
            net_len   = (net_len > sizeof(udp_hdr_t)) ? net_len - sizeof(udp_hdr_t) : 0;
            tproto = NP_PROTO_UDP;
        }
        break;
    }
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6: {
        np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_ICMP, net_data, net_len);
        if (l) pkt->transport = l;
        return NP_OK;
    }
    default:
        return NP_OK;
    }

    /* ---- application layer ---- */
    decode_app(pkt, net_data, net_len, src_port, dst_port, tproto);

    return NP_OK;
}
