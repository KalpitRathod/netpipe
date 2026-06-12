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
        et      = ntohs(*(const uint16_t *)(payload + 2));
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

    np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_IP6, data, sizeof(ip6_hdr_t));
    if (!l) return NP_ERR_GENERIC;
    pkt->net = l;

    /* basic flow hash from first 4 bytes of src+dst */
    uint32_t h = 5381;
    h = hash_u32(h, *(uint32_t *)ip6->src);
    h = hash_u32(h, *(uint32_t *)ip6->dst);
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
        if (l) pkt->app = l;
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
                net_data = after_eth + ihl;
                net_len  = after_len - ihl;
                ip_proto = ip->protocol;
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
                net_data = data + ihl;
                net_len  = len  - ihl;
                ip_proto = ip->protocol;
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
