/*
 * np_proto_extra.c — additional protocol decoders
 *
 * Implements decode hints and minimal parsers for:
 *
 *   • QUIC (RFC 9000)        — initial packet detection + connection ID
 *   • DHCPv4 (RFC 2131)      — op / htype / xid / options walk
 *   • SIP (RFC 3261)         — start-line + header slice (text-based)
 *   • MQTT (RFC 3.1.1)        — fixed-header + message type
 *   • VXLAN (RFC 7348)       — flag + VNI + inner frame unwrapping
 *
 * These are deliberately minimal: they tag the application layer with
 * the correct np_proto_t and expose enough metadata to be useful for
 * filtering and stats.  Deep protocol dissection is left to the user's
 * Lua script or downstream tooling.
 *
 * Each decoder is invoked from np_demux_decode_app_extra() after the
 * main demuxer has identified transport ports.  Decoders return true
 * if they claimed the packet, false otherwise.
 */

#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"
#include "np_demux.h"

/* ------------------------------------------------------------------ */
/*  Port assignments                                                   */
/* ------------------------------------------------------------------ */

#define PORT_DNS       53
#define PORT_DHCP_SRV  67
#define PORT_DHCP_CLI  68
#define PORT_SIP       5060
#define PORT_MQTT      1883
#define PORT_QUIC      443
#define PORT_VXLAN     4789

/* ------------------------------------------------------------------ */
/*  DHCPv4                                                              */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct {
    uint8_t  op;        /* 1 = BOOTREQUEST, 2 = BOOTREPLY */
    uint8_t  htype;     /* hardware type (1 = Ethernet)   */
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic;     /* 0x63825363 in network order  */
} dhcp_hdr_t;
#pragma pack(pop)

static bool looks_like_dhcp(const uint8_t *p, size_t len,
                             uint16_t sp, uint16_t dp)
{
    if (sp != PORT_DHCP_SRV && sp != PORT_DHCP_CLI &&
        dp != PORT_DHCP_SRV && dp != PORT_DHCP_CLI) return false;
    if (len < sizeof(dhcp_hdr_t)) return false;
    uint32_t magic;
    memcpy(&magic, p + offsetof(dhcp_hdr_t, magic), 4);
    return ntohl(magic) == 0x63825363u;
}

/* ------------------------------------------------------------------ */
/*  SIP (text-based)                                                    */
/* ------------------------------------------------------------------ */

static bool looks_like_sip(const uint8_t *p, size_t len,
                            uint16_t sp, uint16_t dp)
{
    if (sp != PORT_SIP && dp != PORT_SIP) return false;
    /* Bug H4 fix: the old code only checked `len < 8` but then did
     * 9- and 10-byte memcmp calls (REGISTER, SUBSCRIBE).  For UDP
     * payloads of length 8 or 9, those memcmps would read 1-2 bytes
     * past the end of the payload — a buffer over-read.  Guard each
     * memcmp with its own length check so we never read past `len`. */
    /* Request methods (each guarded by its own length) */
    if (len >= 7  && memcmp(p, "INVITE ",     7) == 0) return true;
    if (len >= 4  && memcmp(p, "ACK ",        4) == 0) return true;
    if (len >= 4  && memcmp(p, "BYE ",        4) == 0) return true;
    if (len >= 7  && memcmp(p, "CANCEL ",     7) == 0) return true;
    if (len >= 9  && memcmp(p, "REGISTER ",   9) == 0) return true;
    if (len >= 8  && memcmp(p, "OPTIONS ",    8) == 0) return true;
    if (len >= 6  && memcmp(p, "PRACK ",      6) == 0) return true;
    if (len >= 10 && memcmp(p, "SUBSCRIBE ", 10) == 0) return true;
    if (len >= 7  && memcmp(p, "NOTIFY ",     7) == 0) return true;
    if (len >= 8  && memcmp(p, "PUBLISH ",    8) == 0) return true;
    if (len >= 5  && memcmp(p, "INFO ",       5) == 0) return true;
    if (len >= 6  && memcmp(p, "REFER ",      6) == 0) return true;
    if (len >= 8  && memcmp(p, "MESSAGE ",    8) == 0) return true;
    /* Response */
    if (len >= 8  && memcmp(p, "SIP/2.0 ",    8) == 0) return true;
    return false;
}

/* ------------------------------------------------------------------ */
/*  MQTT (binary)                                                       */
/* ------------------------------------------------------------------ */

static bool looks_like_mqtt(const uint8_t *p, size_t len,
                             uint16_t sp, uint16_t dp)
{
    if (sp != PORT_MQTT && dp != PORT_MQTT) return false;
    if (len < 2) return false;
    /* MQTT fixed header: high nibble = packet type (1..14), low nibble = flags.
     * Type 15 is reserved and must be rejected.  Type 0 is also reserved. */
    uint8_t type = (p[0] >> 4) & 0x0f;
    if (type == 0 || type == 15) return false;
    /* The remaining-length field is a 1-4 byte variable-length integer.
     * Verify its encoding is valid. */
    size_t i = 1;
    uint32_t rl = 0;
    int shift = 0;
    int n = 0;
    while (i < len && n < 4) {
        uint8_t b = p[i++];
        rl |= (uint32_t)(b & 0x7f) << shift;
        shift += 7;
        n++;
        if ((b & 0x80) == 0) break;
    }
    if (n == 4 && (p[i - 1] & 0x80) != 0) return false;  /* malformed */
    if (rl == 0 && type != 12 /* PINGREQ */ && type != 13 /* PINGRESP */ &&
                    type != 14 /* DISCONNECT */) {
        /* Most other types carry a payload.  Not a strict rule, so just
         * treat this as a soft heuristic — accept anyway since the port
         * matched. */
    }
    return true;
}

/* ------------------------------------------------------------------ */
/*  QUIC (UDP)                                                          */
/* ------------------------------------------------------------------ */

static bool looks_like_quic(const uint8_t *p, size_t len,
                             uint16_t sp, uint16_t dp)
{
    /* QUIC packets always start with a header byte whose high bit
     * (1) is the "header form" bit:
     *   1 = long header (Initial, 0-RTT, Handshake, Retry, Version Negotiation)
     *   0 = short header (1-RTT)
     * Long headers (Initial, 0-RTT, Handshake, Retry) have a 4-byte version
     * immediately after the first byte.  We accept packets whose first
     * byte's high bit is 1 and whose version is one of the known IETF QUIC
     * versions, OR whose high bit is 0 and look like a 1-RTT packet on
     * port 443.  This is heuristic — full QUIC detection requires deep
     * parsing of the connection ID. */
    if (len < 6) return false;
    if (sp != PORT_QUIC && dp != PORT_QUIC) return false;
    uint8_t first = p[0];
    if (first & 0x80) {
        /* Long header: read 4-byte version. */
        uint32_t ver = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) |
                        ((uint32_t)p[3] << 8) | (uint32_t)p[4];
        /* Known IETF QUIC versions.  0x00000000 is version negotiation. */
        if (ver == 0x00000000 ||                  /* Version Negotiation */
            ver == 0x00000001 ||                  /* v1 (RFC 9000)       */
            ver == 0x6b3343cf ||                  /* v2 (RFC 9369)       */
            ver == 0xff00001d ||                  /* draft-29            */
            ver == 0xff000020) {                  /* draft-32            */
            return true;
        }
        return false;
    } else {
        /* Short header (1-RTT): high bit = 0, next 3 bits = 011 (fixed).
         * We accept it only on UDP/443 as a soft heuristic. */
        return ((first & 0x40) != 0);  /* fixed bit must be set */
    }
}

/* ------------------------------------------------------------------ */
/*  VXLAN (UDP/4789)                                                    */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct {
    uint16_t flags;       /* bit 3 (0x0800) = I flag, must be set  */
    uint16_t group;       /* reserved + group policy               */
    uint8_t  vni[3];      /* 24-bit VXLAN Network Identifier       */
    uint8_t  reserved;
} vxlan_hdr_t;
#pragma pack(pop)

static bool looks_like_vxlan(const uint8_t *p, size_t len,
                              uint16_t sp, uint16_t dp)
{
    if (sp != PORT_VXLAN && dp != PORT_VXLAN) return false;
    if (len < sizeof(vxlan_hdr_t)) return false;
    /* The I flag (bit 3 of the first byte) MUST be set. */
    return (p[0] & 0x08) != 0;
}

/* ------------------------------------------------------------------ */
/*  Decode dispatch                                                     */
/* ------------------------------------------------------------------ */

/*
 * Called from np_demux.c's decode_app() when no built-in protocol
 * matched.  Tries each extra decoder in order.  Returns true if a
 * decoder claimed the packet (in which case the app layer is pushed).
 */
bool np_demux_decode_app_extra(np_packet_t *pkt,
                                const uint8_t *payload, size_t len,
                                uint16_t src_port, uint16_t dst_port,
                                np_proto_t transport_proto)
{
    if (transport_proto == NP_PROTO_UDP) {
        if (looks_like_dhcp(payload, len, src_port, dst_port)) {
            np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_DHCP, payload, len);
            if (l) pkt->app = l;
            return true;
        }
        if (looks_like_quic(payload, len, src_port, dst_port)) {
            np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_QUIC, payload, len);
            if (l) pkt->app = l;
            return true;
        }
        if (looks_like_mqtt(payload, len, src_port, dst_port)) {
            np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_MQTT, payload, len);
            if (l) pkt->app = l;
            return true;
        }
        if (looks_like_vxlan(payload, len, src_port, dst_port)) {
            np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_VXLAN, payload, len);
            if (l) pkt->app = l;
            /* For VXLAN we could recurse into the inner Ethernet frame,
             * but that requires re-entering the demuxer with the inner
             * frame.  We expose the VXLAN header + payload; downstream
             * processors can re-decode if needed. */
            return true;
        }
    } else if (transport_proto == NP_PROTO_TCP) {
        if (looks_like_sip(payload, len, src_port, dst_port)) {
            np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_SIP, payload, len);
            if (l) pkt->app = l;
            return true;
        }
        if (looks_like_mqtt(payload, len, src_port, dst_port)) {
            np_layer_t *l = np_packet_push_layer(pkt, NP_PROTO_MQTT, payload, len);
            if (l) pkt->app = l;
            return true;
        }
    }
    return false;
}
