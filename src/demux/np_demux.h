/*
 * np_demux.h — protocol demuxer: walks raw bytes, pushes layers
 */

#pragma once
#ifndef NP_DEMUX_H
#define NP_DEMUX_H

#include "netpipe.h"

/*
 * Decode all protocol layers of a captured packet.
 * Fills pkt->layers[], sets the convenience pointers (eth, net, transport, app),
 * computes pkt->flow_id.
 *
 * Assumes pkt->raw / pkt->caplen are already set.
 */
np_err_t np_demux_packet(np_packet_t *pkt, np_linktype_t linktype);

/*
 * Try to decode application-layer protocols beyond the core set
 * (DNS/HTTP/TLS).  Currently handles: DHCPv4, QUIC, SIP, MQTT, VXLAN.
 *
 * Called from decode_app() in np_demux.c when no core protocol matched.
 * Returns true if a decoder claimed the packet (and pushed its layer
 * onto pkt->layers + set pkt->app).
 */
bool np_demux_decode_app_extra(np_packet_t *pkt,
                                const uint8_t *payload, size_t len,
                                uint16_t src_port, uint16_t dst_port,
                                np_proto_t transport_proto);

#endif /* NP_DEMUX_H */
