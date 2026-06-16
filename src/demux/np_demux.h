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

#endif /* NP_DEMUX_H */
