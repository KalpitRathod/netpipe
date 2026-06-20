/*
 * np_packet.h — packet allocation, cloning, and introspection helpers
 */

#pragma once
#ifndef NP_PACKET_H
#define NP_PACKET_H

#include "netpipe.h"

/* Push a new layer onto the packet layer stack.
 * Returns a pointer to the np_layer_t that was filled in,
 * or NULL if the stack is full. */
np_layer_t *np_packet_push_layer(np_packet_t *pkt,
                                  np_proto_t proto,
                                  const uint8_t *data,
                                  size_t len);

/* Allocate 'size' bytes from the packet scratch area.
 * Returns NULL if there is not enough space. */
void *np_packet_scratch_alloc(np_packet_t *pkt, size_t size);

/* Pretty-print all layers to fp. */
void np_packet_print(const np_packet_t *pkt, FILE *fp);

/* Compute a 5-tuple flow hash (src/dst ip, src/dst port, proto). */
uint32_t np_packet_flow_hash(const np_packet_t *pkt);

/* np_packet_ts_str() is declared in <netpipe.h>. */

/* FIX (issue: np_bufpool was never wired up): expose pool stats and
 * teardown so the CLI/tests can verify the pool is being used and
 * np_cleanup can destroy it cleanly.  Not part of the stable public
 * ABI — internal symbol. */
void np_packet_pool_stats(FILE *fp);
void np_packet_pool_destroy(void);

#endif /* NP_PACKET_H */
