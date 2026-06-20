/*
 * netpipe — modular network traffic processing pipeline
 *
 * Copyright (C) 2026 netpipe contributors
 *
 * PUBLIC API  —  include this single header in downstream consumers.
 * Internal modules include their own headers directly; nothing in this
 * file is implementation detail.
 *
 * Stable API surface (v0.1.0)
 * ──────────────────────────────────────────────────────────────────────
 * Everything in this file that is NOT marked NP_EXPERIMENTAL is considered
 * stable: we will not rename, remove, or change the signature of any stable
 * symbol without bumping NETPIPE_VERSION_MAJOR.
 *
 * NP_EXPERIMENTAL symbols may change at any time without a major bump.
 * Do not use them in production code without accepting that risk.
 *
 * ABI notes
 * ──────────────────────────────────────────────────────────────────────
 * • np_pipeline_t, np_source_t, np_filter_t, np_processor_t, np_sink_t
 *   are all opaque — their internal layout is never part of the ABI.
 * • np_packet_t and np_layer_t are exposed structs.  They carry
 *   reserved[] padding; only fields explicitly documented in the
 *   manual are stable ABI.  The `scratch` / `scratch_used` region and
 *   `user_data` pointer are stable.
 * • np_http_msg_t and np_dns_msg_t are exposed structs for zero-copy
 *   decoded protocol data.  Their fields are stable; adding new fields
 *   in future versions will only ever happen by replacing a reserved[].
 */

#pragma once
#ifndef NETPIPE_H
#define NETPIPE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/*  Version                                                             */
/* ------------------------------------------------------------------ */

#define NETPIPE_VERSION_MAJOR 0
#define NETPIPE_VERSION_MINOR 1
#define NETPIPE_VERSION_PATCH 0
#define NETPIPE_VERSION_STR   "0.1.0"

/**
 * NETPIPE_VERSION_INT - single integer for compile-time version comparisons.
 *
 * Example:
 *   #if NETPIPE_VERSION_INT >= NETPIPE_MAKE_VERSION(0,2,0)
 *     // use new API
 *   #endif
 */
#define NETPIPE_MAKE_VERSION(maj,min,patch) \
    (((uint32_t)(maj) << 16) | ((uint32_t)(min) << 8) | ((uint32_t)(patch)))
#define NETPIPE_VERSION_INT \
    NETPIPE_MAKE_VERSION(NETPIPE_VERSION_MAJOR, \
                         NETPIPE_VERSION_MINOR, \
                         NETPIPE_VERSION_PATCH)

/**
 * np_version() - runtime version query.
 *
 * Fills *major, *minor, *patch with the version of the library that was
 * actually linked (which may differ from the headers used to compile
 * the caller).  Prefer this over the preprocessor macros when you need
 * to gate behaviour at runtime.
 *
 * Any out-pointer may be NULL.
 */
void np_version(int *major, int *minor, int *patch);

/**
 * NP_EXPERIMENTAL - marks an API as subject to change without notice.
 *
 * Functions and types tagged with NP_EXPERIMENTAL are available for
 * experimentation but are NOT part of the stable ABI.  Their signatures
 * or semantics may change in any release, including patch releases.
 */
#define NP_EXPERIMENTAL

/* ------------------------------------------------------------------ */
/*  Return codes                                                        */
/* ------------------------------------------------------------------ */

/**
 * np_err_t - return codes used by almost every library function.
 *
 * Every negative value indicates failure.  NP_OK (0) indicates success.
 * Use np_strerror() to convert a code to a human-readable English string.
 */
typedef enum {
    NP_OK            =  0,   /**< Success.                              */
    NP_ERR_GENERIC   = -1,   /**< Unspecified error.                    */
    NP_ERR_NOMEM     = -2,   /**< Memory allocation failure.            */
    NP_ERR_IO        = -3,   /**< I/O error (file, socket, device).     */
    NP_ERR_PROTO     = -4,   /**< Protocol parse / validation error.    */
    NP_ERR_FILTER    = -5,   /**< Filter expression error.              */
    NP_ERR_TIMEOUT   = -6,   /**< Operation timed out.                  */
    NP_ERR_NODEV     = -7,   /**< Device or file not found.             */
    NP_ERR_PERM      = -8,   /**< Permission denied.                    */
    NP_ERR_EOF       = -9,   /**< End of input (normal termination).    */
} np_err_t;

/** np_strerror() - convert an np_err_t to a read-only English string. */
const char *np_strerror(np_err_t err);

/* ------------------------------------------------------------------ */
/*  Link layer types                                                    */
/* ------------------------------------------------------------------ */

/**
 * np_linktype_t - identifies the Layer-2 framing of a capture source.
 *
 * Values match the DLT_ constants used by libpcap where they exist.
 */
typedef enum {
    NP_LINK_UNKNOWN   =   0,   /**< Unknown or unsupported link type.   */
    NP_LINK_ETHERNET  =   1,   /**< IEEE 802.3 Ethernet (DLT_EN10MB).  */
    NP_LINK_RAW       = 101,   /**< Raw IP, no link header (DLT_RAW).  */
    NP_LINK_LOOPBACK  = 108,   /**< OpenBSD/macOS loopback (DLT_LOOP). */
    NP_LINK_LINUX_SLL = 113,   /**< Linux "cooked" capture (DLT_LINUX_SLL). */
} np_linktype_t;

/* ------------------------------------------------------------------ */
/*  Protocol layer IDs                                                  */
/* ------------------------------------------------------------------ */

/**
 * np_proto_t - identifies the protocol of a decoded packet layer.
 *
 * Naming scheme
 * ─────────────
 * Protocols whose EtherType / IP-protocol numbers are well-known are
 * encoded directly (IP4 = 0x0800, IP6 = 0x86DD, ARP = 0x0806,
 * TCP = 6, UDP = 17).  Application-layer protocols that do not have a
 * single canonical number use a private range above 0x010000 so they
 * never collide with Layer-2/3/4 values.
 *
 * Note: NP_PROTO_ETH (0x0001) and NP_PROTO_ICMP (0x0001FF) both start
 * with 0x0001 in hex, but do NOT collide (0x1 ≠ 0x1FF).  The raw
 * integer values are stable and may be persisted.
 */
typedef enum {
    NP_PROTO_RAW       = 0x000000,  /**< Raw IP frame — no link header.         */
    NP_PROTO_ETH       = 0x000001,  /**< Ethernet (IEEE 802.3).                 */
    NP_PROTO_ARP       = 0x000806,  /**< Address Resolution Protocol.           */
    NP_PROTO_IP4       = 0x000800,  /**< Internet Protocol version 4.           */
    NP_PROTO_IP6       = 0x0086DD,  /**< Internet Protocol version 6.           */
    NP_PROTO_ICMP      = 0x0001FF,  /**< ICMP / ICMPv6 (private encoding).      */
    NP_PROTO_TCP       = 0x000006,  /**< Transmission Control Protocol.         */
    NP_PROTO_UDP       = 0x000011,  /**< User Datagram Protocol.                */
    NP_PROTO_DNS       = 0x010001,  /**< Domain Name System (private encoding). */
    NP_PROTO_HTTP      = 0x020001,  /**< HTTP/1.x (private encoding).           */
    NP_PROTO_TLS       = 0x020002,  /**< TLS/SSL (private encoding).            */
    NP_PROTO_QUIC      = 0x020003,  /**< QUIC (private encoding). NP_EXPERIMENTAL. */
    NP_PROTO_DHCP      = 0x010002,  /**< DHCPv4 (private encoding).             */
    NP_PROTO_SIP       = 0x020004,  /**< Session Initiation Protocol.           */
    NP_PROTO_MQTT      = 0x010003,  /**< MQTT (private encoding).               */
    NP_PROTO_VXLAN     = 0x010004,  /**< VXLAN overlay (private encoding).      */
} np_proto_t;

/* ------------------------------------------------------------------ */
/*  Zero-copy string                                                    */
/* ------------------------------------------------------------------ */

/**
 * np_str_t - a non-owning string slice (pointer + length).
 *
 * The string data is NOT NUL-terminated.  Always use .len to bound reads.
 * The pointer is valid only for the lifetime of the np_packet_t it came from.
 */
typedef struct {
    const char *str;
    size_t      len;
} np_str_t;

/* ------------------------------------------------------------------ */
/*  Decoded HTTP message                                                */
/* ------------------------------------------------------------------ */

/** Maximum number of HTTP headers decoded per message. */
#define NP_MAX_HTTP_HEADERS 32

/** np_http_header_t - a single HTTP header name/value pair. */
typedef struct {
    np_str_t name;
    np_str_t value;
} np_http_header_t;

/**
 * np_http_msg_t - zero-copy decoded HTTP/1.x request or response.
 *
 * Access via:
 *   if (pkt->app && pkt->app->proto == NP_PROTO_HTTP)
 *       np_http_msg_t *m = (np_http_msg_t *)pkt->app->decoded;
 *
 * All np_str_t fields point into the packet's raw capture buffer and
 * are valid only for the lifetime of the np_packet_t.
 */
typedef struct {
    bool     is_request;     /**< true = request, false = response.   */

    /* ---- request fields (valid when is_request == true) ---- */
    np_str_t method;         /**< e.g., "GET", "POST".                */
    np_str_t path;           /**< Request-URI, e.g., "/index.html".   */
    np_str_t version;        /**< HTTP version, e.g., "HTTP/1.1".     */

    /* ---- response fields (valid when is_request == false) --- */
    int      status_code;    /**< e.g., 200, 404.                     */
    np_str_t status_phrase;  /**< e.g., "OK", "Not Found".            */

    /* ---- common ---- */
    int              num_headers;
    np_http_header_t headers[NP_MAX_HTTP_HEADERS];

    const uint8_t   *body;      /**< Message body bytes (may be NULL). */
    size_t           body_len;  /**< Length of body in bytes.          */
} np_http_msg_t;

/* ------------------------------------------------------------------ */
/*  Decoded DNS message                                                 */
/* ------------------------------------------------------------------ */

/** Maximum number of DNS answer records decoded per message. */
#define NP_MAX_DNS_ANSWERS 8

/**
 * np_dns_answer_t - a single decoded DNS resource record.
 */
typedef struct {
    char     name[256];      /**< Owner name of the record.                     */
    uint16_t type;           /**< Record type (A=1, AAAA=28, CNAME=5, …).       */
    uint16_t class_;         /**< Record class (typically IN=1).                */
    uint32_t ttl;            /**< Time-to-live in seconds.                      */
    uint16_t data_len;       /**< Wire length of RDATA.                         */
    char     rdata_str[256]; /**< Human-readable RDATA (IP addr, CNAME target). */
} np_dns_answer_t;

/**
 * np_dns_msg_t - zero-copy decoded DNS query or response.
 *
 * Access via:
 *   if (pkt->app && pkt->app->proto == NP_PROTO_DNS)
 *       np_dns_msg_t *d = (np_dns_msg_t *)pkt->app->decoded;
 */
typedef struct {
    uint16_t id;              /**< Transaction ID from the DNS header.           */
    bool     is_response;     /**< true = response, false = query.               */
    int      rcode;           /**< Response code (0=NOERROR, 3=NXDOMAIN, …).    */

    char     query_name[256]; /**< Queried domain name, NUL-terminated.          */
    uint16_t query_type;      /**< Query type (A=1, AAAA=28, …).                 */

    int             num_answers;              /**< Count of valid entries in answers[]. */
    np_dns_answer_t answers[NP_MAX_DNS_ANSWERS];
} np_dns_msg_t;

/* ------------------------------------------------------------------ */
/*  Packet                                                              */
/* ------------------------------------------------------------------ */

/** Maximum number of protocol layers in one packet. */
#define NP_MAX_LAYERS 8

/**
 * np_layer_t - one decoded protocol layer within an np_packet_t.
 *
 * 'data' points into the packet's 'raw' buffer; no copy is made.
 * 'decoded' points into the packet's scratch space for structured
 * decode results (np_http_msg_t, np_dns_msg_t, etc.).
 */
typedef struct np_layer {
    np_proto_t    proto;          /**< Protocol identifier.                      */
    const uint8_t *data;          /**< Start of this layer's bytes in raw[].     */
    size_t         len;           /**< Byte length of this layer (hdr + payload).*/
    void          *decoded;       /**< Parsed struct in scratch space (or NULL). */
} np_layer_t;

/**
 * np_packet_t - a fully decoded network packet.
 *
 * Stable fields (ABI guaranteed for all v0.x releases):
 *   ts, caplen, wirelen, raw, nlayers, layers[], eth, net, transport,
 *   app, seq, flow_id, stream_data, stream_len, user_data, reserved[].
 *
 * Do NOT access scratch[] or scratch_used directly; they are managed
 * internally.  Use np_packet_alloc() / np_packet_free() for lifecycle,
 * and np_packet_clone() for copies.
 */
typedef struct np_packet {
    /* ---- capture metadata ---- */
    struct timespec  ts;          /**< Capture timestamp (CLOCK_REALTIME).       */
    uint32_t         caplen;      /**< Bytes actually captured.                  */
    uint32_t         wirelen;     /**< Bytes on the wire.                        */
    uint8_t         *raw;         /**< Raw frame buffer (caplen bytes).          */

    /* ---- layer stack ---- */
    int              nlayers;                /**< Number of valid layers[].       */
    np_layer_t       layers[NP_MAX_LAYERS];  /**< Layer array, layers[0]=link.   */

    /* ---- convenience layer pointers (NULL if layer not present) ---- */
    const np_layer_t *eth;        /**< Ethernet / Linux SLL link layer.          */
    const np_layer_t *net;        /**< IPv4 / IPv6 / ARP network layer.          */
    const np_layer_t *transport;  /**< TCP / UDP / ICMP transport layer.         */
    const np_layer_t *app;        /**< HTTP / DNS / TLS application layer.       */

    /* ---- packet metadata ---- */
    uint64_t         seq;         /**< Monotonically increasing capture index.   */
    uint32_t         flow_id;     /**< 5-tuple flow hash (src/dst ip+port+proto).*/

    /* ---- TCP stream reassembly (set by np_processor_tcp_stream) ---- */
    uint8_t         *stream_data; /**< Reassembled TCP payload (heap-allocated). */
    size_t           stream_len;  /**< Byte length of stream_data.               */

    /* ---- caller-owned context pointer ---- */
    void            *user_data;   /**< Not touched by the library; use freely.   */

    /* ---- internal scratch space — do not access directly ---- */
    uint8_t          scratch[8192];
    size_t           scratch_used;

    /* ---- ABI padding for future stable extensions ---- */
    void            *reserved[4]; /**< Must be NULL; reserved for library use.   */
} np_packet_t;

/**
 * np_packet_alloc() - allocate a new empty packet with a raw buffer of caplen bytes.
 * Returns NULL on allocation failure.
 */
np_packet_t *np_packet_alloc(size_t caplen);

/**
 * np_packet_free() - release all memory owned by pkt, including stream_data.
 * Passing NULL is safe and a no-op.
 */
void         np_packet_free(np_packet_t *pkt);

/**
 * np_packet_clone() - deep-copy src into a new heap allocation.
 * Returns NULL on allocation failure.
 */
np_packet_t *np_packet_clone(const np_packet_t *src);

/**
 * np_packet_ts_str() - format pkt->ts as "HH:MM:SS.uuuuuu" into buf.
 * buf must be at least 16 bytes; 32 is recommended.
 */
void np_packet_ts_str(const np_packet_t *pkt, char *buf, size_t bufsz);

/**
 * np_packet_app_layer_is_decrypted() - returns true if the application
 * layer pointer (pkt->app->data) has been redirected from the original
 * packet raw buffer to a heap-allocated decrypted-plaintext buffer.
 *
 * FIX (issue: np_processor_tls_decrypt mutates pkt->layers[i].data in
 * place to point at decrypted plaintext — a subtle aliasing invariant
 * that np_packet_clone had to be taught to handle):
 *   This function lets downstream code (processors, sinks, scripts)
 *   detect the aliasing explicitly instead of having to compare
 *   pkt->app->data against [pkt->raw, pkt->raw+pkt->caplen) by hand.
 *   Code that needs the ORIGINAL (encrypted) bytes can use
 *   np_packet_original_app_layer() below.
 */
bool np_packet_app_layer_is_decrypted(const np_packet_t *pkt);

/**
 * np_packet_original_app_layer() - if the application layer has been
 * redirected to a decrypted plaintext buffer, return a pointer to the
 * ORIGINAL (encrypted) bytes inside pkt->raw; otherwise return
 * pkt->app->data unchanged.  Output length is written to *out_len.
 * Returns NULL if the packet has no app layer.
 */
const uint8_t *np_packet_original_app_layer(const np_packet_t *pkt,
                                             size_t *out_len);

/* ------------------------------------------------------------------ */
/*  Pipeline context                                                    */
/* ------------------------------------------------------------------ */

/**
 * np_pipeline_t - opaque pipeline orchestrator.
 *
 * A pipeline owns every component added to it (sources, filters,
 * processors, sinks).  Freeing the pipeline frees all of them.
 */
typedef struct np_pipeline np_pipeline_t;

/** np_pipeline_new() - allocate an empty pipeline.  Returns NULL on OOM. */
np_pipeline_t *np_pipeline_new(void);

/**
 * np_pipeline_free() - stop (if running) and release all pipeline resources.
 * All attached components are freed.  Passing NULL is safe.
 */
void           np_pipeline_free(np_pipeline_t *pl);

/**
 * np_pipeline_run() - start processing packets; blocks until stopped or error.
 * Returns NP_OK on clean shutdown, or an np_err_t code on error.
 */
np_err_t       np_pipeline_run(np_pipeline_t *pl);

/**
 * np_pipeline_stop() - signal the pipeline to shut down gracefully.
 * Thread-safe; safe to call from a signal handler.
 * np_pipeline_run() will return after the current packet is finished.
 */
void           np_pipeline_stop(np_pipeline_t *pl);

/* ------------------------------------------------------------------ */
/*  Source (input)                                                      */
/* ------------------------------------------------------------------ */

/** np_source_t - opaque packet ingestion source. */
typedef struct np_source np_source_t;

/**
 * np_source_live() - create a live-capture source via libpcap.
 *
 * @device     Network interface name, e.g. "eth0" or "any".
 * @snaplen    Maximum bytes captured per packet (65535 = full packet).
 * @promisc    Non-zero to enable promiscuous mode.
 * @timeout_ms Read timeout in milliseconds (0 = no timeout).
 *
 * Requires CAP_NET_RAW or root.  Returns NULL on error.
 */
np_source_t *np_source_live(const char *device, int snaplen,
                             int promisc, int timeout_ms);

/**
 * np_source_file() - create an offline source that reads a PCAP or PCAP-NG file.
 * Does not require elevated privileges.  Returns NULL on error.
 */
np_source_t *np_source_file(const char *path);

/**
 * np_source_ring() - create a high-throughput live source using AF_PACKET + PACKET_MMAP.
 * Maps the kernel RX ring directly into user-space; avoids per-packet syscalls.
 * Requires CAP_NET_RAW or root.  Returns NULL on error.
 *
 * FIX (issues: ETH_P_ALL by default + hardcoded ring size):
 *   @eth_proto    EtherType to capture, in HOST byte order.  Pass
 *                 0x0003 (ETH_P_ALL) to capture every protocol on the
 *                 wire.  Use 0x0800 (IPv4), 0x86DD (IPv6), or 0x0806
 *                 (ARP) to restrict the kernel-side filter and cut
 *                 down on user-space processing of unwanted frames.
 *   @ring_blocks  Number of 1 MiB blocks in the PACKET_RX_RING ring
 *                 buffer.  0 selects the default (8 = 8 MiB).
 *                 Larger rings tolerate larger traffic bursts but
 *                 consume more memory and take longer to drain on
 *                 shutdown.
 */
np_source_t *np_source_ring(const char *device,
                             uint16_t eth_proto,
                             int      ring_blocks);

/**
 * np_source_free() - release a source that was NOT added to a pipeline.
 * Sources added via np_pipeline_add_source() are owned by the pipeline;
 * do NOT call this on them.
 */
void         np_source_free(np_source_t *src);

/**
 * np_source_set_kernel_bpf() - install a BPF filter on the underlying
 * capture handle (libpcap sources only) so the kernel drops non-matching
 * packets BEFORE they cross the kernel/user boundary.
 *
 * FIX (issue: BPF filters were run in user-space via bpf_filter()
 * instead of being compiled into the kernel via pcap_setfilter()):
 * calling this is strictly an optimization — semantically equivalent
 * to adding np_filter_bpf() to the pipeline, but avoids the per-packet
 * kernel→user memory copy for packets that would be filtered out.
 * On a high-traffic interface this can reduce CPU usage by orders of
 * magnitude (e.g. "tcp port 80" on a 10 Gbps mirror typically drops
 * 99%+ of frames in the kernel).
 *
 * Must be called BEFORE np_pipeline_run().  Returns NP_OK on success,
 * NP_ERR_FILTER on compile error (bad expression), or NP_ERR_GENERIC
 * on installation failure.  Sources that don't support kernel-side BPF
 * (e.g. np_source_ring) return NP_ERR_PROTO without modifying state.
 */
np_err_t     np_source_set_kernel_bpf(np_source_t *src, const char *expr);

/** np_pipeline_add_source() - attach src to pl.  pl takes ownership of src. */
np_err_t     np_pipeline_add_source(np_pipeline_t *pl, np_source_t *src);

/* ------------------------------------------------------------------ */
/*  Filter                                                              */
/* ------------------------------------------------------------------ */

/** np_filter_t - opaque packet filter. */
typedef struct np_filter np_filter_t;

/**
 * np_filter_bpf() - compile a libpcap/tcpdump BPF expression.
 * e.g. "tcp port 443 and host 8.8.8.8".  Returns NULL on compile error.
 */
np_filter_t *np_filter_bpf(const char *expr);

/**
 * np_filter_proto() - match packets containing proto anywhere in their layer stack.
 * e.g. np_filter_proto(NP_PROTO_DNS) passes only DNS packets.
 */
np_filter_t *np_filter_proto(np_proto_t proto);

/** np_filter_port() - match TCP or UDP packets with source or destination port == port. */
np_filter_t *np_filter_port(uint16_t port);

/** np_filter_host() - match packets with source or destination IPv4 address == host. */
np_filter_t *np_filter_host(const char *host);

/**
 * np_filter_and() / np_filter_or() / np_filter_not() - compose filters.
 *
 * OWNERSHIP: a and b are consumed by these calls.  The caller must not
 * free them; the returned composite filter owns them and will free them
 * when it is itself freed.
 */
np_filter_t *np_filter_and(np_filter_t *a, np_filter_t *b);
np_filter_t *np_filter_or (np_filter_t *a, np_filter_t *b);
np_filter_t *np_filter_not(np_filter_t *a);

/**
 * np_filter_free() - release a filter that was NOT added to a pipeline.
 * Filters added via np_pipeline_add_filter() are owned by the pipeline.
 */
void         np_filter_free(np_filter_t *f);

/** np_pipeline_add_filter() - attach f to pl.  Multiple filters are ANDed. pl takes ownership. */
np_err_t     np_pipeline_add_filter(np_pipeline_t *pl, np_filter_t *f);

/* ------------------------------------------------------------------ */
/*  Processor / transform                                               */
/* ------------------------------------------------------------------ */

/** np_processor_t - opaque packet processor / transform. */
typedef struct np_processor np_processor_t;

/**
 * np_proc_fn - signature for user-supplied callback processors.
 *
 * Return NP_OK to pass the packet forward to subsequent stages.
 * Return any negative np_err_t to drop the packet (it will not reach
 * later processors or sinks) and log a warning.
 * The callback must not free pkt; the pipeline owns it.
 */
typedef np_err_t (*np_proc_fn)(np_packet_t *pkt, void *userdata);

/**
 * np_processor_fn() - create a processor that calls fn(pkt, userdata) per packet.
 * The easiest way to hook custom C logic into a pipeline.
 */
np_processor_t *np_processor_fn(np_proc_fn fn, void *userdata);

/**
 * np_processor_tcp_stream() - TCP stream reassembly processor.
 * Tracks sequence numbers, reconstructs fragmented payloads, and
 * populates pkt->stream_data / pkt->stream_len for matched flows.
 *
 * FIX (issue: hardcoded TCP_MAX_STREAM_BYTES / TCP_HOLE_TIMEOUT_MS):
 *   @max_stream_bytes  Per-flow cap on the reassembled byte stream.
 *                      0 selects the default (1 MiB).  A long-lived
 *                      HTTP connection streaming more than this is
 *                      silently truncated; raise the cap if you need
 *                      the full stream.
 *   @hole_timeout_ms   Gap-flush timeout.  0 selects the default
 *                      (1000 ms).  If a gap persists longer than this,
 *                      the reassembler advances next_seq to the next
 *                      queued segment so lossy links make forward
 *                      progress instead of blocking forever.
 */
np_processor_t *np_processor_tcp_stream_ex(size_t max_stream_bytes,
                                            uint32_t hole_timeout_ms);

/** Backwards-compatible wrapper: defaults (1 MiB stream, 1 s hole timeout). */
np_processor_t *np_processor_tcp_stream(void);

/**
 * np_processor_rate_limit() - token-bucket rate limiter.
 * Throttles pipeline throughput to bytes_per_sec bytes per second.
 * The worker thread sleeps when the bucket is empty.
 */
np_processor_t *np_processor_rate_limit(uint64_t bytes_per_sec);

/**
 * np_processor_payload_transform() - in-place payload pattern replacer.
 *
 * @mode        "literal" or "regex".
 * @pattern     The byte string or regex to search for.
 * @replacement The replacement string.
 */
np_processor_t *np_processor_payload_transform(const char *mode,
                                                const char *pattern,
                                                const char *replacement);

/**
 * np_processor_flow_tracker() - five-tuple flow association processor.
 * Assigns pkt->flow_id based on (src_ip, dst_ip, src_port, dst_port, proto)
 * and maintains per-flow state accessible via user_data.
 *
 * FIX (issue: hardcoded FLOW_MAX_ENTRIES / FLOW_IDLE_TIMEOUT_S):
 *   @max_entries     Hard cap on the number of tracked flows.  0
 *                    selects the default (1,000,000).  Above the cap,
 *                    new flows are dropped (with a counter) to prevent
 *                    SYN-flood OOM.  Lower this for memory-constrained
 *                    sensors; raise it for very large segments.
 *   @idle_timeout_s  Evict flows idle for this many seconds.  0
 *                    selects the default (60 s).
 */
np_processor_t *np_processor_flow_tracker_ex(uint32_t max_entries,
                                              uint32_t idle_timeout_s);

/** Backwards-compatible wrapper: defaults (1M flows, 60 s idle). */
np_processor_t *np_processor_flow_tracker(void);

/**
 * np_processor_lua() - load and execute a Lua 5.4 script per packet.
 * script_path must be readable; the Lua global 'pkt' is a table of
 * the packet's decoded fields.  Returns NULL if the script fails to load.
 *
 * FIX (issue: hardcoded NP_LUA_MEM_LIMIT):
 *   Use np_processor_lua_ex() to override the 16 MiB default Lua VM
 *   memory cap.  Scripts can also query the cap at runtime via the
 *   np_mem_stats() Lua binding.
 */
np_processor_t *np_processor_lua(const char *script_path);

/**
 * np_processor_lua_ex() - like np_processor_lua but with a custom VM
 * memory cap.  @mem_limit_bytes of 0 selects the default (16 MiB).
 */
np_processor_t *np_processor_lua_ex(const char *script_path,
                                     size_t mem_limit_bytes);

/**
 * np_processor_tls_decrypt() - TLS session decryption processor.
 *
 * Loads NSS key-log material (SSLKEYLOGFILE format) from keylog_path
 * and decrypts TLS 1.2 and TLS 1.3 records as they pass through the
 * pipeline.  Decrypted application data is exposed on pkt->stream_data
 * / pkt->stream_len, with the original np_layer_t app layer replaced
 * by the decrypted plaintext.
 *
 * Requires the netpipe binary to be linked against OpenSSL 1.1.1+ or
 * 3.x.  Records that cannot be decrypted (no matching key material,
 * unsupported cipher suite, etc.) are passed through unchanged.
 *
 * Supported cipher suites:
 *   TLS 1.2:  TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
 *              TLS_CHACHA20_POLY1305_SHA256,
 *              TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
 *              TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
 *              TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
 *              TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
 *              TLS_RSA_WITH_AES_128_GCM_SHA256,
 *              TLS_RSA_WITH_AES_256_GCM_SHA384
 *   TLS 1.3:  TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
 *              TLS_CHACHA20_POLY1305_SHA256
 *
 * NP_EXPERIMENTAL: API subject to change.
 */
NP_EXPERIMENTAL np_processor_t *np_processor_tls_decrypt(const char *keylog_path);

/** np_pipeline_add_processor() - attach proc to pl.  pl takes ownership. */
np_err_t        np_pipeline_add_processor(np_pipeline_t *pl,
                                           np_processor_t *proc);

/* ------------------------------------------------------------------ */
/*  Sink (output)                                                       */
/* ------------------------------------------------------------------ */

/** np_sink_t - opaque packet output sink. */
typedef struct np_sink np_sink_t;

/**
 * Stable sinks
 * ─────────────
 * These sinks are part of the stable API and will not be removed or
 * have their signatures changed without a major version bump.
 *
 * path may be "-" to write to stdout, or NULL/"/dev/null" to discard.
 */

/** np_sink_pcap()  - write Wireshark-compatible binary PCAP. */
np_sink_t *np_sink_pcap(const char *path);

/** np_sink_pcapng() - write PCAP-NG with interface and metadata blocks. */
np_sink_t *np_sink_pcapng(const char *path);

/** np_sink_json()  - write one NDJSON object per packet. */
np_sink_t *np_sink_json(const char *path);

/** np_sink_hex()   - write annotated hex dump with layer boundaries. */
np_sink_t *np_sink_hex(const char *path);

/** np_sink_stats() - write periodic (5-second) packet/byte counters. */
np_sink_t *np_sink_stats(const char *path);

/** np_sink_null()  - discard all packets; useful for benchmarking. */
np_sink_t *np_sink_null(void);

/** np_sink_pretty() - write tshark-style single-line packet summaries. */
np_sink_t *np_sink_pretty(const char *path);

/**
 * Experimental sinks
 * ───────────────────
 * These sinks are functional but their URI format and behaviour may
 * change in future releases.  Tag: NP_EXPERIMENTAL.
 */

/**
 * np_sink_tuntap() - inject packets into a Linux TUN/TAP virtual interface.
 *
 * uri format: "tun://tun0" or "tap://tap0".
 * Requires CAP_NET_ADMIN or root.
 * NP_EXPERIMENTAL: URI scheme may change.
 */
NP_EXPERIMENTAL np_sink_t *np_sink_tuntap(const char *uri);

/**
 * np_sink_socket() - stream packets over a TCP connection.
 *
 * uri format: "socket://host:port".
 * fmt: same values accepted by -fmt ("pcap", "json", "hex", ...). "pcap"
 * (the default) streams a live PCAP-framed byte stream that Wireshark/tshark
 * can read directly. "json" streams newline-delimited JSON records
 * identical to the json file/stdout sink. "hex" streams the same
 * human-readable hex dump as the hex sink. fmt may be NULL, which is
 * treated as "pcap".
 * NP_EXPERIMENTAL: URI scheme and framing may change.
 */
NP_EXPERIMENTAL np_sink_t *np_sink_socket(const char *uri, const char *fmt);

/**
 * np_sink_free() - release a sink that was NOT added to a pipeline.
 * Sinks added via np_pipeline_add_sink() are owned by the pipeline.
 */
void       np_sink_free(np_sink_t *s);

/** np_pipeline_add_sink() - attach s to pl.  pl takes ownership. */
np_err_t   np_pipeline_add_sink(np_pipeline_t *pl, np_sink_t *s);

/* ------------------------------------------------------------------ */
/*  Global library init / teardown                                      */
/* ------------------------------------------------------------------ */

/**
 * np_init() - initialize the netpipe library.
 *
 * Must be called once before any other library function.
 * Initialises pcap, the logging subsystem, and built-in plugin registry.
 * Returns NP_OK on success or a negative np_err_t on failure.
 */
np_err_t np_init(void);

/**
 * np_cleanup() - release all global library resources.
 *
 * Call once when finished with the library.  Do not call any library
 * function after np_cleanup() returns.
 */
void     np_cleanup(void);

#ifdef __cplusplus
}
#endif
#endif /* NETPIPE_H */
