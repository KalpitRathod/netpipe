/*
 * netpipe - FFmpeg-like network traffic processing pipeline
 *
 * Copyright (C) 2026 netpipe contributors
 *
 * This is the top-level public header. Include this in downstream
 * consumers; internal modules use their own headers directly.
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

/* ------------------------------------------------------------------ */
/*  Return codes                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    NP_OK            =  0,
    NP_ERR_GENERIC   = -1,
    NP_ERR_NOMEM     = -2,
    NP_ERR_IO        = -3,
    NP_ERR_PROTO     = -4,
    NP_ERR_FILTER    = -5,
    NP_ERR_TIMEOUT   = -6,
    NP_ERR_NODEV     = -7,
    NP_ERR_PERM      = -8,
    NP_ERR_EOF       = -9,
} np_err_t;

const char *np_strerror(np_err_t err);

/* ------------------------------------------------------------------ */
/*  Link layer types                                                    */
/* ------------------------------------------------------------------ */

typedef enum {
    NP_LINK_UNKNOWN  = 0,
    NP_LINK_ETHERNET = 1,
    NP_LINK_RAW      = 101,
    NP_LINK_LOOPBACK = 108,
    NP_LINK_LINUX_SLL = 113,
} np_linktype_t;

/* ------------------------------------------------------------------ */
/*  Protocol Layer Structs                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *str;
    size_t      len;
} np_str_t;

#define NP_MAX_HTTP_HEADERS 32

typedef struct {
    np_str_t name;
    np_str_t value;
} np_http_header_t;

typedef struct {
    bool is_request;
    
    /* Request fields */
    np_str_t method;
    np_str_t path;
    np_str_t version;
    
    /* Response fields */
    int      status_code;
    np_str_t status_phrase;
    
    int              num_headers;
    np_http_header_t headers[NP_MAX_HTTP_HEADERS];
    
    const uint8_t   *body;
    size_t           body_len;
} np_http_msg_t;

#define NP_MAX_DNS_ANSWERS 8

typedef struct {
    char     name[256];
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    uint16_t data_len;
    /* For A/AAAA/CNAME, we can store a string representation here */
    char     rdata_str[256];
} np_dns_answer_t;

typedef struct {
    uint16_t id;
    bool     is_response;
    int      rcode;
    
    char     query_name[256];
    uint16_t query_type;
    
    int              num_answers;
    np_dns_answer_t  answers[NP_MAX_DNS_ANSWERS];
} np_dns_msg_t;

/* ------------------------------------------------------------------ */
/*  Protocol layer IDs                                                  */
/* ------------------------------------------------------------------ */

typedef enum {
    NP_PROTO_RAW      = 0x0000,
    NP_PROTO_ETH      = 0x0001,
    NP_PROTO_ARP      = 0x0806,
    NP_PROTO_IP4      = 0x0800,
    NP_PROTO_IP6      = 0x86DD,
    NP_PROTO_ICMP     = 0x0001FF,
    NP_PROTO_TCP      = 0x000006,
    NP_PROTO_UDP      = 0x000011,
    NP_PROTO_DNS      = 0x010001,
    NP_PROTO_HTTP     = 0x020001,
    NP_PROTO_TLS      = 0x020002,
} np_proto_t;

/* ------------------------------------------------------------------ */
/*  Packet                                                              */
/* ------------------------------------------------------------------ */

#define NP_MAX_LAYERS 8

typedef struct np_layer {
    np_proto_t   proto;
    const uint8_t *data;
    size_t        len;
    /* decoded fields for quick access without re-parsing */
    void         *decoded;   /* points into packet scratch space */
} np_layer_t;

typedef struct np_packet {
    struct timespec  ts;
    uint32_t         caplen;
    uint32_t         wirelen;

    uint8_t         *raw;        /* raw capture buffer  */

    int              nlayers;
    np_layer_t       layers[NP_MAX_LAYERS];

    /* convenience pointers into layers[] */
    const np_layer_t *eth;
    const np_layer_t *net;       /* ip4 / ip6 / arp   */
    const np_layer_t *transport; /* tcp / udp / icmp  */
    const np_layer_t *app;       /* http / dns / tls  */

    /* internal scratch space for decoded structs */
    uint8_t          scratch[8192];
    size_t           scratch_used;

    /* stats / metadata */
    uint64_t         seq;        /* global capture sequence number */
    uint32_t         flow_id;    /* flow hash */

    /* stream reassembly payload (dynamically allocated, freed automatically) */
    uint8_t         *stream_data;
    size_t           stream_len;
} np_packet_t;

np_packet_t *np_packet_alloc(size_t caplen);
void         np_packet_free(np_packet_t *pkt);
np_packet_t *np_packet_clone(const np_packet_t *src);

/* ------------------------------------------------------------------ */
/*  Pipeline context                                                    */
/* ------------------------------------------------------------------ */

typedef struct np_pipeline np_pipeline_t;

np_pipeline_t *np_pipeline_new(void);
void           np_pipeline_free(np_pipeline_t *pl);
np_err_t       np_pipeline_run(np_pipeline_t *pl);
void           np_pipeline_stop(np_pipeline_t *pl);

/* ------------------------------------------------------------------ */
/*  Source (input)                                                      */
/* ------------------------------------------------------------------ */

struct np_source;
typedef struct np_source np_source_t;

np_source_t *np_source_live(const char *device, int snaplen, int promisc, int timeout_ms);
np_source_t *np_source_file(const char *path);
void         np_source_free(np_source_t *src);
np_err_t     np_pipeline_add_source(np_pipeline_t *pl, np_source_t *src);

/* ------------------------------------------------------------------ */
/*  Filter                                                              */
/* ------------------------------------------------------------------ */

struct np_filter;
typedef struct np_filter np_filter_t;

/* BPF-compatible filter expression */
np_filter_t *np_filter_bpf(const char *expr);
/* Built-in high-level filters */
np_filter_t *np_filter_proto(np_proto_t proto);
np_filter_t *np_filter_port(uint16_t port);
np_filter_t *np_filter_host(const char *host);
np_filter_t *np_filter_and(np_filter_t *a, np_filter_t *b);
np_filter_t *np_filter_or(np_filter_t *a,  np_filter_t *b);
np_filter_t *np_filter_not(np_filter_t *a);
void         np_filter_free(np_filter_t *f);
np_err_t     np_pipeline_add_filter(np_pipeline_t *pl, np_filter_t *f);

/* ------------------------------------------------------------------ */
/*  Processor / transform                                               */
/* ------------------------------------------------------------------ */

struct np_processor;
typedef struct np_processor np_processor_t;

/* callback-based processor */
typedef np_err_t (*np_proc_fn)(np_packet_t *pkt, void *userdata);
np_processor_t *np_processor_fn(np_proc_fn fn, void *userdata);
np_processor_t *np_processor_tcp_stream(void);
np_err_t        np_pipeline_add_processor(np_pipeline_t *pl, np_processor_t *proc);

/* ------------------------------------------------------------------ */
/*  Sink (output)                                                       */
/* ------------------------------------------------------------------ */

struct np_sink;
typedef struct np_sink np_sink_t;

np_sink_t *np_sink_pcap(const char *path);
np_sink_t *np_sink_json(const char *path);         /* newline-delimited JSON */
np_sink_t *np_sink_hex(const char *path);          /* human hex dump         */
np_sink_t *np_sink_stats(const char *path);        /* periodic statistics    */
np_sink_t *np_sink_null(void);                     /* /dev/null sink         */
void       np_sink_free(np_sink_t *s);
np_err_t   np_pipeline_add_sink(np_pipeline_t *pl, np_sink_t *s);

/* ------------------------------------------------------------------ */
/*  Global library init / teardown                                      */
/* ------------------------------------------------------------------ */

np_err_t np_init(void);
void     np_cleanup(void);

#ifdef __cplusplus
}
#endif
#endif /* NETPIPE_H */
