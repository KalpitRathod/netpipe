/*
 * np_pipeline.h — internal pipeline wiring
 */

#pragma once
#ifndef NP_PIPELINE_H
#define NP_PIPELINE_H

#include "netpipe.h"
#include <pthread.h>

/* Forward declarations for internal sub-structures */
struct np_source_ops {
    np_err_t (*open )(np_source_t *src);
    np_err_t (*next )(np_source_t *src, np_packet_t **out);
    void     (*close)(np_source_t *src);
    void     (*free )(np_source_t *src);
};

struct np_source {
    const struct np_source_ops *ops;
    void                       *priv;  /* backend-specific data */
    np_linktype_t               linktype;
    char                        name[64];
};

struct np_filter_ops {
    bool     (*match)(np_filter_t *f, const np_packet_t *pkt);
    void     (*free )(np_filter_t *f);
};

struct np_filter {
    const struct np_filter_ops *ops;
    void                       *priv;
};

struct np_processor_ops {
    np_err_t (*process)(np_processor_t *proc, np_packet_t *pkt);
    void     (*free   )(np_processor_t *proc);
};

struct np_processor {
    const struct np_processor_ops *ops;
    void                          *priv;
};

struct np_sink_ops {
    np_err_t (*open )(np_sink_t *sink, np_linktype_t lt);
    np_err_t (*write)(np_sink_t *sink, const np_packet_t *pkt);
    void     (*close)(np_sink_t *sink);
    void     (*free )(np_sink_t *sink);
};

struct np_sink {
    const struct np_sink_ops *ops;
    void                     *priv;
    char                      name[64];
};

/* Maximum counts for each stage */
#define NP_MAX_SOURCES     8
#define NP_MAX_FILTERS    32
#define NP_MAX_PROCESSORS 32
#define NP_MAX_SINKS       8

struct np_pipeline {
    np_source_t    *sources   [NP_MAX_SOURCES];
    int             nsources;

    np_filter_t    *filters   [NP_MAX_FILTERS];
    int             nfilters;

    np_processor_t *processors[NP_MAX_PROCESSORS];
    int             nprocessors;

    np_sink_t      *sinks     [NP_MAX_SINKS];
    int             nsinks;

    volatile bool   running;
    pthread_mutex_t lock;

    /* stats */
    uint64_t        pkts_captured;
    uint64_t        pkts_filtered;
    uint64_t        pkts_processed;
    uint64_t        bytes_captured;
};

#endif /* NP_PIPELINE_H */
