/*
 * np_pipeline.c — pipeline orchestration: source → filter → process → sink
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"
#include "../demux/np_demux.h"
#include "np_pipeline.h"

/* ------------------------------------------------------------------ */
/*  Pipeline lifecycle                                                  */
/* ------------------------------------------------------------------ */

np_pipeline_t *np_pipeline_new(void)
{
    np_pipeline_t *pl = calloc(1, sizeof(*pl));
    if (!pl) return NULL;
    pthread_mutex_init(&pl->lock, NULL);
    pl->running = false;
    return pl;
}

void np_pipeline_free(np_pipeline_t *pl)
{
    if (!pl) return;

    for (int i = 0; i < pl->nsources;    i++) np_source_free(pl->sources[i]);
    for (int i = 0; i < pl->nfilters;    i++) np_filter_free(pl->filters[i]);
    for (int i = 0; i < pl->nprocessors; i++) {
        if (pl->processors[i]->ops->free)
            pl->processors[i]->ops->free(pl->processors[i]);
        free(pl->processors[i]);
    }
    for (int i = 0; i < pl->nsinks;      i++) np_sink_free(pl->sinks[i]);

    pthread_mutex_destroy(&pl->lock);
    free(pl);
}

np_err_t np_pipeline_add_source(np_pipeline_t *pl, np_source_t *src)
{
    if (pl->nsources >= NP_MAX_SOURCES) return NP_ERR_GENERIC;
    pl->sources[pl->nsources++] = src;
    return NP_OK;
}

np_err_t np_pipeline_add_filter(np_pipeline_t *pl, np_filter_t *f)
{
    if (pl->nfilters >= NP_MAX_FILTERS) return NP_ERR_GENERIC;
    pl->filters[pl->nfilters++] = f;
    return NP_OK;
}

np_err_t np_pipeline_add_processor(np_pipeline_t *pl, np_processor_t *proc)
{
    if (pl->nprocessors >= NP_MAX_PROCESSORS) return NP_ERR_GENERIC;
    pl->processors[pl->nprocessors++] = proc;
    return NP_OK;
}

np_err_t np_pipeline_add_sink(np_pipeline_t *pl, np_sink_t *s)
{
    if (pl->nsinks >= NP_MAX_SINKS) return NP_ERR_GENERIC;
    pl->sinks[pl->nsinks++] = s;
    return NP_OK;
}

void np_pipeline_stop(np_pipeline_t *pl)
{
    pl->running = false;
}

/* ------------------------------------------------------------------ */
/*  Main run loop                                                       */
/* ------------------------------------------------------------------ */

np_err_t np_pipeline_run(np_pipeline_t *pl)
{
    if (pl->nsources == 0) {
        NP_LOG_ERROR("no sources configured");
        return NP_ERR_GENERIC;
    }
    if (pl->nsinks == 0) {
        NP_LOG_WARN("no sinks configured — packets will be discarded");
    }

    /* Open all sinks */
    np_linktype_t lt = pl->nsources > 0 ? pl->sources[0]->linktype : NP_LINK_ETHERNET;
    for (int i = 0; i < pl->nsinks; i++) {
        np_err_t e = pl->sinks[i]->ops->open(pl->sinks[i], lt);
        if (e != NP_OK) {
            NP_LOG_ERROR("failed to open sink '%s'", pl->sinks[i]->name);
            return e;
        }
    }

    /* Open all sources */
    for (int i = 0; i < pl->nsources; i++) {
        np_err_t e = pl->sources[i]->ops->open(pl->sources[i]);
        if (e != NP_OK) {
            NP_LOG_ERROR("failed to open source '%s'", pl->sources[i]->name);
            return e;
        }
        NP_LOG_INFO("source '%s' opened (linktype=%d)",
                    pl->sources[i]->name, pl->sources[i]->linktype);
    }

    pl->running = true;
    NP_LOG_INFO("pipeline running (%d source(s), %d filter(s), %d proc(s), %d sink(s))",
                pl->nsources, pl->nfilters, pl->nprocessors, pl->nsinks);

    /* Round-robin across sources until all are exhausted */
    int active = pl->nsources;
    bool *exhausted = calloc(pl->nsources, sizeof(bool));
    if (!exhausted) return NP_ERR_NOMEM;

    while (pl->running && active > 0) {
        for (int si = 0; si < pl->nsources && pl->running; si++) {
            if (exhausted[si]) continue;

            np_packet_t *pkt = NULL;
            np_err_t e = pl->sources[si]->ops->next(pl->sources[si], &pkt);

            if (e == NP_ERR_EOF || e == NP_ERR_TIMEOUT) {
                NP_LOG_INFO("source '%s' exhausted", pl->sources[si]->name);
                exhausted[si] = true;
                active--;
                continue;
            }
            if (e != NP_OK || !pkt) continue;

            pl->pkts_captured++;
            pl->bytes_captured += pkt->caplen;
            pkt->seq = pl->pkts_captured;

            /* Decode layers */
            np_demux_packet(pkt, pl->sources[si]->linktype);

            /* Apply filters — packet must pass ALL filters */
            bool pass = true;
            for (int fi = 0; fi < pl->nfilters && pass; fi++) {
                pass = pl->filters[fi]->ops->match(pl->filters[fi], pkt);
            }

            if (!pass) {
                pl->pkts_filtered++;
                np_packet_free(pkt);
                continue;
            }

            /* Run processors in order */
            for (int pi = 0; pi < pl->nprocessors && pl->running; pi++) {
                np_err_t pe = pl->processors[pi]->ops->process(pl->processors[pi], pkt);
                if (pe != NP_OK) {
                    NP_LOG_WARN("processor %d returned %d", pi, pe);
                }
            }

            pl->pkts_processed++;

            /* Write to all sinks */
            for (int ki = 0; ki < pl->nsinks; ki++) {
                pl->sinks[ki]->ops->write(pl->sinks[ki], pkt);
            }

            np_packet_free(pkt);
        }
    }

    /* Teardown */
    for (int i = 0; i < pl->nsources; i++)
        pl->sources[i]->ops->close(pl->sources[i]);
    for (int i = 0; i < pl->nsinks; i++)
        pl->sinks[i]->ops->close(pl->sinks[i]);

    free(exhausted);

    NP_LOG_INFO("pipeline stopped — captured=%lu  filtered=%lu  processed=%lu  bytes=%lu",
                (unsigned long)pl->pkts_captured,
                (unsigned long)pl->pkts_filtered,
                (unsigned long)pl->pkts_processed,
                (unsigned long)pl->bytes_captured);

    return NP_OK;
}
