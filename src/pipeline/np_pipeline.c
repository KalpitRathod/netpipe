/*
 * np_pipeline.c — pipeline orchestration: source → filter → process → sink
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

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
        else
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
    for (int i = 0; i < pl->nsources; i++) {
        if (pl->sources[i]->ops->stop) {
            pl->sources[i]->ops->stop(pl->sources[i]);
        }
    }
}

/* ------------------------------------------------------------------ */
#define MAX_QUEUE_SIZE 10000

typedef struct queue_node {
    np_packet_t       *pkt;
    np_linktype_t      linktype;
    struct queue_node *next;
} queue_node_t;

typedef struct {
    queue_node_t    *head;
    queue_node_t    *tail;
    pthread_mutex_t  lock;
    pthread_cond_t   cond;
    int              size;
} pkt_queue_t;

typedef struct {
    np_pipeline_t *pl;
    np_source_t   *src;
    pkt_queue_t   *q;
    pthread_t      thread;
    volatile bool  running;
} src_worker_t;

static void queue_init(pkt_queue_t *q)
{
    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
}

static void queue_push(pkt_queue_t *q, np_packet_t *pkt, np_linktype_t linktype)
{
    queue_node_t *node = malloc(sizeof(*node));
    if (!node) {
        np_packet_free(pkt);
        return;
    }
    node->pkt = pkt;
    node->linktype = linktype;
    node->next = NULL;

    pthread_mutex_lock(&q->lock);
    // Drop packet if queue is full to prevent memory bloat on slow processing
    if (q->size >= MAX_QUEUE_SIZE) {
        pthread_mutex_unlock(&q->lock);
        free(node);
        np_packet_free(pkt);
        return;
    }
    if (!q->tail) {
        q->head = node;
        q->tail = node;
    } else {
        q->tail->next = node;
        q->tail = node;
    }
    q->size++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

static bool queue_pop(pkt_queue_t *q, np_packet_t **out_pkt, np_linktype_t *out_lt, int timeout_ms)
{
    pthread_mutex_lock(&q->lock);
    while (!q->head) {
        if (timeout_ms <= 0) {
            pthread_mutex_unlock(&q->lock);
            return false;
        }
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += (long)timeout_ms * 1000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += ts.tv_nsec / 1000000000L;
            ts.tv_nsec %= 1000000000L;
        }
        int rc = pthread_cond_timedwait(&q->cond, &q->lock, &ts);
        if (rc != 0) {
            pthread_mutex_unlock(&q->lock);
            return false;
        }
    }

    queue_node_t *node = q->head;
    q->head = node->next;
    if (!q->head) {
        q->tail = NULL;
    }
    q->size--;

    *out_pkt = node->pkt;
    *out_lt = node->linktype;
    free(node);

    pthread_mutex_unlock(&q->lock);
    return true;
}

static void queue_free(pkt_queue_t *q)
{
    pthread_mutex_lock(&q->lock);
    queue_node_t *curr = q->head;
    while (curr) {
        queue_node_t *next = curr->next;
        np_packet_free(curr->pkt);
        free(curr);
        curr = next;
    }
    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    pthread_mutex_unlock(&q->lock);
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->cond);
}

static void *src_worker_fn(void *arg)
{
    src_worker_t *w = arg;
    np_source_t *src = w->src;
    pkt_queue_t *q = w->q;

    while (w->running && w->pl->running) {
        np_packet_t *pkt = NULL;
        np_err_t e = src->ops->next(src, &pkt);

        if (e == NP_ERR_EOF) {
            break;
        }
        if (e == NP_ERR_TIMEOUT) {
            continue;
        }
        if (e != NP_OK || !pkt) {
            usleep(1000);
            continue;
        }

        queue_push(q, pkt, src->linktype);
    }

    w->running = false;
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Main run loop                                                       */
/* ------------------------------------------------------------------ */

np_err_t np_pipeline_run(np_pipeline_t *pl)
{
    if (pl->nsources == 0) {
        NP_LOG_ERROR("%s", "no sources configured");
        return NP_ERR_GENERIC;
    }
    if (pl->nsinks == 0) {
        NP_LOG_WARN("%s", "no sinks configured — packets will be discarded");
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

    /* Open all sinks now that linktypes are known */
    np_linktype_t lt = pl->nsources > 0 ? pl->sources[0]->linktype : NP_LINK_ETHERNET;
    for (int i = 0; i < pl->nsinks; i++) {
        np_err_t e = pl->sinks[i]->ops->open(pl->sinks[i], lt);
        if (e != NP_OK) {
            NP_LOG_ERROR("failed to open sink '%s'", pl->sinks[i]->name);
            return e;
        }
    }

    pkt_queue_t q;
    queue_init(&q);

    src_worker_t *workers = calloc((size_t)pl->nsources, sizeof(src_worker_t));
    if (!workers) {
        queue_free(&q);
        return NP_ERR_NOMEM;
    }

    pl->running = true;
    NP_LOG_INFO("pipeline running (%d source(s), %d filter(s), %d proc(s), %d sink(s))",
                pl->nsources, pl->nfilters, pl->nprocessors, pl->nsinks);

    // Spawn capture threads
    for (int i = 0; i < pl->nsources; i++) {
        workers[i].pl = pl;
        workers[i].src = pl->sources[i];
        workers[i].q = &q;
        workers[i].running = true;
        pthread_create(&workers[i].thread, NULL, src_worker_fn, &workers[i]);
    }

    while (pl->running) {
        np_packet_t *pkt = NULL;
        np_linktype_t pkt_lt;
        bool got = queue_pop(&q, &pkt, &pkt_lt, 10);

        if (got) {
            pl->pkts_captured++;
            pl->bytes_captured += pkt->caplen;
            pkt->seq = pl->pkts_captured;

            /* Decode layers */
            np_demux_packet(pkt, pkt_lt);

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
            bool proc_pass = true;
            for (int pi = 0; pi < pl->nprocessors; pi++) {
                np_err_t pe = pl->processors[pi]->ops->process(pl->processors[pi], pkt);
                if (pe != NP_OK) {
                    if (pe != NP_ERR_FILTER) {
                        NP_LOG_WARN("processor %d returned error %d", pi, pe);
                    }
                    proc_pass = false;
                    break;
                }
            }

            if (!proc_pass) {
                pl->pkts_filtered++;
                np_packet_free(pkt);
                continue;
            }

            pl->pkts_processed++;

            /* Write to all sinks */
            for (int ki = 0; ki < pl->nsinks; ki++) {
                pl->sinks[ki]->ops->write(pl->sinks[ki], pkt);
            }

            np_packet_free(pkt);
        } else {
            // Check if all source threads have finished
            bool all_done = true;
            for (int i = 0; i < pl->nsources; i++) {
                if (workers[i].running) {
                    all_done = false;
                    break;
                }
            }
            if (all_done && q.size == 0) {
                break;
            }
        }
    }

    // Stop and join workers
    pl->running = false;
    for (int i = 0; i < pl->nsources; i++) {
        workers[i].running = false;
        if (pl->sources[i]->ops->stop) {
            pl->sources[i]->ops->stop(pl->sources[i]);
        }
    }
    for (int i = 0; i < pl->nsources; i++) {
        pthread_join(workers[i].thread, NULL);
    }

    /* Teardown */
    for (int i = 0; i < pl->nsources; i++) {
        pl->sources[i]->ops->close(pl->sources[i]);
    }
    for (int i = 0; i < pl->nsinks; i++) {
        pl->sinks[i]->ops->close(pl->sinks[i]);
    }

    free(workers);
    queue_free(&q);

    NP_LOG_INFO("pipeline stopped — captured=%lu  filtered=%lu  processed=%lu  bytes=%lu",
                (unsigned long)pl->pkts_captured,
                (unsigned long)pl->pkts_filtered,
                (unsigned long)pl->pkts_processed,
                (unsigned long)pl->bytes_captured);

    return NP_OK;
}
