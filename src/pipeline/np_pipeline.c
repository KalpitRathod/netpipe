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
#include <errno.h>
#include <stdatomic.h>

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
    atomic_init(&pl->running, false);
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
    atomic_store(&pl->running, false);
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
    _Atomic bool   running;       /* Bug P4 fix: atomic for cross-thread visibility */
    bool           thread_created; /* Bug P3 fix: track so we only join if created */
} src_worker_t;

static void queue_init(pkt_queue_t *q)
{
    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->cond, NULL);
}

static void queue_push(pkt_queue_t *q, np_packet_t *pkt, np_linktype_t linktype,
                     uint64_t *dropped_counter)
{
    queue_node_t *node = malloc(sizeof(*node));
    if (!node) {
        np_packet_free(pkt);
        if (dropped_counter) (*dropped_counter)++;
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
        if (dropped_counter) (*dropped_counter)++;
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
    /* Bug B20 fix: compute the absolute deadline ONCE outside the loop.
     * The old code recomputed `ts = now + timeout_ms` on every iteration,
     * which means under repeated spurious wakeups the effective wait was
     * unbounded (each wakeup pushed the deadline forward by another
     * timeout_ms).  Now we compute the deadline once and let
     * pthread_cond_timedwait enforce it. */
    struct timespec deadline = {0, 0};
    if (timeout_ms > 0) {
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_nsec += (long)timeout_ms * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec  += deadline.tv_nsec / 1000000000L;
            deadline.tv_nsec %= 1000000000L;
        }
    }
    while (!q->head) {
        if (timeout_ms <= 0) {
            pthread_mutex_unlock(&q->lock);
            return false;
        }
        int rc = pthread_cond_timedwait(&q->cond, &q->lock, &deadline);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&q->lock);
            return false;
        }
        if (rc != 0) {
            /* Any other error — treat as a timeout to avoid spinning. */
            pthread_mutex_unlock(&q->lock);
            return false;
        }
        /* rc == 0: signalled.  Loop back and re-check q->head. */
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

    while (atomic_load(&w->running) && atomic_load(&w->pl->running)) {
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

        queue_push(q, pkt, src->linktype, &w->pl->pkts_dropped);
    }

    atomic_store(&w->running, false);
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

    /* Bug C5 fix: reject mixed-linktype pipelines at run-time.  If
     * sources have different link types (e.g. Ethernet + Loopback),
     * all sinks would be opened with sources[0]'s linktype, and
     * packets from the other sources would be written with the wrong
     * framing — producing corrupt output files.  The proper fix
     * would be to support per-packet linktype at the sink layer
     * (e.g. via PCAP-NG Interface Description Blocks), but that's a
     * larger change.  For now, refuse to run. */
    if (pl->nsources > 1) {
        np_linktype_t first = pl->sources[0]->linktype;
        for (int i = 1; i < pl->nsources; i++) {
            if (pl->sources[i]->linktype != first) {
                NP_LOG_ERROR("mixed linktypes across sources: "
                            "sources[0]=%d vs sources[%d]=%d. "
                            "Mixed-linktype pipelines are not supported.",
                            first, i, pl->sources[i]->linktype);
                return NP_ERR_GENERIC;
            }
        }
    }

    /* Open all sources */
    int opened_sources = 0;
    for (int i = 0; i < pl->nsources; i++) {
        np_err_t e = pl->sources[i]->ops->open(pl->sources[i]);
        if (e != NP_OK) {
            NP_LOG_ERROR("failed to open source '%s'", pl->sources[i]->name);
            /* Bug P5 fix: close already-opened sources before returning. */
            for (int j = 0; j < opened_sources; j++) {
                pl->sources[j]->ops->close(pl->sources[j]);
            }
            return e;
        }
        NP_LOG_INFO("source '%s' opened (linktype=%d)",
                    pl->sources[i]->name, pl->sources[i]->linktype);
        opened_sources++;
    }

    /* Open all sinks now that linktypes are known */
    np_linktype_t lt = pl->nsources > 0 ? pl->sources[0]->linktype : NP_LINK_ETHERNET;
    int opened_sinks = 0;
    for (int i = 0; i < pl->nsinks; i++) {
        np_err_t e = pl->sinks[i]->ops->open(pl->sinks[i], lt);
        if (e != NP_OK) {
            NP_LOG_ERROR("failed to open sink '%s'", pl->sinks[i]->name);
            /* Bug P5 fix: close already-opened sources AND sinks. */
            for (int j = 0; j < opened_sinks; j++) {
                pl->sinks[j]->ops->close(pl->sinks[j]);
            }
            for (int j = 0; j < opened_sources; j++) {
                pl->sources[j]->ops->close(pl->sources[j]);
            }
            return e;
        }
        opened_sinks++;
    }

    pkt_queue_t q;
    queue_init(&q);

    src_worker_t *workers = calloc((size_t)pl->nsources, sizeof(src_worker_t));
    if (!workers) {
        queue_free(&q);
        /* Bug P5 fix: close sources and sinks we just opened. */
        for (int j = 0; j < opened_sources; j++) {
            pl->sources[j]->ops->close(pl->sources[j]);
        }
        for (int j = 0; j < opened_sinks; j++) {
            pl->sinks[j]->ops->close(pl->sinks[j]);
        }
        return NP_ERR_NOMEM;
    }

    atomic_store(&pl->running, true);
    NP_LOG_INFO("pipeline running (%d source(s), %d filter(s), %d proc(s), %d sink(s))",
                pl->nsources, pl->nfilters, pl->nprocessors, pl->nsinks);

    // Spawn capture threads
    int spawned_workers = 0;
    for (int i = 0; i < pl->nsources; i++) {
        workers[i].pl = pl;
        workers[i].src = pl->sources[i];
        workers[i].q = &q;
        atomic_store(&workers[i].running, true);
        workers[i].thread_created = false;
        /* Bug P3 fix: check pthread_create return value.  On EAGAIN
         * (thread exhaustion) the thread handle is uninitialized;
         * calling pthread_join on it is undefined behaviour. */
        int rc = pthread_create(&workers[i].thread, NULL, src_worker_fn, &workers[i]);
        if (rc != 0) {
            NP_LOG_ERROR("pthread_create for source %d failed: %s",
                         i, strerror(rc));
            atomic_store(&workers[i].running, false);
            /* Signal the queue so any already-spawned workers can wake
             * up and notice pl->running went false (set below). */
            continue;
        }
        workers[i].thread_created = true;
        spawned_workers++;
    }
    if (spawned_workers == 0) {
        NP_LOG_ERROR("%s", "no capture threads could be spawned — aborting");
        atomic_store(&pl->running, false);
        free(workers);
        queue_free(&q);
        for (int j = 0; j < opened_sources; j++) {
            pl->sources[j]->ops->close(pl->sources[j]);
        }
        for (int j = 0; j < opened_sinks; j++) {
            pl->sinks[j]->ops->close(pl->sinks[j]);
        }
        return NP_ERR_GENERIC;
    }

    while (atomic_load(&pl->running)) {
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
                if (atomic_load(&workers[i].running)) {
                    all_done = false;
                    break;
                }
            }
            if (all_done) {
                /* Bug H10 fix: drain the queue before exiting.  The
                 * old code unlocked-read q.size, which races with
                 * producer threads.  queue_pop already drained the
                 * queue (it returned false because of the 10ms
                 * timeout, not because the queue was empty), so if
                 * all_done is true AND the queue is truly empty, we
                 * can exit.  We re-check by attempting one more
                 * non-blocking pop. */
                np_packet_t *drain_pkt = NULL;
                np_linktype_t drain_lt;
                if (!queue_pop(&q, &drain_pkt, &drain_lt, 0)) {
                    break;  /* queue empty AND no producers running */
                }
                /* Re-process the drained packet. */
                pl->pkts_captured++;
                pl->bytes_captured += drain_pkt->caplen;
                drain_pkt->seq = pl->pkts_captured;
                np_demux_packet(drain_pkt, drain_lt);
                bool pass = true;
                for (int fi = 0; fi < pl->nfilters && pass; fi++) {
                    pass = pl->filters[fi]->ops->match(pl->filters[fi], drain_pkt);
                }
                if (pass) {
                    bool proc_pass = true;
                    for (int pi = 0; pi < pl->nprocessors; pi++) {
                        np_err_t pe = pl->processors[pi]->ops->process(pl->processors[pi], drain_pkt);
                        if (pe != NP_OK) { proc_pass = false; break; }
                    }
                    if (proc_pass) {
                        pl->pkts_processed++;
                        for (int ki = 0; ki < pl->nsinks; ki++) {
                            pl->sinks[ki]->ops->write(pl->sinks[ki], drain_pkt);
                        }
                    } else {
                        pl->pkts_filtered++;
                    }
                } else {
                    pl->pkts_filtered++;
                }
                np_packet_free(drain_pkt);
            }
        }
    }

    // Stop and join workers
    atomic_store(&pl->running, false);
    for (int i = 0; i < pl->nsources; i++) {
        atomic_store(&workers[i].running, false);
        if (pl->sources[i]->ops->stop) {
            pl->sources[i]->ops->stop(pl->sources[i]);
        }
    }
    /* Wake any worker blocked on queue_push (it holds q.lock briefly
     * so this isn't required, but signal anyway). */
    pthread_mutex_lock(&q.lock);
    pthread_cond_broadcast(&q.cond);
    pthread_mutex_unlock(&q.lock);
    for (int i = 0; i < pl->nsources; i++) {
        if (workers[i].thread_created) {
            pthread_join(workers[i].thread, NULL);
        }
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

    NP_LOG_INFO("pipeline stopped — captured=%lu  filtered=%lu  processed=%lu  dropped=%lu  bytes=%lu",
                (unsigned long)pl->pkts_captured,
                (unsigned long)pl->pkts_filtered,
                (unsigned long)pl->pkts_processed,
                (unsigned long)pl->pkts_dropped,
                (unsigned long)pl->bytes_captured);

    return NP_OK;
}
