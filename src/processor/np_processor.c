/*
 * np_processor.c — built-in packet processors / transforms
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"
#include "../pipeline/np_pipeline.h"

/* ------------------------------------------------------------------ */
/*  Callback-based processor (user-supplied function)                   */
/* ------------------------------------------------------------------ */

typedef struct { np_proc_fn fn; void *userdata; } fn_priv_t;

static np_err_t fn_process(np_processor_t *proc, np_packet_t *pkt)
{
    fn_priv_t *p = proc->priv;
    return p->fn(pkt, p->userdata);
}
static void fn_free(np_processor_t *proc) { free(proc->priv); free(proc); }

static const struct np_processor_ops fn_ops = { .process = fn_process, .free = fn_free };

np_processor_t *np_processor_fn(np_proc_fn fn, void *userdata)
{
    fn_priv_t *p = malloc(sizeof(*p)); if (!p) return NULL;
    p->fn       = fn;
    p->userdata = userdata;
    np_processor_t *proc = calloc(1, sizeof(*proc));
    if (!proc) { free(p); return NULL; }
    proc->ops  = &fn_ops;
    proc->priv = p;
    return proc;
}

/* ------------------------------------------------------------------ */
/*  Rate limiter (Token Bucket)                                         */
/* ------------------------------------------------------------------ */

#include <unistd.h>
#include <time.h>

typedef struct {
    uint64_t bytes_per_sec;
    double   bucket;
    uint64_t last_time_ns;
} rate_priv_t;

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static np_err_t rate_process(np_processor_t *proc, np_packet_t *pkt)
{
    rate_priv_t *p = proc->priv;
    
    while (1) {
        uint64_t now = get_time_ns();
        uint64_t elapsed = now - p->last_time_ns;
        p->last_time_ns = now;
        
        p->bucket += (double)elapsed * ((double)p->bytes_per_sec / 1000000000.0);
        if (p->bucket > (double)(p->bytes_per_sec)) {
            p->bucket = (double)p->bytes_per_sec;
        }
        
        if (p->bucket >= (double)pkt->wirelen) {
            p->bucket -= (double)pkt->wirelen;
            break;
        } else {
            double needed = (double)pkt->wirelen - p->bucket;
            double wait_s = needed / (double)p->bytes_per_sec;
            useconds_t us = (useconds_t)(wait_s * 1000000.0);
            if (us == 0) us = 1;
            usleep(us);
        }
    }
    return NP_OK;
}

static void rate_free(np_processor_t *proc) { free(proc->priv); free(proc); }
static const struct np_processor_ops rate_ops = { .process = rate_process, .free = rate_free };

np_processor_t *np_processor_rate_limit(uint64_t bytes_per_sec)
{
    rate_priv_t *p = malloc(sizeof(*p)); if (!p) return NULL;
    p->bytes_per_sec = bytes_per_sec;
    p->bucket = (double)bytes_per_sec;
    p->last_time_ns = get_time_ns();
    
    np_processor_t *proc = calloc(1, sizeof(*proc));
    if (!proc) { free(p); return NULL; }
    proc->ops  = &rate_ops;
    proc->priv = p;
    return proc;
}
