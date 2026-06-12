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
