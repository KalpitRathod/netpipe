/*
 * np_registry.c — plugin registry implementation
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "np_registry.h"
#include "../log/np_log.h"

/* ------------------------------------------------------------------ */
/*  Registry state                                                      */
/* ------------------------------------------------------------------ */

/* Bug 14 fix: use PTHREAD_MUTEX_INITIALIZER for static initialization,
 * eliminating the check-then-act race in reg_ensure_lock().  The old
 * code had a classic TOCTOU race: two threads could both see
 * lock_init==false and both call pthread_mutex_init on the same mutex,
 * which is undefined behavior per POSIX.  Static initialization is
 * race-free because it's done by the loader before any user code runs. */
static struct {
    np_source_desc_t *sources;
    np_sink_desc_t   *sinks;
    np_filter_desc_t *filters;
    pthread_mutex_t   lock;
} g_reg = {
    .sources = NULL,
    .sinks   = NULL,
    .filters = NULL,
    .lock    = PTHREAD_MUTEX_INITIALIZER,
};

static void reg_ensure_lock(void)
{
    /* No-op — mutex is statically initialized.  Kept for ABI compat. */
}

/* ------------------------------------------------------------------ */
/*  Registration                                                        */
/* ------------------------------------------------------------------ */

void np_registry_add_source(np_source_desc_t *desc)
{
    reg_ensure_lock();
    pthread_mutex_lock(&g_reg.lock);
    desc->next    = g_reg.sources;
    g_reg.sources = desc;
    pthread_mutex_unlock(&g_reg.lock);
    NP_LOG_TRACE("registered source: %s", desc->name);
}

void np_registry_add_sink(np_sink_desc_t *desc)
{
    reg_ensure_lock();
    pthread_mutex_lock(&g_reg.lock);
    desc->next  = g_reg.sinks;
    g_reg.sinks = desc;
    pthread_mutex_unlock(&g_reg.lock);
    NP_LOG_TRACE("registered sink: %s", desc->name);
}

void np_registry_add_filter(np_filter_desc_t *desc)
{
    reg_ensure_lock();
    pthread_mutex_lock(&g_reg.lock);
    desc->next    = g_reg.filters;
    g_reg.filters = desc;
    pthread_mutex_unlock(&g_reg.lock);
    NP_LOG_TRACE("registered filter: %s", desc->name);
}

/* ------------------------------------------------------------------ */
/*  Lookup                                                              */
/* ------------------------------------------------------------------ */

const np_source_desc_t *np_registry_find_source(const char *name)
{
    /* Bug 4 fix: hold the lock during traversal so a concurrent
     * np_registry_add_source() can't modify the list out from under
     * us (data race on the ->next pointers). */
    pthread_mutex_lock(&g_reg.lock);
    for (np_source_desc_t *d = g_reg.sources; d; d = d->next)
        if (strcmp(d->name, name) == 0) {
            pthread_mutex_unlock(&g_reg.lock);
            return d;
        }
    pthread_mutex_unlock(&g_reg.lock);
    return NULL;
}

const np_sink_desc_t *np_registry_find_sink(const char *name)
{
    /* Bug 4 fix: lock during traversal. */
    pthread_mutex_lock(&g_reg.lock);
    for (np_sink_desc_t *d = g_reg.sinks; d; d = d->next)
        if (strcmp(d->name, name) == 0) {
            pthread_mutex_unlock(&g_reg.lock);
            return d;
        }
    pthread_mutex_unlock(&g_reg.lock);
    return NULL;
}

const np_filter_desc_t *np_registry_find_filter(const char *name)
{
    /* Bug 4 fix: lock during traversal. */
    pthread_mutex_lock(&g_reg.lock);
    for (np_filter_desc_t *d = g_reg.filters; d; d = d->next)
        if (strcmp(d->name, name) == 0) {
            pthread_mutex_unlock(&g_reg.lock);
            return d;
        }
    pthread_mutex_unlock(&g_reg.lock);
    return NULL;
}

const np_sink_desc_t *np_registry_find_sink_by_ext(const char *ext)
{
    /* Bug 4 fix: lock during traversal. */
    pthread_mutex_lock(&g_reg.lock);
    /* ext should be without the leading dot */
    for (np_sink_desc_t *d = g_reg.sinks; d; d = d->next) {
        if (!d->extensions) continue;
        /* tokenise extensions field (comma-separated) */
        char buf[128];
        strncpy(buf, d->extensions, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *saveptr = NULL;
        char *tok = strtok_r(buf, ",", &saveptr);
        while (tok) {
            if (strcasecmp(tok, ext) == 0) {
                pthread_mutex_unlock(&g_reg.lock);
                return d;
            }
            tok = strtok_r(NULL, ",", &saveptr);
        }
    }
    pthread_mutex_unlock(&g_reg.lock);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Listing                                                             */
/* ------------------------------------------------------------------ */

void np_registry_list_sources(void)
{
    printf("\033[1mRegistered sources:\033[0m\n");
    for (np_source_desc_t *d = g_reg.sources; d; d = d->next)
        printf("  \033[36m%-20s\033[0m  %s\n", d->name,
               d->long_name ? d->long_name : "");
}

void np_registry_list_sinks(void)
{
    printf("\033[1mRegistered sinks:\033[0m\n");
    for (np_sink_desc_t *d = g_reg.sinks; d; d = d->next)
        printf("  \033[36m%-20s\033[0m  %s  [.%s]\n", d->name,
               d->long_name  ? d->long_name  : "",
               d->extensions ? d->extensions : "—");
}

void np_registry_list_filters(void)
{
    printf("\033[1mRegistered filters:\033[0m\n");
    for (np_filter_desc_t *d = g_reg.filters; d; d = d->next)
        printf("  \033[36m%-20s\033[0m  %s\n", d->name,
               d->long_name ? d->long_name : "");
}
