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

static struct {
    np_source_desc_t *sources;
    np_sink_desc_t   *sinks;
    np_filter_desc_t *filters;
    pthread_mutex_t   lock;
    bool              lock_init;
} g_reg;

static void reg_ensure_lock(void)
{
    /* best-effort: constructor ordering means this might be called
       before other constructors have run — the mutex itself is safe  */
    if (!g_reg.lock_init) {
        pthread_mutex_init(&g_reg.lock, NULL);
        g_reg.lock_init = true;
    }
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
    for (np_source_desc_t *d = g_reg.sources; d; d = d->next)
        if (strcmp(d->name, name) == 0) return d;
    return NULL;
}

const np_sink_desc_t *np_registry_find_sink(const char *name)
{
    for (np_sink_desc_t *d = g_reg.sinks; d; d = d->next)
        if (strcmp(d->name, name) == 0) return d;
    return NULL;
}

const np_filter_desc_t *np_registry_find_filter(const char *name)
{
    for (np_filter_desc_t *d = g_reg.filters; d; d = d->next)
        if (strcmp(d->name, name) == 0) return d;
    return NULL;
}

const np_sink_desc_t *np_registry_find_sink_by_ext(const char *ext)
{
    /* ext should be without the leading dot */
    for (np_sink_desc_t *d = g_reg.sinks; d; d = d->next) {
        if (!d->extensions) continue;
        /* tokenise extensions field (comma-separated) */
        char buf[128];
        strncpy(buf, d->extensions, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *tok = strtok(buf, ",");
        while (tok) {
            if (strcasecmp(tok, ext) == 0) return d;
            tok = strtok(NULL, ",");
        }
    }
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
