/*
 * np_registry.h — plugin self-registration system
 *
 * Inspired by FFmpeg's av_register_all() / codec registration.
 *
 * Every source, filter, processor, and sink module calls a registration
 * macro at program startup (via __attribute__((constructor))) to add
 * itself to a global registry.  The CLI then resolves "-fmt json" or
 * "-proto dns" by name lookup — no hardwired if-else chains required.
 *
 * Usage (in a module .c file):
 *
 *   NP_REGISTER_SINK(json_sink_desc);
 *
 * where json_sink_desc is a np_sink_desc_t with .name="json" and a
 * factory function pointer.
 */

#pragma once
#ifndef NP_REGISTRY_H
#define NP_REGISTRY_H

#include <stddef.h>
#include "netpipe.h"

/* ------------------------------------------------------------------ */
/*  Descriptor types                                                    */
/* ------------------------------------------------------------------ */

typedef struct np_source_desc {
    const char   *name;            /* e.g. "pcap-live", "pcap-file"  */
    const char   *long_name;
    const char   *url_prefix;      /* e.g. "pcap:", "file:"          */
    np_source_t *(*create)(const char *url, int flags);
    struct np_source_desc *next;
} np_source_desc_t;

typedef struct np_sink_desc {
    const char  *name;             /* e.g. "pcap", "json", "hex"     */
    const char  *long_name;
    const char  *extensions;       /* comma-separated: "pcap,cap"    */
    np_sink_t  *(*create)(const char *path);
    struct np_sink_desc *next;
} np_sink_desc_t;

typedef struct np_filter_desc {
    const char   *name;            /* e.g. "port", "host", "bpf"     */
    const char   *long_name;
    np_filter_t *(*create)(const char *args);
    struct np_filter_desc *next;
} np_filter_desc_t;

/* ------------------------------------------------------------------ */
/*  Global registry                                                     */
/* ------------------------------------------------------------------ */

/* Register entries (called automatically via NP_REGISTER_* macros)   */
void np_registry_add_source(np_source_desc_t *desc);
void np_registry_add_sink  (np_sink_desc_t   *desc);
void np_registry_add_filter(np_filter_desc_t *desc);

/* Lookup by name                                                       */
const np_source_desc_t *np_registry_find_source(const char *name);
const np_sink_desc_t   *np_registry_find_sink  (const char *name);
const np_filter_desc_t *np_registry_find_filter(const char *name);

/* Lookup sink by file extension                                        */
const np_sink_desc_t   *np_registry_find_sink_by_ext(const char *ext);

/* Dump registry contents (for -list_sources / -list_sinks)            */
void np_registry_list_sources(void);
void np_registry_list_sinks  (void);
void np_registry_list_filters(void);

/* ------------------------------------------------------------------ */
/*  Self-registration macros                                            */
/* ------------------------------------------------------------------ */

/*
 * Place one of these at file scope in any module .c file.
 * The constructor runs before main(), automatically registering the
 * descriptor with the global registry.
 *
 * Example:
 *   static np_sink_desc_t _json_desc = {
 *       .name       = "json",
 *       .long_name  = "Newline-delimited JSON",
 *       .extensions = "json,ndjson",
 *       .create     = json_sink_create,
 *   };
 *   NP_REGISTER_SINK(_json_desc);
 */

#define NP_REGISTER_SOURCE(desc) \
    static void __attribute__((constructor)) _np_reg_src_##desc(void) { \
        np_registry_add_source(&(desc)); \
    }

#define NP_REGISTER_SINK(desc) \
    static void __attribute__((constructor)) _np_reg_sink_##desc(void) { \
        np_registry_add_sink(&(desc)); \
    }

#define NP_REGISTER_FILTER(desc) \
    static void __attribute__((constructor)) _np_reg_flt_##desc(void) { \
        np_registry_add_filter(&(desc)); \
    }

#endif /* NP_REGISTRY_H */
