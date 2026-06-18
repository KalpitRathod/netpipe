/*
 * np_source_pcap.c — libpcap live + file sources
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pcap/pcap.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"
#include "../pipeline/np_pipeline.h"

/* ------------------------------------------------------------------ */
/*  Private backend                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    pcap_t        *handle;
    bool           is_live;
    char           errbuf[PCAP_ERRBUF_SIZE];
} pcap_priv_t;

/* ------------------------------------------------------------------ */
/*  Link-type mapping                                                   */
/* ------------------------------------------------------------------ */

static np_linktype_t pcap_lt_to_np(int dlt)
{
    switch (dlt) {
    case DLT_EN10MB: return NP_LINK_ETHERNET;
    case DLT_NULL:   return NP_LINK_LOOPBACK;
    case DLT_RAW:    return NP_LINK_RAW;
    case 113:        return NP_LINK_LINUX_SLL; /* DLT_LINUX_SLL is 113 */
    default:         return NP_LINK_UNKNOWN;
    }
}

/* ------------------------------------------------------------------ */
/*  Source ops — live                                                   */
/* ------------------------------------------------------------------ */

static np_err_t live_open(np_source_t *src)
{
    pcap_priv_t *p = src->priv;
    /* handle was already opened by np_source_live() */
    src->linktype = pcap_lt_to_np(pcap_datalink(p->handle));
    return NP_OK;
}

static np_err_t common_next(np_source_t *src, np_packet_t **out)
{
    pcap_priv_t *p = src->priv;
    struct pcap_pkthdr *hdr;
    const u_char       *data;

    int rc = pcap_next_ex(p->handle, &hdr, &data);
    /* Bug H8 fix: distinguish end-of-stream from real I/O errors.
     *
     * libpcap return codes for pcap_next_ex:
     *   1                  — success (packet read)
     *   0                  — timeout on live capture (no packet in time)
     *   PCAP_ERROR_BREAK   — pcap_breakloop was called (treat as EOF)
     *   PCAP_ERROR (-1)    — generic error (read error, interface went
     *                        down, savefile truncated, etc.)
     *   -2                 — end of savefile (EOF on offline pcap)
     *
     * The OLD code lumped PCAP_ERROR in with PCAP_ERROR_BREAK/-2 as
     * NP_ERR_EOF, which caused the pipeline to silently stop on
     * transient errors (e.g. a temporary network hiccup on a live
     * capture) instead of reporting them.  Now only PCAP_ERROR_BREAK
     * and -2 (which IS PCAP_ERROR_BREAK in libpcap) map to EOF; a real
     * PCAP_ERROR maps to NP_ERR_IO and is logged. */
    if (rc == PCAP_ERROR_BREAK || rc == -2) {
        return NP_ERR_EOF;
    }
    if (rc == PCAP_ERROR) {
        NP_LOG_ERROR("pcap source: read error: %s", pcap_geterr(p->handle));
        return NP_ERR_IO;
    }
    if (rc == 0) return NP_ERR_TIMEOUT; /* timeout, caller will retry */

    /* Bug SP2 fix: validate that np_packet_alloc actually returned a
     * packet with a non-NULL raw pointer before memcpy.  A partial
     * allocation (malloc succeeds for the header but fails for raw)
     * could leave raw == NULL with caplen > 0. */
    np_packet_t *pkt = np_packet_alloc(hdr->caplen);
    if (!pkt) return NP_ERR_NOMEM;
    if (hdr->caplen > 0 && !pkt->raw) {
        np_packet_free(pkt);
        return NP_ERR_NOMEM;
    }

    if (hdr->caplen > 0) {
        memcpy(pkt->raw, data, hdr->caplen);
    }
    pkt->caplen  = hdr->caplen;
    pkt->wirelen = hdr->len;
    pkt->ts.tv_sec  = hdr->ts.tv_sec;
    pkt->ts.tv_nsec = (long)hdr->ts.tv_usec * 1000;

    *out = pkt;
    return NP_OK;
}

static void pcap_src_close(np_source_t *src)
{
    pcap_priv_t *p = src->priv;
    if (p->handle) { pcap_close(p->handle); p->handle = NULL; }
}

static void pcap_src_stop(np_source_t *src)
{
    pcap_priv_t *p = src->priv;
    if (p && p->handle) {
        pcap_breakloop(p->handle);
    }
}

static void pcap_src_free(np_source_t *src)
{
    pcap_src_close(src);
    free(src->priv);
    free(src);
}

static const struct np_source_ops live_ops = {
    .open  = live_open,
    .next  = common_next,
    .stop  = pcap_src_stop,
    .close = pcap_src_close,
    .free  = pcap_src_free,
};

static const struct np_source_ops file_ops = {
    .open  = live_open,   /* same — handle already open */
    .next  = common_next,
    .stop  = pcap_src_stop,
    .close = pcap_src_close,
    .free  = pcap_src_free,
};

/* ------------------------------------------------------------------ */
/*  Public constructors                                                 */
/* ------------------------------------------------------------------ */

np_source_t *np_source_live(const char *device, int snaplen,
                             int promisc, int timeout_ms)
{
    pcap_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    p->handle = pcap_open_live(device, snaplen, promisc,
                                timeout_ms, p->errbuf);
    if (!p->handle) {
        NP_LOG_ERROR("pcap_open_live(%s): %s", device, p->errbuf);
        free(p);
        return NULL;
    }
    p->is_live = true;

    /* Bug 4 fix: the old comment said "set non-blocking" but
     * pcap_setnonblock(handle, 0, ...) actually sets BLOCKING mode
     * (the second argument is the nonblock flag: 1=non-blocking,
     * 0=blocking).  Blocking mode with the read timeout passed to
     * pcap_open_live is the CORRECT behavior here — the pipeline
     * worker checks pl->running between pcap_next_ex calls, and the
     * read timeout (default 1s) bounds the shutdown latency.  Setting
     * non-blocking would cause a busy-spin that burns CPU.  Fix the
     * comment to match the code. */
    /* Blocking mode is the default; no need to call pcap_setnonblock. */

    np_source_t *src = calloc(1, sizeof(*src));
    if (!src) { pcap_close(p->handle); free(p); return NULL; }

    src->ops  = &live_ops;
    src->priv = p;
    snprintf(src->name, sizeof(src->name), "live:%s", device);
    return src;
}

np_source_t *np_source_file(const char *path)
{
    pcap_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    p->handle = pcap_open_offline(path, p->errbuf);
    if (!p->handle) {
        NP_LOG_ERROR("pcap_open_offline(%s): %s", path, p->errbuf);
        free(p);
        return NULL;
    }

    np_source_t *src = calloc(1, sizeof(*src));
    if (!src) { pcap_close(p->handle); free(p); return NULL; }

    src->ops  = &file_ops;
    src->priv = p;
    snprintf(src->name, sizeof(src->name), "file:%s", path);
    return src;
}

void np_source_free(np_source_t *src)
{
    if (src && src->ops && src->ops->free) src->ops->free(src);
}
