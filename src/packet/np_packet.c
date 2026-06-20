/*
 * np_packet.c — packet lifecycle and helpers
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "np_packet.h"
#include "../bufpool/np_bufpool.h"   /* FIX: wire up the bufpool module */

/* ------------------------------------------------------------------ */
/*  Alloc / free / clone                                                */
/* ------------------------------------------------------------------ */

/* FIX (issue: np_packet_t is 8 KB+ each and the pipeline mallocs+frees
 * per packet with no free-list reuse — a major throughput bottleneck at
 * high packet rates, presumably why np_bufpool was built but never
 * wired up).
 *
 * TWO-LAYER FIX:
 *
 *  1. (Headers) Per-thread free-list of np_packet_t structs.  The
 *     pipeline's main processing loop is single-threaded (only source
 *     capture is parallel — see np_pipeline.c), so a thread-local
 *     free-list means the hot path is lock-free.
 *
 *  2. (Raw buffers) Process-global np_bufpool_t with reference counting.
 *     This is the existing np_bufpool module, now actually wired up.
 *     Each np_packet_t's `raw` pointer aliases an np_buf_t's `data`
 *     field; the np_buf_t* itself is stashed in pkt->reserved[3]
 *     (public ABI: "reserved for library use").  np_packet_free calls
 *     np_buf_unref, which returns the buffer to the pool when the
 *     refcount hits zero.
 *
 *     The big win is np_packet_clone: instead of memcpy'ing the raw
 *     buffer (which can be 64 KB per packet), it just calls np_buf_ref
 *     — O(1) refcount increment, zero copy.  This matters for pipelines
 *     with multiple sinks (each sink gets its own reference) and for
 *     any processor that wants to retain a packet beyond the current
 *     iteration. */

#define NP_PKT_FREE_LIST_MAX  64   /* max idle packet headers per thread */

/* ------------------------------------------------------------------ */
/*  Per-thread packet-header free-list                                 */
/* ------------------------------------------------------------------ */

typedef struct np_pkt_freelist {
    np_packet_t *pkts[NP_PKT_FREE_LIST_MAX];
    int          npkts;
} np_pkt_freelist_t;

static pthread_key_t g_pkt_fl_key;
static pthread_once_t g_pkt_fl_once = PTHREAD_ONCE_INIT;

static void np_pkt_fl_destructor(void *p)
{
    if (!p) return;
    np_pkt_freelist_t *fl = p;
    for (int i = 0; i < fl->npkts; i++) free(fl->pkts[i]);
    free(fl);
}

static void np_pkt_fl_init(void)
{
    pthread_key_create(&g_pkt_fl_key, np_pkt_fl_destructor);
}

static np_pkt_freelist_t *np_pkt_fl_get(void)
{
    pthread_once(&g_pkt_fl_once, np_pkt_fl_init);
    np_pkt_freelist_t *fl = pthread_getspecific(g_pkt_fl_key);
    if (!fl) {
        fl = calloc(1, sizeof(*fl));
        if (!fl) return NULL;
        pthread_setspecific(g_pkt_fl_key, fl);
    }
    return fl;
}

/* ------------------------------------------------------------------ */
/*  Process-global np_bufpool for raw packet buffers                   */
/* ------------------------------------------------------------------ */

/* Pool config: 65536-byte buffers (typical max packet size), 128 pre-
 * allocated slots (~8 MB).  When the pool is empty, np_buf_alloc falls
 * back to heap allocation transparently, so this is just a hot-path
 * optimization, not a hard cap. */
#define NP_PKT_POOL_CAPACITY  65536
#define NP_PKT_POOL_SIZE      128

static np_bufpool_t *g_pkt_bufpool = NULL;
static pthread_once_t g_pkt_pool_once = PTHREAD_ONCE_INIT;

static void np_pkt_pool_init(void)
{
    g_pkt_bufpool = np_bufpool_create(NP_PKT_POOL_CAPACITY, NP_PKT_POOL_SIZE);
    if (g_pkt_bufpool) {
        NP_LOG_INFO("packet bufpool created (capacity=%d bytes, slots=%d)",
                    NP_PKT_POOL_CAPACITY, NP_PKT_POOL_SIZE);
    } else {
        NP_LOG_WARN("packet bufpool creation failed — falling back to heap alloc");
    }
}

static np_bufpool_t *np_pkt_pool_get(void)
{
    pthread_once(&g_pkt_pool_once, np_pkt_pool_init);
    return g_pkt_bufpool;
}

/* Public: expose pool stats so the CLI / tests can verify the pool is
 * actually being used.  Defined here rather than in netpipe.h to keep
 * the public ABI stable; tests reach in via this symbol. */
void np_packet_pool_stats(FILE *fp)
{
    np_bufpool_t *p = np_pkt_pool_get();
    if (p) np_bufpool_stats(p, fp);
    else fprintf(fp, "packet bufpool: not initialized\n");
}

/* Public: destroy the process-global packet bufpool.  Called from
 * np_cleanup().  Safe to call multiple times — second call is a no-op.
 *
 * Also drains the calling thread's packet-header free-list so valgrind
 * doesn't report the idle headers as leaks.  The free-lists of OTHER
 * threads are not drained here — they're cleaned up by the pthread_key
 * destructor when those threads exit. */
void np_packet_pool_destroy(void)
{
    /* Drain the calling thread's packet-header free-list first, so the
     * pool's outstanding-buffer count is accurate when we destroy it. */
    pthread_once(&g_pkt_fl_once, np_pkt_fl_init);
    np_pkt_freelist_t *fl = pthread_getspecific(g_pkt_fl_key);
    if (fl) {
        for (int i = 0; i < fl->npkts; i++) {
            free(fl->pkts[i]);
        }
        fl->npkts = 0;
        /* Don't free fl itself — the pthread_key destructor will do that
         * when the thread exits.  Just empty it. */
    }

    if (g_pkt_bufpool) {
        np_bufpool_destroy(g_pkt_bufpool);
        g_pkt_bufpool = NULL;
    }
}

np_packet_t *np_packet_alloc(size_t caplen)
{
    /* Bug PKT-03 fix: reject caplen > UINT32_MAX up front so the
     * cast to uint32_t below doesn't silently truncate.  pkt->raw
     * would be allocated at full size but pkt->caplen would record
     * only the low 32 bits, causing downstream bounds checks to use
     * the wrong value. */
    if (caplen > UINT32_MAX) {
        NP_LOG_ERROR("np_packet_alloc: caplen %zu > UINT32_MAX, rejecting", caplen);
        return NULL;
    }

    np_packet_t *pkt = NULL;
    np_pkt_freelist_t *fl = np_pkt_fl_get();

    /* Try to reuse a packet header from the thread-local free-list. */
    if (fl && fl->npkts > 0) {
        pkt = fl->pkts[--fl->npkts];
        memset(pkt, 0, sizeof(*pkt));
    } else {
        pkt = calloc(1, sizeof(*pkt));
        if (!pkt) return NULL;
    }

    /* FIX (issue: np_bufpool was never wired up): allocate the raw
     * buffer from the process-global np_bufpool.  The returned np_buf_t
     * has refcount=1 and its ->data field points at the actual storage.
     * We stash the np_buf_t* in pkt->reserved[3] so np_packet_free can
     * unref it, and point pkt->raw at buf->data for backward compat
     * with all the existing code that reads pkt->raw directly. */
    np_bufpool_t *pool = np_pkt_pool_get();
    np_buf_t *buf = np_buf_alloc(pool, caplen > 0 ? caplen : 1);
    if (!buf) {
        /* np_buf_alloc failed (OOM).  Return the header to the free-list
         * or free it, then bail. */
        if (fl && fl->npkts < NP_PKT_FREE_LIST_MAX) fl->pkts[fl->npkts++] = pkt;
        else free(pkt);
        return NULL;
    }

    pkt->raw        = buf->data;
    pkt->caplen     = (uint32_t)caplen;
    pkt->reserved[3] = (void *)buf;   /* remember the np_buf_t* for free/clone */
    return pkt;
}

void np_packet_free(np_packet_t *pkt)
{
    if (!pkt) return;

    /* FIX (issue: np_bufpool was never wired up): unref the np_buf_t
     * that backs pkt->raw.  When refcount hits 0 the buffer goes back
     * to the pool.  We don't memset the buffer here because the pool
     * may immediately hand it back out to another caller — security-
     * sensitive callers should memset pkt->raw themselves before free
     * if they put plaintext secrets in it (e.g. TLS decrypt). */
    np_buf_t *buf = (np_buf_t *)pkt->reserved[3];
    if (buf) {
        np_buf_unref(&buf);
        pkt->reserved[3] = NULL;
    }
    pkt->raw = NULL;

    /* Free stream_data — never pooled (size varies too much). */
    if (pkt->stream_data) {
        free(pkt->stream_data);
        pkt->stream_data = NULL;
        pkt->stream_len  = 0;
    }

    /* Recycle the packet header into the thread-local free-list. */
    np_pkt_freelist_t *fl = np_pkt_fl_get();
    if (fl && fl->npkts < NP_PKT_FREE_LIST_MAX) {
        /* Clean any pointers the previous owner set, to avoid UAF if
         * the next alloc skips some field initialisation. */
        pkt->caplen     = 0;
        pkt->wirelen    = 0;
        pkt->nlayers    = 0;
        pkt->eth = pkt->net = pkt->transport = pkt->app = NULL;
        pkt->stream_data = NULL;
        pkt->stream_len  = 0;
        pkt->user_data   = NULL;
        pkt->scratch_used = 0;
        pkt->reserved[0] = NULL;
        pkt->reserved[1] = NULL;
        pkt->reserved[2] = NULL;
        pkt->reserved[3] = NULL;
        fl->pkts[fl->npkts++] = pkt;
    } else {
        free(pkt);
    }
}

np_packet_t *np_packet_clone(const np_packet_t *src)
{
    if (!src) return NULL;

    /* FIX (issue: np_bufpool was never wired up): zero-copy clone.
     *
     * The old np_packet_clone called np_packet_alloc(src->caplen) which
     * allocated a FRESH np_buf_t and then memcpy'd the source's raw
     * bytes into it — O(caplen) work, typically 64 KB per packet.
     *
     * The new path:
     *   1. Allocate just a packet HEADER (no raw buffer) by calling
     *      np_packet_alloc(0) and then manually attaching a refcount-
     *      shared np_buf_t via np_buf_ref.
     *   2. dst->raw aliases src->raw (same underlying buffer).
     *   3. Layer pointers are computed as offsets into the SHARED
     *      buffer, so they remain valid as long as both src and dst
     *      hold a reference.
     *   4. np_packet_free on either src or dst just decrements the
     *      refcount; the buffer returns to the pool only when the LAST
     *      reference is dropped.
     *
     * Caveat: if the caller mutates pkt->raw in place (e.g. TLS decrypt
     * redirecting the app layer to a heap plaintext buffer), the clone
     * is unaffected because the redirect changes pkt->layers[i].data,
     * not pkt->raw itself.  The original (encrypted) bytes in the
     * shared buffer remain visible to both src and dst until one of
     * them is freed.  This matches the semantic guarantee callers
     * already relied on under the memcpy implementation (a clone is a
     * snapshot of the packet at clone time), with the bonus that the
     * raw bytes are now shared until either side mutates them
     * (copy-on-write would be a future enhancement, not needed today
     * since no in-place mutation of pkt->raw happens in the codebase). */

    /* Step 1: allocate a header-only packet directly from the thread-
     * local free-list (no np_buf_t placeholder to throw away).  This
     * avoids consuming a 64 KB slab slot just to immediately unref it. */
    np_packet_t *dst = NULL;
    np_pkt_freelist_t *fl = np_pkt_fl_get();
    if (fl && fl->npkts > 0) {
        dst = fl->pkts[--fl->npkts];
        memset(dst, 0, sizeof(*dst));
    } else {
        dst = calloc(1, sizeof(*dst));
        if (!dst) return NULL;
    }

    /* Step 2: attach a refcount-shared np_buf_t from src.  dst->raw
     * aliases src->raw — zero-copy. */
    np_buf_t *src_buf = (np_buf_t *)src->reserved[3];
    if (src_buf) {
        np_buf_t *shared = np_buf_ref(src_buf);
        dst->reserved[3] = (void *)shared;
        dst->raw = shared->data;
    } else if (src->caplen > 0 && src->raw) {
        /* Source had no np_buf_t (defensive — shouldn't happen with the
         * new alloc path, but covers packets constructed by external
         * code that bypasses np_packet_alloc).  Fall back to memcpy. */
        np_bufpool_t *pool = np_pkt_pool_get();
        np_buf_t *dst_buf = np_buf_alloc(pool, src->caplen);
        if (!dst_buf) {
            if (fl && fl->npkts < NP_PKT_FREE_LIST_MAX) fl->pkts[fl->npkts++] = dst;
            else free(dst);
            return NULL;
        }
        dst->reserved[3] = (void *)dst_buf;
        dst->raw = dst_buf->data;
        memcpy(dst->raw, src->raw, src->caplen);
    }

    dst->ts      = src->ts;
    dst->wirelen = src->wirelen;
    dst->caplen  = src->caplen;
    dst->seq     = src->seq;
    dst->flow_id = src->flow_id;

    /* Layers point into raw — re-map offsets.  Because dst->raw aliases
     * src->raw (zero-copy), the offset computation is the same.
     *
     * Bug 2 fix: after TLS decryption, the TLS processor redirects
     * pkt->layers[i].data to a heap-allocated plaintext buffer (NOT
     * into pkt->raw).  We validate that data is within [raw, raw+caplen)
     * before rebasing; if it's not (e.g. redirected by TLS decrypt), we
     * set the clone's layer data to NULL to avoid a dangling pointer.
     *
     * Bug PKT-01 fix: also zero out the layer's len when we set data
     * to NULL, so downstream code that does `if (len > 0) use(data)`
     * doesn't dereference NULL. */
    dst->nlayers = src->nlayers;
    for (int i = 0; i < src->nlayers; i++) {
        dst->layers[i].proto   = src->layers[i].proto;
        const uint8_t *sd = src->layers[i].data;
        /* Bug PKT-02 fix: guard against NULL sd. */
        if (sd != NULL && sd >= src->raw && sd < src->raw + src->caplen) {
            /* Normal case: layer data points into raw buffer. */
            ptrdiff_t off = sd - src->raw;
            dst->layers[i].data = dst->raw + off;
            dst->layers[i].len  = src->layers[i].len;
        } else {
            /* Layer data was redirected (e.g. TLS plaintext) or is NULL.
             * Set both data AND len to 0 so callers don't deref NULL. */
            dst->layers[i].data = NULL;
            dst->layers[i].len  = 0;
        }
        dst->layers[i].decoded = NULL; /* scratch not cloned */
    }

    /* Restore convenience pointers */
    dst->eth       = src->eth       ? dst->layers + (src->eth       - src->layers) : NULL;
    dst->net       = src->net       ? dst->layers + (src->net       - src->layers) : NULL;
    dst->transport = src->transport ? dst->layers + (src->transport - src->layers) : NULL;
    dst->app       = src->app       ? dst->layers + (src->app       - src->layers) : NULL;

    /* Bug 2 fix: copy stream_data (reassembled TCP stream / TLS plaintext).
     * Not shared — each clone gets its own copy because stream_data is
     * typically mutated by downstream processors (e.g. payload_transform
     * regex replace). */
    dst->stream_len = src->stream_len;
    if (src->stream_data && src->stream_len > 0) {
        dst->stream_data = malloc(src->stream_len);
        if (dst->stream_data) {
            memcpy(dst->stream_data, src->stream_data, src->stream_len);
        } else {
            dst->stream_len = 0;
        }
    }

    /* Copy user metadata.  reserved[0..2] are internal-use only
     * (raw_cap, aliasing flag, original offset) and MUST NOT be copied
     * — see the original Bug 2 / TLS-decrypt aliasing comments.
     * reserved[3] is the np_buf_t* which we've already set above via
     * np_buf_ref.  We deliberately do NOT overwrite it here. */
    dst->user_data = src->user_data;

    return dst;
}

/* ------------------------------------------------------------------ */
/*  Layer stack                                                         */
/* ------------------------------------------------------------------ */

np_layer_t *np_packet_push_layer(np_packet_t *pkt,
                                  np_proto_t proto,
                                  const uint8_t *data,
                                  size_t len)
{
    if (pkt->nlayers >= NP_MAX_LAYERS) {
        NP_LOG_WARN("layer stack full (max %d)", NP_MAX_LAYERS);
        return NULL;
    }
    np_layer_t *l   = &pkt->layers[pkt->nlayers++];
    l->proto        = proto;
    l->data         = data;
    l->len          = len;
    l->decoded      = NULL;
    return l;
}

void *np_packet_scratch_alloc(np_packet_t *pkt, size_t size)
{
    /* Bug PKT-08 fix: reject zero-size allocations.  Two consecutive
     * scratch_alloc(0) calls would return the same pointer (the
     * current scratch_used offset), which is correct C but confusing
     * for callers that compare pointers.  Return NULL instead. */
    if (size == 0) return NULL;
    size_t remaining = sizeof(pkt->scratch) - pkt->scratch_used;
    if (size > remaining) {
        /* Log when the scratch allocator is exhausted so the user knows
         * decoded structures (HTTP headers, DNS answers) are being
         * dropped silently.  Without this, a packet with very large
         * headers would flow downstream with a missing decoded struct
         * and no indication why. */
        NP_LOG_WARN("scratch allocator exhausted: requested %zu, remaining %zu (packet seq=%lu)",
                    size, remaining, (unsigned long)pkt->seq);
        return NULL;
    }
    void *ptr = pkt->scratch + pkt->scratch_used;
    pkt->scratch_used += size;
    /* align to 8 bytes */
    pkt->scratch_used = (pkt->scratch_used + 7) & ~(size_t)7;
    return ptr;
}

/* ------------------------------------------------------------------ */
/*  Utilities                                                           */
/* ------------------------------------------------------------------ */

void np_packet_ts_str(const np_packet_t *pkt, char *buf, size_t bufsz)
{
    struct tm tm;
    /* Bug PKT-04 fix: check localtime_r return — on failure (e.g.
     * negative tv_sec, or tv_sec out of time_t range) it returns NULL
     * and `tm` is left uninitialized.  The old code fed uninitialized
     * tm fields to snprintf, producing garbage timestamp strings. */
    if (!localtime_r(&pkt->ts.tv_sec, &tm)) {
        snprintf(buf, bufsz, "??:??:??.??????");
        return;
    }
    snprintf(buf, bufsz, "%02d:%02d:%02d.%06ld",
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             (long)(pkt->ts.tv_nsec / 1000));
}

static const char *proto_name(np_proto_t p)
{
    switch (p) {
    case NP_PROTO_ETH:  return "Ethernet";
    case NP_PROTO_ARP:  return "ARP";
    case NP_PROTO_IP4:  return "IPv4";
    case NP_PROTO_IP6:  return "IPv6";
    case NP_PROTO_ICMP: return "ICMP";
    case NP_PROTO_TCP:  return "TCP";
    case NP_PROTO_UDP:  return "UDP";
    case NP_PROTO_DNS:  return "DNS";
    case NP_PROTO_HTTP: return "HTTP";
    case NP_PROTO_TLS:  return "TLS";
    default:            return "Unknown";
    }
}

void np_packet_print(const np_packet_t *pkt, FILE *fp)
{
    char ts[32];
    np_packet_ts_str(pkt, ts, sizeof(ts));

    fprintf(fp, "┌── Packet #%lu  ts=%s  cap=%u  wire=%u\n",
            (unsigned long)pkt->seq, ts, pkt->caplen, pkt->wirelen);

    for (int i = 0; i < pkt->nlayers; i++) {
        const np_layer_t *l = &pkt->layers[i];
        fprintf(fp, "│  Layer[%d] %-10s  len=%-6zu\n",
                i, proto_name(l->proto), l->len);
    }

    /* hex dump of first 64 bytes */
    fprintf(fp, "│  Raw (first 64 bytes):\n│  ");
    size_t dump = pkt->caplen < 64 ? pkt->caplen : 64;
    /* Bug PKT-05 fix: guard against NULL pkt->raw — a hand-constructed
     * or partially-freed packet could have caplen > 0 but raw == NULL. */
    if (pkt->raw) {
        for (size_t i = 0; i < dump; i++) {
            fprintf(fp, "%02x ", pkt->raw[i]);
            if ((i + 1) % 16 == 0) fprintf(fp, "\n│  ");
        }
    } else {
        fprintf(fp, "<null raw buffer>");
    }
    fprintf(fp, "\n");

    if (pkt->stream_data && pkt->stream_len > 0) {
        fprintf(fp, "│  Stream/Transformed Payload (len=%zu):\n│  ", pkt->stream_len);
        bool is_printable = true;
        for (size_t i = 0; i < pkt->stream_len; i++) {
            uint8_t c = pkt->stream_data[i];
            if ((c < 32 || c > 126) && c != '\t' && c != '\n' && c != '\r') {
                is_printable = false;
                break;
            }
        }
        if (is_printable) {
            size_t p_len = pkt->stream_len < 1000 ? pkt->stream_len : 1000;
            fwrite(pkt->stream_data, 1, p_len, fp);
            if (pkt->stream_len > 1000) fprintf(fp, "... [truncated]");
            fprintf(fp, "\n");
        } else {
            size_t p_len = pkt->stream_len < 256 ? pkt->stream_len : 256;
            for (size_t i = 0; i < p_len; i++) {
                fprintf(fp, "%02x ", pkt->stream_data[i]);
                if ((i + 1) % 16 == 0) fprintf(fp, "\n│  ");
            }
            if (pkt->stream_len > 256) fprintf(fp, "... [truncated]");
            fprintf(fp, "\n");
        }
    }

    fprintf(fp, "└──\n");
}

/* djb2-based 5-tuple hash — filled in by the protocol decoder */
uint32_t np_packet_flow_hash(const np_packet_t *pkt)
{
    return pkt->flow_id;
}

/* FIX (issue: np_processor_tls_decrypt mutates pkt->layers[i].data in
 * place to point at decrypted plaintext): expose the aliasing state
 * via two helpers so downstream code can detect it without poking at
 * pointer arithmetic.  We use reserved[1] as a non-NULL sentinel that
 * np_processor_tls_decrypt sets when it redirects the app layer. */
bool np_packet_app_layer_is_decrypted(const np_packet_t *pkt)
{
    return pkt && pkt->reserved[1] == (void *)1;
}

const uint8_t *np_packet_original_app_layer(const np_packet_t *pkt,
                                             size_t *out_len)
{
    if (!pkt || !pkt->app || !pkt->app->data) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (!np_packet_app_layer_is_decrypted(pkt)) {
        /* No redirection — the app layer still points into pkt->raw. */
        if (out_len) *out_len = pkt->app->len;
        return pkt->app->data;
    }
    /* The original encrypted bytes are at the app layer's original
     * offset within pkt->raw.  We stored that offset in reserved[2]
     * when the TLS processor redirected the pointer. */
    size_t off = (size_t)pkt->reserved[2];
    if (off >= pkt->caplen) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (out_len) *out_len = pkt->caplen - off;
    return pkt->raw + off;
}
