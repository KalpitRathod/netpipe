/*
 * np_processor.c — built-in packet processors / transforms
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <regex.h>

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
    bool     oversized_warned;   /* Bug 10: per-instance, not static */
} rate_priv_t;

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static np_err_t rate_process(np_processor_t *proc, np_packet_t *pkt)
{
    rate_priv_t *p = proc->priv;

    /* Bug 3.1: if a single packet's wirelen exceeds the rate cap, the
     * bucket can never accumulate enough tokens — the while(1) loop
     * would sleep forever.  Detect this upfront and pass the packet
     * through (a policer can't shape a packet larger than its rate).
     *
     * Bug 10 fix: the warning flag was `static`, shared across all
     * rate-limit processor instances.  Now it's per-instance in the
     * private struct, so each rate limiter warns independently. */
    if (pkt->wirelen > p->bytes_per_sec) {
        if (!p->oversized_warned) {
            NP_LOG_WARN("rate_limit: packet wirelen %u exceeds rate cap %lu B/s — passing through",
                        pkt->wirelen, (unsigned long)p->bytes_per_sec);
            p->oversized_warned = true;
        }
        p->bucket = 0.0;
        p->last_time_ns = get_time_ns();
        return NP_OK;
    }

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
            /* Bug 3.2 + 3.3: use nanosleep instead of usleep to avoid
             * useconds_t overflow on large waits (> 4.29 s) and to
             * get higher-resolution sleeps (usleep has ~1ms granularity
             * on non-realtime Linux, causing rate drift under low caps).
             *
             * Bug B22 fix: enforce a minimum sleep of 100µs.  The old
             * code fell back to 1µs when wait_s rounded to 0, which on
             * a non-realtime kernel actually sleeps ~1ms anyway — but
             * the loop iteration overhead (clock_gettime, bucket math)
             * dominated, causing high CPU spin when the rate cap was
             * far above the packet arrival rate.  100µs is a sensible
             * floor: short enough to keep throughput tight, long enough
             * to amortise the syscall + math overhead. */
            double needed = (double)pkt->wirelen - p->bucket;
            double wait_s = needed / (double)p->bytes_per_sec;
            struct timespec ts;
            ts.tv_sec  = (time_t)wait_s;
            ts.tv_nsec = (long)((wait_s - (double)ts.tv_sec) * 1e9);
            if (ts.tv_sec == 0 && ts.tv_nsec < 100000L) {
                ts.tv_nsec = 100000L;  /* min 100µs to avoid busy-spin */
            }
            nanosleep(&ts, NULL);
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
    p->bucket = 0.0; /* Start empty to prevent initial burst */
    p->last_time_ns = get_time_ns();
    
    np_processor_t *proc = calloc(1, sizeof(*proc));
    if (!proc) { free(p); return NULL; }
    proc->ops  = &rate_ops;
    proc->priv = p;
    return proc;
}

/* ------------------------------------------------------------------ */
/*  Payload Transform Processor (regex, base64, hex)                  */
/* ------------------------------------------------------------------ */

typedef enum {
    TRANSFORM_HEX,
    TRANSFORM_BASE64,
    TRANSFORM_REGEX
} transform_mode_t;

typedef struct {
    transform_mode_t mode;
    char            *pattern;
    char            *replacement;
} transform_priv_t;

static void get_packet_payload(const np_packet_t *pkt, const uint8_t **out_data, size_t *out_len)
{
    if (pkt->stream_data && pkt->stream_len > 0) {
        *out_data = pkt->stream_data;
        *out_len  = pkt->stream_len;
        return;
    }
    if (pkt->app && pkt->app->data && pkt->app->len > 0) {
        *out_data = pkt->app->data;
        *out_len  = pkt->app->len;
        return;
    }
    if (pkt->transport && pkt->transport->data && pkt->transport->len > 0) {
        ptrdiff_t offset = (pkt->transport->data + pkt->transport->len) - pkt->raw;
        if (offset >= 0 && (size_t)offset < pkt->caplen) {
            *out_data = pkt->raw + offset;
            *out_len  = pkt->caplen - (size_t)offset;
            return;
        }
    }
    /* Fallback to raw packet data */
    *out_data = pkt->raw;
    *out_len  = pkt->caplen;
}

static void hex_encode(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len)
{
    /* Bug B21 fix: check for size_t overflow before computing in_len * 2.
     * On 32-bit platforms, if in_len > SIZE_MAX/2 the multiplication
     * wraps around to a small value and we'd malloc a tiny buffer then
     * write past its end.  In practice in_len is bounded by pkt->caplen
     * (uint32_t) so this is unreachable on 64-bit, but defensive. */
    if (in_len > (SIZE_MAX - 1) / 2) {
        NP_LOG_ERROR("hex_encode: in_len %zu too large (would overflow)", in_len);
        *out = NULL; *out_len = 0;
        return;
    }
    size_t len = in_len * 2;
    uint8_t *res = malloc(len + 1);
    if (!res) { *out = NULL; *out_len = 0; return; }
    for (size_t i = 0; i < in_len; i++) {
        sprintf((char *)(res + i * 2), "%02x", in[i]);
    }
    res[len] = '\0';
    *out = res;
    *out_len = len;
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len)
{
    /* Bug B21 fix: check for size_t overflow in the base64 length
     * computation.  The formula 4 * ((in_len + 2) / 3) can overflow
     * in two places: (in_len + 2) overflows if in_len > SIZE_MAX - 2,
     * and 4 * ... overflows if the division result > SIZE_MAX / 4.
     * Reject up-front if either bound is breached. */
    if (in_len > SIZE_MAX - 2) {
        NP_LOG_ERROR("base64_encode: in_len %zu too large (would overflow)", in_len);
        *out = NULL; *out_len = 0;
        return;
    }
    size_t triples = (in_len + 2) / 3;
    if (triples > SIZE_MAX / 4) {
        NP_LOG_ERROR("base64_encode: in_len %zu too large (would overflow)", in_len);
        *out = NULL; *out_len = 0;
        return;
    }
    size_t len = 4 * triples;
    uint8_t *res = malloc(len + 1);
    if (!res) { *out = NULL; *out_len = 0; return; }

    size_t i = 0, j = 0;
    for (; i + 2 < in_len; i += 3) {
        uint32_t val = (uint32_t)((in[i] << 16) | (in[i+1] << 8) | in[i+2]);
        res[j++] = (uint8_t)b64_table[(val >> 18) & 0x3F];
        res[j++] = (uint8_t)b64_table[(val >> 12) & 0x3F];
        res[j++] = (uint8_t)b64_table[(val >> 6)  & 0x3F];
        res[j++] = (uint8_t)b64_table[val         & 0x3F];
    }
    if (i < in_len) {
        uint32_t val = (uint32_t)(in[i] << 16);
        if (i + 1 < in_len) val |= (uint32_t)(in[i+1] << 8);

        res[j++] = (uint8_t)b64_table[(val >> 18) & 0x3F];
        res[j++] = (uint8_t)b64_table[(val >> 12) & 0x3F];
        res[j++] = (i + 1 < in_len) ? (uint8_t)b64_table[(val >> 6) & 0x3F] : '=';
        res[j++] = '=';
    }
    res[j] = '\0';
    *out = res;
    *out_len = j;
}

static void regex_replace_payload(const uint8_t *in, size_t in_len,
                                  const char *pattern, const char *replacement,
                                  uint8_t **out, size_t *out_len)
{
    /* Copy to null-terminated string for regexec compatibility */
    char *src = malloc(in_len + 1);
    if (!src) { *out = NULL; *out_len = 0; return; }
    memcpy(src, in, in_len);
    src[in_len] = '\0';

    regex_t re;
    if (regcomp(&re, pattern, REG_EXTENDED) != 0) {
        NP_LOG_ERROR("regex compilation failed for pattern: %s", pattern);
        free(src);
        *out = NULL;
        *out_len = 0;
        return;
    }

    size_t res_cap = in_len + 256;
    char *res = malloc(res_cap);
    if (!res) {
        regfree(&re);
        free(src);
        *out = NULL;
        *out_len = 0;
        return;
    }
    size_t res_len = 0;

    char *cursor = src;
    /* Bug B23 fix: size pmatch from the compiled regex's re_nsub field
     * rather than a fixed array of 10.  POSIX requires nmatch >=
     * re.re_nsub + 1; the old code passed 10 unconditionally, which
     * silently truncated regexes with more than 9 capture groups
     * (regexec would either return REG_NOMATCH or fill only the first
     * 10 slots, losing the others). */
    size_t nmatch = (size_t)re.re_nsub + 1;
    regmatch_t *pmatch = malloc(nmatch * sizeof(*pmatch));
    if (!pmatch) {
        NP_LOG_ERROR("regex_replace: out of memory for %zu match slots", nmatch);
        regfree(&re);
        free(src);
        free(res);
        *out = NULL;
        *out_len = 0;
        return;
    }

    while (regexec(&re, cursor, nmatch, pmatch, 0) == 0) {
        size_t before_len = (size_t)pmatch[0].rm_so;
        if (res_len + before_len >= res_cap) {
            res_cap = res_len + before_len + 256;
            char *new_res = realloc(res, res_cap);
            if (!new_res) goto fail;
            res = new_res;
        }
        memcpy(res + res_len, cursor, before_len);
        res_len += before_len;

        /* Copy replacement and support group backreferences \0 to \9.
         * Bug B23 note: backreferences beyond \9 are not supported by
         * this single-digit syntax — that would require multi-digit
         * parsing (e.g. ${10}).  But at least the matching itself now
         * succeeds for regexes with > 9 capture groups (the pmatch
         * array is sized to re.re_nsub + 1).  Backreferences to groups
         * 10+ in the replacement string are simply ignored. */
        const char *rep_ptr = replacement;
        while (*rep_ptr) {
            if (*rep_ptr == '\\' && *(rep_ptr + 1) >= '0' && *(rep_ptr + 1) <= '9') {
                size_t group = (size_t)(*(rep_ptr + 1) - '0');
                if (group < nmatch &&
                    pmatch[group].rm_so != -1 && pmatch[group].rm_eo != -1) {
                    size_t group_len = (size_t)(pmatch[group].rm_eo - pmatch[group].rm_so);
                    if (res_len + group_len >= res_cap) {
                        res_cap = res_len + group_len + 256;
                        char *new_res = realloc(res, res_cap);
                        if (!new_res) goto fail;
                        res = new_res;
                    }
                    memcpy(res + res_len, cursor + pmatch[group].rm_so, group_len);
                    res_len += group_len;
                }
                rep_ptr += 2;
            } else {
                if (res_len + 1 >= res_cap) {
                    res_cap = res_len + 256;
                    char *new_res = realloc(res, res_cap);
                    if (!new_res) goto fail;
                    res = new_res;
                }
                res[res_len++] = *rep_ptr++;
            }
        }

        cursor += pmatch[0].rm_eo;
        /* Guard against zero-length match: if the match consumed nothing,
         * copy one literal character and step forward to avoid an infinite loop. */
        if (pmatch[0].rm_eo == pmatch[0].rm_so) {
            if (*cursor == '\0') break;
            if (res_len + 1 >= res_cap) {
                res_cap = res_len + 256;
                char *new_res = realloc(res, res_cap);
                if (!new_res) goto fail;
                res = new_res;
            }
            res[res_len++] = *cursor++;
        }
    }

    size_t rem_len = strlen(cursor);
    if (res_len + rem_len >= res_cap) {
        res_cap = res_len + rem_len + 1;
        char *new_res = realloc(res, res_cap);
        if (!new_res) goto fail;
        res = new_res;
    }
    memcpy(res + res_len, cursor, rem_len);
    res_len += rem_len;
    res[res_len] = '\0';

    regfree(&re);
    free(src);
    free(pmatch);
    *out = (uint8_t *)res;
    *out_len = res_len;
    return;

fail:
    regfree(&re);
    free(src);
    free(res);
    free(pmatch);
    *out = NULL;
    *out_len = 0;
}

static np_err_t transform_process(np_processor_t *proc, np_packet_t *pkt)
{
    transform_priv_t *p = proc->priv;

    const uint8_t *in_data = NULL;
    size_t in_len = 0;
    get_packet_payload(pkt, &in_data, &in_len);

    if (in_len == 0 || !in_data) {
        return NP_OK;
    }

    uint8_t *out_data = NULL;
    size_t out_len = 0;

    switch (p->mode) {
    case TRANSFORM_HEX:
        hex_encode(in_data, in_len, &out_data, &out_len);
        break;
    case TRANSFORM_BASE64:
        base64_encode(in_data, in_len, &out_data, &out_len);
        break;
    case TRANSFORM_REGEX:
        regex_replace_payload(in_data, in_len, p->pattern, p->replacement, &out_data, &out_len);
        break;
    }

    if (out_data) {
        if (pkt->stream_data) {
            free(pkt->stream_data);
        }
        pkt->stream_data = out_data;
        pkt->stream_len  = out_len;
    }

    return NP_OK;
}

static void transform_free(np_processor_t *proc)
{
    transform_priv_t *p = proc->priv;
    if (p) {
        if (p->pattern) free(p->pattern);
        if (p->replacement) free(p->replacement);
        free(p);
    }
    free(proc);
}

static const struct np_processor_ops transform_ops = {
    .process = transform_process,
    .free    = transform_free
};

np_processor_t *np_processor_payload_transform(const char *mode, const char *pattern, const char *replacement)
{
    transform_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    if (strcmp(mode, "hex") == 0) {
        p->mode = TRANSFORM_HEX;
    } else if (strcmp(mode, "base64") == 0) {
        p->mode = TRANSFORM_BASE64;
    } else if (strcmp(mode, "regex") == 0) {
        p->mode = TRANSFORM_REGEX;
        if (!pattern || !replacement) {
            NP_LOG_ERROR("%s", "transform: regex mode requires pattern and replacement arguments");
            free(p);
            return NULL;
        }
        p->pattern = strdup(pattern);
        p->replacement = strdup(replacement);
        if (!p->pattern || !p->replacement) {
            if (p->pattern) free(p->pattern);
            if (p->replacement) free(p->replacement);
            free(p);
            return NULL;
        }
    } else {
        NP_LOG_ERROR("transform: unknown mode '%s'", mode);
        free(p);
        return NULL;
    }

    np_processor_t *proc = calloc(1, sizeof(*proc));
    if (!proc) {
        if (p->pattern) free(p->pattern);
        if (p->replacement) free(p->replacement);
        free(p);
        return NULL;
    }

    proc->ops  = &transform_ops;
    proc->priv = p;
    return proc;
}
