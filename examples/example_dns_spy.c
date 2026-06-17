/*
 * example_dns_spy.c
 *
 * Example: intercept and log DNS queries using netpipe library
 *
 *   gcc example_dns_spy.c -I../include -L../build/lib \
 *       -lnetpipe -lpcap -lpthread -o dns_spy
 *   sudo ./dns_spy eth0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "netpipe.h"

static np_pipeline_t *g_pl = NULL;
static void stop(int s) { (void)s; if (g_pl) np_pipeline_stop(g_pl); }

/* ------------------------------------------------------------------ */
/*  Decode a DNS name from wire format into buf                         */
/* ------------------------------------------------------------------ */

static int dns_decode_name(const uint8_t *base, size_t baselen,
                           size_t offset, char *out, size_t outsz)
{
    size_t pos    = offset;
    size_t outpos = 0;
    int    hops   = 0;

    while (pos < baselen && hops < 16) {
        uint8_t len = base[pos];
        if (len == 0) break;

        /* Compression pointer */
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= baselen) return -1;
            pos = (size_t)(((len & 0x3F) << 8) | base[pos + 1]);
            hops++;
            continue;
        }

        if (outpos + len + 1 >= outsz) return -1;
        if (outpos > 0) out[outpos++] = '.';
        pos++;
        memcpy(out + outpos, base + pos, len);
        outpos += len;
        pos    += len;
    }
    out[outpos] = '\0';
    return 0;
}

static np_err_t dns_print(np_packet_t *pkt, void *ud)
{
    (void)ud;
    if (!pkt->app || pkt->app->proto != NP_PROTO_DNS) return NP_OK;

    const uint8_t *d = pkt->app->data;
    size_t         l = pkt->app->len;

    if (l < 12) return NP_OK;

    uint16_t flags   = (uint16_t)((d[2] << 8) | d[3]);
    uint16_t qdcount = (uint16_t)((d[4] << 8) | d[5]);
    bool     is_resp = (flags & 0x8000) != 0;

    if (!qdcount) return NP_OK;

    char name[256];
    if (dns_decode_name(d, l, 12, name, sizeof(name)) != 0) return NP_OK;

    /* qtype at offset after name + null byte */
    char ts[32];
    np_packet_ts_str(pkt, ts, sizeof(ts));

    printf("[%s] DNS %s  %s\n", ts, is_resp ? "RESP" : "QUERY", name);
    return NP_OK;
}

int main(int argc, char *argv[])
{
    if (argc < 2) { fprintf(stderr, "Usage: %s <interface>\n", argv[0]); return 1; }

    np_init();

    np_pipeline_t *pl = np_pipeline_new();
    g_pl = pl;

    np_pipeline_add_source(pl, np_source_live(argv[1], 65535, 1, 500));
    np_pipeline_add_filter(pl, np_filter_port(53));
    np_pipeline_add_processor(pl, np_processor_fn(dns_print, NULL));
    np_pipeline_add_sink(pl, np_sink_null());

    signal(SIGINT, stop);
    printf("DNS spy on %s  (Ctrl-C to stop)\n\n", argv[1]);

    np_pipeline_run(pl);
    np_pipeline_free(pl);
    np_cleanup();
    return 0;
}
