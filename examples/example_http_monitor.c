/*
 * example_http_monitor.c
 *
 * Example: live HTTP traffic monitor using the netpipe library API
 *
 *   gcc example_http_monitor.c -I../../include -L../../build/lib \
 *       -lnetpipe -lpcap -lpthread -o http_monitor
 *   sudo ./http_monitor eth0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "netpipe.h"

static np_pipeline_t *g_pl = NULL;
static void stop(int s) { (void)s; if (g_pl) np_pipeline_stop(g_pl); }

/* ------------------------------------------------------------------ */
/*  Custom processor: print first line of HTTP request/response        */
/* ------------------------------------------------------------------ */

static np_err_t http_print(np_packet_t *pkt, void *ud)
{
    (void)ud;
    if (!pkt->app || pkt->app->proto != NP_PROTO_HTTP) return NP_OK;

    const uint8_t *d = pkt->app->data;
    size_t         l = pkt->app->len;

    /* find first newline */
    size_t line_end = 0;
    while (line_end < l && d[line_end] != '\n') line_end++;

    char ts[32];
    np_packet_ts_str(pkt, ts, sizeof(ts));

    printf("[%s] HTTP  %.*s\n", ts, (int)line_end, (const char *)d);
    return NP_OK;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    np_init();

    np_pipeline_t *pl = np_pipeline_new();
    g_pl = pl;

    /* Source: live capture */
    np_pipeline_add_source(pl, np_source_live(argv[1], 65535, 1, 500));

    /* Filter: only TCP port 80 or 8080 */
    np_filter_t *f = np_filter_or(np_filter_port(80), np_filter_port(8080));
    np_pipeline_add_filter(pl, f);

    /* Processor: print HTTP lines */
    np_pipeline_add_processor(pl, np_processor_fn(http_print, NULL));

    /* Sink: null (we print manually in the processor) */
    np_pipeline_add_sink(pl, np_sink_null());

    signal(SIGINT, stop);
    printf("Monitoring HTTP on %s  (Ctrl-C to stop)\n\n", argv[1]);

    np_pipeline_run(pl);
    np_pipeline_free(pl);
    np_cleanup();
    return 0;
}
