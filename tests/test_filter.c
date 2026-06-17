#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "netpipe.h"
#include "packet/np_packet.h"
#include "demux/np_demux.h"
#include "pipeline/np_pipeline.h"

static void test_filters_on_http_packet(void)
{
    np_source_t *src = np_source_file("tests/fixtures/ipv4_tcp_http.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);

    np_packet_t *pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);
    assert(np_demux_packet(pkt, src->linktype) == NP_OK);

    /* 1. Protocol Filters */
    np_filter_t *f_tcp = np_filter_proto(NP_PROTO_TCP);
    np_filter_t *f_udp = np_filter_proto(NP_PROTO_UDP);
    assert(f_tcp->ops->match(f_tcp, pkt) == true);
    assert(f_udp->ops->match(f_udp, pkt) == false);

    /* 2. Port Filters */
    np_filter_t *f_port_80 = np_filter_port(80);
    np_filter_t *f_port_53 = np_filter_port(53);
    assert(f_port_80->ops->match(f_port_80, pkt) == true);
    assert(f_port_53->ops->match(f_port_53, pkt) == false);

    /* 3. Host Filters */
    np_filter_t *f_host_src = np_filter_host("192.168.1.1");
    np_filter_t *f_host_bad = np_filter_host("8.8.8.8");
    assert(f_host_src->ops->match(f_host_src, pkt) == true);
    assert(f_host_bad->ops->match(f_host_bad, pkt) == false);

    /* 4. Combinators (AND) */
    np_filter_t *f_and_match = np_filter_and(np_filter_proto(NP_PROTO_TCP), np_filter_port(80));
    np_filter_t *f_and_fail = np_filter_and(np_filter_proto(NP_PROTO_TCP), np_filter_port(53));
    assert(f_and_match->ops->match(f_and_match, pkt) == true);
    assert(f_and_fail->ops->match(f_and_fail, pkt) == false);

    /* 5. Combinators (OR) */
    np_filter_t *f_or_match = np_filter_or(np_filter_port(53), np_filter_port(80));
    np_filter_t *f_or_fail = np_filter_or(np_filter_port(53), np_filter_port(443));
    assert(f_or_match->ops->match(f_or_match, pkt) == true);
    assert(f_or_fail->ops->match(f_or_fail, pkt) == false);

    /* 6. Combinators (NOT) */
    np_filter_t *f_not_match = np_filter_not(np_filter_port(53));
    np_filter_t *f_not_fail = np_filter_not(np_filter_port(80));
    assert(f_not_match->ops->match(f_not_match, pkt) == true);
    assert(f_not_fail->ops->match(f_not_fail, pkt) == false);

    /* Cleanup */
    np_filter_free(f_tcp);
    np_filter_free(f_udp);
    np_filter_free(f_port_80);
    np_filter_free(f_port_53);
    np_filter_free(f_host_src);
    np_filter_free(f_host_bad);
    np_filter_free(f_and_match);
    np_filter_free(f_and_fail);
    np_filter_free(f_or_match);
    np_filter_free(f_or_fail);
    np_filter_free(f_not_match);
    np_filter_free(f_not_fail);

    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);
}

int main(void)
{
    np_init();
    printf("Running filter unit tests...\n");

    test_filters_on_http_packet();

    np_cleanup();
    printf("All filter tests PASSED!\n");
    return 0;
}
