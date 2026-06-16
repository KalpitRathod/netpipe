#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "netpipe.h"
#include "packet/np_packet.h"
#include "demux/np_demux.h"
#include "pipeline/np_pipeline.h"

static void test_arp_demux(void)
{
    np_source_t *src = np_source_file("tests/fixtures/arp.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);

    np_packet_t *pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);

    assert(np_demux_packet(pkt, src->linktype) == NP_OK);

    /* Assert layers and protocols */
    assert(pkt->nlayers >= 2);
    assert(pkt->layers[0].proto == NP_PROTO_ETH);
    assert(pkt->layers[1].proto == NP_PROTO_ARP);
    assert(pkt->eth != NULL);
    assert(pkt->net != NULL);

    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);
    printf("  ARP demux check: PASSED\n");
}

static void test_http_demux(void)
{
    np_source_t *src = np_source_file("tests/fixtures/ipv4_tcp_http.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);

    np_packet_t *pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);

    assert(np_demux_packet(pkt, src->linktype) == NP_OK);

    assert(pkt->nlayers >= 4);
    assert(pkt->layers[0].proto == NP_PROTO_ETH);
    assert(pkt->layers[1].proto == NP_PROTO_IP4);
    assert(pkt->layers[2].proto == NP_PROTO_TCP);
    assert(pkt->layers[3].proto == NP_PROTO_HTTP);

    assert(pkt->eth != NULL);
    assert(pkt->net != NULL);
    assert(pkt->transport != NULL);
    assert(pkt->app != NULL);

    /* Assert parsed fields */
    np_http_msg_t *msg = pkt->app->decoded;
    assert(msg != NULL);
    assert(msg->is_request == true);
    assert(strncmp(msg->method.str, "GET", msg->method.len) == 0);
    assert(strncmp(msg->path.str, "/index.html", msg->path.len) == 0);
    
    assert(msg->num_headers > 0);
    assert(strncmp(msg->headers[0].name.str, "Host", msg->headers[0].name.len) == 0);
    assert(strncmp(msg->headers[0].value.str, "example.com", msg->headers[0].value.len) == 0);

    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);
    printf("  HTTP demux check: PASSED\n");
}

static void test_dns_demux(void)
{
    np_source_t *src = np_source_file("tests/fixtures/ipv4_udp_dns.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);

    np_packet_t *pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);

    assert(np_demux_packet(pkt, src->linktype) == NP_OK);

    assert(pkt->nlayers >= 4);
    assert(pkt->layers[0].proto == NP_PROTO_ETH);
    assert(pkt->layers[1].proto == NP_PROTO_IP4);
    assert(pkt->layers[2].proto == NP_PROTO_UDP);
    assert(pkt->layers[3].proto == NP_PROTO_DNS);

    assert(pkt->app != NULL);
    np_dns_msg_t *msg = pkt->app->decoded;
    assert(msg != NULL);
    assert(msg->is_response == false);
    assert(strcmp(msg->query_name, "example.com") == 0);
    assert(msg->query_type == 1); /* A record */

    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);
    printf("  DNS demux check: PASSED\n");
}

static void test_tls_demux(void)
{
    np_source_t *src = np_source_file("tests/fixtures/ipv6_tcp_tls.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);

    np_packet_t *pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);

    assert(np_demux_packet(pkt, src->linktype) == NP_OK);

    assert(pkt->nlayers >= 4);
    assert(pkt->layers[0].proto == NP_PROTO_ETH);
    assert(pkt->layers[1].proto == NP_PROTO_IP6);
    assert(pkt->layers[2].proto == NP_PROTO_TCP);
    assert(pkt->layers[3].proto == NP_PROTO_TLS);

    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);
    printf("  TLS demux check: PASSED\n");
}

static void test_icmp_demux(void)
{
    np_source_t *src = np_source_file("tests/fixtures/ipv4_icmp.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);

    np_packet_t *pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);

    assert(np_demux_packet(pkt, src->linktype) == NP_OK);

    assert(pkt->nlayers >= 3);
    assert(pkt->layers[0].proto == NP_PROTO_ETH);
    assert(pkt->layers[1].proto == NP_PROTO_IP4);
    assert(pkt->layers[2].proto == NP_PROTO_ICMP);

    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);
    printf("  ICMP demux check: PASSED\n");
}

/* ------------------------------------------------------------------ */
/*  Negative demux tests — each fixture must NOT decode as wrong protos */
/* ------------------------------------------------------------------ */

static void test_negative_demux(void)
{
    np_source_t *src;
    np_packet_t *pkt;

    /* ARP packet: must have no transport or app layer */
    src = np_source_file("tests/fixtures/arp.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);
    pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);
    assert(np_demux_packet(pkt, src->linktype) == NP_OK);
    assert(pkt->layers[1].proto == NP_PROTO_ARP);   /* is ARP */
    assert(pkt->transport == NULL);                  /* NOT TCP/UDP/ICMP */
    assert(pkt->app == NULL);                        /* NOT HTTP/DNS/TLS */
    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);

    /* ICMP packet: must have no app layer, transport must not be TCP or UDP */
    src = np_source_file("tests/fixtures/ipv4_icmp.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);
    pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);
    assert(np_demux_packet(pkt, src->linktype) == NP_OK);
    assert(pkt->transport != NULL);
    assert(pkt->transport->proto == NP_PROTO_ICMP); /* is ICMP */
    assert(pkt->transport->proto != NP_PROTO_TCP);  /* NOT TCP */
    assert(pkt->transport->proto != NP_PROTO_UDP);  /* NOT UDP */
    assert(pkt->app == NULL);                        /* NOT HTTP/DNS/TLS */
    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);

    /* HTTP packet: app layer must be HTTP, not DNS or TLS */
    src = np_source_file("tests/fixtures/ipv4_tcp_http.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);
    pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);
    assert(np_demux_packet(pkt, src->linktype) == NP_OK);
    assert(pkt->app != NULL);
    assert(pkt->app->proto == NP_PROTO_HTTP);        /* is HTTP */
    assert(pkt->app->proto != NP_PROTO_DNS);         /* NOT DNS */
    assert(pkt->app->proto != NP_PROTO_TLS);         /* NOT TLS */
    assert(pkt->net->proto  != NP_PROTO_IP6);        /* NOT IPv6 */
    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);

    /* DNS packet: app layer must be DNS, not HTTP or TLS; transport must be UDP not TCP */
    src = np_source_file("tests/fixtures/ipv4_udp_dns.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);
    pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);
    assert(np_demux_packet(pkt, src->linktype) == NP_OK);
    assert(pkt->app != NULL);
    assert(pkt->app->proto == NP_PROTO_DNS);         /* is DNS */
    assert(pkt->app->proto != NP_PROTO_HTTP);        /* NOT HTTP */
    assert(pkt->app->proto != NP_PROTO_TLS);         /* NOT TLS */
    assert(pkt->transport->proto == NP_PROTO_UDP);   /* transport is UDP */
    assert(pkt->transport->proto != NP_PROTO_TCP);   /* NOT TCP */
    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);

    /* TLS packet: app layer must be TLS, not HTTP or DNS; network must be IPv6 not IPv4 */
    src = np_source_file("tests/fixtures/ipv6_tcp_tls.pcap");
    assert(src != NULL);
    assert(src->ops->open(src) == NP_OK);
    pkt = NULL;
    assert(src->ops->next(src, &pkt) == NP_OK);
    assert(pkt != NULL);
    assert(np_demux_packet(pkt, src->linktype) == NP_OK);
    assert(pkt->app != NULL);
    assert(pkt->app->proto == NP_PROTO_TLS);         /* is TLS */
    assert(pkt->app->proto != NP_PROTO_HTTP);        /* NOT HTTP */
    assert(pkt->app->proto != NP_PROTO_DNS);         /* NOT DNS */
    assert(pkt->net->proto  == NP_PROTO_IP6);        /* network is IPv6 */
    assert(pkt->net->proto  != NP_PROTO_IP4);        /* NOT IPv4 */
    np_packet_free(pkt);
    src->ops->close(src);
    np_source_free(src);

    printf("  Negative protocol demux checks: PASSED\n");
}

static void test_malformed_packets(void)
{
    /* 1. Truncated Ethernet header */
    np_packet_t *pkt = np_packet_alloc(10);
    pkt->caplen = 10;
    pkt->wirelen = 10;
    assert(np_demux_packet(pkt, NP_LINK_ETHERNET) == NP_ERR_PROTO);
    np_packet_free(pkt);

    /* 2. Truncated IPv4 header */
    pkt = np_packet_alloc(20);
    /* Valid Eth (14 bytes) but only 6 bytes left for IP */
    memset(pkt->raw, 0, 20);
    pkt->raw[12] = 0x08; pkt->raw[13] = 0x00; /* IPv4 */
    pkt->caplen = 20;
    pkt->wirelen = 20;
    assert(np_demux_packet(pkt, NP_LINK_ETHERNET) == NP_OK);
    /* Should stop decoding at Eth, net should be NULL since IP header is truncated */
    assert(pkt->net == NULL);
    np_packet_free(pkt);

    /* 3. Invalid IPv4 version or IHL */
    pkt = np_packet_alloc(40);
    memset(pkt->raw, 0, 40);
    pkt->raw[12] = 0x08; pkt->raw[13] = 0x00;
    pkt->raw[14] = 0x55; /* Version=5, IHL=5 (invalid version) */
    pkt->caplen = 40;
    pkt->wirelen = 40;
    assert(np_demux_packet(pkt, NP_LINK_ETHERNET) == NP_OK);
    assert(pkt->net == NULL);
    np_packet_free(pkt);

    printf("  Malformed packets error-handling check: PASSED\n");
}

int main(void)
{
    np_init();
    printf("Running protocol demuxer unit tests...\n");

    test_arp_demux();
    test_http_demux();
    test_dns_demux();
    test_tls_demux();
    test_icmp_demux();
    test_malformed_packets();
    test_negative_demux();

    np_cleanup();
    printf("All demuxer tests PASSED!\n");
    return 0;
}
