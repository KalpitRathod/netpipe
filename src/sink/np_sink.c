/*
 * np_sink_pcap.c  — write captured packets to a .pcap file
 * np_sink_json.c  — write packets as newline-delimited JSON
 * np_sink_hex.c   — write human-readable hex dump
 * np_sink_stats.c — periodic statistics to stdout
 * np_sink_null.c  — discard all packets
 *
 * All sinks in one file for brevity; split if the project grows.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"
#include "../pipeline/np_pipeline.h"

/* ------------------------------------------------------------------ */
/*  Helper: proto name                                                  */
/* ------------------------------------------------------------------ */

static const char *pname(np_proto_t p)
{
    switch (p) {
    case NP_PROTO_ETH:  return "ethernet";
    case NP_PROTO_ARP:  return "arp";
    case NP_PROTO_IP4:  return "ipv4";
    case NP_PROTO_IP6:  return "ipv6";
    case NP_PROTO_ICMP: return "icmp";
    case NP_PROTO_TCP:  return "tcp";
    case NP_PROTO_UDP:  return "udp";
    case NP_PROTO_DNS:  return "dns";
    case NP_PROTO_HTTP: return "http";
    case NP_PROTO_TLS:  return "tls";
    default:            return "raw";
    }
}

/* ------------------------------------------------------------------ */
/*  PCAP sink                                                           */
/* ------------------------------------------------------------------ */

typedef struct { pcap_dumper_t *dumper; pcap_t *fake; char path[256]; } pcap_sink_priv_t;

static np_err_t pcap_sink_open(np_sink_t *s, np_linktype_t lt)
{
    pcap_sink_priv_t *p = s->priv;

    int dlt;
    switch (lt) {
    case NP_LINK_ETHERNET: dlt = DLT_EN10MB; break;
    case NP_LINK_LOOPBACK: dlt = DLT_NULL;   break;
    default:               dlt = DLT_RAW;    break;
    }

    p->fake = pcap_open_dead(dlt, 65535);
    if (!p->fake) { NP_LOG_ERROR("%s", "pcap_open_dead failed"); return NP_ERR_IO; }

    p->dumper = pcap_dump_open(p->fake, p->path);
    if (!p->dumper) {
        NP_LOG_ERROR("pcap_dump_open(%s): %s", p->path, pcap_geterr(p->fake));
        pcap_close(p->fake);
        return NP_ERR_IO;
    }
    NP_LOG_INFO("pcap sink: writing to '%s'", p->path);
    return NP_OK;
}

static np_err_t pcap_sink_write(np_sink_t *s, const np_packet_t *pkt)
{
    pcap_sink_priv_t *p = s->priv;
    struct pcap_pkthdr hdr;
    hdr.ts.tv_sec  = pkt->ts.tv_sec;
    hdr.ts.tv_usec = (suseconds_t)(pkt->ts.tv_nsec / 1000);
    hdr.caplen = pkt->caplen;
    hdr.len    = pkt->wirelen;
    pcap_dump((u_char *)p->dumper, &hdr, pkt->raw);
    return NP_OK;
}

static void pcap_sink_close(np_sink_t *s)
{
    pcap_sink_priv_t *p = s->priv;
    if (p->dumper) { pcap_dump_close(p->dumper); p->dumper = NULL; }
    if (p->fake)   { pcap_close(p->fake);         p->fake   = NULL; }
}

static void pcap_sink_free(np_sink_t *s) { pcap_sink_close(s); free(s->priv); free(s); }

static const struct np_sink_ops pcap_sink_ops = {
    .open  = pcap_sink_open,
    .write = pcap_sink_write,
    .close = pcap_sink_close,
    .free  = pcap_sink_free,
};

np_sink_t *np_sink_pcap(const char *path)
{
    pcap_sink_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    snprintf(p->path, sizeof(p->path), "%s", path);
    np_sink_t *s = calloc(1, sizeof(*s));
    if (!s) { free(p); return NULL; }
    s->ops  = &pcap_sink_ops;
    s->priv = p;
    snprintf(s->name, sizeof(s->name), "pcap:%s", path);
    return s;
}

/* ------------------------------------------------------------------ */
/*  JSON (NDJSON) sink                                                  */
/* ------------------------------------------------------------------ */

typedef struct { FILE *fp; char path[256]; uint64_t count; } json_sink_priv_t;

static np_err_t json_sink_open(np_sink_t *s, np_linktype_t lt)
{
    (void)lt;
    json_sink_priv_t *p = s->priv;
    bool to_stdout = strcmp(p->path, "-") == 0;
    p->fp = to_stdout ? stdout : fopen(p->path, "w");
    if (!p->fp) { NP_LOG_ERROR("cannot open %s", p->path); return NP_ERR_IO; }
    NP_LOG_INFO("json sink: writing to '%s'", p->path);
    return NP_OK;
}

static np_err_t json_sink_write(np_sink_t *s, const np_packet_t *pkt)
{
    json_sink_priv_t *p = s->priv;
    char ts[32];
    np_packet_ts_str(pkt, ts, sizeof(ts));

    fprintf(p->fp, "{\"seq\":%lu,\"ts\":\"%s\",\"caplen\":%u,\"wirelen\":%u,"
                   "\"flow_id\":%u,\"layers\":[",
            (unsigned long)pkt->seq, ts, pkt->caplen, pkt->wirelen, pkt->flow_id);

    for (int i = 0; i < pkt->nlayers; i++) {
        if (i) fputc(',', p->fp);
        fprintf(p->fp, "{\"proto\":\"%s\",\"len\":%zu}",
                pname(pkt->layers[i].proto), pkt->layers[i].len);
    }

    /* Embed raw packet as hex string (up to 1500 bytes) */
    size_t dump = pkt->caplen < 1500 ? pkt->caplen : 1500;
    fprintf(p->fp, "],\"raw_hex\":\"");
    for (size_t i = 0; i < dump; i++) fprintf(p->fp, "%02x", pkt->raw[i]);
    fprintf(p->fp, "\"");

    if (pkt->stream_data && pkt->stream_len > 0) {
        fprintf(p->fp, ",\"stream_hex\":\"");
        for (size_t i = 0; i < pkt->stream_len; i++) {
            fprintf(p->fp, "%02x", pkt->stream_data[i]);
        }
        fprintf(p->fp, "\"");
    }

    fprintf(p->fp, "}\n");

    p->count++;
    if (p->count % 1000 == 0) fflush(p->fp);
    return NP_OK;
}

static void json_sink_close(np_sink_t *s)
{
    json_sink_priv_t *p = s->priv;
    if (p->fp && p->fp != stdout) { fflush(p->fp); fclose(p->fp); p->fp = NULL; }
}
static void json_sink_free(np_sink_t *s) { json_sink_close(s); free(s->priv); free(s); }

static const struct np_sink_ops json_sink_ops = {
    .open  = json_sink_open,
    .write = json_sink_write,
    .close = json_sink_close,
    .free  = json_sink_free,
};

np_sink_t *np_sink_json(const char *path)
{
    json_sink_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    snprintf(p->path, sizeof(p->path), "%s", path);
    np_sink_t *s = calloc(1, sizeof(*s));
    if (!s) { free(p); return NULL; }
    s->ops  = &json_sink_ops;
    s->priv = p;
    snprintf(s->name, sizeof(s->name), "json:%s", path);
    return s;
}

/* ------------------------------------------------------------------ */
/*  Hex dump sink                                                       */
/* ------------------------------------------------------------------ */

typedef struct { FILE *fp; char path[256]; } hex_sink_priv_t;

static np_err_t hex_sink_open(np_sink_t *s, np_linktype_t lt)
{
    (void)lt;
    hex_sink_priv_t *p = s->priv;
    bool to_stdout = strcmp(p->path, "-") == 0;
    p->fp = to_stdout ? stdout : fopen(p->path, "w");
    if (!p->fp) { NP_LOG_ERROR("cannot open %s", p->path); return NP_ERR_IO; }
    return NP_OK;
}

static np_err_t hex_sink_write(np_sink_t *s, const np_packet_t *pkt)
{
    hex_sink_priv_t *p = s->priv;
    np_packet_print(pkt, p->fp);
    return NP_OK;
}

static void hex_sink_close(np_sink_t *s)
{
    hex_sink_priv_t *p = s->priv;
    if (p->fp && p->fp != stdout) { fclose(p->fp); p->fp = NULL; }
}
static void hex_sink_free(np_sink_t *s) { hex_sink_close(s); free(s->priv); free(s); }

static const struct np_sink_ops hex_sink_ops = {
    .open  = hex_sink_open,
    .write = hex_sink_write,
    .close = hex_sink_close,
    .free  = hex_sink_free,
};

np_sink_t *np_sink_hex(const char *path)
{
    hex_sink_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    snprintf(p->path, sizeof(p->path), "%s", path ? path : "-");
    np_sink_t *s = calloc(1, sizeof(*s));
    if (!s) { free(p); return NULL; }
    s->ops  = &hex_sink_ops;
    s->priv = p;
    snprintf(s->name, sizeof(s->name), "hex:%s", p->path);
    return s;
}

/* ------------------------------------------------------------------ */
/*  Statistics sink                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    FILE    *fp;
    char     path[256];
    uint64_t pkts;
    uint64_t bytes;
    uint64_t proto_count[16];  /* indexed by rough proto bucket */
    time_t   last_report;
    int      interval_s;
} stats_sink_priv_t;

static np_err_t stats_sink_open(np_sink_t *s, np_linktype_t lt)
{
    (void)lt;
    stats_sink_priv_t *p = s->priv;
    bool to_stdout = strcmp(p->path, "-") == 0;
    p->fp = to_stdout ? stdout : fopen(p->path, "w");
    if (!p->fp) { NP_LOG_ERROR("cannot open %s", p->path); return NP_ERR_IO; }
    p->last_report = time(NULL);
    NP_LOG_INFO("stats sink: reporting every %ds to '%s'", p->interval_s, p->path);
    return NP_OK;
}

static np_err_t stats_sink_write(np_sink_t *s, const np_packet_t *pkt)
{
    stats_sink_priv_t *p = s->priv;
    p->pkts++;
    p->bytes += pkt->caplen;

    /* bucket by transport proto */
    if (pkt->transport) {
        switch (pkt->transport->proto) {
        case NP_PROTO_TCP:  p->proto_count[0]++; break;
        case NP_PROTO_UDP:  p->proto_count[1]++; break;
        case NP_PROTO_ICMP: p->proto_count[2]++; break;
        default:            p->proto_count[3]++; break;
        }
    }
    if (pkt->app) {
        switch (pkt->app->proto) {
        case NP_PROTO_HTTP: p->proto_count[4]++; break;
        case NP_PROTO_DNS:  p->proto_count[5]++; break;
        case NP_PROTO_TLS:  p->proto_count[6]++; break;
        default: break;
        }
    }

    time_t now = time(NULL);
    if (now - p->last_report >= p->interval_s) {
        p->last_report = now;
        struct tm tm;
        localtime_r(&now, &tm);
        fprintf(p->fp,
            "[%02d:%02d:%02d] pkts=%-8lu bytes=%-12lu "
            "TCP=%-6lu UDP=%-6lu ICMP=%-6lu "
            "HTTP=%-6lu DNS=%-6lu TLS=%-6lu\n",
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            (unsigned long)p->pkts,
            (unsigned long)p->bytes,
            (unsigned long)p->proto_count[0],
            (unsigned long)p->proto_count[1],
            (unsigned long)p->proto_count[2],
            (unsigned long)p->proto_count[4],
            (unsigned long)p->proto_count[5],
            (unsigned long)p->proto_count[6]);
        fflush(p->fp);
    }
    return NP_OK;
}

static void stats_sink_close(np_sink_t *s)
{
    stats_sink_priv_t *p = s->priv;
    if (p->fp) {
        fprintf(p->fp,
            "\n=== Final Stats ===\n"
            "  Packets : %lu\n"
            "  Bytes   : %lu\n"
            "  TCP     : %lu\n"
            "  UDP     : %lu\n"
            "  ICMP    : %lu\n"
            "  HTTP    : %lu\n"
            "  DNS     : %lu\n"
            "  TLS     : %lu\n",
            (unsigned long)p->pkts,
            (unsigned long)p->bytes,
            (unsigned long)p->proto_count[0],
            (unsigned long)p->proto_count[1],
            (unsigned long)p->proto_count[2],
            (unsigned long)p->proto_count[4],
            (unsigned long)p->proto_count[5],
            (unsigned long)p->proto_count[6]);
        fflush(p->fp);
        if (p->fp != stdout) fclose(p->fp);
        p->fp = NULL;
    }
}
static void stats_sink_free(np_sink_t *s) { stats_sink_close(s); free(s->priv); free(s); }

static const struct np_sink_ops stats_sink_ops = {
    .open  = stats_sink_open,
    .write = stats_sink_write,
    .close = stats_sink_close,
    .free  = stats_sink_free,
};

np_sink_t *np_sink_stats(const char *path)
{
    stats_sink_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    snprintf(p->path, sizeof(p->path), "%s", path ? path : "-");
    p->interval_s = 5;
    np_sink_t *s = calloc(1, sizeof(*s));
    if (!s) { free(p); return NULL; }
    s->ops  = &stats_sink_ops;
    s->priv = p;
    snprintf(s->name, sizeof(s->name), "stats:%s", p->path);
    return s;
}

/* ------------------------------------------------------------------ */
/*  Null sink                                                           */
/* ------------------------------------------------------------------ */

static np_err_t null_open (np_sink_t *s, np_linktype_t lt) { (void)s; (void)lt; return NP_OK; }
static np_err_t null_write(np_sink_t *s, const np_packet_t *pkt) { (void)s; (void)pkt; return NP_OK; }
static void     null_close(np_sink_t *s) { (void)s; }
static void     null_free (np_sink_t *s) { free(s); }
static const struct np_sink_ops null_sink_ops = {
    .open  = null_open,
    .write = null_write,
    .close = null_close,
    .free  = null_free,
};

np_sink_t *np_sink_null(void)
{
    np_sink_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->ops = &null_sink_ops;
    snprintf(s->name, sizeof(s->name), "null");
    return s;
}

void np_sink_free(np_sink_t *s)
{
    if (s && s->ops && s->ops->free) s->ops->free(s);
}
