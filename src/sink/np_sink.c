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
    case NP_LINK_LINUX_SLL: dlt = 113;       break;
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

static void fprint_json_str(FILE *fp, const char *str, size_t len) {
    fputc('"', fp);
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        if (c == '"' || c == '\\') { fputc('\\', fp); fputc(c, fp); }
        else if (c == '\n') fputs("\\n", fp);
        else if (c == '\r') fputs("\\r", fp);
        else if (c == '\t') fputs("\\t", fp);
        else if (c >= 0x20 && c <= 0x7e) fputc(c, fp);
    }
    fputc('"', fp);
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

    if (pkt->app && pkt->app->proto == NP_PROTO_HTTP && pkt->app->decoded) {
        const np_http_msg_t *http = pkt->app->decoded;
        fprintf(p->fp, ",\"http\":{");
        if (http->is_request) {
            fprintf(p->fp, "\"method\":"); fprint_json_str(p->fp, http->method.str, http->method.len);
            fprintf(p->fp, ",\"path\":"); fprint_json_str(p->fp, http->path.str, http->path.len);
            fprintf(p->fp, ",\"version\":"); fprint_json_str(p->fp, http->version.str, http->version.len);
        } else {
            fprintf(p->fp, "\"status\":%d,", http->status_code);
            fprintf(p->fp, "\"phrase\":"); fprint_json_str(p->fp, http->status_phrase.str, http->status_phrase.len);
            fprintf(p->fp, ",\"version\":"); fprint_json_str(p->fp, http->version.str, http->version.len);
        }
        fprintf(p->fp, ",\"headers\":{");
        for (int i = 0; i < http->num_headers; i++) {
            if (i > 0) fprintf(p->fp, ",");
            fprint_json_str(p->fp, http->headers[i].name.str, http->headers[i].name.len);
            fprintf(p->fp, ":");
            fprint_json_str(p->fp, http->headers[i].value.str, http->headers[i].value.len);
        }
        fprintf(p->fp, "}}");
    } else if (pkt->app && pkt->app->proto == NP_PROTO_DNS && pkt->app->decoded) {
        const np_dns_msg_t *dns = pkt->app->decoded;
        fprintf(p->fp, ",\"dns\":{");
        fprintf(p->fp, "\"id\":%u,", dns->id);
        fprintf(p->fp, "\"is_response\":%s,", dns->is_response ? "true" : "false");
        fprintf(p->fp, "\"rcode\":%d,", dns->rcode);
        
        if (dns->query_name[0]) {
            fprintf(p->fp, "\"query\":{\"name\":");
            fprint_json_str(p->fp, dns->query_name, strlen(dns->query_name));
            fprintf(p->fp, ",\"type\":%u},", dns->query_type);
        } else {
            fprintf(p->fp, "\"query\":null,");
        }
        
        fprintf(p->fp, "\"answers\":[");
        for (int i = 0; i < dns->num_answers; i++) {
            const np_dns_answer_t *ans = &dns->answers[i];
            if (i > 0) fprintf(p->fp, ",");
            fprintf(p->fp, "{\"name\":"); fprint_json_str(p->fp, ans->name, strlen(ans->name));
            fprintf(p->fp, ",\"type\":%u,\"class\":%u,\"ttl\":%u,\"data\":",
                    ans->type, ans->class_, ans->ttl);
            if (ans->rdata_str[0]) {
                fprint_json_str(p->fp, ans->rdata_str, strlen(ans->rdata_str));
            } else {
                fprintf(p->fp, "null");
            }
            fprintf(p->fp, "}");
        }
        fprintf(p->fp, "]}");
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

/* ------------------------------------------------------------------ */
/*  Pretty (tshark-style) sink                                          */
/* ------------------------------------------------------------------ */

/* ANSI colours — only emit when writing to a real terminal */
#include <unistd.h>
#define COL(s)  (use_color ? (s) : "")
#define CRESET  "\033[0m"
#define CGRAY   "\033[90m"
#define CCYAN   "\033[36m"
#define CGREEN  "\033[32m"
#define CYELLOW "\033[33m"
#define CRED    "\033[31m"
#define CBLUE   "\033[34m"
#define CMAG    "\033[35m"
#define CBOLD   "\033[1m"

typedef struct { FILE *fp; bool use_color; } pretty_sink_priv_t;

/* Format an IPv4 address from 4 bytes in network order */
static void fmt_ip4(char *buf, size_t bsz, const uint8_t *b) {
    snprintf(buf, bsz, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}
/* Format an IPv6 address from 16 bytes */
static void fmt_ip6(char *buf, size_t bsz, const uint8_t *b) {
    snprintf(buf, bsz, "%x:%x:%x:%x:%x:%x:%x:%x",
        (unsigned)((b[0]<<8)|b[1]), (unsigned)((b[2]<<8)|b[3]),
        (unsigned)((b[4]<<8)|b[5]), (unsigned)((b[6]<<8)|b[7]),
        (unsigned)((b[8]<<8)|b[9]), (unsigned)((b[10]<<8)|b[11]),
        (unsigned)((b[12]<<8)|b[13]), (unsigned)((b[14]<<8)|b[15]));
}

/* Build the "Info" column from decoded app-layer data */
static void build_info(const np_packet_t *pkt, char *info, size_t isz)
{
    info[0] = '\0';
    if (!pkt->app || !pkt->app->decoded) return;

    if (pkt->app->proto == NP_PROTO_HTTP) {
        const np_http_msg_t *h = pkt->app->decoded;
        if (h->is_request) {
            char method[16] = {0}, path[128] = {0};
            size_t ml = h->method.len < 15 ? h->method.len : 15;
            size_t pl = h->path.len   < 127 ? h->path.len  : 127;
            memcpy(method, h->method.str, ml);
            memcpy(path,   h->path.str,   pl);
            snprintf(info, isz, "%s %s", method, path);
        } else {
            char phrase[32] = {0};
            size_t phl = h->status_phrase.len < 31 ? h->status_phrase.len : 31;
            memcpy(phrase, h->status_phrase.str, phl);
            snprintf(info, isz, "%d %s", h->status_code, phrase);
        }
    } else if (pkt->app->proto == NP_PROTO_DNS) {
        const np_dns_msg_t *d = pkt->app->decoded;
        if (!d->is_response && d->query_name[0]) {
            const char *qtype = (d->query_type == 1)  ? "A" :
                                (d->query_type == 28) ? "AAAA" :
                                (d->query_type == 5)  ? "CNAME" : "?";
            snprintf(info, isz, "Q %s %s", qtype, d->query_name);
        } else if (d->is_response && d->num_answers > 0) {
            snprintf(info, isz, "A %s → %s",
                d->query_name[0] ? d->query_name : "?",
                d->answers[0].rdata_str[0] ? d->answers[0].rdata_str : "?");
        }
    } else if (pkt->app->proto == NP_PROTO_TLS) {
        /* Peek into raw TLS for SNI: ContentType=0x16, HandshakeType=0x01 */
        const uint8_t *d = pkt->app->data;
        size_t         n = pkt->app->len;
        if (n > 9 && d[0] == 0x16 && d[5] == 0x01) {
            /* ClientHello — scan for SNI extension (type 0x0000) */
            size_t pos = 9 + 32; /* skip record+handshake header + random */
            if (pos < n) {
                pos += 1 + d[pos]; /* skip session id */
                if (pos + 2 < n) {
                    uint16_t clen = (uint16_t)((d[pos]<<8)|d[pos+1]); pos += 2 + clen;
                }
                if (pos + 1 < n) { pos += 1 + d[pos]; } /* skip compression */
                if (pos + 2 < n) {
                    pos += 2; /* extensions length */
                    while (pos + 4 < n) {
                        uint16_t etype = (uint16_t)((d[pos]<<8)|d[pos+1]);
                        uint16_t elen  = (uint16_t)((d[pos+2]<<8)|d[pos+3]);
                        pos += 4;
                        if (etype == 0 && pos + 5 < n) {
                            /* SNI extension: list_len(2)+type(1)+name_len(2)+name */
                            size_t nlen = (size_t)((d[pos+3]<<8)|d[pos+4]);
                            if (pos + 5 + nlen <= n && nlen < 200) {
                                char sni[201] = {0};
                                memcpy(sni, d + pos + 5, nlen);
                                snprintf(info, isz, "ClientHello SNI=%s", sni);
                            }
                            break;
                        }
                        pos += elen;
                    }
                }
            }
            if (!info[0]) snprintf(info, isz, "ClientHello");
        } else if (n > 5 && d[0] == 0x16 && d[5] == 0x02) {
            snprintf(info, isz, "ServerHello");
        } else if (n > 5 && d[0] == 0x17) {
            snprintf(info, isz, "ApplicationData (%zu B)", n);
        }
    }
}

static np_err_t pretty_sink_write(np_sink_t *s, const np_packet_t *pkt)
{
    pretty_sink_priv_t *p = s->priv;
    bool use_color = p->use_color;

    /* ── Timestamp ─────────────────────────────────────────────────── */
    char ts[24];
    np_packet_ts_str(pkt, ts, sizeof(ts));
    /* Keep only HH:MM:SS.uuuuuu from the full string */
    const char *ts_short = strchr(ts, ' ');
    ts_short = ts_short ? ts_short + 1 : ts;

    /* ── Addresses ─────────────────────────────────────────────────── */
    char src[48] = "?", dst[48] = "?";
    uint16_t sport = 0, dport = 0;

    if (pkt->net) {
        const uint8_t *d = pkt->net->data;
        if (pkt->net->proto == NP_PROTO_IP4 && pkt->net->len >= 20) {
            fmt_ip4(src, sizeof(src), d + 12);
            fmt_ip4(dst, sizeof(dst), d + 16);
        } else if (pkt->net->proto == NP_PROTO_IP6 && pkt->net->len >= 40) {
            fmt_ip6(src, sizeof(src), d + 8);
            fmt_ip6(dst, sizeof(dst), d + 24);
        }
    }
    if (pkt->transport && pkt->transport->len >= 4) {
        const uint8_t *d = pkt->transport->data;
        sport = (uint16_t)((d[0] << 8) | d[1]);
        dport = (uint16_t)((d[2] << 8) | d[3]);
    }

    /* ── Highest protocol & colour ──────────────────────────────────── */
    const char *proto_color = CGRAY;
    const char *proto_name  = "ETH";
    if (pkt->app) {
        proto_name = pname(pkt->app->proto);
        switch (pkt->app->proto) {
        case NP_PROTO_HTTP: proto_color = CGREEN;  break;
        case NP_PROTO_DNS:  proto_color = CCYAN;   break;
        case NP_PROTO_TLS:  proto_color = CMAG;    break;
        default:            proto_color = CYELLOW; break;
        }
    } else if (pkt->transport) {
        proto_name = pname(pkt->transport->proto);
        proto_color = (pkt->transport->proto == NP_PROTO_TCP) ? CBLUE : CYELLOW;
    } else if (pkt->net) {
        proto_name = pname(pkt->net->proto);
    }

    /* ── Info string ────────────────────────────────────────────────── */
    char info[256] = {0};
    build_info(pkt, info, sizeof(info));

    /* ── Emit one line ──────────────────────────────────────────────── */
    if (sport || dport) {
        fprintf(p->fp, "%s%s%s  %-20s%s → %s%-20s%s  %s%-6s%s  %5u  %s%s%s\n",
            COL(CGRAY),  ts_short, COL(CRESET),
            src,         COL(CGRAY), COL(CRESET),
            dst,         COL(CRESET),
            COL(proto_color), proto_name, COL(CRESET),
            pkt->wirelen,
            COL(CGRAY), info, COL(CRESET));
    } else {
        fprintf(p->fp, "%s%s%s  %-42s  %s%-6s%s  %5u  %s%s%s\n",
            COL(CGRAY), ts_short, COL(CRESET),
            src,
            COL(proto_color), proto_name, COL(CRESET),
            pkt->wirelen,
            COL(CGRAY), info, COL(CRESET));
    }
    fflush(p->fp);
    return NP_OK;
}

static np_err_t pretty_sink_open(np_sink_t *s, np_linktype_t lt)
{
    (void)lt;
    pretty_sink_priv_t *p = s->priv;
    bool to_stdout = (p->fp == stdout);

    /* Print a header row */
    bool use_color = p->use_color;
    fprintf(p->fp, "%s%-12s  %-20s  %-20s  %-6s  %5s  %s%s\n",
        COL(CBOLD),
        "Time", "Source", "Destination", "Proto", "Len", "Info",
        COL(CRESET));
    fprintf(p->fp, "%s%s%s\n", COL(CGRAY),
        "─────────────────────────────────────────────────────────────────────────────",
        COL(CRESET));
    (void)to_stdout;
    return NP_OK;
}

static void pretty_sink_close(np_sink_t *s)
{
    pretty_sink_priv_t *p = s->priv;
    if (p->fp && p->fp != stdout) fclose(p->fp);
}
static void pretty_sink_free(np_sink_t *s)
{
    pretty_sink_close(s);
    free(s->priv);
    free(s);
}
static const struct np_sink_ops pretty_sink_ops = {
    .open  = pretty_sink_open,
    .write = pretty_sink_write,
    .close = pretty_sink_close,
    .free  = pretty_sink_free,
};

np_sink_t *np_sink_pretty(const char *path)
{
    pretty_sink_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    bool to_stdout = (!path || !strcmp(path, "-"));
    p->fp         = to_stdout ? stdout : fopen(path, "w");
    if (!p->fp) { free(p); return NULL; }
    p->use_color  = isatty(fileno(p->fp));
    np_sink_t *s = calloc(1, sizeof(*s));
    if (!s) { if (!to_stdout) fclose(p->fp); free(p); return NULL; }
    s->ops  = &pretty_sink_ops;
    s->priv = p;
    snprintf(s->name, sizeof(s->name), "pretty:%s", to_stdout ? "stdout" : path);
    return s;
}

/* ------------------------------------------------------------------ */
/*  TUN/TAP sink                                                        */
/* ------------------------------------------------------------------ */

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <net/if.h>
#include <linux/if_tun.h>

typedef struct {
    int fd;
    char dev[IFNAMSIZ];
    bool is_tun;
} tuntap_sink_priv_t;

static np_err_t tuntap_sink_open(np_sink_t *s, np_linktype_t lt)
{
    (void)lt;
    tuntap_sink_priv_t *p = s->priv;
    if ((p->fd = open("/dev/net/tun", O_RDWR)) < 0) {
        NP_LOG_ERROR("%s", "tuntap: failed to open /dev/net/tun (try running as root)");
        return NP_ERR_GENERIC;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    
    ifr.ifr_flags = (short)((p->is_tun ? IFF_TUN : IFF_TAP) | IFF_NO_PI);
    if (p->dev[0]) {
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", p->dev);
    }
    
    if (ioctl(p->fd, TUNSETIFF, (void *) &ifr) < 0) {
        NP_LOG_ERROR("tuntap: ioctl(TUNSETIFF) failed on %s", p->dev);
        close(p->fd);
        p->fd = -1;
        return NP_ERR_GENERIC;
    }
    
    strcpy(p->dev, ifr.ifr_name);
    NP_LOG_INFO("tuntap: opened %s device: %s", p->is_tun ? "TUN" : "TAP", p->dev);
    
    return NP_OK;
}

static np_err_t tuntap_sink_write(np_sink_t *s, const np_packet_t *pkt)
{
    tuntap_sink_priv_t *p = s->priv;
    if (p->fd < 0) return NP_ERR_GENERIC;

    const uint8_t *buf = NULL;
    size_t         buflen = 0;

    if (p->is_tun) {
        /* TUN = Layer 3: try net layer first, else fall back to raw */
        if (pkt->net && pkt->net->data && pkt->net->len > 0) {
            buf    = pkt->net->data;
            buflen = pkt->net->len;
        } else {
            buf    = pkt->raw;
            buflen = pkt->caplen;
        }
    } else {
        /* TAP = Layer 2: try eth layer first (Ethernet), else fall back to
         * the net layer (and we will synthesize an Ethernet header below). */
        if (pkt->eth && pkt->eth->data && pkt->eth->len > 0) {
            buf    = pkt->eth->data;
            buflen = pkt->eth->len;
        } else if (pkt->net && pkt->net->data && pkt->net->len > 0) {
            buf    = pkt->net->data;
            buflen = pkt->net->len;
        } else if (pkt->nlayers > 0 && pkt->layers[0].data && pkt->layers[0].len > 0) {
            buf    = pkt->layers[0].data;
            buflen = pkt->layers[0].len;
        } else {
            buf    = pkt->raw;
            buflen = pkt->caplen;
        }
    }

    if (buf && buflen > 0) {
        if (!p->is_tun && !pkt->eth) {
            /* Missing Ethernet header on a Layer 2 TAP interface.
             * This happens when replaying SLL-captured PCAPs (like from wlo1).
             * We must synthesize a 14-byte Ethernet header. */
            uint8_t eth_hdr[14] = {
                0x02, 0x00, 0x00, 0x00, 0x00, 0x01, /* dst MAC */
                0x02, 0x00, 0x00, 0x00, 0x00, 0x02, /* src MAC */
                0x08, 0x00   /* EtherType: default to IPv4 */
            };
            if (pkt->net && pkt->net->proto == NP_PROTO_IP6) {
                eth_hdr[12] = 0x86; eth_hdr[13] = 0xDD;
            }
            struct iovec iov[2];
            iov[0].iov_base = eth_hdr;
            iov[0].iov_len  = 14;
            iov[1].iov_base = (void *)buf;
            iov[1].iov_len  = buflen;
            if (writev(p->fd, iov, 2) < 0) return NP_ERR_IO;
        } else {
            if (write(p->fd, buf, buflen) < 0) return NP_ERR_IO;
        }
    }
    return NP_OK;
}

static void tuntap_sink_close(np_sink_t *s)
{
    tuntap_sink_priv_t *p = s->priv;
    if (p->fd >= 0) {
        close(p->fd);
        p->fd = -1;
    }
}

static void tuntap_sink_free(np_sink_t *s)
{
    tuntap_sink_close(s);
    free(s->priv);
    free(s);
}

static const struct np_sink_ops tuntap_sink_ops = {
    .open  = tuntap_sink_open,
    .write = tuntap_sink_write,
    .close = tuntap_sink_close,
    .free  = tuntap_sink_free,
};

np_sink_t *np_sink_tuntap(const char *uri)
{
    bool is_tun = false;
    char dev_name[16] = {0};
    
    if (strncmp(uri, "tun://", 6) == 0) {
        is_tun = true;
        strncpy(dev_name, uri + 6, sizeof(dev_name) - 1);
    } else if (strncmp(uri, "tap://", 6) == 0) {
        is_tun = false;
        strncpy(dev_name, uri + 6, sizeof(dev_name) - 1);
    } else {
        return NULL;
    }

    tuntap_sink_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    
    p->fd = -1;
    p->is_tun = is_tun;
    strcpy(p->dev, dev_name);
    
    np_sink_t *s = calloc(1, sizeof(*s));
    if (!s) { free(p); return NULL; }
    
    s->ops  = &tuntap_sink_ops;
    s->priv = p;
    snprintf(s->name, sizeof(s->name), "tuntap:%s", p->dev);
    return s;
}
#else
np_sink_t *np_sink_tuntap(const char *uri) {
    (void)uri;
    NP_LOG_ERROR("%s", "tuntap sink is only supported on Linux");
    return NULL;
}
#endif

/* ------------------------------------------------------------------ */
/*  Socket sink                                                         */
/* ------------------------------------------------------------------ */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

typedef struct {
    int fd;
    char host[128];
    int port;
} socket_sink_priv_t;

static np_err_t socket_sink_open(np_sink_t *s, np_linktype_t lt)
{
    socket_sink_priv_t *p = s->priv;
    
    struct hostent *he = gethostbyname(p->host);
    if (!he) {
        NP_LOG_ERROR("socket: unknown host %s", p->host);
        return NP_ERR_GENERIC;
    }
    
    p->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (p->fd < 0) {
        NP_LOG_ERROR("%s", "socket: creation failed");
        return NP_ERR_GENERIC;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)p->port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);
    
    if (connect(p->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        NP_LOG_ERROR("socket: failed to connect to %s:%d", p->host, p->port);
        close(p->fd);
        p->fd = -1;
        return NP_ERR_GENERIC;
    }
    
    NP_LOG_INFO("socket: connected to %s:%d", p->host, p->port);

    /* Write a PCAP global header so the receiver can parse this as a valid
     * pcap file/stream directly (e.g. piped into Wireshark or tshark). */
    struct {
        uint32_t magic;
        uint16_t major;
        uint16_t minor;
        int32_t  thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    } __attribute__((packed)) ghdr = {
        .magic   = 0xa1b2c3d4,
        .major   = 2,
        .minor   = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = (uint32_t)lt,  /* link type matches the capture source */
    };
    if (send(p->fd, &ghdr, sizeof(ghdr), 0) < 0) {
        NP_LOG_ERROR("%s", "socket: failed to write pcap global header");
        close(p->fd);
        p->fd = -1;
        return NP_ERR_IO;
    }

    return NP_OK;
}

static np_err_t socket_sink_write(np_sink_t *s, const np_packet_t *pkt)
{
    socket_sink_priv_t *p = s->priv;
    if (p->fd < 0) return NP_ERR_GENERIC;

    /* Write a PCAP per-packet record header before the raw bytes */
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t caplen;
        uint32_t origlen;
    } __attribute__((packed)) phdr = {
        .ts_sec  = (uint32_t)(pkt->ts.tv_sec),
        .ts_usec = (uint32_t)(pkt->ts.tv_nsec / 1000),
        .caplen  = (uint32_t)pkt->caplen,
        .origlen = (uint32_t)pkt->wirelen,
    };

    if (send(p->fd, &phdr, sizeof(phdr), MSG_MORE) < 0) {
        NP_LOG_ERROR("%s", "socket: write failed (packet header)");
        return NP_ERR_IO;
    }
    ssize_t n = send(p->fd, pkt->raw, pkt->caplen, 0);
    if (n < 0) {
        NP_LOG_ERROR("%s", "socket: write failed (packet data)");
        return NP_ERR_IO;
    }
    
    return NP_OK;
}

static void socket_sink_close(np_sink_t *s)
{
    socket_sink_priv_t *p = s->priv;
    if (p->fd >= 0) {
        close(p->fd);
        p->fd = -1;
    }
}

static void socket_sink_free(np_sink_t *s)
{
    socket_sink_close(s);
    free(s->priv);
    free(s);
}

static const struct np_sink_ops socket_sink_ops = {
    .open  = socket_sink_open,
    .write = socket_sink_write,
    .close = socket_sink_close,
    .free  = socket_sink_free,
};

np_sink_t *np_sink_socket(const char *uri)
{
    if (strncmp(uri, "socket://", 9) != 0) return NULL;
    
    char host_port[256];
    strncpy(host_port, uri + 9, sizeof(host_port) - 1);
    host_port[sizeof(host_port) - 1] = '\0';
    
    char *colon = strchr(host_port, ':');
    if (!colon) {
        NP_LOG_ERROR("socket: invalid uri '%s' (expected socket://host:port)", uri);
        return NULL;
    }
    *colon = '\0';
    
    socket_sink_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    
    p->fd = -1;
    snprintf(p->host, sizeof(p->host), "%s", host_port);
    p->port = atoi(colon + 1);
    
    np_sink_t *s = calloc(1, sizeof(*s));
    if (!s) { free(p); return NULL; }
    
    s->ops  = &socket_sink_ops;
    s->priv = p;
    snprintf(s->name, sizeof(s->name), "socket:%s:%d", p->host, p->port);
    return s;
}

/* ------------------------------------------------------------------ */
/*  PCAP-NG sink (native)                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    FILE *fp;
    char path[256];
    np_linktype_t lt;
} pcapng_sink_priv_t;

static np_err_t pcapng_sink_open(np_sink_t *s, np_linktype_t lt)
{
    pcapng_sink_priv_t *p = s->priv;
    p->lt = lt;

    bool to_stdout = strcmp(p->path, "-") == 0;
    p->fp = to_stdout ? stdout : fopen(p->path, "wb");
    if (!p->fp) {
        NP_LOG_ERROR("pcapng sink: cannot open '%s' for writing", p->path);
        return NP_ERR_IO;
    }

    /* 1. Write Section Header Block (SHB) */
    uint32_t shb_type = 0x0A0D0D0A;
    uint32_t shb_len = 28;
    uint32_t magic = 0x1A2B3C4D;
    uint16_t major = 1;
    uint16_t minor = 0;
    int64_t sec_len = -1;

    fwrite(&shb_type, 4, 1, p->fp);
    fwrite(&shb_len, 4, 1, p->fp);
    fwrite(&magic, 4, 1, p->fp);
    fwrite(&major, 2, 1, p->fp);
    fwrite(&minor, 2, 1, p->fp);
    fwrite(&sec_len, 8, 1, p->fp);
    fwrite(&shb_len, 4, 1, p->fp);

    /* 2. Write Interface Description Block (IDB) */
    uint32_t idb_type = 0x00000001;
    uint32_t idb_len = 20;
    uint16_t link_type = 1;
    switch (lt) {
        case NP_LINK_ETHERNET:  link_type = 1;   break;
        case NP_LINK_LOOPBACK:  link_type = 108; break;
        case NP_LINK_LINUX_SLL: link_type = 113; break;
        default:                link_type = 1;   break;
    }
    uint16_t reserved = 0;
    uint32_t snap_len = 65535;

    fwrite(&idb_type, 4, 1, p->fp);
    fwrite(&idb_len, 4, 1, p->fp);
    fwrite(&link_type, 2, 1, p->fp);
    fwrite(&reserved, 2, 1, p->fp);
    fwrite(&snap_len, 4, 1, p->fp);
    fwrite(&idb_len, 4, 1, p->fp);

    fflush(p->fp);
    NP_LOG_INFO("pcapng sink: writing to '%s'", p->path);
    return NP_OK;
}

static np_err_t pcapng_sink_write(np_sink_t *s, const np_packet_t *pkt)
{
    pcapng_sink_priv_t *p = s->priv;
    if (!p->fp) return NP_ERR_IO;

    /* Calculate padding */
    size_t padded_len = (pkt->caplen + 3) & ~3U;
    size_t padding_bytes = padded_len - pkt->caplen;
    uint32_t block_len = (uint32_t)(28 + padded_len + 4);

    /* Calculate timestamp in microseconds resolution */
    uint64_t ts_val = (uint64_t)pkt->ts.tv_sec * 1000000ULL + (uint64_t)pkt->ts.tv_nsec / 1000ULL;
    uint32_t ts_high = (uint32_t)(ts_val >> 32);
    uint32_t ts_low = (uint32_t)(ts_val & 0xFFFFFFFFULL);

    uint32_t epb_type = 0x00000006;
    uint32_t iface_id = 0;

    fwrite(&epb_type, 4, 1, p->fp);
    fwrite(&block_len, 4, 1, p->fp);
    fwrite(&iface_id, 4, 1, p->fp);
    fwrite(&ts_high, 4, 1, p->fp);
    fwrite(&ts_low, 4, 1, p->fp);
    fwrite(&pkt->caplen, 4, 1, p->fp);
    fwrite(&pkt->wirelen, 4, 1, p->fp);

    /* Write packet data */
    fwrite(pkt->raw, 1, pkt->caplen, p->fp);

    /* Write padding */
    if (padding_bytes > 0) {
        uint8_t pad[3] = {0, 0, 0};
        fwrite(pad, 1, padding_bytes, p->fp);
    }

    /* Write trailing Block Total Length */
    fwrite(&block_len, 4, 1, p->fp);

    fflush(p->fp);
    return NP_OK;
}

static void pcapng_sink_close(np_sink_t *s)
{
    pcapng_sink_priv_t *p = s->priv;
    if (p->fp) {
        if (p->fp != stdout) {
            fclose(p->fp);
        }
        p->fp = NULL;
    }
}

static void pcapng_sink_free(np_sink_t *s)
{
    pcapng_sink_close(s);
    free(s->priv);
    free(s);
}

static const struct np_sink_ops pcapng_sink_ops = {
    .open  = pcapng_sink_open,
    .write = pcapng_sink_write,
    .close = pcapng_sink_close,
    .free  = pcapng_sink_free,
};

np_sink_t *np_sink_pcapng(const char *path)
{
    pcapng_sink_priv_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    snprintf(p->path, sizeof(p->path), "%s", path);
    np_sink_t *s = calloc(1, sizeof(*s));
    if (!s) { free(p); return NULL; }
    s->ops  = &pcapng_sink_ops;
    s->priv = p;
    snprintf(s->name, sizeof(s->name), "pcapng:%s", path);
    return s;
}

void np_sink_free(np_sink_t *s)
{
    if (s && s->ops && s->ops->free) s->ops->free(s);
}
