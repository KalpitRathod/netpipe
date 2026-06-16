/*
 * main.c — netpipe CLI
 *
 * Usage examples (FFmpeg-style):
 *
 *   # Live capture on eth0, write pcap + stats
 *   sudo netpipe -i eth0 -o capture.pcap -stats stats.txt
 *
 *   # Read pcap file, filter HTTP, dump hex to stdout
 *   netpipe -r input.pcap -f "tcp port 80" -fmt hex
 *
 *   # Live capture, filter by host and protocol, write JSON
 *   sudo netpipe -i eth0 -host 1.2.3.4 -proto tcp -o out.json -fmt json
 *
 *   # Print to stdout, verbose logging
 *   sudo netpipe -i lo -fmt hex -v
 *
 *   # List available devices
 *   netpipe -D
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "netpipe.h"
#include "log/np_log.h"
#include "pipeline/np_pipeline.h"

/* ------------------------------------------------------------------ */
/*  Global pipeline (for signal handling)                               */
/* ------------------------------------------------------------------ */

static np_pipeline_t *g_pipeline = NULL;

static void sigint_handler(int sig)
{
    (void)sig;
    fprintf(stderr, "\n[netpipe] interrupted — flushing and closing...\n");
    if (g_pipeline) np_pipeline_stop(g_pipeline);
}

/* ------------------------------------------------------------------ */
/*  ANSI banner                                                         */
/* ------------------------------------------------------------------ */

static void print_banner(void)
{
    printf("\033[1;36m"
           "  ███╗   ██╗███████╗████████╗██████╗ ██╗██████╗ ███████╗\n"
           "  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝\n"
           "  ██╔██╗ ██║█████╗     ██║   ██████╔╝██║██████╔╝█████╗  \n"
           "  ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██║██╔═══╝ ██╔══╝  \n"
           "  ██║ ╚████║███████╗   ██║   ██║     ██║██║     ███████╗ \n"
           "  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝     ╚══════╝\n"
           "\033[0m"
           "\033[2m  network processing pipeline  v" NETPIPE_VERSION_STR "\033[0m\n\n");
}

/* ------------------------------------------------------------------ */
/*  Usage                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    printf(
        "Usage: %s [OPTIONS]\n\n"
        "Input:\n"
        "  -i <device>       Live capture on network interface (requires root)\n"
        "  --ring            Enable Linux zero-copy packet ring buffer capture (AF_PACKET + PACKET_MMAP)\n"
        "  -r <file.pcap>    Read from pcap file\n"
        "  -D                List available capture devices and exit\n"
        "  -s <snaplen>      Snapshot length (default 65535)\n"
        "  -p                Disable promiscuous mode\n"
        "  -T <ms>           Read timeout in milliseconds (default 1000)\n"
        "\n"
        "Filtering:\n"
        "  -f <bpf-expr>     BPF filter expression  (e.g. \"tcp port 80\")\n"
        "  -proto <name>     Protocol filter: eth, arp, ip, ip6, icmp, tcp, udp, dns, http, tls\n"
        "  -port  <port>     Port filter (src or dst)\n"
        "  -host  <ip>       Host filter (src or dst IPv4)\n"
        "\n"
        "Output:\n"
        "  -o <file>         Output file (format inferred from extension or -fmt)\n"
        "  -o tap://<dev>    Inject packets into a Linux TAP (Layer 2) virtual interface\n"
        "  -o tun://<dev>    Inject packets into a Linux TUN (Layer 3) virtual interface\n"
        "  -o socket://<h:p> Forward raw packets to a remote host over TCP\n"
        "  -fmt <format>     Output format: pcap (default), pcapng, json, hex, pretty, stats, null\n"
        "  -stats <file>     Write periodic statistics to file (use '-' for stdout)\n"
        "  -c <count>        Stop after capturing N packets\n"
        "\n"
        "Processing:\n"
        "  -proc tcp-stream  Enable TCP stream reassembly\n"
        "  -proc flow-tracker Maintain per-5-tuple state across packets and print summary table\n"
        "  -proc transform:<hex|base64|regex:pat:rep>  Apply transformation to payload\n"
        "  -proc lua:<file.lua> Execute a Lua packet processing/filtering script\n"
        "  -rate <bps>       Rate-limit output to N bytes per second (token bucket)\n"
        "\n"
        "Logging:\n"
        "  -v                Verbose (DEBUG level)\n"
        "  -vv               Very verbose (TRACE level)\n"
        "  -q                Quiet (WARN level only)\n"
        "  -no-color         Disable ANSI colours\n"
        "\n"
        "Misc:\n"
        "  -h, --help        Show this help\n"
        "  --version         Print version and exit\n"
        "\n"
        "Examples:\n"
        "  sudo %s -i eth0 -o capture.pcap\n"
        "  sudo %s -i eth0 -f \"udp port 53\" -fmt json -o dns.json\n"
        "       %s -r dump.pcap -proto http -fmt hex\n"
        "  sudo %s -i lo -port 8080 -stats - -o /dev/null\n"
        "  sudo %s -r cap.pcap -o tap://tap0 -rate 10000\n"
        "  sudo %s -i wlo1 -c 50 -o socket://192.168.1.10:9999\n"
        "\n",
        prog, prog, prog, prog, prog, prog, prog);
}

/* ------------------------------------------------------------------ */
/*  Device listing                                                      */
/* ------------------------------------------------------------------ */

static void list_devices(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs, *d;

    if (pcap_findalldevs(&devs, errbuf) != 0) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return;
    }

    printf("\033[1mAvailable capture devices:\033[0m\n");
    int n = 0;
    for (d = devs; d; d = d->next, n++) {
        printf("  \033[36m%-20s\033[0m  %s\n",
               d->name, d->description ? d->description : "(no description)");

        /* print addresses */
        for (pcap_addr_t *a = d->addresses; a; a = a->next) {
            if (!a->addr) continue;
            char addr_str[64] = "?";
            if (a->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
                printf("    IPv4: %s\n", addr_str);
            } else if (a->addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)a->addr;
                inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
                printf("    IPv6: %s\n", addr_str);
            }
        }
    }
    if (n == 0) printf("  (none found — are you running as root?)\n");
    printf("\n");
    pcap_freealldevs(devs);
}

/* ------------------------------------------------------------------ */
/*  Proto name → ID                                                     */
/* ------------------------------------------------------------------ */

static np_proto_t parse_proto(const char *name)
{
    if (!strcasecmp(name, "eth"))  return NP_PROTO_ETH;
    if (!strcasecmp(name, "arp"))  return NP_PROTO_ARP;
    if (!strcasecmp(name, "ip")  || !strcasecmp(name, "ipv4")) return NP_PROTO_IP4;
    if (!strcasecmp(name, "ip6") || !strcasecmp(name, "ipv6")) return NP_PROTO_IP6;
    if (!strcasecmp(name, "icmp")) return NP_PROTO_ICMP;
    if (!strcasecmp(name, "tcp"))  return NP_PROTO_TCP;
    if (!strcasecmp(name, "udp"))  return NP_PROTO_UDP;
    if (!strcasecmp(name, "dns"))  return NP_PROTO_DNS;
    if (!strcasecmp(name, "http")) return NP_PROTO_HTTP;
    if (!strcasecmp(name, "tls") || !strcasecmp(name, "ssl")) return NP_PROTO_TLS;
    return NP_PROTO_RAW; /* unknown */
}

/* ------------------------------------------------------------------ */
/*  Count-limiting processor                                            */
/* ------------------------------------------------------------------ */

typedef struct { uint64_t limit; uint64_t count; np_pipeline_t *pl; } count_priv_t;

static np_err_t count_proc(np_packet_t *pkt, void *ud)
{
    (void)pkt;
    count_priv_t *p = ud;
    if (++p->count >= p->limit) {
        NP_LOG_INFO("packet limit (%lu) reached", (unsigned long)p->limit);
        np_pipeline_stop(p->pl);
    }
    return NP_OK;
}

/* ------------------------------------------------------------------ */
/*  Infer output format from extension                                  */
/* ------------------------------------------------------------------ */

static const char *infer_fmt(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot) return "pcap";
    if (!strcasecmp(dot, ".pcapng")) return "pcapng";
    if (!strcasecmp(dot, ".pcap") || !strcasecmp(dot, ".cap")) return "pcap";
    if (!strcasecmp(dot, ".json") || !strcasecmp(dot, ".ndjson")) return "json";
    if (!strcasecmp(dot, ".txt")  || !strcasecmp(dot, ".hex")) return "hex";
    return "pcap";
}

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */


int main(int argc, char *argv[])
{
    np_init();

    /* ---- Default options ---- */
    bool quiet             = false;
    const char *fmt        = NULL;
    const char *bpf_expr   = NULL;
    const char *proto_str  = NULL;
    const char *host_str   = NULL;
    const char *stats_path = NULL;
    int         snaplen    = 65535;
    int         promisc    = 1;
    int         timeout_ms = 1000;
    uint64_t    count      = 0;  /* 0 = unlimited */
    bool        list_dev   = false;
    bool        no_color   = false;
    uint16_t    port_num   = 0;
    bool        use_tcp_stream = false;
    bool        use_flow_tracker = false;
    const char *lua_script_path = NULL;
    uint64_t    rate_bps   = 0;
    bool        use_transform = false;
    char        transform_mode[64] = {0};
    char       *transform_pattern = NULL;
    char       *transform_replacement = NULL;
    bool        use_ring   = false;

    const char *inputs[NP_MAX_SOURCES];
    bool        input_is_file[NP_MAX_SOURCES];
    int         n_inputs = 0;

    const char *outputs[NP_MAX_SINKS];
    const char *out_fmts[NP_MAX_SINKS];
    int         n_outputs = 0;

    /* ---- Arg parsing ---- */
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

#define NEED_ARG(flag) \
    do { if (i + 1 >= argc) { \
        fprintf(stderr, "error: %s requires an argument\n", flag); return 1; \
    } } while (0)

        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "--version")) {
            printf("netpipe version %s\n", NETPIPE_VERSION_STR);
            return 0;
        }
        else if (!strcmp(a, "-D"))  { list_dev  = true; }
        else if (!strcmp(a, "-p"))  { promisc   = 0; }
        else if (!strcmp(a, "--ring") || !strcmp(a, "-ring")) { use_ring = true; }
        else if (!strcmp(a, "-v"))  { np_log_set_level(NP_LOG_DEBUG); }
        else if (!strcmp(a, "-vv")) { np_log_set_level(NP_LOG_TRACE); }
        else if (!strcmp(a, "-q"))  { quiet = true; np_log_set_level(NP_LOG_WARN); }
        else if (!strcmp(a, "-no-color")) { no_color = true; }
        else if (!strcmp(a, "-i")) {
            NEED_ARG("-i");
            if (n_inputs >= NP_MAX_SOURCES) {
                fprintf(stderr, "error: maximum of %d inputs exceeded\n", NP_MAX_SOURCES);
                return 1;
            }
            inputs[n_inputs] = argv[++i];
            input_is_file[n_inputs] = false;
            n_inputs++;
        }
        else if (!strcmp(a, "-r")) {
            NEED_ARG("-r");
            if (n_inputs >= NP_MAX_SOURCES) {
                fprintf(stderr, "error: maximum of %d inputs exceeded\n", NP_MAX_SOURCES);
                return 1;
            }
            inputs[n_inputs] = argv[++i];
            input_is_file[n_inputs] = true;
            n_inputs++;
        }
        else if (!strcmp(a, "-o")) {
            NEED_ARG("-o");
            if (n_outputs >= NP_MAX_SINKS) {
                fprintf(stderr, "error: maximum of %d outputs exceeded\n", NP_MAX_SINKS);
                return 1;
            }
            outputs[n_outputs] = argv[++i];
            out_fmts[n_outputs] = fmt;
            fmt = NULL; /* consumed */
            n_outputs++;
        }
        else if (!strcmp(a, "-fmt"))   { NEED_ARG("-fmt");   fmt        = argv[++i]; }
        else if (!strcmp(a, "-f"))     { NEED_ARG("-f");     bpf_expr   = argv[++i]; }
        else if (!strcmp(a, "-proto")) { NEED_ARG("-proto"); proto_str  = argv[++i]; }
        else if (!strcmp(a, "-host"))  { NEED_ARG("-host");  host_str   = argv[++i]; }
        else if (!strcmp(a, "-stats")) { NEED_ARG("-stats"); stats_path = argv[++i]; }
        else if (!strcmp(a, "-s"))     { NEED_ARG("-s");     snaplen    = atoi(argv[++i]); }
        else if (!strcmp(a, "-T"))     { NEED_ARG("-T");     timeout_ms = atoi(argv[++i]); }
        else if (!strcmp(a, "-c"))     { NEED_ARG("-c");     count      = (uint64_t)strtoull(argv[++i], NULL, 10); }
        else if (!strcmp(a, "-port"))  { NEED_ARG("-port");  port_num   = (uint16_t)atoi(argv[++i]); }
        else if (!strcmp(a, "-rate"))  { NEED_ARG("-rate");  rate_bps   = (uint64_t)strtoull(argv[++i], NULL, 10); }
        else if (!strcmp(a, "-proc"))  { 
            NEED_ARG("-proc");
            const char *proc_arg = argv[++i];
            if (!strcmp(proc_arg, "tcp-stream")) {
                use_tcp_stream = true;
            } else if (!strcmp(proc_arg, "flow-tracker")) {
                use_flow_tracker = true;
            } else if (!strncmp(proc_arg, "lua:", 4)) {
                lua_script_path = proc_arg + 4;
            } else if (!strncmp(proc_arg, "transform:", 10)) {
                use_transform = true;
                const char *mode_part = proc_arg + 10;
                if (!strncmp(mode_part, "regex:", 6)) {
                    strcpy(transform_mode, "regex");
                    const char *pat_start = mode_part + 6;
                    const char *next_colon = strchr(pat_start, ':');
                    if (next_colon) {
                        size_t pat_len = (size_t)(next_colon - pat_start);
                        transform_pattern = malloc(pat_len + 1);
                        if (transform_pattern) {
                            memcpy(transform_pattern, pat_start, pat_len);
                            transform_pattern[pat_len] = '\0';
                        }
                        transform_replacement = strdup(next_colon + 1);
                    } else {
                        fprintf(stderr, "error: transform:regex requires pattern and replacement (e.g. transform:regex:pattern:replacement)\n");
                        return 1;
                    }
                } else if (!strcmp(mode_part, "hex")) {
                    strcpy(transform_mode, "hex");
                } else if (!strcmp(mode_part, "base64")) {
                    strcpy(transform_mode, "base64");
                } else {
                    fprintf(stderr, "error: unknown transform mode: %s (expected hex, base64, or regex:...)\n", mode_part);
                    return 1;
                }
            } else {
                fprintf(stderr, "unknown processor: %s\n", proc_arg);
                return 1;
            }
        }
        else {
            fprintf(stderr, "unknown option: %s  (use -h for help)\n", a);
            return 1;
        }
    }

    if (no_color) np_log_set_color(false);

    /* If -fmt was specified after one or more -o flags (rather than before), the
     * per-output slot will be NULL because -fmt hadn't been seen yet when -o ran.
     * Apply the leftover fmt now so "-o out.pcap -fmt json" works as expected. */
    if (fmt) {
        for (int idx = 0; idx < n_outputs; idx++) {
            if (!out_fmts[idx]) out_fmts[idx] = fmt;
        }
    }

    /* Automatically suppress banner if JSON output is requested on stdout */
    bool json_to_stdout = false;
    if (n_outputs == 0 && fmt && !strcmp(fmt, "json")) {
        json_to_stdout = true;
    } else {
        for (int idx = 0; idx < n_outputs; idx++) {
            if (!strcmp(outputs[idx], "-") && out_fmts[idx] && !strcmp(out_fmts[idx], "json")) {
                json_to_stdout = true;
                break;
            }
        }
    }
    if (json_to_stdout) quiet = true;

    if (!quiet) print_banner();

    if (list_dev) { list_devices(); return 0; }

    /* Validate */
    if (n_inputs == 0) {
        fprintf(stderr, "error: specify at least one input with -i <device> or -r <file.pcap>\n"
                        "       Use -D to list available devices.\n");
        usage(argv[0]);
        return 1;
    }

    /* ---- Build pipeline ---- */
    np_pipeline_t *pl = np_pipeline_new();
    if (!pl) { NP_LOG_FATAL("%s", "out of memory"); return 1; }
    g_pipeline = pl;

    /* Sources */
    for (int idx = 0; idx < n_inputs; idx++) {
        np_source_t *src;
        if (input_is_file[idx]) {
            src = np_source_file(inputs[idx]);
        } else {
            if (use_ring) {
                src = np_source_ring(inputs[idx]);
            } else {
                src = np_source_live(inputs[idx], snaplen, promisc, timeout_ms);
            }
        }

        if (!src) {
            fprintf(stderr, "error: could not open input '%s' — do you need root for live capture?\n", inputs[idx]);
            np_pipeline_free(pl);
            return 1;
        }
        np_pipeline_add_source(pl, src);
    }

    /* Filters */
    if (bpf_expr) {
        np_filter_t *f = np_filter_bpf(bpf_expr);
        if (!f) { NP_LOG_ERROR("bad BPF expression: %s", bpf_expr); np_pipeline_free(pl); return 1; }
        np_pipeline_add_filter(pl, f);
    }
    if (proto_str) {
        np_proto_t p = parse_proto(proto_str);
        if (p == NP_PROTO_RAW) {
            NP_LOG_WARN("unknown protocol '%s' — filter ignored", proto_str);
        } else {
            np_pipeline_add_filter(pl, np_filter_proto(p));
        }
    }
    if (port_num) {
        np_pipeline_add_filter(pl, np_filter_port(port_num));
    }
    if (host_str) {
        np_filter_t *hf = np_filter_host(host_str);
        if (!hf) { NP_LOG_ERROR("bad host: %s", host_str); np_pipeline_free(pl); return 1; }
        np_pipeline_add_filter(pl, hf);
    }

    /* Processors */
    count_priv_t count_state = { .limit = count, .count = 0, .pl = pl };
    if (count > 0) {
        np_processor_t *cp = np_processor_fn(count_proc, &count_state);
        if (cp) np_pipeline_add_processor(pl, cp);
    }
    if (use_tcp_stream) {
        np_processor_t *sp = np_processor_tcp_stream();
        if (sp) np_pipeline_add_processor(pl, sp);
        else { NP_LOG_ERROR("%s", "failed to create tcp stream processor"); np_pipeline_free(pl); return 1; }
    }
    if (rate_bps > 0) {
        np_processor_t *rp = np_processor_rate_limit(rate_bps);
        if (rp) np_pipeline_add_processor(pl, rp);
        else { NP_LOG_ERROR("%s", "failed to create rate limiter"); np_pipeline_free(pl); return 1; }
    }
    if (use_transform) {
        np_processor_t *tp = np_processor_payload_transform(transform_mode, transform_pattern, transform_replacement);
        if (tp) np_pipeline_add_processor(pl, tp);
        else { NP_LOG_ERROR("failed to create transform processor: %s", transform_mode); np_pipeline_free(pl); return 1; }
    }
    if (use_flow_tracker) {
        np_processor_t *ftp = np_processor_flow_tracker();
        if (ftp) np_pipeline_add_processor(pl, ftp);
        else { NP_LOG_ERROR("%s", "failed to create flow tracker processor"); np_pipeline_free(pl); return 1; }
    }
    if (lua_script_path) {
        np_processor_t *lp = np_processor_lua(lua_script_path);
        if (lp) np_pipeline_add_processor(pl, lp);
        else { NP_LOG_ERROR("failed to create Lua processor from script '%s'", lua_script_path); np_pipeline_free(pl); return 1; }
    }

    /* Sinks */
    if (n_outputs > 0) {
        for (int idx = 0; idx < n_outputs; idx++) {
            const char *outfile = outputs[idx];
            const char *eff_fmt = out_fmts[idx];
            np_sink_t *out_sink = NULL;

            if (!strncmp(outfile, "tun://", 6) || !strncmp(outfile, "tap://", 6)) {
                out_sink = np_sink_tuntap(outfile);
            } else if (!strncmp(outfile, "socket://", 9)) {
                out_sink = np_sink_socket(outfile);
            } else {
                if (!eff_fmt) eff_fmt = infer_fmt(outfile);
                if (!strcmp(eff_fmt, "json"))       out_sink = np_sink_json(outfile);
                else if (!strcmp(eff_fmt, "hex"))   out_sink = np_sink_hex(outfile);
                else if (!strcmp(eff_fmt, "pretty")) out_sink = np_sink_pretty(outfile);
                else if (!strcmp(eff_fmt, "stats")) out_sink = np_sink_stats(outfile);
                else if (!strcmp(eff_fmt, "null"))  out_sink = np_sink_null();
                else if (!strcmp(eff_fmt, "pcapng")) out_sink = np_sink_pcapng(outfile);
                else                                out_sink = np_sink_pcap(outfile);
            }

            if (!out_sink) {
                NP_LOG_ERROR("failed to create output sink for '%s'", outfile);
                np_pipeline_free(pl);
                return 1;
            }
            np_pipeline_add_sink(pl, out_sink);
        }
    } else if (fmt) {
        /* No -o but -fmt given → use stdout/- */
        np_sink_t *out_sink = NULL;
        if (!strcmp(fmt, "json"))   out_sink = np_sink_json("-");
        else if (!strcmp(fmt, "hex"))    out_sink = np_sink_hex("-");
        else if (!strcmp(fmt, "pretty")) out_sink = np_sink_pretty("-");
        else if (!strcmp(fmt, "stats"))  out_sink = np_sink_stats("-");
        else if (!strcmp(fmt, "null"))   out_sink = np_sink_null();
        else if (!strcmp(fmt, "pcapng")) out_sink = np_sink_pcapng("-");
        else {
            NP_LOG_WARN("format '%s' requires an output file (-o). Defaulting to pretty.", fmt);
            out_sink = np_sink_pretty("-");
        }
        if (out_sink) np_pipeline_add_sink(pl, out_sink);
    } else {
        /* Default: pretty to stdout */
        np_pipeline_add_sink(pl, np_sink_pretty("-"));
    }

    /* Optional stats side-channel */
    if (stats_path) {
        np_sink_t *ss = np_sink_stats(stats_path);
        if (ss) np_pipeline_add_sink(pl, ss);
    }

    /* Signal handler for clean Ctrl-C */
    signal(SIGINT,  sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* ---- Run ---- */
    np_err_t ret = np_pipeline_run(pl);

    np_pipeline_free(pl);
    g_pipeline = NULL;
    np_cleanup();

    if (transform_pattern) free(transform_pattern);
    if (transform_replacement) free(transform_replacement);

    return ret == NP_OK ? 0 : 1;
}
