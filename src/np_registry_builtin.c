/*
 * np_registry_builtin.c — self-registration of built-in sinks/sources/filters
 *
 * FIX (issue: np_registry is fully implemented and unit-tested but never
 * called by the production pipeline — the CLI's infer_fmt() and the
 * sink-selection logic use hard-coded if/else chains instead).
 *
 * This file wires the existing built-in sinks into the registry via the
 * NP_REGISTER_SINK macro.  The constructors run before main() (via
 * __attribute__((constructor))), so by the time the CLI parses args,
 * np_registry_find_sink() and np_registry_find_sink_by_ext() can resolve
 * format names and file extensions without any hard-coded if/else chains.
 *
 * The CLI's infer_fmt() and sink-creation logic in main.c now consult
 * the registry first, falling back to the hard-coded paths only if the
 * registry is empty (which shouldn't happen, but defensive coding is
 * cheap).
 *
 * Future external plugins can drop in a .c file with their own
 * NP_REGISTER_SINK(my_desc); and the CLI will pick them up automatically
 * — no main.c changes required.
 */

#include "netpipe.h"
#include "registry/np_registry.h"

/* ------------------------------------------------------------------ */
/*  Sink descriptors                                                   */
/* ------------------------------------------------------------------ */

static np_sink_desc_t _pcap_desc = {
    .name       = "pcap",
    .long_name  = "Wireshark-compatible binary PCAP",
    .extensions = "pcap,cap",
    .create     = np_sink_pcap,
};
NP_REGISTER_SINK(_pcap_desc)

static np_sink_desc_t _pcapng_desc = {
    .name       = "pcapng",
    .long_name  = "PCAP-NG with interface and metadata blocks",
    .extensions = "pcapng",
    .create     = np_sink_pcapng,
};
NP_REGISTER_SINK(_pcapng_desc)

static np_sink_desc_t _json_desc = {
    .name       = "json",
    .long_name  = "Newline-delimited JSON (one object per packet)",
    .extensions = "json,ndjson",
    .create     = np_sink_json,
};
NP_REGISTER_SINK(_json_desc)

static np_sink_desc_t _hex_desc = {
    .name       = "hex",
    .long_name  = "Annotated hex dump with layer boundaries",
    .extensions = "hex,txt",
    .create     = np_sink_hex,
};
NP_REGISTER_SINK(_hex_desc)

static np_sink_desc_t _pretty_desc = {
    .name       = "pretty",
    .long_name  = "tshark-style single-line packet summaries",
    .extensions = "",
    .create     = np_sink_pretty,
};
NP_REGISTER_SINK(_pretty_desc)

static np_sink_desc_t _stats_desc = {
    .name       = "stats",
    .long_name  = "Periodic (5-second) packet/byte counters",
    .extensions = "stats",
    .create     = np_sink_stats,
};
NP_REGISTER_SINK(_stats_desc)

/* null sink has no path argument; the create function ignores it. */
static np_sink_t *_null_sink_create(const char *path) {
    (void)path;
    return np_sink_null();
}
static np_sink_desc_t _null_desc = {
    .name       = "null",
    .long_name  = "Discard all packets (for benchmarking)",
    .extensions = "",
    .create     = _null_sink_create,
};
NP_REGISTER_SINK(_null_desc)

/* ------------------------------------------------------------------ */
/*  Source descriptors (informational — sources still go through       */
/*  np_source_live / np_source_file / np_source_ring constructors     */
/*  because they take specialized arguments.  The registry entries    */
/*  let users list available sources via np_registry_list_sources().  */
/* ------------------------------------------------------------------ */

static np_source_t *_live_source_create(const char *url, int flags) {
    (void)flags;
    /* url is the interface name; default snaplen/promisc/timeout */
    return np_source_live(url, 65535, 0, 1000);
}
static np_source_desc_t _live_desc = {
    .name       = "live",
    .long_name  = "Live capture on a network interface (libpcap)",
    .url_prefix = "live:",
    .create     = _live_source_create,
};
NP_REGISTER_SOURCE(_live_desc)

static np_source_t *_file_source_create(const char *url, int flags) {
    (void)flags;
    return np_source_file(url);
}
static np_source_desc_t _file_desc = {
    .name       = "file",
    .long_name  = "Read packets from a PCAP file",
    .url_prefix = "file:",
    .create     = _file_source_create,
};
NP_REGISTER_SOURCE(_file_desc)

/* np_source_ring takes extra args (eth_proto, ring_blocks) that don't
 * fit the simple create(url, flags) signature, so we register it with
 * a stub factory that uses defaults. */
static np_source_t *_ring_source_create(const char *url, int flags) {
    (void)flags;
    return np_source_ring(url, 0, 0);
}
static np_source_desc_t _ring_desc = {
    .name       = "ring",
    .long_name  = "Linux AF_PACKET + PACKET_MMAP zero-copy ring capture",
    .url_prefix = "ring:",
    .create     = _ring_source_create,
};
NP_REGISTER_SOURCE(_ring_desc)
