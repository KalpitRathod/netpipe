# C API Components

The `netpipe` processing engine relies on pluggable components (Sources, Filters, Processors, and Sinks). You can mix and match these components to build custom pipelines.

---

## Ingestion Sources

Sources ingest packets from the physical environment (interfaces, ring buffers, files) and push them into the pipeline.

```c
// Live capture using libpcap
np_source_t *np_source_live(const char *device, int snaplen, int promisc, int timeout_ms);

// Offline capture from standard PCAP/PCAP-NG files
np_source_t *np_source_file(const char *path);

// High-performance circular ring buffer live capture (Linux PACKET_MMAP raw socket)
np_source_t *np_source_ring(const char *device);

// Manually release source (if not added to a pipeline)
void np_source_free(np_source_t *src);
```

* **Live Source**: Excellent for general capture, requires `root` or `CAP_NET_RAW`.
* **Offline Source**: Parses PCAP dumps, does not require administrative privileges.
* **Ring Source**: Highly optimized circular RX ring mapped directly to user-space memory (`mmap`). Essential for high packet-per-second (PPS) capture without drops.

---

## Packet Filters

Filters discard packets that do not match specific criteria.

```c
// Standard BPF compile (syntax identical to tcpdump / wireshark)
np_filter_t *np_filter_bpf(const char *expr);

// Filter by protocol in the packet's layer stack
np_filter_t *np_filter_proto(np_proto_t proto);

// Filter by source/destination TCP/UDP port
np_filter_t *np_filter_port(uint16_t port);

// Filter by source/destination IPv4 address
np_filter_t *np_filter_host(const char *host);

// Composite Filters
np_filter_t *np_filter_and(np_filter_t *a, np_filter_t *b);
np_filter_t *np_filter_or(np_filter_t *a,  np_filter_t *b);
np_filter_t *np_filter_not(np_filter_t *a);

// Manually release filter (if not added to a pipeline)
void np_filter_free(np_filter_t *f);
```

### Composing Filters
You can build complex, nested filter hierarchies:
```c
np_filter_t *tcp_only = np_filter_proto(NP_PROTO_TCP);
np_filter_t *port_80  = np_filter_port(80);
np_filter_t *port_443 = np_filter_port(443);

np_filter_t *web_ports = np_filter_or(port_80, port_443);
np_filter_t *final_flt = np_filter_and(tcp_only, web_ports);

np_pipeline_add_filter(pl, final_flt);
```

---

## Processors (DPI & Transforms)

Processors inspect, rate-limit, transform, or associate context to packets passing through.

```c
// Custom callback processor function signature
typedef np_err_t (*np_proc_fn)(np_packet_t *pkt, void *userdata);

// Create custom callback processor
np_processor_t *np_processor_fn(np_proc_fn fn, void *userdata);

// TCP stream reassembly processor (rebuilds contiguous payloads)
np_processor_t *np_processor_tcp_stream(void);

// Token-bucket rate limiter
np_processor_t *np_processor_rate_limit(uint64_t bytes_per_sec);

// Payload pattern replacement/transformer
np_processor_t *np_processor_payload_transform(const char *mode, const char *pattern, const char *replacement);

// Flow tracker (five-tuple association and flow ID generation)
np_processor_t *np_processor_flow_tracker(void);

// Embedded Lua scripting hook
np_processor_t *np_processor_lua(const char *script_path);
```

### Implementing a Custom Callback Processor
You can easily write custom C logic to inspect packet headers:
```c
np_err_t my_packet_inspector(np_packet_t *pkt, void *ud) {
    (void)ud;
    // Check if packet contains a TCP layer
    if (pkt->transport && pkt->transport->proto == NP_PROTO_TCP) {
        printf("TCP packet caplen: %u bytes\n", pkt->caplen);
    }
    return NP_OK; // Return NP_OK to pass packet forward; return negative to filter it out
}

...
np_pipeline_add_processor(pl, np_processor_fn(my_packet_inspector, NULL));
```

---

## Output Sinks

Sinks are the final stage of the pipeline. They format, record, or transmit packet data.

```c
// Write standard binary PCAP file
np_sink_t *np_sink_pcap(const char *path);

// Write PCAP-NG file (supports interface details and block headers)
np_sink_t *np_sink_pcapng(const char *path);

// Newline-delimited JSON formatter (NDJSON)
np_sink_t *np_sink_json(const char *path);

// Layer-annotated hex-dump formatter
np_sink_t *np_sink_hex(const char *path);

// Write stats report every 5 seconds
np_sink_t *np_sink_stats(const char *path);

// Discard packet (useful for benchmarks)
np_sink_t *np_sink_null(void);

// tshark-style pretty output formatter
np_sink_t *np_sink_pretty(const char *path);

// Virtual network interface injector (e.g. "tun://tun0", "tap://tap0")
np_sink_t *np_sink_tuntap(const char *uri);

// Forward raw packets over a network socket (e.g. "socket://host:port")
np_sink_t *np_sink_socket(const char *uri);

// Manually release sink (if not added to a pipeline)
void np_sink_free(np_sink_t *s);
```
