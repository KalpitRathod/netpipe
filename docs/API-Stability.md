# netpipe Public API Stability

> **tl;dr** — If a symbol in `include/netpipe.h` is not tagged `NP_EXPERIMENTAL`, it is frozen.
> We will not rename it, change its signature, or alter its semantics without bumping `NETPIPE_VERSION_MAJOR`.

---

## Versioning Scheme

netpipe follows [Semantic Versioning](https://semver.org/):

| Version component | Incremented when … |
|---|---|
| **MAJOR** | Any stable public API symbol is renamed, removed, or has its signature changed. |
| **MINOR** | New symbols are added to the stable public API; no existing symbol changes. |
| **PATCH** | Bug fixes only; no API changes of any kind. |

Runtime version detection:
```c
int maj, min, patch;
np_version(&maj, &min, &patch);
```

Compile-time comparisons:
```c
#if NETPIPE_VERSION_INT >= NETPIPE_MAKE_VERSION(0, 2, 0)
    /* use a hypothetical 0.2.0 API */
#endif
```

---

## Stable Surface (v0.1.0)

The following symbols are **frozen** as of v0.1.0.

### Error codes (`np_err_t`)
`NP_OK`, `NP_ERR_GENERIC`, `NP_ERR_NOMEM`, `NP_ERR_IO`, `NP_ERR_PROTO`,
`NP_ERR_FILTER`, `NP_ERR_TIMEOUT`, `NP_ERR_NODEV`, `NP_ERR_PERM`, `NP_ERR_EOF`

### Protocol IDs (`np_proto_t`)
`NP_PROTO_RAW`, `NP_PROTO_ETH`, `NP_PROTO_ARP`, `NP_PROTO_IP4`,
`NP_PROTO_IP6`, `NP_PROTO_ICMP`, `NP_PROTO_TCP`, `NP_PROTO_UDP`,
`NP_PROTO_DNS`, `NP_PROTO_HTTP`, `NP_PROTO_TLS`

The **integer values** of all `np_proto_t` enumerators are stable and safe to persist (e.g., in log files or databases).

### Link types (`np_linktype_t`)
`NP_LINK_UNKNOWN`, `NP_LINK_ETHERNET`, `NP_LINK_RAW`,
`NP_LINK_LOOPBACK`, `NP_LINK_LINUX_SLL`

### Packet structures
`np_str_t`, `np_http_header_t`, `np_http_msg_t`,
`np_dns_answer_t`, `np_dns_msg_t`,
`np_layer_t`, `np_packet_t`

Stable fields of `np_packet_t`:
`ts`, `caplen`, `wirelen`, `raw`, `nlayers`, `layers[]`,
`eth`, `net`, `transport`, `app`, `seq`, `flow_id`,
`stream_data`, `stream_len`, `user_data`, `reserved[]`

Fields `scratch[]` and `scratch_used` are **not stable ABI**; they are exposed purely to avoid a second heap allocation.  Do not read or write them.

### Library lifecycle
`np_init()`, `np_cleanup()`, `np_strerror()`, `np_version()`

### Pipeline
`np_pipeline_new()`, `np_pipeline_free()`,
`np_pipeline_run()`, `np_pipeline_stop()`,
`np_pipeline_add_source()`, `np_pipeline_add_filter()`,
`np_pipeline_add_processor()`, `np_pipeline_add_sink()`

### Sources
`np_source_live()`, `np_source_file()`, `np_source_ring()`, `np_source_free()`

### Filters
`np_filter_bpf()`, `np_filter_proto()`, `np_filter_port()`, `np_filter_host()`,
`np_filter_and()`, `np_filter_or()`, `np_filter_not()`, `np_filter_free()`

### Processors
`np_proc_fn` typedef, `np_processor_fn()`, `np_processor_tcp_stream()`,
`np_processor_rate_limit()`, `np_processor_payload_transform()`,
`np_processor_flow_tracker()`, `np_processor_lua()`

### Stable sinks
`np_sink_pcap()`, `np_sink_pcapng()`, `np_sink_json()`, `np_sink_hex()`,
`np_sink_stats()`, `np_sink_null()`, `np_sink_pretty()`, `np_sink_free()`

### Packet helpers
`np_packet_alloc()`, `np_packet_free()`, `np_packet_clone()`, `np_packet_ts_str()`

### Macros
`NETPIPE_VERSION_MAJOR`, `NETPIPE_VERSION_MINOR`, `NETPIPE_VERSION_PATCH`,
`NETPIPE_VERSION_STR`, `NETPIPE_VERSION_INT`, `NETPIPE_MAKE_VERSION()`,
`NP_MAX_LAYERS`, `NP_MAX_HTTP_HEADERS`, `NP_MAX_DNS_ANSWERS`

---

## Experimental Surface (`NP_EXPERIMENTAL`)

The following are available but **not stable**:

| Symbol | Reason for experimental status |
|---|---|
| `np_sink_tuntap()` | URI scheme (`tun://`, `tap://`) not yet finalized |
| `np_sink_socket()` | URI scheme (`socket://`) and framing details may change |

When these APIs are promoted to stable, `NP_EXPERIMENTAL` will be removed from their declarations and a **MINOR** version bump will be made.

---

## Internal Symbols (not part of the public API)

The following are **not** in `include/netpipe.h` and must never be called by downstream code:

- `np_packet_push_layer()` — internal demuxer helper
- `np_packet_scratch_alloc()` — internal scratch allocator
- `np_packet_print()` — internal debug printer (used by `np_sink_hex`)
- `np_packet_flow_hash()` — internal hash utility
- `np_demux_packet()` — internal protocol decoder
- Everything in `src/log/np_log.h`, `src/bufpool/np_bufpool.h`,
  `src/evloop/np_evloop.h`, `src/registry/np_registry.h`,
  `src/pipeline/np_pipeline.h`

These symbols live in internal headers under `src/` and are never installed.  Their existence, signatures, and behaviour may change at any time.

---

## Breaking Change Policy

1. Any removal or signature change to a **stable** symbol requires a `NETPIPE_VERSION_MAJOR` bump.
2. Any `NP_EXPERIMENTAL` symbol may be changed or removed in a **MINOR** or even **PATCH** release — check the CHANGELOG.
3. Changing an `np_proto_t` or `np_err_t` integer value is always a breaking change (even for experimental protocols) because downstream code may persist or compare the raw integers.
4. Adding new fields to exposed structs (`np_packet_t`, `np_layer_t`, `np_http_msg_t`, `np_dns_msg_t`) is done only by replacing one of the `reserved[]` slots; existing field offsets must never move.
