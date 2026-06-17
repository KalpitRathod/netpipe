# C API Packets & Parsing

Every packet moving through the pipeline is represented as an `np_packet_t` object. This structure contains physical packet lengths, timestamps, convenience layer offsets, and optional reassembled TCP payload or zero-copy decoded structures.

---

## Packet Allocations

If you need to manually generate or clone packets, the library provides standard lifecycle APIs:

```c
// Allocate a packet structure with raw capture space up to caplen
np_packet_t *np_packet_alloc(size_t caplen);

// Make a deep clone of a packet
np_packet_t *np_packet_clone(const np_packet_t *src);

// Free packet allocation and all associated data (passing NULL is safe)
void np_packet_free(np_packet_t *pkt);

// Format the packet timestamp as "HH:MM:SS.uuuuuu" into buf (bufsz >= 16)
void np_packet_ts_str(const np_packet_t *pkt, char *buf, size_t bufsz);
```

---

## Data Structures

### The Packet Object (`np_packet_t`)

```c
typedef struct np_packet {
    struct timespec  ts;            /* Time of arrival */
    uint32_t         caplen;        /* Length captured in raw buffer */
    uint32_t         wirelen;       /* Real length of frame on wire */

    uint8_t         *raw;           /* Raw captured frame bytes */

    int              nlayers;       /* Active layer count */
    np_layer_t       layers[8];     /* Array of all parsed layers */

    /* Convenience pointers into the layers[] array (NULL if not parsed) */
    const np_layer_t *eth;          /* Link layer (Ethernet / Linux Cooked SLL) */
    const np_layer_t *net;          /* Network layer (IPv4 / IPv6 / ARP) */
    const np_layer_t *transport;    /* Transport layer (TCP / UDP / ICMP) */
    const np_layer_t *app;          /* Application layer (HTTP / DNS / TLS) */

    uint64_t         seq;           /* Packet capture sequence number */
    uint32_t         flow_id;       /* 5-tuple flow hash signature */

    /* TCP reassembled stream data (populated by np_processor_tcp_stream) */
    uint8_t         *stream_data;   /* Continuous stream buffer */
    size_t           stream_len;    /* Stream buffer length */

    void            *user_data;    /* Caller-owned context; not touched by library */
} np_packet_t;
```

### The Layer Object (`np_layer_t`)

```c
typedef struct np_layer {
    np_proto_t     proto;    /* Protocol ID enum */
    const uint8_t *data;     /* Pointer to the start of this layer in 'raw' */
    size_t         len;      /* Length of the layer header + payload */
    void          *decoded;  /* Decoded structure (e.g. np_http_msg_t) */
} np_layer_t;
```

### The Protocol Enum (`np_proto_t`)

```c
typedef enum {
    NP_PROTO_RAW      = 0x0000,
    NP_PROTO_ETH      = 0x0001,
    NP_PROTO_ARP      = 0x0806,
    NP_PROTO_IP4      = 0x0800,
    NP_PROTO_IP6      = 0x86DD,
    NP_PROTO_ICMP     = 0x0001FF,
    NP_PROTO_TCP      = 0x000006,
    NP_PROTO_UDP      = 0x000011,
    NP_PROTO_DNS      = 0x010001,
    NP_PROTO_HTTP     = 0x020001,
    NP_PROTO_TLS      = 0x020002,
} np_proto_t;
```

---


## Zero-Copy Strings (`np_str_t`)

All string fields inside decoded protocol structures use `np_str_t`:

```c
typedef struct {
    const char *str;  /* NOT NUL-terminated — always use .len */
    size_t      len;
} np_str_t;
```

The pointer is valid only for the lifetime of the `np_packet_t` it came from.
Never NUL-terminate it yourself; the underlying byte may be part of a protocol header.

## Zero-Copy Decoded Structures

For high-level protocols (DNS and HTTP), the built-in demuxer builds parsed C structs directly in packet-scoped scratch memory. To maximize speed, string properties do not allocate memory on the heap. Instead, they use `np_str_t`, which contains a pointer back into the raw packet data and a length.



### Decoded HTTP Message (`np_http_msg_t`)
Access this via `pkt->app->decoded` if `pkt->app->proto == NP_PROTO_HTTP`:

```c
typedef struct {
    bool is_request;                /* true for request, false for response */
    
    /* Request fields */
    np_str_t method;                /* e.g., "GET" */
    np_str_t path;                  /* e.g., "/index.html" */
    np_str_t version;               /* e.g., "HTTP/1.1" */
    
    /* Response fields */
    int      status_code;           /* e.g., 200 */
    np_str_t status_phrase;         /* e.g., "OK" */
    
    int              num_headers;
    np_http_header_t headers[32];   /* List of header names & values */
    
    const uint8_t   *body;          /* Pointer to message body */
    size_t           body_len;      /* Length of body */
} np_http_msg_t;
```

### Decoded DNS Message (`np_dns_msg_t`)
Access this via `pkt->app->decoded` if `pkt->app->proto == NP_PROTO_DNS`:

```c
typedef struct {
    uint16_t id;                    /* DNS query ID */
    bool     is_response;           /* true for response, false for query */
    int      rcode;                 /* Response status (e.g. 0 = NOERROR) */
    
    char     query_name[256];       /* Unrolled query name string */
    uint16_t query_type;            /* Query type (A, AAAA, CNAME) */
    
    int              num_answers;
    np_dns_answer_t  answers[8];    /* Array of answer record structs */
} np_dns_msg_t;
```
Each answers array entry contains:
```c
typedef struct {
    char     name[256];             /* Resource domain name */
    uint16_t type;                  /* Record type code */
    uint16_t class_;                /* Class (typically 1 = IN) */
    uint32_t ttl;                   /* Time-To-Live */
    uint16_t data_len;              /* Data length */
    char     rdata_str[256];        /* String representation (IP address or target CNAME) */
} np_dns_answer_t;
```
