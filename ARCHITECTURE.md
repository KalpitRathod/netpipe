# netpipe Architecture Reference

This document provides a detailed overview of the netpipe system architecture, covering its core design principles, data flow, memory management, and execution model.

---

## 1. Packet Buffer Pool (`np_bufpool_t`)

### Description
netpipe uses a zero-allocation buffer pool system to eliminate runtime heap allocation overhead during high-speed packet capture. The pool pre-allocates a contiguous memory slab of buffer structures (`np_buf_t`) and raw data storage blocks during initialization.

### Data Flow & Lifecycle Diagram
```
   [Contiguous Memory Slab]
   ┌─────────────────────────────────────────────────────────┐
   │ [np_buf_t #1 + Storage] -> [np_buf_t #2 + Storage] ...  │
   └───────────┬─────────────────────────────────────────────┘
               │ (Thread onto free-list)
               ▼
        [Pool Free List] ◄──────────────────────────────┐
               │                                        │
          (np_buf_alloc)                           (np_buf_unref)
               │                                        │
               ▼                                        │
        [np_buf_t (Ref=1)] ────(np_buf_ref)───┐         │
               │                              ▼         │
               │                       [np_buf_t (Ref=2)]
               │                              │         │
               │                           (unref)      │
               │                              ▼         │
               └───────────────────────> [np_buf_t (Ref=1)]
                                              │
                                           (unref)
                                              │
                                              ▼
                                       [Refcount == 0]
                                              │
                                       (Return to Pool)
```

### Invariants & Safety Boundaries
1. **Contiguous Allocation**: The memory slab for the pool is allocated in a single call to `malloc()`. Buffers must never be individually freed using `free()` if they are part of the slab.
2. **Reference Counting Safety**: Access to `buf->refcount` must always be synchronized using the buffer-specific `buf->reflock` mutex.
3. **Fallback Allocation (Pool Miss)**: If the pool is exhausted (`free_list == NULL`) or the requested buffer size exceeds the pool's capacity, `np_buf_alloc` falls back to a standard `malloc`. The buffer remembers its source; when its reference count drops to 0, it is freed via `free()` instead of being returned to the pool.
4. **Violation Consequences**: Violating reference counting guarantees will result in memory leaks (buffers never returning to the pool) or double-returns/use-after-free corruption (returning a buffer still in use back to the free list).

---

## 2. Event Loop (`np_evloop_t`)

### Description
The event loop abstracts I/O multiplexing and asynchronous event dispatching. It is built on top of Linux `epoll(7)` and uses `timerfd` and `eventfd` to manage network input, timers, and inter-thread notifications.

### Event Dispatch Diagram
```
                          ┌────────────────────────┐
                          │    epoll_wait() Loop   │
                          └───────────┬────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         ▼                            ▼                            ▼
   [Network FDs]                 [Timer FDs]                [Wake eventfd]
 (Read/Write events)       (timerfd_create clock)         (np_evloop_stop)
         │                            │                            │
         ▼                            ▼                            ▼
   Read Callback                Timer Dispatch              Set running=false
(e.g., capture read)          (Drain fd, run cb)            (Break epoll_wait)
```

### Invariants & Safety Boundaries
1. **O(1) Callback Lookup**: The loop maintains a flat array of entries (`entries`) indexed directly by file descriptor number. This ensures O(1) callback dispatch.
2. **Direct Mapping Guarantee**: Before registering an fd with `epoll`, `entries_ensure()` must be called to resize the callback array if `fd >= entries_cap`.
3. **Interruptibility**: The `wakefd` (an `eventfd`) is registered with the epoll set at startup. When `np_evloop_stop` is called, it writes to `wakefd` to instantly wake up the thread blocked in `epoll_wait()`.
4. **Violation Consequences**: Closing a file descriptor without calling `np_evloop_del` leaves a stale entry in the `entries` array. If a new file descriptor is subsequently created with the same number, it will inherit the old callback and context, causing silent corruption or crashes.

---

## 3. Plugin Self-Registration

### Description
To prevent monolithic if-else blocks or hardcoded lists of modules in `main.c`, netpipe uses GCC constructor attributes (`__attribute__((constructor))`) to achieve decentralized module registration.

### Registration flow
```
  [Source/Sink/Filter C File]
              │
     (Defines static desc)
              │
              ▼
   NP_REGISTER_* Macro
              │
    (Linker places pointer in)
              │
              ▼
        .init_array
              │
      (Runs before main())
              │
              ▼
     np_registry_add_*()  ───> [Global Registry Lists (g_reg)]
```

### Invariants & Safety Boundaries
1. **Static Constructor Execution**: Registry lists are populated during binary initialization (before `main()` starts) when the dynamic linker processes the `.init_array` section.
2. **Thread Safety During Registration**: Because constructor registration happens sequentially on the main thread before any user threads are spawned, registry inserts do not contend. However, a mutex protects registry structures for future compatibility (e.g., dynamically loading plugins via `dlopen`).
3. **Name Uniqueness**: Names of registered sinks, sources, and filters must be unique.
4. **Violation Consequences**: If constructors fail to run (e.g., when compiling with flags that omit constructor execution or wrapping modules in static archives without `--whole-archive`), plugins will be missing from the registry, causing CLI resolution to fail.

---

## 4. Pipeline Orchestration

### Description
The pipeline coordinates packet capture threads, decodes packets, executes the filter chain, runs packet processors, and forwards packets to output sinks.

### Pipeline Data Flow
```
   [Worker Thread 1] ────> [queue_push] ───┐
                                           ▼
   [Worker Thread 2] ────> [queue_push] ───┼─> [pkt_queue_t] ─> [queue_pop] (Main Thread)
                                           ▲                       │
   [Worker Thread N] ────> [queue_push] ───┘                       ▼
                                                            np_demux_packet()
                                                                   │
                                                                   ▼
                                                            Filter Evaluation
                                                                   │
                                                                   ▼
                                                            Processor Chain
                                                                   │
                                                                   ▼
                                                             Sinks (Outputs)
```

### Invariants & Safety Boundaries
1. **Thread Separation**: Packet sniffing is delegated to worker threads (one per source). Packet decoding, filtering, processing, and writing are executed sequentially on the main thread to avoid complex synchronization over data pipelines.
2. **Thread-Safe Queue Bounds**: The connection between worker threads and the main thread is a thread-safe synchronized queue (`pkt_queue_t`). If the queue size exceeds `MAX_QUEUE_SIZE` (10,000 packets), incoming packets are dropped to prevent memory exhaustion under heavy load.
3. **Strict Sequencing**: A packet must pass all registered filters and processors in order. If a filter fails or a processor errors, the packet is freed and skipped.
4. **Violation Consequences**: Allowing multiple threads to call `np_demux_packet` or write to the same sink without synchronization would trigger data races and packet corruption.

---

## 5. Incremental Demuxer

### Description
The demuxer transforms a raw packet capture frame into a structured, queryable layer stack representation (`np_packet_t`) containing Ethernet, Network, Transport, and Application layers.

### Layer Stack Diagram
```
  [Raw Packet Bytes]
  ┌────────────────────────────────────────────────────────────┐
  │ Ethernet Hdr │ IP Header │ TCP Header │   HTTP Payload     │
  └──────┬───────┴─────┬─────┴─────┬──────┴────────┬───────────┘
         │             │           │               │
         ▼             ▼           ▼               ▼
     layers[0]     layers[1]   layers[2]       layers[3]
     (.eth)        (.net)      (.transport)    (.app)
```

### Invariants & Safety Boundaries
1. **Stack Limits**: The layers stack size is fixed at `NP_MAX_LAYERS` (8). If a packet contains more protocol layers than this limit, the remaining layers are skipped.
2. **Scratch Space Ownership**: Deeply parsed application payloads (like `np_dns_msg_t` and `np_http_msg_t`) are stored inside a static pre-allocated packet `scratch` buffer (`8192` bytes). Pointers inside dynamic structures point directly into this buffer, which is freed when the packet itself is freed.
3. **Violation Consequences**: Returning pointers from `scratch` after a packet has been freed leads to use-after-free bugs. If the scratch size limit is exceeded during parsing without validation, memory corruption occurs.

---

## 6. Filter Chain

### Description
The filter chain evaluates boolean match expressions to filter traffic. It includes atomic filters (matching port, host, protocol, BPF expressions) and logical combinators (AND, OR, NOT).

### Composite Evaluation Tree Example
```
                     [AND Filter]
                    /            \
            [OR Filter]        [NOT Filter]
           /           \             │
     [Port=80]   [Host=1.1.1.1]  [Proto=ARP]
```

### Invariants & Safety Boundaries
1. **Short-Circuit Evaluation**: Combinators must evaluate their child nodes sequentially. For example, `and_match` evaluates `a` first; if it returns `false`, `b` is never evaluated.
2. **Memory Ownership**: Parent combinators (like `AND`, `OR`, `NOT`) own their child filters. Freeing a parent filter recursively frees all nested child filters.
3. **Violation Consequences**: Incorrect tree cleanup will lead to memory leaks or double-frees when disposing of composite filter structures.
