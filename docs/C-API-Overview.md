# C API Overview

The `libnetpipe` C library lets you embed the stream-processing engine in downstream C or C++ applications.

---

## Stable vs Experimental API

Everything in `<netpipe.h>` that is **not** marked `NP_EXPERIMENTAL` is part of the **stable API**: names, signatures, and semantics will not change without bumping `NETPIPE_VERSION_MAJOR`.

`NP_EXPERIMENTAL` symbols (currently `np_sink_tuntap()` and `np_sink_socket()`) are available for use but may change in any release, including patch releases.  Do not depend on them in production code without accepting that risk.

---

## Version Detection

Two mechanisms are available:

**Compile-time** (against the headers you compiled with):
```c
#include <netpipe.h>

#if NETPIPE_VERSION_INT >= NETPIPE_MAKE_VERSION(0, 2, 0)
    /* use an API added in 0.2.0 */
#endif
```

**Runtime** (the library that was actually linked):
```c
int maj, min, patch;
np_version(&maj, &min, &patch);
printf("libnetpipe %d.%d.%d\n", maj, min, patch);
```

Use `np_version()` whenever the library may have been updated independently of your application.

---

## Compilation and Linking

```bash
gcc myapp.c -I/usr/local/include -L/usr/local/lib -lnetpipe -lpcap -lpthread -ldl -lm -o myapp
```

---

## Library Lifecycle

```c
#include <netpipe.h>

np_err_t np_init(void);      /* call once before anything else    */
void     np_cleanup(void);   /* call once when completely done    */

const char *np_strerror(np_err_t err);   /* error code → string   */
void  np_version(int *major, int *minor, int *patch);
```

---

## Pipeline Management

```c
np_pipeline_t *np_pipeline_new(void);

np_err_t np_pipeline_add_source   (np_pipeline_t *pl, np_source_t    *src);
np_err_t np_pipeline_add_filter   (np_pipeline_t *pl, np_filter_t    *f);
np_err_t np_pipeline_add_processor(np_pipeline_t *pl, np_processor_t *proc);
np_err_t np_pipeline_add_sink     (np_pipeline_t *pl, np_sink_t      *s);

np_err_t np_pipeline_run (np_pipeline_t *pl);   /* blocking           */
void     np_pipeline_stop(np_pipeline_t *pl);   /* thread-safe        */
void     np_pipeline_free(np_pipeline_t *pl);   /* frees all components */
```

> **Ownership rule**: once a component is successfully added to a pipeline, the pipeline owns it.  Do **not** free it manually; `np_pipeline_free()` will release everything.

---

## Code Example

```c
#include <netpipe.h>
#include <stdio.h>
#include <signal.h>

static np_pipeline_t *g_pl;
static void on_sigint(int s) { (void)s; np_pipeline_stop(g_pl); }

int main(void) {
    if (np_init() != NP_OK) {
        fprintf(stderr, "np_init failed\n");
        return 1;
    }

    signal(SIGINT, on_sigint);

    g_pl = np_pipeline_new();

    /* 1. Source: live capture on eth0 */
    np_pipeline_add_source(g_pl, np_source_live("eth0", 65535, 1, 1000));

    /* 2. Filter: only TCP port 80 */
    np_pipeline_add_filter(g_pl, np_filter_port(80));

    /* 3. Sink: write a PCAP file */
    np_pipeline_add_sink(g_pl, np_sink_pcap("http_traffic.pcap"));

    printf("Capturing HTTP on eth0 — Ctrl-C to stop.\n");
    np_err_t err = np_pipeline_run(g_pl);
    if (err != NP_OK)
        fprintf(stderr, "error: %s\n", np_strerror(err));

    np_pipeline_free(g_pl);
    np_cleanup();
    return 0;
}
```
