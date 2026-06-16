# C API Overview

The `libnetpipe` C library allows embedding the stream-processing engine in downstream C and C++ applications.

---

## Compilation and Linking

To compile applications using `libnetpipe`, link against the compiled static library `libnetpipe.a` and its standard system dependencies:

```bash
gcc myapp.c -I/usr/local/include -L/usr/local/lib -lnetpipe -lpcap -lpthread -ldl -lm -o myapp
```

---

## Library Lifecycle

The library must be initialized before calling any processing functions and cleaned up before termination.

```c
#include <netpipe.h>

// Initialize library context
np_err_t np_init(void);

// Clean up library resources
void np_cleanup(void);

// Convert np_err_t status codes into English strings
const char *np_strerror(np_err_t err);
```

---

## Pipeline Management

A pipeline (`np_pipeline_t`) coordinates the execution. You instantiate a pipeline context, add components to it, run it, and free it.

```c
// Instantiate an empty pipeline
np_pipeline_t *np_pipeline_new(void);

// Attach ingestion sources, filters, processors, and sinks
np_err_t np_pipeline_add_source(np_pipeline_t *pl, np_source_t *src);
np_err_t np_pipeline_add_filter(np_pipeline_t *pl, np_filter_t *f);
np_err_t np_pipeline_add_processor(np_pipeline_t *pl, np_processor_t *proc);
np_err_t np_pipeline_add_sink(np_pipeline_t *pl, np_sink_t *s);

// Start packet processing (blocking call)
np_err_t np_pipeline_run(np_pipeline_t *pl);

// Stop execution (thread-safe, can be called from signal handlers)
void np_pipeline_stop(np_pipeline_t *pl);

// Stop execution and release all pipeline components
void np_pipeline_free(np_pipeline_t *pl);
```

> [!NOTE]
> Once a source, filter, processor, or sink is successfully added to a pipeline, it is owned by the pipeline. The caller must not free it manually; `np_pipeline_free()` will release all components.

---

## Code Example

Below is a complete program that builds a pipeline to capture live traffic, filters for HTTP (port 80) frames, and logs them to a PCAP file:

```c
#include <netpipe.h>
#include <stdio.h>
#include <signal.h>

static np_pipeline_t *pipeline = NULL;

void handle_sigint(int sig) {
    (void)sig;
    if (pipeline) {
        np_pipeline_stop(pipeline);
    }
}

int main(void) {
    // 1. Initialize Library
    if (np_init() != NP_OK) {
        fprintf(stderr, "Initialization failed\n");
        return 1;
    }

    // Register Ctrl-C handler
    signal(SIGINT, handle_sigint);

    // 2. Create Pipeline
    pipeline = np_pipeline_new();
    if (!pipeline) {
        fprintf(stderr, "Failed to create pipeline\n");
        np_cleanup();
        return 1;
    }

    // 3. Add Live Source (promiscuous, 1000ms timeout)
    np_source_t *src = np_source_live("eth0", 65535, 1, 1000);
    np_pipeline_add_source(pipeline, src);

    // 4. Add Filter (only TCP port 80)
    np_filter_t *flt = np_filter_port(80);
    np_pipeline_add_filter(pipeline, flt);

    // 5. Add Sink (write to output file)
    np_sink_t *snk = np_sink_pcap("http_traffic.pcap");
    np_pipeline_add_sink(pipeline, snk);

    // 6. Run the Pipeline
    printf("Capturing traffic... Press Ctrl-C to stop.\n");
    np_err_t err = np_pipeline_run(pipeline);
    if (err != NP_OK) {
        fprintf(stderr, "Pipeline error: %s\n", np_strerror(err));
    }

    // 7. Cleanup Resources
    np_pipeline_free(pipeline);
    np_cleanup();
    return 0;
}
```
