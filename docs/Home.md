# Welcome to the netpipe Wiki

`netpipe` is a high-performance, modular stream-processing engine for network traffic, written in pure C11. It allows you to compose pipelines out of ingestion sources, filtering trees, custom or built-in processors, and output routing sinks.

This wiki provides comprehensive documentation on using the command-line utility and interfacing with the `netpipe` engine via C or Python.

---

## Documentation Index

### Command-Line Interface
* **[CLI Reference](CLI-Reference)** — Guide to options, input capture modes, output formats, and CLI recipes.

### C Library API
* **[C API Overview](C-API-Overview)** — Getting started, linking requirements, pipeline lifecycle, and a complete code example.
* **[C API Components](C-API-Components)** — Details on implementing and composing Pipeline Sources, Filters, Processors, and Sinks.
* **[C API Packets & Parsing](C-API-Packets)** — Details on packet allocation, the layer stack model, and zero-copy HTTP and DNS decoding.

### Python Integration
* **[Python Integration Guide](Python-Integration)** — Running netpipe as a subprocess, NDJSON schemas, and real-time script recipes.
* **[Python Examples Reference](Python-Examples)** — Reference for all 22 python example scripts (intrusion detection, visualizations, reassembly).

---

## Quick Start (CLI)

List available network capture interfaces:
```bash
netpipe -D
```

Live capture on an interface and display annotated hex-dumps:
```bash
sudo netpipe -i eth0 -fmt hex
```

Filter DNS traffic and write output to a PCAP file:
```bash
sudo netpipe -i eth0 -proto dns -o dns_capture.pcap
```

Analyze a PCAP file offline and output structured JSON:
```bash
netpipe -r capture.pcap -fmt json
```
