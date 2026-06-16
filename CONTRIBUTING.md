# Contributing to netpipe

Thank you for your interest in contributing to netpipe! To maintain code quality, performance, and reliability, please follow these guidelines when preparing contributions.

---

## 1. Development Environment Setup

These steps will set up a complete development environment and build a debug executable with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) enabled.

### Tested on Ubuntu 22.04 LTS & 24.04 LTS

Run the following commands to install dependencies, clone, and build:

```bash
# 1. Update package list and install toolchain and libpcap development headers
sudo apt update
sudo apt install -y build-essential libpcap-dev git

# 2. Clone the repository
git clone https://github.com/KalpitRathod/netpipe.git
cd netpipe

# 3. Compile a debug build with sanitizers enabled
make debug
```

The resulting executable is located at `build/bin/netpipe`.

---

## 2. Running the Test Suite

netpipe utilizes two methods of verification: functional pipeline checks and standalone unit tests.

### Functional Pipeline Check
Runs the built binary against a sample PCAP file to verify pipeline execution and hex formatting:
```bash
make check
```

### Running the Unit Test Suite
Compiles and runs the complete unit test suite (demuxer checks, filter engine checks, and buffer pool stress checks) under AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan):
```bash
make test
```

---

## 3. Code Style Rules

We enforce a strict C11 coding standard to ensure the codebase remains clean, readable, and consistent.

### Naming Conventions
* **Public API**: All public functions, structs, enums, and types must be prefixed with `np_` and use `snake_case` (e.g., `np_packet_t`, `np_pipeline_run()`).
* **Private Helper Functions**: Must be declared `static` and use `snake_case` without the `np_` prefix (e.g., `tuntap_sink_open()`).
* **Variables and Fields**: Always use `snake_case` (e.g., `pkt->stream_data`).

### Brace Placement (K&R Variation)
* **Function Definitions**: The opening brace must be on a new line.
* **Control Flow Blocks** (`if`, `for`, `while`, `switch`): The opening brace must be on the same line as the statement.

```c
/* Correct Brace Placement Example */
np_packet_t *np_packet_alloc(size_t caplen)
{
    np_packet_t *pkt = calloc(1, sizeof(*pkt));
    if (!pkt) {
        return NULL;
    }
    
    for (size_t i = 0; i < caplen; i++) {
        pkt->raw[i] = 0;
    }
    
    return pkt;
}
```

### Formatting Details
* **Maximum Line Length**: Keep all lines under 100 characters.
* **Indentation**: Use 4 spaces for indentation (no tabs).
* **Comment Style**: Use standard C comment blocks `/* comment */` or C++ style single-line comments `// comment`.
* **Section Dividers**: Separate logical divisions of files using standard header blocks:
  ```c
  /* ------------------------------------------------------------------ */
  /*  Section Name                                                      */
  /* ------------------------------------------------------------------ */
  ```

---

## 4. Pull Request Structure

To ensure efficient reviews, please structure your submissions according to these rules:

* **Scope**: One feature or bug fix per Pull Request. Do not combine unrelated changes.
* **Testing**: If you add new protocol parsers, filters, or processing engines, you must include corresponding test coverage in `test_demux.c` or add a new test file.
* **PR Description**: Your PR description must follow this structure:
  ```markdown
  ### Summary
  Brief explanation of the change and the problem it solves.

  ### Implementation Details
  List of key files modified and the design rationale.

  ### Testing Performed
  Exact commands executed to verify correct behavior.
  ```

---

## 5. Good First Issues

If you are new to the codebase, check out issues tagged `good-first-issue` on GitHub:
* Link: [netpipe Good First Issues](https://github.com/KalpitRathod/netpipe/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)

---

## 6. What We Will NOT Accept

We aim to keep netpipe lightweight, fast, and optimized for Linux network environments. We will reject contributions proposing:
* **Windows Support**: netpipe relies heavily on Linux-specific network constructs such as `epoll`, `timerfd`, and `PACKET_MMAP` ring buffers. Windows support is out of scope.
* **Alternative Scripting Languages**: Lua is the integrated scripting engine for user-defined processing. We do not accept bindings or engines for other languages (e.g., Python, JavaScript) inside the C core.
* **New External Dependencies**: To prevent dependency bloat, any new library requirement must be discussed and approved in an issue prior to submitting a PR.

---

## 7. Review Service Level Agreement (SLA)

We respect your time and efforts. The maintainers commit to responding with initial feedback or approval on all Pull Requests and Issues within **48 hours** of submission.
