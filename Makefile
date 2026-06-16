# netpipe — GNU Makefile
#
# Build:
#   make            # release build
#   make debug      # with AddressSanitizer
#   make install    # install to /usr/local
#   make clean

# ------------------------------------------------------------------ #
#  Toolchain                                                           #
# ------------------------------------------------------------------ #

CC      := gcc
AR      := ar
INSTALL := install

# ------------------------------------------------------------------ #
#  Directories                                                         #
# ------------------------------------------------------------------ #

SRCDIR   := src
INCDIR   := include
BUILDDIR := build
BINDIR   := $(BUILDDIR)/bin
LIBDIR   := $(BUILDDIR)/lib
OBJDIR   := $(BUILDDIR)/obj

PREFIX   := /usr/local
BINPATH  := $(PREFIX)/bin
INCPATH  := $(PREFIX)/include
LIBPATH  := $(PREFIX)/lib
MANPATH  := $(PREFIX)/share/man

# ------------------------------------------------------------------ #
#  Sources                                                             #
# ------------------------------------------------------------------ #

SRCS := \
	$(SRCDIR)/main.c \
	$(SRCDIR)/np_global.c \
	$(SRCDIR)/log/np_log.c \
	$(SRCDIR)/packet/np_packet.c \
	$(SRCDIR)/bufpool/np_bufpool.c \
	$(SRCDIR)/registry/np_registry.c \
	$(SRCDIR)/evloop/np_evloop.c \
	$(SRCDIR)/demux/np_demux.c \
	$(SRCDIR)/pipeline/np_pipeline.c \
	$(SRCDIR)/source/np_source_pcap.c \
	$(SRCDIR)/source/np_source_ring.c \
	$(SRCDIR)/filter/np_filter.c \
	$(SRCDIR)/sink/np_sink.c \
	$(SRCDIR)/processor/np_processor.c \
	$(SRCDIR)/processor/np_tcp_stream.c \
	$(SRCDIR)/processor/np_flow_tracker.c \
	$(SRCDIR)/processor/np_lua.c

# Library sources (everything except main.c)
LIB_SRCS := $(filter-out $(SRCDIR)/main.c, $(SRCS))

OBJS     := $(patsubst %.c, $(OBJDIR)/%.o, $(SRCS))
LIB_OBJS := $(patsubst %.c, $(OBJDIR)/%.o, $(LIB_SRCS))

# ------------------------------------------------------------------ #
#  Lua Configuration                                                  #
# ------------------------------------------------------------------ #

LUA_LOCAL_DIR  := $(CURDIR)/lua-5.4.7/install
LUA_STATIC_LIB := $(LUA_LOCAL_DIR)/lib/liblua.a

# Check if the vendored Lua source directory exists in the repo
ifneq ($(wildcard lua-5.4.7/Makefile),)
    LUA_CFLAGS  := -I$(LUA_LOCAL_DIR)/include
    LUA_LDFLAGS := $(LUA_STATIC_LIB) -lm -ldl
    LUA_DEP     := $(LUA_STATIC_LIB)
else
    LUA_CFLAGS  :=
    LUA_LDFLAGS := -llua -lm -ldl
    LUA_DEP     :=
endif

# ------------------------------------------------------------------ #
#  Flags                                                               #
# ------------------------------------------------------------------ #

CFLAGS_BASE := \
	-std=c11 \
	-Wall -Wextra -Wpedantic \
	-Wformat=2 -Wformat-security \
	-Wshadow -Wconversion \
	-Wno-format-truncation \
	-I$(INCDIR) \
	$(LUA_CFLAGS) \
	-D_GNU_SOURCE \
	-D_POSIX_C_SOURCE=200809L

CFLAGS_REL  := -O2 -DNDEBUG -fstack-protector-strong
CFLAGS_DBG  := -O0 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer

LDFLAGS     := -lpcap $(LUA_LDFLAGS) -lpthread
LDFLAGS_DBG := $(LDFLAGS) -fsanitize=address,undefined

# ------------------------------------------------------------------ #
#  Targets                                                             #
# ------------------------------------------------------------------ #

BIN     := $(BINDIR)/netpipe
STATIC  := $(LIBDIR)/libnetpipe.a
TEST_BINS := $(BINDIR)/test_demux $(BINDIR)/test_filter $(BINDIR)/test_bufpool

.PHONY: all release debug clean install uninstall docs check test fuzz fuzz-libfuzzer

all: release

release: CFLAGS = $(CFLAGS_BASE) $(CFLAGS_REL)
release: LFLAGS = $(LDFLAGS)
release: $(BIN) $(STATIC)
	@echo "  ✓  netpipe built  →  $(BIN)"

debug: CFLAGS = $(CFLAGS_BASE) $(CFLAGS_DBG)
debug: LFLAGS = $(LDFLAGS_DBG)
debug: $(BIN) $(STATIC)
	@echo "  ✓  netpipe debug build  →  $(BIN)"

test: CFLAGS = $(CFLAGS_BASE) $(CFLAGS_DBG)
test: LFLAGS = $(LDFLAGS_DBG)
test: debug $(TEST_BINS)
	@echo "Running test suite..."
	$(BINDIR)/test_demux
	$(BINDIR)/test_filter
	$(BINDIR)/test_bufpool
	@echo "  ✓  All tests passed successfully!"

$(BINDIR)/test_%: tests/test_%.c $(STATIC)
	@mkdir -p $(BINDIR)
	@echo "  LD  $@"
	$(CC) $(CFLAGS) -Isrc $< -o $@ $(STATIC) $(LFLAGS)

# ------------------------------------------------------------------ #
#  Fuzzing                                                             #
#                                                                      #
#  AFL++ (preferred for long runs):                                    #
#    CC=afl-clang-fast make fuzz                                       #
#    afl-fuzz -i tests/fixtures/ -o fuzz-out/ -- ./build/bin/fuzz_demux #
#                                                                      #
#  Standalone stdin / CI regression (no fuzzer required):             #
#    make fuzz                                                          #
#    ./build/bin/fuzz_demux < tests/fixtures/ipv4_tcp_http.pcap        #
#                                                                      #
#  libFuzzer (clang only):                                             #
#    make fuzz-libfuzzer                                               #
#    ./build/bin/fuzz_demux_libfuzzer tests/fixtures/                  #
# ------------------------------------------------------------------ #

FUZZ_BIN := $(BINDIR)/fuzz_demux

# Detect whether we have AFL++ instrumentation available.
# afl-clang-fast defines __AFL_HAVE_MANUAL_CONTROL; plain gcc does not.
FUZZ_CC   := $(CC)
FUZZ_CFLAGS := $(CFLAGS_BASE) -O1 -g \
	-fsanitize=address,undefined \
	-fno-omit-frame-pointer \
	-Isrc

fuzz: $(STATIC)
	@mkdir -p $(BINDIR) fuzz-out
	@echo "  LD  $(FUZZ_BIN)"
	$(FUZZ_CC) $(FUZZ_CFLAGS) tests/fuzz_demux.c \
		-o $(FUZZ_BIN) $(STATIC) $(LDFLAGS) -fsanitize=address,undefined
	@echo "  ✓  fuzz harness built → $(FUZZ_BIN)"
	@echo "  Run: afl-fuzz -i tests/fixtures/ -o fuzz-out/ -- $(FUZZ_BIN)"
	@echo "  Or:  $(FUZZ_BIN) < tests/fixtures/ipv4_tcp_http.pcap"

fuzz-libfuzzer: $(STATIC)
	@mkdir -p $(BINDIR) fuzz-out
	@echo "  LD  $(BINDIR)/fuzz_demux_libfuzzer  (libFuzzer)"
	clang $(FUZZ_CFLAGS) -DLIBFUZZER -fsanitize=fuzzer \
		tests/fuzz_demux.c \
		-o $(BINDIR)/fuzz_demux_libfuzzer \
		$(STATIC) $(LDFLAGS)
	@echo "  ✓  libFuzzer harness built → $(BINDIR)/fuzz_demux_libfuzzer"
	@echo "  Run: $(BINDIR)/fuzz_demux_libfuzzer tests/fixtures/"

# ------------------------------------------------------------------ #
#  Compilation rules                                                   #
# ------------------------------------------------------------------ #

$(OBJDIR)/%.o: %.c | $(LUA_DEP)
	@mkdir -p $(dir $@)
	@echo "  CC  $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(LUA_STATIC_LIB):
	@echo "  Building local Lua dependency..."
	$(MAKE) -C lua-5.4.7 linux install INSTALL_TOP=$(LUA_LOCAL_DIR)

# ------------------------------------------------------------------ #
#  Link                                                                #
# ------------------------------------------------------------------ #

$(BIN): $(OBJS)
	@mkdir -p $(BINDIR)
	@echo "  LD  $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

$(STATIC): $(LIB_OBJS)
	@mkdir -p $(LIBDIR)
	@echo "  AR  $@"
	$(AR) rcs $@ $^

# ------------------------------------------------------------------ #
#  Install / Uninstall                                                 #
# ------------------------------------------------------------------ #

install: release
	$(INSTALL) -d $(DESTDIR)$(BINPATH) $(DESTDIR)$(INCPATH) $(DESTDIR)$(LIBPATH)
	$(INSTALL) -m 755 $(BIN)    $(DESTDIR)$(BINPATH)/netpipe
	$(INSTALL) -m 644 $(STATIC) $(DESTDIR)$(LIBPATH)/libnetpipe.a
	$(INSTALL) -m 644 $(INCDIR)/netpipe.h $(DESTDIR)$(INCPATH)/netpipe.h
	$(INSTALL) -d $(DESTDIR)$(MANPATH)/man1 $(DESTDIR)$(MANPATH)/man3 $(DESTDIR)$(MANPATH)/man7
	$(INSTALL) -m 644 man/man1/netpipe.1 $(DESTDIR)$(MANPATH)/man1/netpipe.1
	$(INSTALL) -m 644 man/man3/libnetpipe.3 $(DESTDIR)$(MANPATH)/man3/libnetpipe.3
	$(INSTALL) -m 644 man/man3/np_pipeline.3 $(DESTDIR)$(MANPATH)/man3/np_pipeline.3
	$(INSTALL) -m 644 man/man3/np_source.3 $(DESTDIR)$(MANPATH)/man3/np_source.3
	$(INSTALL) -m 644 man/man3/np_filter.3 $(DESTDIR)$(MANPATH)/man3/np_filter.3
	$(INSTALL) -m 644 man/man3/np_processor.3 $(DESTDIR)$(MANPATH)/man3/np_processor.3
	$(INSTALL) -m 644 man/man3/np_sink.3 $(DESTDIR)$(MANPATH)/man3/np_sink.3
	$(INSTALL) -m 644 man/man3/np_packet.3 $(DESTDIR)$(MANPATH)/man3/np_packet.3
	$(INSTALL) -m 644 man/man7/netpipe-python.7 $(DESTDIR)$(MANPATH)/man7/netpipe-python.7
	@echo "  ✓  installed to $(PREFIX)"

uninstall:
	rm -f $(DESTDIR)$(BINPATH)/netpipe
	rm -f $(DESTDIR)$(LIBPATH)/libnetpipe.a
	rm -f $(DESTDIR)$(INCPATH)/netpipe.h
	rm -f $(DESTDIR)$(MANPATH)/man1/netpipe.1
	rm -f $(DESTDIR)$(MANPATH)/man3/libnetpipe.3
	rm -f $(DESTDIR)$(MANPATH)/man3/np_pipeline.3
	rm -f $(DESTDIR)$(MANPATH)/man3/np_source.3
	rm -f $(DESTDIR)$(MANPATH)/man3/np_filter.3
	rm -f $(DESTDIR)$(MANPATH)/man3/np_processor.3
	rm -f $(DESTDIR)$(MANPATH)/man3/np_sink.3
	rm -f $(DESTDIR)$(MANPATH)/man3/np_packet.3
	rm -f $(DESTDIR)$(MANPATH)/man7/netpipe-python.7

# ------------------------------------------------------------------ #
#  Clean                                                               #
# ------------------------------------------------------------------ #

clean:
	rm -rf $(BUILDDIR)
	@if [ -d lua-5.4.7 ]; then \
		$(MAKE) -C lua-5.4.7 clean >/dev/null 2>&1 || true; \
		rm -rf lua-5.4.7/install; \
	fi
	@echo "  cleaned"

# ------------------------------------------------------------------ #
#  Quick sanity check (runs on a test pcap if present)                 #
# ------------------------------------------------------------------ #

check: release
	@if [ -f test/sample.pcap ]; then \
		echo "  Running on test/sample.pcap ..."; \
		$(BIN) -r test/sample.pcap -fmt hex 2>/dev/null | head -30; \
	else \
		echo "  No test/sample.pcap found — skipping functional test."; \
	fi

# ------------------------------------------------------------------ #
#  Dependency auto-generation                                          #
# ------------------------------------------------------------------ #

-include $(OBJS:.o=.d)

$(OBJDIR)/%.d: %.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS_BASE) -MM -MT '$(OBJDIR)/$*.o' $< > $@ 2>/dev/null || true
