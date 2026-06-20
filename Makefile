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
	$(SRCDIR)/np_registry_builtin.c \
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
	$(SRCDIR)/processor/np_lua.c \
	$(SRCDIR)/processor/np_tls_decrypt.c \
	$(SRCDIR)/demux/np_proto_extra.c

# Library sources (everything except main.c)
LIB_SRCS := $(filter-out $(SRCDIR)/main.c, $(SRCS))

OBJS     := $(patsubst %.c, $(OBJDIR)/%.o, $(SRCS))
LIB_OBJS := $(patsubst %.c, $(OBJDIR)/%.o, $(LIB_SRCS))

# ------------------------------------------------------------------ #
#  Lua Configuration                                                  #
# ------------------------------------------------------------------ #
#
# FIX (issue: link fails on Debian/Ubuntu because liblua5.4-dev
# installs liblua5.4.so, not liblua.so — so `-llua` can't find it).
#
# Detection order:
#   1. Vendored lua-5.4.7/ tree (if present) — statically linked.
#   2. pkg-config lua5.4  (Debian/Ubuntu: liblua5.4-dev provides this)
#   3. pkg-config lua     (some distros ship a generic .pc file)
#   4. Manual -llua5.4 -I/usr/include/lua5.4  (fallback if no pkg-config)
#   5. Manual -llua                            (older distros, no version suffix)

LUA_LOCAL_DIR  := $(CURDIR)/lua-5.4.7/install
LUA_STATIC_LIB := $(LUA_LOCAL_DIR)/lib/liblua.a

ifneq ($(wildcard lua-5.4.7/Makefile),)
    # Vendored Lua — static link
    LUA_CFLAGS  := -I$(LUA_LOCAL_DIR)/include
    LUA_LDFLAGS := $(LUA_STATIC_LIB) -lm -ldl
    LUA_DEP     := $(LUA_STATIC_LIB)
else ifneq ($(shell pkg-config --exists lua5.4 && echo yes),)
    # Debian/Ubuntu: liblua5.4-dev provides lua5.4.pc
    LUA_CFLAGS  := $(shell pkg-config --cflags lua5.4)
    LUA_LDFLAGS := $(shell pkg-config --libs lua5.4) -lm -ldl
    LUA_DEP     :=
else ifneq ($(shell pkg-config --exists lua && echo yes),)
    # Generic lua.pc (Arch Linux, some BSDs)
    LUA_CFLAGS  := $(shell pkg-config --cflags lua)
    LUA_LDFLAGS := $(shell pkg-config --libs lua) -lm -ldl
    LUA_DEP     :=
else ifneq ($(wildcard /usr/include/lua5.4/lua.h),)
    # Fallback: headers in /usr/include/lua5.4/, lib name liblua5.4
    LUA_CFLAGS  := -I/usr/include/lua5.4
    LUA_LDFLAGS := -llua5.4 -lm -ldl
    LUA_DEP     :=
else ifneq ($(wildcard /usr/include/lua5.3/lua.h),)
    # Fallback: Lua 5.3 headers (compatible enough for netpipe)
    LUA_CFLAGS  := -I/usr/include/lua5.3
    LUA_LDFLAGS := -llua5.3 -lm -ldl
    LUA_DEP     :=
else
    # Last resort: assume generic -llua (older distros, Homebrew, etc.)
    LUA_CFLAGS  :=
    LUA_LDFLAGS := -llua -lm -ldl
    LUA_DEP     :=
endif

# ------------------------------------------------------------------ #
#  Local prefix (optional)                                              #
#                                                                      #
#  Set LOCAL_PREFIX to a path containing include/ and lib/ subdirs     #
#  if your libpcap / libssl are not installed in the system prefix.    #
#  Example:  make LOCAL_PREFIX=/opt/local                               #
# ------------------------------------------------------------------ #

LOCAL_PREFIX ?=
ifneq ($(LOCAL_PREFIX),)
LOCAL_CFLAGS := -I$(LOCAL_PREFIX)/include
LOCAL_LDFLAGS := -L$(LOCAL_PREFIX)/lib -Wl,-rpath,$(LOCAL_PREFIX)/lib
else
LOCAL_CFLAGS :=
LOCAL_LDFLAGS :=
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
	$(LOCAL_CFLAGS) \
	-D_GNU_SOURCE \
	-D_POSIX_C_SOURCE=200809L

CFLAGS_REL  := -O2 -DNDEBUG -fstack-protector-strong
CFLAGS_DBG  := -O0 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer

LDFLAGS     := $(LOCAL_LDFLAGS) -lpcap $(LUA_LDFLAGS) -lpthread -lssl -lcrypto
LDFLAGS_DBG := $(LDFLAGS) -fsanitize=address,undefined

# ------------------------------------------------------------------ #
#  Targets                                                             #
# ------------------------------------------------------------------ #

BIN     := $(BINDIR)/netpipe
STATIC  := $(LIBDIR)/libnetpipe.a
TEST_BINS := $(BINDIR)/test_demux $(BINDIR)/test_filter $(BINDIR)/test_bufpool \
	    $(BINDIR)/test_tcp_reassembly $(BINDIR)/test_tcp_reassembly_stress \
	    $(BINDIR)/test_tls_keylog

.PHONY: all release debug clean install uninstall docs check test fuzz fuzz-libfuzzer \
	deb tarball dist package

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
	$(BINDIR)/test_tcp_reassembly
	$(BINDIR)/test_tcp_reassembly_stress
	$(BINDIR)/test_tls_keylog
	@echo "  ✓  All tests passed successfully!"

# TCP reassembly & TLS keylog tests need visibility into internal types,
# so they pull the .c file in directly.  They still link against the
# static lib for the rest of the pipeline (np_init, np_demux_packet, etc.).
$(BINDIR)/test_tcp_reassembly: tests/test_tcp_reassembly.c $(STATIC)
	@mkdir -p $(BINDIR)
	@echo "  LD  $@"
	$(CC) $(CFLAGS) -Isrc -Iinclude $< -o $@ $(STATIC) $(LFLAGS)

$(BINDIR)/test_tcp_reassembly_stress: tests/test_tcp_reassembly_stress.c $(STATIC)
	@mkdir -p $(BINDIR)
	@echo "  LD  $@"
	$(CC) $(CFLAGS) -Isrc -Iinclude $< -o $@ $(STATIC) $(LFLAGS)

$(BINDIR)/test_tls_keylog: tests/test_tls_keylog.c $(STATIC)
	@mkdir -p $(BINDIR)
	@echo "  LD  $@"
	$(CC) $(CFLAGS) -Isrc -Iinclude $< -o $@ $(STATIC) $(LFLAGS)

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
#  Packaging — .deb and source tarball                                 #
# ------------------------------------------------------------------ #

# The .deb is built by staging the install tree into a temporary DESTDIR
# and then invoking dpkg-deb.  The control file lives in packaging/deb/.
DEB_NAME    := netpipe
DEB_VERSION := 0.1.0
DEB_ARCH    := $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
DEB_PKG     := $(DEB_NAME)_$(DEB_VERSION)_$(DEB_ARCH).deb
DEB_ROOT    := $(BUILDDIR)/debroot

# Source tarball — excludes build artifacts and vendored Lua build outputs.
TAR_NAME    := $(DEB_NAME)-$(DEB_VERSION)
TARBALL     := $(TAR_NAME).tar.gz

package: deb tarball

# Build the .deb package
deb: release
	@echo "  PACK  $(DEB_PKG)"
	rm -rf $(DEB_ROOT)
	$(MAKE) install DESTDIR=$(DEB_ROOT) PREFIX=/usr
	# Install bundled Lua shared objects so netpipe runs out-of-the-box
	install -d $(DEB_ROOT)/usr/share/netpipe/lua
	install -m 644 mitigate.lua test.lua $(DEB_ROOT)/usr/share/netpipe/lua/
	install -d $(DEB_ROOT)/usr/share/doc/netpipe
	install -m 644 README.md LICENSE RELEASE_NOTES.md \
		$(DEB_ROOT)/usr/share/doc/netpipe/
	install -d $(DEB_ROOT)/DEBIAN
	install -m 644 packaging/deb/control $(DEB_ROOT)/DEBIAN/control
	install -m 755 packaging/deb/postinst $(DEB_ROOT)/DEBIAN/postinst
	install -m 755 packaging/deb/prerm    $(DEB_ROOT)/DEBIAN/prerm
	# Compute installed size for control file (in KB)
	SIZE=$$(du -sk $(DEB_ROOT)/usr | cut -f1); \
	sed -i "s/^Installed-Size:.*/Installed-Size: $$SIZE/" $(DEB_ROOT)/DEBIAN/control
	# Generate md5sums
	cd $(DEB_ROOT) && find usr -type f -exec md5sum {} \; > DEBIAN/md5sums
	dpkg-deb --build --root-owner-group $(DEB_ROOT) $(DEB_PKG)
	@echo "  ✓  $(DEB_PKG) built"
	@echo "     Install with:  sudo dpkg -i $(DEB_PKG)"
	@echo "     Inspect with:  dpkg-deb -I $(DEB_PKG)"

# Build the source tarball
tarball:
	@echo "  TAR   $(TARBALL)"
	rm -rf $(BUILDDIR)/$(TAR_NAME)
	mkdir -p $(BUILDDIR)/$(TAR_NAME)
	# Copy the source tree, excluding build artifacts and binaries
	tar --exclude='./build' \
	    --exclude='./lua-5.4.7/install' \
	    --exclude='./lua-5.4.7/src/*.o' \
	    --exclude='./lua-5.4.7/src/lua' \
	    --exclude='./lua-5.4.7/src/luac' \
	    --exclude='./lua-5.4.7/src/liblua.a' \
	    --exclude='./fuzz-out' \
	    --exclude='./.git' \
	    -cf - . | tar -xf - -C $(BUILDDIR)/$(TAR_NAME)
	tar -czf $(TARBALL) -C $(BUILDDIR) $(TAR_NAME)
	@echo "  ✓  $(TARBALL) built"
	@echo "     Extract with:  tar xzf $(TARBALL)"

# ------------------------------------------------------------------ #
#  Dependency auto-generation                                          #
# ------------------------------------------------------------------ #

-include $(OBJS:.o=.d)

$(OBJDIR)/%.d: %.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS_BASE) -MM -MT '$(OBJDIR)/$*.o' $< > $@ 2>/dev/null || true
