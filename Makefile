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

# ------------------------------------------------------------------ #
#  Sources                                                             #
# ------------------------------------------------------------------ #

SRCS := \
	$(SRCDIR)/main.c \
	$(SRCDIR)/np_global.c \
	$(SRCDIR)/log/np_log.c \
	$(SRCDIR)/packet/np_packet.c \
	$(SRCDIR)/demux/np_demux.c \
	$(SRCDIR)/pipeline/np_pipeline.c \
	$(SRCDIR)/source/np_source_pcap.c \
	$(SRCDIR)/filter/np_filter.c \
	$(SRCDIR)/sink/np_sink.c \
	$(SRCDIR)/processor/np_processor.c

# Library sources (everything except main.c)
LIB_SRCS := $(filter-out $(SRCDIR)/main.c, $(SRCS))

OBJS     := $(patsubst %.c, $(OBJDIR)/%.o, $(SRCS))
LIB_OBJS := $(patsubst %.c, $(OBJDIR)/%.o, $(LIB_SRCS))

# ------------------------------------------------------------------ #
#  Flags                                                               #
# ------------------------------------------------------------------ #

CFLAGS_BASE := \
	-std=c11 \
	-Wall -Wextra -Wpedantic \
	-Wformat=2 -Wformat-security \
	-Wshadow -Wconversion \
	-I$(INCDIR) \
	-D_GNU_SOURCE \
	-D_POSIX_C_SOURCE=200809L

CFLAGS_REL  := -O2 -DNDEBUG -fstack-protector-strong
CFLAGS_DBG  := -O0 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer

LDFLAGS     := -lpcap -lpthread
LDFLAGS_DBG := $(LDFLAGS) -fsanitize=address,undefined

# ------------------------------------------------------------------ #
#  Targets                                                             #
# ------------------------------------------------------------------ #

BIN     := $(BINDIR)/netpipe
STATIC  := $(LIBDIR)/libnetpipe.a

.PHONY: all release debug clean install uninstall docs check

all: release

release: CFLAGS = $(CFLAGS_BASE) $(CFLAGS_REL)
release: LFLAGS = $(LDFLAGS)
release: $(BIN) $(STATIC)
	@echo "  ✓  netpipe built  →  $(BIN)"

debug: CFLAGS = $(CFLAGS_BASE) $(CFLAGS_DBG)
debug: LFLAGS = $(LDFLAGS_DBG)
debug: $(BIN) $(STATIC)
	@echo "  ✓  netpipe debug build  →  $(BIN)"

# ------------------------------------------------------------------ #
#  Compilation rules                                                   #
# ------------------------------------------------------------------ #

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	@echo "  CC  $<"
	$(CC) $(CFLAGS) -c $< -o $@

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
	@echo "  ✓  installed to $(PREFIX)"

uninstall:
	rm -f $(DESTDIR)$(BINPATH)/netpipe
	rm -f $(DESTDIR)$(LIBPATH)/libnetpipe.a
	rm -f $(DESTDIR)$(INCPATH)/netpipe.h

# ------------------------------------------------------------------ #
#  Clean                                                               #
# ------------------------------------------------------------------ #

clean:
	rm -rf $(BUILDDIR)
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
