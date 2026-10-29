#
# aflnet-pp - AFLNet network protocol test tools
# ----------------------------------------------
#
# Standalone replayers ported from the original AFLNet repository:
#
#   aflnet-replay  replay a structured (length-prefixed) test case
#   afl-replay     replay a raw (concatenated) test case
#
# Both link ../../src/aflnet/protocols.c, i.e. the exact same protocol
# request/response parsers the fuzzer uses, so they never drift apart.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

PREFIX      ?= /usr/local
BIN_PATH     = $(PREFIX)/bin
DOC_PATH     = $(PREFIX)/share/doc/afl

SYS = $(shell uname -s)

PROGRAMS = aflnet-replay afl-replay

# The protocol extractors are shared with the fuzzer.
AFLNET_PROTOCOLS = ../../src/aflnet/protocols.c
AFLNET_INCLUDES  = -I../../include -I../../src/aflnet

CFLAGS  += -O2 -g -Wall -Wno-pointer-sign -D_GNU_SOURCE
LDFLAGS +=

ifdef STATIC
  CFLAGS  += -static
endif

ifeq "$(SYS)" "SunOS"
  LDFLAGS += -lnsl -lsocket
endif

.PHONY: all clean install

all: $(PROGRAMS)

aflnet-replay: aflnet-replay.c replay-net.c replay-net.h $(AFLNET_PROTOCOLS)
	$(CC) $(CFLAGS) $(AFLNET_INCLUDES) -o $@ aflnet-replay.c replay-net.c \
	    $(AFLNET_PROTOCOLS) $(LDFLAGS)

afl-replay: afl-replay.c replay-net.c replay-net.h $(AFLNET_PROTOCOLS)
	$(CC) $(CFLAGS) $(AFLNET_INCLUDES) -o $@ afl-replay.c replay-net.c \
	    $(AFLNET_PROTOCOLS) $(LDFLAGS)

clean:
	rm -f $(PROGRAMS) *~ core

install: all
	install -d -m 755 $${DESTDIR}$(BIN_PATH) $${DESTDIR}$(DOC_PATH)
	install -m 755 $(PROGRAMS) $${DESTDIR}$(BIN_PATH)
	install -T -m 644 README.md $${DESTDIR}$(DOC_PATH)/README.aflnet_tools.md
