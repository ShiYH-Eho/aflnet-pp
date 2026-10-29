#
# Makefile for the sock2shm LD_PRELOAD library
#
# Builds sockhook.so -- an LD_PRELOAD library that hooks the socket calls of
# the target (server) process and redirects per-connection send/recv traffic
# through shared memory, so the fuzzer and the target exchange data without
# going through the network stack.
#
# Ported from HNPFuzzer (https://github.com/HNPFuzzer/HNPFuzzer).
# Original link flags:  -shared -fPIC -ldl -lrt -lpthread
#

CC       ?= gcc
CFLAGS   ?= -O3 -funroll-loops
override CFLAGS += -I ../../include -Wall -g -Wno-pointer-sign -Wno-unused-result

PREFIX     ?= /usr/local
HELPER_PATH = $(PREFIX)/lib/afl

OBJECTS = sockhook.o sock2shm_utils.o
HEADERS = sock2shm_utils.h ../../include/alloc-inl.h ../../include/types.h \
          ../../include/config.h ../../include/debug.h

all: sockhook.so
	cp -fv sockhook.so ../../

sockhook.so: $(OBJECTS)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $(OBJECTS) -ldl -lrt -lpthread

sockhook.o: sockhook.c $(HEADERS)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

sock2shm_utils.o: sock2shm_utils.c $(HEADERS)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

clean:
	rm -f *.o *.so *~ core

install: all
	install -m 755 -d $${DESTDIR}$(HELPER_PATH)
	install -m 755 sockhook.so $${DESTDIR}$(HELPER_PATH)

.PHONY: all clean install
