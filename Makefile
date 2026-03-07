CROSS_COMPILE ?=
CFLAGS ?= -O3 -march=native
CC = $(CROSS_COMPILE)gcc
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)

.PHONY: clean

wg-vanity: wg-vanity.c
	$(CC) $(CFLAGS) -DVERSION='"$(VERSION)"' -Wall -Wextra -pthread -o $@ $<

clean:
	rm -f wg-vanity

