# Makefile to generate dhtest
prefix?=$(DESTDIR)/usr
CC=gcc
CFLAGS?=-Wall -O3 -g --std=c99 -D_SVID_SOURCE -D_POSIX_SOURCE -D_BSD_SOURCE

%.o: %.c headers.h
	$(CC) $(CFLAGS) -o $@ -c $<

dhtest: dhtest.o functions.o
	$(CC) dhtest.o functions.o -o dhtest

install: dhtest
	install -d $(prefix)/sbin
	install -m 0755 dhtest $(prefix)/sbin

clean:
	rm -f dhtest functions.o dhtest.o

.PHONY: install
