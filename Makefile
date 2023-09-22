# Makefile to generate dhtest
prefix ?= /usr
CC=gcc
CFLAGS?=-g -O3 -Wall -Wextra
CFLAGS+=--std=c99 -D_POSIX_SOURCE -D_DEFAULT_SOURCE

%.o: %.c headers.h
	$(CC) $(CFLAGS) -o $@ -c $<

dhtest: dhtest.o functions.o
	$(CC) dhtest.o functions.o -o dhtest

install: dhtest
	install -d $(DESTDIR)$(prefix)/sbin
	install -m 0755 dhtest $(DESTDIR)$(prefix)/sbin

clean:
	rm -f dhtest functions.o dhtest.o

.PHONY: install
