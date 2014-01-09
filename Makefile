# Makefile to generate dhtest

CC=gcc
CFLAGS?=-Wall -O3 -g --std=c99 -D_SVID_SOURCE -D_POSIX_SOURCE -D_BSD_SOURCE

%.o: %.c headers.h
	$(CC) $(CFLAGS) -o $@ -c $<

dhtest: dhtest.o functions.o 
	$(CC) dhtest.o functions.o -o dhtest

clean:
	rm -f dhtest functions.o dhtest.o
