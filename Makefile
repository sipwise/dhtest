# Makefile to generate dhtest

CC?=gcc
CFLAGS?=-Wall -O3 -g

%.o: %.c headers.h
	$(CC) $(CFLAGS) -o $@ -c $<

dhtest: dhtest.o functions.o 
	$(CC) dhtest.o functions.o -o dhtest

clean:
	rm -f dhtest functions.o dhtest.o
