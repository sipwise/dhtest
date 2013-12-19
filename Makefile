# Makefile to generate dhtest

CC=gcc
CFLAGS=-Wall -O3 -g -fno-strict-aliasing

dhtest: dhtest.o functions.o 
	$(CC) dhtest.o functions.o -o dhtest

clean:
	rm -f dhtest functions.o dhtest.o
