CFLAGS=-g -Wall -O0
LDLIBS = -lcrypto

PROGRAMS = crypttest

CSRC = crypttest.c

default all: $(PROGRAMS)

crypttest: loadkeys.o crypttest.o
	$(CC) $(CFLAGS) -o $@ crypttest.o loadkeys.o $(LDLIBS)

crypttest.o: loadkeys.h

clean:
	rm $(PROGRAMS) crypttest.o loadkeys.o
