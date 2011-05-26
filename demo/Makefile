

CFLAGS=-g -Wall
CCNINCDIR = /home/milki/git/ccnx/include/ccn
CCNLIBDIR = /home/milki/git/ccnx/csrc/lib
LDLIBS = -L$(CCNLIBDIR) -lccn -lcrypto

PROGRAMS = server client

CSRC = server.c client.c

default all: $(PROGRAMS)

$(PROGRAMS): $(CCNLIBDIR)/libccn.a

client: client.o
	$(CC) $(CFLAGS) -o $@ client.o $(LDLIBS)

server: server.o
	$(CC) $(CFLAGS) -o $@ server.o $(LDLIBS)

server.o: $(CCNINCDIR)/ccn.h $(CCNINCDIR)/charbuf.h \
	$(CCNINCDIR)/uri.h $(CCNINCDIR)/header.h \
	messages.h

server.o: $(CCNINCDIR)/ccn.h $(CCNINCDIR)/charbuf.h \
	$(CCNINCDIR)/uri.h $(CCNINCDIR)/header.h \
	messages.h

clean:
	rm $(PROGRAMS) server.o client.o
