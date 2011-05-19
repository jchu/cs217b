


CCNINCDIR = /home/milki/git/ccnx/include/ccn
CCNLIBDIR = /home/milki/git/ccnx/csrc/lib
LDLIBS = -L$(CCNLIBDIR) -lccn -lcrypto

PROGRAMS = server

CSRC = server.c

default all: $(PROGRAMS)

$(PROGRAMS): $(CCNLIBDIR)/libccn.a

server: server.o
	$(CC) $(CFLAGS) -o $@ server.o $(LDLIBS)

server.o: $(CCNINCDIR)/ccn.h $(CCNINCDIR)/charbuf.h \
	$(CCNINCDIR)/uri.h $(CCNINCDIR)/header.h \
	messages.h
