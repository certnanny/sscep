#
# $Id: Makefile,v 1.0 2003/01/12 13:17:37 jt Exp $
#

BINDIR = /usr/local/bin
MANDIR = /usr/local/man/man8

CC	= gcc
#WITH_DEBUG   = -g
OPENSSL = /c/Users/tob130/Downloads/openssl-mingw
CFLAGS	= -Wall -O $(WITH_DEBUG) -I $(OPENSSL)/include

LDFLAGS = -L$(OPENSSL)/lib
LDLIBS = -lcrypto

MAN	= sscep.8
PROG	= sscep
OBJS    = sscep.o init.o net.o sceputils.o pkcs7.o ias.o fileutils.o configuration.o engine.o

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS) $(LDLIBS) $(LDFLAGS)

clean:
	rm -f $(PROG) $(OBJS) $(MAN) core

test:
	prove t/*.t

install:
	./install-sh $(PROG) $(BINDIR)
	./install-sh $(MAN) $(MANDIR)

