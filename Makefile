#
# $Id: Makefile,v 1.0 2003/01/12 13:17:37 jt Exp $
#

BINDIR = /usr/local/bin
MANDIR = /usr/local/man/man8

CC	= gcc
WITH_DEBUG   = -g
CFLAGS	= -Wall -O $(WITH_DEBUG)

MAN	= sscep.8
PROG	= sscep
OBJS    = sscep.o init.o net.o sceputils.o pkcs7.o ias.o fileutils.o

$(PROG): $(OBJS)
	 $(CC) $(CFLAGS) -o $(PROG) $(OBJS) -lcrypto

clean:
	rm -f $(PROG) $(OBJS) $(MAN) core

install:
	./install-sh $(PROG) $(BINDIR)
	./install-sh $(MAN) $(MANDIR)
