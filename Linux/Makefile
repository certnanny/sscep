#
# Makefile for Linux
#

BINDIR = /opt/CertNanny/bin
MANDIR = /usr/local/man/man8

CC	= gcc
#WITH_DEBUG   = -g
OPENSSL = ../openssl
CFLAGS	= -Wall -O $(WITH_DEBUG) -I $(OPENSSL)/include 

LDFLAGS = -L$(OPENSSL)
LDLIBS = -lcrypto

MAN	= sscep.8
PROG	= sscep
OBJS    = sscep.o init.o net.o sceputils.o pkcs7.o ias.o fileutils.o configuration.o engine.o

all: $(PROG)_static $(PROG)_dyn

$(PROG)_static: $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG)_static $(OBJS) $(OPENSSL)/libcrypto.a -ldl

$(PROG)_dyn: $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG)_dyn $(OBJS) $(LDLIBS) $(LDFLAGS)

clean:
	rm -f $(PROG) $(OBJS) $(MAN) core

install:
	echo "TODO: install target"

package: all
	echo "Creating package..."
	Linux/make_Linux_package.sh

