#
# Makefile for Solaris
#


BINDIR = /opt/CertNanny/bin
MANDIR = /usr/local/man/man8

CC	= gcc
#WITH_DEBUG   = -g
OPENSSL = ../openssl
CFLAGS	= -Wall -O $(WITH_DEBUG) -I $(OPENSSL)/include -m64

LDFLAGS = -L$(OPENSSL)
LDLIBS = -lcrypto -lsocket -lnsl -ldl

MAN	= sscep.8
PROG	= sscep
OBJS    = sscep.o init.o net.o sceputils.o pkcs7.o ias.o fileutils.o configuration.o engine.o

all: $(PROG)_static $(PROG)_dyn

$(PROG)_static: $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG)_static $(OBJS) $(OPENSSL)/libcrypto.a -lsocket -lnsl -ldl

$(PROG)_dyn: $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG)_dyn $(OBJS) $(LDLIBS) $(LDFLAGS)

clean:
	rm -f $(PROG)_static $(PROG)_dyn $(OBJS) $(MAN) core Solaris/pkginfo Makefile
	rm -rf opt/ usr/ CertNanny-sscep* 

install:
	echo "TODO: install target"

package: all Solaris/pkginfo.template Solaris/Prototype
	./Solaris/make_Solaris_package.sh

