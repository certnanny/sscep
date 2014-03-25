AM_CFLAGS = @OPENSSL_CFLAGS@ -Wall
AM_LDFLAGS = @OPENSSL_LIBS@
docdir = $(datadir)/doc/@PACKAGE@-@VERSION@

bin_PROGRAMS = sscep
sscep_SOURCES = src/sscep.c \
				src/init.c \
				src/net.c \
				src/sceputils.c \
				src/pkcs7.c \
				src/ias.c \
				src/fileutils.c

dist_doc_DATA = README README.md TODO doc/draft-nourse-scep-06.txt doc/draft-nourse-scep-11.txt sscep.conf
EXTRA_DIST = autogen.sh deploy patches resources
