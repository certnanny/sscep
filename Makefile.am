ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = sscep
sscep_SOURCES = src/sscep.c \
                src/sscep.h \
                src/conf.h \
                src/cmd.h \
                src/getopt.c \
                src/getopt.h \
                src/configuration.c \
                src/configuration.h \
                src/engine.c \
                src/engine.h \
                src/net.c \
                src/picohttpparser.c \
                src/picohttpparser.h \
                src/ias.c \
                src/ias.h \
                src/pkcs7.c \
                src/fileutils.c \
                src/fileutils_capi.h \
                src/sceputils.c

dist_doc_DATA = COPYING \
                README.md

EXTRA_DIST = doc/rfc8894.txt \
             CMakeLists.txt \
             VERSION \
             bootstrap.sh \
             mkrequest \
             sscep.conf
