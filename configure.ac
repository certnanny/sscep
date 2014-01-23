#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(sscep, 0.4.1, minfrin@sharp.fm)
AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_FILES([Makefile sscep.spec])
AC_CONFIG_SRCDIR([sscep.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
PKG_CHECK_MODULES(openssl, openssl >= 0.9.7)
#
CFLAGS="$CFLAGS $openssl_CFLAGS"
CPPFLAGS="$CPPFLAGS $openssl_CPPFLAGS"
LDFLAGS="$LDFLAGS $openssl_LIBS"

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([alarm gethostbyname memset socket strchr strdup strstr])

AC_OUTPUT

