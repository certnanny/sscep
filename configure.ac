#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([sscep],[0.8.1],[certnanny@github.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign subdir-objects dist-bzip2])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_SRCDIR([src/sscep.c])
AC_CONFIG_MACRO_DIR([m4])
LT_INIT

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

AC_CONFIG_FILES([Makefile])
AC_SUBST([LIBTOOL_DEPS])
AC_OUTPUT

