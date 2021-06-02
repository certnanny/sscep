#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([sscep],[0.10.0],[certnanny@github.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign subdir-objects dist-bzip2])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_SRCDIR([src/sscep.c])
AC_CONFIG_MACRO_DIR([m4])
LT_INIT

AC_ARG_ENABLE([engines],
    AS_HELP_STRING([--enable-engines], [Enable support for OpenSSL ENGINE API]))
AM_CONDITIONAL(WITH_ENGINES, test "x$enable_engines" = "xyes")
AS_IF([test "x$enable_engines" = "xyes"], [AC_DEFINE([WITH_ENGINES], [1], [ENGINE API enabled])])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
PKG_CHECK_MODULES(openssl, openssl >= 1.1.0)
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

