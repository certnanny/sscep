dnl Process this file with autoconf
AC_INIT([sscep], [0.4.0])
AM_INIT_AUTOMAKE([foreign dist-xz subdir-objects])

AC_PROG_CC
AC_PROG_INSTALL

PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([OPENSSL], [openssl])

AC_CHECK_HEADERS([stdio.h sys/types.h stdlib.h string.h ctype.h signal.h setjmp.h sys/socket.h netinet/in.h arpa/inet.h netdb.h unistd.h errno.h],
	[sscep_found_headers=yes; break;])

AS_IF([test "x$sscep_found_headers" != "xyes"],
	[AC_MSG_ERROR([Unable to find the required system headers])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
