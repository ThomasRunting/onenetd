AC_INIT(onenetd, 1.11, ats@offog.org)
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS(config.h)

dnl Checks for programs.
AC_PROG_CC

AC_CHECK_LIB(socket, socket,,, -lnsl)
AC_CHECK_LIB(nsl, gethostbyname,,, -lsocket)

AC_OUTPUT(Makefile)
