AC_INIT(onenetd, 12, ats@offog.org)
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS(config.h)

dnl Checks for programs.
AC_PROG_CC

AC_CHECK_LIB(socket, socket,,, -lnsl)
AC_CHECK_LIB(nsl, gethostbyname,,, -lsocket)

AC_CHECK_PROGS([PYTHON], [python], [no])
AM_CONDITIONAL([WITH_TESTS], [test "x$PYTHON" != "xno"])

AC_OUTPUT(Makefile)
