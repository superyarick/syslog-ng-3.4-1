AM_CFLAGS = -I$(top_srcdir)/lib -I../../../lib -I$(top_srcdir)/modules/afsocket -I..
AM_LDFLAGS = -dlpreopen ../../afsocket/libafsocket.la
LDADD = $(top_builddir)/lib/libsyslog-ng.la @TOOL_DEPS_LIBS@

check_PROGRAMS = test_afsocket

test_afsocket_SOURCES = test_afsocket.c ../../../lib/gtestutils/gtestutils.c

TESTS = $(check_PROGRAMS)
