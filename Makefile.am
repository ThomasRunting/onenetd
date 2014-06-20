AUTOMAKE_OPTIONS = no-dependencies foreign

bin_PROGRAMS = onenetd
onenetd_SOURCES = onenetd.c
man_MANS = onenetd.1

if WITH_TESTS
check-local:
	$(srcdir)/test-onenetd ./onenetd
endif

EXTRA_DIST = $(man_MANS) test-onenetd
