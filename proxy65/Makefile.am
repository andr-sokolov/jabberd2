AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -I@top_srcdir@

LIBTOOL += --quiet

bin_PROGRAMS = proxy65

noinst_HEADERS = proxy65.h
proxy65_SOURCES = main.c router.c iq.c socks.c

proxy65_LDADD = $(top_builddir)/sx/libsx.la \
            $(top_builddir)/mio/libmio.la \
            $(top_builddir)/util/libutil.la
if USE_LIBSUBST
proxy65_LDADD += $(top_builddir)/subst/libsubst.la
endif
