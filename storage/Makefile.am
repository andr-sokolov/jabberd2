AM_CFLAGS = -I$(top_srcdir)/c2s -I@top_srcdir@

LIBTOOL += --quiet

MODULE_LDFLAGS = -module -avoid-version
MODULE_LIBADD = -lexpat -L$(top_srcdir)/util

pkglib_LTLIBRARIES =

pkglib_LTLIBRARIES += libstorage.la
libstorage_la_SOURCES = storage.h storage.c object.c
libstorage_la_LIBADD = $(SQLITE_LIBS)

pkglib_LTLIBRARIES += authreg_plain.la
authreg_plain_la_SOURCES = authreg_plain.c
authreg_plain_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_plain_la_LIBADD  = $(MODULE_LIBADD)
