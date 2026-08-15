AM_CFLAGS = -I$(top_srcdir)/c2s -I@top_srcdir@

LIBTOOL += --quiet

MODULE_LDFLAGS = -module -avoid-version
MODULE_LIBADD = -lexpat -L$(top_srcdir)/util

pkglib_LTLIBRARIES =

pkglib_LTLIBRARIES += libstorage.la
libstorage_la_SOURCES = storage.h storage.c object.c
libstorage_la_CPPFLAGS = -DLIBRARY_DIR=\"$(pkglibdir)\"

if STORAGE_SQLITE
pkglib_LTLIBRARIES += authreg_sqlite.la storage_sqlite.la
authreg_sqlite_la_SOURCES = authreg_sqlite.c
authreg_sqlite_la_LDFLAGS = $(MODULE_LDFLAGS)
authreg_sqlite_la_LIBADD  = $(MODULE_LIBADD) $(SQLITE_LIBS)
storage_sqlite_la_SOURCES = storage_sqlite.c
storage_sqlite_la_LDFLAGS = $(MODULE_LDFLAGS)
storage_sqlite_la_LIBADD  = $(MODULE_LIBADD) $(SQLITE_LIBS)
endif
