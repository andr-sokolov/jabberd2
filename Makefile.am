EXTRA_DIST = Doxyfile.in README.md README.protocol README.config contrib docs

LIBTOOL += --quiet

SUBDIRS = etc man
SUBDIRS += tools mio sx util c2s router storage sm proxy65
if ENABLE_TESTS
SUBDIRS += tests
endif

.PHONY: docs cppcheck

docs: Doxyfile
	@doxygen

cppcheck:
	cppcheck --force --quiet --report-progress -j6 --std=c99 -DSIGHUP -DSIGPIPE --enable=warning,performance,portability,information,missingInclude .

dist-hook:
	if grep 'AC_INIT.*dev' configure.ac ; then echo "Remove 'dev' version flag first!"; exit 1; else : ; fi
	find $(distdir) -depth \( -name CVS -o -name .svn -o -name .git \) -exec rm -rf {} \;
