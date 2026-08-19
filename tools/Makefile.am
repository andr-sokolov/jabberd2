LIBTOOL += --quiet

bin_SCRIPTS = jabberd
EXTRA_DIST = jabberd.in jabberd.rc

edit = sed \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@VERSION\@,$(VERSION),g' \
	-e 's,@bindir\@,$(bindir),g' \
	-e 's,@libexecdir\@,$(libexecdir),g'

$(bin_SCRIPTS): $(EXTRA_DIST)
	@echo "generating $@ from $@.in"; \
	rm -f $@ $@.tmp; \
	$(edit) < @srcdir@/$@.in > $@.tmp; \
	chmod +x $@.tmp; \
	mv $@.tmp $@

clean-local:
	rm -f $(bin_SCRIPTS)
