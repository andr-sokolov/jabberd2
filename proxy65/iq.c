/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "proxy65.h"

static void _route_attrs(proxy65_t p, nad_t req, nad_t out,
                         char *iq_to, size_t iq_to_sz,
                         char *iq_from, size_t iq_from_sz,
                         char *iq_id, size_t iq_id_sz,
                         char *rto, size_t rto_sz) {
    iq_to[0] = iq_from[0] = iq_id[0] = rto[0] = '\0';

    int attr = nad_find_attr(req, 1, -1, "from", NULL);
    if(attr >= 0)
        snprintf(iq_to, iq_to_sz, "%.*s", NAD_AVAL_L(req, attr), NAD_AVAL(req, attr));

    attr = nad_find_attr(req, 1, -1, "to", NULL);
    if(attr >= 0)
        snprintf(iq_from, iq_from_sz, "%.*s", NAD_AVAL_L(req, attr), NAD_AVAL(req, attr));
    else
        snprintf(iq_from, iq_from_sz, "%s", p->id);

    attr = nad_find_attr(req, 1, -1, "id", NULL);
    if(attr >= 0)
        snprintf(iq_id, iq_id_sz, "%.*s", NAD_AVAL_L(req, attr), NAD_AVAL(req, attr));

    attr = nad_find_attr(req, 0, -1, "from", NULL);
    if(attr >= 0)
        snprintf(rto, rto_sz, "%.*s", NAD_AVAL_L(req, attr), NAD_AVAL(req, attr));
}

static nad_t _iq_result_skel(proxy65_t p, nad_t req, int *iq_elem) {
    char iq_to[1024], iq_from[1024], iq_id[256], rto[1024];
    _route_attrs(p, req, NULL, iq_to, sizeof(iq_to), iq_from, sizeof(iq_from),
                 iq_id, sizeof(iq_id), rto, sizeof(rto));

    nad_t nad = nad_new();
    int rns = nad_add_namespace(nad, uri_COMPONENT, NULL);
    nad_append_elem(nad, rns, "route", 0);
    if(rto[0] != '\0')
        nad_append_attr(nad, -1, "to", rto);
    nad_append_attr(nad, -1, "from", p->id);

    int cns = nad_add_namespace(nad, uri_CLIENT, NULL);
    *iq_elem = nad_append_elem(nad, cns, "iq", 1);
    nad_append_attr(nad, -1, "type", "result");
    if(iq_id[0] != '\0')
        nad_append_attr(nad, -1, "id", iq_id);
    if(iq_to[0] != '\0')
        nad_append_attr(nad, -1, "to", iq_to);
    if(iq_from[0] != '\0')
        nad_append_attr(nad, -1, "from", iq_from);

    return nad;
}

void proxy65_route_reply(proxy65_t p, nad_t nad) {
    char rfrom[1024];
    rfrom[0] = '\0';

    int attr = nad_find_attr(nad, 0, -1, "from", NULL);
    if(attr >= 0)
        snprintf(rfrom, sizeof(rfrom), "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

    stanza_tofrom(nad, 1);
    nad_set_attr(nad, 0, -1, "to", rfrom[0] != '\0' ? rfrom : NULL, 0);
    nad_set_attr(nad, 0, -1, "from", p->id, 0);

    sx_nad_write(p->router, nad);
}

void proxy65_route_error(proxy65_t p, nad_t nad, int err) {
    stanza_error(nad, 1, err);
    proxy65_route_reply(p, nad);
}

static void _iq_disco_info(proxy65_t p, nad_t req) {
    int iq;
    nad_t nad = _iq_result_skel(p, req, &iq);
    int ns = nad_add_namespace(nad, uri_DISCO_INFO, NULL);
    nad_append_elem(nad, ns, "query", 2);

    nad_append_elem(nad, ns, "identity", 3);
    nad_append_attr(nad, -1, "category", "proxy");
    nad_append_attr(nad, -1, "type", "bytestreams");
    nad_append_attr(nad, -1, "name", "SOCKS5 Bytestreams Proxy");

    nad_append_elem(nad, ns, "feature", 3);
    nad_append_attr(nad, -1, "var", uri_DISCO_INFO);
    nad_append_elem(nad, ns, "feature", 3);
    nad_append_attr(nad, -1, "var", uri_BYTESTREAMS);

    nad_free(req);
    sx_nad_write(p->router, nad);
}

static void _iq_disco_items(proxy65_t p, nad_t req) {
    int iq;
    nad_t nad = _iq_result_skel(p, req, &iq);
    int ns = nad_add_namespace(nad, uri_DISCO_ITEMS, NULL);
    nad_append_elem(nad, ns, "query", 2);

    nad_free(req);
    sx_nad_write(p->router, nad);
}

static void _iq_bytestreams_get(proxy65_t p, nad_t req) {
    char sid[256];
    sid[0] = '\0';

    int ns = nad_find_scoped_namespace(req, uri_BYTESTREAMS, NULL);
    int query = nad_find_elem(req, 1, ns, "query", 1);
    if(query >= 0) {
        int attr = nad_find_attr(req, query, -1, "sid", NULL);
        if(attr >= 0)
            snprintf(sid, sizeof(sid), "%.*s", NAD_AVAL_L(req, attr), NAD_AVAL(req, attr));
    }

    int iq;
    nad_t nad = _iq_result_skel(p, req, &iq);
    ns = nad_add_namespace(nad, uri_BYTESTREAMS, NULL);
    nad_append_elem(nad, ns, "query", 2);
    if(sid[0] != '\0')
        nad_append_attr(nad, -1, "sid", sid);

    char port[16];
    snprintf(port, sizeof(port), "%d", p->local_port);
    nad_append_elem(nad, ns, "streamhost", 3);
    nad_append_attr(nad, -1, "jid", p->id);
    nad_append_attr(nad, -1, "host", p->local_host);
    nad_append_attr(nad, -1, "port", port);

    nad_free(req);
    sx_nad_write(p->router, nad);
}

static void _iq_bytestreams_activate(proxy65_t p, nad_t req) {
    int ns = nad_find_scoped_namespace(req, uri_BYTESTREAMS, NULL);
    int query = nad_find_elem(req, 1, ns, "query", 1);
    if(query < 0) {
        proxy65_route_error(p, req, stanza_err_BAD_REQUEST);
        return;
    }

    int attr = nad_find_attr(req, query, -1, "sid", NULL);
    if(attr < 0) {
        proxy65_route_error(p, req, stanza_err_BAD_REQUEST);
        return;
    }

    char sid[256];
    snprintf(sid, sizeof(sid), "%.*s", NAD_AVAL_L(req, attr), NAD_AVAL(req, attr));

    int act = nad_find_elem(req, query, -1, "activate", 1);
    if(act < 0 || NAD_CDATA_L(req, act) <= 0) {
        proxy65_route_error(p, req, stanza_err_BAD_REQUEST);
        return;
    }

    char target[1024];
    snprintf(target, sizeof(target), "%.*s", NAD_CDATA_L(req, act), NAD_CDATA(req, act));

    attr = nad_find_attr(req, 1, -1, "from", NULL);
    if(attr < 0) {
        proxy65_route_error(p, req, stanza_err_BAD_REQUEST);
        return;
    }

    char from[1024];
    snprintf(from, sizeof(from), "%.*s", NAD_AVAL_L(req, attr), NAD_AVAL(req, attr));

    jid_t jfrom = jid_new(from, -1);
    jid_t jtarget = jid_new(target, -1);
    if(jfrom == NULL || jtarget == NULL) {
        if(jfrom) jid_free(jfrom);
        if(jtarget) jid_free(jtarget);
        proxy65_route_error(p, req, stanza_err_JID_MALFORMED);
        return;
    }

    char hash[PROXY65_HASH_HEX_LEN + 1];
    proxy65_hash_sid(sid, jid_full(jfrom), jid_full(jtarget), hash);
    jid_free(jfrom);
    jid_free(jtarget);

    bytestream_t bs = proxy65_stream_get(p, hash);
    if(bs == NULL || bs->npeers < 2) {
        log_write(p->log, LOG_NOTICE, "activate failed for sid=%s hash=%s (peers=%d)",
                  sid, hash, bs ? bs->npeers : 0);
        proxy65_route_error(p, req, stanza_err_ITEM_NOT_FOUND);
        return;
    }

    strncpy(bs->sid, sid, sizeof(bs->sid) - 1);
    bs->sid[sizeof(bs->sid) - 1] = '\0';
    proxy65_socks_activate(p, hash, sid);

    int iq;
    nad_t nad = _iq_result_skel(p, req, &iq);
    nad_free(req);
    sx_nad_write(p->router, nad);
}

void proxy65_iq_handle(proxy65_t p, nad_t nad) {
    int attr = nad_find_attr(nad, 1, -1, "type", NULL);
    if(attr < 0) {
        nad_free(nad);
        return;
    }

    char type[16];
    snprintf(type, sizeof(type), "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

    int ns = nad_find_scoped_namespace(nad, uri_DISCO_INFO, NULL);
    if(ns >= 0) {
        int query = nad_find_elem(nad, 1, ns, "query", 1);
        if(query >= 0 && strcmp(type, "get") == 0) {
            _iq_disco_info(p, nad);
            return;
        }
    }

    ns = nad_find_scoped_namespace(nad, uri_DISCO_ITEMS, NULL);
    if(ns >= 0) {
        int query = nad_find_elem(nad, 1, ns, "query", 1);
        if(query >= 0 && strcmp(type, "get") == 0) {
            _iq_disco_items(p, nad);
            return;
        }
    }

    ns = nad_find_scoped_namespace(nad, uri_BYTESTREAMS, NULL);
    if(ns >= 0) {
        int query = nad_find_elem(nad, 1, ns, "query", 1);
        if(query >= 0) {
            if(strcmp(type, "get") == 0) {
                _iq_bytestreams_get(p, nad);
                return;
            }
            if(strcmp(type, "set") == 0) {
                if(nad_find_elem(nad, query, -1, "activate", 1) >= 0) {
                    _iq_bytestreams_activate(p, nad);
                    return;
                }
            }
        }
    }

    if(strcmp(type, "error") == 0) {
        nad_free(nad);
        return;
    }

    log_debug(ZONE, "unhandled iq, returning service-unavailable");
    proxy65_route_error(p, nad, stanza_err_SERVICE_UNAVAILABLE);
}
