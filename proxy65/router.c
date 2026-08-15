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

int proxy65_router_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    proxy65_t p = (proxy65_t) arg;
    sx_buf_t buf = (sx_buf_t) data;

    switch(e) {
        case event_WANT_READ:
            mio_read(p->mio, p->fd);
            break;

        case event_WANT_WRITE:
            mio_write(p->mio, p->fd);
            break;

        case event_READ: {
            int len = recv(p->fd->fd, buf->data, buf->len, 0);

            if(len < 0) {
                if(MIO_WOULDBLOCK) {
                    buf->len = 0;
                    return 0;
                }
                log_write(p->log, LOG_NOTICE, "[%d] [router] read error: %s (%d)", p->fd->fd, strerror(errno), errno);
                sx_kill(s);
                return -1;
            } else if(len == 0) {
                sx_kill(s);
                return -1;
            }

            buf->len = len;
            return len;
        }

        case event_WRITE: {
            int len = send(p->fd->fd, buf->data, buf->len, 0);
            if(len >= 0)
                return len;

            if(MIO_WOULDBLOCK)
                return 0;

            log_write(p->log, LOG_NOTICE, "[%d] [router] write error: %s (%d)", p->fd->fd, strerror(errno), errno);
            sx_kill(s);
            return -1;
        }

        case event_ERROR: {
            sx_error_t *sxe = (sx_error_t *) data;
            log_write(p->log, LOG_NOTICE, "error from router: %s (%s)", sxe->generic, sxe->specific);
            if(sxe->code == SX_ERR_AUTH)
                sx_close(s);
            break;
        }

        case event_STREAM:
            break;

        case event_OPEN: {
            log_write(p->log, LOG_NOTICE, "connection to router established");
            p->retry_left = p->retry_lost;

            nad_t nad = nad_new();
            int ns = nad_add_namespace(nad, uri_COMPONENT, NULL);
            nad_append_elem(nad, ns, "bind", 0);
            nad_append_attr(nad, -1, "name", p->id);

            log_debug(ZONE, "requesting component bind for '%s'", p->id);
            sx_nad_write(p->router, nad);
            break;
        }

        case event_PACKET: {
            nad_t nad = (nad_t) data;

            if(NAD_ENS(nad, 0) < 0) {
                nad_free(nad);
                return 0;
            }

            /* features / SASL */
            if(s->state == state_STREAM) {
                if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_STREAMS) || strncmp(uri_STREAMS, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_STREAMS)) != 0 || NAD_ENAME_L(nad, 0) != 8 || strncmp("features", NAD_ENAME(nad, 0), 8) != 0) {
                    nad_free(nad);
                    return 0;
                }

#ifdef HAVE_SSL
                if(p->sx_ssl != NULL && p->router_pemfile != NULL && s->ssf == 0) {
                    int ns = nad_find_scoped_namespace(nad, uri_TLS, NULL);
                    if(ns >= 0) {
                        int elem = nad_find_elem(nad, 0, ns, "starttls", 1);
                        if(elem >= 0) {
                            if(sx_ssl_client_starttls(p->sx_ssl, s, p->router_pemfile, p->router_private_key_password) == 0) {
                                nad_free(nad);
                                return 0;
                            }
                            log_write(p->log, LOG_NOTICE, "unable to establish encrypted session with router");
                        }
                    }
                }
#endif

                sx_sasl_auth(p->sx_sasl, s, "jabberd-router", "DIGEST-MD5", p->router_user, p->router_pass);
                nad_free(nad);
                return 0;
            }

            /* bind response */
            if(s->state == state_OPEN && !p->online) {
                if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_COMPONENT) || strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) != 0 || NAD_ENAME_L(nad, 0) != 4 || strncmp("bind", NAD_ENAME(nad, 0), 4)) {
                    nad_free(nad);
                    return 0;
                }

                int attr = nad_find_attr(nad, 0, -1, "error", NULL);
                if(attr >= 0) {
                    log_write(p->log, LOG_NOTICE, "router refused bind request (%.*s)", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
                    exit(1);
                }

                if(p->server_fd == NULL)
                    proxy65_socks_listen(p);

                p->online = p->started = 1;
                log_write(p->log, LOG_NOTICE, "ready as %s (SOCKS5 on %s:%d, advertise %s:%d)",
                          p->id, p->local_ip, p->local_port, p->local_host, p->local_port);

                nad_free(nad);
                return 0;
            }

            if(NAD_NURI_L(nad, NAD_ENS(nad, 0)) != strlen(uri_COMPONENT) || strncmp(uri_COMPONENT, NAD_NURI(nad, NAD_ENS(nad, 0)), strlen(uri_COMPONENT)) != 0) {
                nad_free(nad);
                return 0;
            }

            if(NAD_ENAME_L(nad, 0) != 5 || strncmp("route", NAD_ENAME(nad, 0), 5) != 0) {
                nad_free(nad);
                return 0;
            }

            if(nad_find_attr(nad, 0, -1, "type", NULL) >= 0) {
                nad_free(nad);
                return 0;
            }

            /* expect iq as first child */
            if(nad->ecur < 2 || NAD_ENAME_L(nad, 1) != 2 || strncmp("iq", NAD_ENAME(nad, 1), 2) != 0) {
                log_debug(ZONE, "dropping non-iq route packet");
                nad_free(nad);
                return 0;
            }

            proxy65_iq_handle(p, nad);
            return 0;
        }

        case event_CLOSED:
            mio_close(p->mio, p->fd);
            p->fd = NULL;
            return -1;
    }

    return 0;
}

int proxy65_router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    proxy65_t p = (proxy65_t) arg;

    switch(a) {
        case action_READ: {
            int nbytes;
            ioctl(fd->fd, FIONREAD, &nbytes);
            if(nbytes == 0) {
                sx_kill(p->router);
                return 0;
            }
            return sx_can_read(p->router);
        }

        case action_WRITE:
            return sx_can_write(p->router);

        case action_CLOSE:
            log_write(p->log, LOG_NOTICE, "connection to router closed");
            proxy65_lost_router = 1;
            p->online = 0;
            break;

        case action_ACCEPT:
            break;
    }

    return 0;
}
