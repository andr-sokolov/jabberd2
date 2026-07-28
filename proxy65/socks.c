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

static void _sock_conn_close(proxy65_t p, sock_conn_t sc);
static int _sock_conn_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);

bytestream_t proxy65_stream_get(proxy65_t p, const char *hash) {
    return (bytestream_t) xhash_get(p->streams, hash);
}

static bytestream_t _stream_get_or_create(proxy65_t p, const char *hash) {
    bytestream_t bs = proxy65_stream_get(p, hash);
    if(bs != NULL)
        return bs;

    bs = (bytestream_t) calloc(1, sizeof(struct bytestream_st));
    strncpy(bs->hash, hash, PROXY65_HASH_HEX_LEN);
    bs->hash[PROXY65_HASH_HEX_LEN] = '\0';
    bs->created = time(NULL);
    xhash_put(p->streams, bs->hash, bs);
    return bs;
}

void proxy65_stream_free(proxy65_t p, bytestream_t bs) {
    if(bs == NULL)
        return;

    for(int i = 0; i < 2; i++) {
        if(bs->peers[i] != NULL) {
            sock_conn_t sc = bs->peers[i];
            bs->peers[i] = NULL;
            sc->bs = NULL;
            _sock_conn_close(p, sc);
        }
    }

    xhash_zap(p->streams, bs->hash);
    free(bs);
}

void proxy65_socks_listen(proxy65_t p) {
    p->server_fd = mio_listen(p->mio, p->local_port, p->local_ip, proxy65_socks_mio_callback, (void *) p);
    if(p->server_fd == NULL) {
        log_write(p->log, LOG_ERR, "[%s, port=%d] failed to listen for SOCKS5", p->local_ip, p->local_port);
        exit(1);
    }
    log_write(p->log, LOG_NOTICE, "[%s, port=%d] listening for SOCKS5 bytestreams", p->local_ip, p->local_port);
}

void proxy65_socks_activate(proxy65_t p, const char *hash, const char *sid) {
    bytestream_t bs = proxy65_stream_get(p, hash);
    if(bs == NULL || bs->npeers < 2)
        return;

    bs->activated = 1;
    if(sid != NULL) {
        strncpy(bs->sid, sid, sizeof(bs->sid) - 1);
        bs->sid[sizeof(bs->sid) - 1] = '\0';
    }

    for(int i = 0; i < 2; i++) {
        if(bs->peers[i] != NULL) {
            bs->peers[i]->state = sock_RELAY;
            mio_read(p->mio, bs->peers[i]->fd);
        }
    }

    log_write(p->log, LOG_NOTICE, "bytestream activated hash=%s sid=%s", hash, bs->sid);
}

static void _sock_conn_free(sock_conn_t sc) {
    if(sc == NULL)
        return;
    free(sc->wbuf);
    free(sc);
}

/* Initiate teardown. sock_conn_t is freed from action_CLOSE. */
static void _sock_conn_close(proxy65_t p, sock_conn_t sc) {
    if(sc == NULL || sc->state == (sock_state_t) -1)
        return;

    sc->state = (sock_state_t) -1;
    bytestream_t bs = sc->bs;
    sc->bs = NULL;

    sock_conn_t peer = NULL;
    mio_fd_t peerfd = NULL;

    if(bs != NULL) {
        for(int i = 0; i < 2; i++) {
            if(bs->peers[i] == sc)
                bs->peers[i] = NULL;
            else if(bs->peers[i] != NULL)
                peer = bs->peers[i];
        }
        bs->peers[0] = bs->peers[1] = NULL;
        xhash_zap(p->streams, bs->hash);
        free(bs);

        if(peer != NULL && peer->state != (sock_state_t) -1) {
            peer->state = (sock_state_t) -1;
            peer->bs = NULL;
            peerfd = peer->fd;
            peer->fd = NULL;
        }
    }

    mio_fd_t myfd = sc->fd;
    sc->fd = NULL;

    if(peerfd != NULL)
        mio_close(p->mio, peerfd);

    if(myfd != NULL)
        mio_close(p->mio, myfd);
    else
        _sock_conn_free(sc);
}

static int _hex_is_valid(const char *s, int len) {
    if(len != PROXY65_HASH_HEX_LEN)
        return 0;
    for(int i = 0; i < len; i++) {
        char c = s[i];
        if(!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

static void _socks_reply_fail(sock_conn_t sc, unsigned char rep) {
    unsigned char resp[10] = { 0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    send(sc->fd->fd, resp, 10, 0);
}

static void _socks_reply_ok(sock_conn_t sc) {
    unsigned char resp[10] = { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    send(sc->fd->fd, resp, 10, 0);
}

static int _socks_process(proxy65_t p, sock_conn_t sc) {
    unsigned char *buf = sc->rbuf;
    int n = sc->rlen;

    if(sc->state == sock_GREETING) {
        if(n < 2)
            return 0;
        if(buf[0] != 0x05) {
            log_debug(ZONE, "bad SOCKS version %d", buf[0]);
            return -1;
        }
        int need = 2 + buf[1];
        if(n < need)
            return 0;

        /* select no-auth */
        {
            unsigned char reply[2] = { 0x05, 0x00 };
            int have_noauth = 0;
            for(int i = 0; i < buf[1]; i++) {
                if(buf[2 + i] == 0x00)
                    have_noauth = 1;
            }
            if(!have_noauth)
                reply[1] = 0xff;
            send(sc->fd->fd, reply, 2, 0);
            if(!have_noauth)
                return -1;
        }

        memmove(buf, buf + need, n - need);
        sc->rlen = n - need;
        sc->state = sock_REQUEST;
        n = sc->rlen;
    }

    if(sc->state == sock_REQUEST) {
        if(n < 5)
            return 0;
        if(buf[0] != 0x05 || buf[1] != 0x01) { /* CONNECT */
            _socks_reply_fail(sc, 0x07);
            return -1;
        }

        char hash[PROXY65_HASH_HEX_LEN + 1];
        unsigned char atyp = buf[3];
        int need = 0;
        if(atyp == 0x03) { /* domain */
            unsigned char alen = buf[4];
            need = 5 + alen + 2;
            if(n < need)
                return 0;
            if(!_hex_is_valid((const char *) (buf + 5), alen)) {
                _socks_reply_fail(sc, 0x04);
                return -1;
            }
            memcpy(hash, buf + 5, alen);
            hash[alen] = '\0';
            /* lowercase */
            for(int i = 0; i < alen; i++) {
                if(hash[i] >= 'A' && hash[i] <= 'F')
                    hash[i] = hash[i] - 'A' + 'a';
            }
        } else {
            _socks_reply_fail(sc, 0x08);
            return -1;
        }

        bytestream_t bs = _stream_get_or_create(p, hash);
        if(bs->npeers >= 2 || bs->activated) {
            _socks_reply_fail(sc, 0x05);
            return -1;
        }

        strncpy(sc->hash, hash, PROXY65_HASH_HEX_LEN);
        sc->hash[PROXY65_HASH_HEX_LEN] = '\0';
        sc->bs = bs;
        bs->peers[bs->npeers++] = sc;
        sc->state = sock_CONNECTED;

        _socks_reply_ok(sc);

        memmove(buf, buf + need, n - need);
        sc->rlen = n - need;

        log_write(p->log, LOG_NOTICE, "[%d] SOCKS5 CONNECT ok hash=%s peers=%d",
                  sc->fd->fd, hash, bs->npeers);

        /* no further reads until activated (except leftover data after activate) */
        return 0;
    }

    return 0;
}

static int _socks_relay_flush(proxy65_t p, sock_conn_t sc) {
    if(sc->wbuf == NULL || sc->woff >= sc->wlen)
        return 0;

    int n = send(sc->fd->fd, sc->wbuf + sc->woff, sc->wlen - sc->woff, 0);
    if(n < 0) {
        if(MIO_WOULDBLOCK)
            return 0;
        return -1;
    }
    sc->woff += n;
    if(sc->woff >= sc->wlen) {
        free(sc->wbuf);
        sc->wbuf = NULL;
        sc->wlen = sc->woff = 0;
    } else {
        mio_write(p->mio, sc->fd);
    }
    return 0;
}

static int _socks_relay_write(proxy65_t p, sock_conn_t dest, const unsigned char *data, int len) {
    if(dest->wbuf != NULL) {
        unsigned char *nb = (unsigned char *) realloc(dest->wbuf, dest->wlen + len);
        if(nb == NULL)
            return -1;
        dest->wbuf = nb;
        memcpy(dest->wbuf + dest->wlen, data, len);
        dest->wlen += len;
        mio_write(p->mio, dest->fd);
        return 0;
    }

    int n = send(dest->fd->fd, data, len, 0);
    if(n < 0) {
        if(!MIO_WOULDBLOCK)
            return -1;
        n = 0;
    }
    if(n < len) {
        dest->wlen = len - n;
        dest->woff = 0;
        dest->wbuf = (unsigned char *) malloc(dest->wlen);
        if(dest->wbuf == NULL)
            return -1;
        memcpy(dest->wbuf, data + n, dest->wlen);
        mio_write(p->mio, dest->fd);
    }
    return 0;
}

static sock_conn_t _socks_peer(sock_conn_t sc) {
    bytestream_t bs = sc->bs;
    if(bs == NULL)
        return NULL;
    for(int i = 0; i < 2; i++) {
        if(bs->peers[i] != NULL && bs->peers[i] != sc)
            return bs->peers[i];
    }
    return NULL;
}

static int _sock_conn_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    sock_conn_t sc = (sock_conn_t) arg;
    proxy65_t p = sc->p;

    switch(a) {
        case action_READ:
            sc->last_activity = time(NULL);

            if(sc->state == sock_RELAY) {
                sock_conn_t peer = _socks_peer(sc);
                if(peer == NULL)
                    return 0;

                if(peer->wbuf != NULL) {
                    /* backpressure: don't read until peer drain */
                    return 0;
                }

                unsigned char buf[PROXY65_RELAY_BUF];
                int n = recv(fd->fd, buf, sizeof(buf), 0);
                if(n < 0) {
                    if(MIO_WOULDBLOCK)
                        return 1;
                    _sock_conn_close(p, sc);
                    return 0;
                }
                if(n == 0) {
                    _sock_conn_close(p, sc);
                    return 0;
                }
                if(_socks_relay_write(p, peer, buf, n) < 0) {
                    _sock_conn_close(p, sc);
                    return 0;
                }
                return 1;
            }

            /* greeting / request */
            {
                int nbytes;
                ioctl(fd->fd, FIONREAD, &nbytes);
                if(nbytes == 0 && sc->rlen == 0) {
                    _sock_conn_close(p, sc);
                    return 0;
                }
            }

            if(sc->rlen >= (int) sizeof(sc->rbuf)) {
                _sock_conn_close(p, sc);
                return 0;
            }

            {
                int n = recv(fd->fd, sc->rbuf + sc->rlen, sizeof(sc->rbuf) - sc->rlen, 0);
                if(n < 0) {
                    if(MIO_WOULDBLOCK)
                        return 1;
                    _sock_conn_close(p, sc);
                    return 0;
                }
                if(n == 0) {
                    _sock_conn_close(p, sc);
                    return 0;
                }
                sc->rlen += n;
            }

            if(_socks_process(p, sc) < 0) {
                _sock_conn_close(p, sc);
                return 0;
            }

            /* keep reading while greeting/request incomplete */
            if(sc->state == sock_GREETING || sc->state == sock_REQUEST)
                return 1;
            return 0;

        case action_WRITE:
            if(sc->state == sock_RELAY) {
                if(_socks_relay_flush(p, sc) < 0) {
                    _sock_conn_close(p, sc);
                    return 0;
                }
                /* peer may have been paused */
                sock_conn_t peer = _socks_peer(sc);
                if(peer != NULL && sc->wbuf == NULL)
                    mio_read(p->mio, peer->fd);
            }
            return 0;

        case action_CLOSE:
            /* If we still own a bytestream, tear the peer down too. */
            if(sc->state != (sock_state_t) -1) {
                bytestream_t bs = sc->bs;
                sock_conn_t peer = NULL;

                sc->state = (sock_state_t) -1;
                sc->bs = NULL;
                sc->fd = NULL;

                if(bs != NULL) {
                    for(int i = 0; i < 2; i++) {
                        if(bs->peers[i] == sc)
                            bs->peers[i] = NULL;
                        else if(bs->peers[i] != NULL)
                            peer = bs->peers[i];
                    }
                    bs->peers[0] = bs->peers[1] = NULL;
                    xhash_zap(p->streams, bs->hash);
                    free(bs);

                    if(peer != NULL && peer->state != (sock_state_t) -1) {
                        peer->state = (sock_state_t) -1;
                        peer->bs = NULL;
                        mio_fd_t pfd = peer->fd;
                        peer->fd = NULL;
                        if(pfd != NULL)
                            mio_close(p->mio, pfd);
                    }
                }
            } else {
                sc->fd = NULL;
            }
            _sock_conn_free(sc);
            break;

        case action_ACCEPT:
            break;
    }

    return 0;
}

int proxy65_socks_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    proxy65_t p = (proxy65_t) arg;

    switch(a) {
        case action_ACCEPT: {
            log_write(p->log, LOG_NOTICE, "[%d] [%s] SOCKS5 connect", fd->fd, (char *) data);

            sock_conn_t sc = (sock_conn_t) calloc(1, sizeof(struct sock_conn_st));
            sc->p = p;
            sc->fd = fd;
            sc->state = sock_GREETING;
            sc->last_activity = time(NULL);

            mio_app(m, fd, _sock_conn_mio_callback, (void *) sc);
            mio_read(m, fd);
            break;
        }

        case action_READ:
        case action_WRITE:
        case action_CLOSE:
            break;
    }

    return 0;
}

void proxy65_socks_expire(proxy65_t p) {
    time_t now = time(NULL);
    bytestream_t *todo = NULL;
    int ntodo = 0;

    if(xhash_iter_first(p->streams))
        do {
            const char *key;
            int keylen;
            bytestream_t bs;
            xhash_iter_get(p->streams, &key, &keylen, (void **) &bs);
            if(bs == NULL)
                continue;
            if(!bs->activated && now > bs->created + PROXY65_SOCK_IDLE) {
                todo = (bytestream_t *) realloc(todo, (ntodo + 1) * sizeof(bytestream_t));
                todo[ntodo++] = bs;
            }
        } while(xhash_iter_next(p->streams));

    for(int i = 0; i < ntodo; i++) {
        log_write(p->log, LOG_NOTICE, "expiring idle bytestream hash=%s", todo[i]->hash);
        proxy65_stream_free(p, todo[i]);
    }
    free(todo);
}
