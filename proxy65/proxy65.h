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

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include "mio/mio.h"
#include "sx/sx.h"

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

typedef struct proxy65_st       *proxy65_t;
typedef struct sock_conn_st     *sock_conn_t;
typedef struct bytestream_st    *bytestream_t;

#define PROXY65_HASH_HEX_LEN    40
#define PROXY65_RELAY_BUF       8192
#define PROXY65_SOCK_IDLE       300

typedef enum {
    sock_GREETING = 0,
    sock_REQUEST,
    sock_CONNECTED,
    sock_RELAY
} sock_state_t;

struct sock_conn_st {
    proxy65_t           p;
    mio_fd_t            fd;
    sock_state_t        state;

    unsigned char       rbuf[512];
    int                 rlen;

    char                hash[PROXY65_HASH_HEX_LEN + 1];
    bytestream_t        bs;

    /* pending write buffer for relay */
    unsigned char       *wbuf;
    int                 wlen;
    int                 woff;

    time_t              last_activity;
};

struct bytestream_st {
    char                hash[PROXY65_HASH_HEX_LEN + 1];
    char                sid[256];
    sock_conn_t         peers[2];
    int                 npeers;
    int                 activated;
    time_t              created;
};

struct proxy65_st {
    const char          *id;

    const char          *router_ip;
    int                 router_port;
    const char          *router_user;
    const char          *router_pass;
    const char          *router_pemfile;
    const char          *router_cachain;
    const char          *router_private_key_password;
    const char          *router_ciphers;

    mio_t               mio;
    sx_env_t            sx_env;
    sx_plugin_t         sx_ssl;
    sx_plugin_t         sx_sasl;

    sx_t                router;
    mio_fd_t            fd;
    mio_fd_t            server_fd;

    config_t            config;
    log_t               log;
    log_type_t          log_type;
    const char          *log_facility;
    const char          *log_ident;

    int                 retry_init;
    int                 retry_lost;
    int                 retry_sleep;
    int                 retry_left;

    const char          *local_ip;
    int                 local_port;
    const char          *local_host;    /* advertised streamhost host */

    int                 io_max_fds;

    int                 started;
    int                 online;

    xht                 streams;        /* hash -> bytestream_t */
    jqueue_t            dead;
};

extern sig_atomic_t proxy65_lost_router;

int     proxy65_router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);
int     proxy65_router_sx_callback(sx_t s, sx_event_t e, void *data, void *arg);

void    proxy65_iq_handle(proxy65_t p, nad_t nad);

int     proxy65_socks_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);
void    proxy65_socks_listen(proxy65_t p);
void    proxy65_socks_activate(proxy65_t p, const char *hash, const char *sid);
bytestream_t proxy65_stream_get(proxy65_t p, const char *hash);
void    proxy65_stream_free(proxy65_t p, bytestream_t bs);
void    proxy65_socks_expire(proxy65_t p);

void    proxy65_hash_sid(const char *sid, const char *requester, const char *target,
                         char out_hex[PROXY65_HASH_HEX_LEN + 1]);
void    proxy65_route_reply(proxy65_t p, nad_t nad);
void    proxy65_route_error(proxy65_t p, nad_t nad, int err);
