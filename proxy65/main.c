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

#include <unistd.h>

static sig_atomic_t proxy65_shutdown = 0;
sig_atomic_t proxy65_lost_router = 0;
static sig_atomic_t proxy65_logrotate = 0;

static void _proxy65_signal(int signum) {
    proxy65_shutdown = 1;
    proxy65_lost_router = 0;
}

static void _proxy65_signal_hup(int signum) {
    proxy65_logrotate = 1;
}

static void _proxy65_signal_usr1(int signum) {
    set_debug_flag(0);
}

static void _proxy65_signal_usr2(int signum) {
    set_debug_flag(1);
}

static void _proxy65_pidfile(proxy65_t p) {
    const char *pidfile = config_get_one(p->config, "pidfile", 0);
    if(pidfile == NULL)
        return;

    pid_t pid = getpid();

    FILE *f = fopen(pidfile, "w+");
    if(f == NULL) {
        log_write(p->log, LOG_ERR, "couldn't open %s for writing: %s", pidfile, strerror(errno));
        return;
    }

    if(fprintf(f, "%d", pid) < 0) {
        log_write(p->log, LOG_ERR, "couldn't write to %s: %s", pidfile, strerror(errno));
        fclose(f);
        return;
    }

    fclose(f);
    log_write(p->log, LOG_INFO, "process id is %d, written to %s", pid, pidfile);
}

static void _proxy65_config_expand(proxy65_t p) {
    set_debug_log_from_config(p->config);

    p->id = config_get_one(p->config, "id", 0);
    if(p->id == NULL)
        p->id = "proxy.localhost.localdomain";

    p->router_ip = config_get_one(p->config, "router.ip", 0);
    if(p->router_ip == NULL)
        p->router_ip = "127.0.0.1";

    p->router_port = j_atoi(config_get_one(p->config, "router.port", 0), 5347);

    p->router_user = config_get_one(p->config, "router.user", 0);
    if(p->router_user == NULL)
        p->router_user = "jabberd";
    p->router_pass = config_get_one(p->config, "router.pass", 0);
    if(p->router_pass == NULL)
        p->router_pass = "secret";

    p->router_pemfile = config_get_one(p->config, "router.pemfile", 0);
    p->router_cachain = config_get_one(p->config, "router.cachain", 0);
    p->router_private_key_password = config_get_one(p->config, "router.private_key_password", 0);
    p->router_ciphers = config_get_one(p->config, "router.ciphers", 0);

    p->retry_init = j_atoi(config_get_one(p->config, "router.retry.init", 0), 3);
    p->retry_lost = j_atoi(config_get_one(p->config, "router.retry.lost", 0), 3);
    if((p->retry_sleep = j_atoi(config_get_one(p->config, "router.retry.sleep", 0), 2)) < 1)
        p->retry_sleep = 1;

    p->log_type = log_STDOUT;
    if(config_get(p->config, "log") != NULL) {
        char *str = config_get_attr(p->config, "log", 0, "type");
        if(str != NULL) {
            if(strcmp(str, "file") == 0)
                p->log_type = log_FILE;
            else if(strcmp(str, "syslog") == 0)
                p->log_type = log_SYSLOG;
        }
    }

    if(p->log_type == log_SYSLOG) {
        p->log_facility = config_get_one(p->config, "log.facility", 0);
        p->log_ident = config_get_one(p->config, "log.ident", 0);
        if(p->log_ident == NULL)
            p->log_ident = "jabberd/proxy65";
    } else if(p->log_type == log_FILE)
        p->log_ident = config_get_one(p->config, "log.file", 0);

    p->local_ip = config_get_one(p->config, "local.ip", 0);
    if(p->local_ip == NULL)
        p->local_ip = "0.0.0.0";

    p->local_port = j_atoi(config_get_one(p->config, "local.port", 0), 7777);

    p->local_host = config_get_one(p->config, "local.host", 0);
    if(p->local_host == NULL)
        p->local_host = "127.0.0.1";

    p->io_max_fds = j_atoi(config_get_one(p->config, "io.max_fds", 0), 1024);
}

static int _proxy65_router_connect(proxy65_t p) {
    log_write(p->log, LOG_NOTICE, "attempting connection to router at %s, port=%d", p->router_ip, p->router_port);

    p->fd = mio_connect(p->mio, p->router_port, p->router_ip, NULL, proxy65_router_mio_callback, (void *) p);
    if(p->fd == NULL) {
        if(errno == ECONNREFUSED)
            proxy65_lost_router = 1;
        log_write(p->log, LOG_NOTICE, "connection attempt to router failed: %s (%d)", strerror(errno), errno);
        return 1;
    }

    p->router = sx_new(p->sx_env, p->fd->fd, proxy65_router_sx_callback, (void *) p);
    sx_client_init(p->router, 0, NULL, NULL, NULL, "1.0");

    return 0;
}

void proxy65_hash_sid(const char *sid, const char *requester, const char *target,
                      char out_hex[PROXY65_HASH_HEX_LEN + 1]) {
    sha1_state_t ctx;
    sha1_init(&ctx);
    sha1_append(&ctx, (const unsigned char *) sid, strlen(sid));
    sha1_append(&ctx, (const unsigned char *) requester, strlen(requester));
    sha1_append(&ctx, (const unsigned char *) target, strlen(target));

    unsigned char digest[20];
    sha1_finish(&ctx, digest);
    hex_from_raw(digest, 20, out_hex);
    out_hex[PROXY65_HASH_HEX_LEN] = '\0';
}

JABBER_MAIN("jabberd2proxy65", "Jabber 2 SOCKS5 Bytestreams Proxy", "Jabber Open Source Server: XEP-0065 proxy", "jabberd2router\0")
{
#ifdef HAVE_UMASK
    umask((mode_t) 0027);
#endif

    srand(time(NULL));

    jabber_signal(SIGINT, _proxy65_signal);
    jabber_signal(SIGTERM, _proxy65_signal);
#ifdef SIGHUP
    jabber_signal(SIGHUP, _proxy65_signal_hup);
#endif
#ifdef SIGPIPE
    jabber_signal(SIGPIPE, SIG_IGN);
#endif
    jabber_signal(SIGUSR1, _proxy65_signal_usr1);
    jabber_signal(SIGUSR2, _proxy65_signal_usr2);

    proxy65_t p = (proxy65_t) calloc(1, sizeof(struct proxy65_st));
    p->config = config_new();

    char *config_file = CONFIG_DIR "/proxy65.xml";
    const char *cli_id = 0;

    for(int optchar; (optchar = getopt(argc, argv, "Dc:hi:?")) >= 0; ) {
        switch(optchar) {
            case 'c':
                config_file = optarg;
                break;
            case 'D':
#ifdef DEBUG
                set_debug_flag(1);
#else
                printf("WARN: Debugging not enabled.  Ignoring -D.\n");
#endif
                break;
            case 'i':
                cli_id = optarg;
                break;
            case 'h': case '?': default:
                fputs(
                    "proxy65 - jabberd SOCKS5 Bytestreams proxy (" VERSION ")\n"
                    "Usage: proxy65 <options>\n"
                    "Options are:\n"
                    "   -c <config>     config file to use [default: " CONFIG_DIR "/proxy65.xml]\n"
                    "   -i id           Override <id> config element\n"
#ifdef DEBUG
                    "   -D              Show debug output\n"
#endif
                    ,
                    stdout);
                config_free(p->config);
                free(p);
                return 1;
        }
    }

    if(config_load_with_id(p->config, config_file, cli_id) != 0) {
        fputs("proxy65: couldn't load config, aborting\n", stderr);
        config_free(p->config);
        free(p);
        return 2;
    }

    _proxy65_config_expand(p);

    p->log = log_new(p->log_type, p->log_ident, p->log_facility);
    log_write(p->log, LOG_NOTICE, "starting up (id=%s, socks=%s:%d, advertise=%s)",
              p->id, p->local_ip, p->local_port, p->local_host);

    _proxy65_pidfile(p);

    p->streams = xhash_new(401);
    p->dead = jqueue_new();

    p->sx_env = sx_env_new();

#ifdef HAVE_SSL
    if(p->router_pemfile != NULL) {
        p->sx_ssl = sx_env_plugin(p->sx_env, sx_ssl_init, NULL, p->router_pemfile, p->router_cachain, NULL, p->router_private_key_password, p->router_ciphers);
        if(p->sx_ssl == NULL) {
            log_write(p->log, LOG_ERR, "failed to load router SSL pemfile, channel to router will not be SSL encrypted");
            p->router_pemfile = NULL;
        }
    }
#endif

    p->sx_sasl = sx_env_plugin(p->sx_env, sx_sasl_init, "xmpp", NULL, NULL);
    if(p->sx_sasl == NULL) {
        log_write(p->log, LOG_ERR, "failed to initialise SASL context, aborting");
        exit(1);
    }

    p->mio = mio_new(p->io_max_fds);

    p->retry_left = p->retry_init;
    _proxy65_router_connect(p);

    time_t last_expire = 0;
    while(!proxy65_shutdown) {
        mio_run(p->mio, 5);

        time_t now = time(NULL);

        if(proxy65_logrotate) {
            set_debug_log_from_config(p->config);
            log_write(p->log, LOG_NOTICE, "reopening log ...");
            log_free(p->log);
            p->log = log_new(p->log_type, p->log_ident, p->log_facility);
            log_write(p->log, LOG_NOTICE, "log started");
            proxy65_logrotate = 0;
        }

        if(proxy65_lost_router) {
            if(p->retry_left < 0) {
                log_write(p->log, LOG_NOTICE, "attempting reconnect");
                sleep(p->retry_sleep);
                proxy65_lost_router = 0;
                if(p->router) sx_free(p->router);
                _proxy65_router_connect(p);
            } else if(p->retry_left == 0) {
                proxy65_shutdown = 1;
            } else {
                log_write(p->log, LOG_NOTICE, "attempting reconnect (%d left)", p->retry_left);
                p->retry_left--;
                sleep(p->retry_sleep);
                proxy65_lost_router = 0;
                if(p->router) sx_free(p->router);
                _proxy65_router_connect(p);
            }
        }

        while(jqueue_size(p->dead) > 0)
            sx_free((sx_t) jqueue_pull(p->dead));

        if(now >= last_expire + 30) {
            proxy65_socks_expire(p);
            last_expire = now;
        }
    }

    log_write(p->log, LOG_NOTICE, "shutting down");

    if(p->server_fd != NULL)
        mio_close(p->mio, p->server_fd);
    if(p->fd != NULL)
        mio_close(p->mio, p->fd);

    while(jqueue_size(p->dead) > 0)
        sx_free((sx_t) jqueue_pull(p->dead));

    /* close remaining bytestreams */
    while(xhash_iter_first(p->streams)) {
        bytestream_t bs = NULL;
        xhash_iter_get(p->streams, NULL, NULL, (void **) &bs);
        if(bs != NULL)
            proxy65_stream_free(p, bs);
        else
            xhash_iter_zap(p->streams);
    }

    xhash_free(p->streams);
    jqueue_free(p->dead);

    if(p->router)
        sx_free(p->router);
    sx_env_free(p->sx_env);
    mio_free(p->mio);
    log_free(p->log);
    config_free(p->config);
    free(p);

    return 0;
}
