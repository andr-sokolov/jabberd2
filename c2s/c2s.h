/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <expat.h>
#include <stdbool.h>

#include "mio/mio.h"
#include "sx/sx.h"
#include "util/util.h"

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

/* forward declarations */
typedef struct host_st      *host_t;
typedef struct c2s_st       *c2s_t;
typedef struct bres_st      *bres_t;
typedef struct sess_st      *sess_t;

/** list of resources bound to session */
struct bres_st {
    /** full bound jid */
    jid_t               jid;
    /** session id for this jid for us and them */
    char                c2s_id[44], sm_id[41];
    /** this holds the id of the current pending SM request */
    char                sm_request[41];

    bres_t              next;
};

/**
 * There is one instance of this struct per user who is logged in to
 * this c2s instance.
 */
struct sess_st {
    c2s_t               c2s;

    mio_fd_t            fd;

    char                skey[44];

    const char          *smcomp; /* sm component servicing this session */

    const char          *ip;
    int                 port;

    sx_t                s;

    /** host this session belongs to */
    host_t              host;

    rate_t              rate;
    int                 rate_log;

    rate_t              stanza_rate;
    int                 stanza_rate_log;

    time_t              last_activity;
    unsigned int        packet_count;

    /* count of bound resources */
    int                 bound;
    /* list of bound jids */
    bres_t              resources;

    int                 active;

    /* session related packet waiting for sm response */
    nad_t               result;

    int                 sasl_authd;     /* 1 = they did a sasl auth */

    /** Apple: session challenge for challenge-response authentication */
    char                auth_challenge[65];

    /* Per user session authreg private data */
    void                *authreg_private;
};

/* allowed mechanisms */
#define AR_MECH_TRAD_PLAIN      (1<<0)
#define AR_MECH_TRAD_DIGEST     (1<<1)
#define AR_MECH_TRAD_CRAMMD5    (1<<2)

struct host_st {
    /** our realm (SASL) */
    const char          *realm;

    /** starttls pemfile */
    const char          *host_pemfile;

    /** certificate chain */
    const char          *host_cachain;

    /** private key password */
    char                *host_private_key_password;

    /** verify-mode  */
    int                 host_verify_mode;

    /** require starttls */
    int                 host_require_starttls;

    /** list of TLS ciphers */
    const char          *host_ciphers;
};

enum pws_crypt {
    MPC_PLAIN,
#ifdef HAVE_CRYPT
    MPC_CRYPT,
#endif
#ifdef HAVE_SSL
    MPC_A1HASH,
#endif
};

struct c2s_st {
    /** our id (hostname) with the router */
    const char          *id;

    /** how to connect to the router */
    const char          *router_ip;
    int                 router_port;
    const char          *router_user;
    const char          *router_pass;
    const char          *router_pemfile;
    const char          *router_cachain;
    const char          *router_private_key_password;
    const char          *router_ciphers;

    /** mio context */
    mio_t               mio;

    /** sessions */
    xht                 sessions;

    /** sx environment */
    sx_env_t            sx_env;
    sx_plugin_t         sx_ssl;
    sx_plugin_t         sx_sasl;

    /** router's conn */
    sx_t                router;
    mio_fd_t            fd;

    /** listening sockets */
    mio_fd_t            server_fd;
#ifdef HAVE_SSL
    mio_fd_t            server_ssl_fd;
#endif

    /** config */
    config_t            config;

    /** logging */
    log_t               log;

    /** log data */
    log_type_t          log_type;
    const char          *log_facility;
    const char          *log_ident;

    /** packet counter */
    long long int       packet_count;
    const char          *packet_stats;

    /** connect retry */
    int                 retry_init;
    int                 retry_lost;
    int                 retry_sleep;
    int                 retry_left;

    /** ip to listen on */
    const char          *local_ip;

    /** unencrypted port */
    int                 local_port;

    /** encrypted port */
    int                 local_ssl_port;

    /** encrypted port pemfile */
    const char          *local_pemfile;

    /** encrypted port cachain file */
    const char          *local_cachain;

    /** private key password */
    const char          *local_private_key_password;

    /** verify-mode  */
    int                 local_verify_mode;

    /** list of TLS ciphers */
    const char          *local_ciphers;

    /** http forwarding URL */
    const char          *http_forward;

    /** websocket support */
    int                 websocket;

    /** stream redirection (see-other-host) on session connect */
    xht                 stream_redirects;

    /** max file descriptors */
    int                 io_max_fds;

    /** enable Stream Compression */
    int                 compression;

    /** time checks */
    int                 io_check_interval;
    int                 io_check_idle;
    int                 io_check_keepalive;

    time_t              next_check;

    /** allowed mechanisms */
    int                 ar_mechanisms;
    int                 ar_ssl_mechanisms;

    /** connection rates */
    int                 conn_rate_total;
    int                 conn_rate_seconds;
    int                 conn_rate_wait;

    xht                 conn_rates;

    /** byte rates (karma) */
    int                 byte_rate_total;
    int                 byte_rate_seconds;
    int                 byte_rate_wait;

    /** stanza rates */
    int                 stanza_rate_total;
    int                 stanza_rate_seconds;
    int                 stanza_rate_wait;

    /** maximum stanza size */
    int                 stanza_size_limit;

    /** access controls */
    access_t            access;

    /** list of sx_t on the way out */
    jqueue_t            dead;

    /** list of sess on the way out */
    jqueue_t            dead_sess;

    /** this is true if we've connected to the router at least once */
    int                 started;

    /** true if we're bound in the router */
    int                 online;

    /** hosts mapping */
    xht                 hosts;
    host_t              vhost;

    /** availability of sms that we are servicing */
    xht                 sm_avail;

    const char          *authreg_filename;
    enum pws_crypt      password_type;
};

extern sig_atomic_t c2s_lost_router;

int         c2s_router_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg);
int         c2s_router_sx_callback(sx_t s, sx_event_t e, void *data, void *arg);

void        sm_start(sess_t sess, bres_t res);
void        sm_end(sess_t sess, bres_t res);
void        sm_create(sess_t sess, bres_t res);
void        sm_delete(sess_t sess, bres_t res);
void        sm_packet(sess_t sess, bres_t res, nad_t nad);

int         bind_init(sx_env_t env, sx_plugin_t p, va_list args);

/* My IP Address plugin */
int    address_init(sx_env_t env, sx_plugin_t p, va_list args);

/** get a handle for the plain module */
bool   authreg_init(c2s_t c2s);

/** the main authreg processor */
int         authreg_process(c2s_t c2s, sess_t sess, nad_t nad);

bool authreg_user_exists(c2s_t c2s, const char *username);
bool authreg_get_password(c2s_t c2s, const char *username, char password[257]);
bool authreg_check_password(c2s_t c2s, const char *username, const char *realm, char password[257]);

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  const char **char_val;
  sess_t *sess_val;
};

// Data for stream redirect errors
typedef struct stream_redirect_st
{
    const char *to_address;
    const char *to_port;
} *stream_redirect_t;
