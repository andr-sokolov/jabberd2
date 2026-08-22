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

#include "c2s.h"
#include <stringprep.h>
#include <dlfcn.h>

/* authreg module manager */

typedef struct _authreg_error_st {
    char        *class;
    char        *name;
    char        *code;
    char        *uri;
} *authreg_error_t;

/** auth logger */
inline static void _authreg_auth_log(c2s_t c2s, sess_t sess, const char *method, const char *username, const char *resource, int success) {
    log_write(c2s->log, LOG_NOTICE, "[%d] %s authentication %s: %s@%s/%s %s:%d %s",
        sess->s->tag, method, success ? "succeeded" : "failed",
        username, sess->host->realm, resource,
        sess->s->ip, sess->s->port, _sx_flags(sess->s)
    );
}

/** auth get handler */
static void _authreg_auth_get(c2s_t c2s, sess_t sess, nad_t nad) {
    int ns, elem, attr, err;
    char username[1024], id[128];
    int ar_mechs;

    /* can't auth if they're active */
    if(sess->active) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    /* sort out the username */
    ns = nad_find_scoped_namespace(nad, uri_AUTH, NULL);
    elem = nad_find_elem(nad, 1, ns, "username", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "auth get with no username, bouncing it");

        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));

        return;
    }

    snprintf(username, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
    if(stringprep_xmpp_nodeprep(username, 1024) != 0) {
        log_debug(ZONE, "auth get username failed nodeprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }

    ar_mechs = c2s->ar_mechanisms;
    if (sess->s->ssf>0) 
        ar_mechs = ar_mechs | c2s->ar_ssl_mechanisms;
        
    /* no point going on if we have no mechanisms */
    if(!(ar_mechs & (AR_MECH_TRAD_PLAIN | AR_MECH_TRAD_DIGEST | AR_MECH_TRAD_CRAMMD5))) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_FORBIDDEN), 0));
        return;
    }
    
    /* do we have the user? */
    if(!authreg_user_exists(c2s, username)) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));
        return;
    }

    /* extract the id */
    attr = nad_find_attr(nad, 0, -1, "id", NULL);
    if(attr >= 0)
        snprintf(id, 128, "%.*s", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));

    nad_free(nad);

    /* build a result packet */
    nad = nad_new();

    ns = nad_add_namespace(nad, uri_CLIENT, NULL);

    nad_append_elem(nad, ns, "iq", 0);
    nad_append_attr(nad, -1, "type", "result");

    if(attr >= 0)
        nad_append_attr(nad, -1, "id", id);

    ns = nad_add_namespace(nad, uri_AUTH, NULL);
    nad_append_elem(nad, ns, "query", 1);
    
    nad_append_elem(nad, ns, "username", 2);
    nad_append_cdata(nad, username, strlen(username), 3);

    nad_append_elem(nad, ns, "resource", 2);

    /* fill out the packet with available auth mechanisms */
    if(ar_mechs & AR_MECH_TRAD_PLAIN)
        nad_append_elem(nad, ns, "password", 2);

    if(ar_mechs & AR_MECH_TRAD_DIGEST)
        nad_append_elem(nad, ns, "digest", 2);

    /* give it back to the client */
    sx_nad_write(sess->s, nad);

    return;
}

/** auth set handler */
static void _authreg_auth_set(c2s_t c2s, sess_t sess, nad_t nad) {
    int ns, elem, attr, authd = 0;
    char username[1024], resource[1024], str[1024], hash[280];
    int ar_mechs;

    /* can't auth if they're active */
    if(sess->active) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
        return;
    }

    ns = nad_find_scoped_namespace(nad, uri_AUTH, NULL);

    /* sort out the username */
    elem = nad_find_elem(nad, 1, ns, "username", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "auth set with no username, bouncing it");

        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));

        return;
    }

    snprintf(username, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
    if(stringprep_xmpp_nodeprep(username, 1024) != 0) {
        log_debug(ZONE, "auth set username failed nodeprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }

    /* make sure we have the resource */
    elem = nad_find_elem(nad, 1, ns, "resource", 1);
    if(elem < 0)
    {
        log_debug(ZONE, "auth set with no resource, bouncing it");

        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));

        return;
    }

    snprintf(resource, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
    if(stringprep_xmpp_resourceprep(resource, 1024) != 0) {
        log_debug(ZONE, "auth set resource failed resourceprep, bouncing it");
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_JID_MALFORMED), 0));
        return;
    }

    ar_mechs = c2s->ar_mechanisms;
    if (sess->s->ssf > 0)
        ar_mechs = ar_mechs | c2s->ar_ssl_mechanisms;
    
    /* no point going on if we have no mechanisms */
    if(!(ar_mechs & (AR_MECH_TRAD_PLAIN | AR_MECH_TRAD_DIGEST | AR_MECH_TRAD_CRAMMD5))) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_FORBIDDEN), 0));
        return;
    }
    
    /* do we have the user? */
    if(!authreg_user_exists(c2s, username)) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));
        return;
    }

    /* digest auth */
    if(!authd && ar_mechs & AR_MECH_TRAD_DIGEST)
    {
        elem = nad_find_elem(nad, 1, ns, "digest", 1);
        if(elem >= 0)
        {
            if(authreg_get_password(c2s, username, str))
            {
                snprintf(hash, 280, "%s%s", sess->s->id, str);
                shahash_r(hash, hash);

                if(strlen(hash) == NAD_CDATA_L(nad, elem) && strncmp(hash, NAD_CDATA(nad, elem), NAD_CDATA_L(nad, elem)) == 0)
                {
                    log_debug(ZONE, "digest auth succeeded");
                    authd = 1;
                    _authreg_auth_log(c2s, sess, "traditional.digest", username, resource, TRUE);
                } else {
                    _authreg_auth_log(c2s, sess, "traditional.digest", username, resource, FALSE);
                }
            }
        }
    }

    /* plaintext auth (compare) */
    if(!authd && ar_mechs & AR_MECH_TRAD_PLAIN)
    {
        elem = nad_find_elem(nad, 1, ns, "password", 1);
        if(elem >= 0)
        {
            if(authreg_get_password(c2s, username, str) &&
                    strlen(str) == NAD_CDATA_L(nad, elem) && strncmp(str, NAD_CDATA(nad, elem), NAD_CDATA_L(nad, elem)) == 0)
            {
                log_debug(ZONE, "plaintext auth (compare) succeeded");
                authd = 1;
                _authreg_auth_log(c2s, sess, "traditional.plain(compare)", username, resource, TRUE);
            } else {
                _authreg_auth_log(c2s, sess, "traditional.plain(compare)", username, resource, FALSE);
            }
        }
    }

    /* plaintext auth (check) */
    if(!authd && ar_mechs & AR_MECH_TRAD_PLAIN)
    {
        elem = nad_find_elem(nad, 1, ns, "password", 1);
        if(elem >= 0)
        {
            snprintf(str, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
            if(authreg_check_password(c2s, username, sess->host->realm, str))
            {
                log_debug(ZONE, "plaintext auth (check) succeded");
                authd = 1;
                _authreg_auth_log(c2s, sess, "traditional.plain", username, resource, TRUE);
            } else {
                _authreg_auth_log(c2s, sess, "traditional.plain", username, resource, FALSE);
            }
        }
    }

    /* now, are they authenticated? */
    if(authd)
    {
        /* create new bound jid holder */
        if(sess->resources == NULL) {
            sess->resources = (bres_t) calloc(1, sizeof(struct bres_st));
        }

        /* our local id */
        sprintf(sess->resources->c2s_id, "%d", sess->s->tag);

        /* the full user jid for this session */
        sess->resources->jid = jid_new(sess->s->req_to, -1);
        jid_reset_components(sess->resources->jid, username, sess->resources->jid->domain, resource);

        log_write(sess->c2s->log, LOG_NOTICE, "[%d] requesting session: jid=%s", sess->s->tag, jid_full(sess->resources->jid));

        /* build a result packet, we'll send this back to the client after we have a session for them */
        sess->result = nad_new();

        ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

        nad_append_elem(sess->result, ns, "iq", 0);
        nad_set_attr(sess->result, 0, -1, "type", "result", 6);

        attr = nad_find_attr(nad, 0, -1, "id", NULL);
        if(attr >= 0)
            nad_set_attr(sess->result, 0, -1, "id", NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

        /* start a session with the sm */
        sm_start(sess, sess->resources);

        /* finished with the nad */
        nad_free(nad);

        return;
    }

    _authreg_auth_log(c2s, sess, "traditional", username, resource, FALSE);

    /* auth failed, so error */
    sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));

    return;
}

/**
 * processor for iq:auth and iq:register packets
 * return 0 if handled, 1 if not handled
 */
int authreg_process(c2s_t c2s, sess_t sess, nad_t nad) {
    int ns, query, type, authreg = -1, getset = -1;

    /* need iq */
    if(NAD_ENAME_L(nad, 0) != 2 || strncmp("iq", NAD_ENAME(nad, 0), 2) != 0)
        return 1;

    /* only want auth or register packets */
    if((ns = nad_find_scoped_namespace(nad, uri_AUTH, NULL)) >= 0 && (query = nad_find_elem(nad, 0, ns, "query", 1)) >= 0)
        authreg = 0;
    else if((ns = nad_find_scoped_namespace(nad, uri_REGISTER, NULL)) >= 0 && (query = nad_find_elem(nad, 0, ns, "query", 1)) >= 0)
        authreg = 1;
    else
        return 1;

    /* if its to someone else, pass it */
    if(nad_find_attr(nad, 0, -1, "to", NULL) >= 0 && nad_find_attr(nad, 0, -1, "to", sess->s->req_to) < 0)
        return 1;

    /* need a type */
    if((type = nad_find_attr(nad, 0, -1, "type", NULL)) < 0 || NAD_AVAL_L(nad, type) != 3)
    {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));
        return 0;
    }

    /* get or set? */
    if(strncmp("get", NAD_AVAL(nad, type), NAD_AVAL_L(nad, type)) == 0)
        getset = 0;
    else if(strncmp("set", NAD_AVAL(nad, type), NAD_AVAL_L(nad, type)) == 0)
        getset = 1;
    else
    {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_BAD_REQUEST), 0));
        return 0;
    }

    /* hand to the correct handler */
    if(authreg == 0) {
        /* can't do iq:auth after sasl auth */
        if(sess->sasl_authd) {
            sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));
            return 0;
        }

        if(getset == 0) {
            log_debug(ZONE, "auth get");
            _authreg_auth_get(c2s, sess, nad);
        } else if(getset == 1) {
            log_debug(ZONE, "auth set");
            _authreg_auth_set(c2s, sess, nad);
        }
    } else if (authreg == 1)
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_NOT_ALLOWED), 0));

    /* handled */
    return 0;
}



////////////////////


#define _XOPEN_SOURCE 500

#include <string.h>

#ifdef HAVE_CRYPT
#include <crypt.h>
#endif

#ifdef HAVE_SSL
/* We use OpenSSL's MD5 routines for the a1hash password type */
#include <openssl/md5.h>
#endif

#define PLAIN_LU  1024   /* maximum length of username */
#define PLAIN_LR   256   /* maximum length of realm */
#define PLAIN_LP   256   /* maximum length of password */
#define PLAIN_MAX_INDENT  64   /* leading tabs for group nesting */

#ifdef HAVE_CRYPT
static char salter[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./";
#endif

#ifdef HAVE_SSL
static void calc_a1hash(const char *username, const char *realm, const char *password, char *a1hash)
{
#define A1PPASS_LEN PLAIN_LU + 1 + PLAIN_LR + 1 + PLAIN_LP + 1 /* user:realm:password\0 */
    char buf[A1PPASS_LEN];
    unsigned char md5digest[MD5_DIGEST_LENGTH];
    int i;

    snprintf(buf, A1PPASS_LEN, "%.*s:%.*s:%.*s", PLAIN_LU, username, PLAIN_LR, realm, PLAIN_LP, password);

    MD5((unsigned char*)buf, strlen(buf), md5digest);

    for(i=0; i<16; i++) {
        sprintf(a1hash+i*2, "%02hhx", md5digest[i]);
    }
}
#endif

/**
 * Look up username in a tab-indented hierarchy file.
 * Leading tabs are nesting indent. After indent: two columns (tab-separated)
 * are login and password; one column is a group at that level (skipped).
 * Nesting depth is arbitrary; groups may be omitted entirely.
 * @return true if found, false if not
 */
static bool
_ar_plain_lookup(c2s_t c2s, const char *username, char *password_out)
{
    bool found = false;

    if (username == NULL || c2s->authreg_filename == NULL)
        return 0;

    FILE *fp = fopen(c2s->authreg_filename, "r");
    if (fp == NULL) {
        log_write(c2s->log, LOG_ERR, "authreg: can't open %s", c2s->authreg_filename);
        return 0;
    }

    size_t userlen = strlen(username);

    char line[PLAIN_MAX_INDENT + PLAIN_LU + 1 + PLAIN_LP + 8];
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p;
        char *tab;
        char *nl;
        size_t login_len;

        nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        nl = strchr(line, '\r');
        if (nl)
            *nl = '\0';

        p = line;
        while (*p == '\t')
            p++;

        if (*p == '\0')
            continue;

        tab = strchr(p, '\t');
        if (tab == NULL)
            continue;

        login_len = (size_t)(tab - p);
        if (login_len == 0)
            continue;

        if (login_len != userlen || strncmp(p, username, userlen) != 0)
            continue;

        found = true;
        if (password_out != NULL) {
            strncpy(password_out, tab + 1, 256);
            password_out[256] = '\0';
        }
        break;
    }

    fclose(fp);
    return found;
}

/**
 * @return true if the user exists, false if not
 */
bool authreg_user_exists(c2s_t c2s, const char *username)
{
    return _ar_plain_lookup(c2s, username, NULL);
}

/**
 * @return true is password is populated, false if not
 */
bool authreg_get_password(c2s_t c2s, const char *username, char password[257])
{
    return _ar_plain_lookup(c2s, username, password);
}

/**
 * @return true if the given password matches the password stored in the file, false if not
 */
bool authreg_check_password(c2s_t c2s, const char *username, const char *realm, char password[257])
{
    char db_pw_value[257];
    if (!authreg_get_password(c2s, username, db_pw_value))
        return false;

    switch (c2s->password_type) {
        case MPC_PLAIN:
                return (strcmp (password, db_pw_value) == 0);

#ifdef HAVE_CRYPT
        case MPC_CRYPT:
        {
                char *crypted_pw = crypt(password,db_pw_value);
                return (strcmp(crypted_pw, db_pw_value) == 0);
        }
#endif

#ifdef HAVE_SSL
        case MPC_A1HASH:
        {
                if (strchr(username, ':')) {
                    log_write(c2s->log, LOG_ERR, "Username cannot contain : with a1hash encryption type.");
                    return false;
                }
                if (strchr(realm, ':')) {
                    log_write(c2s->log, LOG_ERR, "Realm cannot contain : with a1hash encryption type.");
                    return false;
                }

                char a1hash_pw[33];
                calc_a1hash(username, realm, password, a1hash_pw);
                return (strncmp(a1hash_pw, db_pw_value, 32) == 0);
        }
#endif

        default:
        /* should never happen */
                log_write(c2s->log, LOG_ERR, "Unknown encryption type which passed through config check.");
                return false;
    }
}

/** get a handle for the plain module */
bool authreg_init(c2s_t c2s) {
    c2s->authreg_filename = config_get_one(c2s->config, "authreg.filename", 0);

    if (c2s->authreg_filename == NULL) {
        log_write(c2s->log, LOG_ERR, "authreg.filename is not set");
        return false;
    }

    FILE *fp = fopen(c2s->authreg_filename, "r");
    if (fp == NULL) {
        log_write(c2s->log, LOG_ERR, "can't open %s", c2s->authreg_filename);
        return false;
    }
    fclose(fp);

    /* get encryption type used in the password file */
    if (config_get_one(c2s->config, "authreg.password_type.plaintext", 0)) {
        c2s->password_type = MPC_PLAIN;
#ifdef HAVE_CRYPT
    } else if (config_get_one(c2s->config, "authreg.password_type.crypt", 0)) {
        c2s->password_type = MPC_CRYPT;
#endif
#ifdef HAVE_SSL
    } else if (config_get_one(c2s->config, "authreg.password_type.a1hash", 0)) {
        c2s->password_type = MPC_A1HASH;
#endif
    } else {
        c2s->password_type = MPC_PLAIN;
    }

    return true;
}
