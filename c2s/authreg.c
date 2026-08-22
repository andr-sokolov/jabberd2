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

int ar_init(authreg_t ar);

/** get a handle for the plain module */
authreg_t authreg_init(c2s_t c2s) {
    /* make a new one */
    authreg_t ar = (authreg_t) calloc(1, sizeof(*ar));
    if(!ar) {
        log_write(c2s->log, LOG_ERR, "cannot allocate memory for new authreg, aborting");
        exit(1);
    }

    ar->c2s = c2s;

    /* call the initialiser */
    if(ar_init(ar) != 0)
    {
        log_write(c2s->log, LOG_ERR, "failed to initialize auth module 'plain'");
        authreg_free(ar);
        return NULL;
    }
    
    /* its good */
    ar->initialized = TRUE;
    log_write(c2s->log, LOG_NOTICE, "initialized auth module 'plain'");

    return ar;
}

/** shutdown the authreg system */
void authreg_free(authreg_t ar) {
    if (ar && ar->initialized) {
        if(ar->free != NULL) (ar->free)(ar);
    }
}

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
    if((c2s->ar->user_exists)(c2s->ar, sess, username, sess->host->realm) == 0) {
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
    if(ar_mechs & AR_MECH_TRAD_PLAIN && (c2s->ar->get_password != NULL || c2s->ar->check_password != NULL))
        nad_append_elem(nad, ns, "password", 2);

    if(ar_mechs & AR_MECH_TRAD_DIGEST && c2s->ar->get_password != NULL)
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
    if((c2s->ar->user_exists)(c2s->ar, sess, username, sess->host->realm) == 0) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));
        return;
    }

    /* digest auth */
    if(!authd && ar_mechs & AR_MECH_TRAD_DIGEST && c2s->ar->get_password != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "digest", 1);
        if(elem >= 0)
        {
            if((c2s->ar->get_password)(c2s->ar, sess, username, sess->host->realm, str) == 0)
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
    if(!authd && ar_mechs & AR_MECH_TRAD_PLAIN && c2s->ar->get_password != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "password", 1);
        if(elem >= 0)
        {
            if((c2s->ar->get_password)(c2s->ar, sess, username, sess->host->realm, str) == 0 &&
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
    if(!authd && ar_mechs & AR_MECH_TRAD_PLAIN && c2s->ar->check_password != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "password", 1);
        if(elem >= 0)
        {
            snprintf(str, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
            if((c2s->ar->check_password)(c2s->ar, sess, username, sess->host->realm, str) == 0)
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

enum pws_crypt {
    MPC_PLAIN,
#ifdef HAVE_CRYPT
    MPC_CRYPT,
#endif
#ifdef HAVE_SSL
    MPC_A1HASH,
#endif
};

#ifdef HAVE_CRYPT
static char salter[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./";
#endif

typedef struct moddata_st {
    char *filename;
    enum pws_crypt password_type;
} *moddata_t;

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
 * @return 1 if found, 0 if not
 */
static int
_ar_plain_lookup(authreg_t ar, const char *username, char *password_out)
{
    FILE *fp;
    char line[PLAIN_MAX_INDENT + PLAIN_LU + 1 + PLAIN_LP + 8];
    moddata_t data = (moddata_t) ar->private;
    size_t userlen;
    int found = 0;

    if (username == NULL || data == NULL || data->filename == NULL)
        return 0;

    fp = fopen(data->filename, "r");
    if (fp == NULL) {
        log_write(ar->c2s->log, LOG_ERR, "plain (authreg): can't open %s", data->filename);
        return 0;
    }

    userlen = strlen(username);

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

        found = 1;
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
 * @return 1 if the user exists, 0 if not
 */
static int
_ar_plain_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    int ret;

    (void) sess;
    (void) realm;

    log_debug(ZONE, "plain (authreg): user exists");

    ret = _ar_plain_lookup(ar, username, NULL);
    log_debug(ZONE, "plain (authreg): user exists : %s", ret ? "yes" : "no");
    return ret;
}

/**
 * @return 0 is password is populated, 1 if not
 */
static int
_ar_plain_get_password(authreg_t ar, sess_t sess, const char *username, const char *realm,
            char password[257])
{
    (void) sess;
    (void) realm;

    log_debug(ZONE, "plain (authreg): get password");

    if (!_ar_plain_lookup(ar, username, password))
        return 1;
    return 0;
}

/**
 * @return 0 if the given password matches the password stored in the file, !0 if not
 */
static int
_ar_plain_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm,
              char password[257])
{

    char db_pw_value[257];
#ifdef HAVE_CRYPT
    char *crypted_pw;
#endif
#ifdef HAVE_SSL
    char a1hash_pw[33];
#endif
    moddata_t data = (moddata_t) ar->private;
    int ret=1;

    log_debug(ZONE, "plain (authreg): check password");

    ret = _ar_plain_get_password(ar, sess, username, realm, db_pw_value);
    if (ret)
        return ret;

    switch (data->password_type) {
        case MPC_PLAIN:
                ret = (strcmp (password, db_pw_value) != 0);
                break;

#ifdef HAVE_CRYPT
        case MPC_CRYPT:
                crypted_pw = crypt(password,db_pw_value);
                ret = (strcmp(crypted_pw, db_pw_value) != 0);
                break;
#endif

#ifdef HAVE_SSL
        case MPC_A1HASH:
                if (strchr(username, ':')) {
                    ret = 1;
                    log_write(ar->c2s->log, LOG_ERR, "Username cannot contain : with a1hash encryption type.");
                    break;
                }
                if (strchr(realm, ':')) {
                    ret = 1;
                    log_write(ar->c2s->log, LOG_ERR, "Realm cannot contain : with a1hash encryption type.");
                    break;
                }
                calc_a1hash(username, realm, password, a1hash_pw);
                ret = (strncmp(a1hash_pw, db_pw_value, 32) != 0);
                break;
#endif

        default:
        /* should never happen */
                ret = 1;
                log_write(ar->c2s->log, LOG_ERR, "Unknown encryption type which passed through config check.");
                break;
    }

    return ret;
}

/**
 * @return does not return
 */
static void
_ar_plain_free(authreg_t ar)
{
    moddata_t data = (moddata_t) ar->private;

    log_debug(ZONE, "plain (authreg): free");

    if (data) {
        free(data->filename);
        free(data);
    }
}

int
ar_init(authreg_t ar)
{
    const char *filename = config_get_one(ar->c2s->config, "authreg.filename", 0);

    log_debug(ZONE, "plain (authreg): start init");

    if (filename == NULL) {
        log_write(ar->c2s->log, LOG_ERR,
              "plain (authreg): invalid driver config.");
        return 1;
    }

    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        log_write(ar->c2s->log, LOG_ERR,
              "plain (authreg): can't open %s", filename);
        return 1;
    }
    fclose(fp);

    moddata_t data = (moddata_t) calloc(1, sizeof(struct moddata_st));
    if (!data) {
        log_write(ar->c2s->log, LOG_ERR,
              "plain (authreg): memory error.");
        return 1;
    }

    data->filename = strdup(filename);
    if (data->filename == NULL) {
        log_write(ar->c2s->log, LOG_ERR,
              "plain (authreg): memory error.");
        free(data);
        return 1;
    }

    /* get encryption type used in the password file */
    if (config_get_one(ar->c2s->config, "authreg.password_type.plaintext", 0)) {
        data->password_type = MPC_PLAIN;
#ifdef HAVE_CRYPT
    } else if (config_get_one(ar->c2s->config, "authreg.password_type.crypt", 0)) {
        data->password_type = MPC_CRYPT;
#endif
#ifdef HAVE_SSL
    } else if (config_get_one(ar->c2s->config, "authreg.password_type.a1hash", 0)) {
        data->password_type = MPC_A1HASH;
#endif
    } else {
        data->password_type = MPC_PLAIN;
    }

    ar->private = data;

    ar->user_exists = _ar_plain_user_exists;
    ar->get_password = _ar_plain_get_password;
    ar->check_password = _ar_plain_check_password;
    ar->free = _ar_plain_free;

    log_debug(ZONE, "plain (authreg): finish init");

    return 0;
}
