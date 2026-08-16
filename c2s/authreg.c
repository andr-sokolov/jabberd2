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

/** get a handle for the named module */
authreg_t authreg_init(c2s_t c2s, const char *name) {
    char mod_fullpath[PATH_MAX];
    const char *modules_path;
    ar_module_init_fn init_fn = NULL;
    authreg_t ar;
    void *handle;

    /* return if already loaded */
    ar = xhash_get(c2s->ar_modules, name);
    if (ar) {
        return ar->initialized ? ar : NULL;
    }

    /* load authreg module */
    modules_path = config_get_one(c2s->config, "authreg.path", 0);
    if (modules_path != NULL)
        log_write(c2s->log, LOG_NOTICE, "modules search path: %s", modules_path);
    else
        log_write(c2s->log, LOG_NOTICE, "modules search path undefined, using default: "LIBRARY_DIR);

    log_write(c2s->log, LOG_INFO, "loading '%s' authreg module", name);
    if (modules_path != NULL)
        snprintf(mod_fullpath, PATH_MAX, "%s/authreg_%s.so", modules_path, name);
    else
        snprintf(mod_fullpath, PATH_MAX, "%s/authreg_%s.so", LIBRARY_DIR, name);
    handle = dlopen(mod_fullpath, RTLD_LAZY);
    if (handle != NULL)
        init_fn = dlsym(handle, "ar_init");

    if (handle != NULL && init_fn != NULL) {
        log_debug(ZONE, "preloaded module '%s' (not initialized yet)", name);
    } else {
        log_write(c2s->log, LOG_ERR, "failed loading authreg module '%s' (%s)", name, dlerror());
        if (handle != NULL)
            dlclose(handle);
        return NULL;
    }

    /* make a new one */
    ar = (authreg_t) pmalloco(xhash_pool(c2s->ar_modules), sizeof(struct authreg_st));
    if(!ar) {
        log_write(c2s->log, LOG_ERR, "cannot allocate memory for new authreg, aborting");
        exit(1);
    }

    ar->handle = handle;
    ar->c2s = c2s;

    xhash_put(c2s->ar_modules, name, ar);

    /* call the initialiser */
    if((init_fn)(ar) != 0)
    {
        log_write(c2s->log, LOG_ERR, "failed to initialize auth module '%s'", name);
        authreg_free(ar);
        return NULL;
    }

    /* we need user_exists(), at the very least */
    if(ar->user_exists == NULL)
    {
        log_write(c2s->log, LOG_ERR, "auth module '%s' has no check for user existence", name);
        authreg_free(ar);
        return NULL;
    }
    
    /* its good */
    ar->initialized = TRUE;
    log_write(c2s->log, LOG_NOTICE, "initialized auth module '%s'", name);

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
    if((sess->host->ar->user_exists)(sess->host->ar, sess, username, sess->host->realm) == 0) {
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
    if(ar_mechs & AR_MECH_TRAD_PLAIN && (sess->host->ar->get_password != NULL || sess->host->ar->check_password != NULL))
        nad_append_elem(nad, ns, "password", 2);

    if(ar_mechs & AR_MECH_TRAD_DIGEST && sess->host->ar->get_password != NULL)
        nad_append_elem(nad, ns, "digest", 2);

    if (ar_mechs & AR_MECH_TRAD_CRAMMD5 && sess->host->ar->create_challenge != NULL) {
        err = (sess->host->ar->create_challenge)(sess->host->ar, sess, (char *) username, sess->host->realm,
                (char *) sess->auth_challenge, sizeof(sess->auth_challenge));
        if (0 == err) { /* operation failed */
            sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_INTERNAL_SERVER_ERROR), 0));
            return;
        }
        else if (1 == err) { /* operation succeeded */
            nad_append_elem(nad, ns, "crammd5", 2);
            nad_append_attr(nad, -1, "challenge", sess->auth_challenge);
        }
        else ; /* auth method unsupported for user */
    }

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
    if((sess->host->ar->user_exists)(sess->host->ar, sess, username, sess->host->realm) == 0) {
        sx_nad_write(sess->s, stanza_tofrom(stanza_error(nad, 0, stanza_err_OLD_UNAUTH), 0));
        return;
    }
    
    /* handle CRAM-MD5 response */
    if(!authd && ar_mechs & AR_MECH_TRAD_CRAMMD5 && sess->host->ar->check_response != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "crammd5", 1);
        if(elem >= 0)
        {
            snprintf(str, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
            if((sess->host->ar->check_response)(sess->host->ar, sess, username, sess->host->realm, sess->auth_challenge, str) == 0)
            {
                log_debug(ZONE, "crammd5 auth (check) succeded");
                authd = 1;
                _authreg_auth_log(c2s, sess, "traditional.cram-md5", username, resource, TRUE);
            } else {
                _authreg_auth_log(c2s, sess, "traditional.cram-md5", username, resource, FALSE);
            }
        }
    }

    /* digest auth */
    if(!authd && ar_mechs & AR_MECH_TRAD_DIGEST && sess->host->ar->get_password != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "digest", 1);
        if(elem >= 0)
        {
            if((sess->host->ar->get_password)(sess->host->ar, sess, username, sess->host->realm, str) == 0)
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
    if(!authd && ar_mechs & AR_MECH_TRAD_PLAIN && sess->host->ar->get_password != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "password", 1);
        if(elem >= 0)
        {
            if((sess->host->ar->get_password)(sess->host->ar, sess, username, sess->host->realm, str) == 0 &&
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
    if(!authd && ar_mechs & AR_MECH_TRAD_PLAIN && sess->host->ar->check_password != NULL)
    {
        elem = nad_find_elem(nad, 1, ns, "password", 1);
        if(elem >= 0)
        {
            snprintf(str, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
            if((sess->host->ar->check_password)(sess->host->ar, sess, username, sess->host->realm, str) == 0)
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
