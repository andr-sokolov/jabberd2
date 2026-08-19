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

#include "sm.h"
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/** @file sm/mod_offline.c
  * @brief offline storage
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.26 $
  */

#define OFFLINE_PATH_MAX    1024
#define OFFLINE_LINE_MAX    65536

typedef struct _mod_offline_st {
    int dropmessages;
    int storeheadlines;
    int dropsubscriptions;
    const char *spooldir;
} *mod_offline_t;

/** \ -> \\, newline/CR -> \n (process each original char once) */
static char *_offline_escape(const char *in, int inlen) {
    if(in == NULL || inlen < 0)
        inlen = 0;

    int outlen = 0;
    for(int i = 0; i < inlen; i++) {
        if(in[i] == '\\' || in[i] == '\n' || in[i] == '\r')
            outlen += 2;
        else
            outlen++;
    }

    char *out = malloc(outlen + 1);
    if(out == NULL)
        return NULL;

    int j = 0;
    for(int i = 0; i < inlen; i++) {
        if(in[i] == '\\') {
            out[j++] = '\\';
            out[j++] = '\\';
        } else if(in[i] == '\n' || in[i] == '\r') {
            out[j++] = '\\';
            out[j++] = 'n';
        } else {
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
    return out;
}

static char *_offline_unescape(const char *in) {
    if(in == NULL)
        return NULL;

    int inlen = strlen(in);
    char* out = malloc(inlen + 1);
    if(out == NULL)
        return NULL;

    int j = 0;
    for(int i = 0; i < inlen; i++) {
        if(in[i] == '\\' && i + 1 < inlen) {
            i++;
            if(in[i] == 'n')
                out[j++] = '\n';
            else if(in[i] == '\\')
                out[j++] = '\\';
            else
                out[j++] = in[i];
        } else {
            out[j++] = in[i];
        }
    }
    out[j] = '\0';
    return out;
}

/** 0 = ok (including skip), -1 = I/O error */
static int _offline_save_to_file(mod_offline_t offline, user_t user, pkt_t pkt) {
    if(!(pkt->type & pkt_MESSAGE))
        return 0;

    int elem = nad_find_elem(pkt->nad, 1, -1, "body", 1);
    if(elem < 0 || NAD_CDATA_L(pkt->nad, elem) <= 0)
        return 0;

    char path[OFFLINE_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", offline->spooldir, user->jid->node);

    FILE *fp = fopen(path, "a");
    if(fp == NULL) {
        log_write(user->sm->log, LOG_ERR, "offline: can't open %s for writing: %s", path, strerror(errno));
        return -1;
    }

    char *escaped = _offline_escape(NAD_CDATA(pkt->nad, elem), NAD_CDATA_L(pkt->nad, elem));
    if(escaped == NULL) {
        fclose(fp);
        return -1;
    }

    const char *from = (pkt->from != NULL) ? jid_full(pkt->from) : "";
    if(fprintf(fp, "%s\t%s\n", from, escaped) < 0) {
        log_write(user->sm->log, LOG_ERR, "offline: write to %s failed: %s", path, strerror(errno));
        free(escaped);
        fclose(fp);
        return -1;
    }

    free(escaped);
    fclose(fp);
    return 0;
}

static void _offline_deliver_from_file(mod_offline_t offline, sess_t sess) {
    char path[OFFLINE_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", offline->spooldir, sess->jid->node);

    FILE* fp = fopen(path, "r");
    if(fp == NULL)
        return;

    char line[OFFLINE_LINE_MAX];
    while(fgets(line, sizeof(line), fp) != NULL) {
        char *nl = strchr(line, '\n');
        if(nl)
            *nl = '\0';
        nl = strchr(line, '\r');
        if(nl)
            *nl = '\0';

        if(line[0] == '\0')
            continue;

        char *tab = strchr(line, '\t');
        if(tab == NULL) {
            log_debug(ZONE, "offline: skipping malformed spool line for %s", jid_full(sess->jid));
            continue;
        }
        *tab = '\0';

        char *body = _offline_unescape(tab + 1);
        if(body == NULL)
            continue;

        pkt_t queued = pkt_create(sess->user->sm, "message", "chat", jid_full(sess->jid), line);
        if(queued == NULL) {
            log_debug(ZONE, "offline: could not rebuild queued packet for %s", jid_full(sess->jid));
            free(body);
            continue;
        }

        nad_append_elem(queued->nad, -1, "body", 2);
        if(body[0] != '\0')
            nad_append_cdata(queued->nad, body, strlen(body), 3);

        log_debug(ZONE, "delivering queued packet to %s", jid_full(sess->jid));
        pkt_sess(queued, sess);
        free(body);
    }

    fclose(fp);
    if(unlink(path) < 0 && errno != ENOENT)
        log_write(sess->user->sm->log, LOG_ERR, "offline: can't remove %s: %s", path, strerror(errno));
}

static mod_ret_t _offline_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    mod_offline_t offline = (mod_offline_t) mi->mod->private;

    /* if they're becoming available for the first time */
    if(pkt->type == pkt_PRESENCE && sess->pri >= 0 && pkt->to == NULL && sess->user->top == NULL)
        _offline_deliver_from_file(offline, sess);

    /* pass it so that other modules and mod_presence can get it */
    return mod_PASS;
}

static mod_ret_t _offline_pkt_user(mod_instance_t mi, user_t user, pkt_t pkt) {
    mod_offline_t offline = (mod_offline_t) mi->mod->private;
    int ns, elem, attr;
    pkt_t event;

    /* send messages to the top sessions */
    if(user->top != NULL && (pkt->type & pkt_MESSAGE || pkt->type & pkt_S10N)) {
        sess_t scan;
    
        /* loop over each session */
        for(scan = user->sessions; scan != NULL; scan = scan->next) {
            /* don't deliver to unavailable sessions */
            if(!scan->available)
                continue;

            /* skip negative priorities */
            if(scan->pri < 0)
                continue;

            /* headlines go to all, other to top priority */
            if(pkt->type != pkt_MESSAGE_HEADLINE && scan->pri < user->top->pri)
                continue;
    
            /* deliver to session */
            log_debug(ZONE, "delivering message to %s", jid_full(scan->jid));
            pkt_sess(pkt_dup(pkt, jid_full(scan->jid), jid_full(pkt->from)), scan);
        }

        pkt_free(pkt);
        return mod_HANDLED;
    }

    /* save messages and s10ns for later (s10ns are not written to files) */
    if((pkt->type & pkt_MESSAGE && !offline->dropmessages) ||
       (pkt->type & pkt_S10N && !offline->dropsubscriptions)) {

        /* check type of the message and drop headlines and groupchat */
        if((((pkt->type & pkt_MESSAGE_HEADLINE) == pkt_MESSAGE_HEADLINE) && !offline->storeheadlines) ||
            (pkt->type & pkt_MESSAGE_GROUPCHAT) == pkt_MESSAGE_GROUPCHAT) {
            log_debug(ZONE, "not saving message (type 0x%X) for later", pkt->type);
            pkt_free(pkt);
            return mod_HANDLED;
        }

        log_debug(ZONE, "saving packet for later");

        pkt_delay(pkt, time(NULL), user->jid->domain);

        if(_offline_save_to_file(offline, user, pkt) < 0)
            return -stanza_err_INTERNAL_SERVER_ERROR;

        /* XEP-0022 - send offline events if they asked for it */
        /* if there's an id element, then this is a notification, not a request, so ignore it */

        if((ns = nad_find_scoped_namespace(pkt->nad, uri_EVENT, NULL)) >= 0 &&
           (elem = nad_find_elem(pkt->nad, 1, ns, "x", 1)) >= 0 &&
           nad_find_elem(pkt->nad, elem, ns, "offline", 1) >= 0 && 
           nad_find_elem(pkt->nad, elem, ns, "id", 1) < 0) {

            event = pkt_create(user->sm, "message", NULL, jid_full(pkt->from), jid_full(pkt->to));

            attr = nad_find_attr(pkt->nad, 1, -1, "type", NULL);
            if(attr >= 0)
                nad_set_attr(event->nad, 1, -1, "type", NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr));

            ns = nad_add_namespace(event->nad, uri_EVENT, NULL);
            nad_append_elem(event->nad, ns, "x", 2);
            nad_append_elem(event->nad, ns, "offline", 3);

            nad_append_elem(event->nad, ns, "id", 3);
            attr = nad_find_attr(pkt->nad, 1, -1, "id", NULL);
            if(attr >= 0)
                nad_append_cdata(event->nad, NAD_AVAL(pkt->nad, attr), NAD_AVAL_L(pkt->nad, attr), 4);

            pkt_router(event);
        }

        pkt_free(pkt);
        return mod_HANDLED;
    }

    return mod_PASS;
}

static void _offline_free(module_t mod) {
    mod_offline_t offline = (mod_offline_t) mod->private;

    free(offline);
}

int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;
    const char *configval;
    mod_offline_t offline;

    if(mod->init) return 0;

    offline = (mod_offline_t) calloc(1, sizeof(struct _mod_offline_st));

    configval = config_get_one(mod->mm->sm->config, "offline.dropmessages", 0);
    if (configval != NULL)
        offline->dropmessages = 1;

    configval = config_get_one(mod->mm->sm->config, "offline.storeheadlines", 0);
    if (configval != NULL)
        offline->storeheadlines = 1;

    configval = config_get_one(mod->mm->sm->config, "offline.dropsubscriptions", 0);
    if (configval != NULL)
        offline->dropsubscriptions = 1;

    offline->spooldir = config_get_one(mod->mm->sm->config, "offline.dir", 0);
    if (offline->spooldir == NULL || offline->spooldir[0] == '\0') {
        log_write(mod->mm->sm->log, LOG_ERR, "offline: offline.dir is not set");
        return 1;
    }

    if(mkdir(offline->spooldir, 0750) < 0 && errno != EEXIST)
        log_write(mod->mm->sm->log, LOG_ERR, "offline: can't create %s: %s", offline->spooldir, strerror(errno));

    mod->private = offline;

    mod->in_sess = _offline_in_sess;
    mod->pkt_user = _offline_pkt_user;
    mod->free = _offline_free;

    feature_register(mod->mm->sm, "msgoffline");

    return 0;
}
