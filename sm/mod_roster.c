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

/** @file sm/mod_roster.c
  * @brief roster managment & subscriptions
  * @author Robert Norris
  * $Date: 2005/09/09 05:34:13 $
  * $Revision: 1.61 $
  */

#define ROSTER_MAX_INDENT  64
#define ROSTER_LINE_LEN    4096

typedef struct _roster_walker_st {
    pkt_t  pkt;
    int    req_ver;
    int    ver;
    sess_t sess;
} *roster_walker_t;

/** free a single roster item */
static void _roster_freeuser_walker(const char *key, int keylen, void *val, void *arg)
{
    item_t item = (item_t) val;
    int i;

    jid_free(item->jid);
    
    if(item->name != NULL)
        free((void*)item->name);

    for(i = 0; i < item->ngroups; i++)
        free((void*)item->groups[i]);
    free(item->groups);

    free(item);
}

/** free the roster */
static void _roster_freeuser(user_t user)
{
    if(user->roster == NULL)
        return;

    log_debug(ZONE, "freeing roster for %s", jid_user(user->jid));

    xhash_walk(user->roster, _roster_freeuser_walker, NULL);

    xhash_free(user->roster);
    user->roster = NULL;
}

/** insert a roster item into this pkt, starting at elem */
static void _roster_insert_item(pkt_t pkt, item_t item, int elem)
{
    int ns = nad_add_namespace(pkt->nad, uri_CLIENT, NULL);
    elem = nad_insert_elem(pkt->nad, elem, ns, "item", NULL);
    nad_set_attr(pkt->nad, elem, -1, "jid", jid_full(item->jid), 0);
    nad_set_attr(pkt->nad, elem, -1, "subscription", "both", 0);

    if(item->name != NULL)
        nad_set_attr(pkt->nad, elem, -1, "name", item->name, 0);

    for(int i = 0; i < item->ngroups; i++)
        nad_insert_elem(pkt->nad, elem, NAD_ENS(pkt->nad, elem), "group", item->groups[i]);
}

/** build the iq:roster packet from the hash */
static void _roster_get_walker(const char *id, int idlen, void *val, void *arg)
{
    item_t item = (item_t) val;
    roster_walker_t rw = (roster_walker_t) arg;

    _roster_insert_item(rw->pkt, item, 2);

    /* remember largest item version */
    if(item->ver > rw->ver) rw->ver = item->ver;
}

/** push roster XEP-0237 updates to client */
static void _roster_update_walker(const char *id, int idlen, void *val, void *arg)
{
    pkt_t push;
    char *buf;
    int elem, ns;
    item_t item = (item_t) val;
    roster_walker_t rw = (roster_walker_t) arg;

    /* skip unneded roster items */
    if(item->ver <= rw->req_ver) return;

    /* build a interim roster push packet */
    push = pkt_create(rw->sess->user->sm, "iq", "set", NULL, NULL);
    pkt_id_new(push);
    ns = nad_add_namespace(push->nad, uri_ROSTER, NULL);
    elem = nad_append_elem(push->nad, ns, "query", 3);

    buf = (char *) malloc(sizeof(char) * 128);
    sprintf(buf, "%d", item->ver);
    nad_set_attr(push->nad, elem, -1, "ver", buf, 0);
    free(buf);

    _roster_insert_item(push, item, elem);

    pkt_sess(push, rw->sess);
}

/** our main handler for packets arriving from a session */
static mod_ret_t _roster_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt)
{
    module_t mod = mi->mod;
    int elem, attr, ver = 0;
    pkt_t result;
    char *buf;
    roster_walker_t rw;

    /* we only want to play with iq:roster packets */
    if(pkt->ns != ns_ROSTER)
        return mod_PASS;

    /* quietly drop results, its probably them responding to a push */
    if(pkt->type == pkt_IQ_RESULT) {
        pkt_free(pkt);
        return mod_HANDLED;
    }

    /* need gets */
    if(pkt->type != pkt_IQ)
        return mod_PASS;

    /* get */
    /* check for "XEP-0237: Roster Versioning request" */
    if((elem = nad_find_elem(pkt->nad, 1, -1, "query", 1)) >= 0
     &&(attr = nad_find_attr(pkt->nad, elem, -1, "ver", NULL)) >= 0) {
        if (NAD_AVAL_L(pkt->nad, attr) > 0)
        {
            buf = (char *) malloc(sizeof(char) * (NAD_AVAL_L(pkt->nad, attr) + 1));
            sprintf(buf, "%.*s", NAD_AVAL_L(pkt->nad, attr), NAD_AVAL(pkt->nad, attr));
            ver = j_atoi(buf, 0);
            free(buf);
        }
    }

    /* build the packet */
    rw = (roster_walker_t) calloc(1, sizeof(struct _roster_walker_st));
    rw->pkt = pkt;
    rw->req_ver = ver;
    rw->sess = sess;

    nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);

    if(ver > 0) {
        /* send XEP-0237 empty result */
        nad_drop_elem(pkt->nad, elem);
        pkt_sess(pkt_tofrom(pkt), sess);
        xhash_walk(sess->user->roster, _roster_update_walker, (void *) rw);
    }
    else {
        xhash_walk(sess->user->roster, _roster_get_walker, (void *) rw);
        if(elem >= 0 && attr >= 0) {
            buf = (char *) malloc(sizeof(char) * 128);
            sprintf(buf, "%d", rw->ver);
            nad_set_attr(pkt->nad, elem, -1, "ver", buf, 0);
            free(buf);
        }
        pkt_sess(pkt_tofrom(pkt), sess);
    }

    free(rw);

    /* remember that they loaded it, so we know to push updates to them */
    sess->module_data[mod->index] = (void *) 1;

    return mod_HANDLED;
}

/** trim group stack to indent (exclusive) */
static void _roster_stack_trim(char **stack, int *depth, int indent)
{
    while (*depth > indent) {
        (*depth)--;
        free(stack[*depth]);
        stack[*depth] = NULL;
    }
}

/** join group stack with XEP-0083 delimiter "::" */
static void _roster_join_groups(char **stack, int depth, char *out, size_t outlen)
{
    size_t n = 0;

    out[0] = '\0';
    if (outlen == 0)
        return;

    for (int i = 0; i < depth; i++) {
        if (stack[i] == NULL)
            continue;

        size_t glen = strlen(stack[i]);
        if (i > 0) {
            if (n + 3 > outlen)
                break;
            out[n++] = ':';
            out[n++] = ':';
        }
        if (n + glen + 1 > outlen) {
            if (n + 1 >= outlen)
                break;
            glen = outlen - n - 1;
        }
        memcpy(out + n, stack[i], glen);
        n += glen;
        out[n] = '\0';
    }
}

/** load roster from a tab-indented users file (same format as authreg_plain) */
static void _roster_load_from_file(user_t user, const char *filename)
{
    char line[ROSTER_LINE_LEN];
    char* stack[ROSTER_MAX_INDENT] = {NULL};
    int stack_depth = 0;

    const char *domain = user->jid->domain; //TODO: get the domain from server settings
    if (domain == NULL || domain[0] == '\0') {
        log_write(user->sm->log, LOG_ERR, "roster: no domain on user jid, cannot load %s", filename);
        return;
    }

    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        log_write(user->sm->log, LOG_ERR, "roster: can't open %s", filename);
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        nl = strchr(line, '\r');
        if (nl)
            *nl = '\0';

        int indent = 0;
        char *p = line;
        while (*p == '\t') {
            if (indent < ROSTER_MAX_INDENT - 1)
                indent++;
            p++;
        }

        if (*p == '\0')
            continue;

        char *tab = strchr(p, '\t');
        if (tab == NULL) {
            /* group at this indent */
            if (indent > stack_depth)
                indent = stack_depth;
            _roster_stack_trim(stack, &stack_depth, indent);
            if (stack_depth >= ROSTER_MAX_INDENT)
                continue;
            stack[stack_depth] = strdup(p);
            if (stack[stack_depth] != NULL)
                stack_depth++;
            continue;
        }

        size_t login_len = (size_t)(tab - p);
        if (login_len == 0)
            continue;

        _roster_stack_trim(stack, &stack_depth, indent);

        char jidbuf[MAXLEN_JID + 1];
        snprintf(jidbuf, sizeof(jidbuf), "%.*s@%s", (int)login_len, p, domain);

        item_t item = (item_t) calloc(1, sizeof(*item));
        if (item == NULL)
            continue;

        item->jid = jid_new(jidbuf, -1);
        if (item->jid == NULL) {
            log_write(user->sm->log, LOG_ERR, "roster: invalid jid %s, skipping", jidbuf);
            free(item);
            continue;
        }

        /* skip ourselves */
        if (jid_compare_user(item->jid, user->jid) == 0) {
            jid_free(item->jid);
            free(item);
            continue;
        }

        if (xhash_get(user->roster, jid_full(item->jid)) != NULL) {
            jid_free(item->jid);
            free(item);
            continue;
        }

        char *name = (char *) malloc(login_len + 1);
        if (name == NULL) {
            jid_free(item->jid);
            free(item);
            continue;
        }
        memcpy(name, p, login_len);
        name[login_len] = '\0';
        item->name = name;

        if (stack_depth > 0) {
            char path[4096];
            _roster_join_groups(stack, stack_depth, path, sizeof(path));
            if (path[0] != '\0') {
                item->groups = (const char **) malloc(sizeof(char *));
                if (item->groups != NULL) {
                    item->groups[0] = strdup(path);
                    if (item->groups[0] != NULL) {
                        item->ngroups = 1;
                    } else {
                        free(item->groups);
                        item->groups = NULL;
                    }
                }
            }
        }

        xhash_put(user->roster, jid_full(item->jid), (void *) item);

        log_debug(ZONE, "added %s to roster from file (group %s)",
                  jid_full(item->jid), item->ngroups > 0 ? item->groups[0] : "(none)");
    }

    fclose(fp);
    _roster_stack_trim(stack, &stack_depth, 0);
}

static int _roster_user_load(mod_instance_t mi, user_t user) {
    const char* filename = (const char*) mi->mod->private;

    log_debug(ZONE, "loading roster for %s", jid_user(user->jid));

    user->roster = xhash_new(101);

    _roster_load_from_file(user, filename);
    pool_cleanup(user->p, (void (*))(void *) _roster_freeuser, user);

    return 0;
}

int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->private = config_get_one(mod->mm->sm->config, "roster.filename", 0);

    mod->in_sess = _roster_in_sess;
    mod->user_load = _roster_user_load;

    feature_register(mod->mm->sm, uri_ROSTER);

    return 0;
}
