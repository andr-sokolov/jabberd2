/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2003 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
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

/** @file storage/storage.c
  * @brief storage manager
  * @author Robert Norris
  * $Date: 2005/06/02 06:31:10 $
  * $Revision: 1.21 $
  */

#include "storage.h"
#include "storage_sqlite.h"
#include <ctype.h>


storage_t storage_new(config_t config, log_t log) {
    storage_t st;

    st = (storage_t) calloc(1, sizeof(struct storage_st));

    st->config = config;
    st->log = log;

    if(st_init(st) == st_FAILED) {
        free(st);
        return NULL;
    }

    return st;
}

void storage_free(storage_t st) {
    st_sqlite_free(st);
    free(st);
}

st_ret_t storage_put(storage_t st, const char *type, const char *owner, os_t os) {
    log_debug(ZONE, "storage_put: type=%s owner=%s os=%X", type, owner, os);

    return st_sqlite_put(st, type, owner, os);
}

st_ret_t storage_get(storage_t st, const char *type, const char *owner, const char *filter, os_t *os) {
    log_debug(ZONE, "storage_get: type=%s owner=%s filter=%s", type, owner, filter);

    return st_sqlite_get(st, type, owner, filter, os);
}

st_ret_t storage_get_custom_sql(storage_t st, const char* request, os_t* os, const char *type /*= 0*/)
{
    log_debug(ZONE, "storage_get_custom_sql: query='%s'", request);

    return st_NOTIMPL;
}

st_ret_t storage_count(storage_t st, const char *type, const char *owner, const char *filter, int *count) {
    log_debug(ZONE, "storage_count: type=%s owner=%s filter=%s", type, owner, filter);

    return st_sqlite_count(st, type, owner, filter, count);
}


st_ret_t storage_delete(storage_t st, const char *type, const char *owner, const char *filter) {
    log_debug(ZONE, "storage_zap: type=%s owner=%s filter=%s", type, owner, filter);

    return st_sqlite_delete(st, type, owner, filter);
}

st_ret_t storage_replace(storage_t st, const char *type, const char *owner, const char *filter, os_t os) {
    log_debug(ZONE, "storage_replace: type=%s owner=%s filter=%s os=%X", type, owner, filter, os);

    return st_sqlite_replace(st, type, owner, filter, os);
}

static st_filter_t _storage_filter(pool_t p, const char *f, int len) {
    char *c, *key, *val, *sub;
    int vallen;
    st_filter_t res, sf;
    
    if(f[0] != '(' && f[len] != ')')
        return NULL;

    /* key/value pair */

    /* if value is numeric, then represented as is.                                      */
    /* if value is string, it is preceded by length: e.g. "key=5:abcde"                  */
    /* (needed to pass values which include a closing bracket ')', e.g. in resourcenames */

    if(isalpha(f[1])) {
        key = strdup(f+1);

        c = strchr(key, '=');
        if(c == NULL) {
		free(key);
		return NULL;
	}
        *c = '\0'; c++;

        val = c;

	/* decide whether number or string by checking for ':' before ')' */

        while (*c != ':' && *c != ')' && *c)
           c++;

        if (!*c) {
		free(key);
		return NULL;
	}

        if (*c == ':') {
                /* string */
                *c = '\0';
                vallen = atoi(val);
                c++;
                val = c;
                c += vallen;
        }

        *c = '\0';
        log_debug(ZONE, "extracted key %s val %s", key, val);

        res = pmalloco(p, sizeof(struct st_filter_st));
        res->p = p;

        res->type = st_filter_type_PAIR;
        res->key = pstrdup(p, key);
        res->val = pstrdup(p, val);

	free(key);
        return res;
    }

    /* operator */
    if(f[1] != '&' && f[1] != '|' && f[1] != '!')
        return NULL;

    res = pmalloco(p, sizeof(struct st_filter_st));
    res->p = p;

    switch(f[1]) {
        case '&': res->type = st_filter_type_AND; break;
        case '|': res->type = st_filter_type_OR; break;
        case '!': res->type = st_filter_type_NOT; break;
    }

    /* remove const for now, we will not change the string */
    c = (char *) &f[2];
    while(*c == '(') {
        sub = c;
        c = strchr(sub, ')');
        c++;

        sf = _storage_filter(p, (const char *) sub, c - sub);

        sf->next = res->sub;
        res->sub = sf;
    }

    return res;
}

st_filter_t storage_filter(const char *filter) {
    pool_t p;
    st_filter_t f;

    if(filter == NULL)
        return NULL;

    p = pool_new();

    f = _storage_filter(p, filter, strlen(filter));
    if(f == NULL)
        pool_free(p);

    return f;
}

static int _storage_match(st_filter_t f, os_object_t o, os_t os) {
    void *val;
    os_type_t ot;
    st_filter_t scan;

    switch(f->type) {
        case st_filter_type_PAIR:
            if(!os_object_get(os, o, f->key, &val, os_type_UNKNOWN, &ot))
                return 0;

            switch(ot) {
                case os_type_BOOLEAN:
                    if((atoi(f->val) != 0) == (((int) (long) val) != 0))
                        return 1;
                    return 0;

                case os_type_INTEGER:
                    if(atoi(f->val) == (int) (long) val)
                        return 1;
                    return 0;

                case os_type_STRING:
                    if(strcmp(f->val, val) == 0)
                        return 1;
                    return 0;
                
                case os_type_NAD:
                    /* !!! this is hard, but probably not needed. if you need it, you implement it ;) */
                    return 1;

		case os_type_UNKNOWN:
	             return 0;
            }

            return 0;

        case st_filter_type_AND:
            for(scan = f->sub; scan != NULL; scan = scan->next)
                if(!_storage_match(scan, o, os))
                    return 0;
            return 1;

        case st_filter_type_OR:
            for(scan = f->sub; scan != NULL; scan = scan->next)
                if(_storage_match(scan, o, os))
                    return 1;
            return 0;

        case st_filter_type_NOT:
            if(_storage_match(f->sub, o, os))
                return 0;
            return 1;
    }

    return 0;
}

int storage_match(st_filter_t filter, os_object_t o, os_t os) {
    if(filter == NULL)
        return 1;

    return _storage_match(filter, o, os);
}
