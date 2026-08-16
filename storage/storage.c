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
#include <ctype.h>
#include <sqlite3.h>

/** storage manager data */
struct storage_st {
    log_t       log;            /**< log context */

    sqlite3     *db;
    const char  *prefix;
    int         txn;
};

typedef struct storage_st   *storage_t;

/** storage filter types */
typedef enum {
    st_filter_type_PAIR,        /**< key=value pair */
    st_filter_type_AND,         /**< and operator */
    st_filter_type_OR,          /**< or operator */
    st_filter_type_NOT          /**< not operator */
} st_filter_type_t;

typedef struct st_filter_st *st_filter_t;
/** filter abstraction */
struct st_filter_st {
    pool_t              p;      /**< pool that filter is allocated from */

    st_filter_type_t    type;   /**< type of this filter */

    char                *key;   /**< key for PAIR filters */
    char                *val;   /**< value for PAIR filters */

    st_filter_t         sub;    /**< sub-filter for operator filters */

    st_filter_t         next;   /**< next filter in a group */
};

static st_filter_t storage_filter(const char *filter);

storage_t storage_new(config_t config, log_t log) {
    storage_t st;

    st = (storage_t) calloc(1, sizeof(struct storage_st));

    st->log = log;


    const char *busy_timeout;
    char *err_msg = NULL;

    const char *dbname = config_get_one (config, "storage.sqlite.dbname", 0);
    if (dbname == NULL) {
        log_write (st->log, LOG_ERR, "sqlite: invalid driver config");
        free(st);
        return NULL;
    }

    if (sqlite3_open (dbname, &st->db) != SQLITE_OK) {
        log_write (st->log, LOG_ERR, "sqlite: can't open database '%s'", dbname);
        free(st);
        return NULL;
    }

    const char *sql_stmt = config_get_one (config, "storage.sqlite.sql", 0);
    if (sql_stmt != NULL) {
        log_write (st->log, LOG_INFO, "sqlite: %s", sql_stmt);
        if (sqlite3_exec (st->db, sql_stmt, NULL, NULL, &err_msg) != SQLITE_OK) {
            log_write (st->log, LOG_ERR, "sqlite: %s", err_msg);
            sqlite3_free(err_msg);
            free(st);
            return NULL;
        }
    }

    busy_timeout = config_get_one (config, "storage.sqlite.busy-timeout", 0);
    if (busy_timeout != NULL) {
        sqlite3_busy_timeout (st->db, atoi (busy_timeout));
    }

    st->prefix = config_get_one (config, "storage.sqlite.prefix", 0);

    return st;
}

void storage_free(storage_t st) {
    sqlite3_close(st->db);
    free(st);
}

#define BLOCKSIZE (1024)


/** internal: do and return the math and ensure it gets realloc'd */
static int _st_sqlite_realloc (void **oblocks, int len) {
    void *nblocks;
    int nlen;

    /* round up to standard block sizes */
    nlen = (((len-1)/BLOCKSIZE)+1)*BLOCKSIZE;

    /* keep trying till we get it */
    while ((nblocks = realloc(*oblocks, nlen)) == NULL) sleep (1);
    *oblocks = nblocks;

    return nlen;
}

/** this is the safety check used to make sure there's always enough mem */
#define SQLITE_SAFE(blocks, size, len) \
    if((size) >= (len)) \
        len = _st_sqlite_realloc((void**)&(blocks),(size) + 1);

#define SQLITE_SAFE_CAT(blocks, size, len, s1) \
    do { \
	SQLITE_SAFE(blocks, size + sizeof (s1) - 1, len); \
	memcpy (&blocks[size], s1, sizeof (s1)); \
	size += sizeof (s1) - 1; \
    } while (0)

#define SQLITE_SAFE_CAT3(blocks, size, len, s1, s2, s3) \
    do { \
	const unsigned int l = strlen (s2); \
	SQLITE_SAFE(blocks, size + sizeof (s1) + l + sizeof (s2) - 2, len); \
	memcpy (&blocks[size], s1, sizeof (s1) - 1); \
	memcpy (&blocks[size + sizeof (s1) - 1], s2, l); \
	memcpy (&blocks[size + sizeof (s1) - 1 + l], s3, sizeof (s3)); \
	size += sizeof (s1) + l + sizeof (s3) - 2; \
    } while (0)

static void _st_sqlite_convert_filter_recursive (st_filter_t f, char **buf,
						 int *buflen, int *nbuf) {

    st_filter_t scan;

    switch (f->type) {
     case st_filter_type_PAIR:
      SQLITE_SAFE_CAT3 ((*buf), *nbuf, *buflen,
			"( \"", f->key, "\" = ? ) ");
      break;

     case st_filter_type_AND:
      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, "( ");

      for (scan = f->sub; scan != NULL; scan = scan->next) {
	  _st_sqlite_convert_filter_recursive (scan, buf,
					       buflen, nbuf);

	  if (scan->next != NULL) {
	      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, "AND ");
	  }
      }

      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, ") ");

      return;

     case st_filter_type_OR:
      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, "( ");

      for (scan = f->sub; scan != NULL; scan = scan->next) {
	  _st_sqlite_convert_filter_recursive (scan, buf,
					       buflen, nbuf);

	  if (scan->next != NULL) {
	      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, "OR ");
	  }
      }

      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, ") ");

      return;

     case st_filter_type_NOT:
      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, "( NOT ");

      _st_sqlite_convert_filter_recursive(f->sub, buf,
					  buflen, nbuf);

      SQLITE_SAFE_CAT ((*buf), *nbuf, *buflen, ") ");

      return;
    }
}

static char *_st_sqlite_convert_filter (storage_t st, const char *owner,
					const char *filter) {

    char *buf = NULL;
    int buflen = 0, nbuf = 0;
    st_filter_t f;


    SQLITE_SAFE_CAT (buf, nbuf, buflen, "\"collection-owner\" = ?");

    f = storage_filter (filter);
    if (f == NULL) {
	return buf;
    }

    SQLITE_SAFE_CAT (buf, nbuf, buflen, " AND ");

    _st_sqlite_convert_filter_recursive (f, &buf, &buflen, &nbuf);

    pool_free (f->p);

    return buf;
}

static void _st_sqlite_bind_filter_recursive (st_filter_t f,
					      sqlite3_stmt *stmt,
					      unsigned int bind_off) {

    st_filter_t scan;
    unsigned int i;

    switch (f->type) {
     case st_filter_type_PAIR:
      sqlite3_bind_text (stmt, bind_off, f->val, strlen (f->val),
			 SQLITE_TRANSIENT);
      break;

     case st_filter_type_AND:
      for (scan = f->sub, i = 0; scan != NULL; scan = scan->next, ++i) {
	  _st_sqlite_bind_filter_recursive (scan, stmt, bind_off + i);
      }
      return;

     case st_filter_type_OR:
      for (scan = f->sub, i = 0; scan != NULL; scan = scan->next, ++i) {
	  _st_sqlite_bind_filter_recursive (scan, stmt, bind_off + i);
      }
      return;

     case st_filter_type_NOT:
      _st_sqlite_bind_filter_recursive(f->sub, stmt, bind_off);
      return;
    }
}

static void _st_sqlite_bind_filter (storage_t st, const char *owner,
				    const char *filter,
				    sqlite3_stmt *stmt,
				    unsigned int bind_off) {

    st_filter_t f;


    sqlite3_bind_text (stmt, bind_off, owner, strlen (owner),
		       SQLITE_TRANSIENT);

    f = storage_filter (filter);
    if (f == NULL) {
	return;
    }

    _st_sqlite_bind_filter_recursive (f, stmt, bind_off + 1);

    pool_free (f->p);
}

static st_ret_t _st_sqlite_put_guts (storage_t st, const char *type,
				     const char *owner, os_t os) {
    char *left = NULL, *right = NULL;
    unsigned int lleft = 0, lright = 0;
    os_object_t o;
    char *key, *cval = NULL;
    void *val;
    os_type_t ot;
    const char *xml;
    int xlen;
    char tbuf[128];
    int res;

    if (os_count (os) == 0) {
	return st_SUCCESS;
    }

    if (st->prefix != NULL) {
	snprintf (tbuf, sizeof (tbuf), "%s%s", st->prefix, type);
	type = tbuf;
    }

    if (os_iter_first (os)) {
	do {

	    unsigned int i = 0;
	    unsigned int nleft = 0, nright = 0;
	    sqlite3_stmt *stmt;


	    SQLITE_SAFE_CAT3 (left, nleft, lleft,
			      "INSERT INTO \"", type,
			      "\" ( \"collection-owner\"");
	    SQLITE_SAFE_CAT (right, nright, lright, " ) VALUES ( ?");

	    o = os_iter_object (os);
	    if (os_object_iter_first(o))
		do {
		    os_object_iter_get (o, &key, &val, &ot);

		    log_debug (ZONE, "key %s val %s", key, cval);

		    SQLITE_SAFE_CAT3 (left, nleft, lleft,
				      ", \"", key, "\"");

		    SQLITE_SAFE_CAT (right, nright, lright, ", ?");

		} while (os_object_iter_next (o));

	    SQLITE_SAFE (left, nleft + nright, lleft);
	    memcpy (&left[nleft], right, nright);
	    nleft += nright;
	    free (right);
	    right = NULL;
	    lright = 0;

	    SQLITE_SAFE_CAT (left, nleft, lleft, " )");

	    log_debug (ZONE, "prepared sql: %s", left);

	    res = sqlite3_prepare (st->db, left, strlen (left), &stmt, NULL);
	    free (left);
	    left = NULL;
	    lleft = 0;
	    if (res != SQLITE_OK) {
		log_write (st->log, LOG_ERR,
			   "sqlite: sql insert failed: %s",
			   sqlite3_errmsg (st->db));
		return st_FAILED;
	    }

	    sqlite3_bind_text (stmt, 1, owner, strlen (owner),
			       SQLITE_TRANSIENT);

	    o = os_iter_object (os);
	    if (os_object_iter_first(o))
		do {
            /* For os_type_BOOLEAN and os_type_INTEGER, sizeof(int) bytes
               are stored in val, which might be less than sizeof(void *).
               Therefore, the difference is garbage unless cleared first.
             */
            val = NULL;
		    os_object_iter_get (o, &key, &val, &ot);

		    switch(ot) {
		     case os_type_BOOLEAN:
		      sqlite3_bind_int (stmt, i + 2, ((int)val != 0) ? 1 : 0);
		      break;

		     case os_type_INTEGER:
		      sqlite3_bind_int (stmt, i + 2, (int)val);
		      break;

		     case os_type_STRING:
		      sqlite3_bind_text (stmt, i + 2,
					 (const char *) val,
					 strlen ((const char *) val),
					 SQLITE_TRANSIENT);
		      break;

		      /* !!! might not be a good idea to mark nads this way */
		     case os_type_NAD:
		      nad_print ((nad_t) val, 0, &xml, &xlen);
		      cval = (char *) malloc(sizeof(char) * (xlen + 4));
		      memcpy (&cval[3], xml, xlen + 1);
		      memcpy (cval, "NAD", 3);

		      sqlite3_bind_text (stmt, i + 2,
					 cval, xlen + 3, free);
		      break;

		     case os_type_UNKNOWN:
		     default:
		      log_write (st->log, LOG_ERR, "sqlite: unknown value in query");

		    }

		    i += 1;
		} while (os_object_iter_next (o));

	    res = sqlite3_step (stmt);
	    if (res != SQLITE_DONE) {
		log_write (st->log, LOG_ERR,
			   "sqlite: sql insert failed: %s",
			   sqlite3_errmsg (st->db));
		sqlite3_finalize (stmt);
		return st_FAILED;
	    }
	    sqlite3_finalize (stmt);

	} while (os_iter_next (os));
    }

    return st_SUCCESS;
}

st_ret_t storage_put(storage_t st, const char *type, const char *owner, os_t os) {
    if (os_count (os) == 0)
        return st_SUCCESS;

    return _st_sqlite_put_guts (st, type, owner, os);
}

st_ret_t storage_get(storage_t st, const char *type, const char *owner, const char *filter, os_t *os) {
    char *buf = NULL;
    unsigned int nbuf = 0;
    unsigned int buflen = 0;
    unsigned int num_rows = 0;
    char tbuf[128];

    if (st->prefix != NULL) {
        snprintf (tbuf, sizeof (tbuf), "%s%s", st->prefix, type);
        type = tbuf;
    }

    char *cond = _st_sqlite_convert_filter (st, owner, filter);

    SQLITE_SAFE_CAT3 (buf, nbuf, buflen, "SELECT * FROM \"", type, "\" WHERE ");
    strcpy (&buf[nbuf], cond);
    strcpy (&buf[strlen(buf)], " ORDER BY \"object-sequence\"");
    free (cond);

    log_debug (ZONE, "prepared sql: %s", buf);

    sqlite3_stmt *stmt;
    int result = sqlite3_prepare (st->db, buf, strlen (buf), &stmt, NULL);
    free (buf);
    if (result != SQLITE_OK)
        return st_FAILED;

    _st_sqlite_bind_filter (st, owner, filter, stmt, 1);

    *os = os_new ();

    do {
        result = sqlite3_step (stmt);

        if (result != SQLITE_ROW)
            continue;

        os_object_t o = os_object_new (*os);
        unsigned int num_cols = sqlite3_data_count (stmt);

        for (int i = 0; i < num_cols; i++) {
            const char *colname = sqlite3_column_name (stmt, i);
            if (strcmp (colname, "collection-owner") == 0)
                continue;

            int coltype = sqlite3_column_type (stmt, i);
            if (coltype == SQLITE_NULL) {
                log_debug (ZONE, "coldata is NULL");
                continue;
            }

            if (coltype == SQLITE_INTEGER) {
                os_type_t ot = (strcmp (sqlite3_column_decltype (stmt, i), "BOOL") == 0) ? os_type_BOOLEAN : os_type_INTEGER;
                int ival = sqlite3_column_int (stmt, i);
                os_object_put (o, colname, &ival, ot);
            } else if (coltype == SQLITE3_TEXT) {
                const char *val = (const char*)sqlite3_column_text (stmt, i);
                os_object_put (o, colname, val, os_type_STRING);
            } else
                log_write (st->log, LOG_NOTICE, "sqlite: unknown field: %s:%d", colname, coltype);
        }

        num_rows++;
    } while (result == SQLITE_ROW);

    sqlite3_finalize (stmt);

    if (num_rows == 0) {
        os_free(*os);
        *os = NULL;
        return st_NOTFOUND;
    }

    return st_SUCCESS;
}

st_ret_t storage_count(storage_t st, const char *type, const char *owner, const char *filter, int *count) {
    char *buf = NULL;
    unsigned int nbuf = 0;
    unsigned int buflen = 0;
    char tbuf[128];

    if (st->prefix != NULL) {
        snprintf (tbuf, sizeof (tbuf), "%s%s", st->prefix, type);
        type = tbuf;
    }

    char *cond = _st_sqlite_convert_filter (st, owner, filter);
    log_debug (ZONE, "generated filter: %s", cond);

    SQLITE_SAFE_CAT3 (buf, nbuf, buflen, "SELECT COUNT(*) FROM \"", type, "\" WHERE ");
    strcpy (&buf[nbuf], cond);
    free (cond);

    log_debug (ZONE, "prepared sql: %s", buf);

    sqlite3_stmt *stmt;
    int res = sqlite3_prepare (st->db, buf, strlen (buf), &stmt, NULL);
    free (buf);
    if (res != SQLITE_OK)
        return st_FAILED;

    _st_sqlite_bind_filter (st, owner, filter, stmt, 1);

    res = sqlite3_step (stmt);
    if (res != SQLITE_ROW) {
        log_write (st->log, LOG_ERR, "sqlite: sql select failed: %s", sqlite3_errmsg (st->db));
        sqlite3_finalize (stmt);
        return st_FAILED;
    }

    if (sqlite3_column_type (stmt, 0) != SQLITE_INTEGER) {
        log_write (st->log, LOG_ERR, "sqlite: weird, count() returned non integer value: %s",
            sqlite3_errmsg (st->db));
        sqlite3_finalize (stmt);
        return st_FAILED;
    }

    *count = sqlite3_column_int (stmt, 0);

    sqlite3_finalize (stmt);

    return st_SUCCESS;
}


st_ret_t storage_delete(storage_t st, const char *type, const char *owner, const char *filter) {
    char *cond, *buf = NULL;
    unsigned int nbuf = 0;
    unsigned int buflen = 0;
    char tbuf[128];
    int res;
    sqlite3_stmt *stmt;

    if (st->prefix != NULL) {
        snprintf (tbuf, sizeof (tbuf), "%s%s", st->prefix, type);
        type = tbuf;
    }

    cond = _st_sqlite_convert_filter (st, owner, filter);
    log_debug (ZONE, "generated filter: %s", cond);

    SQLITE_SAFE_CAT3 (buf, nbuf, buflen, "DELETE FROM \"", type, "\" WHERE ");
    strcpy (&buf[nbuf], cond);
    free (cond);

    log_debug (ZONE, "prepared sql: %s", buf);

    res = sqlite3_prepare (st->db, buf, strlen (buf), &stmt, NULL);
    free (buf);
    if (res != SQLITE_OK)
        return st_FAILED;


    _st_sqlite_bind_filter (st, owner, filter, stmt, 1);

    res = sqlite3_step (stmt);
    if (res != SQLITE_DONE) {
        log_write (st->log, LOG_ERR, "sqlite: sql delete failed: %s", sqlite3_errmsg (st->db));
        sqlite3_finalize (stmt);
        return st_FAILED;
    }
    sqlite3_finalize (stmt);

    return st_SUCCESS;
}

st_ret_t storage_replace(storage_t st, const char *type, const char *owner, const char *filter, os_t os) {
    if (storage_delete(st, type, owner, filter) == st_FAILED)
        return st_FAILED;

    if (_st_sqlite_put_guts(st, type, owner, os) == st_FAILED)
        return st_FAILED;

    return st_SUCCESS;
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

static st_filter_t storage_filter(const char *filter) {
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

