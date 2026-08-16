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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/**
 * @file authreg_plain.c
 * @brief plaintext file authentication for jabberd2
 * @bug no known bugs
 */

#define _XOPEN_SOURCE 500
#include "c2s.h"
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
 * Look up username in the text file (login\\tpassword, no realm).
 * @return 1 if found, 0 if not
 */
static int
_ar_plain_lookup(authreg_t ar, const char *username, char *password_out)
{
    FILE *fp;
    char line[PLAIN_LU + 1 + PLAIN_LP + 8];
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
        char *tab;
        char *nl;
        size_t login_len;

        nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        nl = strchr(line, '\r');
        if (nl)
            *nl = '\0';

        if (line[0] == '\0')
            continue;

        tab = strchr(line, '\t');
        if (tab == NULL)
            continue;

        login_len = (size_t)(tab - line);
        if (login_len != userlen || strncmp(line, username, userlen) != 0)
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
    const char *filename = config_get_one(ar->c2s->config, "authreg.plain.filename", 0);

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
    if (config_get_one(ar->c2s->config, "authreg.plain.password_type.plaintext", 0)) {
        data->password_type = MPC_PLAIN;
#ifdef HAVE_CRYPT
    } else if (config_get_one(ar->c2s->config, "authreg.plain.password_type.crypt", 0)) {
        data->password_type = MPC_CRYPT;
#endif
#ifdef HAVE_SSL
    } else if (config_get_one(ar->c2s->config, "authreg.plain.password_type.a1hash", 0)) {
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
