#ifndef _STORAGE_SQLITE_H_
#define _STORAGE_SQLITE_H_

#include "storage.h"

st_ret_t        st_init(storage_t st);
st_ret_t        st_sqlite_put(storage_t st, const char *type, const char *owner, os_t os);
st_ret_t        st_sqlite_get(storage_t st, const char *type, const char *owner, const char *filter, os_t *os);
st_ret_t        st_sqlite_count(storage_t st, const char *type, const char *owner, const char *filter, int *count);
st_ret_t        st_sqlite_delete(storage_t st, const char *type, const char *owner, const char *filter);
st_ret_t        st_sqlite_replace(storage_t st, const char *type, const char *owner, const char *filter, os_t os);
void            st_sqlite_free(storage_t st);

#endif
