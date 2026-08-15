#ifndef _STORAGE_SQLITE_H_
#define _STORAGE_SQLITE_H_

#include "storage.h"

st_ret_t        st_init(st_driver_t drv);
st_ret_t        st_sqlite_put(st_driver_t drv, const char *type, const char *owner, os_t os);
st_ret_t        st_sqlite_get(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t *os);
st_ret_t        st_sqlite_count(st_driver_t drv, const char *type, const char *owner, const char *filter, int *count);
st_ret_t        st_sqlite_delete(st_driver_t drv, const char *type, const char *owner, const char *filter);
st_ret_t        st_sqlite_replace(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t os);
void            st_sqlite_free(st_driver_t drv);

#endif
