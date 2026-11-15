/**
 * @file db_connection.h
 * @brief SQLite3 WAL-mode connection lifecycle.
 */
#ifndef CBAE_DB_CONNECTION_H
#define CBAE_DB_CONNECTION_H

#include "cbae/cbae_error.h"
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_db {
    sqlite3    *handle;
    char        path[512];
    int         busy_timeout_ms;
} cbae_db_t;

cbae_err_t cbae_db_open  (cbae_db_t *db, const char *path);
void       cbae_db_close (cbae_db_t *db);
int        cbae_db_exec  (cbae_db_t *db, const char *sql);
sqlite3   *cbae_db_handle(const cbae_db_t *db);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DB_CONNECTION_H */
