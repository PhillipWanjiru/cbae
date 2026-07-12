/**
 * @file db_connection.c
 * @brief Open SQLite in WAL mode, tune PRAGMAs, close safely.
 */
#include "db/db_connection.h"
#include "platform/logging.h"
#include <string.h>
#include <stdbool.h>

static const char *S_PRAGMAS =
    "PRAGMA journal_mode = WAL;"
    "PRAGMA synchronous  = NORMAL;"
    "PRAGMA cache_size   = -32000;"
    "PRAGMA foreign_keys = ON;"
    "PRAGMA temp_store   = MEMORY;";

cbae_err_t cbae_db_open(cbae_db_t *db, const char *path) {
    if(!db || !path) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");
    memset(db, 0, sizeof(*db));
    strncpy(db->path, path, sizeof(db->path) - 1);
    db->busy_timeout_ms = 5000;
    int rc = sqlite3_open(path, &db->handle);
    if(rc != SQLITE_OK)
        CBAE_RETURN_ERR(CBAE_ERR_DB, "sqlite3_open(%s): %s",
                        path, sqlite3_errmsg(db->handle));
    sqlite3_busy_timeout(db->handle, db->busy_timeout_ms);
    char *errmsg = NULL;
    rc = sqlite3_exec(db->handle, S_PRAGMAS, NULL, NULL, &errmsg);
    if(rc != SQLITE_OK) {
        LOG_WARN("PRAGMA setup warning: %s", errmsg ? errmsg : "?");
        sqlite3_free(errmsg);
    }
    LOG_DEBUG("Opened DB: %s", path);
    return CBAE_OK;
}

void cbae_db_close(cbae_db_t *db) {
    if(!db || !db->handle) return;
    sqlite3_close(db->handle);
    db->handle = NULL;
    LOG_DEBUG("Closed DB: %s", db->path);
}

int cbae_db_exec(cbae_db_t *db, const char *sql) {
    if(!db || !sql) return SQLITE_MISUSE;
    char *err = NULL;
    int rc = sqlite3_exec(db->handle, sql, NULL, NULL, &err);
    if(rc != SQLITE_OK) {
        LOG_ERROR("cbae_db_exec: %s | SQL: %.80s", err ? err : "?", sql);
        sqlite3_free(err);
    }
    return rc;
}

sqlite3 *cbae_db_handle(const cbae_db_t *db) { return db ? db->handle : NULL; }
