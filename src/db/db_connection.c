/**
 * @file db_connection.c
 * @brief Open SQLite in WAL mode, apply and check the settings, close without leaking.
 */
#include "db/db_connection.h"
#include "platform/logging.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

cbae_err_t cbae_db_err_from_sqlite(int rc) {
    switch (rc & 0xFF) {                                     /* the primary code of an extended one */
        case SQLITE_OK: case SQLITE_ROW: case SQLITE_DONE:     return CBAE_OK;
        case SQLITE_NOMEM:                                     return CBAE_ERR_OOM;
        case SQLITE_BUSY: case SQLITE_LOCKED:                  return CBAE_ERR_BUSY;
        case SQLITE_CANTOPEN: case SQLITE_IOERR: case SQLITE_FULL:
        case SQLITE_READONLY: case SQLITE_PERM:                return CBAE_ERR_IO;
        case SQLITE_MISUSE: case SQLITE_RANGE:                 return CBAE_ERR_INVALID;
        default:                                               return CBAE_ERR_DB;
    }
}

/* Runs one statement and copies the first column of its first row (as text) into @p out; empty if there is no row. */
static cbae_err_t query_text(sqlite3 *h, const char *sql, char *out, size_t cap) {
    out[0] = '\0';
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(h, sql, -1, &st, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            const unsigned char *t = sqlite3_column_text(st, 0);
            if (t) snprintf(out, cap, "%s", (const char *)t);
            rc = SQLITE_OK;
        } else if (rc == SQLITE_DONE) rc = SQLITE_OK;
    }
    if (rc != SQLITE_OK) {
        char why[CBAE_ERR_MSG_MAX];
        snprintf(why, sizeof why, "%s", sqlite3_errmsg(h));
        sqlite3_finalize(st);
        const cbae_err_t err = cbae_db_err_from_sqlite(rc);
        CBAE_SET_ERR(err, "%s: %s", sql, why);
        return err;
    }
    sqlite3_finalize(st);
    return CBAE_OK;
}

#define WAL_RETRY_MS  5                                  /* between the tries at switching a file to WAL */

static const char S_PRAGMAS[] =
    "PRAGMA synchronous  = NORMAL;"
    "PRAGMA cache_size   = -32000;"
    "PRAGMA foreign_keys = ON;"
    "PRAGMA temp_store   = MEMORY;";

/* Sets up a freshly opened connection and checks that the settings the schema relies on took effect. */
static cbae_err_t configure(sqlite3 *h, const char *path, int busy_ms) {
    int rc = sqlite3_busy_timeout(h, busy_ms);
    if (rc != SQLITE_OK) {
        const cbae_err_t err = cbae_db_err_from_sqlite(rc);
        CBAE_RETURN_ERR(err, "cannot set the busy timeout of '%s': %s", path, sqlite3_errstr(rc));
    }

    /* The first statement that reads the file: this is where a file that is not a database is found out. SQLite
     * answers a journal mode it cannot give with the mode it kept, not with an error, so the answer is checked.
     *
     * Switching a file to WAL needs the file to itself for a moment, and SQLite then fails with BUSY at once, without
     * asking the busy handler: connections that open a new file together (a worker per thread) would fail at random.
     * So the switch is tried again, for as long as the busy timeout, before BUSY is reported. */
    char mode[32];
    cbae_err_t err;
    for (int waited = 0;; waited += WAL_RETRY_MS) {
        err = query_text(h, "PRAGMA journal_mode = WAL;", mode, sizeof mode);
        if (err != CBAE_ERR_BUSY || waited >= busy_ms) break;
        sqlite3_sleep(WAL_RETRY_MS);
    }
    if (err != CBAE_OK) return err;
    const bool transient = path[0] == '\0' || strcmp(path, ":memory:") == 0;
    if (!transient && sqlite3_stricmp(mode, "wal") != 0)
        CBAE_RETURN_ERR(CBAE_ERR_DB, "'%s' cannot use WAL journaling (journal_mode is '%s')", path, mode);

    char *msg = NULL;
    rc = sqlite3_exec(h, S_PRAGMAS, NULL, NULL, &msg);
    if (rc != SQLITE_OK) {
        const cbae_err_t err = cbae_db_err_from_sqlite(rc);
        CBAE_SET_ERR(err, "cannot configure '%s': %s", path, msg ? msg : sqlite3_errstr(rc));
        sqlite3_free(msg);
        return err;
    }

    /* "PRAGMA foreign_keys = ON" is silently ignored by an SQLite built without foreign keys. The schema's
     * ON DELETE CASCADE would then leave orphans behind without any error. */
    char fk[8];
    CBAE_CHECK(query_text(h, "PRAGMA foreign_keys;", fk, sizeof fk));
    if (strcmp(fk, "1") != 0)
        CBAE_RETURN_ERR(CBAE_ERR_UNSUPPORTED, "this SQLite does not enforce foreign keys (needed by the schema)");
    return CBAE_OK;
}

cbae_err_t cbae_db_open(cbae_db_t *db, const char *path) {
    if (!db || !path) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");
    memset(db, 0, sizeof *db);
    snprintf(db->path, sizeof db->path, "%s", path);                 /* for messages: the full path is what is opened */
    db->busy_timeout_ms = CBAE_DB_BUSY_TIMEOUT_MS;

    sqlite3 *h = NULL;
    const int rc = sqlite3_open_v2(path, &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        const cbae_err_t err = cbae_db_err_from_sqlite(rc);
        CBAE_SET_ERR(err, "cannot open database '%s': %s", path, h ? sqlite3_errmsg(h) : sqlite3_errstr(rc));
        sqlite3_close(h);                                            /* SQLite hands out a handle even when it fails */
        return err;
    }
    const cbae_err_t err = configure(h, path, db->busy_timeout_ms);
    if (err != CBAE_OK) {
        sqlite3_close(h);
        return err;
    }
    db->handle = h;
    LOG_DEBUG("Opened DB: %s", db->path);
    return CBAE_OK;
}

void cbae_db_close(cbae_db_t *db) {
    if (!db || !db->handle) return;
    int unfinalized = 0;
    for (sqlite3_stmt *s = sqlite3_next_stmt(db->handle, NULL); s; s = sqlite3_next_stmt(db->handle, s)) unfinalized++;
    if (unfinalized) LOG_WARN("Closing DB %s with %d statement(s) not finalized", db->path, unfinalized);
    sqlite3_close_v2(db->handle);                       /* with statements left, the connection goes when the last one is finalized */
    db->handle = NULL;
    LOG_DEBUG("Closed DB: %s", db->path);
}

cbae_err_t cbae_db_exec(cbae_db_t *db, const char *sql) {
    if (!db || !sql) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");
    if (!db->handle) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "the database is not open");
    char *msg = NULL;
    const int rc = sqlite3_exec(db->handle, sql, NULL, NULL, &msg);
    if (rc == SQLITE_OK) return CBAE_OK;
    const cbae_err_t err = cbae_db_err_from_sqlite(rc);
    CBAE_SET_ERR(err, "%s | SQL: %.80s", msg ? msg : sqlite3_errstr(rc), sql);
    sqlite3_free(msg);
    return err;
}

sqlite3 *cbae_db_handle(const cbae_db_t *db) { return db ? db->handle : NULL; }
