/**
 * @file db_connection.h
 * @brief SQLite connection: opened in WAL mode with the settings CBAE relies on, closed without leaking.
 *
 * A cbae_db_t is used by one thread at a time; for parallel work open one connection per thread (in WAL mode readers
 * do not block the writer). The functions of the db layer return CBAE_OK or a negative cbae_err_t, with SQLite's
 * message in cbae_last_error(). SQLite's result codes become the layer's codes by cbae_db_err_from_sqlite().
 */
#ifndef CBAE_DB_CONNECTION_H
#define CBAE_DB_CONNECTION_H

#include "cbae/cbae_error.h"
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

/** How long a statement waits for a lock held by another connection before it fails with CBAE_ERR_BUSY. */
#define CBAE_DB_BUSY_TIMEOUT_MS  5000

typedef struct cbae_db {
    sqlite3    *handle;                  /**< NULL when the connection is closed */
    char        path[512];               /**< the path as given, cut to fit: for messages only */
    int         busy_timeout_ms;
} cbae_db_t;

/**
 * Opens the database at @p path (creating it if it does not exist) and sets it up: WAL journal, synchronous NORMAL,
 * foreign keys on, temporary tables in memory, a 32 MB page cache, the busy timeout. @p db must not hold an open
 * connection. Every setting is checked, because the schema relies on all of them: a file that is not a database, a
 * journal mode that stays something other than WAL (":memory:" and "" are never WAL and are exempt) and an SQLite built
 * without foreign keys are errors, not warnings. On failure db->handle is NULL and nothing is left open. Connections
 * that open the same new file together are safe: the one-time switch to WAL is retried while another connection has the
 * file, for as long as the busy timeout, and only then is CBAE_ERR_BUSY returned.
 */
cbae_err_t cbae_db_open  (cbae_db_t *db, const char *path);

/**
 * Closes the connection; a transaction that is still open is rolled back. A statement that has not been finalized
 * keeps the connection alive until it is, and a warning is logged. Closing a closed or NULL connection does nothing.
 */
void       cbae_db_close (cbae_db_t *db);

/** Runs one or more statements that return no rows. */
cbae_err_t cbae_db_exec  (cbae_db_t *db, const char *sql);

sqlite3   *cbae_db_handle(const cbae_db_t *db);

/**
 * The layer's code for an SQLite result code, primary or extended: NOMEM is CBAE_ERR_OOM; BUSY and LOCKED are
 * CBAE_ERR_BUSY (the operation can be tried again); CANTOPEN, IOERR, FULL, READONLY and PERM (the file cannot be read or
 * written) are CBAE_ERR_IO; MISUSE and RANGE are CBAE_ERR_INVALID; OK, ROW and DONE are CBAE_OK; every other code is
 * CBAE_ERR_DB.
 */
cbae_err_t cbae_db_err_from_sqlite(int sqlite_rc);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DB_CONNECTION_H */
