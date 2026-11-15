/**
 * @file db_query.h
 * @brief Prepared statements: prepare, bind, step, read the columns, finalize.
 *
 * Parameter numbers start at 1, column numbers at 0 (SQLite's own). A statement is used from one thread at a time and
 * must be finalized before its connection is closed (cbae_db_close warns about one that was not).
 */
#ifndef CBAE_DB_QUERY_H
#define CBAE_DB_QUERY_H

#include "db_connection.h"
#include <sqlite3.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** What cbae_db_step returns while there is a row to read. */
#define CBAE_DB_ROW  1

/**
 * Prepares exactly one statement. *out_stmt is NULL unless CBAE_OK is returned. A string with no statement in it
 * (empty, or only comments and semicolons) and a string with a second statement after the first are CBAE_ERR_INVALID:
 * SQLite would ignore the rest, and a caller that wrote two statements wants both. (cbae_db_exec runs several.)
 */
cbae_err_t cbae_db_prepare (cbae_db_t *db, const char *sql, sqlite3_stmt **out_stmt);

/**
 * Runs the statement to its next row. Returns CBAE_DB_ROW (1) if a row can be read, CBAE_OK (0) when the statement has
 * finished (all rows read, or an INSERT/UPDATE/DELETE done), and a negative cbae_err_t on failure:
 *
 *     int rc;
 *     while ((rc = cbae_db_step(stmt)) == CBAE_DB_ROW) { ... cbae_db_col_...(stmt, n) ... }
 *     if (rc < 0) { ... cbae_last_error() ... }
 *
 * A statement that has finished or failed runs again from the start on the next step (SQLite resets it itself and keeps
 * the bound values). cbae_db_reset does that explicitly, and also lets go of a statement that is part-way through.
 */
int        cbae_db_step    (sqlite3_stmt *stmt);

/** Makes the statement ready to run again, and forgets what was bound to it (every parameter is NULL until bound again). */
void       cbae_db_reset   (sqlite3_stmt *stmt);
void       cbae_db_finalize(sqlite3_stmt *stmt);

cbae_err_t cbae_db_bind_int64 (sqlite3_stmt *s, int idx, int64_t v);
cbae_err_t cbae_db_bind_double(sqlite3_stmt *s, int idx, double v);               /* NaN is stored as NULL, as SQLite does */
cbae_err_t cbae_db_bind_text  (sqlite3_stmt *s, int idx, const char *v);          /* copied; up to the first NUL; NULL binds SQL NULL */
cbae_err_t cbae_db_bind_blob  (sqlite3_stmt *s, int idx,
                               const void *data, int len);                        /* copied; len >= 0; data NULL (with len 0) binds SQL NULL; len 0 with data is an empty blob */
cbae_err_t cbae_db_bind_null  (sqlite3_stmt *s, int idx);

/* The current row. A pointer is valid until the next step, reset or finalize. Text and blobs are what was stored:
 * text is not necessarily UTF-8 and may be cut by an embedded NUL; use cbae_db_col_bytes for the length. NULL (0 for
 * the numbers) is returned for an SQL NULL, and also when there is no current row (before the first step, after the
 * last one), the column does not exist or the statement is NULL. Call col_text or col_blob before col_bytes. */
int64_t     cbae_db_col_int64 (sqlite3_stmt *s, int col);
double      cbae_db_col_double(sqlite3_stmt *s, int col);
const char *cbae_db_col_text  (sqlite3_stmt *s, int col);
const void *cbae_db_col_blob  (sqlite3_stmt *s, int col);
int         cbae_db_col_bytes (sqlite3_stmt *s, int col);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DB_QUERY_H */
