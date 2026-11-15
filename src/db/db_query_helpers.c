/**
 * @file db_query_helpers.c
 * @brief Prepared statements: prepare exactly one, bind with checked results, step with ROW/DONE told apart.
 */
#include "db/db_query.h"
#include "platform/logging.h"
#include <stdbool.h>

/* Is there anything after the first statement? Whitespace, semicolons and comments are not statements. */
static cbae_err_t check_nothing_follows(sqlite3 *h, const char *tail, const char *sql) {
    sqlite3_stmt *next = NULL;
    const int rc = sqlite3_prepare_v2(h, tail, -1, &next, NULL);
    const bool more = next != NULL;
    sqlite3_finalize(next);
    if (rc == SQLITE_NOMEM) CBAE_RETURN_ERR(CBAE_ERR_OOM, "out of memory preparing: %.120s", sql);
    if (rc != SQLITE_OK || more)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "more than one SQL statement (only the first would run): %.120s", sql);
    return CBAE_OK;
}

cbae_err_t cbae_db_prepare(cbae_db_t *db, const char *sql, sqlite3_stmt **out) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null statement output");
    *out = NULL;
    if (!db || !sql) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");
    if (!db->handle) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "the database is not open");

    sqlite3_stmt *st = NULL;
    const char *tail = NULL;
    const int rc = sqlite3_prepare_v2(db->handle, sql, -1, &st, &tail);
    if (rc != SQLITE_OK) {
        const cbae_err_t err = cbae_db_err_from_sqlite(rc);
        CBAE_SET_ERR(err, "prepare failed: %s  SQL: %.120s", sqlite3_errmsg(db->handle), sql);
        return err;
    }
    if (!st) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "no SQL statement in: %.120s", sql);
    const cbae_err_t err = check_nothing_follows(db->handle, tail, sql);
    if (err != CBAE_OK) { sqlite3_finalize(st); return err; }
    *out = st;
    return CBAE_OK;
}

int cbae_db_step(sqlite3_stmt *stmt) {
    if (!stmt) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null statement");
    const int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) return CBAE_DB_ROW;
    if (rc == SQLITE_DONE) return CBAE_OK;
    const cbae_err_t err = cbae_db_err_from_sqlite(rc);
    CBAE_SET_ERR(err, "step: %s", sqlite3_errmsg(sqlite3_db_handle(stmt)));
    return err;
}

void cbae_db_reset(sqlite3_stmt *s) {
    if (!s) return;
    sqlite3_reset(s);                                   /* its result is the failure of the last step, which was reported then */
    sqlite3_clear_bindings(s);
}
void cbae_db_finalize(sqlite3_stmt *s) { sqlite3_finalize(s); }

static cbae_err_t bound(int rc, const char *what, int idx) {
    if (rc == SQLITE_OK) return CBAE_OK;
    const cbae_err_t err = cbae_db_err_from_sqlite(rc);
    CBAE_SET_ERR(err, "bind_%s at parameter %d: %s", what, idx, sqlite3_errstr(rc));
    return err;
}

cbae_err_t cbae_db_bind_int64(sqlite3_stmt *s, int idx, int64_t v) {
    if (!s) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null statement");
    return bound(sqlite3_bind_int64(s, idx, v), "int64", idx);
}

cbae_err_t cbae_db_bind_double(sqlite3_stmt *s, int idx, double v) {
    if (!s) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null statement");
    return bound(sqlite3_bind_double(s, idx, v), "double", idx);
}

cbae_err_t cbae_db_bind_text(sqlite3_stmt *s, int idx, const char *v) {
    if (!s) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null statement");
    return bound(sqlite3_bind_text(s, idx, v, -1, SQLITE_TRANSIENT), "text", idx);
}

cbae_err_t cbae_db_bind_blob(sqlite3_stmt *s, int idx, const void *data, int len) {
    if (!s) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null statement");
    /* SQLite takes a negative length of a blob as "up to a terminator", which a blob does not have: it would read on
     * past the end of the caller's buffer. */
    if (len < 0) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "bind_blob at parameter %d: negative length %d", idx, len);
    if (!data && len > 0) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "bind_blob at parameter %d: %d bytes from a NULL pointer", idx, len);
    return bound(sqlite3_bind_blob(s, idx, data, len, SQLITE_TRANSIENT), "blob", idx);
}

cbae_err_t cbae_db_bind_null(sqlite3_stmt *s, int idx) {
    if (!s) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null statement");
    return bound(sqlite3_bind_null(s, idx), "null", idx);
}

/* SQLite calls the result for a column of a row that is not there undefined (it happens to be NULL): the layer says so itself. */
static bool has_column(sqlite3_stmt *s, int c) { return s && c >= 0 && c < sqlite3_data_count(s); }

int64_t     cbae_db_col_int64 (sqlite3_stmt *s, int c) { return has_column(s, c) ? (int64_t)sqlite3_column_int64(s, c) : 0; }
double      cbae_db_col_double(sqlite3_stmt *s, int c) { return has_column(s, c) ? sqlite3_column_double(s, c) : 0.0; }
const char *cbae_db_col_text  (sqlite3_stmt *s, int c) { return has_column(s, c) ? (const char *)sqlite3_column_text(s, c) : NULL; }
const void *cbae_db_col_blob  (sqlite3_stmt *s, int c) { return has_column(s, c) ? sqlite3_column_blob(s, c) : NULL; }
int         cbae_db_col_bytes (sqlite3_stmt *s, int c) { return has_column(s, c) ? sqlite3_column_bytes(s, c) : 0; }
