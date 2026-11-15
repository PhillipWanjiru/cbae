/**
 * @file db_query_helpers.c
 * @brief Thin wrappers around sqlite3_bind/step/column/finalize.
 */
#include "db/db_query.h"
#include "platform/logging.h"

cbae_err_t cbae_db_prepare(cbae_db_t *db, const char *sql, sqlite3_stmt **out) {
    int rc = sqlite3_prepare_v2(db->handle, sql, -1, out, NULL);
    if(rc != SQLITE_OK)
        CBAE_RETURN_ERR(CBAE_ERR_DB, "prepare failed: %s  SQL: %.120s",
                        sqlite3_errmsg(db->handle), sql);
    return CBAE_OK;
}

cbae_err_t cbae_db_step(sqlite3_stmt *stmt) {
    int rc = sqlite3_step(stmt);
    if(rc == SQLITE_DONE || rc == SQLITE_ROW) return CBAE_OK;
    CBAE_RETURN_ERR(CBAE_ERR_DB, "step: %s",
                    sqlite3_errmsg(sqlite3_db_handle(stmt)));
}

void cbae_db_reset   (sqlite3_stmt *s) { sqlite3_reset(s); }
void cbae_db_finalize(sqlite3_stmt *s) { sqlite3_finalize(s); }

cbae_err_t cbae_db_bind_int64 (sqlite3_stmt *s, int c, int64_t v) {
    return sqlite3_bind_int64(s, c, v)==SQLITE_OK ? CBAE_OK :
           (CBAE_SET_ERR(CBAE_ERR_DB,"bind_int64 col %d",c), CBAE_ERR_DB);
}
cbae_err_t cbae_db_bind_double(sqlite3_stmt *s, int c, double v) {
    return sqlite3_bind_double(s, c, v)==SQLITE_OK ? CBAE_OK :
           (CBAE_SET_ERR(CBAE_ERR_DB,"bind_double col %d",c), CBAE_ERR_DB);
}
cbae_err_t cbae_db_bind_text(sqlite3_stmt *s, int c, const char *v) {
    return sqlite3_bind_text(s,c,v,-1,SQLITE_TRANSIENT)==SQLITE_OK ? CBAE_OK :
           (CBAE_SET_ERR(CBAE_ERR_DB,"bind_text col %d",c), CBAE_ERR_DB);
}
cbae_err_t cbae_db_bind_blob(sqlite3_stmt *s, int c, const void *d, int len) {
    return sqlite3_bind_blob(s,c,d,len,SQLITE_TRANSIENT)==SQLITE_OK ? CBAE_OK :
           (CBAE_SET_ERR(CBAE_ERR_DB,"bind_blob col %d",c), CBAE_ERR_DB);
}
cbae_err_t cbae_db_bind_null(sqlite3_stmt *s, int c) {
    sqlite3_bind_null(s, c); return CBAE_OK;
}

int64_t    cbae_db_col_int64 (sqlite3_stmt *s, int c) { return (int64_t)sqlite3_column_int64(s,c); }
double     cbae_db_col_double(sqlite3_stmt *s, int c) { return sqlite3_column_double(s,c); }
const char*cbae_db_col_text  (sqlite3_stmt *s, int c) { return (const char*)sqlite3_column_text(s,c); }
const void*cbae_db_col_blob  (sqlite3_stmt *s, int c) { return sqlite3_column_blob(s,c); }
int        cbae_db_col_bytes (sqlite3_stmt *s, int c) { return sqlite3_column_bytes(s,c); }
