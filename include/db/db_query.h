/**
 * @file db_query.h
 * @brief Prepared statement helpers — bind, step, column wrappers.
 */
#ifndef CBAE_DB_QUERY_H
#define CBAE_DB_QUERY_H

#include "db_connection.h"
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

cbae_err_t cbae_db_prepare(cbae_db_t *db,
                            const char *sql, sqlite3_stmt **out_stmt);
cbae_err_t cbae_db_step   (sqlite3_stmt *stmt);
void       cbae_db_reset  (sqlite3_stmt *stmt);
void       cbae_db_finalize(sqlite3_stmt *stmt);

cbae_err_t cbae_db_bind_int64 (sqlite3_stmt *s, int col, int64_t  v);
cbae_err_t cbae_db_bind_double(sqlite3_stmt *s, int col, double   v);
cbae_err_t cbae_db_bind_text  (sqlite3_stmt *s, int col, const char *v);
cbae_err_t cbae_db_bind_blob  (sqlite3_stmt *s, int col,
                                const void *data, int len);
cbae_err_t cbae_db_bind_null  (sqlite3_stmt *s, int col);

int64_t     cbae_db_col_int64 (sqlite3_stmt *s, int col);
double      cbae_db_col_double(sqlite3_stmt *s, int col);
const char *cbae_db_col_text  (sqlite3_stmt *s, int col);
const void *cbae_db_col_blob  (sqlite3_stmt *s, int col);
int         cbae_db_col_bytes (sqlite3_stmt *s, int col);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DB_QUERY_H */
