/**
 * @file db_schema.c
 * @brief Schema version tracking and migration runner.
 */
#include "db/db_schema.h"
#include "platform/logging.h"
#include <stdio.h>

cbae_err_t cbae_db_migration_001(cbae_db_t *db);
cbae_err_t cbae_db_migration_002(cbae_db_t *db);

typedef cbae_err_t (*migration_fn_t)(cbae_db_t *);
static const migration_fn_t MIGRATIONS[] = {
    cbae_db_migration_001,
    cbae_db_migration_002,
};
#define MIGRATION_COUNT (int)(sizeof(MIGRATIONS)/sizeof(MIGRATIONS[0]))

int cbae_schema_version(cbae_db_t *db) {
    sqlite3_stmt *stmt = NULL;
    int version = 0;
    if(sqlite3_prepare_v2(db->handle, "PRAGMA user_version;",
                           -1, &stmt, NULL) == SQLITE_OK) {
        if(sqlite3_step(stmt) == SQLITE_ROW)
            version = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }
    return version;
}

cbae_err_t cbae_schema_migrate(cbae_db_t *db) {
    int current = cbae_schema_version(db);
    LOG_INFO("DB schema: current=%d  target=%d", current, CBAE_SCHEMA_CURRENT_VERSION);
    if(current >= CBAE_SCHEMA_CURRENT_VERSION) { LOG_DEBUG("Schema up to date"); return CBAE_OK; }
    for(int i = current; i < MIGRATION_COUNT; i++) {
        int version = i + 1;
        LOG_INFO("Applying migration %03d ...", version);
        cbae_err_t err = MIGRATIONS[i](db);
        if(err != CBAE_OK)
            CBAE_RETURN_ERR(err, "Migration %03d failed: %s", version, cbae_last_error());
        char sql[64];
        snprintf(sql, sizeof(sql), "PRAGMA user_version = %d;", version);
        int rc = cbae_db_exec(db, sql);
        if(rc != SQLITE_OK)
            CBAE_RETURN_ERR(CBAE_ERR_DB, "Failed to set user_version to %d", version);
        LOG_INFO("Migration %03d applied — schema now at v%d", version, version);
    }
    LOG_INFO("All migrations complete — schema v%d", CBAE_SCHEMA_CURRENT_VERSION);
    return CBAE_OK;
}
