/**
 * @file db_schema.c
 * @brief Schema version tracking and migration runner.
 */
#include "db/db_schema.h"
#include "db/db_query.h"
#include "db/db_transaction.h"
#include "db_migrations.h"
#include "platform/logging.h"
#include <stdio.h>

static const cbae_migration_fn MIGRATIONS[] = {
    cbae_db_migration_001,
    cbae_db_migration_002,
};
#define MIGRATION_COUNT  ((int)(sizeof MIGRATIONS / sizeof MIGRATIONS[0]))
_Static_assert(MIGRATION_COUNT == CBAE_SCHEMA_CURRENT_VERSION, "there is one migration for every schema version");

int cbae_schema_version(cbae_db_t *db) {
    sqlite3_stmt *stmt = NULL;
    CBAE_CHECK(cbae_db_prepare(db, "PRAGMA user_version;", &stmt));
    const int     rc      = cbae_db_step(stmt);
    const int64_t version = rc == CBAE_DB_ROW ? cbae_db_col_int64(stmt, 0) : 0;
    cbae_db_finalize(stmt);
    if (rc < 0) return rc;
    /* user_version is a signed number that anything can set: a negative one would pass for an error code. */
    if (version < 0) CBAE_RETURN_ERR(CBAE_ERR_DB, "the database has a negative schema version (%lld)", (long long)version);
    return (int)version;
}

/* Takes the write lock, and if the schema is still behind applies the next migration and records the new version, all
 * in one transaction. *current is set to the version that results. The version is read again under the lock: another
 * process may have migrated while we waited for it. */
static cbae_err_t migrate_once(cbae_db_t *db, int *current) {
    cbae_txn_t txn;
    CBAE_CHECK(cbae_txn_begin(&txn, db));

    const int found = cbae_schema_version(db);
    if (found < 0) {
        cbae_txn_rollback(&txn);
        return (cbae_err_t)found;
    }
    if (found >= CBAE_SCHEMA_CURRENT_VERSION) {              /* nothing (more) to apply */
        *current = found;
        return cbae_txn_commit(&txn);                        /* ends the transaction that took the lock */
    }

    const int version = found + 1;
    LOG_INFO("Applying migration %03d ...", version);
    cbae_err_t err = MIGRATIONS[found](db);
    if (err != CBAE_OK) {
        CBAE_SET_ERR(err, "Migration %03d failed: %s", version, cbae_last_error());
    } else {
        char sql[64];
        snprintf(sql, sizeof sql, "PRAGMA user_version = %d;", version);
        err = cbae_db_exec(db, sql);
    }
    if (err == CBAE_OK) err = cbae_txn_commit(&txn);
    if (err != CBAE_OK) {
        cbae_txn_rollback(&txn);                             /* a no-op when the commit failed: it has ended the transaction */
        return err;
    }
    LOG_INFO("Migration %03d applied - schema now at v%d", version, version);
    *current = version;
    return CBAE_OK;
}

cbae_err_t cbae_schema_migrate(cbae_db_t *db) {
    int current = cbae_schema_version(db);
    if (current < 0) return (cbae_err_t)current;
    LOG_INFO("DB schema: current=%d  target=%d", current, CBAE_SCHEMA_CURRENT_VERSION);
    while (current != CBAE_SCHEMA_CURRENT_VERSION) {
        if (current > CBAE_SCHEMA_CURRENT_VERSION)
            CBAE_RETURN_ERR(CBAE_ERR_UNSUPPORTED, "the database schema is v%d, newer than the v%d this build understands",
                            current, CBAE_SCHEMA_CURRENT_VERSION);
        CBAE_CHECK(migrate_once(db, &current));
    }
    LOG_DEBUG("Schema at v%d", current);
    return CBAE_OK;
}
