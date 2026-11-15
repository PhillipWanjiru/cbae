/**
 * @file db_migration_001.c
 * @brief Migration 001 — baseline schema: binaries, analysis_jobs.
 */
#include "db_migrations.h"
#include "platform/logging.h"

static const char S_DDL[] =
"CREATE TABLE IF NOT EXISTS binaries ("
"  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
"  path        TEXT    NOT NULL,"
"  sha256      TEXT    NOT NULL,"
"  format      TEXT    NOT NULL,"
"  arch        TEXT    NOT NULL,"
"  os_origin   TEXT    NOT NULL,"
"  file_size   INTEGER NOT NULL,"
"  entry_point INTEGER,"
"  created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
");"
"CREATE UNIQUE INDEX IF NOT EXISTS idx_binaries_sha256 ON binaries(sha256);"
"CREATE TABLE IF NOT EXISTS analysis_jobs ("
"  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
"  binary_id   INTEGER REFERENCES binaries(id),"
"  stage       TEXT    NOT NULL DEFAULT 'pending',"
"  priority    INTEGER NOT NULL DEFAULT 0,"
"  worker_pid  INTEGER,"
"  error_msg   TEXT,"
"  created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),"
"  updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
");"
"CREATE INDEX IF NOT EXISTS idx_jobs_stage ON analysis_jobs(stage, priority DESC);";

cbae_err_t cbae_db_migration_001(cbae_db_t *db) {
    LOG_INFO("Running migration 001 — baseline schema");
    return cbae_db_exec(db, S_DDL);
}
