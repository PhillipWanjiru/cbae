/**
 * @file db_schema.h
 * @brief Schema versioning and migration runner.
 *
 * The schema version is SQLite's user_version. Every migration runs in its own transaction together with the update of
 * the version: a migration that fails changes nothing, and two processes migrating the same file take turns.
 *
 * Version history:
 *   1 — Phase 1: binaries, analysis_jobs
 *   2 — Phase 2: sections, symbols, imports, relocations, loader_results
 */
#ifndef CBAE_DB_SCHEMA_H
#define CBAE_DB_SCHEMA_H

#include "db_connection.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CBAE_SCHEMA_CURRENT_VERSION  2

/**
 * Brings the schema up to CBAE_SCHEMA_CURRENT_VERSION, one migration at a time; a schema that is current is not
 * touched (no lock is taken). A database whose version is newer than this build knows is CBAE_ERR_UNSUPPORTED and is
 * left as it is: an older program must not write into a schema it does not understand. A migration that fails is
 * rolled back, the error names it, and the database stays at the last version that was applied completely.
 */
cbae_err_t cbae_schema_migrate(cbae_db_t *db);

/** The schema version (0 for a database that nothing has been created in), or a negative cbae_err_t. */
int        cbae_schema_version(cbae_db_t *db);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DB_SCHEMA_H */
