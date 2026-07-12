/**
 * @file db_schema.h
 * @brief Schema versioning and migration runner.
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

cbae_err_t cbae_schema_migrate(cbae_db_t *db);
int        cbae_schema_version(cbae_db_t *db);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DB_SCHEMA_H */
