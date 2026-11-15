/**
 * @file db_migrations.h
 * @brief The migrations, one per schema version. Private to the db layer: db_schema.c runs them.
 *
 * A migration only creates or alters objects. db_schema.c wraps it in a transaction and records the new version, so a
 * migration neither begins nor commits and returns the first error it meets.
 */
#ifndef CBAE_DB_MIGRATIONS_H
#define CBAE_DB_MIGRATIONS_H

#include "db/db_connection.h"

typedef cbae_err_t (*cbae_migration_fn)(cbae_db_t *db);

cbae_err_t cbae_db_migration_001(cbae_db_t *db);     /* version 1 */
cbae_err_t cbae_db_migration_002(cbae_db_t *db);     /* version 2 */

#endif /* CBAE_DB_MIGRATIONS_H */
