"""The mutants of src/db/db_schema.c: (name, text that occurs exactly once, its replacement). A name starts with its tag.
Used by run_mut.py (set MUT_TIMEOUT=60: a mutant that hangs is killed by the timeout). The mutants that cannot be told from
the original are marked (equivalent) and explained in docs/audit."""
SRC = 'src/db/db_schema.c'
TESTS = ['test_db_persistence']

MUTANTS = [
 ("S01 version: a failed prepare is not noticed (the message differs only)", '    CBAE_CHECK(cbae_db_prepare(db, "PRAGMA user_version;", &stmt));', '    cbae_db_prepare(db, "PRAGMA user_version;", &stmt);'),
 ("S02 version: a failed read is the version 0", "    if (rc < 0) return rc;\n", ""),
 ("S03 version: a failed read is a generic error", "    if (rc < 0) return rc;", "    if (rc < 0) return CBAE_ERR_GENERIC;"),
 ("S04 version: 0 is an invalid version", "if (version < 0) CBAE_RETURN_ERR", "if (version <= 0) CBAE_RETURN_ERR"),
 ("S05 version: a negative version is not noticed", "    if (version < 0) CBAE_RETURN_ERR(CBAE_ERR_DB, \"the database has a negative schema version (%lld)\", (long long)version);\n", ""),
 ("S06 version: a negative version is an I/O error", 'CBAE_RETURN_ERR(CBAE_ERR_DB, "the database has a negative', 'CBAE_RETURN_ERR(CBAE_ERR_IO, "the database has a negative'),
 ("S07 version: the statement is not finalized", "    cbae_db_finalize(stmt);\n    if (rc < 0) return rc;", "    if (rc < 0) return rc;"),
 ("S08 migrate_once: the lock is not taken (equivalent when it is free; a busy lock shows as busy later)", "    CBAE_CHECK(cbae_txn_begin(&txn, db));\n", "    (void)cbae_txn_begin(&txn, db);\n"),
 ("S09 migrate_once: the transaction is left open when the version cannot be read", "    if (found < 0) {\n        cbae_txn_rollback(&txn);\n        return (cbae_err_t)found;\n    }", "    if (found < 0) {\n        return (cbae_err_t)found;\n    }"),
 ("S10 migrate_once: a current schema runs a migration", "if (found >= CBAE_SCHEMA_CURRENT_VERSION) {              /* nothing (more) to apply */", "if (found > CBAE_SCHEMA_CURRENT_VERSION) {               /* nothing (more) to apply */"),
 ("S11 migrate_once: the version found under the lock is not kept", "        *current = found;\n        return cbae_txn_commit(&txn);", "        return cbae_txn_commit(&txn);"),
 ("S12 migrate_once: the transaction that took the lock is left open", "        return cbae_txn_commit(&txn);                        /* ends the transaction that took the lock */", "        return CBAE_OK;                                      /* ends the transaction that took the lock */"),
 ("S13 migrate_once: the next version is not taken from what was found", "    const int version = found + 1;", "    const int version = *current + 1;"),
 ("S14 migrate_once: the migration is not taken from what was found", "    cbae_err_t err = MIGRATIONS[found](db);", "    cbae_err_t err = MIGRATIONS[*current](db);"),
 ("S15 migrate_once: the failure does not name the migration", '        CBAE_SET_ERR(err, "Migration %03d failed: %s", version, cbae_last_error());\n', ""),
 ("S16 migrate_once: the version is not recorded", "        err = cbae_db_exec(db, sql);\n    }", "        err = CBAE_OK;\n    }"),
 ("S17 migrate_once: the version recorded is the old one", 'snprintf(sql, sizeof sql, "PRAGMA user_version = %d;", version);', 'snprintf(sql, sizeof sql, "PRAGMA user_version = %d;", found);'),
 ("S18 migrate_once: the migration is not committed", "    if (err == CBAE_OK) err = cbae_txn_commit(&txn);\n", ""),
 ("S19 migrate_once: a failed migration is not rolled back", "        cbae_txn_rollback(&txn);                             /* a no-op when the commit failed: it has ended the transaction */\n", ""),
 ("S20 migrate_once: the new version is not reported", "    *current = version;\n    return CBAE_OK;", "    return CBAE_OK;"),
 ("S21 migrate: a failed read of the version is not returned (equivalent: the next step fails the same way)", "    if (current < 0) return (cbae_err_t)current;\n", ""),
 ("S22 migrate: a newer schema is not refused", "while (current != CBAE_SCHEMA_CURRENT_VERSION) {", "while (current < CBAE_SCHEMA_CURRENT_VERSION) {"),
 ("S23 migrate: a newer schema is a database error", "CBAE_RETURN_ERR(CBAE_ERR_UNSUPPORTED, \"the database schema is v%d", "CBAE_RETURN_ERR(CBAE_ERR_DB, \"the database schema is v%d"),
 ("S24 migrate: the two versions in the message are swapped", "                            current, CBAE_SCHEMA_CURRENT_VERSION);", "                            CBAE_SCHEMA_CURRENT_VERSION, current);"),
 ("S25 migrate: the failure of a step is not returned", "        CBAE_CHECK(migrate_once(db, &current));", "        (void)migrate_once(db, &current);"),
 ("S26 migrate: a newer schema is refused at the version itself (equivalent: the loop never runs for it)", "        if (current > CBAE_SCHEMA_CURRENT_VERSION)\n", "        if (current >= CBAE_SCHEMA_CURRENT_VERSION)\n"),
]
