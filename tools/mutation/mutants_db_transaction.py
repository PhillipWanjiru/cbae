"""The mutants of src/db/db_transaction.c: (name, text that occurs exactly once, its replacement). A name starts with its tag.
Used by run_mut.py (set MUT_TIMEOUT=60: a mutant that hangs is killed by the timeout). The mutants that cannot be told from
the original are marked (equivalent) and explained in docs/audit."""
SRC = 'src/db/db_transaction.c'
TESTS = ['test_db_persistence']

MUTANTS = [
 ("X01 open_on_connection: a transaction without a connection is not allowed for (equivalent: only an active transaction gets here, and it has one)", "return txn->db && txn->db->handle &&", "return txn->db->handle &&"),
 ("X02 open_on_connection: a closed connection is not allowed for", "return txn->db && txn->db->handle &&", "return txn->db &&"),
 ("X03 open_on_connection: inverted", "&& !sqlite3_get_autocommit(txn->db->handle);", "&& sqlite3_get_autocommit(txn->db->handle);"),
 ("X04 rollback_if_open: ROLLBACK even when nothing is open", "    if (!open_on_connection(txn)) return CBAE_OK;\n    return cbae_db_exec(txn->db, \"ROLLBACK;\");", "    return cbae_db_exec(txn->db, \"ROLLBACK;\");"),
 ("X05 rollback_if_open: COMMIT instead of ROLLBACK", 'return cbae_db_exec(txn->db, "ROLLBACK;");', 'return cbae_db_exec(txn->db, "COMMIT;");'),
 ("X06 begin: a NULL transaction is accepted", '    if (!txn) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null transaction");\n', ""),
 ("X07 begin: the transaction keeps its connection after a failure", "    txn->db     = NULL;                                  /* a failed begin leaves a transaction that does nothing */\n", ""),
 ("X08 begin: the transaction keeps its state after a failure", "    txn->active = false;\n    if (!db)", "    if (!db)"),
 ("X09 begin: a NULL database is accepted", '    if (!db) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null database");\n', ""),
 ("X10 begin: a closed database is passed on", '    if (!db->handle) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "the database is not open");\n', ""),
 ("X11 begin: a transaction inside a transaction is not noticed", '    if (!sqlite3_get_autocommit(db->handle))\n        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "a transaction is already open on this connection (they do not nest)");\n', ""),
 ("X12 begin: the lock is not taken until the first write", '"BEGIN IMMEDIATE;"', '"BEGIN;"'),
 ("X13 begin: EXCLUSIVE instead of IMMEDIATE (equivalent in WAL mode)", '"BEGIN IMMEDIATE;"', '"BEGIN EXCLUSIVE;"'),
 ("X14 begin: the connection is not kept", "    txn->db     = db;\n", ""),
 ("X15 begin: the transaction is not active", "    txn->active = true;\n", ""),
 ("X16 commit: a transaction that is not active is committed", "if (!txn || !txn->active) CBAE_RETURN_ERR(CBAE_ERR_INVALID, \"no active transaction\");", "if (!txn) CBAE_RETURN_ERR(CBAE_ERR_INVALID, \"no active transaction\");"),
 ("X17 commit: a transaction SQLite ended is committed", "    if (!open_on_connection(txn)) {\n        txn->active = false;", "    if (0) {\n        txn->active = false;"),
 ("X18 commit: a transaction SQLite ended stays active", "    if (!open_on_connection(txn)) {\n        txn->active = false;\n", "    if (!open_on_connection(txn)) {\n"),
 ("X19 commit: a transaction SQLite ended is an invalid argument", 'CBAE_RETURN_ERR(CBAE_ERR_DB, "the transaction was already rolled back', 'CBAE_RETURN_ERR(CBAE_ERR_INVALID, "the transaction was already rolled back'),
 ("X20 commit: ROLLBACK instead of COMMIT", 'cbae_db_exec(txn->db, "COMMIT;")', 'cbae_db_exec(txn->db, "ROLLBACK;")'),
 ("X21 commit: still active after a commit that worked", "    if (err == CBAE_OK) {\n        txn->active = false;\n        return CBAE_OK;\n    }", "    if (err == CBAE_OK) {\n        return CBAE_OK;\n    }"),
 ("X22 commit: a failed commit leaves the transaction open", "    txn->active = rollback_if_open(txn) != CBAE_OK;\n", "    txn->active = false;\n"),
 ("X23 commit: a failed commit stays active", "    txn->active = rollback_if_open(txn) != CBAE_OK;\n", "    rollback_if_open(txn);\n    txn->active = true;\n"),
 ("X24 commit: a failed rollback after a failed commit is not remembered (equivalent: a rollback that fails cannot be provoked)", "    txn->active = rollback_if_open(txn) != CBAE_OK;\n", "    rollback_if_open(txn);\n    txn->active = false;\n"),
 ("X25 commit: the reason is not in the message", 'snprintf(why, sizeof why, "%s", cbae_last_error());', "why[0] = '\\0';"),
 ("X26 commit: the message does not say it was rolled back", '"COMMIT failed, transaction rolled back: %s"', '"COMMIT failed: %s"'),
 ("X27 commit: a failed commit is a generic error", 'CBAE_SET_ERR(err, "COMMIT failed', 'CBAE_SET_ERR(CBAE_ERR_GENERIC, "COMMIT failed'),
 ("X28 rollback: a transaction that is not active is rolled back (and warned about)", "if (!txn || !txn->active) return;\n    if (rollback_if_open", "if (!txn) return;\n    if (rollback_if_open"),
 ("X29 rollback: the transaction stays active", "    txn->active = false;\n    LOG_WARN(\"Transaction rolled back\");", "    LOG_WARN(\"Transaction rolled back\");"),
 ("X30 rollback: no warning", '    LOG_WARN("Transaction rolled back");\n', ""),
 ("X31 rollback: a failed ROLLBACK ends the transaction (equivalent: a rollback that fails cannot be provoked)", "        return;\n    }\n    txn->active = false;", "    }\n    txn->active = false;"),
]
