/**
 * @file db_transaction.c
 * @brief Transactions: BEGIN IMMEDIATE / COMMIT / ROLLBACK, and what to do when SQLite has ended one by itself.
 */
#include "db/db_transaction.h"
#include "platform/logging.h"
#include <stdio.h>

/* Is the transaction open on its connection? SQLite ends a transaction by itself after some errors (disk full, an I/O
 * error, out of memory, an interrupt), and closing the connection ends it too. */
static bool open_on_connection(const cbae_txn_t *txn) {
    return txn->db && txn->db->handle && !sqlite3_get_autocommit(txn->db->handle);
}

/* ROLLBACK if the transaction is still open; CBAE_OK when none is left open. */
static cbae_err_t rollback_if_open(cbae_txn_t *txn) {
    if (!open_on_connection(txn)) return CBAE_OK;
    return cbae_db_exec(txn->db, "ROLLBACK;");
}

cbae_err_t cbae_txn_begin(cbae_txn_t *txn, cbae_db_t *db) {
    if (!txn) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null transaction");
    txn->db     = NULL;                                  /* a failed begin leaves a transaction that does nothing */
    txn->active = false;
    if (!db) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null database");
    if (!db->handle) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "the database is not open");
    if (!sqlite3_get_autocommit(db->handle))
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "a transaction is already open on this connection (they do not nest)");
    CBAE_CHECK(cbae_db_exec(db, "BEGIN IMMEDIATE;"));
    txn->db     = db;
    txn->active = true;
    return CBAE_OK;
}

cbae_err_t cbae_txn_commit(cbae_txn_t *txn) {
    if (!txn || !txn->active) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "no active transaction");
    if (!open_on_connection(txn)) {
        txn->active = false;
        CBAE_RETURN_ERR(CBAE_ERR_DB, "the transaction was already rolled back (by SQLite after an error, or by closing the database)");
    }
    const cbae_err_t err = cbae_db_exec(txn->db, "COMMIT;");
    if (err == CBAE_OK) {
        txn->active = false;
        return CBAE_OK;
    }
    /* A failed COMMIT can leave the transaction open (a deferred constraint, a busy lock). The caller cannot do
     * anything with a transaction whose commit has failed, and the next BEGIN would fail while it is open: end it. */
    char why[CBAE_ERR_MSG_MAX];
    snprintf(why, sizeof why, "%s", cbae_last_error());
    txn->active = rollback_if_open(txn) != CBAE_OK;
    CBAE_SET_ERR(err, "COMMIT failed, transaction rolled back: %s", why);
    return err;
}

void cbae_txn_rollback(cbae_txn_t *txn) {
    if (!txn || !txn->active) return;
    if (rollback_if_open(txn) != CBAE_OK) {
        LOG_ERROR("ROLLBACK failed (%s); the transaction stays open until the connection is closed", cbae_last_error());
        return;
    }
    txn->active = false;
    LOG_WARN("Transaction rolled back");
}
