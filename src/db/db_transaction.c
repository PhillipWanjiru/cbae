/**
 * @file db_transaction.c
 * @brief Scoped transactions — BEGIN / COMMIT / ROLLBACK.
 */
#include "db/db_transaction.h"
#include "platform/logging.h"

cbae_err_t cbae_txn_begin(cbae_txn_t *txn, cbae_db_t *db) {
    if(!txn || !db) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null arg");
    int rc = cbae_db_exec(db, "BEGIN;");
    if(rc != SQLITE_OK) CBAE_RETURN_ERR(CBAE_ERR_DB, "BEGIN failed");
    txn->db     = db;
    txn->active = true;
    return CBAE_OK;
}

cbae_err_t cbae_txn_commit(cbae_txn_t *txn) {
    if(!txn || !txn->active) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "no active txn");
    int rc = cbae_db_exec(txn->db, "COMMIT;");
    txn->active = false;
    if(rc != SQLITE_OK) CBAE_RETURN_ERR(CBAE_ERR_DB, "COMMIT failed");
    return CBAE_OK;
}

void cbae_txn_rollback(cbae_txn_t *txn) {
    if(!txn || !txn->active) return;
    cbae_db_exec(txn->db, "ROLLBACK;");
    txn->active = false;
    LOG_WARN("Transaction rolled back");
}
