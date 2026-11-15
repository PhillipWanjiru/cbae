/**
 * @file db_transaction.h
 * @brief Transactions: begin takes the write lock, commit either commits or rolls back, rollback is always safe to call.
 *
 * One transaction at a time per connection; they do not nest (use SAVEPOINT through cbae_db_exec for that). A
 * cbae_txn_t is valid from a successful cbae_txn_begin until commit or rollback, and its connection must outlive it:
 *
 *     cbae_txn_t txn;
 *     CBAE_CHECK(cbae_txn_begin(&txn, db));
 *     ...                                          on a failure:  cbae_txn_rollback(&txn); return err;
 *     CBAE_CHECK(cbae_txn_commit(&txn));
 */
#ifndef CBAE_DB_TRANSACTION_H
#define CBAE_DB_TRANSACTION_H

#include "db_connection.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_txn {
    cbae_db_t *db;
    bool       active;               /**< true from a successful begin until the transaction has ended */
} cbae_txn_t;

/**
 * Starts a transaction with BEGIN IMMEDIATE: the write lock is taken now, waiting up to the busy timeout for another
 * connection that holds it, and the first statement is never the one to find out that it cannot write. @p txn is set
 * on every call, so after a failure it is inactive and cbae_txn_rollback does nothing. CBAE_ERR_BUSY if the lock could
 * not be had in time; CBAE_ERR_INVALID if @p db is closed or already has a transaction open.
 */
cbae_err_t cbae_txn_begin   (cbae_txn_t *txn, cbae_db_t *db);

/**
 * Commits. If the commit fails (a deferred foreign key violated, the disk full) the transaction is rolled back and the
 * error returned: after any return the transaction has ended and nothing is left open on the connection.
 * CBAE_ERR_DB if SQLite had already ended the transaction after an earlier error (an I/O error, out of memory).
 */
cbae_err_t cbae_txn_commit  (cbae_txn_t *txn);

/**
 * Rolls back. Does nothing for a transaction that is not active, so it can follow a failed commit or be called twice.
 * A transaction that SQLite has already ended, or whose connection was closed, counts as rolled back. If the ROLLBACK
 * itself fails (an I/O error) the error is logged and txn->active stays true: the call can be repeated, and closing
 * the connection ends the transaction in any case.
 */
void       cbae_txn_rollback(cbae_txn_t *txn);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DB_TRANSACTION_H */
