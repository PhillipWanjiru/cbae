/**
 * @file db_transaction.h
 * @brief Scoped ACID transactions with automatic rollback on error.
 */
#ifndef CBAE_DB_TRANSACTION_H
#define CBAE_DB_TRANSACTION_H

#include "db_connection.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_txn {
    cbae_db_t *db;
    bool       active;
} cbae_txn_t;

cbae_err_t cbae_txn_begin   (cbae_txn_t *txn, cbae_db_t *db);
cbae_err_t cbae_txn_commit  (cbae_txn_t *txn);
void       cbae_txn_rollback(cbae_txn_t *txn);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_DB_TRANSACTION_H */
