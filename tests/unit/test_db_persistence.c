/**
 * @file test_db_persistence.c
 * @brief Verify schema creation, record insert, and read-back via SQLite.
 */
#include "db/db_connection.h"
#include "db/db_schema.h"
#include "db/db_query.h"
#include "db/db_transaction.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TEST_DB  "/tmp/cbae_test_phase2.db"

int main(void) {
    printf("=== test_db_persistence ===\n");
    unlink(TEST_DB);
    cbae_db_t db;
    assert(cbae_db_open(&db, TEST_DB) == CBAE_OK);
    printf("  [PASS] open\n");

    assert(cbae_schema_migrate(&db) == CBAE_OK);
    int ver = cbae_schema_version(&db);
    assert(ver == CBAE_SCHEMA_CURRENT_VERSION);
    printf("  [PASS] migration applied, version = %d\n", ver);

    /* Idempotent */
    assert(cbae_schema_migrate(&db) == CBAE_OK);
    assert(cbae_schema_version(&db) == CBAE_SCHEMA_CURRENT_VERSION);
    printf("  [PASS] migration idempotent\n");

    cbae_txn_t txn;
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    sqlite3_stmt *ins;
    assert(cbae_db_prepare(&db,
        "INSERT INTO binaries(path,sha256,format,arch,os_origin,file_size)"
        " VALUES(?,?,?,?,?,?);", &ins) == CBAE_OK);
    cbae_db_bind_text (ins, 1, "/drivers/r8169.sys");
    cbae_db_bind_text (ins, 2, "aabbccdd");
    cbae_db_bind_text (ins, 3, "pe32plus");
    cbae_db_bind_text (ins, 4, "x86_64");
    cbae_db_bind_text (ins, 5, "windows");
    cbae_db_bind_int64(ins, 6, 98765);
    assert(cbae_db_step(ins) == CBAE_OK);
    cbae_db_finalize(ins);
    assert(cbae_txn_commit(&txn) == CBAE_OK);
    printf("  [PASS] insert binary record\n");

    sqlite3_stmt *sel;
    assert(cbae_db_prepare(&db,
        "SELECT path, file_size FROM binaries WHERE sha256='aabbccdd';",
        &sel) == CBAE_OK);
    assert(cbae_db_step(sel) == CBAE_OK);
    const char *path = cbae_db_col_text(sel, 0);
    int64_t     size = cbae_db_col_int64(sel, 1);
    assert(path && strcmp(path, "/drivers/r8169.sys") == 0);
    assert(size == 98765);
    cbae_db_finalize(sel);
    printf("  [PASS] read-back path and size\n");

    /* Rollback test */
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    cbae_db_exec(&db,
        "INSERT INTO binaries(path,sha256,format,arch,os_origin,file_size)"
        " VALUES('/tmp/x','deadbeef','elf64','x86_64','linux',1);");
    cbae_txn_rollback(&txn);
    sqlite3_stmt *chk;
    cbae_db_prepare(&db,
        "SELECT COUNT(*) FROM binaries WHERE sha256='deadbeef';", &chk);
    cbae_db_step(chk);
    assert(cbae_db_col_int64(chk, 0) == 0);
    cbae_db_finalize(chk);
    printf("  [PASS] rollback removes record\n");

    /* Verify Phase 2 tables */
    sqlite3_stmt *tbl;
    cbae_db_prepare(&db,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        " AND name IN ('sections','symbols','imports','relocations','loader_results');",
        &tbl);
    cbae_db_step(tbl);
    assert(cbae_db_col_int64(tbl, 0) == 5);
    cbae_db_finalize(tbl);
    printf("  [PASS] Phase 2 tables exist\n");

    cbae_db_close(&db);
    unlink(TEST_DB);
    printf("All DB persistence tests passed.\n");
    return 0;
}
