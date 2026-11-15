/*
 * A-043 evidence: what the database layer does with the situations below, before and after the rewrite.
 *
 * One program, built against either tree (CBAE_DB_ROW exists only in the new db_query.h, so the demo says which API it is):
 *
 *   gcc -O0 -g -I<tree>/include A-043_demo.c <tree>/src/db/*.c <tree>/src/engine/cbae_error.c \
 *       <tree>/src/platform/logging.c -lsqlite3 -lpthread -o demo
 *
 * Every line printed is the result of the layer's own calls; nothing here is simulated.
 */
#define _GNU_SOURCE
#include "db/db_connection.h"
#include "db/db_query.h"
#include "db/db_schema.h"
#include "db/db_transaction.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef CBAE_DB_ROW
#define API "new"
#else
#define API "old"
#endif

#define DIR "/tmp/cbae_a043"

static void rmdb(const char *p) {
    char f[256];
    unlink(p);
    snprintf(f, sizeof f, "%s-wal", p); unlink(f);
    snprintf(f, sizeof f, "%s-shm", p); unlink(f);
}

/* Straight to SQLite, so the same code reads the state under both APIs. */
static long raw_count(cbae_db_t *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    long v = -1;
    if (sqlite3_prepare_v2(db->handle, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) v = (long)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static void d1_open_leak(void) {
    const long before = (long)sqlite3_memory_used();
    for (int i = 0; i < 100; i++) { cbae_db_t db; (void)cbae_db_open(&db, "/tmp"); }       /* a directory cannot be opened */
    printf("1  100 failed opens: SQLite memory still held afterwards: %ld bytes\n", (long)sqlite3_memory_used() - before);
}

static void d2_not_a_database(void) {
    const char *junk = DIR "/junk.db";
    char bytes[4096];
    for (size_t i = 0; i < sizeof bytes; i++) bytes[i] = "this is not a database. "[i % 24];
    FILE *f = fopen(junk, "wb"); fwrite(bytes, 1, sizeof bytes, f); fclose(f);
    cbae_db_t db;
    const int rc = cbae_db_open(&db, junk);
    printf("2  open of a file that is not a database: rc=%d (%s)\n", rc, rc == 0 ? "accepted: the failure only shows at the first query" : "refused");
    if (rc == 0) {
        printf("   its first statement: rc=%d\n", cbae_db_exec(&db, "CREATE TABLE t(x);"));
        cbae_db_close(&db);
    }
    unlink(junk);
}

static void d3_step(void) {
    cbae_db_t db;
    cbae_db_open(&db, ":memory:");
    cbae_db_exec(&db, "CREATE TABLE t(x); INSERT INTO t VALUES(1),(2),(3);");
    sqlite3_stmt *st = NULL;
    cbae_db_prepare(&db, "SELECT x FROM t;", &st);
    int r[5];
    for (int i = 0; i < 5; i++) r[i] = cbae_db_step(st);
    printf("3  step() on a SELECT with 3 rows, five calls return: %d %d %d %d %d   (rows, end, then it starts over)\n", r[0], r[1], r[2], r[3], r[4]);
    cbae_db_finalize(st);
    cbae_db_close(&db);
}

static void d4_prepare(void) {
    cbae_db_t db;
    cbae_db_open(&db, ":memory:");
    cbae_db_exec(&db, "CREATE TABLE t(x);");
    sqlite3_stmt *st = (sqlite3_stmt *)0x1;
    int rc = cbae_db_prepare(&db, "-- nothing\n;", &st);
    printf("4a prepare() of a string with no statement: rc=%d, statement=%s%s\n", rc, st ? "non-NULL" : "NULL", rc == 0 && !st ? " (and the caller is told it worked)" : "");
    st = NULL;
    rc = cbae_db_prepare(&db, "INSERT INTO t VALUES(1); INSERT INTO t VALUES(2);", &st);
    if (rc == 0 && st) { cbae_db_step(st); cbae_db_finalize(st); }
    printf("4b prepare() of two INSERTs: rc=%d, rows inserted: %ld\n", rc, raw_count(&db, "SELECT COUNT(*) FROM t;"));
    cbae_db_close(&db);
}

static void d5_negative_blob(void) {
    fflush(stdout);
    const pid_t pid = fork();
    if (pid == 0) {
        cbae_db_t db;
        cbae_db_open(&db, ":memory:");
        cbae_db_exec(&db, "CREATE TABLE b(v);");
        sqlite3_stmt *st = NULL;
        cbae_db_prepare(&db, "INSERT INTO b VALUES(?1);", &st);
        char *buf = malloc(8);
        memset(buf, 'x', 8);
        const int rc = cbae_db_bind_blob(st, 1, buf, -1);
        const int sr = cbae_db_step(st);
        printf("5  bind_blob with length -1: bind rc=%d, step rc=%d, stored length=%ld\n", rc, sr, raw_count(&db, "SELECT COALESCE(length(v), -1) FROM b;"));
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) printf("5  bind_blob with length -1: the process died with signal %d\n", WTERMSIG(status));
}

static void d6_close_with_statement(void) {
    const char *p = DIR "/close.db";
    rmdb(p);
    const long before = (long)sqlite3_memory_used();
    cbae_db_t db;
    cbae_db_open(&db, p);
    sqlite3_stmt *st = NULL;
    cbae_db_prepare(&db, "SELECT 1;", &st);
    cbae_db_close(&db);
    cbae_db_finalize(st);
    printf("6  close with a statement not finalized, then finalize it: SQLite memory still held: %ld bytes\n", (long)sqlite3_memory_used() - before);
    rmdb(p);
}

static void d7_commit_failure(void) {
    const char *p = DIR "/commit.db";
    rmdb(p);
    cbae_db_t db;
    cbae_db_open(&db, p);
    cbae_schema_migrate(&db);
    cbae_txn_t txn;
    cbae_txn_begin(&txn, &db);
    cbae_db_exec(&db, "PRAGMA defer_foreign_keys = ON;");
    cbae_db_exec(&db, "INSERT INTO sections(binary_id,section_idx,name,virt_addr,virt_size,file_offset,file_size,flags) VALUES(9999,0,'.t',0,0,0,0,0);");
    const int rc = cbae_txn_commit(&txn);
    printf("7  COMMIT that violates a deferred foreign key: rc=%d, transaction still open in SQLite: %s\n", rc, sqlite3_get_autocommit(db.handle) ? "no" : "YES");
    cbae_txn_t next;
    const int rc2 = cbae_txn_begin(&next, &db);
    printf("   the next begin on that connection: rc=%d%s\n", rc2, rc2 == 0 ? " (works)" : " (refused: the connection is stuck)");
    cbae_db_close(&db);
    rmdb(p);
}

static void d8_begin_lock(void) {
    const char *p = DIR "/lock.db";
    rmdb(p);
    cbae_db_t a, b;
    cbae_db_open(&a, p);
    cbae_db_open(&b, p);
    sqlite3_busy_timeout(b.handle, 100);
    cbae_db_exec(&a, "CREATE TABLE t(x);");
    cbae_txn_t ta, tb;
    cbae_txn_begin(&ta, &a);
    cbae_db_exec(&a, "INSERT INTO t VALUES(1);");
    const int rc = cbae_txn_begin(&tb, &b);
    printf("8  a second connection begins while the first is writing: begin rc=%d", rc);
    if (rc == 0) printf(", its first write rc=%d (the lock is only discovered here)", cbae_db_exec(&b, "INSERT INTO t VALUES(2);"));
    printf("\n");
    cbae_txn_rollback(&ta);
    cbae_txn_rollback(&tb);
    cbae_db_close(&a);
    cbae_db_close(&b);
    rmdb(p);
}

typedef struct { const char *path; pthread_barrier_t *bar; int fails; } w9_t;

static void *w9(void *arg) {
    w9_t *w = arg;
    cbae_db_t db;
    cbae_db_open(&db, w->path);
    pthread_barrier_wait(w->bar);
    for (int i = 0; i < 50; i++) {
        cbae_txn_t txn;
        if (cbae_txn_begin(&txn, &db) != 0) { w->fails++; continue; }
        sqlite3_stmt *st = NULL;
        long top = -1;
        if (cbae_db_prepare(&db, "SELECT COALESCE(MAX(x), 0) FROM seq;", &st) == 0) {
            if (cbae_db_step(st) >= 0) top = (long)cbae_db_col_int64(st, 0);
            cbae_db_finalize(st);
        }
        int ok = top >= 0 && cbae_db_prepare(&db, "INSERT INTO seq(x) VALUES(?1);", &st) == 0;
        if (ok) { ok = cbae_db_bind_int64(st, 1, top + 1) == 0 && cbae_db_step(st) >= 0; cbae_db_finalize(st); }
        if (!ok || cbae_txn_commit(&txn) != 0) { cbae_txn_rollback(&txn); w->fails++; }
    }
    cbae_db_close(&db);
    return NULL;
}

static void d9_read_then_write(void) {
    const char *p = DIR "/seq.db";
    rmdb(p);
    cbae_db_t db;
    cbae_db_open(&db, p);
    cbae_db_exec(&db, "CREATE TABLE seq(x INTEGER PRIMARY KEY);");
    pthread_barrier_t bar;
    pthread_barrier_init(&bar, NULL, 4);
    pthread_t th[4];
    w9_t w[4];
    for (int i = 0; i < 4; i++) { w[i] = (w9_t){ p, &bar, 0 }; pthread_create(&th[i], NULL, w9, &w[i]); }
    for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
    printf("9  4 connections x 50 transactions that read and then write: failed transactions %d of 200, rows written %ld\n",
           w[0].fails + w[1].fails + w[2].fails + w[3].fails, raw_count(&db, "SELECT COUNT(*) FROM seq;"));
    cbae_db_close(&db);
    rmdb(p);
}

static void d10_schema(void) {
    const char *p = DIR "/schema.db";
    rmdb(p);
    cbae_db_t db;
    cbae_db_open(&db, p);
    cbae_schema_migrate(&db);

    cbae_db_exec(&db, "PRAGMA user_version = 3;");
    printf("10a a database from a newer program (schema v3): migrate returns %d\n", cbae_schema_migrate(&db));
    cbae_db_exec(&db, "PRAGMA user_version = 2;");

    cbae_db_exec(&db, "DROP TABLE loader_results; DROP TABLE relocations; DROP TABLE imports; DROP TABLE symbols; DROP TABLE sections; PRAGMA user_version = 1;");
    cbae_db_exec(&db, "CREATE VIEW symbols AS SELECT 1 AS binary_id;");
    const int rc = cbae_schema_migrate(&db);
    printf("10b migration 002 failing half way (a view is in the way): rc=%d, version %d, 'sections' table left behind: %s\n",
           rc, cbae_schema_version(&db), raw_count(&db, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'sections';") ? "YES (half a migration)" : "no");
    cbae_db_close(&db);
    printf("10c schema version of a closed connection: %d\n", cbae_schema_version(&db));
    rmdb(p);
}

int main(void) {
    sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 1);
    mkdir(DIR, 0700);
    printf("A-043 demo (%s API)\n", API);
    d1_open_leak();
    d2_not_a_database();
    d3_step();
    d4_prepare();
    d5_negative_blob();
    d6_close_with_statement();
    d7_commit_failure();
    d8_begin_lock();
    d9_read_then_write();
    d10_schema();
    return 0;
}
