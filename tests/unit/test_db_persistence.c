/**
 * @file test_db_persistence.c
 * @brief Unit tests for the database layer (audit A-043): opening (the settings that must take effect, and every way it
 *        can fail without leaking), SQLite's result codes, exec / prepare / step / bind / columns, transactions (the
 *        write lock, a failed commit, a transaction SQLite ended itself), schema migrations (atomic, a newer schema
 *        refused, several connections at once), WAL behaviour, and every failure of SQLite's own allocator.
 *
 * Needs   -Wl,--wrap=sqlite3_column_text,--wrap=sqlite3_busy_timeout,--wrap=sqlite3_step,--wrap=sqlite3_sleep
 * (tests/CMakeLists.txt): they let a test make the journal mode, the foreign-key setting, the busy-timeout call and a busy
 * lock answer what no real file gives on demand, and make the wait between two tries instant.
 */
#define _GNU_SOURCE
#include "db/db_connection.h"
#include "db/db_query.h"
#include "db/db_schema.h"
#include "db/db_transaction.h"
#include "platform/logging.h"
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PASS(name) printf("  [PASS] %s\n", name)
#define QUICK (getenv("CBAE_TEST_QUICK") != NULL)

/* ---- SQLite's allocator, replaced by one that counts the requests and fails the k-th on demand ---- */

#define SQ_HDR 16                                      /* room for the size, and the alignment SQLite expects */
static _Atomic long g_sq_count;                        /* requests since sq_arm */
static _Atomic long g_sq_fail_at;                      /* the request to fail; 0: none */
static _Atomic int  g_sq_fired;                        /* a request was failed since sq_arm */

static bool sq_fail_now(void) {
    const long n = atomic_fetch_add(&g_sq_count, 1) + 1;
    if (n != atomic_load(&g_sq_fail_at)) return false;
    atomic_store(&g_sq_fired, 1);
    return true;
}
static void *sq_malloc(int n) {
    if (sq_fail_now()) return NULL;
    char *p = malloc((size_t)n + SQ_HDR);
    if (!p) return NULL;
    memcpy(p, &n, sizeof n);
    return p + SQ_HDR;
}
static void  sq_free(void *p) { if (p) free((char *)p - SQ_HDR); }
static int   sq_size(void *p) { int n = 0; if (p) memcpy(&n, (char *)p - SQ_HDR, sizeof n); return n; }
static void *sq_realloc(void *p, int n) {
    if (sq_fail_now()) return NULL;
    char *q = realloc(p ? (char *)p - SQ_HDR : NULL, (size_t)n + SQ_HDR);
    if (!q) return NULL;
    memcpy(q, &n, sizeof n);
    return q + SQ_HDR;
}
static int   sq_roundup(int n) { return (n + 7) & ~7; }
static int   sq_init(void *unused) { (void)unused; return SQLITE_OK; }
static void  sq_shutdown(void *unused) { (void)unused; }

static void sq_arm(long k)  { atomic_store(&g_sq_count, 0); atomic_store(&g_sq_fired, 0); atomic_store(&g_sq_fail_at, k); }
static long sq_disarm(void) { atomic_store(&g_sq_fail_at, 0); return atomic_load(&g_sq_count); }

/* ---- calls made to answer something else (see the note at the top) ---- */

const unsigned char *__real_sqlite3_column_text(sqlite3_stmt *, int);
int                  __real_sqlite3_busy_timeout(sqlite3 *, int);

static const char *g_fake_journal;                     /* what "PRAGMA journal_mode" answers, if set */
static const char *g_fake_fk;                          /* what "PRAGMA foreign_keys;" answers, if set */
static int         g_fake_busy_rc;                     /* what sqlite3_busy_timeout returns, if not 0 */

const unsigned char *__wrap_sqlite3_column_text(sqlite3_stmt *st, int col) {
    const char *sql = sqlite3_sql(st);
    if (g_fake_journal && sql && strstr(sql, "journal_mode")) return (const unsigned char *)g_fake_journal;
    if (g_fake_fk && sql && strstr(sql, "PRAGMA foreign_keys;")) return (const unsigned char *)g_fake_fk;
    return __real_sqlite3_column_text(st, col);
}
int __wrap_sqlite3_busy_timeout(sqlite3 *h, int ms) {
    return g_fake_busy_rc ? g_fake_busy_rc : __real_sqlite3_busy_timeout(h, ms);
}

int __real_sqlite3_step(sqlite3_stmt *);
int __real_sqlite3_sleep(int);

static int  g_fake_journal_busy;                       /* the journal-mode statement answers BUSY this many more times (-1: always) */
static bool g_fake_sleep;                              /* sqlite3_sleep only counts what it is asked for */
static long g_slept_ms, g_sleeps;

int __wrap_sqlite3_step(sqlite3_stmt *st) {
    if (g_fake_journal_busy != 0) {
        const char *sql = sqlite3_sql(st);
        if (sql && strstr(sql, "journal_mode")) {
            if (g_fake_journal_busy > 0) g_fake_journal_busy--;
            return SQLITE_BUSY;
        }
    }
    return __real_sqlite3_step(st);
}
int __wrap_sqlite3_sleep(int ms) {
    if (!g_fake_sleep) return __real_sqlite3_sleep(ms);
    g_slept_ms += ms;
    g_sleeps++;
    return ms;
}

/* ---- helpers ---- */

static char g_dir[64];
#define PATH(var, name) char var[320]; snprintf(var, sizeof var, "%s/%s", g_dir, (name))

static void rm_db(const char *p) {
    static const char *const SUFFIX[] = { "", "-wal", "-shm", "-journal" };
    for (size_t i = 0; i < sizeof SUFFIX / sizeof SUFFIX[0]; i++) {
        char f[400];
        snprintf(f, sizeof f, "%s%s", p, SUFFIX[i]);
        unlink(f);
    }
}

static size_t read_file(const char *p, char *buf, size_t cap) {
    FILE *f = fopen(p, "rb");
    if (!f) return (size_t)-1;
    const size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

static void write_file(const char *p, const void *data, size_t n) {
    FILE *f = fopen(p, "wb");
    assert(f);
    assert(fwrite(data, 1, n, f) == n);
    fclose(f);
}

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static sqlite3_int64 g_mem_base;
#define MEM_MARK()   (g_mem_base = sqlite3_memory_used())
#define MEM_CHECK()  assert(sqlite3_memory_used() == g_mem_base)

static cbae_db_t open_ok(const char *path) {
    cbae_db_t db;
    const cbae_err_t e = cbae_db_open(&db, path);
    if (e != CBAE_OK) fprintf(stderr, "open '%s' failed: %s\n", path, cbae_last_error());
    assert(e == CBAE_OK && db.handle);
    return db;
}

static void must_exec(cbae_db_t *db, const char *sql) {
    const cbae_err_t e = cbae_db_exec(db, sql);
    if (e != CBAE_OK) fprintf(stderr, "exec failed: %s\n", cbae_last_error());
    assert(e == CBAE_OK);
}

/* The first column of the first row. */
static int64_t scalar(cbae_db_t *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    assert(cbae_db_prepare(db, sql, &st) == CBAE_OK);
    assert(cbae_db_step(st) == CBAE_DB_ROW);
    const int64_t v = cbae_db_col_int64(st, 0);
    cbae_db_finalize(st);
    return v;
}

/* The first column of the first row as a double. The comparison is made in C: SQLite reads a decimal literal with long
 * double arithmetic, which Valgrind does not have, so a literal in the SQL can differ by a bit from the C constant. */
static double scalar_double(cbae_db_t *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    assert(cbae_db_prepare(db, sql, &st) == CBAE_OK);
    assert(cbae_db_step(st) == CBAE_DB_ROW);
    const double v = cbae_db_col_double(st, 0);
    cbae_db_finalize(st);
    return v;
}

static void scalar_text(cbae_db_t *db, const char *sql, char *out, size_t cap) {
    sqlite3_stmt *st = NULL;
    assert(cbae_db_prepare(db, sql, &st) == CBAE_OK);
    assert(cbae_db_step(st) == CBAE_DB_ROW);
    const char *t = cbae_db_col_text(st, 0);
    snprintf(out, cap, "%s", t ? t : "(null)");
    cbae_db_finalize(st);
}

static void expect_msg(const char *part) {
    if (!strstr(cbae_last_error(), part)) fprintf(stderr, "error message '%s' lacks '%s'\n", cbae_last_error(), part);
    assert(strstr(cbae_last_error(), part));
}

/* ---- opening ---- */

static void test_open_settings(void) {
    PATH(p, "settings.db");
    rm_db(p);
    MEM_MARK();
    cbae_db_t db;
    assert(cbae_db_open(&db, p) == CBAE_OK);
    assert(db.handle && cbae_db_handle(&db) == db.handle);
    assert(strcmp(db.path, p) == 0 && db.busy_timeout_ms == CBAE_DB_BUSY_TIMEOUT_MS);
    assert(access(p, F_OK) == 0);

    char v[64];
    scalar_text(&db, "PRAGMA journal_mode;", v, sizeof v);
    assert(strcmp(v, "wal") == 0);
    assert(scalar(&db, "PRAGMA synchronous;") == 1);                      /* NORMAL */
    assert(scalar(&db, "PRAGMA foreign_keys;") == 1);
    assert(scalar(&db, "PRAGMA temp_store;") == 2);                       /* MEMORY */
    assert(scalar(&db, "PRAGMA cache_size;") == -32000);
    assert(scalar(&db, "PRAGMA busy_timeout;") == CBAE_DB_BUSY_TIMEOUT_MS);
    cbae_db_close(&db);
    assert(db.handle == NULL && cbae_db_handle(&db) == NULL);

    /* the file stays in WAL mode, and opening it again gives the same settings */
    db = open_ok(p);
    scalar_text(&db, "PRAGMA journal_mode;", v, sizeof v);
    assert(strcmp(v, "wal") == 0 && scalar(&db, "PRAGMA foreign_keys;") == 1);
    cbae_db_close(&db);
    MEM_CHECK();
    rm_db(p);
    PASS("open: WAL, synchronous NORMAL, foreign keys, in-memory temporaries, cache and busy timeout are all in effect");
}

static void test_open_transient(void) {
    MEM_MARK();
    static const char *const NAMES[] = { ":memory:", "" };
    for (int i = 0; i < 2; i++) {
        cbae_db_t db = open_ok(NAMES[i]);
        char v[64];
        scalar_text(&db, "PRAGMA journal_mode;", v, sizeof v);
        assert(strcmp(v, "wal") != 0);                                    /* these cannot be WAL: and that is not an error */
        assert(scalar(&db, "PRAGMA foreign_keys;") == 1);
        must_exec(&db, "CREATE TABLE t(x); INSERT INTO t VALUES(5);");
        assert(scalar(&db, "SELECT x FROM t;") == 5);
        cbae_db_close(&db);
    }
    MEM_CHECK();
    PASS("open: an in-memory and a private temporary database work without WAL");
}

static void test_open_arguments(void) {
    cbae_db_t db;
    assert(cbae_db_open(NULL, ":memory:") == CBAE_ERR_INVALID);
    expect_msg("null");
    assert(cbae_db_open(&db, NULL) == CBAE_ERR_INVALID);
    assert(cbae_db_handle(NULL) == NULL);
    PASS("open: null arguments");
}

static void test_open_failures(void) {
    MEM_MARK();
    cbae_db_t db;

    memset(&db, 0xAB, sizeof db);                                         /* whatever was there: a failed open leaves a closed connection */
    assert(cbae_db_open(&db, g_dir) == CBAE_ERR_IO);                      /* a directory */
    assert(db.handle == NULL);
    expect_msg("cannot open");
    expect_msg(g_dir);
    MEM_CHECK();

    PATH(missing, "no/such/dir/x.db");
    assert(cbae_db_open(&db, missing) == CBAE_ERR_IO && db.handle == NULL);
    MEM_CHECK();

    /* a file that is not a database is found out by open, and left as it was */
    PATH(junk, "junk.db");
    PATH(junk_wal, "junk.db-wal");
    char bytes[4096], back[8192];
    for (size_t i = 0; i < sizeof bytes; i++) bytes[i] = "this is not a database. "[i % 24];
    write_file(junk, bytes, sizeof bytes);
    assert(cbae_db_open(&db, junk) == CBAE_ERR_DB && db.handle == NULL);
    expect_msg("not a database");
    assert(read_file(junk, back, sizeof back) == sizeof bytes && memcmp(back, bytes, sizeof bytes) == 0);
    assert(access(junk_wal, F_OK) != 0);
    MEM_CHECK();
    unlink(junk);

    /* an empty file is a database with nothing in it */
    PATH(empty, "empty.db");
    write_file(empty, "", 0);
    db = open_ok(empty);
    assert(cbae_schema_version(&db) == 0);
    cbae_db_close(&db);
    MEM_CHECK();
    rm_db(empty);
    PASS("open: a directory, a missing directory and a file that is not a database fail cleanly (nothing leaked, nothing changed)");
}

static void test_open_refusals(void) {
    PATH(p, "refuse.db");
    rm_db(p);
    MEM_MARK();
    cbae_db_t db;

    g_fake_journal = "delete";                                            /* a file system that cannot do WAL */
    assert(cbae_db_open(&db, p) == CBAE_ERR_DB && db.handle == NULL);
    expect_msg("WAL");
    expect_msg("delete");
    g_fake_journal = NULL;
    MEM_CHECK();

    g_fake_journal = "WAL";                                               /* the name is not case sensitive */
    db = open_ok(p);
    cbae_db_close(&db);
    g_fake_journal = "delete";                                            /* a database that cannot be WAL anyway */
    db = open_ok(":memory:");
    cbae_db_close(&db);
    g_fake_journal = NULL;
    rm_db(p);

    g_fake_fk = "0";                                                      /* an SQLite built without foreign keys */
    assert(cbae_db_open(&db, p) == CBAE_ERR_UNSUPPORTED && db.handle == NULL);
    expect_msg("foreign key");
    g_fake_fk = NULL;
    MEM_CHECK();

    g_fake_busy_rc = SQLITE_NOMEM;
    assert(cbae_db_open(&db, ":memory:") == CBAE_ERR_OOM && db.handle == NULL);
    expect_msg("busy timeout");
    g_fake_busy_rc = SQLITE_MISUSE;
    assert(cbae_db_open(&db, ":memory:") == CBAE_ERR_INVALID && db.handle == NULL);
    g_fake_busy_rc = 0;
    MEM_CHECK();
    rm_db(p);
    PASS("open: a journal mode that is not WAL, no foreign keys or a refused busy timeout are errors, and leak nothing");
}

static void test_open_busy_retry(void) {
    PATH(p, "retry.db");
    PATH(junk, "retry_junk.db");
    rm_db(p);
    MEM_MARK();
    cbae_db_t db;
    g_fake_sleep = true;

    g_fake_journal_busy = 3;                                              /* three busy answers, then the real one */
    g_slept_ms = g_sleeps = 0;
    assert(cbae_db_open(&db, p) == CBAE_OK);
    assert(g_fake_journal_busy == 0 && g_sleeps == 3 && g_slept_ms == 15);
    char v[64];
    scalar_text(&db, "PRAGMA journal_mode;", v, sizeof v);
    assert(strcmp(v, "wal") == 0);
    cbae_db_close(&db);
    rm_db(p);

    g_fake_journal_busy = -1;                                             /* always busy: given up when the busy timeout is used up */
    g_slept_ms = g_sleeps = 0;
    assert(cbae_db_open(&db, p) == CBAE_ERR_BUSY && db.handle == NULL);
    assert(g_slept_ms == CBAE_DB_BUSY_TIMEOUT_MS && g_sleeps == CBAE_DB_BUSY_TIMEOUT_MS / 5);
    expect_msg("journal_mode");
    g_fake_journal_busy = 0;
    MEM_CHECK();
    rm_db(p);

    /* only BUSY is tried again: a file that is not a database is refused at once */
    char bytes[4096];
    memset(bytes, 'j', sizeof bytes);
    write_file(junk, bytes, sizeof bytes);
    g_slept_ms = g_sleeps = 0;
    assert(cbae_db_open(&db, junk) == CBAE_ERR_DB && g_sleeps == 0);
    g_fake_sleep = false;
    unlink(junk);
    MEM_CHECK();
    PASS("open: a busy answer to the switch to WAL is tried again for the length of the busy timeout, and nothing else is");
}

static void test_long_path(void) {
    /* SQLite's unix file system takes pathnames of up to 512 bytes (and the -wal and -shm names are longer), so the name
     * the layer keeps for messages (512 bytes) holds every path that can be opened; a longer one is an error. */
    char a[201], b[201], d1[320], d2[640], fname[300], ok[1000], tooLong[1000];
    memset(a, 'a', 200); a[200] = '\0';
    memset(b, 'b', 200); b[200] = '\0';
    snprintf(d1, sizeof d1, "%s/%s", g_dir, a);
    snprintf(d2, sizeof d2, "%s/%s", d1, b);
    assert(mkdir(d1, 0700) == 0 && mkdir(d2, 0700) == 0);

    const size_t base = strlen(d2) + 1;                                   /* the directory and the slash */
    memset(fname, 'f', sizeof fname);
    fname[500 - base] = '\0';                                             /* a path of 500 bytes */
    snprintf(ok, sizeof ok, "%s/%s", d2, fname);
    assert(strlen(ok) == 500);
    cbae_db_t db = open_ok(ok);
    assert(strcmp(db.path, ok) == 0);
    must_exec(&db, "CREATE TABLE t(x);");
    cbae_db_close(&db);
    rm_db(ok);

    memset(fname, 'g', sizeof fname);
    fname[560 - base] = '\0';                                             /* 560 bytes: longer than the name kept, and than SQLite allows */
    snprintf(tooLong, sizeof tooLong, "%s/%s", d2, fname);
    assert(strlen(tooLong) == 560);
    memset(&db, 0xAB, sizeof db);
    assert(cbae_db_open(&db, tooLong) == CBAE_ERR_IO && db.handle == NULL);
    assert(strlen(db.path) == sizeof db.path - 1 && memcmp(db.path, tooLong, sizeof db.path - 1) == 0);   /* cut, not overrun */
    rm_db(tooLong);
    rmdir(d2);
    rmdir(d1);
    PASS("open: a path of 500 bytes opens, one of 560 is refused, and the name kept for messages is cut, not overrun");
}

static void test_close(void) {
    PATH(p, "close.db");
    PATH(logp, "close.log");
    rm_db(p);
    cbae_db_close(NULL);                                                  /* nothing to do */
    cbae_db_t db = open_ok(":memory:");
    cbae_db_close(&db);
    cbae_db_close(&db);                                                   /* twice is the same as once */
    assert(db.handle == NULL);

    /* a statement that is not finalized: warned about, and the connection goes when the statement does */
    MEM_MARK();
    unlink(logp);
    db = open_ok(p);
    sqlite3_stmt *st = NULL;
    assert(cbae_db_prepare(&db, "SELECT 1;", &st) == CBAE_OK);
    cbae_log_init(CBAE_LOG_WARN, logp, false);
    cbae_db_close(&db);
    cbae_log_shutdown();
    assert(db.handle == NULL);
    char log[4096];
    const size_t n = read_file(logp, log, sizeof log - 1);
    assert(n != (size_t)-1 && n > 0);
    log[n] = '\0';
    assert(strstr(log, "not finalized"));
    cbae_db_finalize(st);
    MEM_CHECK();
    unlink(logp);
    rm_db(p);

    /* a transaction that is still open is rolled back */
    db = open_ok(p);
    must_exec(&db, "CREATE TABLE t(x);");
    cbae_txn_t txn;
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    must_exec(&db, "INSERT INTO t VALUES(1);");
    cbae_db_close(&db);
    db = open_ok(p);
    assert(scalar(&db, "SELECT COUNT(*) FROM t;") == 0);
    cbae_db_close(&db);
    rm_db(p);
    PASS("close: twice, with a statement not finalized (no leak once it is), with a transaction open");
}

/* ---- result codes ---- */

static cbae_err_t expected_code(int primary) {                           /* written out in numbers, from sqlite.org's list */
    switch (primary) {
        case 0: case 100: case 101: return CBAE_OK;                      /* OK, ROW, DONE */
        case 7:                     return CBAE_ERR_OOM;                 /* NOMEM */
        case 5: case 6:             return CBAE_ERR_BUSY;                /* BUSY, LOCKED */
        case 3: case 8: case 10: case 13: case 14: return CBAE_ERR_IO;   /* PERM, READONLY, IOERR, FULL, CANTOPEN */
        case 21: case 25:           return CBAE_ERR_INVALID;             /* MISUSE, RANGE */
        default:                    return CBAE_ERR_DB;
    }
}

static void test_err_mapping(void) {
    static const struct { int rc; cbae_err_t want; } NAMED[] = {
        { SQLITE_OK, CBAE_OK }, { SQLITE_ROW, CBAE_OK }, { SQLITE_DONE, CBAE_OK }, { SQLITE_OK | (1 << 8), CBAE_OK },
        { SQLITE_NOMEM, CBAE_ERR_OOM },
        { SQLITE_BUSY, CBAE_ERR_BUSY }, { SQLITE_BUSY_SNAPSHOT, CBAE_ERR_BUSY }, { SQLITE_LOCKED, CBAE_ERR_BUSY },
        { SQLITE_LOCKED_SHAREDCACHE, CBAE_ERR_BUSY },
        { SQLITE_CANTOPEN, CBAE_ERR_IO }, { SQLITE_CANTOPEN_ISDIR, CBAE_ERR_IO }, { SQLITE_IOERR, CBAE_ERR_IO },
        { SQLITE_IOERR_READ, CBAE_ERR_IO }, { SQLITE_FULL, CBAE_ERR_IO }, { SQLITE_READONLY, CBAE_ERR_IO },
        { SQLITE_READONLY_ROLLBACK, CBAE_ERR_IO }, { SQLITE_PERM, CBAE_ERR_IO },
        { SQLITE_MISUSE, CBAE_ERR_INVALID }, { SQLITE_RANGE, CBAE_ERR_INVALID },
        { SQLITE_ERROR, CBAE_ERR_DB }, { SQLITE_CONSTRAINT, CBAE_ERR_DB }, { SQLITE_CONSTRAINT_FOREIGNKEY, CBAE_ERR_DB },
        { SQLITE_CORRUPT, CBAE_ERR_DB }, { SQLITE_NOTADB, CBAE_ERR_DB }, { SQLITE_INTERRUPT, CBAE_ERR_DB },
        { SQLITE_TOOBIG, CBAE_ERR_DB }, { SQLITE_SCHEMA, CBAE_ERR_DB }, { SQLITE_AUTH, CBAE_ERR_DB },
        { -1, CBAE_ERR_DB }, { INT32_MAX, CBAE_ERR_DB },
    };
    for (size_t i = 0; i < sizeof NAMED / sizeof NAMED[0]; i++) {
        if (cbae_db_err_from_sqlite(NAMED[i].rc) != NAMED[i].want)
            fprintf(stderr, "SQLite code %d maps to %d, expected %d\n", NAMED[i].rc, (int)cbae_db_err_from_sqlite(NAMED[i].rc), (int)NAMED[i].want);
        assert(cbae_db_err_from_sqlite(NAMED[i].rc) == NAMED[i].want);
    }
    /* every primary code, and every extended code made of it */
    for (int primary = 0; primary < 256; primary++)
        for (int ext = 0; ext < 9; ext++) {
            const int rc = primary | (ext << 8);
            if (cbae_db_err_from_sqlite(rc) != expected_code(primary)) fprintf(stderr, "code %d\n", rc);
            assert(cbae_db_err_from_sqlite(rc) == expected_code(primary));
        }
    PASS("result codes: every SQLite code, primary or extended, maps to the documented layer code");
}

/* ---- exec, prepare ---- */

static void test_exec(void) {
    MEM_MARK();
    cbae_db_t db = open_ok(":memory:");
    must_exec(&db, "CREATE TABLE t(x INTEGER PRIMARY KEY, y TEXT NOT NULL);"
                   "INSERT INTO t(y) VALUES('a'); INSERT INTO t(y) VALUES('b');");
    assert(scalar(&db, "SELECT COUNT(*) FROM t;") == 2);
    must_exec(&db, "SELECT * FROM t;");                                   /* rows are discarded */
    must_exec(&db, "");
    must_exec(&db, ";");

    /* one failure among several statements: the ones before it ran */
    assert(cbae_db_exec(&db, "INSERT INTO t(y) VALUES('c'); INSERT INTO t(y) VALUES(NULL); INSERT INTO t(y) VALUES('d');") == CBAE_ERR_DB);
    expect_msg("NOT NULL");
    expect_msg("SQL: INSERT INTO t(y) VALUES('c')");
    assert(scalar(&db, "SELECT COUNT(*) FROM t;") == 3);

    assert(cbae_db_exec(&db, "SELEC 1;") == CBAE_ERR_DB);
    expect_msg("syntax error");
    assert(cbae_db_exec(&db, "SELECT * FROM nothing_here;") == CBAE_ERR_DB);
    expect_msg("no such table");

    char longsql[400] = "SELEC ";                                         /* the message shows the start of the SQL, and is not overrun */
    memset(longsql + 6, 'X', 300);
    longsql[306] = '\0';
    assert(cbae_db_exec(&db, longsql) == CBAE_ERR_DB);
    const char *at = strstr(cbae_last_error(), "SQL: ");
    assert(at && strlen(at + 5) <= 80 && strlen(cbae_last_error()) < CBAE_ERR_MSG_MAX);

    assert(cbae_db_exec(NULL, "SELECT 1;") == CBAE_ERR_INVALID);
    assert(cbae_db_exec(&db, NULL) == CBAE_ERR_INVALID);
    cbae_db_close(&db);
    assert(cbae_db_exec(&db, "SELECT 1;") == CBAE_ERR_INVALID);
    expect_msg("not open");
    MEM_CHECK();                                                          /* the messages SQLite allocated for the failures were freed */
    PASS("exec: several statements, each way to fail, the message, null and closed");
}

static void test_prepare(void) {
    cbae_db_t db = open_ok(":memory:");
    must_exec(&db, "CREATE TABLE t(x);");
    sqlite3_stmt *st = (sqlite3_stmt *)0x1;                               /* garbage: a failure must clear it */

    assert(cbae_db_prepare(&db, "SELECT 1;", NULL) == CBAE_ERR_INVALID);
    assert(cbae_db_prepare(NULL, "SELECT 1;", &st) == CBAE_ERR_INVALID && st == NULL);
    expect_msg("null argument");
    st = (sqlite3_stmt *)0x1;
    assert(cbae_db_prepare(&db, NULL, &st) == CBAE_ERR_INVALID && st == NULL);
    expect_msg("null argument");                                          /* the layer's own answer: SQLite's would be "misuse" */

    static const char *const NOTHING[] = { "", "   ", ";", " ;; ", "-- only a comment", "/* c */ ; -- d\n" };
    for (size_t i = 0; i < sizeof NOTHING / sizeof NOTHING[0]; i++) {
        st = (sqlite3_stmt *)0x1;
        assert(cbae_db_prepare(&db, NOTHING[i], &st) == CBAE_ERR_INVALID && st == NULL);
        expect_msg("no SQL statement");
    }
    static const char *const MORE[] = { "SELECT 1; SELECT 2", "SELECT 1;SELECT 2;", "SELECT 1; garbage garbage", "SELECT 1; /* c */ SELECT 2" };
    for (size_t i = 0; i < sizeof MORE / sizeof MORE[0]; i++) {
        st = (sqlite3_stmt *)0x1;
        assert(cbae_db_prepare(&db, MORE[i], &st) == CBAE_ERR_INVALID && st == NULL);
        expect_msg("more than one");
        assert(sqlite3_next_stmt(db.handle, NULL) == NULL);               /* nothing left prepared */
    }
    static const char *const ONE[] = { "SELECT 1", "SELECT 1;", "  SELECT 1 ;  ", "SELECT 1; -- done", "SELECT 1;\n/* the end */ ;;  ", "-- first\nSELECT 1" };
    for (size_t i = 0; i < sizeof ONE / sizeof ONE[0]; i++) {
        st = NULL;
        assert(cbae_db_prepare(&db, ONE[i], &st) == CBAE_OK && st);
        assert(cbae_db_step(st) == CBAE_DB_ROW && cbae_db_col_int64(st, 0) == 1);
        cbae_db_finalize(st);
    }

    st = (sqlite3_stmt *)0x1;
    assert(cbae_db_prepare(&db, "SELEC 1", &st) == CBAE_ERR_DB && st == NULL);
    expect_msg("syntax error");
    expect_msg("SELEC 1");
    assert(cbae_db_prepare(&db, "SELECT y FROM t", &st) == CBAE_ERR_DB && st == NULL);
    expect_msg("no such column");

    cbae_db_close(&db);
    st = (sqlite3_stmt *)0x1;
    assert(cbae_db_prepare(&db, "SELECT 1", &st) == CBAE_ERR_INVALID && st == NULL);
    expect_msg("not open");
    PASS("prepare: exactly one statement, nothing prepared on failure, null and closed");
}

/* ---- step, columns, bind ---- */

static void test_step_and_columns(void) {
    cbae_db_t db = open_ok(":memory:");
    must_exec(&db, "CREATE TABLE typed(i INTEGER, d REAL, s TEXT, b BLOB);"
                   "INSERT INTO typed VALUES(9223372036854775807, 1.5, 'caf' || char(233), x'00ff00');"
                   "INSERT INTO typed VALUES(-9223372036854775807 - 1, -2.25, '', x'');"
                   "INSERT INTO typed VALUES(NULL, NULL, NULL, NULL);");
    sqlite3_stmt *st = NULL;
    assert(cbae_db_prepare(&db, "SELECT i, d, s, b FROM typed ORDER BY rowid;", &st) == CBAE_OK);

    assert(cbae_db_col_int64(st, 0) == 0 && cbae_db_col_double(st, 1) == 0.0);        /* no row yet */
    assert(cbae_db_col_text(st, 2) == NULL && cbae_db_col_blob(st, 3) == NULL && cbae_db_col_bytes(st, 2) == 0);

    assert(cbae_db_step(st) == CBAE_DB_ROW);
    assert(cbae_db_col_int64(st, 0) == INT64_MAX && cbae_db_col_double(st, 1) == 1.5);
    assert(strcmp(cbae_db_col_text(st, 2), "caf\xC3\xA9") == 0 && cbae_db_col_bytes(st, 2) == 5);
    const unsigned char *blob = cbae_db_col_blob(st, 3);
    assert(blob && cbae_db_col_bytes(st, 3) == 3 && blob[0] == 0x00 && blob[1] == 0xFF && blob[2] == 0x00);
    const int errcode = sqlite3_errcode(db.handle);
    assert(cbae_db_col_int64(st, 4) == 0 && cbae_db_col_int64(st, -1) == 0 && cbae_db_col_double(st, 4) == 0.0);   /* no such column */
    assert(cbae_db_col_text(st, 4) == NULL && cbae_db_col_text(st, -1) == NULL && cbae_db_col_blob(st, 99) == NULL);
    assert(cbae_db_col_bytes(st, 4) == 0 && cbae_db_col_bytes(st, -1) == 0);
    assert(sqlite3_errcode(db.handle) == errcode);                        /* SQLite is not left with a "column index out of range" error */

    assert(cbae_db_step(st) == CBAE_DB_ROW);
    assert(cbae_db_col_int64(st, 0) == INT64_MIN && cbae_db_col_double(st, 1) == -2.25);
    assert(cbae_db_col_text(st, 2) != NULL && cbae_db_col_text(st, 2)[0] == '\0' && cbae_db_col_bytes(st, 2) == 0);
    assert(cbae_db_col_bytes(st, 3) == 0);

    assert(cbae_db_step(st) == CBAE_DB_ROW);                              /* NULLs */
    assert(cbae_db_col_int64(st, 0) == 0 && cbae_db_col_double(st, 1) == 0.0);
    assert(cbae_db_col_text(st, 2) == NULL && cbae_db_col_blob(st, 3) == NULL && cbae_db_col_bytes(st, 3) == 0);

    assert(cbae_db_step(st) == CBAE_OK);                                  /* finished */
    assert(cbae_db_col_int64(st, 0) == 0 && cbae_db_col_text(st, 2) == NULL && cbae_db_col_bytes(st, 2) == 0);
    assert(cbae_db_step(st) == CBAE_DB_ROW && cbae_db_col_int64(st, 0) == INT64_MAX);   /* the next step starts over */
    cbae_db_reset(st);
    assert(cbae_db_col_int64(st, 0) == 0 && cbae_db_col_text(st, 2) == NULL);
    cbae_db_finalize(st);

    /* a NUL inside text cuts the string, and the byte count shows it */
    assert(cbae_db_prepare(&db, "SELECT char(65, 0, 66);", &st) == CBAE_OK);
    assert(cbae_db_step(st) == CBAE_DB_ROW);
    assert(strcmp(cbae_db_col_text(st, 0), "A") == 0 && cbae_db_col_bytes(st, 0) == 3);
    cbae_db_finalize(st);

    /* success leaves no error behind */
    assert(cbae_db_prepare(&db, "SELECT 1;", &st) == CBAE_OK);
    cbae_error_clear();
    assert(cbae_db_step(st) == CBAE_DB_ROW && cbae_db_step(st) == CBAE_OK);
    assert(cbae_error_get_context()->message[0] == '\0');
    cbae_db_finalize(st);

    /* the loop from the header */
    assert(cbae_db_prepare(&db, "SELECT rowid FROM typed;", &st) == CBAE_OK);
    int rows = 0, rc;
    while ((rc = cbae_db_step(st)) == CBAE_DB_ROW) rows++;
    assert(rc == CBAE_OK && rows == 3);
    cbae_db_finalize(st);

    /* nothing at all */
    assert(cbae_db_step(NULL) == CBAE_ERR_INVALID);
    expect_msg("null statement");
    assert(cbae_db_col_int64(NULL, 0) == 0 && cbae_db_col_double(NULL, 0) == 0.0 && cbae_db_col_text(NULL, 0) == NULL);
    assert(cbae_db_col_blob(NULL, 0) == NULL && cbae_db_col_bytes(NULL, 0) == 0);
    cbae_db_reset(NULL);
    cbae_db_finalize(NULL);

    /* failures: a constraint, and an error part-way through a SELECT */
    must_exec(&db, "CREATE TABLE u(k INTEGER UNIQUE);");
    assert(cbae_db_prepare(&db, "INSERT INTO u VALUES(1);", &st) == CBAE_OK);
    assert(cbae_db_step(st) == CBAE_OK);
    assert(cbae_db_step(st) == CBAE_ERR_DB);
    expect_msg("UNIQUE constraint failed");
    cbae_db_finalize(st);
    assert(cbae_db_prepare(&db, "SELECT abs(i) FROM typed WHERE i = -9223372036854775807 - 1;", &st) == CBAE_OK);
    assert(cbae_db_step(st) == CBAE_ERR_DB);
    expect_msg("integer overflow");
    cbae_db_finalize(st);
    cbae_db_close(&db);
    PASS("step and columns: ROW and DONE told apart, every type, NULLs, no row, no column, errors");
}

static void expect_stored(cbae_db_t *db, int rowid, const char *type) {
    char sql[96], got[32];
    snprintf(sql, sizeof sql, "SELECT typeof(v) FROM b WHERE rowid = %d;", rowid);
    scalar_text(db, sql, got, sizeof got);
    if (strcmp(got, type) != 0) fprintf(stderr, "row %d: stored as %s, expected %s\n", rowid, got, type);
    assert(strcmp(got, type) == 0);
}

static void test_bind(void) {
    cbae_db_t db = open_ok(":memory:");
    must_exec(&db, "CREATE TABLE b(v);");
    sqlite3_stmt *ins = NULL;
    assert(cbae_db_prepare(&db, "INSERT INTO b(v) VALUES(?1);", &ins) == CBAE_OK);
    int row = 0;
#define STORE(call) do { assert((call) == CBAE_OK); assert(cbae_db_step(ins) == CBAE_OK); cbae_db_reset(ins); row++; } while (0)

    STORE(cbae_db_bind_int64(ins, 1, INT64_MIN));
    STORE(cbae_db_bind_int64(ins, 1, INT64_MAX));
    STORE(cbae_db_bind_double(ins, 1, 1e300));
    STORE(cbae_db_bind_double(ins, 1, 5e-324));
    STORE(cbae_db_bind_double(ins, 1, INFINITY));
    STORE(cbae_db_bind_double(ins, 1, NAN));                              /* row 6: NaN is stored as NULL */
    STORE(cbae_db_bind_text(ins, 1, "caf\xC3\xA9"));                      /* 7 */
    STORE(cbae_db_bind_text(ins, 1, "a\xFF" "z"));                        /* 8: not UTF-8, stored as it is */
    STORE(cbae_db_bind_text(ins, 1, ""));                                 /* 9 */
    STORE(cbae_db_bind_text(ins, 1, NULL));                               /* 10 */
    STORE(cbae_db_bind_blob(ins, 1, "\x00\x01\x00\x02", 4));              /* 11 */
    STORE(cbae_db_bind_blob(ins, 1, "", 0));                              /* 12: an empty blob, not NULL */
    STORE(cbae_db_bind_blob(ins, 1, NULL, 0));                            /* 13: NULL */
    STORE(cbae_db_bind_null(ins, 1));                                     /* 14 */
    assert(row == 14);

    static const char *const TYPES[] = { "integer", "integer", "real", "real", "real", "null", "text", "text", "text", "null",
                                         "blob", "blob", "null", "null" };
    for (int i = 0; i < 14; i++) expect_stored(&db, i + 1, TYPES[i]);
    assert(scalar(&db, "SELECT v FROM b WHERE rowid = 1;") == INT64_MIN);
    assert(scalar(&db, "SELECT v FROM b WHERE rowid = 2;") == INT64_MAX);
    assert(scalar_double(&db, "SELECT v FROM b WHERE rowid = 3;") == 1e300);
    assert(scalar_double(&db, "SELECT v FROM b WHERE rowid = 4;") == 5e-324);
    assert(scalar_double(&db, "SELECT v FROM b WHERE rowid = 5;") == INFINITY);
    assert(scalar(&db, "SELECT v = 'caf' || char(233) FROM b WHERE rowid = 7;") == 1);
    assert(scalar(&db, "SELECT hex(v) = '61FF7A' FROM b WHERE rowid = 8;") == 1);
    assert(scalar(&db, "SELECT length(v) FROM b WHERE rowid = 9;") == 0);
    assert(scalar(&db, "SELECT hex(v) = '00010002' FROM b WHERE rowid = 11;") == 1);
    assert(scalar(&db, "SELECT length(v) FROM b WHERE rowid = 12;") == 0);

    /* a big value */
    char *big = malloc((size_t)1 << 20);
    assert(big);
    memset(big, 'x', (size_t)1 << 20);
    big[(1 << 20) - 1] = '\0';
    STORE(cbae_db_bind_text(ins, 1, big));
    assert(scalar(&db, "SELECT length(v) FROM b WHERE rowid = 15;") == (1 << 20) - 1);
    STORE(cbae_db_bind_blob(ins, 1, big, 1 << 20));
    assert(scalar(&db, "SELECT length(v) FROM b WHERE rowid = 16;") == 1 << 20);
    free(big);

    /* what is refused */
    assert(cbae_db_bind_int64(ins, 0, 1) == CBAE_ERR_INVALID);            /* parameters count from 1 */
    assert(cbae_db_bind_int64(ins, 2, 1) == CBAE_ERR_INVALID);
    assert(cbae_db_bind_int64(ins, -1, 1) == CBAE_ERR_INVALID);
    assert(cbae_db_bind_double(ins, 2, 1.0) == CBAE_ERR_INVALID);
    assert(cbae_db_bind_text(ins, 2, "x") == CBAE_ERR_INVALID);
    assert(cbae_db_bind_blob(ins, 2, "x", 1) == CBAE_ERR_INVALID);
    assert(cbae_db_bind_null(ins, 2) == CBAE_ERR_INVALID);
    expect_msg("parameter 2");
    assert(cbae_db_bind_int64(NULL, 1, 1) == CBAE_ERR_INVALID);
    expect_msg("null statement");
    cbae_error_clear();
    assert(cbae_db_bind_double(NULL, 1, 1.0) == CBAE_ERR_INVALID);
    expect_msg("null statement");
    cbae_error_clear();
    assert(cbae_db_bind_text(NULL, 1, "x") == CBAE_ERR_INVALID);
    expect_msg("null statement");
    cbae_error_clear();
    assert(cbae_db_bind_blob(NULL, 1, "x", 1) == CBAE_ERR_INVALID);
    expect_msg("null statement");
    cbae_error_clear();
    assert(cbae_db_bind_null(NULL, 1) == CBAE_ERR_INVALID);
    expect_msg("null statement");

    /* a negative length would make SQLite read the buffer up to a terminator that a blob does not have */
    char small[4] = { 1, 2, 3, 4 };
    assert(cbae_db_bind_int64(ins, 1, 77) == CBAE_OK);
    assert(cbae_db_bind_blob(ins, 1, small, -1) == CBAE_ERR_INVALID);
    expect_msg("negative length");
    assert(cbae_db_bind_blob(ins, 1, small, INT32_MIN) == CBAE_ERR_INVALID);
    assert(cbae_db_bind_blob(ins, 1, NULL, 5) == CBAE_ERR_INVALID);
    expect_msg("NULL pointer");
    assert(cbae_db_step(ins) == CBAE_OK);                                 /* the refused calls changed nothing: still 77 */
    assert(scalar(&db, "SELECT v FROM b WHERE rowid = 17;") == 77);
    cbae_db_reset(ins);

    /* the value is copied when it is bound: the caller's buffer may change, or go, before the statement runs */
    char text[] = "before";
    unsigned char bytes[4] = { 9, 8, 7, 6 };
    assert(cbae_db_bind_text(ins, 1, text) == CBAE_OK);
    memset(text, 'X', sizeof text - 1);
    assert(cbae_db_step(ins) == CBAE_OK);
    cbae_db_reset(ins);
    assert(scalar(&db, "SELECT v = 'before' FROM b WHERE rowid = 18;") == 1);
    assert(cbae_db_bind_blob(ins, 1, bytes, (int)sizeof bytes) == CBAE_OK);
    memset(bytes, 0, sizeof bytes);
    assert(cbae_db_step(ins) == CBAE_OK);
    cbae_db_reset(ins);
    assert(scalar(&db, "SELECT hex(v) = '09080706' FROM b WHERE rowid = 19;") == 1);

    /* a statement that is part-way through cannot be bound */
    sqlite3_stmt *sel = NULL;
    assert(cbae_db_prepare(&db, "SELECT ?1 FROM b;", &sel) == CBAE_OK);
    assert(cbae_db_bind_int64(sel, 1, 5) == CBAE_OK);
    assert(cbae_db_step(sel) == CBAE_DB_ROW);
    assert(cbae_db_bind_int64(sel, 1, 6) == CBAE_ERR_INVALID);
    cbae_db_reset(sel);
    assert(cbae_db_bind_int64(sel, 1, 6) == CBAE_OK);
    cbae_db_finalize(sel);
    cbae_db_finalize(ins);
#undef STORE
    cbae_db_close(&db);
    PASS("bind: every type, NULL forms, big values, bad index, negative or NULL blob, a running statement");
}

static void test_reset(void) {
    cbae_db_t db = open_ok(":memory:");
    must_exec(&db, "CREATE TABLE r(x); CREATE TABLE u(k INTEGER UNIQUE);");
    sqlite3_stmt *st = NULL;
    assert(cbae_db_prepare(&db, "INSERT INTO r(x) VALUES(?1);", &st) == CBAE_OK);
    assert(cbae_db_bind_int64(st, 1, 5) == CBAE_OK && cbae_db_step(st) == CBAE_OK);
    assert(cbae_db_step(st) == CBAE_OK);                                  /* run again with no reset: SQLite keeps the binding */
    assert(scalar(&db, "SELECT COUNT(*) FROM r WHERE x = 5;") == 2);
    cbae_db_reset(st);                                                    /* reset forgets it */
    assert(cbae_db_step(st) == CBAE_OK);
    assert(scalar(&db, "SELECT COUNT(*) FROM r WHERE x IS NULL;") == 1);
    cbae_db_finalize(st);

    /* after a failure: reset, bind something else, go on */
    assert(cbae_db_prepare(&db, "INSERT INTO u(k) VALUES(?1);", &st) == CBAE_OK);
    assert(cbae_db_bind_int64(st, 1, 1) == CBAE_OK && cbae_db_step(st) == CBAE_OK);
    cbae_db_reset(st);
    assert(cbae_db_bind_int64(st, 1, 1) == CBAE_OK && cbae_db_step(st) == CBAE_ERR_DB);
    cbae_db_reset(st);
    assert(cbae_db_bind_int64(st, 1, 2) == CBAE_OK && cbae_db_step(st) == CBAE_OK);
    assert(scalar(&db, "SELECT COUNT(*) FROM u;") == 2);
    cbae_db_finalize(st);
    cbae_db_close(&db);
    PASS("reset: forgets the bindings, and a statement that failed can be used again");
}

/* ---- the schema in use ---- */

static void test_schema_in_use(void) {
    PATH(p, "schema.db");
    rm_db(p);
    cbae_db_t db = open_ok(p);
    assert(cbae_schema_version(&db) == 0);
    assert(cbae_schema_migrate(&db) == CBAE_OK);
    assert(cbae_schema_version(&db) == CBAE_SCHEMA_CURRENT_VERSION);

    static const char *const OBJECTS[] = {
        "binaries", "analysis_jobs", "sections", "symbols", "imports", "relocations", "loader_results",
        "idx_binaries_sha256", "idx_jobs_stage", "idx_sections_binary", "idx_sections_va", "idx_symbols_binary",
        "idx_symbols_address", "idx_symbols_name", "idx_imports_binary", "idx_imports_iat", "idx_imports_name",
        "idx_relocs_binary", "idx_loader_results_binary",
    };
    for (size_t i = 0; i < sizeof OBJECTS / sizeof OBJECTS[0]; i++) {
        char sql[160];
        snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM sqlite_master WHERE name = '%s';", OBJECTS[i]);
        if (scalar(&db, sql) != 1) fprintf(stderr, "missing schema object %s\n", OBJECTS[i]);
        assert(scalar(&db, sql) == 1);
    }

    /* foreign keys are enforced, and the cascade works */
    must_exec(&db, "INSERT INTO binaries(id,path,sha256,format,arch,os_origin,file_size) VALUES(1,'/a','h1','elf64','x86_64','linux',1);");
    must_exec(&db, "INSERT INTO sections(binary_id,section_idx,name,virt_addr,virt_size,file_offset,file_size,flags) VALUES(1,0,'.text',0,0,0,0,0);");
    assert(cbae_db_exec(&db, "INSERT INTO sections(binary_id,section_idx,name,virt_addr,virt_size,file_offset,file_size,flags) VALUES(99,0,'.x',0,0,0,0,0);") == CBAE_ERR_DB);
    expect_msg("FOREIGN KEY");
    assert(cbae_db_exec(&db, "INSERT INTO binaries(path,sha256,format,arch,os_origin,file_size) VALUES('/b','h1','elf64','x86_64','linux',1);") == CBAE_ERR_DB);
    expect_msg("UNIQUE");
    assert(scalar(&db, "SELECT COUNT(*) FROM sections;") == 1);
    must_exec(&db, "DELETE FROM binaries WHERE id = 1;");
    assert(scalar(&db, "SELECT COUNT(*) FROM sections;") == 0);
    cbae_db_close(&db);
    rm_db(p);
    PASS("schema: every table and index exists, foreign keys and the unique index are enforced, delete cascades");
}

/* ---- transactions ---- */

static void test_transactions(void) {
    PATH(p, "txn.db");
    rm_db(p);
    cbae_db_t db = open_ok(p), other = open_ok(p);
    must_exec(&db, "CREATE TABLE t(x);");
    cbae_txn_t txn;

    assert(cbae_txn_begin(&txn, &db) == CBAE_OK && txn.active && txn.db == &db);
    must_exec(&db, "INSERT INTO t VALUES(1);");
    assert(scalar(&other, "SELECT COUNT(*) FROM t;") == 0);               /* not visible before the commit */
    assert(cbae_txn_commit(&txn) == CBAE_OK && !txn.active);
    assert(scalar(&other, "SELECT COUNT(*) FROM t;") == 1);               /* and visible to another connection after it */
    assert(cbae_txn_commit(&txn) == CBAE_ERR_INVALID);                    /* once only */

    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    must_exec(&db, "INSERT INTO t VALUES(2);");
    cbae_txn_rollback(&txn);
    assert(!txn.active && scalar(&db, "SELECT COUNT(*) FROM t;") == 1);
    cbae_txn_rollback(&txn);                                              /* twice is the same as once */
    assert(cbae_txn_commit(&txn) == CBAE_ERR_INVALID);
    cbae_txn_rollback(NULL);
    assert(cbae_txn_commit(NULL) == CBAE_ERR_INVALID);
    cbae_txn_t never = { NULL, false };
    cbae_txn_rollback(&never);
    assert(cbae_txn_commit(&never) == CBAE_ERR_INVALID);

    /* they do not nest: the second begin is refused and the first goes on */
    cbae_txn_t second;
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    must_exec(&db, "INSERT INTO t VALUES(3);");
    memset(&second, 0xAB, sizeof second);
    assert(cbae_txn_begin(&second, &db) == CBAE_ERR_INVALID);
    expect_msg("already open");
    assert(!second.active && second.db == NULL);
    cbae_txn_rollback(&second);                                           /* harmless */
    assert(cbae_txn_commit(&txn) == CBAE_OK);
    assert(scalar(&db, "SELECT COUNT(*) FROM t;") == 2);

    /* a failed begin leaves a transaction that does nothing, whatever was in it */
    memset(&second, 0xAB, sizeof second);
    assert(cbae_txn_begin(&second, NULL) == CBAE_ERR_INVALID && !second.active && second.db == NULL);
    assert(cbae_txn_begin(NULL, &db) == CBAE_ERR_INVALID);
    cbae_db_t closed = open_ok(":memory:");
    cbae_db_close(&closed);
    memset(&second, 0xAB, sizeof second);
    assert(cbae_txn_begin(&second, &closed) == CBAE_ERR_INVALID && !second.active);
    expect_msg("not open");

    /* the connection closed under a transaction: it was rolled back, and nothing crashes */
    cbae_db_t gone = open_ok(p);
    assert(cbae_txn_begin(&txn, &gone) == CBAE_OK);
    must_exec(&gone, "INSERT INTO t VALUES(4);");
    cbae_db_close(&gone);
    assert(cbae_txn_commit(&txn) == CBAE_ERR_DB && !txn.active);
    expect_msg("already rolled back");
    gone = open_ok(p);
    assert(cbae_txn_begin(&txn, &gone) == CBAE_OK);
    cbae_db_close(&gone);
    cbae_txn_rollback(&txn);
    assert(!txn.active);
    assert(scalar(&db, "SELECT COUNT(*) FROM t;") == 2);

    cbae_db_close(&other);
    cbae_db_close(&db);
    rm_db(p);
    PASS("transactions: begin, commit, rollback, once only, no nesting, failed begin, a closed connection");
}

static void test_commit_failure(void) {
    PATH(p, "commitfail.db");
    rm_db(p);
    cbae_db_t db = open_ok(p);
    assert(cbae_schema_migrate(&db) == CBAE_OK);
    cbae_txn_t txn;

    /* the foreign key is checked at COMMIT, and SQLite leaves the transaction open when it fails */
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    must_exec(&db, "PRAGMA defer_foreign_keys = ON;");
    must_exec(&db, "INSERT INTO sections(binary_id,section_idx,name,virt_addr,virt_size,file_offset,file_size,flags) VALUES(9999,0,'.t',0,0,0,0,0);");
    assert(cbae_txn_commit(&txn) == CBAE_ERR_DB);
    assert(cbae_error_get_context()->code == CBAE_ERR_DB);                /* the recorded code is the returned one */
    expect_msg("FOREIGN KEY");
    expect_msg("rolled back");
    assert(!txn.active);
    assert(sqlite3_get_autocommit(db.handle));                            /* nothing is left open on the connection */
    assert(scalar(&db, "SELECT COUNT(*) FROM sections;") == 0);
    cbae_txn_rollback(&txn);                                              /* the cleanup that follows is harmless */

    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);                         /* and the connection is usable again */
    must_exec(&db, "INSERT INTO binaries(path,sha256,format,arch,os_origin,file_size) VALUES('/c','h2','elf64','x86_64','linux',1);");
    assert(cbae_txn_commit(&txn) == CBAE_OK);
    assert(scalar(&db, "SELECT COUNT(*) FROM binaries;") == 1);
    cbae_db_close(&db);
    rm_db(p);
    PASS("commit: a failed commit ends the transaction, with the reason, and the connection is usable again");
}

static int interrupt_always(void *unused) { (void)unused; return 1; }

static void test_transaction_ended_by_sqlite(void) {
    cbae_db_t db = open_ok(":memory:");
    must_exec(&db, "CREATE TABLE t(x);");
    cbae_txn_t txn;

    /* an interrupted INSERT inside a transaction makes SQLite roll the whole transaction back by itself */
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    sqlite3_progress_handler(db.handle, 1, interrupt_always, NULL);
    assert(cbae_db_exec(&db, "INSERT INTO t VALUES(1);") == CBAE_ERR_DB);
    sqlite3_progress_handler(db.handle, 0, NULL, NULL);
    assert(sqlite3_get_autocommit(db.handle) && txn.active);              /* SQLite ended it; the layer has not been told */
    assert(cbae_txn_commit(&txn) == CBAE_ERR_DB && !txn.active);
    expect_msg("already rolled back");

    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    sqlite3_progress_handler(db.handle, 1, interrupt_always, NULL);
    assert(cbae_db_exec(&db, "INSERT INTO t VALUES(1);") == CBAE_ERR_DB);
    sqlite3_progress_handler(db.handle, 0, NULL, NULL);
    cbae_error_clear();
    cbae_txn_rollback(&txn);                                              /* nothing to roll back, and no error to report */
    assert(!txn.active && cbae_error_get_context()->code == CBAE_OK);
    assert(scalar(&db, "SELECT COUNT(*) FROM t;") == 0);
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK && cbae_txn_commit(&txn) == CBAE_OK);
    cbae_db_close(&db);
    PASS("transactions: one that SQLite ended after an error is reported by commit and rollback is quiet");
}

static void test_lock_contention(void) {
    PATH(p, "contend.db");
    rm_db(p);
    cbae_db_t a = open_ok(p), b = open_ok(p);
    must_exec(&a, "CREATE TABLE t(x);");
    sqlite3_busy_timeout(b.handle, 50);                                   /* b does not wait the five seconds */
    cbae_txn_t ta, tb;

    assert(cbae_txn_begin(&ta, &a) == CBAE_OK);
    const int64_t t0 = now_ms();
    assert(cbae_txn_begin(&tb, &b) == CBAE_ERR_BUSY);                     /* the lock is taken at begin: told now, not at the first write */
    assert(now_ms() - t0 < 3000);
    assert(!tb.active && sqlite3_get_autocommit(b.handle));
    assert(scalar(&b, "SELECT COUNT(*) FROM t;") == 0);                   /* WAL: a reader is not blocked by the writer */
    assert(cbae_db_exec(&b, "INSERT INTO t VALUES(1);") == CBAE_ERR_BUSY);
    assert(cbae_txn_commit(&ta) == CBAE_OK);

    assert(cbae_txn_begin(&tb, &b) == CBAE_OK);
    must_exec(&b, "INSERT INTO t VALUES(1);");
    assert(cbae_txn_commit(&tb) == CBAE_OK);
    assert(scalar(&a, "SELECT COUNT(*) FROM t;") == 1);
    cbae_db_close(&a);
    cbae_db_close(&b);
    rm_db(p);
    PASS("transactions: begin takes the write lock and reports BUSY at once when another connection has it");
}

static void test_wal_readers(void) {
    PATH(p, "wal.db");
    rm_db(p);
    cbae_db_t w = open_ok(p), r = open_ok(p);
    must_exec(&w, "CREATE TABLE t(x); INSERT INTO t VALUES(1);");
    sqlite3_busy_timeout(w.handle, 50);                                   /* in rollback-journal mode the commit below would wait for the reader */
    must_exec(&r, "BEGIN;");
    assert(scalar(&r, "SELECT COUNT(*) FROM t;") == 1);                   /* the reader's snapshot */
    cbae_txn_t txn;
    assert(cbae_txn_begin(&txn, &w) == CBAE_OK);
    must_exec(&w, "INSERT INTO t VALUES(2);");
    assert(cbae_txn_commit(&txn) == CBAE_OK);                             /* the writer is not held up by the open reader */
    assert(scalar(&r, "SELECT COUNT(*) FROM t;") == 1);                   /* and the reader still sees what it saw */
    must_exec(&r, "COMMIT;");
    assert(scalar(&r, "SELECT COUNT(*) FROM t;") == 2);
    cbae_db_close(&w);
    cbae_db_close(&r);
    rm_db(p);
    PASS("WAL: an open reader neither blocks the writer nor sees its changes");
}

/* ---- migrations ---- */

static int count_commit(void *arg) { ++*(int *)arg; return 0; }           /* 0: let the commit go ahead */

static void test_migration(void) {
    PATH(p, "migrate.db");
    rm_db(p);
    cbae_db_t db = open_ok(p);

    assert(cbae_schema_version(NULL) == CBAE_ERR_INVALID);
    assert(cbae_schema_migrate(NULL) == CBAE_ERR_INVALID);
    cbae_db_t closed = open_ok(":memory:");
    cbae_db_close(&closed);
    assert(cbae_schema_version(&closed) == CBAE_ERR_INVALID);
    expect_msg("not open");
    cbae_error_clear();
    assert(cbae_schema_migrate(&closed) == CBAE_ERR_INVALID);
    expect_msg("not open");

    int commits = 0;
    sqlite3_commit_hook(db.handle, count_commit, &commits);
    assert(cbae_schema_migrate(&db) == CBAE_OK);
    assert(cbae_schema_version(&db) == CBAE_SCHEMA_CURRENT_VERSION);
    assert(commits == CBAE_SCHEMA_CURRENT_VERSION);                       /* one transaction for each migration, no more */
    assert(cbae_schema_migrate(&db) == CBAE_OK);                          /* idempotent */
    assert(cbae_schema_version(&db) == CBAE_SCHEMA_CURRENT_VERSION);
    assert(commits == CBAE_SCHEMA_CURRENT_VERSION);                       /* and none when there is nothing to do */
    sqlite3_commit_hook(db.handle, NULL, NULL);

    /* a current schema is not touched: no lock is taken, so a writer elsewhere does not stop the check */
    cbae_db_t other = open_ok(p);
    sqlite3_busy_timeout(db.handle, 50);
    cbae_txn_t txn;
    assert(cbae_txn_begin(&txn, &other) == CBAE_OK);
    assert(cbae_schema_migrate(&db) == CBAE_OK);
    assert(cbae_txn_commit(&txn) == CBAE_OK);
    cbae_db_close(&other);

    /* a version that is not a version */
    must_exec(&db, "PRAGMA user_version = -3;");
    assert(cbae_schema_version(&db) == CBAE_ERR_DB);
    expect_msg("negative");
    assert(cbae_schema_migrate(&db) == CBAE_ERR_DB);
    must_exec(&db, "PRAGMA user_version = 2;");

    /* a database from a newer program is refused, and left as it is */
    must_exec(&db, "PRAGMA user_version = 3;");
    assert(cbae_schema_version(&db) == 3);
    assert(cbae_schema_migrate(&db) == CBAE_ERR_UNSUPPORTED);
    expect_msg("schema is v3");
    expect_msg("the v2 this build");
    assert(cbae_schema_version(&db) == 3);
    assert(scalar(&db, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'binaries';") == 1);
    must_exec(&db, "PRAGMA user_version = 2;");

    /* from version 1: migration 002 is applied */
    must_exec(&db, "DROP TABLE loader_results; DROP TABLE relocations; DROP TABLE imports; DROP TABLE symbols; DROP TABLE sections;"
                   "PRAGMA user_version = 1;");
    assert(cbae_schema_version(&db) == 1);
    assert(cbae_schema_migrate(&db) == CBAE_OK);
    assert(cbae_schema_version(&db) == 2 && scalar(&db, "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('sections','symbols','imports','relocations','loader_results');") == 5);
    assert(sqlite3_get_autocommit(db.handle));
    cbae_db_close(&db);
    rm_db(p);
    PASS("migrate: versions, idempotent, no lock when current, a negative or newer version, from version 1");
}

static void test_migration_is_atomic(void) {
    PATH(p, "atomic.db");
    rm_db(p);
    cbae_db_t db = open_ok(p);
    assert(cbae_schema_migrate(&db) == CBAE_OK);
    must_exec(&db, "DROP TABLE loader_results; DROP TABLE relocations; DROP TABLE imports; DROP TABLE symbols; DROP TABLE sections;"
                   "PRAGMA user_version = 1;");
    /* a view named like a table makes migration 002 fail half way: its first statements work, a later one cannot index a view */
    must_exec(&db, "CREATE VIEW symbols AS SELECT 1 AS binary_id;");
    assert(cbae_schema_migrate(&db) == CBAE_ERR_DB);
    expect_msg("Migration 002 failed");
    assert(cbae_schema_version(&db) == 1);                                /* still version 1 ... */
    assert(scalar(&db, "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('sections','imports','relocations','loader_results');") == 0);   /* ... with nothing of 002 left */
    assert(sqlite3_get_autocommit(db.handle));

    must_exec(&db, "DROP VIEW symbols;");                                 /* the cause removed: the same migration now succeeds */
    assert(cbae_schema_migrate(&db) == CBAE_OK);
    assert(cbae_schema_version(&db) == 2);
    assert(scalar(&db, "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('sections','symbols','imports','relocations','loader_results');") == 5);
    cbae_db_close(&db);
    rm_db(p);
    PASS("migrate: a migration that fails changes nothing, and succeeds once the cause is gone");
}

static void test_migration_waits_for_the_lock(void) {
    PATH(p, "waits.db");
    rm_db(p);
    cbae_db_t a = open_ok(p), b = open_ok(p);
    sqlite3_busy_timeout(b.handle, 50);
    cbae_txn_t ta;
    assert(cbae_txn_begin(&ta, &a) == CBAE_OK);
    assert(cbae_schema_migrate(&b) == CBAE_ERR_BUSY);                     /* told it could not, and changed nothing */
    assert(cbae_schema_version(&b) == 0 && sqlite3_get_autocommit(b.handle));
    cbae_txn_rollback(&ta);
    assert(cbae_schema_migrate(&b) == CBAE_OK && cbae_schema_version(&a) == CBAE_SCHEMA_CURRENT_VERSION);
    cbae_db_close(&a);
    cbae_db_close(&b);
    rm_db(p);
    PASS("migrate: BUSY, with nothing changed, while another connection holds the write lock");
}

static void test_migration_inside_a_transaction(void) {
    PATH(p, "intxn.db");
    rm_db(p);
    cbae_db_t db = open_ok(p);
    cbae_txn_t txn;
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    assert(cbae_schema_migrate(&db) == CBAE_ERR_INVALID);                 /* it needs a transaction of its own */
    expect_msg("already open");
    assert(scalar(&db, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'binaries';") == 0);   /* nothing was done in the caller's */
    assert(txn.active && !sqlite3_get_autocommit(db.handle));             /* which is still the caller's */
    cbae_txn_rollback(&txn);
    assert(cbae_schema_version(&db) == 0);
    cbae_db_close(&db);
    rm_db(p);
    PASS("migrate: refused, and nothing done, inside a transaction of the caller");
}

static void test_version_read_failure(void) {
    cbae_db_t db = open_ok(":memory:");
    must_exec(&db, "PRAGMA user_version = 3;");
    sqlite3_progress_handler(db.handle, 1, interrupt_always, NULL);
    assert(cbae_schema_version(&db) == CBAE_ERR_DB);                      /* an error, not 0: 0 is the version of an empty database */
    sqlite3_progress_handler(db.handle, 0, NULL, NULL);
    assert(cbae_schema_version(&db) == 3);
    cbae_db_close(&db);
    PASS("version: a read that fails is an error, not the version of an empty database");
}

/* The busy handler runs while a connection waits for a lock. Here it is the other connection finishing what it was
 * doing, so the schema changes after migrate has started and before it has the lock. */
typedef struct { cbae_txn_t *txn; int calls; } handoff_t;


static int hand_off(void *arg, int count) {
    handoff_t *h = arg;
    (void)count;
    h->calls++;
    if (h->txn->active) assert(cbae_txn_commit(h->txn) == CBAE_OK);
    return 1;                                                             /* try again */
}

static cbae_err_t migrate_while_another_sets_version(const char *path, int set, int *version_after, int64_t *tables_after, int *commits) {
    rm_db(path);
    cbae_db_t a = open_ok(path), b = open_ok(path);
    cbae_txn_t ta;
    assert(cbae_txn_begin(&ta, &a) == CBAE_OK);
    char sql[64];
    snprintf(sql, sizeof sql, "PRAGMA user_version = %d;", set);
    must_exec(&a, sql);                                                   /* a version change and nothing else, not yet committed */
    handoff_t h = { &ta, 0 };
    sqlite3_busy_handler(b.handle, hand_off, &h);
    *commits = 0;
    sqlite3_commit_hook(b.handle, count_commit, commits);                 /* how many transactions b commits */
    const cbae_err_t e = cbae_schema_migrate(&b);
    assert(h.calls >= 1 && !ta.active);                                   /* b did wait for a, and a is what it waited for */
    *version_after = cbae_schema_version(&a);
    *tables_after = scalar(&a, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN "
                               "('binaries','analysis_jobs','sections','symbols','imports','relocations','loader_results');");
    assert(sqlite3_get_autocommit(b.handle));
    cbae_db_close(&a);
    cbae_db_close(&b);
    rm_db(path);
    return e;
}

static void test_migration_after_waiting(void) {
    PATH(p, "handoff.db");
    int version, commits;
    int64_t tables;

    /* the schema was finished by someone else while we waited: nothing is run, and the version is not touched */
    assert(migrate_while_another_sets_version(p, 2, &version, &tables, &commits) == CBAE_OK);
    assert(version == 2 && tables == 0 && commits == 1);                  /* the one commit ends the transaction that took the lock */

    /* it was half way: only the migration that is left is run, once */
    assert(migrate_while_another_sets_version(p, 1, &version, &tables, &commits) == CBAE_OK);
    assert(version == 2 && tables == 5 && commits == 1);                  /* 002's tables, and not 001's */

    /* a newer program got there first: refused, and left alone */
    assert(migrate_while_another_sets_version(p, 3, &version, &tables, &commits) == CBAE_ERR_UNSUPPORTED);
    assert(version == 3 && tables == 0 && commits == 1);
    PASS("migrate: the version is read again under the lock (finished, half done and newer by the time the lock is had)");
}

static void test_transaction_logging(void) {
    PATH(p, "txnlog.db");
    PATH(quiet, "txnlog_quiet.log");
    PATH(loud, "txnlog_loud.log");
    rm_db(p);
    unlink(quiet);
    unlink(loud);
    cbae_db_t db = open_ok(p);
    must_exec(&db, "CREATE TABLE t(x);");
    cbae_txn_t txn;
    cbae_txn_t never = { NULL, false };
    char log[2048];

    cbae_log_init(CBAE_LOG_WARN, quiet, false);                           /* what is not a rollback says nothing */
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK && cbae_txn_commit(&txn) == CBAE_OK);
    cbae_txn_rollback(&txn);
    cbae_txn_rollback(&never);
    cbae_log_shutdown();
    size_t n = read_file(quiet, log, sizeof log - 1);
    assert(n == 0 || n == (size_t)-1);

    cbae_log_init(CBAE_LOG_WARN, loud, false);                            /* a rollback that is done is warned about */
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    cbae_txn_rollback(&txn);
    cbae_log_shutdown();
    n = read_file(loud, log, sizeof log - 1);
    assert(n != (size_t)-1 && n > 0);
    log[n] = '\0';
    assert(strstr(log, "Transaction rolled back"));
    cbae_db_close(&db);
    unlink(quiet);
    unlink(loud);
    rm_db(p);
    PASS("transactions: a rollback that is done is warned about, and one that is not needed is silent");
}

/* ---- several connections at once ---- */

typedef struct {
    const char       *path;
    int               txns;
    pthread_barrier_t *start;
    _Atomic int      *failures;
    cbae_err_t        result;
} worker_t;

static void *migrator(void *arg) {
    worker_t *w = arg;
    cbae_db_t db;
    assert(cbae_db_open(&db, w->path) == CBAE_OK);
    pthread_barrier_wait(w->start);
    w->result = cbae_schema_migrate(&db);
    if (w->result == CBAE_OK && cbae_schema_version(&db) != CBAE_SCHEMA_CURRENT_VERSION) w->result = CBAE_ERR_GENERIC;
    cbae_db_close(&db);
    return NULL;
}

static void test_concurrent_migration(void) {
    enum { THREADS = 4 };
    PATH(p, "concurrent_migrate.db");
    const int rounds = QUICK ? 2 : 8;
    for (int r = 0; r < rounds; r++) {
        rm_db(p);
        pthread_barrier_t bar;
        pthread_barrier_init(&bar, NULL, THREADS);
        pthread_t th[THREADS];
        worker_t w[THREADS];
        for (int i = 0; i < THREADS; i++) {
            w[i] = (worker_t){ .path = p, .start = &bar, .result = CBAE_ERR_GENERIC };
            assert(pthread_create(&th[i], NULL, migrator, &w[i]) == 0);
        }
        for (int i = 0; i < THREADS; i++) pthread_join(th[i], NULL);
        pthread_barrier_destroy(&bar);
        for (int i = 0; i < THREADS; i++) {
            if (w[i].result != CBAE_OK) fprintf(stderr, "thread %d: %d\n", i, (int)w[i].result);
            assert(w[i].result == CBAE_OK);
        }
        cbae_db_t db = open_ok(p);
        assert(cbae_schema_version(&db) == CBAE_SCHEMA_CURRENT_VERSION);
        assert(scalar(&db, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('binaries','analysis_jobs','sections','symbols','imports','relocations','loader_results');") == 7);
        cbae_db_close(&db);
    }
    rm_db(p);
    PASS("migrate: connections migrating the same file at once all succeed, and the schema is made once");
}

typedef struct {
    const char        *path;
    int                rounds;
    pthread_barrier_t *go, *done;
    _Atomic int       *failures, *not_wal;
} opener_t;

static void *opener(void *arg) {
    opener_t *o = arg;
    for (int r = 0; r < o->rounds; r++) {
        pthread_barrier_wait(o->go);
        cbae_db_t db;
        if (cbae_db_open(&db, o->path) != CBAE_OK) {
            atomic_fetch_add(o->failures, 1);
        } else {
            char mode[32];
            scalar_text(&db, "PRAGMA journal_mode;", mode, sizeof mode);
            if (strcmp(mode, "wal") != 0) atomic_fetch_add(o->not_wal, 1);
            cbae_db_close(&db);
        }
        pthread_barrier_wait(o->done);
    }
    return NULL;
}

static void test_concurrent_open(void) {
    enum { THREADS = 8 };
    PATH(p, "concurrent_open.db");
    const int rounds = QUICK ? 15 : 150;
    _Atomic int failures = 0, not_wal = 0;
    pthread_barrier_t go, done;
    pthread_barrier_init(&go, NULL, THREADS + 1);
    pthread_barrier_init(&done, NULL, THREADS + 1);
    opener_t o = { p, rounds, &go, &done, &failures, &not_wal };
    pthread_t th[THREADS];
    for (int i = 0; i < THREADS; i++) assert(pthread_create(&th[i], NULL, opener, &o) == 0);
    for (int r = 0; r < rounds; r++) {
        rm_db(p);                                                         /* a new file every round: the switch to WAL is what is raced */
        pthread_barrier_wait(&go);
        pthread_barrier_wait(&done);
    }
    for (int i = 0; i < THREADS; i++) pthread_join(th[i], NULL);
    pthread_barrier_destroy(&go);
    pthread_barrier_destroy(&done);
    if (atomic_load(&failures) != 0) fprintf(stderr, "%d of %d opens failed\n", atomic_load(&failures), THREADS * rounds);
    assert(atomic_load(&failures) == 0 && atomic_load(&not_wal) == 0);
    rm_db(p);
    PASS("open: connections opening the same new file together all succeed, and the file ends up in WAL mode");
}

static void *writer(void *arg) {
    worker_t *w = arg;
    cbae_db_t db;
    assert(cbae_db_open(&db, w->path) == CBAE_OK);
    pthread_barrier_wait(w->start);
    for (int i = 0; i < w->txns; i++) {
        cbae_txn_t txn;
        if (cbae_txn_begin(&txn, &db) != CBAE_OK) { atomic_fetch_add(w->failures, 1); continue; }
        /* read, then write: the shape that fails when the lock is only taken at the first write */
        sqlite3_stmt *st = NULL;
        int64_t top = -1;
        if (cbae_db_prepare(&db, "SELECT COALESCE(MAX(x), 0) FROM seq;", &st) == CBAE_OK) {
            if (cbae_db_step(st) == CBAE_DB_ROW) top = cbae_db_col_int64(st, 0);
            cbae_db_finalize(st);
        }
        cbae_err_t e = top < 0 ? CBAE_ERR_GENERIC : cbae_db_prepare(&db, "INSERT INTO seq(x) VALUES(?1);", &st);
        if (e == CBAE_OK) {
            e = cbae_db_bind_int64(st, 1, top + 1);
            if (e == CBAE_OK) { const int rc = cbae_db_step(st); e = rc < 0 ? (cbae_err_t)rc : CBAE_OK; }
            cbae_db_finalize(st);
        }
        if (e == CBAE_OK) e = cbae_txn_commit(&txn);
        if (e != CBAE_OK) { cbae_txn_rollback(&txn); atomic_fetch_add(w->failures, 1); }
    }
    cbae_db_close(&db);
    return NULL;
}

static void test_concurrent_writers(void) {
    enum { THREADS = 4 };
    PATH(p, "writers.db");
    rm_db(p);
    cbae_db_t db = open_ok(p);
    must_exec(&db, "CREATE TABLE seq(x INTEGER PRIMARY KEY);");
    const int txns = QUICK ? 10 : 50;
    _Atomic int failures = 0;
    pthread_barrier_t bar;
    pthread_barrier_init(&bar, NULL, THREADS);
    pthread_t th[THREADS];
    worker_t w[THREADS];
    for (int i = 0; i < THREADS; i++) {
        w[i] = (worker_t){ .path = p, .txns = txns, .start = &bar, .failures = &failures };
        assert(pthread_create(&th[i], NULL, writer, &w[i]) == 0);
    }
    for (int i = 0; i < THREADS; i++) pthread_join(th[i], NULL);
    pthread_barrier_destroy(&bar);
    assert(atomic_load(&failures) == 0);
    assert(scalar(&db, "SELECT COUNT(*) FROM seq;") == THREADS * txns);
    assert(scalar(&db, "SELECT MAX(x) FROM seq;") == THREADS * txns);     /* every one saw the others' work: no lost update */
    cbae_db_close(&db);
    rm_db(p);
    PASS("transactions: connections that read and then write, at once, never fail and never lose an update");
}

/* ---- SQLite's allocator failing ---- */

/* One life of a connection: open, migrate, write a row in a transaction, read it back, close. Returns the first error;
 * when it returns CBAE_OK the data has been checked. */
static cbae_err_t life(const char *path) {
    cbae_db_t db;
    cbae_err_t e = cbae_db_open(&db, path);
    if (e != CBAE_OK) { assert(db.handle == NULL); return e; }
    e = cbae_schema_migrate(&db);
    assert(sqlite3_get_autocommit(db.handle));                            /* no transaction is left open, whatever happened */
    if (e == CBAE_OK) {
        const int v = cbae_schema_version(&db);
        if (v < 0) { assert(atomic_load(&g_sq_fired)); e = (cbae_err_t)v; }   /* the failed allocation fell in this very call */
        else assert(v == CBAE_SCHEMA_CURRENT_VERSION);
    }
    if (e == CBAE_OK) {
        cbae_txn_t txn;
        e = cbae_txn_begin(&txn, &db);
        if (e == CBAE_OK) {
            sqlite3_stmt *st = NULL;
            e = cbae_db_prepare(&db, "INSERT INTO binaries(path,sha256,format,arch,os_origin,file_size) VALUES(?,?,?,?,?,?);", &st);
            if (e == CBAE_OK) e = cbae_db_bind_text(st, 1, "/drivers/r8169.sys");
            if (e == CBAE_OK) e = cbae_db_bind_text(st, 2, "aabbccdd");
            if (e == CBAE_OK) e = cbae_db_bind_text(st, 3, "pe32plus");
            if (e == CBAE_OK) e = cbae_db_bind_text(st, 4, "x86_64");
            if (e == CBAE_OK) e = cbae_db_bind_text(st, 5, "windows");
            if (e == CBAE_OK) e = cbae_db_bind_int64(st, 6, 98765);
            if (e == CBAE_OK) { const int rc = cbae_db_step(st); e = rc < 0 ? (cbae_err_t)rc : CBAE_OK; }
            cbae_db_finalize(st);
            if (e == CBAE_OK) e = cbae_txn_commit(&txn);
            else cbae_txn_rollback(&txn);
        }
    }
    if (e == CBAE_OK) {
        sqlite3_stmt *st = NULL;
        e = cbae_db_prepare(&db, "SELECT path, file_size FROM binaries WHERE sha256 = 'aabbccdd';", &st);
        if (e == CBAE_OK) {
            const int rc = cbae_db_step(st);
            if (rc == CBAE_DB_ROW) {
                assert(strcmp(cbae_db_col_text(st, 0), "/drivers/r8169.sys") == 0 && cbae_db_col_int64(st, 1) == 98765);
            } else {
                e = rc < 0 ? (cbae_err_t)rc : CBAE_ERR_GENERIC;           /* a row was written and committed: not finding it is an error */
            }
            cbae_db_finalize(st);
        }
    }
    cbae_db_close(&db);
    return e;
}

typedef struct { long runs, failed, as_oom, swallowed; } sweep_t;

static sweep_t sweep(const char *path, long stride) {
    if (path[0] == '/') rm_db(path);
    sq_arm(0);
    assert(life(path) == CBAE_OK);                                        /* once without failures: warms up SQLite's global state */
    if (path[0] == '/') rm_db(path);
    sq_arm(0);
    assert(life(path) == CBAE_OK);
    const long total = sq_disarm();
    const sqlite3_int64 base = sqlite3_memory_used();
    sweep_t s = { 0, 0, 0, 0 };
    for (long k = 1; k <= total + 3; k += (k < total ? stride : 1)) {
        if (path[0] == '/') rm_db(path);
        sq_arm(k);
        const cbae_err_t e = life(path);
        const bool fired = atomic_load(&g_sq_fired);
        sq_disarm();
        if (sqlite3_memory_used() != base) fprintf(stderr, "allocation %ld of %ld failed (code %d) and memory leaked\n", k, total, (int)e);
        assert(sqlite3_memory_used() == base);                            /* nothing leaked, whatever failed */
        s.runs++;
        if (e != CBAE_OK) {
            if (!fired) fprintf(stderr, "allocation %ld of %ld: error %d without a failed allocation\n", k, total, (int)e);
            assert(fired && cbae_error_get_context()->message[0] != '\0');
            s.failed++;
            if (e == CBAE_ERR_OOM) s.as_oom++;
            else fprintf(stderr, "allocation %ld of %ld failed: reported as %d (%s)\n", k, total, (int)e, cbae_last_error());
        } else if (fired) s.swallowed++;                                  /* SQLite coped: the data was checked by life() */
    }
    assert(s.failed > 0);
    return s;
}

static void test_allocation_failure_in_memory(void) {
    const long stride = QUICK ? 17 : 1;
    const sweep_t s = sweep(":memory:", stride);
    assert(s.as_oom == s.failed);
    printf("         (%ld runs: %ld failed as out-of-memory, %ld absorbed by SQLite)\n", s.runs, s.failed, s.swallowed);
    PASS("allocation failure: in an in-memory life, every failure is reported as out of memory and nothing leaks");
}

static void test_allocation_failure_on_file(void) {
    PATH(p, "oom.db");
    const long stride = QUICK ? 41 : 7;
    const sweep_t s = sweep(p, stride);
    assert(s.as_oom == s.failed);
    printf("         (%ld runs: %ld failed as out-of-memory, %ld absorbed by SQLite)\n", s.runs, s.failed, s.swallowed);
    rm_db(p);
    PASS("allocation failure: in a life on a file, every failure is reported as out of memory and nothing leaks");
}

/* ---- the layer's original round trip, now with the data surviving a close ---- */

static void test_persistence(void) {
    PATH(p, "persist.db");
    rm_db(p);
    cbae_db_t db = open_ok(p);
    assert(cbae_schema_migrate(&db) == CBAE_OK);
    assert(cbae_schema_version(&db) == CBAE_SCHEMA_CURRENT_VERSION);

    cbae_txn_t txn;
    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);
    sqlite3_stmt *ins = NULL;
    assert(cbae_db_prepare(&db, "INSERT INTO binaries(path,sha256,format,arch,os_origin,file_size) VALUES(?,?,?,?,?,?);", &ins) == CBAE_OK);
    assert(cbae_db_bind_text(ins, 1, "/drivers/r8169.sys") == CBAE_OK);
    assert(cbae_db_bind_text(ins, 2, "aabbccdd") == CBAE_OK);
    assert(cbae_db_bind_text(ins, 3, "pe32plus") == CBAE_OK);
    assert(cbae_db_bind_text(ins, 4, "x86_64") == CBAE_OK);
    assert(cbae_db_bind_text(ins, 5, "windows") == CBAE_OK);
    assert(cbae_db_bind_int64(ins, 6, 98765) == CBAE_OK);
    assert(cbae_db_step(ins) == CBAE_OK);
    cbae_db_finalize(ins);
    assert(cbae_txn_commit(&txn) == CBAE_OK);

    assert(cbae_txn_begin(&txn, &db) == CBAE_OK);                         /* a rolled-back insert leaves nothing */
    must_exec(&db, "INSERT INTO binaries(path,sha256,format,arch,os_origin,file_size) VALUES('/tmp/x','deadbeef','elf64','x86_64','linux',1);");
    cbae_txn_rollback(&txn);
    assert(scalar(&db, "SELECT COUNT(*) FROM binaries WHERE sha256 = 'deadbeef';") == 0);
    cbae_db_close(&db);

    db = open_ok(p);                                                      /* it is all still there */
    assert(cbae_schema_migrate(&db) == CBAE_OK && cbae_schema_version(&db) == CBAE_SCHEMA_CURRENT_VERSION);
    sqlite3_stmt *sel = NULL;
    assert(cbae_db_prepare(&db, "SELECT path, file_size FROM binaries WHERE sha256 = 'aabbccdd';", &sel) == CBAE_OK);
    assert(cbae_db_step(sel) == CBAE_DB_ROW);
    assert(strcmp(cbae_db_col_text(sel, 0), "/drivers/r8169.sys") == 0 && cbae_db_col_int64(sel, 1) == 98765);
    assert(cbae_db_step(sel) == CBAE_OK);
    cbae_db_finalize(sel);
    cbae_db_close(&db);
    rm_db(p);
    PASS("persistence: schema, a committed record read back after a close and reopen, a rolled-back record absent");
}

int main(void) {
    printf("=== test_db_persistence ===\n");
    /* SQLite's configuration is fixed once it has been used, so it is set before anything else. */
    static const sqlite3_mem_methods SQ_METHODS = { sq_malloc, sq_free, sq_realloc, sq_size, sq_roundup, sq_init, sq_shutdown, NULL };
    assert(sqlite3_config(SQLITE_CONFIG_MEMSTATUS, 1) == SQLITE_OK);
    assert(sqlite3_config(SQLITE_CONFIG_MALLOC, &SQ_METHODS) == SQLITE_OK);
    snprintf(g_dir, sizeof g_dir, "/tmp/cbae_db_test_XXXXXX");
    assert(mkdtemp(g_dir) != NULL);

    test_open_settings();
    test_open_transient();
    test_open_arguments();
    test_open_failures();
    test_open_refusals();
    test_open_busy_retry();
    test_long_path();
    test_close();
    test_err_mapping();
    test_exec();
    test_prepare();
    test_step_and_columns();
    test_bind();
    test_reset();
    test_schema_in_use();
    test_transactions();
    test_commit_failure();
    test_transaction_ended_by_sqlite();
    test_transaction_logging();
    test_lock_contention();
    test_wal_readers();
    test_migration();
    test_migration_is_atomic();
    test_migration_waits_for_the_lock();
    test_migration_inside_a_transaction();
    test_version_read_failure();
    test_migration_after_waiting();
    test_concurrent_migration();
    test_concurrent_open();
    test_concurrent_writers();
    test_allocation_failure_in_memory();
    test_allocation_failure_on_file();
    test_persistence();

    rmdir(g_dir);                                                         /* fails if a test left something behind: that is a finding */
    printf("All DB persistence tests passed.\n");
    return 0;
}
