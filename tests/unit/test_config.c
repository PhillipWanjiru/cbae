/**
 * @file test_config.c
 * @brief Unit tests for the strict configuration parser (audit A-032) and the engine's use of it.
 *
 * The defects: trim() advanced a local pointer, so a leading space stayed in every value (the shipped
 * file loaded db_path as " /var/lib/cbae/analysis.db"); numbers went through atoi/atol/atof (garbage
 * read as 0, a negative arena size became a huge size_t); unknown keys and stray lines were ignored.
 */
#include "cbae/cbae_engine.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef CBAE_SHIPPED_CONFIG
#error "CMake passes the path of config/cbae.conf as CBAE_SHIPPED_CONFIG"
#endif

#define PASS(name) printf("  [PASS] %s\n", name)

static char g_path[64];

/* writes `len` bytes to a fresh temp file and loads it */
static cbae_err_t load_bytes(const void *data, size_t len, cbae_config_t *cfg) {
    snprintf(g_path, sizeof g_path, "/tmp/cbae_test_cfg_XXXXXX");
    const int fd = mkstemp(g_path);
    assert(fd >= 0);
    size_t off = 0;
    while (off < len) { const ssize_t w = write(fd, (const char *)data + off, len - off); assert(w > 0); off += (size_t)w; }
    close(fd);
    const cbae_err_t rc = cbae_config_load(g_path, cfg);
    unlink(g_path);
    return rc;
}
static cbae_err_t load_text(const char *text, cbae_config_t *cfg) { return load_bytes(text, strlen(text), cfg); }

static bool same(const cbae_config_t *a, const cbae_config_t *b) { return memcmp(a, b, sizeof *a) == 0; }

static void expect_defaults(const cbae_config_t *c) {
    cbae_config_t d;
    cbae_config_defaults(&d);
    assert(same(c, &d));
}

/* a config that fails: the right code, the file and line in the message, defaults in *cfg */
static void expect_refused(const char *text, cbae_err_t code, const char *line_tag) {
    cbae_config_t c;
    memset(&c, 0xAB, sizeof c);
    const cbae_err_t rc = load_text(text, &c);
    if (rc != code) fprintf(stderr, "config text [%s]: code %d, expected %d (%s)\n", text, (int)rc, (int)code, cbae_last_error());
    assert(rc == code);
    expect_defaults(&c);
    if (line_tag) {
        if (!strstr(cbae_last_error(), line_tag)) fprintf(stderr, "message [%s] lacks [%s]\n", cbae_last_error(), line_tag);
        assert(strstr(cbae_last_error(), line_tag));
        assert(strstr(cbae_last_error(), "/tmp/cbae_test_cfg_"));
    }
}

static void test_defaults(void) {
    cbae_config_t c;
    cbae_config_defaults(&c);
    assert(strcmp(c.db_path, "/var/lib/cbae/analysis.db") == 0 && c.log_path[0] == '\0' && c.api_db_path[0] == '\0');
    assert(c.worker_count == 4 && c.capture_vm_count == 2 && c.arena_size_mb == 256 && c.log_level == 2 && c.log_json == false);
    assert(c.api_confidence_min == 0.75f && c.dna_similarity_thresh == 0.90f);
    cbae_config_defaults(NULL);
    PASS("defaults");
}

static void test_shipped_config(void) {
    cbae_config_t c;
    assert(cbae_config_load(CBAE_SHIPPED_CONFIG, &c) == CBAE_OK);
    assert(strcmp(c.db_path, "/var/lib/cbae/analysis.db") == 0);        /* no leading space (the old trim bug) */
    assert(c.log_path[0] == '\0' && strcmp(c.api_db_path, "/var/lib/cbae/api_sigs.db") == 0);
    assert(c.worker_count == 8 && c.capture_vm_count == 2 && c.arena_size_mb == 256 && c.log_level == 2 && c.log_json == false);
    assert(c.api_confidence_min == 0.75f && c.dna_similarity_thresh == 0.90f);
    PASS("the shipped config/cbae.conf loads, with exact values");
}

static void test_format(void) {
    cbae_config_t c;
    assert(load_text("  db_path\t=   /a b/c.db  # trailing comment\r\n\r\n# whole-line comment\n\t# indented comment\nworker_count=3\n"
                     "log_path =\napi_db_path = /x=y\n  log_level = +4  \nlog_json = TRUE", &c) == CBAE_OK);
    assert(strcmp(c.db_path, "/a b/c.db") == 0);                         /* trimmed both ends, inner space kept */
    assert(c.worker_count == 3 && c.log_path[0] == '\0' && strcmp(c.api_db_path, "/x=y") == 0 && c.log_level == 4 && c.log_json == true);
    assert(load_text("", &c) == CBAE_OK); expect_defaults(&c);
    assert(load_text("# only a comment", &c) == CBAE_OK); expect_defaults(&c);
    assert(load_text("\xEF\xBB\xBF" "worker_count = 5\n", &c) == CBAE_OK && c.worker_count == 5);        /* a full byte order mark is skipped */
    assert(load_text("worker_count = 1\nworker_count = 2\n", &c) == CBAE_OK && c.worker_count == 2);    /* a repeated key: the last wins */
    assert(load_text("log_json = 1\n", &c) == CBAE_OK && c.log_json && load_text("log_json = Off\n", &c) == CBAE_OK && !c.log_json);
    PASS("whitespace, comments, CRLF, no final newline, BOM, repeated key, boolean spellings");
}

static void test_each_key_only_its_field(void) {
    /* every key given a value that differs from the default; the result must equal a struct built by hand,
     * byte for byte, whichever order the keys come in (a store through the wrong type would show) */
    cbae_config_t want;
    cbae_config_defaults(&want);
    snprintf(want.db_path, sizeof want.db_path, "%s", "/d");
    snprintf(want.log_path, sizeof want.log_path, "%s", "/l");
    snprintf(want.api_db_path, sizeof want.api_db_path, "%s", "/a");
    want.worker_count = 7; want.capture_vm_count = 9; want.arena_size_mb = 4096; want.log_level = 5; want.log_json = true;
    want.api_confidence_min = 0.5f; want.dna_similarity_thresh = 0.125f;
    static const char *const lines[] = { "db_path=/d", "log_path=/l", "api_db_path=/a", "worker_count=7", "capture_vm_count=9",
        "arena_size_mb=4096", "log_level=5", "log_json=yes", "api_confidence_min=0.5", "dna_similarity_thresh=.125" };
    enum { N = sizeof lines / sizeof lines[0] };
    char forward[512] = "", backward[512] = "";
    for (int i = 0; i < N; i++) { strcat(forward, lines[i]); strcat(forward, "\n"); strcat(backward, lines[N - 1 - i]); strcat(backward, "\n"); }
    cbae_config_t a, b;
    memset(&a, 0x55, sizeof a); memset(&b, 0x77, sizeof b);
    assert(load_text(forward, &a) == CBAE_OK && load_text(backward, &b) == CBAE_OK);
    assert(same(&a, &want) && same(&b, &want));
    /* and one key at a time changes exactly one thing */
    for (int i = 0; i < N; i++) {
        cbae_config_t one, base;
        cbae_config_defaults(&base);
        char text[64]; snprintf(text, sizeof text, "%s\n", lines[i]);
        assert(load_text(text, &one) == CBAE_OK);
        size_t diff = 0;
        for (size_t k = 0; k < sizeof one; k++) if (((uint8_t *)&one)[k] != ((uint8_t *)&base)[k]) diff++;
        assert(diff > 0);
        cbae_config_t expect = base;                                       /* the field the key owns, taken from `want` */
        const uint8_t *w = (const uint8_t *)&want; uint8_t *e = (uint8_t *)&expect;
        for (size_t k = 0; k < sizeof one; k++) if (((uint8_t *)&one)[k] != ((uint8_t *)&base)[k]) e[k] = w[k];
        assert(same(&one, &expect));
    }
    PASS("every key sets its own field and nothing else, in either order");
}

static void test_bad_values(void) {
    static const char *const bad[] = {
        /* integers: empty, signs, text, trailing junk, other bases, overflow, out of range */
        "worker_count =", "worker_count = abc", "worker_count = 4x", "worker_count = 4 5", "worker_count = 0x10", "worker_count = 1e2",
        "worker_count = 4.0", "worker_count = --4", "worker_count = +", "worker_count = -1", "worker_count = 0", "worker_count = 1025",
        "worker_count = 99999999999999999999", "capture_vm_count = -1", "capture_vm_count = 1025", "arena_size_mb = -256",
        "arena_size_mb = 0", "arena_size_mb = 65537", "arena_size_mb =", "log_level = 6", "log_level = -1", "log_level = info",
        /* booleans */
        "log_json = 2", "log_json = maybe", "log_json =", "log_json = tru",
        /* floats: empty, text, non-finite, hex, out of range, trailing junk, no digits */
        "api_confidence_min =", "api_confidence_min = nan", "api_confidence_min = inf", "api_confidence_min = 0x1p-1",
        "api_confidence_min = 1.5", "api_confidence_min = -0.1", "api_confidence_min = 0.5.5", "api_confidence_min = .",
        "api_confidence_min = 1e", "api_confidence_min = 0,5", "dna_similarity_thresh = 1e400", "dna_similarity_thresh = abc",
        "dna_similarity_thresh = 0.9f",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char text[128];
        snprintf(text, sizeof text, "# first line\n%s\n", bad[i]);
        expect_refused(text, CBAE_ERR_PARSE, ":2:");
    }
    printf("  [PASS] %zu bad numbers, booleans and floats refused, with the line number\n", sizeof bad / sizeof bad[0]);
}

static void test_structure_errors(void) {
    expect_refused("worker_count = 3\nunknown_key = 1\n", CBAE_ERR_PARSE, ":2: unknown key 'unknown_key'");
    expect_refused("db_pat = /x\n", CBAE_ERR_PARSE, ":1: unknown key 'db_pat'");                    /* a prefix of a key is not the key */
    expect_refused("db_path_extra = /x\n", CBAE_ERR_PARSE, ":1: unknown key");                      /* nor is an extension */
    expect_refused("DB_PATH = /x\n", CBAE_ERR_PARSE, ":1: unknown key");                            /* case-sensitive */
    expect_refused("\n\nthis line has no equals sign\n", CBAE_ERR_PARSE, ":3: expected 'key = value'");
    expect_refused("= value\n", CBAE_ERR_PARSE, ":1: empty key");
    expect_refused("   = value\n", CBAE_ERR_PARSE, ":1: empty key");
    expect_refused("\xEF\xBB worker_count = 3\n", CBAE_ERR_PARSE, ":1:");                           /* half a byte order mark is not swallowed */
    expect_refused("\xEF\xBB\xBF\xEF\xBB\xBF" "worker_count = 3\n", CBAE_ERR_PARSE, ":1:");        /* only one is skipped */
    expect_refused("worker_count = 3\n" "\x01" "garbage\n", CBAE_ERR_PARSE, ":2:");
    PASS("unknown keys, prefixes, case, stray lines, empty keys, partial byte order mark");
}

static void test_never_half_applied(void) {
    cbae_config_t c;
    memset(&c, 0, sizeof c);
    assert(load_text("worker_count = 9\ndb_path = /mine\nlog_level = 4\nlog_level = loud\n", &c) == CBAE_ERR_PARSE);
    expect_defaults(&c);                                                                              /* not worker_count 9, not /mine */
    PASS("an error in line 4 leaves none of lines 1 to 3 applied");
}

static void test_string_limits(void) {
    char text[1200], v[600];
    cbae_config_t c;
    memset(v, 'p', sizeof v);
    v[511] = '\0';
    snprintf(text, sizeof text, "db_path = %s\n", v);
    assert(load_text(text, &c) == CBAE_OK && strlen(c.db_path) == 511 && c.db_path[510] == 'p');                  /* the longest that fits */
    v[512] = '\0'; v[511] = 'p';
    snprintf(text, sizeof text, "db_path = %s\n", v);
    expect_refused(text, CBAE_ERR_PARSE, ":1: value of 'db_path' is too long");                                     /* one more byte: refused, not cut */
    snprintf(text, sizeof text, "log_path = %s\n", v);
    expect_refused(text, CBAE_ERR_PARSE, "log_path");
    snprintf(text, sizeof text, "api_db_path = %s\n", v);
    expect_refused(text, CBAE_ERR_PARSE, "api_db_path");
    PASS("a 511-byte string fits; 512 bytes is refused rather than cut");
}

static void test_file_level_errors(void) {
    cbae_config_t c;
    memset(&c, 0xAB, sizeof c);
    assert(cbae_config_load("/nonexistent_dir_for_cbae/none.conf", &c) == CBAE_ERR_NOT_FOUND);
    expect_defaults(&c);
    assert(strstr(cbae_last_error(), "/nonexistent_dir_for_cbae/none.conf"));
    memset(&c, 0xAB, sizeof c);
    assert(cbae_config_load("/tmp", &c) == CBAE_ERR_IO);                                              /* a directory */
    expect_defaults(&c);
    assert(cbae_config_load(NULL, &c) == CBAE_ERR_INVALID);
    assert(cbae_config_load(CBAE_SHIPPED_CONFIG, NULL) == CBAE_ERR_INVALID);
    /* NUL byte: the line number is where it is */
    const char withnul[] = "worker_count = 3\nlog_level = 1\n\0worker_count = 4\n";
    memset(&c, 0xAB, sizeof c);
    assert(load_bytes(withnul, sizeof withnul - 1, &c) == CBAE_ERR_PARSE && strstr(cbae_last_error(), ":3: NUL byte"));
    expect_defaults(&c);
    /* size: exactly 64 KiB is read, one byte more is refused */
    static char big[65538];
    memset(big, ' ', 65536);
    big[65535] = '\n';
    assert(load_bytes(big, 65536, &c) == CBAE_OK);
    expect_defaults(&c);
    memset(big, ' ', 65537);
    big[65536] = '\n';
    assert(load_bytes(big, 65537, &c) == CBAE_ERR_PARSE && strstr(cbae_last_error(), "larger than 65536 bytes"));
    expect_defaults(&c);
    PASS("missing file, directory, NULL arguments, NUL byte, size limit");
}

static void test_engine(void) {
    cbae_engine_t *e = (cbae_engine_t *)1;
    assert(cbae_engine_init("/nonexistent_dir_for_cbae/none.conf", &e) == CBAE_ERR_NOT_FOUND && e == NULL);   /* a bad path is an error, not defaults */
    assert(cbae_engine_init(NULL, NULL) == CBAE_ERR_INVALID);
    char conf[64], db[80], text[400];
    snprintf(conf, sizeof conf, "/tmp/cbae_test_engine_XXXXXX");
    int fd = mkstemp(conf); assert(fd >= 0); close(fd);
    snprintf(db, sizeof db, "%s.db", conf);
    snprintf(text, sizeof text, "db_path = %s\nlog_level = 5\nworker_count = 3\n", db);
    FILE *f = fopen(conf, "w"); assert(f); fputs(text, f); fclose(f);
    assert(cbae_engine_init(conf, &e) == CBAE_OK && e);
    assert(cbae_engine_config(e)->worker_count == 3 && strcmp(cbae_engine_config(e)->db_path, db) == 0);
    cbae_engine_shutdown(e);
    f = fopen(conf, "w"); assert(f); fputs("worker_count = many\n", f); fclose(f);
    e = (cbae_engine_t *)1;
    assert(cbae_engine_init(conf, &e) == CBAE_ERR_PARSE && e == NULL);
    unlink(conf);
    char wal[96];
    unlink(db); snprintf(wal, sizeof wal, "%s-wal", db); unlink(wal); snprintf(wal, sizeof wal, "%s-shm", db); unlink(wal);
    PASS("the engine starts from a good file, refuses a missing or malformed one");
}

int main(void) {
    printf("=== test_config ===\n");
    test_defaults();
    test_shipped_config();
    test_format();
    test_each_key_only_its_field();
    test_bad_values();
    test_structure_errors();
    test_never_half_applied();
    test_string_limits();
    test_file_level_errors();
    test_engine();
    printf("All config tests passed.\n");
    return 0;
}
