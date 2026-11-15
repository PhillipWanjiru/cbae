/**
 * @file cbae_config.c
 * @brief Strict parser for cbae.conf (key = value lines) into cbae_config_t.
 *
 * The file format
 *   - one `key = value` per line; whitespace around key and value is ignored
 *   - `#` starts a comment anywhere on a line, so a value cannot contain `#`
 *   - blank and comment-only lines are skipped; LF and CRLF line ends; the last line needs no newline;
 *     a UTF-8 byte order mark at the very start of the file is skipped
 *   - keys are exact and case-sensitive; a key given twice takes its last value
 *   - strings (db_path, log_path, api_db_path) may be empty and must fit their field; they are never cut
 *   - numbers are decimal and must fill the whole value and lie in the range of their key; booleans are
 *     0/1/true/false/yes/no/on/off (any case); the two thresholds are decimal numbers from 0 to 1
 *
 * Everything else is an error that names the file and the line: an unknown key, a line that is not
 * `key = value`, an empty key, a value that does not fit, a NUL byte, a file over 64 KiB. The old
 * parser skipped such lines or read garbage as 0 (`atoi("abc")`), so a typo in a configuration file
 * changed the behaviour of an analysis run without a word.
 *
 * On any error *cfg is the defaults, never a half-applied file.
 */
#include "cbae/cbae_engine.h"
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define CONFIG_MAX_BYTES 65536u

void cbae_config_defaults(cbae_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->db_path, sizeof cfg->db_path, "%s", "/var/lib/cbae/analysis.db");
    cfg->worker_count          = 4;
    cfg->capture_vm_count      = 2;
    cfg->arena_size_mb         = 256;
    cfg->log_level             = 2;
    cfg->log_json              = false;
    cfg->api_confidence_min    = 0.75f;
    cfg->dna_similarity_thresh = 0.90f;
}

typedef enum { K_STR, K_INT, K_SIZE_MB, K_BOOL, K_FLOAT } key_kind_t;

typedef struct {
    const char *name;
    key_kind_t  kind;
    size_t      offset;     /* of the field in cbae_config_t */
    size_t      size;       /* K_STR: bytes in the field including the NUL */
    long        lo, hi;     /* K_INT, K_SIZE_MB */
} config_key_t;

#define KEY_STR(n, f)           { n, K_STR,     offsetof(cbae_config_t, f), sizeof(((cbae_config_t *)0)->f), 0, 0 }
#define KEY_INT(n, f, lo, hi)   { n, K_INT,     offsetof(cbae_config_t, f), 0, lo, hi }
#define KEY_SIZE(n, f, lo, hi)  { n, K_SIZE_MB, offsetof(cbae_config_t, f), 0, lo, hi }
#define KEY_BOOL(n, f)          { n, K_BOOL,    offsetof(cbae_config_t, f), 0, 0, 0 }
#define KEY_UNIT(n, f)          { n, K_FLOAT,   offsetof(cbae_config_t, f), 0, 0, 0 }

/* worker_count, capture_vm_count and arena_size_mb are read by later phases (the batch daemon, the
 * capture VMs, the analysis arenas); they are parsed and range-checked here so a bad value is refused
 * now rather than when that phase starts. */
static const config_key_t KEYS[] = {
    KEY_STR ("db_path",               db_path),
    KEY_STR ("log_path",              log_path),
    KEY_STR ("api_db_path",           api_db_path),
    KEY_INT ("worker_count",          worker_count,     1, 1024),
    KEY_INT ("capture_vm_count",      capture_vm_count, 0, 1024),
    KEY_SIZE("arena_size_mb",         arena_size_mb,    1, 65536),
    KEY_INT ("log_level",             log_level,        0, 5),
    KEY_BOOL("log_json",              log_json),
    KEY_UNIT("api_confidence_min",    api_confidence_min),
    KEY_UNIT("dna_similarity_thresh", dna_similarity_thresh),
};

static bool parse_int(const char *s, long lo, long hi, long *out) {
    const char *p = s;
    if (*p == '+' || *p == '-') p++;
    if (!isdigit((unsigned char)*p)) return false;
    for (const char *q = p; *q; q++) if (!isdigit((unsigned char)*q)) return false;
    errno = 0;
    char *end;
    const long v = strtol(s, &end, 10);
    if (errno == ERANGE || *end != '\0' || v < lo || v > hi) return false;
    *out = v;
    return true;
}

static bool parse_bool(const char *s, bool *out) {
    static const char *const yes[] = { "1", "true", "yes", "on" };
    static const char *const no[]  = { "0", "false", "no", "off" };
    for (size_t i = 0; i < 4; i++) {
        if (strcasecmp(s, yes[i]) == 0) { *out = true;  return true; }
        if (strcasecmp(s, no[i])  == 0) { *out = false; return true; }
    }
    return false;
}

/* [+-]digits[.digits][e[+-]digits] or .digits, whole value, finite, from 0 to 1. strtod alone would also
 * take "nan", "inf", "0x1p-1" and leading garbage-free forms nobody means in a configuration file. */
static bool parse_unit_float(const char *s, float *out) {
    const char *p = s;
    if (*p == '+' || *p == '-') p++;
    size_t digits = 0;
    while (isdigit((unsigned char)*p)) { p++; digits++; }
    if (*p == '.') { p++; while (isdigit((unsigned char)*p)) { p++; digits++; } }
    if (digits == 0) return false;
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!isdigit((unsigned char)*p)) return false;
        while (isdigit((unsigned char)*p)) p++;
    }
    if (*p != '\0') return false;
    errno = 0;
    char *end;
    const double v = strtod(s, &end);
    if (errno == ERANGE || end != p || !isfinite(v) || v < 0.0 || v > 1.0) return false;
    *out = (float)v;
    return true;
}

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = '\0';
    return s;
}

/* Applies one key = value to cfg. On failure returns the reason (static text or *why filled). */
static const char *apply(cbae_config_t *cfg, const char *key, const char *val, char *why, size_t why_len) {
    const config_key_t *k = NULL;
    for (size_t i = 0; i < sizeof KEYS / sizeof KEYS[0]; i++)
        if (strcmp(KEYS[i].name, key) == 0) { k = &KEYS[i]; break; }
    if (!k) { snprintf(why, why_len, "unknown key '%.40s'", key); return why; }
    uint8_t *field = (uint8_t *)cfg + k->offset;
    switch (k->kind) {
    case K_STR:
        if (strlen(val) >= k->size) {
            snprintf(why, why_len, "value of '%s' is too long (%zu bytes, at most %zu)", k->name, strlen(val), k->size - 1);
            return why;
        }
        memcpy(field, val, strlen(val) + 1);
        return NULL;
    case K_INT: {
        long v;
        if (!parse_int(val, k->lo, k->hi, &v)) {
            snprintf(why, why_len, "'%s' needs a whole number from %ld to %ld, not '%.40s'", k->name, k->lo, k->hi, val);
            return why;
        }
        const int iv = (int)v;
        memcpy(field, &iv, sizeof iv);
        return NULL;
    }
    case K_SIZE_MB: {
        long v;
        if (!parse_int(val, k->lo, k->hi, &v)) {
            snprintf(why, why_len, "'%s' needs a whole number from %ld to %ld, not '%.40s'", k->name, k->lo, k->hi, val);
            return why;
        }
        const size_t sv = (size_t)v;
        memcpy(field, &sv, sizeof sv);
        return NULL;
    }
    case K_BOOL: {
        bool b;
        if (!parse_bool(val, &b)) {
            snprintf(why, why_len, "'%s' needs 0, 1, true, false, yes, no, on or off, not '%.40s'", k->name, val);
            return why;
        }
        memcpy(field, &b, sizeof b);
        return NULL;
    }
    case K_FLOAT: {
        float f;
        if (!parse_unit_float(val, &f)) {
            snprintf(why, why_len, "'%s' needs a decimal number from 0 to 1, not '%.40s'", k->name, val);
            return why;
        }
        memcpy(field, &f, sizeof f);
        return NULL;
    }
    }
    return "internal error";
}

cbae_err_t cbae_config_load(const char *path, cbae_config_t *cfg) {
    if (!cfg) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "config: cfg is NULL");
    cbae_config_defaults(cfg);
    if (!path) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "config: path is NULL");

    FILE *f = fopen(path, "rb");
    if (!f) {
        const int e = errno;
        if (e == ENOENT) CBAE_RETURN_ERR(CBAE_ERR_NOT_FOUND, "config file '%.200s' does not exist", path);
        CBAE_RETURN_ERR(CBAE_ERR_IO, "cannot open config file '%.200s': %s", path, strerror(e));
    }
    char *buf = malloc((size_t)CONFIG_MAX_BYTES + 1);
    if (!buf) { fclose(f); CBAE_RETURN_ERR(CBAE_ERR_OOM, "config: cannot allocate the read buffer"); }
    const size_t n = fread(buf, 1, (size_t)CONFIG_MAX_BYTES + 1, f);
    const bool read_failed = ferror(f) != 0;
    fclose(f);
    if (read_failed) { free(buf); CBAE_RETURN_ERR(CBAE_ERR_IO, "cannot read config file '%.200s'", path); }
    if (n > CONFIG_MAX_BYTES) { free(buf); CBAE_RETURN_ERR(CBAE_ERR_PARSE, "%.200s: larger than %u bytes", path, CONFIG_MAX_BYTES); }
    buf[n] = '\0';
    const char *nul = memchr(buf, '\0', n);
    if (nul) {
        size_t line = 1;
        for (const char *q = buf; q < nul; q++) if (*q == '\n') line++;
        free(buf);
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "%.200s:%zu: NUL byte in the file", path, line);
    }

    cbae_config_t tmp;
    cbae_config_defaults(&tmp);
    char *p = buf;
    if ((unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF) p += 3;

    size_t lineno = 0;
    cbae_err_t rc = CBAE_OK;
    while (*p) {
        lineno++;
        char *nl = strchr(p, '\n');
        char *next = nl ? nl + 1 : p + strlen(p);
        if (nl) *nl = '\0';
        char *hash = strchr(p, '#');
        if (hash) *hash = '\0';
        char *line = trim(p);                       /* also drops the \r of a CRLF line end */
        p = next;
        if (!*line) continue;
        char *eq = strchr(line, '=');
        char why[CBAE_ERR_MSG_MAX];
        const char *reason = NULL;
        if (!eq) { snprintf(why, sizeof why, "expected 'key = value', found '%.40s'", line); reason = why; }
        else {
            *eq = '\0';
            char *key = trim(line), *val = trim(eq + 1);
            if (!*key) reason = "empty key before '='";
            else reason = apply(&tmp, key, val, why, sizeof why);
        }
        if (reason) {
            CBAE_SET_ERR(CBAE_ERR_PARSE, "%.120s:%zu: %s", path, lineno, reason);
            rc = CBAE_ERR_PARSE;
            break;
        }
    }
    free(buf);
    if (rc == CBAE_OK) *cfg = tmp;
    return rc;
}
