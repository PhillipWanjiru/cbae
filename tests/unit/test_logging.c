/**
 * @file test_logging.c
 * @brief Unit tests for the logger (audit A-042): the line format in both modes, the levels, the UTC time stamp,
 *        hostile text (names taken from the binary under analysis) that must not forge a line, break the JSON or
 *        drive a terminal, the choice and replacement of the sink, and use from many threads at once.
 *
 * Every expectation is computed by code in this file that shares nothing with the logger: a table-driven UTF-8
 * validator (Table 3-7 of the Unicode standard) and a strict RFC 8259 reader for the JSON lines.
 */
#define _GNU_SOURCE
#include "platform/logging.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#define PASS(name) printf("  [PASS] %s\n", name)
#define QUICK (getenv("CBAE_TEST_QUICK") != NULL)

/* ================================================================ files and descriptors */

static char g_dir[64];

static void make_dir(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/cbae_log_XXXXXX");
    assert(mkdtemp(g_dir) != NULL);
}
static void path_of(char *out, size_t cap, const char *name) { snprintf(out, cap, "%s/%s", g_dir, name); }
static void remove_dir(void) {
    DIR *d = opendir(g_dir);
    assert(d);
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char p[sizeof g_dir + 256];                 /* the longest directory name, a '/', the longest entry name, a NUL */
        path_of(p, sizeof p, e->d_name);
        unlink(p);
    }
    closedir(d);
    rmdir(g_dir);
}

static int count_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    assert(d);
    int n = 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

typedef struct { const char *p; size_t n; } span_t;
typedef struct { char *data; size_t size; span_t *line; size_t count; } logfile_t;

/* The lines of a file. It is empty or ends in a newline, and a newline ends a line: a message cannot make more
 * lines than were logged. */
static logfile_t read_log(const char *path) {
    logfile_t f = { NULL, 0, NULL, 0 };
    FILE *fp = fopen(path, "rb");
    assert(fp);
    assert(fseek(fp, 0, SEEK_END) == 0);
    const long sz = ftell(fp);
    assert(sz >= 0);
    rewind(fp);
    f.data = malloc((size_t)sz + 1);
    assert(f.data && fread(f.data, 1, (size_t)sz, fp) == (size_t)sz);
    fclose(fp);
    f.data[sz] = '\0';
    f.size = (size_t)sz;
    if (f.size) assert(f.data[f.size - 1] == '\n');
    size_t cap = 1;
    for (size_t i = 0; i < f.size; i++) if (f.data[i] == '\n') cap++;
    f.line = calloc(cap, sizeof *f.line);
    assert(f.line);
    size_t start = 0;
    for (size_t i = 0; i < f.size; i++)
        if (f.data[i] == '\n') { f.line[f.count].p = f.data + start; f.line[f.count].n = i - start; f.count++; start = i + 1; }
    return f;
}
static void free_log(logfile_t *f) { free(f->data); free(f->line); memset(f, 0, sizeof *f); }

static bool span_has(span_t l, const char *needle) { return memmem(l.p, l.n, needle, strlen(needle)) != NULL; }

static int g_saved_stderr = -1;
static void stderr_to(const char *path) {
    fflush(stderr);
    g_saved_stderr = dup(2);
    assert(g_saved_stderr >= 0);
    const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0 && dup2(fd, 2) == 2);
    close(fd);
}
static void stderr_back(void) {
    fflush(stderr);
    assert(dup2(g_saved_stderr, 2) == 2);
    close(g_saved_stderr);
    g_saved_stderr = -1;
}

/* cbae_log_write_v with a format that is not a literal (so that NULL can be passed and no warning is raised). */
static void logv(cbae_log_level_t lv, const char *file, int line, const char *func, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cbae_log_write_v(lv, file, line, func, fmt, ap);
    va_end(ap);
}

/* ================================================================ oracles */

/* Length of the well-formed UTF-8 sequence at s (n bytes left), 0 if none starts there. */
static size_t wf_len(const unsigned char *s, size_t n) {
    static const struct { unsigned char lo, hi, b2lo, b2hi, len; } T[] = {
        { 0x00, 0x7F, 0x00, 0xFF, 1 }, { 0xC2, 0xDF, 0x80, 0xBF, 2 }, { 0xE0, 0xE0, 0xA0, 0xBF, 3 },
        { 0xE1, 0xEC, 0x80, 0xBF, 3 }, { 0xED, 0xED, 0x80, 0x9F, 3 }, { 0xEE, 0xEF, 0x80, 0xBF, 3 },
        { 0xF0, 0xF0, 0x90, 0xBF, 4 }, { 0xF1, 0xF3, 0x80, 0xBF, 4 }, { 0xF4, 0xF4, 0x80, 0x8F, 4 },
    };
    for (size_t t = 0; t < sizeof T / sizeof T[0]; t++) {
        if (s[0] < T[t].lo || s[0] > T[t].hi) continue;
        const size_t len = T[t].len;
        if (len > n) return 0;
        if (len > 1 && (s[1] < T[t].b2lo || s[1] > T[t].b2hi)) return 0;
        for (size_t k = 2; k < len; k++) if (s[k] < 0x80 || s[k] > 0xBF) return 0;
        return len;
    }
    return 0;
}

/* The multi-byte sequences that are written as \uXXXX: U+0080..U+009F, U+2028..U+202E, U+2066..U+2069. Their
 * code point, or 0 for any other sequence. */
static unsigned special_cp(const unsigned char *s, size_t len) {
    if (len == 2 && s[0] == 0xC2 && s[1] >= 0x80 && s[1] <= 0x9F) return s[1];
    if (len == 3 && s[0] == 0xE2 && s[1] == 0x80 && s[2] >= 0xA8 && s[2] <= 0xAE) return 0x2000u + (s[2] - 0x80u);
    if (len == 3 && s[0] == 0xE2 && s[1] == 0x81 && s[2] >= 0xA6 && s[2] <= 0xA9) return 0x2040u + (s[2] - 0x80u);
    return 0;
}

/* Everything a log line may contain: printable ASCII and well-formed UTF-8 that is not one of the special sequences. */
static bool line_is_clean(span_t l) {
    const unsigned char *s = (const unsigned char *)l.p;
    for (size_t i = 0; i < l.n;) {
        if (s[i] >= 0x20 && s[i] < 0x7F) { i++; continue; }
        const size_t len = wf_len(s + i, l.n - i);
        if (len < 2 || special_cp(s + i, len)) return false;
        i += len;
    }
    return true;
}

/* @p raw (n bytes) as text mode must write it; @p out has room for 6 * n + 1 bytes. */
static size_t esc_text(char *out, const char *raw, size_t n) {
    const unsigned char *s = (const unsigned char *)raw;
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        const size_t len = wf_len(s + i, n - i);
        if (len > 1) {
            const unsigned cp = special_cp(s + i, len);
            if (cp) o += (size_t)sprintf(out + o, "\\u%04x", cp);
            else { memcpy(out + o, s + i, len); o += len; }
            i += len;
            continue;
        }
        const unsigned c = s[i++];
        if (len == 0 || c < 0x20 || c == 0x7F) o += (size_t)sprintf(out + o, "\\x%02x", c);
        else if (c == '\\') { out[o++] = '\\'; out[o++] = '\\'; }
        else out[o++] = (char)c;
    }
    out[o] = '\0';
    return o;
}

/* What a JSON reader must get back for @p raw: the same bytes, each byte that is not UTF-8 replaced by U+FFFD. */
static size_t json_value(char *out, const char *raw, size_t n) {
    const unsigned char *s = (const unsigned char *)raw;
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        const size_t len = wf_len(s + i, n - i);
        if (len == 0) { memcpy(out + o, "\xEF\xBF\xBD", 3); o += 3; i++; }
        else { memcpy(out + o, s + i, len); o += len; i += len; }
    }
    out[o] = '\0';
    return o;
}

static time_t now_utc(void) {                                  /* the clock the logger reads, not the coarse one behind time() */
    struct timespec t;
    assert(clock_gettime(CLOCK_REALTIME, &t) == 0);
    return t.tv_sec;
}

static size_t cut(const char *s, size_t max) { const size_t n = strlen(s); return n < max ? n : max; }

/* ---- a strict reader for one JSON line: {"ts":S,"level":S,"file":S,"line":N,"func":S,"msg":S} ---- */

typedef struct { const char *s; size_t n, pos; } jp_t;
typedef struct { char *v; size_t n; } jstr_t;
typedef struct { jstr_t ts, level, file, func, msg; long line; } jrec_t;

static bool jp_lit(jp_t *j, char c) {
    if (j->pos < j->n && j->s[j->pos] == c) { j->pos++; return true; }
    return false;
}

/* A JSON string (RFC 8259): no raw control character, the defined escapes only, valid UTF-8, no lone surrogate. */
static bool jp_string(jp_t *j, jstr_t *out) {
    if (!jp_lit(j, '"')) return false;
    char *buf = malloc(j->n + 1);
    assert(buf);
    size_t o = 0;
    for (;;) {
        if (j->pos >= j->n) goto bad;
        const unsigned char c = (unsigned char)j->s[j->pos];
        if (c == '"') { j->pos++; break; }
        if (c < 0x20) goto bad;
        if (c == '\\') {
            if (++j->pos >= j->n) goto bad;
            const char e = j->s[j->pos++];
            switch (e) {
                case '"':  buf[o++] = '"';  break;
                case '\\': buf[o++] = '\\'; break;
                case '/':  buf[o++] = '/';  break;
                case 'b':  buf[o++] = '\b'; break;
                case 'f':  buf[o++] = '\f'; break;
                case 'n':  buf[o++] = '\n'; break;
                case 'r':  buf[o++] = '\r'; break;
                case 't':  buf[o++] = '\t'; break;
                case 'u': {
                    if (j->pos + 4 > j->n) goto bad;
                    unsigned v = 0;
                    for (int k = 0; k < 4; k++) {
                        const char h = j->s[j->pos++];
                        if (h >= '0' && h <= '9') v = v * 16 + (unsigned)(h - '0');
                        else if (h >= 'a' && h <= 'f') v = v * 16 + (unsigned)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') v = v * 16 + (unsigned)(h - 'A' + 10);
                        else goto bad;
                    }
                    if (v >= 0xD800 && v <= 0xDFFF) goto bad;
                    if (v < 0x80) buf[o++] = (char)v;
                    else if (v < 0x800) { buf[o++] = (char)(0xC0 | (v >> 6)); buf[o++] = (char)(0x80 | (v & 0x3F)); }
                    else { buf[o++] = (char)(0xE0 | (v >> 12)); buf[o++] = (char)(0x80 | ((v >> 6) & 0x3F)); buf[o++] = (char)(0x80 | (v & 0x3F)); }
                    break;
                }
                default: goto bad;
            }
            continue;
        }
        const size_t len = wf_len((const unsigned char *)j->s + j->pos, j->n - j->pos);
        if (len == 0) goto bad;
        memcpy(buf + o, j->s + j->pos, len);
        o += len;
        j->pos += len;
    }
    buf[o] = '\0';
    out->v = buf;
    out->n = o;
    return true;
bad:
    free(buf);
    return false;
}

static bool jp_int(jp_t *j, long *out) {
    const size_t start = j->pos;
    if (jp_lit(j, '-')) {}
    const size_t digits = j->pos;
    while (j->pos < j->n && j->s[j->pos] >= '0' && j->s[j->pos] <= '9') j->pos++;
    if (j->pos == digits) return false;
    if (j->s[digits] == '0' && j->pos - digits > 1) return false;               /* no leading zero */
    *out = strtol(j->s + start, NULL, 10);
    return true;
}

static void free_rec(jrec_t *r) { free(r->ts.v); free(r->level.v); free(r->file.v); free(r->func.v); free(r->msg.v); memset(r, 0, sizeof *r); }

static bool parse_record(span_t l, jrec_t *r) {
    static const char *const KEYS[6] = { "ts", "level", "file", "line", "func", "msg" };
    jp_t j = { l.p, l.n, 0 };
    memset(r, 0, sizeof *r);
    if (!jp_lit(&j, '{')) return false;
    for (int k = 0; k < 6; k++) {
        if (k && !jp_lit(&j, ',')) goto bad;
        jstr_t key;
        if (!jp_string(&j, &key)) goto bad;
        const bool match = strcmp(key.v, KEYS[k]) == 0;
        free(key.v);
        if (!match || !jp_lit(&j, ':')) goto bad;
        bool ok;
        switch (k) {
            case 0:  ok = jp_string(&j, &r->ts);    break;
            case 1:  ok = jp_string(&j, &r->level); break;
            case 2:  ok = jp_string(&j, &r->file);  break;
            case 3:  ok = jp_int(&j, &r->line);     break;
            case 4:  ok = jp_string(&j, &r->func);  break;
            default: ok = jp_string(&j, &r->msg);   break;
        }
        if (!ok) goto bad;
    }
    if (!jp_lit(&j, '}') || j.pos != l.n) goto bad;
    return true;
bad:
    free_rec(r);
    return false;
}

/* ---- the frame of a line ---- */

/* "YYYY-MM-DDTHH:MM:SS.mmmZ", a UTC time between lo and hi (seconds). */
static void check_ts(const char *ts, time_t lo, time_t hi) {
    assert(strlen(ts) == 24);
    for (int i = 0; i < 24; i++) {
        const char c = ts[i];
        if (i == 4 || i == 7) assert(c == '-');
        else if (i == 10) assert(c == 'T');
        else if (i == 13 || i == 16) assert(c == ':');
        else if (i == 19) assert(c == '.');
        else if (i == 23) assert(c == 'Z');
        else assert(c >= '0' && c <= '9');
    }
    struct tm tm;
    memset(&tm, 0, sizeof tm);
    assert(sscanf(ts, "%4d-%2d-%2dT%2d:%2d:%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6);
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    const time_t t = timegm(&tm);
    assert(t >= lo && t <= hi);
}

/* The line is "[ts] LEVEL  file:line (func)  msg", with file, func and msg escaped and cut. */
static void check_text(span_t l, const char *level, const char *file, int line, const char *func, const char *msg,
                       time_t lo, time_t hi) {
    assert(line_is_clean(l));
    assert(l.n > 27 && l.p[0] == '[' && l.p[25] == ']' && l.p[26] == ' ');
    char ts[25];
    memcpy(ts, l.p + 1, 24);
    ts[24] = '\0';
    check_ts(ts, lo, hi);
    const size_t fn = cut(file, 255), un = cut(func, 255), mn = cut(msg, CBAE_LOG_MSG_MAX - 1);
    char *want = malloc(6 * (fn + un + mn) + 64);
    assert(want);
    size_t n = (size_t)sprintf(want, "%s  ", level);
    n += esc_text(want + n, file, fn);
    n += (size_t)sprintf(want + n, ":%d (", line);
    n += esc_text(want + n, func, un);
    n += (size_t)sprintf(want + n, ")  ");
    n += esc_text(want + n, msg, mn);
    if (l.n - 27 != n || memcmp(l.p + 27, want, n) != 0) {
        fprintf(stderr, "text line differs\n  got : %.*s\n  want: %s\n", (int)l.n, l.p, want);
        assert(!"text line differs");
    }
    free(want);
}

static void check_json(span_t l, const char *level, const char *file, int line, const char *func, const char *msg,
                       time_t lo, time_t hi) {
    assert(line_is_clean(l));
    jrec_t r;
    if (!parse_record(l, &r)) { fprintf(stderr, "not a JSON line: %.*s\n", (int)l.n, l.p); assert(!"not a JSON line"); }
    check_ts(r.ts.v, lo, hi);
    assert(strcmp(r.level.v, level) == 0);
    assert(r.line == line);
    const struct { const jstr_t *got; const char *raw; size_t max; } F[3] = {
        { &r.file, file, 255 }, { &r.func, func, 255 }, { &r.msg, msg, CBAE_LOG_MSG_MAX - 1 },
    };
    for (int i = 0; i < 3; i++) {
        const size_t rn = cut(F[i].raw, F[i].max);
        char *want = malloc(3 * rn + 1);
        assert(want);
        const size_t wn = json_value(want, F[i].raw, rn);
        assert(F[i].got->n == wn && memcmp(F[i].got->v, want, wn) == 0);
        free(want);
    }
    free_rec(&r);
}

/* Logs one message at INFO into a fresh file in the given mode and checks the single line that results. */
static void log_one_and_check(const char *file, int line, const char *func, const char *msg, bool json) {
    char path[160];
    path_of(path, sizeof path, "one.log");
    unlink(path);
    const time_t lo = now_utc();
    cbae_log_init(CBAE_LOG_TRACE, path, json);
    cbae_log_write(CBAE_LOG_INFO, file, line, func, "%s", msg);
    cbae_log_shutdown();
    const time_t hi = now_utc();
    logfile_t f = read_log(path);
    assert(f.count == 1);
    if (json) check_json(f.line[0], "INFO", file, line, func, msg, lo, hi);
    else      check_text(f.line[0], "INFO", file, line, func, msg, lo, hi);
    free_log(&f);
}

/* ================================================================ tests */

static void test_silent_until_init_and_after_shutdown(void) {
    char err[160], path[160];
    path_of(err, sizeof err, "stderr.txt");
    path_of(path, sizeof path, "silent.log");
    unlink(path);

    stderr_to(err);
    cbae_log_shutdown();                                       /* before any init: nothing to do */
    LOG_ERROR("before init");
    cbae_log_init(CBAE_LOG_INFO, path, 0);
    LOG_INFO("one");
    logfile_t live = read_log(path);                           /* before shutdown: every line is flushed as it is written */
    assert(live.count == 1);
    free_log(&live);
    cbae_log_shutdown();
    LOG_ERROR("after shutdown");
    cbae_log_shutdown();                                       /* twice */
    LOG_ERROR("after the second shutdown");
    stderr_back();

    logfile_t f = read_log(path);
    assert(f.count == 1 && span_has(f.line[0], "  one"));
    free_log(&f);
    f = read_log(err);
    assert(f.size == 0);                                       /* nothing went to stderr either */
    free_log(&f);
    PASS("nothing is written before cbae_log_init or after cbae_log_shutdown; shutdown twice is harmless");
}

static void test_levels(void) {
    char path[160];
    path_of(path, sizeof path, "levels.log");
    static const char *const NAME[5] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR" };
    for (int min = -1; min <= CBAE_LOG_NONE; min++) {              /* -1: a minimum below TRACE admits every real level */
        const int first = min < 0 ? 0 : min;
        unlink(path);
        const time_t lo = now_utc();
        cbae_log_init((cbae_log_level_t)min, path, 0);
        for (int lv = 0; lv < 5; lv++) cbae_log_write((cbae_log_level_t)lv, "f.c", 7, "fn", "m%d", lv);
        cbae_log_write(CBAE_LOG_NONE, "f.c", 7, "fn", "level none");          /* never a message level */
        cbae_log_write((cbae_log_level_t)-1, "f.c", 7, "fn", "level -1");
        cbae_log_write((cbae_log_level_t)99, "f.c", 7, "fn", "level 99");
        cbae_log_shutdown();
        const time_t hi = now_utc();
        logfile_t f = read_log(path);
        assert(f.count == (size_t)(5 - first));
        for (size_t k = 0; k < f.count; k++) {
            const int lv = first + (int)k;
            char m[8];
            snprintf(m, sizeof m, "m%d", lv);
            check_text(f.line[k], NAME[lv], "f.c", 7, "fn", m, lo, hi);
        }
        free_log(&f);
    }
    PASS("only messages at or above the minimum level are written; NONE and out-of-range levels never are");
}

static void test_frames_and_macros(void) {
    char path[160];
    path_of(path, sizeof path, "frames.log");

    /* explicit arguments, both modes */
    for (int json = 0; json < 2; json++) {
        unlink(path);
        const time_t lo = now_utc();
        cbae_log_init(CBAE_LOG_TRACE, path, json);
        cbae_log_write(CBAE_LOG_WARN, "dir/file.c", 123, "my_func", "hello %d %s %c %.2f 100%%", 42, "world", 'x', 2.5);
        cbae_log_shutdown();
        const time_t hi = now_utc();
        logfile_t f = read_log(path);
        assert(f.count == 1);
        if (json) check_json(f.line[0], "WARN", "dir/file.c", 123, "my_func", "hello 42 world x 2.50 100%", lo, hi);
        else      check_text(f.line[0], "WARN", "dir/file.c", 123, "my_func", "hello 42 world x 2.50 100%", lo, hi);
        free_log(&f);
    }

    /* the macros pass the file, line and function of the call, with and without arguments */
    unlink(path);
    const time_t lo = now_utc();
    cbae_log_init(CBAE_LOG_TRACE, path, 0);
    int ln[5];
    ln[0] = __LINE__; LOG_TRACE("t %d", 1);
    ln[1] = __LINE__; LOG_DEBUG("d %s", "x");
    ln[2] = __LINE__; LOG_INFO("no arguments");
    ln[3] = __LINE__; LOG_WARN("w %d%%", 5);
    ln[4] = __LINE__; LOG_ERROR("e");
    cbae_log_shutdown();
    const time_t hi = now_utc();
    logfile_t f = read_log(path);
    assert(f.count == 5);
    static const char *const NAME[5] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR" };
    static const char *const MSG[5]  = { "t 1", "d x", "no arguments", "w 5%", "e" };
    for (int k = 0; k < 5; k++) check_text(f.line[k], NAME[k], __FILE__, ln[k], __func__, MSG[k], lo, hi);
    free_log(&f);

    /* the JSON escapes as they are written: the short forms where JSON has them, \u00NN for the other controls and DEL */
    unlink(path);
    cbae_log_init(CBAE_LOG_TRACE, path, 1);
    cbae_log_write(CBAE_LOG_INFO, "f.c", 1, "fn", "%s", "a\nb\tc\rd\be\ff\x01g\x1f\x7f\"q\"\\");
    cbae_log_write(CBAE_LOG_INFO, "f.c", 2, "fn", "%s", "bad \xFF and \xC2\x85 and \xE2\x80\xA8");
    cbae_log_shutdown();
    f = read_log(path);
    assert(f.count == 2);
    assert(span_has(f.line[0], "\"msg\":\"a\\nb\\tc\\rd\\be\\ff\\u0001g\\u001f\\u007f\\\"q\\\"\\\\\"}"));
    assert(span_has(f.line[1], "\"msg\":\"bad \\ufffd and \\u0085 and \\u2028\"}"));
    free_log(&f);
    PASS("text and JSON line formats; the LOG_* macros pass the call site; the JSON escapes as documented");
}

static void test_timestamp_is_utc(void) {
    char path[160];
    path_of(path, sizeof path, "time.log");
    setenv("TZ", "XYZ-3", 1);                                  /* a zone three hours ahead of UTC, no database needed */
    tzset();
    for (int json = 0; json < 2; json++) {
        unlink(path);
        const time_t lo = now_utc();
        cbae_log_init(CBAE_LOG_INFO, path, json);
        LOG_INFO("time");
        cbae_log_shutdown();
        const time_t hi = now_utc();
        logfile_t f = read_log(path);
        assert(f.count == 1);
        if (json) { jrec_t r; assert(parse_record(f.line[0], &r)); check_ts(r.ts.v, lo, hi); free_rec(&r); }
        else { char ts[25]; assert(f.line[0].n > 27); memcpy(ts, f.line[0].p + 1, 24); ts[24] = '\0'; check_ts(ts, lo, hi); }
        free_log(&f);
    }
    unsetenv("TZ");
    tzset();
    PASS("the time stamp is UTC to the millisecond, whatever the local zone");
}

/* Text that a hostile binary can put into a name. */
static const char *const HOSTILE[] = {
    "",
    "plain ascii 0123456789 !#$%&'()*+,-./:;<=>?@[]^_`{|}~",
    "line one\nline two",
    "carriage\rreturn",
    "crlf\r\n",
    "forged\n[2026-01-01T00:00:00.000Z] ERROR  forged.c:1 (forge)  FORGED",
    "json forge\"}\n{\"ts\":\"2026-01-01T00:00:00.000Z\",\"level\":\"ERROR\",\"file\":\"forged.c\",\"line\":1,\"func\":\"forge\",\"msg\":\"FORGED\"}",
    "ansi \x1b[31mred\x1b[0m title \x1b]0;pwned\x07",
    "bell\a backspace\b formfeed\f vtab\v tab\t",
    "low controls \x01\x02\x03\x1f",
    "del \x7f" "x",
    "back\\slash and \\n literal and \\u0041 literal and trailing\\",
    "quote \"inside\" quotes",
    "percent 100% %s %n %d",
    "caf\xC3\xA9",
    "euro \xE2\x82\xAC",
    "emoji \xF0\x9F\x98\x80",
    "highest \xF4\x8F\xBF\xBF",
    "bom \xEF\xBB\xBF replacement \xEF\xBF\xBD",
    "edges \xDF\xBF \xE0\xA0\x80 \xED\x9F\xBF \xEE\x80\x80 \xF0\x90\x80\x80",
    "nel \xC2\x85 end",
    "csi \xC2\x9B" "31m",
    "c1 edges \xC2\x80 \xC2\x9F and not \xC2\xA0 \xC2\x7F",
    "separators \xE2\x80\xA8 \xE2\x80\xA9",
    "bidi \xE2\x80\xAA \xE2\x80\xAB \xE2\x80\xAC \xE2\x80\xAD \xE2\x80\xAE",
    "isolates \xE2\x81\xA6\xE2\x81\xA7\xE2\x81\xA8\xE2\x81\xA9",
    "neighbours that stay \xE2\x80\xA7 \xE2\x80\xAF \xE2\x81\xA5 \xE2\x81\xAA \xE2\x80\x8F",
    "lone ff \xFF",
    "overlong nul \xC0\x80 slash \xC1\xBF",
    "overlong 3 \xE0\x80\x80 4 \xF0\x80\x80\x80",
    "largest overlong forms \xC1\xBF \xE0\x9F\xBF \xF0\x8F\xBF\xBF",
    "surrogate \xED\xA0\x80 \xED\xBF\xBF",
    "too high \xF4\x90\x80\x80 \xF5\x80\x80\x80",
    "lone continuation \x80\xBF",
    "truncated in the middle \xE2\x82 more \xF0\x9F\x98 more",
    "ends mid-sequence \xE2\x82",
    "bad then good \xE2\x82" "A and \xC3" "B",
    "everything a\n\xFF\xC2\x9B\"\\\x1b \xE2\x80\xAE b",
};

static void test_hostile_text(void) {
    const size_t n = sizeof HOSTILE / sizeof HOSTILE[0];
    for (size_t i = 0; i < n; i++) {
        for (int json = 0; json < 2; json++) {
            log_one_and_check("src/x.c", 5, "fn", HOSTILE[i], json);          /* in the message */
            log_one_and_check(HOSTILE[i], 6, "fn", "m", json);                /* in the file name */
            log_one_and_check("src/x.c", 7, HOSTILE[i], "m", json);           /* in the function name */
        }
    }
    PASS("hostile text in a message, file name or function name is escaped in both modes (hand-written cases)");
}

static uint32_t rng(uint32_t *s) { *s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5; return *s; }

static size_t put_utf8(unsigned char *o, unsigned cp) {
    if (cp < 0x80) { o[0] = (unsigned char)cp; return 1; }
    if (cp < 0x800) { o[0] = (unsigned char)(0xC0 | (cp >> 6)); o[1] = (unsigned char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) { o[0] = (unsigned char)(0xE0 | (cp >> 12)); o[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F)); o[2] = (unsigned char)(0x80 | (cp & 0x3F)); return 3; }
    o[0] = (unsigned char)(0xF0 | (cp >> 18)); o[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
    o[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F)); o[3] = (unsigned char)(0x80 | (cp & 0x3F));
    return 4;
}

/* A random message: a mix of every kind of fragment, valid and not. Never contains a NUL byte. */
static size_t random_message(uint32_t *rs, unsigned char *buf, size_t cap) {
    static const unsigned SPECIAL[] = { 0x80, 0x85, 0x9B, 0x9F, 0x2028, 0x2029, 0x202A, 0x202E, 0x2066, 0x2069 };
    size_t n = 0;
    const size_t target = rng(rs) % 200;
    while (n < target && n + 5 < cap) {
        switch (rng(rs) % 11) {
            case 0: case 1: case 2: buf[n++] = (unsigned char)(0x20 + rng(rs) % 95); break;
            case 3:  buf[n++] = (unsigned char)(1 + rng(rs) % 31); break;
            case 4:  buf[n++] = 0x7F; break;
            case 5: {
                unsigned cp;
                switch (rng(rs) % 3) {
                    case 0:  cp = 0x80 + rng(rs) % (0x800 - 0x80); break;
                    case 1:  do cp = 0x800 + rng(rs) % (0x10000 - 0x800); while (cp >= 0xD800 && cp <= 0xDFFF); break;
                    default: cp = 0x10000 + rng(rs) % (0x110000 - 0x10000); break;
                }
                n += put_utf8(buf + n, cp);
                break;
            }
            case 6:  n += put_utf8(buf + n, SPECIAL[rng(rs) % (sizeof SPECIAL / sizeof SPECIAL[0])]); break;
            case 7:  buf[n++] = (unsigned char)(0x80 + rng(rs) % 128); break;
            case 8: {
                buf[n++] = (unsigned char)(0xC2 + rng(rs) % (0xF5 - 0xC2));
                for (unsigned k = rng(rs) % 3; k; k--) buf[n++] = (unsigned char)(0x80 + rng(rs) % 64);
                break;
            }
            case 9:  buf[n++] = '\\'; break;
            default: buf[n++] = '"'; break;
        }
    }
    buf[n] = '\0';
    return n;
}

static void test_random_text(void) {
    const int count = QUICK ? 400 : 3000;
    char path[160];
    path_of(path, sizeof path, "random.log");
    for (int json = 0; json < 2; json++) {
        unlink(path);
        uint32_t rs = 0x9E3779B9u + (uint32_t)json;
        const time_t lo = now_utc();
        cbae_log_init(CBAE_LOG_TRACE, path, json);
        for (int i = 0; i < count; i++) {
            unsigned char m[256];
            random_message(&rs, m, sizeof m);
            cbae_log_write(CBAE_LOG_INFO, "r.c", i, "rnd", "%s", (const char *)m);
        }
        cbae_log_shutdown();
        const time_t hi = now_utc();
        logfile_t f = read_log(path);
        assert(f.count == (size_t)count);                                      /* one line each, however hostile */
        rs = 0x9E3779B9u + (uint32_t)json;
        for (int i = 0; i < count; i++) {
            unsigned char m[256];
            random_message(&rs, m, sizeof m);
            if (json) check_json(f.line[i], "INFO", "r.c", i, "rnd", (const char *)m, lo, hi);
            else      check_text(f.line[i], "INFO", "r.c", i, "rnd", (const char *)m, lo, hi);
        }
        free_log(&f);
    }
    PASS("random messages of every kind of fragment: one clean line each, and the JSON reads back as written");
}

static void test_limits(void) {
    char *big = malloc(3000);
    assert(big);

    /* a message is cut at 1023 bytes; a name at 255 */
    for (int json = 0; json < 2; json++) {
        memset(big, 'x', 2000); big[2000] = '\0';
        log_one_and_check("f.c", 1, "fn", big, json);
        for (size_t len = 1020; len <= 1026; len++) { memset(big, 'y', len); big[len] = '\0'; log_one_and_check("f.c", 1, "fn", big, json); }
        memset(big, 'f', 300); big[300] = '\0';
        log_one_and_check(big, 2, "fn", "m", json);
        log_one_and_check("f.c", 2, big, "m", json);
        for (size_t len = 254; len <= 256; len++) { memset(big, 'g', len); big[len] = '\0'; log_one_and_check(big, 3, big, "m", json); }

        /* the cut falls inside a character: the part of it that is left is not UTF-8 and is escaped like any other such byte */
        static const char *const CHAR[3] = { "\xC3\xA9", "\xE2\x82\xAC", "\xF0\x9F\x98\x80" };
        for (int c = 0; c < 3; c++) {
            const size_t clen = strlen(CHAR[c]);
            for (size_t kept = 0; kept <= clen; kept++) {                       /* how much of the character is before the cut */
                memset(big, 'a', 1023 - kept); memcpy(big + 1023 - kept, CHAR[c], clen + 1);
                log_one_and_check("f.c", 4, "fn", big, json);
                memset(big, 'b', 255 - kept); memcpy(big + 255 - kept, CHAR[c], clen + 1);
                log_one_and_check(big, 4, big, "m", json);
            }
        }
    }

    /* the worst case: every byte of the message and of both names becomes six bytes of the line */
    for (int json = 0; json < 2; json++) {
        char name[256], msg[CBAE_LOG_MSG_MAX];
        memset(name, 0x01, 255); name[255] = '\0';
        memset(msg, 0x01, sizeof msg - 1); msg[sizeof msg - 1] = '\0';
        log_one_and_check(name, 8, name, msg, json);
        memset(name, 0xFF, 255); memset(msg, 0xFF, sizeof msg - 1);
        log_one_and_check(name, 8, name, msg, json);
        memset(name, '"', 255); memset(msg, '"', sizeof msg - 1);
        log_one_and_check(name, 8, name, msg, json);
        for (size_t i = 0; i + 1 < sizeof msg - 1; i += 2) { msg[i] = (char)0xC2; msg[i + 1] = (char)0x85; }    /* 2 bytes -> 6 */
        msg[sizeof msg - 2] = '\0';
        log_one_and_check("f.c", 8, "fn", msg, json);
    }
    free(big);
    PASS("a message is cut at 1023 bytes and a name at 255; the line buffer holds the worst expansion");
}

static void test_missing_arguments(void) {
    char path[160];
    path_of(path, sizeof path, "null.log");
    for (int json = 0; json < 2; json++) {
        unlink(path);
        const time_t lo = now_utc();
        cbae_log_init(CBAE_LOG_TRACE, path, json);
        cbae_log_write(CBAE_LOG_INFO, NULL, 3, NULL, "no file and no function");
        logv(CBAE_LOG_INFO, "f.c", 4, "fn", NULL);                                  /* no format */
        cbae_log_shutdown();
        const time_t hi = now_utc();
        logfile_t f = read_log(path);
        assert(f.count == 2);
        if (json) {
            check_json(f.line[0], "INFO", "?", 3, "?", "no file and no function", lo, hi);
            check_json(f.line[1], "INFO", "f.c", 4, "fn", "", lo, hi);
        } else {
            check_text(f.line[0], "INFO", "?", 3, "?", "no file and no function", lo, hi);
            check_text(f.line[1], "INFO", "f.c", 4, "fn", "", lo, hi);
        }
        free_log(&f);
    }
    PASS("a NULL file, function or format is tolerated");
}

static void test_unformattable(void) {
    /* A conversion that fails (a wide character the C locale cannot encode) must not leave half a message or the
     * stack's contents in the line. Only run where this C library really fails that conversion. */
    char probe[16];
    if (snprintf(probe, sizeof probe, "%ls", L"\xE9") >= 0) { printf("  [SKIP] unformattable message (this C library converts it)\n"); return; }
    char path[160];
    path_of(path, sizeof path, "badfmt.log");
    unlink(path);
    const time_t lo = now_utc();
    cbae_log_init(CBAE_LOG_TRACE, path, 0);
    LOG_INFO("start %ls end", L"\xE9");
    cbae_log_shutdown();
    const time_t hi = now_utc();
    logfile_t f = read_log(path);
    assert(f.count == 1);
    check_text(f.line[0], "INFO", __FILE__, __LINE__ - 5, __func__, "(unformattable log message)", lo, hi);
    free_log(&f);
    PASS("a message that cannot be formatted is replaced by a fixed text");
}

static void test_sinks(void) {
    char path[160], err[160], other[160];
    path_of(path, sizeof path, "sink.log");
    path_of(err, sizeof err, "stderr2.txt");
    path_of(other, sizeof other, "other.log");

    /* the file is appended to, not truncated */
    unlink(path);
    FILE *fp = fopen(path, "w");
    assert(fp);
    fputs("existing line\n", fp);
    fclose(fp);
    cbae_log_init(CBAE_LOG_INFO, path, 0);
    LOG_INFO("appended");
    cbae_log_shutdown();
    logfile_t f = read_log(path);
    assert(f.count == 2 && span_has(f.line[0], "existing line") && span_has(f.line[1], "  appended"));
    free_log(&f);

    /* NONE: nothing is logged */
    unlink(path);
    cbae_log_init(CBAE_LOG_NONE, path, 0);
    LOG_ERROR("never");
    cbae_log_shutdown();
    f = read_log(path);
    assert(f.size == 0);
    free_log(&f);

    /* no path, or an empty one: stderr, and no complaint */
    stderr_to(err);
    cbae_log_init(CBAE_LOG_INFO, NULL, 0);
    LOG_INFO("to stderr, no path");
    cbae_log_init(CBAE_LOG_INFO, "", 1);
    LOG_INFO("to stderr, empty path");
    cbae_log_shutdown();
    stderr_back();
    f = read_log(err);
    assert(f.count == 2 && span_has(f.line[0], "to stderr, no path"));
    assert(span_has(f.line[1], "\"msg\":\"to stderr, empty path\""));            /* the second init chose JSON */
    free_log(&f);

    /* a file that cannot be opened: stderr instead, and a warning that says why */
    static const struct { const char *path; const char *why; } BAD[] = {
        { "/nonexistent-cbae-dir/x.log", "No such file or directory" },
        { "/", "Is a directory" },
    };
    for (size_t i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
        stderr_to(err);
        cbae_log_init(CBAE_LOG_INFO, BAD[i].path, 0);
        LOG_INFO("after the fallback");
        cbae_log_shutdown();
        stderr_back();
        f = read_log(err);
        assert(f.count == 2);
        assert(span_has(f.line[0], " WARN  "));
        char want[128];
        snprintf(want, sizeof want, "cannot open log file '%s': %s; logging to stderr", BAD[i].path, BAD[i].why);
        assert(span_has(f.line[0], want));
        assert(span_has(f.line[1], "  after the fallback"));
        free_log(&f);
    }

    /* the warning obeys the level; the messages still go to stderr */
    stderr_to(err);
    cbae_log_init(CBAE_LOG_ERROR, "/nonexistent-cbae-dir/x.log", 0);
    LOG_WARN("hidden");
    LOG_ERROR("shown");
    cbae_log_shutdown();
    stderr_back();
    f = read_log(err);
    assert(f.count == 1 && span_has(f.line[0], "  shown"));
    free_log(&f);

    /* the path is hostile too */
    stderr_to(err);
    cbae_log_init(CBAE_LOG_INFO, "/nonexistent-cbae-dir/\n[2026-01-01T00:00:00.000Z] ERROR  forged.c:1 (f)  FORGED", 0);
    cbae_log_shutdown();
    stderr_back();
    f = read_log(err);
    assert(f.count == 1 && line_is_clean(f.line[0]) && span_has(f.line[0], "\\x0a[2026-01-01"));
    free_log(&f);

    /* the sink can be replaced; the old file is closed and gets nothing more */
    unlink(path);
    unlink(other);
    cbae_log_init(CBAE_LOG_INFO, path, 0);
    LOG_INFO("first");
    cbae_log_init(CBAE_LOG_INFO, other, 1);
    LOG_INFO("second");
    cbae_log_shutdown();
    f = read_log(path);
    assert(f.count == 1 && span_has(f.line[0], "  first"));
    free_log(&f);
    f = read_log(other);
    assert(f.count == 1 && span_has(f.line[0], "\"msg\":\"second\""));
    free_log(&f);
    PASS("the sink: appended file, stderr, fallback with a warning, replacement");
}

static void test_restart_closes_files(void) {
    char a[160], b[160];
    path_of(a, sizeof a, "restart_a.log");
    path_of(b, sizeof b, "restart_b.log");
    const int before = count_fds();
    for (int i = 0; i < 40; i++) {
        cbae_log_init(CBAE_LOG_INFO, (i & 1) ? a : b, i & 1);
        LOG_INFO("restart %d", i);
        assert(count_fds() == before + 1);                                       /* exactly one open sink */
    }
    cbae_log_shutdown();
    assert(count_fds() == before);
    cbae_log_shutdown();
    assert(count_fds() == before);
    PASS("every restart closes the previous file; shutdown closes the last");
}

/* ---- threads ---- */

typedef struct { int id; int count; } writer_t;

static void *writer_main(void *p) {
    const writer_t *w = (const writer_t *)p;
    for (int i = 0; i < w->count; i++) LOG_INFO("w=%d i=%d", w->id, i);
    return NULL;
}

/* The writer and index of one logged line, in either format; false if the line is neither whole text nor whole JSON. */
static bool read_writer_line(span_t l, int *w, int *i) {
    if (l.n && l.p[0] == '{') {
        jrec_t r;
        if (!parse_record(l, &r)) return false;
        const bool ok = sscanf(r.msg.v, "w=%d i=%d", w, i) == 2;
        free_rec(&r);
        return ok;
    }
    if (!line_is_clean(l) || l.n < 28 || l.p[0] != '[' || l.p[25] != ']') return false;
    const char *at = memmem(l.p, l.n, ")  w=", 5);
    if (!at) return false;
    char tail[64];
    const size_t left = l.n - (size_t)(at + 3 - l.p);
    if (left >= sizeof tail) return false;
    memcpy(tail, at + 3, left);
    tail[left] = '\0';
    return sscanf(tail, "w=%d i=%d", w, i) == 2;
}

#define WRITERS 4

static void test_threads(void) {
    const int per = QUICK ? 300 : 2000;
    char path[160];
    path_of(path, sizeof path, "threads.log");
    for (int json = 0; json < 2; json++) {
        unlink(path);
        cbae_log_init(CBAE_LOG_INFO, path, json);
        pthread_t th[WRITERS];
        writer_t arg[WRITERS];
        for (int t = 0; t < WRITERS; t++) { arg[t].id = t; arg[t].count = per; assert(pthread_create(&th[t], NULL, writer_main, &arg[t]) == 0); }
        for (int t = 0; t < WRITERS; t++) assert(pthread_join(th[t], NULL) == 0);
        cbae_log_shutdown();

        logfile_t f = read_log(path);
        assert(f.count == (size_t)WRITERS * (size_t)per);
        unsigned char *seen = calloc((size_t)WRITERS * (size_t)per, 1);
        assert(seen);
        for (size_t k = 0; k < f.count; k++) {
            int w, i;
            assert(read_writer_line(f.line[k], &w, &i));                           /* whole lines, never mixed */
            assert(w >= 0 && w < WRITERS && i >= 0 && i < per);
            assert(!seen[(size_t)w * (size_t)per + (size_t)i]);
            seen[(size_t)w * (size_t)per + (size_t)i] = 1;
        }
        free(seen);
        free_log(&f);
    }
    PASS("lines written from several threads are whole, and none is lost");
}

typedef struct { const char *path; atomic_bool *stop; int flavour; } churn_t;

static void *churn_main(void *p) {
    const churn_t *c = (const churn_t *)p;
    unsigned n = (unsigned)c->flavour;
    while (!atomic_load(c->stop)) {
        cbae_log_init(CBAE_LOG_TRACE, c->path, (int)(n & 1));
        n++;
        if ((n % 7) == 0) cbae_log_shutdown();
    }
    return NULL;
}

static void test_restart_while_logging(void) {
    const int per = QUICK ? 300 : 2000;
    char path[160];
    path_of(path, sizeof path, "churn.log");
    unlink(path);
    const int fds = count_fds();
    cbae_log_init(CBAE_LOG_INFO, path, 0);
    atomic_bool stop = false;
    pthread_t wt[WRITERS], ct[2];
    writer_t wa[WRITERS];
    churn_t ca[2] = { { path, &stop, 0 }, { path, &stop, 1 } };
    for (int t = 0; t < 2; t++) assert(pthread_create(&ct[t], NULL, churn_main, &ca[t]) == 0);
    for (int t = 0; t < WRITERS; t++) { wa[t].id = t; wa[t].count = per; assert(pthread_create(&wt[t], NULL, writer_main, &wa[t]) == 0); }
    for (int t = 0; t < WRITERS; t++) assert(pthread_join(wt[t], NULL) == 0);
    atomic_store(&stop, true);
    for (int t = 0; t < 2; t++) assert(pthread_join(ct[t], NULL) == 0);
    /* On a busy machine the restarts can leave the logger down for the whole of the writers' run, so that none of their
     * lines is kept (it was seen once in sixty runs under load). One line more, from a logger that is known to be up,
     * gives the file something to hold either way. */
    cbae_log_init(CBAE_LOG_INFO, path, 0);
    LOG_INFO("w=%d i=%d", WRITERS, 0);
    cbae_log_shutdown();
    assert(count_fds() == fds);                                                  /* no file leaked, none closed twice */

    /* lines are lost while the logger is down, but each one that was written is whole, in one format or the other */
    logfile_t f = read_log(path);
    assert(f.count >= 1 && f.count <= (size_t)WRITERS * (size_t)per + 1);
    unsigned char *seen = calloc((size_t)WRITERS * (size_t)per, 1);
    assert(seen);
    bool marker = false;
    for (size_t k = 0; k < f.count; k++) {
        int w, i;
        assert(read_writer_line(f.line[k], &w, &i));
        if (w == WRITERS) {                                                      /* the line written after the churn */
            assert(i == 0 && !marker);
            marker = true;
            continue;
        }
        assert(w >= 0 && w < WRITERS && i >= 0 && i < per);
        assert(!seen[(size_t)w * (size_t)per + (size_t)i]);
        seen[(size_t)w * (size_t)per + (size_t)i] = 1;
    }
    assert(marker);
    free(seen);
    free_log(&f);
    PASS("init and shutdown while other threads log: no torn line, no leaked or doubly closed file");
}

int main(void) {
    printf("=== test_logging ===\n");
    make_dir();
    test_silent_until_init_and_after_shutdown();
    test_levels();
    test_frames_and_macros();
    test_timestamp_is_utc();
    test_hostile_text();
    test_random_text();
    test_limits();
    test_missing_arguments();
    test_unformattable();
    test_sinks();
    test_restart_closes_files();
    test_threads();
    test_restart_while_logging();
    remove_dir();
    printf("All logging tests passed.\n");
    return 0;
}
