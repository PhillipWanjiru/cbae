/**
 * @file loader_util.h
 * @brief What the PE and ELF loaders share: reading numbers and strings out of an untrusted file.
 *
 * Internal to the loaders. Three rules, both loaders follow them:
 *  - Numbers are read by byte assembly (rd16/rd32/rd64), never through a cast pointer: a table can start
 *    at any offset, so alignment and host byte order must not matter.
 *  - Nothing is read except through a span (a pointer plus the number of file-backed bytes behind it); a
 *    string read stops at the span's end, and at a cap, whichever comes first.
 *  - A table is walked twice by the same code through a sink: a plan pass that only counts, then a fill
 *    pass that writes into arrays sized for exactly that count.
 */
#ifndef CBAE_LOADER_UTIL_H
#define CBAE_LOADER_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static inline uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

/** n bytes at p, all of them in the file. {NULL, 0} is the empty span. */
typedef struct { const uint8_t *p; size_t n; } span_t;

typedef enum { STR_OK, STR_CUT, STR_UNTERMINATED, STR_UNMAPPED } str_res_t;

/**
 * Copies the NUL-terminated string at the start of @p s into dst (cap bytes, always terminated). Never
 * scans more than cap bytes: a name that long is cut anyway.
 *   STR_OK            the whole string fit
 *   STR_CUT           it was longer than cap - 1 bytes and was cut
 *   STR_UNTERMINATED  the span ended before a NUL: what was there is the name
 *   STR_UNMAPPED      the span is empty: dst is ""
 */
static inline str_res_t read_str(span_t s, char *dst, size_t cap) {
    dst[0] = '\0';
    if (!s.p || s.n == 0) return STR_UNMAPPED;
    const size_t limit = s.n < cap - 1 ? s.n : cap - 1;
    const uint8_t *nul = (const uint8_t *)memchr(s.p, 0, limit);
    const size_t len = nul ? (size_t)(nul - s.p) : limit;
    memcpy(dst, s.p, len);
    dst[len] = '\0';
    if (nul) return STR_OK;
    if (s.n > limit) return s.p[limit] == 0 ? STR_OK : STR_CUT;
    return STR_UNTERMINATED;
}

/** Where a walker puts what it finds. dst NULL: count only. n counts everything the walk produced, even
 *  what did not fit, so after the fill pass n == cap means the plan and the fill agreed. */
typedef struct { void *dst; uint32_t cap, n; } sink_t;

static inline void *sink_slot(sink_t *k, size_t elem) {
    void *e = (k->dst && k->n < k->cap) ? (uint8_t *)k->dst + (size_t)k->n * elem : NULL;
    k->n++;
    return e;
}

/** Bytes an arena needs for n elements of the given size, with slack for alignment. */
static inline uint64_t array_bytes(uint64_t n, size_t elem) { return n * (uint64_t)elem + 16; }

#endif /* CBAE_LOADER_UTIL_H */
