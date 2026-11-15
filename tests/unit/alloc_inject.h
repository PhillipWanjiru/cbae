/*
 * alloc_inject.h - allocation-failure injection for tests.
 *
 * A test executable that includes this header in exactly ONE of its .c files, and is linked with
 *
 *     target_link_options(<test> PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
 *
 * has every malloc, calloc and realloc made by the code linked into it (the library under test and
 * the test itself; not the C library's own internal allocations) counted, and the one the test picks
 * made to fail with NULL and errno = ENOMEM. free passes through. The count and the failures are
 * atomic, so the injector can sit under the thread-pool tests.
 *
 *   ai_reset()          forget the count and the failures, disarm
 *   ai_fail_at(k)       from now on allocation number k (1 = the next one) fails; every other succeeds
 *   ai_fail_from(k)     allocation number k and every later one fail
 *   ai_disarm()         stop failing; keep counting
 *   ai_count()          allocations attempted since the last reset
 *   ai_failed()         allocations made to fail since the last reset
 *   ai_max_request()    the largest size asked of malloc, calloc (count * size) or realloc since the last reset,
 *                       whether or not that request was made to fail (an unbounded request is a defect even if
 *                       the machine happens to grant it)
 *
 * Arm it around the operation under test and disarm before the test's own bookkeeping allocates.
 * A realloc counts as one allocation. Under ASan or Valgrind the real allocator behind the wrapper is
 * the sanitizer's, so a leak on a failure path is reported when the process exits.
 */
#ifndef CBAE_TEST_ALLOC_INJECT_H
#define CBAE_TEST_ALLOC_INJECT_H

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void *__real_malloc(size_t n);
void *__real_calloc(size_t a, size_t b);
void *__real_realloc(void *p, size_t n);
void  __real_free(void *p);

static _Atomic uint64_t ai_n_calls;
static _Atomic uint64_t ai_n_failed;
static _Atomic uint64_t ai_k_at;      /* 0 = not armed */
static _Atomic uint64_t ai_k_from;    /* 0 = not armed */
static _Atomic size_t   ai_n_max;     /* largest request */

static inline void ai_reset(void) {
    atomic_store(&ai_k_at, 0); atomic_store(&ai_k_from, 0);
    atomic_store(&ai_n_calls, 0); atomic_store(&ai_n_failed, 0); atomic_store(&ai_n_max, 0);
}
static inline void ai_fail_at(uint64_t k)   { atomic_store(&ai_k_from, 0); atomic_store(&ai_k_at, atomic_load(&ai_n_calls) + k); }
static inline void ai_fail_from(uint64_t k) { atomic_store(&ai_k_at, 0);   atomic_store(&ai_k_from, atomic_load(&ai_n_calls) + k); }
static inline void ai_disarm(void)          { atomic_store(&ai_k_at, 0); atomic_store(&ai_k_from, 0); }
static inline uint64_t ai_count(void)       { return atomic_load(&ai_n_calls); }
static inline uint64_t ai_failed(void)      { return atomic_load(&ai_n_failed); }
static inline size_t   ai_max_request(void) { return atomic_load(&ai_n_max); }

static inline void ai_note(size_t n) {
    size_t m = atomic_load(&ai_n_max);
    while (n > m && !atomic_compare_exchange_weak(&ai_n_max, &m, n)) { }
}

static inline bool ai_should_fail(void) {
    const uint64_t n = atomic_fetch_add(&ai_n_calls, 1) + 1;
    const uint64_t at = atomic_load(&ai_k_at), from = atomic_load(&ai_k_from);
    if ((at != 0 && n == at) || (from != 0 && n >= from)) { atomic_fetch_add(&ai_n_failed, 1); return true; }
    return false;
}

void *__wrap_malloc(size_t n)             { ai_note(n); if (ai_should_fail()) { errno = ENOMEM; return NULL; } return __real_malloc(n); }
void *__wrap_calloc(size_t a, size_t b)   { ai_note(a != 0 && b > SIZE_MAX / a ? SIZE_MAX : a * b); if (ai_should_fail()) { errno = ENOMEM; return NULL; } return __real_calloc(a, b); }
void *__wrap_realloc(void *p, size_t n)   { ai_note(n); if (ai_should_fail()) { errno = ENOMEM; return NULL; } return __real_realloc(p, n); }
void  __wrap_free(void *p)                { __real_free(p); }

#endif
