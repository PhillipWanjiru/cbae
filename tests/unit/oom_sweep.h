/*
 * oom_sweep.h - run an operation once for every allocation it makes, and fail that one.
 *
 * Needs alloc_inject.h in the same executable (include it first, in the same .c file).
 *
 * oom_sweep(body, ctx, strict)
 *   Calls body(ctx, 0) with no failure: it must return CBAE_OK, and the number of allocations it made
 *   is N. Then, for k = 1..N, twice: once with allocation k alone failing and once with k and every
 *   later allocation failing (so the cleanup paths see failures too). The body does the operation,
 *   releases whatever it made, and asserts what a caller may rely on: on an error the outputs are in
 *   the documented empty state; on success the result is complete and correct. It returns the error
 *   code of the operation. With strict set, an injected failure that the operation answered with
 *   CBAE_OK is a failure of the test - an allocation failure must never be swallowed into a wrong
 *   (or merely less complete) answer. The report counts both kinds of outcome.
 *
 * oom_sweep_arena(body, ctx, lo, hi, step)
 *   Calls body(ctx, size) for arena capacities lo, lo+step, ..., hi. Exhaustion of a fixed-capacity
 *   arena is not a malloc failure, so it needs its own sweep. Requires: sizes below some threshold fail
 *   with an error, every size from the threshold up succeeds (never a failure after a success). Returns
 *   the smallest size that succeeded (hi + 1 if none did).
 */
#ifndef CBAE_TEST_OOM_SWEEP_H
#define CBAE_TEST_OOM_SWEEP_H

#include "alloc_inject.h"
#include "cbae/cbae_error.h"
#include <assert.h>
#include <stdio.h>

typedef cbae_err_t (*oom_body_fn)(void *ctx, uint64_t failing_allocation);
typedef cbae_err_t (*oom_arena_body_fn)(void *ctx, size_t arena_bytes);

typedef struct {
    uint64_t allocations;   /* made by the failure-free run */
    uint64_t runs;          /* runs with an injected failure */
    uint64_t reported;      /* ... that ended in an error */
    uint64_t swallowed;     /* ... that ended in CBAE_OK although an allocation had failed */
} oom_report_t;

static inline oom_report_t oom_sweep(oom_body_fn body, void *ctx, bool strict) {
    oom_report_t r = {0, 0, 0, 0};
    ai_reset();
    const cbae_err_t base = body(ctx, 0);
    ai_disarm();
    r.allocations = ai_count();
    assert(base == CBAE_OK && "oom_sweep: the failure-free run must succeed");
    assert(ai_failed() == 0);
    for (int from_here_on = 0; from_here_on < 2; from_here_on++) {
        for (uint64_t k = 1; k <= r.allocations; k++) {
            ai_reset();
            if (from_here_on) ai_fail_from(k); else ai_fail_at(k);
            const cbae_err_t rc = body(ctx, k);
            const uint64_t failed = ai_failed();
            ai_disarm();
            r.runs++;
            if (failed == 0) continue;             /* the run made fewer than k allocations this time */
            if (rc != CBAE_OK) r.reported++;
            else {
                r.swallowed++;
                if (strict) {
                    fprintf(stderr, "oom_sweep: allocation %llu failed (%s) and the operation still reported success\n",
                            (unsigned long long)k, from_here_on ? "and every later one" : "alone");
                    assert(!"an allocation failure was swallowed");
                }
            }
        }
    }
    ai_reset();
    return r;
}

static inline size_t oom_sweep_arena(oom_arena_body_fn body, void *ctx, size_t lo, size_t hi, size_t step) {
    assert(step > 0 && lo <= hi);
    size_t first_ok = hi + 1;
    for (size_t sz = lo; sz <= hi; sz += step) {
        const cbae_err_t rc = body(ctx, sz);
        if (rc == CBAE_OK) { if (first_ok > hi) first_ok = sz; }
        else if (first_ok <= hi) {
            fprintf(stderr, "oom_sweep_arena: arena of %zu bytes failed (%d) after %zu succeeded\n", sz, (int)rc, first_ok);
            assert(!"a larger arena failed where a smaller one succeeded");
        }
        if (sz > hi - step) break;                 /* no wrap */
    }
    return first_ok;
}

#endif
