/**
 * @file test_dataflow_engine.c
 * @brief Generic worklist dataflow solver: backward liveness and forward
 *        reaching-blocks on an acyclic diamond and on a loop, plus the
 *        engine's error contracts.
 *
 * Pure engine test: CFGs are built directly through the CIR builder's
 * block/edge API (no x86 bytes, no lifter) because the solver depends
 * only on graph structure and the caller's transfer functions.
 *
 * Values are 32-bit bitmasks allocated in the arena. Every expected
 * value below was derived by hand from the dataflow equations BEFORE
 * running anything; each test shows its derivation.
 *
 *   FORWARD :  IN[b]  = U OUT[pred]      OUT[b] = transfer(IN[b])
 *   BACKWARD:  OUT[b] = U IN[succ]       IN[b]  = transfer(OUT[b])
 *
 * Both analyses are "may" analyses (meet = union, init/boundary = empty
 * set), which satisfies the engine's rule that init_value() is the meet
 * identity.
 *
 * Liveness transfer:   IN  = use[b] | (OUT & ~def[b])
 * Reaching transfer:   OUT = IN | (1 << b)     ("which blocks' code
 *                      has executed on SOME path reaching this point")
 */
#include "dataflow/dataflow_engine.h"
#include "cir/cir_builder.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Bitset values ────────────────────────────────────────────────────── */

typedef struct { uint32_t bits; } bs_t;

static void *mk(cbae_arena_t *a, uint32_t bits) {
    bs_t *v = CBAE_ARENA_ALLOC(a, bs_t);
    if (v) v->bits = bits;
    return v;
}
static uint32_t bits_of(const void *v) { return ((const bs_t *)v)->bits; }

static void *bs_init(cbae_arena_t *a, void *ud) {
    (void)ud;
    return mk(a, 0);
}
static void *bs_meet(cbae_arena_t *a, void *x, void *y, void *ud) {
    (void)ud;
    return mk(a, bits_of(x) | bits_of(y));
}
static bool bs_equals(void *x, void *y, void *ud) {
    (void)ud;
    return bits_of(x) == bits_of(y);
}

typedef struct { uint32_t use[8]; uint32_t def[8]; } live_ctx_t;

static void *live_transfer(cbae_arena_t *a, uint32_t b, void *out, void *ud) {
    const live_ctx_t *c = ud;
    return mk(a, c->use[b] | (bits_of(out) & ~c->def[b]));
}
static void *reach_transfer(cbae_arena_t *a, uint32_t b, void *in, void *ud) {
    (void)ud;
    return mk(a, bits_of(in) | (1u << b));
}

static const cbae_dataflow_ops_t LIVE_OPS  = { bs_init, bs_meet, live_transfer,  bs_equals };
static const cbae_dataflow_ops_t REACH_OPS = { bs_init, bs_meet, reach_transfer, bs_equals };

#define V0 (1u << 0)
#define V1 (1u << 1)
#define V2 (1u << 2)
#define V3 (1u << 3)

#define IN_IS(r, b, want)  assert(bits_of((r).in_values[(b)])  == (want))
#define OUT_IS(r, b, want) assert(bits_of((r).out_values[(b)]) == (want))

/* Build a function with `nblocks` empty blocks and the given edges. */
static cbae_cir_function_t *make_cfg(cbae_arena_t *arena, uint32_t nblocks,
                                       const uint32_t edges[][2], uint32_t nedges) {
    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(arena, 0x1000, "cfg", &f) == CBAE_OK);
    cbae_cir_block_t **blocks = malloc(sizeof(cbae_cir_block_t *) * nblocks);
    for (uint32_t i = 0; i < nblocks; i++)
        assert(cbae_cir_block_create(f, 0x1000 + i * 0x10, &blocks[i]) == CBAE_OK);
    for (uint32_t e = 0; e < nedges; e++)
        assert(cbae_cir_block_add_edge(blocks[edges[e][0]], blocks[edges[e][1]]) == CBAE_OK);
    free(blocks);
    return f;
}

/* ── 1. Backward liveness on the diamond  0 -> {1,2} -> 3 ────────────────
 *
 * def[0] = {V0};  use[1] = use[2] = {V0};  everything else empty.
 *
 *   Block 3 has no successors -> OUT[3] = {} (boundary).
 *     IN[3]  = use[3] | (OUT[3] & ~def[3]) = {}
 *   Block 1: OUT[1] = IN[3] = {}        IN[1] = use[1] = {V0}
 *   Block 2: OUT[2] = IN[3] = {}        IN[2] = use[2] = {V0}
 *   Block 0: OUT[0] = IN[1] | IN[2] = {V0}
 *            IN[0]  = use[0] | (OUT[0] & ~def[0]) = {V0} & ~{V0} = {}
 *   V0 is live on both branches (each reads it) and dead before
 *   block 0, which defines it.
 */
static void t_liveness_diamond(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    const uint32_t edges[][2] = { {0,1}, {0,2}, {1,3}, {2,3} };
    cbae_cir_function_t *f = make_cfg(&arena, 4, edges, 4);

    live_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.def[0] = V0;
    ctx.use[1] = V0;
    ctx.use[2] = V0;

    cbae_dataflow_result_t r;
    assert(cbae_dataflow_run(f, CBAE_DATAFLOW_BACKWARD, &LIVE_OPS, &ctx, &arena, &r) == CBAE_OK);
    assert(r.block_count == 4);

    IN_IS(r, 3, 0);   OUT_IS(r, 3, 0);
    IN_IS(r, 1, V0);  OUT_IS(r, 1, 0);
    IN_IS(r, 2, V0);  OUT_IS(r, 2, 0);
    IN_IS(r, 0, 0);   OUT_IS(r, 0, V0);

    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] backward liveness on a diamond\n");
}

/* ── 2. Forward reaching-blocks on the diamond ───────────────────────────
 *
 *   Block 0 has no predecessors -> IN[0] = {} (boundary)
 *     OUT[0] = IN[0] | {0}                       = {0}
 *   Block 1: IN[1] = OUT[0] = {0}      OUT[1]    = {0,1}
 *   Block 2: IN[2] = OUT[0] = {0}      OUT[2]    = {0,2}
 *   Block 3: IN[3] = OUT[1] | OUT[2]             = {0,1,2}
 *            OUT[3] = IN[3] | {3}                = {0,1,2,3}
 *   Block 3 sees BOTH branches (union at the join) but no block sees
 *   its own sibling branch.
 */
static void t_reaching_diamond(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    const uint32_t edges[][2] = { {0,1}, {0,2}, {1,3}, {2,3} };
    cbae_cir_function_t *f = make_cfg(&arena, 4, edges, 4);

    cbae_dataflow_result_t r;
    assert(cbae_dataflow_run(f, CBAE_DATAFLOW_FORWARD, &REACH_OPS, NULL, &arena, &r) == CBAE_OK);

    IN_IS(r, 0, 0);               OUT_IS(r, 0, V0);
    IN_IS(r, 1, V0);              OUT_IS(r, 1, V0 | V1);
    IN_IS(r, 2, V0);              OUT_IS(r, 2, V0 | V2);
    IN_IS(r, 3, V0 | V1 | V2);    OUT_IS(r, 3, V0 | V1 | V2 | V3);

    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] forward reaching-blocks on a diamond\n");
}

/* ── 3. Backward liveness through a loop ─────────────────────────────────
 *
 * CFG:  0 -> 1;  1 -> 2;  1 -> 3;  2 -> 1     (1 = loop header,
 *                                              2 = loop body, 3 = exit)
 * def[0] = {V0};  use[1] = {V0};  everything else empty.
 *
 *   Block 3: no successors -> OUT[3] = {}, IN[3] = {}
 *   Block 2: OUT[2] = IN[1];            IN[2] = OUT[2]       (no use/def)
 *   Block 1: OUT[1] = IN[2] | IN[3] = IN[2]
 *            IN[1]  = use[1] | OUT[1] = {V0} | IN[2]
 *   The loop makes IN[1], OUT[1], IN[2], OUT[2] mutually dependent:
 *       IN[1] = {V0} | IN[1]
 *   whose LEAST fixed point is IN[1] = {V0}; hence
 *       IN[1] = OUT[1] = IN[2] = OUT[2] = {V0}.
 *   Block 0: OUT[0] = IN[1] = {V0};  IN[0] = {V0} & ~def[0] = {}.
 *   V0 is live around the whole loop because the header reads it on
 *   every iteration; the first pass through blocks 2 and 1 sees stale
 *   (empty) values and must be corrected by a revisit.
 */
static void t_liveness_loop(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    const uint32_t edges[][2] = { {0,1}, {1,2}, {1,3}, {2,1} };
    cbae_cir_function_t *f = make_cfg(&arena, 4, edges, 4);

    live_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.def[0] = V0;
    ctx.use[1] = V0;

    cbae_dataflow_result_t r;
    assert(cbae_dataflow_run(f, CBAE_DATAFLOW_BACKWARD, &LIVE_OPS, &ctx, &arena, &r) == CBAE_OK);

    IN_IS(r, 3, 0);   OUT_IS(r, 3, 0);
    IN_IS(r, 1, V0);  OUT_IS(r, 1, V0);
    IN_IS(r, 2, V0);  OUT_IS(r, 2, V0);
    IN_IS(r, 0, 0);   OUT_IS(r, 0, V0);

    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] backward liveness through a loop (needs revisits)\n");
}

/* ── 4. Forward reaching-blocks through the same loop ────────────────────
 *
 *   Block 0: IN[0] = {}                 OUT[0] = {0}
 *   Block 1: IN[1]  = OUT[0] | OUT[2]   OUT[1] = IN[1] | {1}
 *   Block 2: IN[2]  = OUT[1]            OUT[2] = IN[2] | {2}
 *   Block 3: IN[3]  = OUT[1]            OUT[3] = IN[3] | {3}
 *   Substituting around the cycle:
 *       OUT[2] = OUT[1] | {2} = IN[1] | {1,2}
 *       IN[1]  = {0} | IN[1] | {1,2}
 *   LEAST fixed point: IN[1] = {0,1,2}. So
 *       IN[1] = OUT[1] = IN[2] = OUT[2] = IN[3] = {0,1,2}
 *       OUT[3] = {0,1,2,3}
 *   Block 1 sees ITSELF and block 2 only because of the back edge 2->1;
 *   block 3 (outside the loop) sees them via the header.
 */
static void t_reaching_loop(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    const uint32_t edges[][2] = { {0,1}, {1,2}, {1,3}, {2,1} };
    cbae_cir_function_t *f = make_cfg(&arena, 4, edges, 4);

    cbae_dataflow_result_t r;
    assert(cbae_dataflow_run(f, CBAE_DATAFLOW_FORWARD, &REACH_OPS, NULL, &arena, &r) == CBAE_OK);

    const uint32_t loop_set = V0 | V1 | V2;
    IN_IS(r, 0, 0);          OUT_IS(r, 0, V0);
    IN_IS(r, 1, loop_set);   OUT_IS(r, 1, loop_set);
    IN_IS(r, 2, loop_set);   OUT_IS(r, 2, loop_set);
    IN_IS(r, 3, loop_set);   OUT_IS(r, 3, loop_set | V3);

    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] forward reaching-blocks through a loop (back edge)\n");
}

/* ── 5. Error contracts ──────────────────────────────────────────────── */

static void t_invalid_arguments(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 64 * 1024);
    const uint32_t edges[][2] = { {0,1} };
    cbae_cir_function_t *f = make_cfg(&arena, 2, edges, 1);
    cbae_dataflow_result_t r;

    assert(cbae_dataflow_run(NULL, CBAE_DATAFLOW_FORWARD, &REACH_OPS, NULL, &arena, &r) == CBAE_ERR_INVALID);
    assert(cbae_dataflow_run(f, CBAE_DATAFLOW_FORWARD, NULL, NULL, &arena, &r) == CBAE_ERR_INVALID);
    assert(cbae_dataflow_run(f, CBAE_DATAFLOW_FORWARD, &REACH_OPS, NULL, NULL, &r) == CBAE_ERR_INVALID);
    assert(cbae_dataflow_run(f, CBAE_DATAFLOW_FORWARD, &REACH_OPS, NULL, &arena, NULL) == CBAE_ERR_INVALID);
    assert(cbae_dataflow_run(f, (cbae_dataflow_direction_t)99, &REACH_OPS, NULL, &arena, &r) == CBAE_ERR_INVALID);

    cbae_dataflow_ops_t no_meet = REACH_OPS;
    no_meet.meet = NULL;
    assert(cbae_dataflow_run(f, CBAE_DATAFLOW_FORWARD, &no_meet, NULL, &arena, &r) == CBAE_ERR_INVALID);

    /* A function with zero blocks has no entry to analyse. */
    cbae_cir_function_t *empty;
    assert(cbae_cir_function_create(&arena, 0x2000, "empty", &empty) == CBAE_OK);
    assert(cbae_dataflow_run(empty, CBAE_DATAFLOW_FORWARD, &REACH_OPS, NULL, &arena, &r) == CBAE_ERR_INVALID);

    cbae_cir_function_destroy(empty);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] null/invalid arguments rejected\n");
}

/* An exhausted arena must surface as CBAE_ERR_OOM from a failed callback
 * allocation (or the engine's own arrays) -- never a crash or a result
 * with NULL entries. */
static void t_arena_exhaustion(void) {
    const uint32_t edges[][2] = { {0,1}, {0,2}, {1,3}, {2,3} };
    const size_t caps[] = { 32, 64, 80, 96, 128, 160, 192, 256, 1u << 20 };

    for (size_t i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
        /* The CIR function lives in its own roomy arena so only the
         * solver's arena is starved. */
        cbae_arena_t cir_arena; cbae_arena_init(&cir_arena, 64 * 1024);
        cbae_cir_function_t *f = make_cfg(&cir_arena, 4, edges, 4);

        cbae_arena_t tiny; assert(cbae_arena_init(&tiny, caps[i]) == CBAE_OK);
        cbae_dataflow_result_t r;
        cbae_err_t rc = cbae_dataflow_run(f, CBAE_DATAFLOW_FORWARD, &REACH_OPS, NULL, &tiny, &r);

        assert(rc == CBAE_OK || rc == CBAE_ERR_OOM);
        if (caps[i] == 32)       assert(rc == CBAE_ERR_OOM);  /* cannot even hold the result arrays */
        if (caps[i] == (1u << 20)) {
            assert(rc == CBAE_OK);
            for (uint32_t b = 0; b < 4; b++) {
                assert(r.in_values[b] != NULL);
                assert(r.out_values[b] != NULL);
            }
        }

        cbae_arena_destroy(&tiny);
        cbae_cir_function_destroy(f);
        cbae_arena_destroy(&cir_arena);
    }
    printf("  [PASS] arena exhaustion reported as CBAE_ERR_OOM at every size\n");
}

/* A transfer function that is NOT monotone (it keeps producing larger
 * values around a loop) can never reach a fixed point; the visit budget
 * must turn that into CBAE_ERR_OVERFLOW instead of an endless loop. */
static void *grow_transfer(cbae_arena_t *a, uint32_t b, void *in, void *ud) {
    (void)b; (void)ud;
    return mk(a, bits_of(in) + 1);
}

static void t_nonconvergent_is_bounded(void) {
    cbae_arena_t arena; cbae_arena_init(&arena, 16u * 1024 * 1024);
    const uint32_t edges[][2] = { {0,1}, {1,2}, {2,1}, {1,3} };
    cbae_cir_function_t *f = make_cfg(&arena, 4, edges, 4);

    const cbae_dataflow_ops_t ops = { bs_init, bs_meet, grow_transfer, bs_equals };
    cbae_dataflow_result_t r;
    assert(cbae_dataflow_run(f, CBAE_DATAFLOW_FORWARD, &ops, NULL, &arena, &r) == CBAE_ERR_OVERFLOW);

    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] non-monotone transfer aborts with CBAE_ERR_OVERFLOW\n");
}

int main(void) {
    printf("=== test_dataflow_engine ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);

    t_liveness_diamond();
    t_reaching_diamond();
    t_liveness_loop();
    t_reaching_loop();
    t_invalid_arguments();
    t_arena_exhaustion();
    t_nonconvergent_is_bounded();

    printf("All dataflow engine tests passed.\n");
    return 0;
}
