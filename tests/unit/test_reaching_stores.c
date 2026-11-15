/**
 * @file test_reaching_stores.c
 * @brief Reaching stores: hand-derived cases.
 *
 * Every expected set below was derived on paper from the function being
 * queried -- which stores execute before the load, which of them write
 * provably different bytes, which are overwritten by a later store of the
 * same bytes -- and not read off the analysis output. Where a result is
 * deliberately less precise than the truth (a documented limit), the test
 * says so, so that an improvement is a conscious change to the test.
 *
 *   - the opcode classification that decides what counts as a write;
 *   - straight-line shapes: shadowing, disjoint offsets, widths, indexed
 *     addresses written twice with different SSA values;
 *   - calls: inside a block and across blocks, including the case the E/F
 *     bits exist for (a store AFTER a call must hide the call);
 *   - joins and loops, initial content, unstable addresses;
 *   - barrier kinds, malformed instructions, unreachable code, API edges,
 *     the state limit, a larger function, and lifted machine code.
 *
 * The check against real executions is test_reaching_soundness.c.
 */
#include "dataflow/reaching_stores.h"
#include "cir/cir_printer.h"
#include "platform/logging.h"
#include "cir_test_util.h"
#include "lift_helpers.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef const cbae_cir_instruction_t *insn_t;

#define SET(...) ((const cbae_cir_instruction_t *const[]){ __VA_ARGS__ }), \
    (uint32_t)(sizeof((const cbae_cir_instruction_t *const[]){ __VA_ARGS__ }) / \
               sizeof(const cbae_cir_instruction_t *))
#define EMPTY NULL, 0u

typedef struct {
    cbae_use_def_t           ud;
    cbae_alias_ctx_t         alias;
    cbae_reaching_stores_t   rs;
} rsx_t;

static void rsx_build_unchecked(rsx_t *x, const cbae_cir_function_t *f) {
    assert(cbae_use_def_build(f, &x->ud) == CBAE_OK);
    assert(cbae_alias_ctx_build(&x->ud, &x->alias) == CBAE_OK);
    assert(cbae_reaching_stores_build(&x->ud, &x->alias, &x->rs) == CBAE_OK);
}

static void rsx_build(rsx_t *x, const fn_t *f) {
    fn_verify(f);
    rsx_build_unchecked(x, f->f);
}

static void rsx_free(rsx_t *x) {
    cbae_reaching_stores_destroy(&x->rs);
    cbae_alias_ctx_destroy(&x->alias);
    cbae_use_def_destroy(&x->ud);
}

static void show(const char *label, const cbae_cir_instruction_t *const *v, uint32_t n) {
    fprintf(stderr, "  %s {", label);
    for (uint32_t i = 0; i < n; i++) fprintf(stderr, "%s#%u", i ? ", " : "", v[i]->id);
    fprintf(stderr, "}\n");
}

/* The reaching set of `load` must be exactly `want` (in definition order, which
 * is the order the query reports) and may_be_initial must match. */
static void reaches(const rsx_t *x, const char *what, insn_t load,
                    const cbae_cir_instruction_t *const *want, uint32_t nwant, bool want_initial) {
    const cbae_rs_def_t *got[64];
    uint32_t n = 0;
    bool initial = !want_initial;
    assert(cbae_reaching_stores_for_load(&x->rs, load, got, 64, &n, &initial) == CBAE_OK);
    assert(n <= 64);

    bool ok = n == nwant && initial == want_initial;
    for (uint32_t i = 0; ok && i < nwant; i++) {
        bool found = false;
        for (uint32_t j = 0; j < n; j++) found |= got[j]->insn == want[i];
        ok = found;
    }
    for (uint32_t j = 0; ok && j + 1 < n; j++) ok = got[j] < got[j + 1];   /* definition order */
    if (!ok) {
        fprintf(stderr, "FAIL [%s] load #%u: want %u defs initial=%d, got %u defs initial=%d\n",
                what, load->id, nwant, (int)want_initial, n, (int)initial);
        show("want", want, nwant);
        const cbae_cir_instruction_t *gi[64];
        for (uint32_t j = 0; j < n; j++) gi[j] = got[j]->insn;
        show("got ", gi, n);
    }
    assert(ok);
}

/* forwardable <=> `store` is non-NULL, and it is that very store. */
static void forwards(const rsx_t *x, const char *what, insn_t load, insn_t store) {
    const cbae_cir_instruction_t *got = NULL;
    const bool f = cbae_reaching_stores_forwardable(&x->rs, load, &got);
    if (f != (store != NULL) || (store && got != store))
        fprintf(stderr, "FAIL [%s] load #%u: forwardable=%d (store #%u), want %s #%u\n", what,
                load->id, (int)f, got ? got->id : 0u, store ? "store" : "none", store ? store->id : 0u);
    assert(f == (store != NULL));
    if (store) assert(got == store);
    else       assert(got == NULL);
}

/* ── Classification ──────────────────────────────────────────────────── */

static void t_classification(void) {
    static const cbae_cir_opcode_t READONLY[] = {
        CIR_OP_LOAD, CIR_OP_LEA, CIR_OP_MMIO_READ, CIR_OP_PORT_READ, CIR_OP_MSR_READ,
        CIR_OP_PCI_CONFIG_READ, CIR_OP_ADD, CIR_OP_SUB, CIR_OP_MUL, CIR_OP_DIV, CIR_OP_AND,
        CIR_OP_OR, CIR_OP_XOR, CIR_OP_NOT, CIR_OP_NEG, CIR_OP_SHL, CIR_OP_SHR, CIR_OP_SAR,
        CIR_OP_CMP, CIR_OP_TEST, CIR_OP_COPY, CIR_OP_PHI, CIR_OP_BRANCH, CIR_OP_JUMP,
        CIR_OP_RETURN };
    static const cbae_cir_opcode_t BARRIERS[] = {
        CIR_OP_INVALID, CIR_OP_CALL, CIR_OP_API_CALL, CIR_OP_PUSH, CIR_OP_POP,
        CIR_OP_MMIO_WRITE, CIR_OP_PORT_WRITE, CIR_OP_MSR_WRITE, CIR_OP_PCI_CONFIG_WRITE,
        CIR_OP_SPINLOCK_ACQUIRE, CIR_OP_SPINLOCK_RELEASE, CIR_OP_MUTEX_LOCK, CIR_OP_MUTEX_UNLOCK,
        CIR_OP_WAIT, CIR_OP_IRQ_REGISTER, CIR_OP_IRQ_UNREGISTER, CIR_OP_IRQ_HANDLER_ENTRY,
        CIR_OP_IRQ_HANDLER_EXIT, CIR_OP_DPC_CALL, CIR_OP_DMA_ALLOC, CIR_OP_DMA_FREE,
        CIR_OP_DMA_MAP, CIR_OP_DMA_SYNC, CIR_OP_POWER_STATE_ENTER, CIR_OP_POWER_STATE_EXIT };
    const unsigned nro = sizeof READONLY / sizeof READONLY[0];
    const unsigned nbar = sizeof BARRIERS / sizeof BARRIERS[0];

    for (unsigned i = 0; i < nro; i++)
        assert(cbae_rs_classify_opcode(READONLY[i]) == CBAE_RS_OP_READONLY);
    for (unsigned i = 0; i < nbar; i++)
        assert(cbae_rs_classify_opcode(BARRIERS[i]) == CBAE_RS_OP_BARRIER);
    assert(cbae_rs_classify_opcode(CIR_OP_STORE) == CBAE_RS_OP_STORE);

    /* Every opcode is in exactly one list: a new opcode must be classified on
     * purpose, and until it is, it is a barrier (default-deny). */
    assert(nro + nbar + 1 == (unsigned)CIR_OP_COUNT);
    for (int op = 0; op < (int)CIR_OP_COUNT; op++) {
        unsigned hits = op == CIR_OP_STORE;
        for (unsigned i = 0; i < nro; i++)  hits += READONLY[i] == (cbae_cir_opcode_t)op;
        for (unsigned i = 0; i < nbar; i++) hits += BARRIERS[i] == (cbae_cir_opcode_t)op;
        assert(hits == 1);
    }
    assert(cbae_rs_classify_opcode(CIR_OP_COUNT) == CBAE_RS_OP_BARRIER);
    assert(cbae_rs_classify_opcode((cbae_cir_opcode_t)255) == CBAE_RS_OP_BARRIER);
    assert(cbae_rs_classify_opcode((cbae_cir_opcode_t)-1) == CBAE_RS_OP_BARRIER);
    printf("  [PASS] opcode classes: 25 read-only, STORE, every other opcode (and any unknown one) a barrier\n");
}

/* ── Straight line ───────────────────────────────────────────────────── */

static void t_straight_line(void) {
    /*   b0: p, q = params ; sA = store [p] ; sB = store [p+8] ; l1 = load [p]
     *       sC = store [p] ; l2 = load [p] ; l3 = load [p+8] (fresh add) ; l4 = load [q]
     *
     *   l1: backwards sB is [p+8] (disjoint: NO), then sA is the load's own
     *       range and covers every byte -> {sA}, nothing initial.
     *   l2: sC covers it at once -> {sC}.
     *   l3: sC is [p] (NO), sB is the same range -> {sB}.
     *   l4: [q] may be anywhere relative to p: sC and sB may overlap it. sA is
     *       hidden by sC (same bytes, later). Nothing covers [q], so its
     *       initial content is possible. -> {sB, sC}, initial.                 */
    fn_t x; fn_init(&x, "straight");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
    cbae_cir_value_t *c1 = k_const(b, 1), *c2 = k_const(b, 2), *c3 = k_const(b, 3), *c8 = k_const(b, 8);
    cbae_cir_value_t *p8 = k_add(b, p, c8);
    insn_t sA = k_store(b, p, c1);
    insn_t sB = k_store(b, p8, c2);
    cbae_cir_value_t *l1 = k_load(b, p);
    insn_t sC = k_store(b, p, c3);
    cbae_cir_value_t *l2 = k_load(b, p);
    cbae_cir_value_t *p8b = k_add(b, p, c8);
    cbae_cir_value_t *l3 = k_load(b, p8b);
    cbae_cir_value_t *l4 = k_load(b, q);
    cbae_cir_return(b, l4, 0);

    rsx_t r; rsx_build(&r, &x);
    reaches(&r, "l1", k_def(l1), SET(sA), false);
    reaches(&r, "l2", k_def(l2), SET(sC), false);
    reaches(&r, "l3", k_def(l3), SET(sB), false);
    reaches(&r, "l4", k_def(l4), SET(sB, sC), true);
    forwards(&r, "l1", k_def(l1), sA);
    forwards(&r, "l2", k_def(l2), sC);
    forwards(&r, "l3", k_def(l3), sB);
    forwards(&r, "l4", k_def(l4), NULL);
    assert(cbae_reaching_stores_def_count(&r.rs) == 3);
    rsx_free(&r); fn_done(&x);
    printf("  [PASS] straight line: a store hides earlier stores of its bytes, disjoint offsets never reach\n");
}

static void t_widths(void) {
    /* One base, each scenario at its own offset (so scenarios cannot reach each
     * other). A load is forwardable only from a store of EXACTLY its bytes.
     *   +0    sA, sB both i64 [p], then load i64 [p]: the later store -> {sB}
     *   +64   store i32 [p+64]; load i64 [p+64]: overlap, not identical -> MAY;
     *         the load's own class has no store, so its initial bytes (the
     *         other four) stay possible -> {s}, initial, not forwardable
     *   +128  store i64 [p+128]; load i32 [p+128]: the store covers the load in
     *         truth, but containment is not recognised -> {s}, initial (limit)
     *   +192  store i32; load i32 at the same address -> identical: forwardable
     *   +256  store i64 [p+256]; load i64 [p+260]: partial overlap -> {s}, initial */
    fn_t x; fn_init(&x, "widths");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c1 = k_const(b, 1), *c2 = k_const(b, 2);
    cbae_cir_value_t *v32 = cbae_cir_const(b, T32, 7);
    insn_t sA = k_store(b, p, c1);
    insn_t sB = k_store(b, p, c2);
    cbae_cir_value_t *l0 = k_load(b, p);

    cbae_cir_value_t *a64 = k_add(b, p, k_const(b, 64));
    insn_t s32 = k_store(b, a64, v32);
    cbae_cir_value_t *l64 = k_load(b, k_add(b, p, k_const(b, 64)));

    cbae_cir_value_t *a128 = k_add(b, p, k_const(b, 128));
    insn_t s64 = k_store(b, a128, c1);
    cbae_cir_value_t *l32 = k_load_t(b, k_add(b, p, k_const(b, 128)), T32);

    cbae_cir_value_t *a192 = k_add(b, p, k_const(b, 192));
    insn_t s32b = k_store(b, a192, v32);
    cbae_cir_value_t *l32b = k_load_t(b, k_add(b, p, k_const(b, 192)), T32);

    cbae_cir_value_t *a256 = k_add(b, p, k_const(b, 256));
    insn_t sa = k_store(b, a256, c1);
    cbae_cir_value_t *lb = k_load(b, k_add(b, p, k_const(b, 260)));
    cbae_cir_return(b, NULL, 0);
    (void)sA;

    rsx_t r; rsx_build(&r, &x);
    reaches(&r, "+0 later store wins",              k_def(l0),   SET(sB),  false);
    reaches(&r, "+64 i32 store, i64 load",          k_def(l64),  SET(s32), true);
    reaches(&r, "+128 i64 store, i32 load",         k_def(l32),  SET(s64), true);
    reaches(&r, "+192 same width and address",      k_def(l32b), SET(s32b), false);
    reaches(&r, "+256 partial overlap",             k_def(lb),   SET(sa),  true);
    forwards(&r, "+0",   k_def(l0),   sB);
    forwards(&r, "+64",  k_def(l64),  NULL);
    forwards(&r, "+128", k_def(l32),  NULL);
    forwards(&r, "+192", k_def(l32b), s32b);
    forwards(&r, "+256", k_def(lb),   NULL);
    rsx_free(&r); fn_done(&x);
    printf("  [PASS] widths: only identical ranges forward; partial overwrites keep initial content possible\n");
}

static void t_may_alias_pointers(void) {
    /*   b0: p, q = params ; s1 = store [p] ; s2 = store [q] ; l1 = load [p] ; l2 = load [q]
     *   l1: q may equal p, so s2 may be the last writer; s1 is its own range.
     *       -> {s1, s2}, nothing initial.
     *   l2: s2 is its own range and covers it; s1 (which may have written the
     *       same bytes) is hidden behind s2. -> {s2}.                           */
    fn_t x; fn_init(&x, "mayalias");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
    cbae_cir_value_t *c = k_const(b, 5);
    insn_t s1 = k_store(b, p, c);
    insn_t s2 = k_store(b, q, c);
    cbae_cir_value_t *l1 = k_load(b, p);
    cbae_cir_value_t *l2 = k_load(b, q);
    cbae_cir_return(b, NULL, 0);

    rsx_t r; rsx_build(&r, &x);
    reaches(&r, "l1", k_def(l1), SET(s1, s2), false);
    reaches(&r, "l2", k_def(l2), SET(s2), false);
    forwards(&r, "l1", k_def(l1), NULL);
    forwards(&r, "l2", k_def(l2), s2);
    rsx_free(&r); fn_done(&x);
    printf("  [PASS] different pointers: both stores may reach the first load, the second hides the first\n");
}

static void t_indexed_forwarding(void) {
    /*   b0: p, i = params. Address of the store and of the load are built
     *   separately, each with its own MUL: p + i*8 + 16. Different SSA values,
     *   the same linear form, so the same class.
     *   l1 = load [p + i*8 + 16] -> {s}, forwardable.
     *   l2 = load [p + i*8 + 24] -> disjoint from s: {}, initial.               */
    fn_t x; fn_init(&x, "indexed");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *i = cbae_cir_param(b, CBAE_REG_RCX);
    cbae_cir_value_t *c8 = k_const(b, 8), *v = k_const(b, 9);
    cbae_cir_value_t *a1 = k_add(b, k_add(b, p, k_mul(b, i, c8)), k_const(b, 16));
    insn_t s = k_store(b, a1, v);
    cbae_cir_value_t *a2 = k_add(b, k_add(b, p, k_mul(b, i, c8)), k_const(b, 16));
    cbae_cir_value_t *l1 = k_load(b, a2);
    cbae_cir_value_t *a3 = k_add(b, k_add(b, p, k_mul(b, i, c8)), k_const(b, 24));
    cbae_cir_value_t *l2 = k_load(b, a3);
    cbae_cir_return(b, NULL, 0);

    rsx_t r; rsx_build(&r, &x);
    reaches(&r, "same element", k_def(l1), SET(s), false);
    reaches(&r, "next element",  k_def(l2), EMPTY, true);
    forwards(&r, "same element", k_def(l1), s);
    forwards(&r, "next element", k_def(l2), NULL);
    rsx_free(&r); fn_done(&x);
    printf("  [PASS] indexed addressing: [p+i*8+16] written and read through different MULs forwards\n");
}

/* ── Calls ───────────────────────────────────────────────────────────── */

static void t_calls_in_block(void) {
    /*   b0: p ; s0 = store [p] ; k = call ; l1 = load [p] ; s1 = store [p] ; l2 = load [p]
     *       k2 = call ; l3 = load [p+8]
     *   l1: k is a barrier after s0 -> {s0, k}.
     *   l2: s1 covers every byte; the call before it cannot be the last writer
     *       -> {s1}.
     *   l3: [p+8] is never stored to, so nothing in this function hides a call:
     *       both calls (k before s1 as well) may have written it. s0, s1 are
     *       [p], disjoint. -> {k, k2}, initial.                                 */
    fn_t x; fn_init(&x, "calls_in_block");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c = k_const(b, 5);
    insn_t s0 = k_store(b, p, c);
    insn_t k  = k_call(b, "f");
    cbae_cir_value_t *l1 = k_load(b, p);
    insn_t s1 = k_store(b, p, c);
    cbae_cir_value_t *l2 = k_load(b, p);
    insn_t k2 = k_call(b, "g");
    cbae_cir_value_t *l3 = k_load(b, k_add(b, p, k_const(b, 8)));
    cbae_cir_return(b, NULL, 0);

    rsx_t r; rsx_build(&r, &x);
    reaches(&r, "l1 call after the store", k_def(l1), SET(s0, k), false);
    reaches(&r, "l2 store after the call", k_def(l2), SET(s1), false);
    reaches(&r, "l3 never-stored bytes",   k_def(l3), SET(k, k2), true);
    forwards(&r, "l1", k_def(l1), NULL);
    forwards(&r, "l2", k_def(l2), s1);
    forwards(&r, "l3", k_def(l3), NULL);
    rsx_free(&r); fn_done(&x);
    printf("  [PASS] calls in a block: a store after a call hides it, a call after a store does not\n");
}

static void t_calls_across_blocks(void) {
    cbae_cir_value_t *c;

    {   /* (a) b0: k = call ; jump b1 | b1: s = store [p] ; jump b2 | b2: l = load [p]
         * The store came after the call on the only path: the call cannot be the
         * last writer. The E/F bits exist for exactly this. -> {s}, forwardable. */
        fn_t x; fn_init(&x, "call_then_store");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        c = k_const(b, 5);
        k_call(b, "f");
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        insn_t s = k_store(b, p, c);
        cbae_cir_jump(b, b2, 0);
        fn_at(&x, b2);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "(a) call, store, load", k_def(l), SET(s), false);
        forwards(&r, "(a)", k_def(l), s);
        rsx_free(&r); fn_done(&x);
    }
    {   /* (b) b0: s = store [p] ; k = call ; jump b1 | b1: l = load [p] -> {s, k} */
        fn_t x; fn_init(&x, "store_then_call");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        c = k_const(b, 5);
        insn_t s = k_store(b, p, c);
        insn_t k = k_call(b, "f");
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "(b) store, call, load", k_def(l), SET(s, k), false);
        forwards(&r, "(b)", k_def(l), NULL);
        rsx_free(&r); fn_done(&x);
    }
    {   /* (c) b0: s = store [p] ; jump b1 | b1: k = call ; jump b2 | b2: l = load [p] -> {s, k} */
        fn_t x; fn_init(&x, "store_call_load_3blocks");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        c = k_const(b, 5);
        insn_t s = k_store(b, p, c);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        insn_t k = k_call(b, "f");
        cbae_cir_jump(b, b2, 0);
        fn_at(&x, b2);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "(c)", k_def(l), SET(s, k), false);
        rsx_free(&r); fn_done(&x);
    }
    {   /* (d) b0: branch b1, b2 | b1: k = call ; jump b3 | b2: s = store [p] ; jump b3 | b3: l = load [p]
         * Path via b1: the call ran and nothing covers [p]: the call may be the
         * last writer, and the bytes are still initial. Path via b2: s. -> {k, s}, initial. */
        fn_t x; fn_init(&x, "diamond_call_store");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        c = k_const(b, 5);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, p, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b1);
        insn_t k = k_call(b, "f");
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b2);
        insn_t s = k_store(b, p, c);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b3);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "(d)", k_def(l), SET(k, s), true);
        forwards(&r, "(d)", k_def(l), NULL);
        rsx_free(&r); fn_done(&x);
    }
    {   /* (e) b0: k = call ; branch b1, b2 | b1: s = store [p] ; jump b3 | b2: jump b3 | b3: l = load [p]
         * Path via b2 keeps the call live and the content initial. -> {k, s}, initial. */
        fn_t x; fn_init(&x, "call_diamond_store");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        c = k_const(b, 5);
        insn_t k = k_call(b, "f");
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, p, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b1);
        insn_t s = k_store(b, p, c);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b2);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b3);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "(e)", k_def(l), SET(k, s), true);
        rsx_free(&r); fn_done(&x);
    }
    printf("  [PASS] calls across blocks: store-after-call hides the call; any path that skips the store keeps it\n");
}

/* ── Joins and loops ─────────────────────────────────────────────────── */

static void t_join(void) {
    {   /*   b0: branch b1, b2 | b1: s1 = store [p] | b2: s2 = store [p] | b3: l = load [p]
         *   Both arms store the same bytes: {s1, s2}, nothing initial.           */
        fn_t x; fn_init(&x, "join_both");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c1 = k_const(b, 1), *c2 = k_const(b, 2);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, p, c1, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b1);
        insn_t s1 = k_store(b, p, c1);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b2);
        insn_t s2 = k_store(b, p, c2);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b3);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "both arms store", k_def(l), SET(s1, s2), false);
        forwards(&r, "both arms store", k_def(l), NULL);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   only b1 stores: {s1}, and the content may still be initial (via b2). */
        fn_t x; fn_init(&x, "join_one");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c1 = k_const(b, 1);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, p, c1, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b1);
        insn_t s1 = k_store(b, p, c1);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b2);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b3);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "one arm stores", k_def(l), SET(s1), true);
        forwards(&r, "one arm stores", k_def(l), NULL);
        rsx_free(&r); fn_done(&x);
    }
    printf("  [PASS] joins: both arms store -> both reach, none initial; one arm -> initial stays possible\n");
}

static void t_loops(void) {
    {   /*   b0: p ; jump b1
         *   b1: l1 = load [p] ; s = store [p] ; cmp ; branch b1, b2
         *   b2: l2 = load [p]
         *   l1: first iteration reads initial content, later ones read s -> {s}, initial.
         *   l2: b2 is only entered after b1 ran at least once -> {s}, nothing initial. */
        fn_t x; fn_init(&x, "loop_rw");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        cbae_cir_value_t *l1 = k_load(b, p);
        insn_t s = k_store(b, p, c);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, l1, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b2);
        cbae_cir_value_t *l2 = k_load(b, p);
        cbae_cir_return(b, l2, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "load before the store, in the loop", k_def(l1), SET(s), true);
        reaches(&r, "load after the loop",                k_def(l2), SET(s), false);
        forwards(&r, "in the loop", k_def(l1), NULL);
        forwards(&r, "after the loop", k_def(l2), s);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   b0: s0 = store [p] ; jump b1 | b1: k = call ; l = load [p] ; branch b1, b2 | b2: return
         *   l: the call in this very block, the store from b0, and the call from the
         *   previous iteration (the same instruction) -> {s0, k}, nothing initial. */
        fn_t x; fn_init(&x, "loop_call");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        insn_t s0 = k_store(b, p, c);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        insn_t k = k_call(b, "f");
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, l, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b2);
        cbae_cir_return(b, NULL, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "call in the loop", k_def(l), SET(s0, k), false);
        forwards(&r, "call in the loop", k_def(l), NULL);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   Two stores of one class in a loop body, a load between them.
         *   b1: sa = store [p] ; l = load [p] ; sb = store [p] ; branch b1, b2
         *   l: sa covers it -> {sa}. (sb of the previous iteration is hidden by sa.) */
        fn_t x; fn_init(&x, "loop_two_stores");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        insn_t sa = k_store(b, p, c);
        cbae_cir_value_t *l = k_load(b, p);
        insn_t sb = k_store(b, p, c);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, l, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b2);
        cbae_cir_return(b, NULL, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "store, load, store in a loop", k_def(l), SET(sa), false);
        forwards(&r, "store, load, store in a loop", k_def(l), sa);
        (void)sb;
        rsx_free(&r); fn_done(&x);
    }
    printf("  [PASS] loops: the previous iteration's store reaches, initial content only on the first pass\n");
}

/* ── Addresses the analysis cannot compare ───────────────────────────── */

static void t_unstable_addresses(void) {
    {   /*   b0: p ; s0 = store [p] ; jump b1
         *   b1: i = phi(0, i+8) ; a = p + i ; l = load [a] ; i2 = i + 8 ; cmp ; branch b1, b2
         *   [a] changes every iteration: no class. s0 may or may not be what it reads;
         *   the content may be initial. -> {s0}, initial, not forwardable.       */
        fn_t x; fn_init(&x, "unstable_load");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c0 = k_const(b, 0), *c8 = k_const(b, 8), *c = k_const(b, 5);
        insn_t s0 = k_store(b, p, c);
        cbae_cir_jump(b, b1, 0);
        cbae_cir_value_t *i = cbae_cir_phi_create(x.f, b1, T64);
        fn_at(&x, b1);
        cbae_cir_value_t *a = k_add(b, p, i);
        cbae_cir_value_t *l = k_load(b, a);
        cbae_cir_value_t *i2 = k_add(b, i, c8);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, l, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b2);
        cbae_cir_return(b, NULL, 0);
        assert(cbae_cir_phi_add_incoming(x.f, k_def(i), c0, x.b0->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, k_def(i), i2, b1->id) == CBAE_OK);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "unstable load address", k_def(l), SET(s0), true);
        forwards(&r, "unstable load address", k_def(l), NULL);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   Same loop, plus an unstable STORE and a stable load of [p].
         *   b1: i = phi ; a = p + i ; s1 = store [a] ; l = load [p] ; ...
         *   s1 might write [p] (when i == 0 at run time) and never kills anything.
         *   l: s1 (this block, and from the previous iteration: one definition) and
         *   s0 (b0, still live) -> {s0, s1}, nothing initial (s0 covered it).   */
        fn_t x; fn_init(&x, "unstable_store");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c0 = k_const(b, 0), *c8 = k_const(b, 8), *c = k_const(b, 5);
        insn_t s0 = k_store(b, p, c);
        cbae_cir_jump(b, b1, 0);
        cbae_cir_value_t *i = cbae_cir_phi_create(x.f, b1, T64);
        fn_at(&x, b1);
        cbae_cir_value_t *a = k_add(b, p, i);
        insn_t s1 = k_store(b, a, c);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_value_t *i2 = k_add(b, i, c8);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, l, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b2);
        cbae_cir_return(b, NULL, 0);
        assert(cbae_cir_phi_add_incoming(x.f, k_def(i), c0, x.b0->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, k_def(i), i2, b1->id) == CBAE_OK);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "unstable store", k_def(l), SET(s0, s1), false);
        forwards(&r, "unstable store", k_def(l), NULL);
        rsx_free(&r); fn_done(&x);
    }
    printf("  [PASS] unstable addresses: an unstable load reaches everything possible, an unstable store kills nothing\n");
}

static void t_walk_pruning(void) {
    {   /*   A store of another class, hidden behind a store of the load's bytes in an
         *   earlier block.
         *   b0: s0 = store [p] ; s1 = store [q] ; jump b1
         *   b1: s2 = store [p] ; jump b2
         *   b2: l = load [p]
         *   s2 rewrote [p]; if q == p then s1's bytes were s2's too. Exact: {s2}.
         *   (The dataflow alone keeps s1; the backward walk from b2 stops at s2 in
         *   b1 and never sees b0.)                                                  */
        fn_t x; fn_init(&x, "walk_other_class");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
        cbae_cir_value_t *c = k_const(b, 5);
        k_store(b, p, c);
        k_store(b, q, c);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        insn_t s2 = k_store(b, p, c);
        cbae_cir_jump(b, b2, 0);
        fn_at(&x, b2);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "other class behind a covering store", k_def(l), SET(s2), false);
        forwards(&r, "other class behind a covering store", k_def(l), s2);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   A call before the store, another after it.
         *   b0: k1 = call ; s = store [p] ; k2 = call ; jump b1 | b1: l = load [p]
         *   k1 ran before s rewrote the bytes: it cannot be the last writer.
         *   The F bit is set (k2), so the dataflow alone keeps both calls. -> {s, k2}. */
        fn_t x; fn_init(&x, "walk_two_calls");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        k_call(b, "f");
        insn_t s  = k_store(b, p, c);
        insn_t k2 = k_call(b, "g");
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "call before the store is hidden", k_def(l), SET(s, k2), false);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   Both arms of a diamond store; one of them calls afterwards.
         *   b0: k1 = call ; branch b1, b2
         *   b1: s1 = store [p] ; k2 = call ; jump b3
         *   b2: s2 = store [p] ; jump b3
         *   b3: l = load [p]
         *   Every path from k1 to l passes a store of [p]: k1 is hidden. -> {s1, k2, s2}. */
        fn_t x; fn_init(&x, "walk_diamond");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        k_call(b, "f");
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, p, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b1);
        insn_t s1 = k_store(b, p, c);
        insn_t k2 = k_call(b, "g");
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b2);
        insn_t s2 = k_store(b, p, c);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b3);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "diamond, both arms store", k_def(l), SET(s1, k2, s2), false);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   The same diamond where one arm does NOT store: k1 reaches through it.
         *   b2: k3 = call ; jump b3 instead of the store. -> {k1, s1, k2, k3}, initial. */
        fn_t x; fn_init(&x, "walk_diamond_open");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        insn_t k1 = k_call(b, "f");
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, p, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b1);
        insn_t s1 = k_store(b, p, c);
        insn_t k2 = k_call(b, "g");
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b2);
        insn_t k3 = k_call(b, "h");
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b3);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "diamond, one arm open", k_def(l), SET(k1, s1, k2, k3), true);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   A loop entered at its header; the class store sits at the END of the body, after the load.
         *   b0: k0 = call ; jump b1
         *   b1: l = load [p] ; s = store [p] ; k1 = call ; cmp ; branch b1, b2
         *   l: k0 on the way in, and s then k1 around the back edge. The walk must
         *   scan b1 in full, from k1 up to s. -> {k0, s, k1}, initial (first pass). */
        fn_t x; fn_init(&x, "walk_loop_tail");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        insn_t k0 = k_call(b, "f");
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        cbae_cir_value_t *l = k_load(b, p);
        insn_t s  = k_store(b, p, c);
        insn_t k1 = k_call(b, "g");
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, l, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b2);
        cbae_cir_return(b, NULL, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "loop, store at the tail", k_def(l), SET(k0, s, k1), true);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   A call before the first store of a loop-carried class:
         *   b0: k0 = call ; s0 = store [p] ; jump b1
         *   b1: k1 = call ; l = load [p] ; branch b1, b2
         *   k0 is before s0: hidden. -> {s0, k1}, nothing initial.                  */
        fn_t x; fn_init(&x, "walk_loop_head");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        k_call(b, "f");
        insn_t s0 = k_store(b, p, c);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        insn_t k1 = k_call(b, "g");
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, l, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b2);
        cbae_cir_return(b, NULL, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "loop head, call before the store", k_def(l), SET(s0, k1), false);
        rsx_free(&r); fn_done(&x);
    }
    printf("  [PASS] backward walk: definitions hidden behind a store of the load's bytes are dropped, loops and diamonds included\n");
}

static void t_cross_block_filters(void) {
    {   /*   A later store of the same bytes hides an earlier one even from a load of
         *   OTHER bytes that may overlap them, where no covering test applies.
         *   b0: s1 = store [p] ; jump b1
         *   b1: s2 = store [p] ; jump b2
         *   b2: l = load [q]                     q is unrelated to p
         *   s2 rewrote every byte s1 wrote: s1 is the last writer of nothing. [q] has no
         *   store of its own, so its initial bytes stay possible. -> {s2}, initial.   */
        fn_t x; fn_init(&x, "cross_kill");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
        cbae_cir_value_t *c = k_const(b, 5);
        k_store(b, p, c);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        insn_t s2 = k_store(b, p, c);
        cbae_cir_jump(b, b2, 0);
        fn_at(&x, b2);
        cbae_cir_value_t *l = k_load(b, q);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "kill across blocks, other bytes", k_def(l), SET(s2), true);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   ... but only along the paths that pass the second store.
         *   b0: s1 = store [p] ; branch b1, b2
         *   b1: s2 = store [p] ; jump b3          b2: jump b3
         *   b3: l = load [q]
         *   Through b2 s1 is untouched. -> {s1, s2}, initial.                         */
        fn_t x; fn_init(&x, "cross_kill_open");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
        cbae_cir_value_t *c = k_const(b, 5);
        insn_t s1 = k_store(b, p, c);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, p, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b1);
        insn_t s2 = k_store(b, p, c);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b2);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b3);
        cbae_cir_value_t *l = k_load(b, q);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "kill on one path only", k_def(l), SET(s1, s2), true);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   A store of an EARLIER block that provably writes other bytes is not in the
         *   answer, and one that may write the same bytes is.
         *   b0: s1 = store [p+8] ; s3 = store [r] ; jump b1       r unrelated to p
         *   b1: l = load [p]                                      nothing ever stores [p]
         *   s1 is [p+8], disjoint from [p]: NO. s3 may alias. [p] is never stored to, so it
         *   may still hold its initial bytes. -> {s3}, initial.                         */
        fn_t x; fn_init(&x, "cross_disjoint");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *rr = cbae_cir_param(b, CBAE_REG_RCX);
        cbae_cir_value_t *c = k_const(b, 5);
        k_store(b, k_add(b, p, k_const(b, 8)), c);
        insn_t s3 = k_store(b, rr, c);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "disjoint store of an earlier block", k_def(l), SET(s3), true);
        forwards(&r, "disjoint store of an earlier block", k_def(l), NULL);
        rsx_free(&r); fn_done(&x);
    }
    printf("  [PASS] filters across blocks: a later store of the same bytes kills on the paths it covers, disjoint stores are dropped\n");
}

/* A STORE to a second slot, repeated: a block of `n` definitions that is neither a
 * barrier nor in any answer for [p] (offset 8 is provably disjoint), so it costs
 * the backward walk its budget and nothing else. */
static void filler_stores(fn_t *x, cbae_cir_value_t *p, cbae_cir_value_t *c, uint32_t n) {
    cbae_cir_builder_t *b = &x->bld;
    cbae_cir_value_t *a = k_add(b, p, k_const(b, 8));
    for (uint32_t i = 0; i < n; i++) k_store(b, a, c);
}

static void t_budget_fallback_filters(void) {
    /*   When the walk runs out of budget the answer is the dataflow's, and what the
     *   dataflow keeps of a barrier is decided by the F bit alone. These pin the F
     *   bit's life cycle; each is exactly what the walk would also have found.
     *
     *   (a) the call and the store in ONE block, store last:
     *   b0: k0 = call ; s = store [p] ; jump b1
     *   b1: 70000 stores to [p+8] ; jump b2
     *   b2: l = load [p]
     *   The store clears the F bit the call set. No barrier since, so F is clear at
     *   b2 and k0 is dropped. -> {s}, nothing initial, forwardable.
     *
     *   (b) the call BEFORE the block that stores:
     *   b0: k0 = call ; jump b1       b1: s = store [p] ; jump b2
     *   b2: 70000 stores to [p+8] ; jump b3      b3: l = load [p]
     *   F arrives at b1 set and the store kills it. -> {s}, nothing initial.
     *
     *   (c) a call AFTER the store, past the filler: F must survive.
     *   b0: s = store [p] ; jump b1     b1: 70000 stores to [p+8] ; k1 = call ; jump b2
     *   b2: l = load [p]                -> {s, k1}, nothing initial.               */
    const uint32_t N = 70000;
    assert(N > CBAE_RS_WALK_BUDGET);
    {
        fn_t x; fn_init_sized(&x, "budget_f_same_block", 96u << 20);
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        k_call(b, "f");
        insn_t s = k_store(b, p, c);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        filler_stores(&x, p, c, N);
        cbae_cir_jump(b, b2, 0);
        fn_at(&x, b2);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "F cleared by a store later in the same block", k_def(l), SET(s), false);
        forwards(&r, "F cleared by a store later in the same block", k_def(l), s);
        rsx_free(&r); fn_done(&x);
    }
    {
        fn_t x; fn_init_sized(&x, "budget_f_earlier_block", 96u << 20);
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        k_call(b, "f");
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        insn_t s = k_store(b, p, c);
        cbae_cir_jump(b, b2, 0);
        fn_at(&x, b2);
        filler_stores(&x, p, c, N);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b3);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "F killed by a store in a later block", k_def(l), SET(s), false);
        forwards(&r, "F killed by a store in a later block", k_def(l), s);
        rsx_free(&r); fn_done(&x);
    }
    {
        fn_t x; fn_init_sized(&x, "budget_f_survives", 96u << 20);
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        insn_t s = k_store(b, p, c);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        filler_stores(&x, p, c, N);
        insn_t k1 = k_call(b, "g");
        cbae_cir_jump(b, b2, 0);
        fn_at(&x, b2);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "F set by a call after the store", k_def(l), SET(s, k1), false);
        forwards(&r, "F set by a call after the store", k_def(l), NULL);
        rsx_free(&r); fn_done(&x);
    }
    printf("  [PASS] work budget, filters alone: a barrier survives exactly when it ran after the last store of the load's bytes\n");
}

static void t_budget_fallback(void) {
    /*   b0: k0 = call ; s = store [p] ; jump b1
     *   b1: 70000 calls ; l = load [p] ; branch b1, b2
     *   The exact answer drops k0 (it ran before s). Proving that needs the walk to
     *   scan b1, which is longer than CBAE_RS_WALK_BUDGET: the query falls back to
     *   the unrefined set, which still contains k0 and is otherwise the same:
     *   70000 calls + s + k0.                                                       */
    const uint32_t NCALLS = 70000;
    assert(NCALLS > CBAE_RS_WALK_BUDGET);
    fn_t x; fn_init_sized(&x, "budget", 96u << 20);
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c = k_const(b, 5);
    insn_t k0 = k_call(b, "f");
    insn_t s  = k_store(b, p, c);
    cbae_cir_jump(b, b1, 0);
    fn_at(&x, b1);
    for (uint32_t i = 0; i < NCALLS; i++) k_call(b, "g");
    cbae_cir_value_t *l = k_load(b, p);
    cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, l, c, cir_type_i1(), 0);
    cbae_cir_branch(b, cond, b1, b2, 0);
    fn_at(&x, b2);
    cbae_cir_return(b, NULL, 0);

    rsx_t r; rsx_build(&r, &x);
    uint32_t n = 0; bool init = true;
    assert(cbae_reaching_stores_for_load(&r.rs, k_def(l), NULL, 0, &n, &init) == CBAE_OK);
    assert(n == NCALLS + 2 && !init);
    const cbae_rs_def_t **all = malloc(n * sizeof *all);
    assert(all);
    assert(cbae_reaching_stores_for_load(&r.rs, k_def(l), all, n, &n, &init) == CBAE_OK);
    bool has_k0 = false, has_s = false;
    for (uint32_t i = 0; i < n; i++) { has_k0 |= all[i]->insn == k0; has_s |= all[i]->insn == s; }
    assert(has_k0 && has_s);
    free(all);
    rsx_free(&r); fn_done(&x);
    printf("  [PASS] work budget: a walk longer than CBAE_RS_WALK_BUDGET falls back to the unrefined (sound) set\n");
}

static void t_documented_limits(void) {
    {   /*   LIMIT 1: a definition that escapes the kill on one path and the cover on
         *   another is kept, although no single path lets it through.
         *   b0: s1 = store [q] ; branch b1, b2
         *   b1: s1b = store [q] ; jump b3        (path A: s1b overwrites s1)
         *   b2: s2  = store [p] ; jump b3        (path B: s2 overwrites [p])
         *   b3: l = load [p]
         *   Exact: {s1b, s2}, and [p] may still be initial (path A never stores to
         *   it unless q == p). The dataflow keeps s1 because path B has no store of
         *   [q]; the walk keeps it because path A has no store of [p]. Each test
         *   is about a different path. Sound, one definition too many.             */
        fn_t x; fn_init(&x, "limit_joint_path");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
        cbae_cir_value_t *c = k_const(b, 5);
        insn_t s1 = k_store(b, q, c);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, p, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b1);
        insn_t s1b = k_store(b, q, c);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b2);
        insn_t s2 = k_store(b, p, c);
        cbae_cir_jump(b, b3, 0);
        fn_at(&x, b3);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "joint-path (limit)", k_def(l), SET(s1, s1b, s2), true);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   Inside ONE block the local scan is exact: s2 covers the load, s0 and the
         *   other-class store s1 are behind it. (Context for the limit above: only
         *   the cross-block case needs the dataflow and the walk.)                  */
        fn_t x; fn_init(&x, "same_block_exact");
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
        cbae_cir_value_t *c = k_const(b, 5);
        k_store(b, p, c);
        k_store(b, q, c);
        insn_t s2 = k_store(b, p, c);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "other class, same block", k_def(l), SET(s2), false);
        forwards(&r, "other class, same block", k_def(l), s2);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   LIMIT 2: two accesses through the same SSA value that is redefined every loop
         *   iteration are never provably the same (see alias_analysis.h), so a store
         *   and a load through one loop-carried pointer do not forward.
         *   b1: i = phi ; a = p + i ; s = store [a] ; l = load [a] ; ...
         *   -> {s} and initial, not forwardable.                                 */
        fn_t x; fn_init(&x, "limit_loop_pointer");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c0 = k_const(b, 0), *c8 = k_const(b, 8), *c = k_const(b, 5);
        cbae_cir_jump(b, b1, 0);
        cbae_cir_value_t *i = cbae_cir_phi_create(x.f, b1, T64);
        fn_at(&x, b1);
        cbae_cir_value_t *a = k_add(b, p, i);
        insn_t s = k_store(b, a, c);
        cbae_cir_value_t *l = k_load(b, a);
        cbae_cir_value_t *i2 = k_add(b, i, c8);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, l, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b2);
        cbae_cir_return(b, NULL, 0);
        assert(cbae_cir_phi_add_incoming(x.f, k_def(i), c0, x.b0->id) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(x.f, k_def(i), i2, b1->id) == CBAE_OK);
        rsx_t r; rsx_build(&r, &x);
        reaches(&r, "loop-carried pointer (limit)", k_def(l), SET(s), true);
        forwards(&r, "loop-carried pointer (limit)", k_def(l), NULL);
        rsx_free(&r); fn_done(&x);
    }
    printf("  [PASS] documented limits hold exactly: the joint-path over-approximation, loop pointers do not forward\n");
}

/* ── Opcode kinds, malformed input, reachability ─────────────────────── */

static void t_barrier_kinds(void) {
    /*   b0: p, c ; s = store [p] ; w = port_write ; r = mmio_read [p] (read-only) ;
     *       u = push ; a = api_call ; l = load [p]
     *   Writers: s, w, u, a -- r is not one. l: s covers it, the three barriers
     *   came after s -> {s, w, u, a}. Four definitions in all.                  */
    fn_t x; fn_init(&x, "barrier_kinds");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c = k_const(b, 5);
    insn_t s = k_store(b, p, c);
    cbae_cir_value_t *wops[2] = { c, c };
    insn_t w = k_raw(b, CIR_OP_PORT_WRITE, wops, 2);
    cbae_cir_value_t *rops[1] = { p };
    cbae_cir_value_t *rv = cbae_cir_emit(b, CIR_OP_MMIO_READ, T64, 0, rops, 1);
    assert(rv);
    cbae_cir_value_t *uops[1] = { c };
    insn_t u = k_raw(b, CIR_OP_PUSH, uops, 1);
    cbae_cir_value_t *aops[1] = { p };
    cbae_cir_value_t *av = cbae_cir_emit(b, CIR_OP_API_CALL, T64, 0, aops, 1);
    assert(av);
    insn_t a = k_def(av);
    cbae_cir_value_t *l = k_load(b, p);
    cbae_cir_return(b, l, 0);

    rsx_t r; rsx_build(&r, &x);
    assert(cbae_reaching_stores_def_count(&r.rs) == 4);
    assert(cbae_reaching_stores_def_of(&r.rs, k_def(rv)) == NULL);
    assert(cbae_reaching_stores_def_of(&r.rs, w) && cbae_reaching_stores_def_of(&r.rs, w)->is_barrier);
    assert(cbae_reaching_stores_def_of(&r.rs, u) && cbae_reaching_stores_def_of(&r.rs, u)->is_barrier);
    assert(cbae_reaching_stores_def_of(&r.rs, a) && cbae_reaching_stores_def_of(&r.rs, a)->is_barrier);
    assert(cbae_reaching_stores_def_of(&r.rs, s) && !cbae_reaching_stores_def_of(&r.rs, s)->is_barrier);
    reaches(&r, "store then port write, push, api call", k_def(l), SET(s, w, u, a), false);
    forwards(&r, "barriers after the store", k_def(l), NULL);
    rsx_free(&r); fn_done(&x);
    printf("  [PASS] barrier kinds: port write, push and api call write; mmio read does not\n");
}

static void t_malformed(void) {
    /*   A STORE with one operand, and a STORE whose value is missing, cannot be
     *   said to write anywhere in particular: both are barriers. A LOAD with no
     *   address is a load of unknown bytes: it can be anything, nothing hides it.
     *   b0: p ; s = store [p] ; m1 = store(p) ; m2 = store(p, NULL) ; l = load [p] ; ln = load(NULL)
     *   l : s covers it; m1 and m2 came after -> {s, m1, m2}.
     *   ln: every definition may be what it reads, and it may be initial.        */
    fn_t x; fn_init(&x, "malformed");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c = k_const(b, 5);
    insn_t s = k_store(b, p, c);
    cbae_cir_value_t *ops1[1] = { p };
    insn_t m1 = k_raw(b, CIR_OP_STORE, ops1, 1);
    cbae_cir_value_t *ops2[2] = { p, c };
    cbae_cir_instruction_t *m2w = k_raw(b, CIR_OP_STORE, ops2, 2);
    m2w->operands[1] = NULL;                                  /* the builder refuses a NULL operand: it is put in afterwards */
    insn_t m2 = m2w;
    cbae_cir_value_t *l = k_load(b, p);
    cbae_cir_value_t *nops[1] = { p };
    cbae_cir_value_t *ln = cbae_cir_emit(b, CIR_OP_LOAD, T64, 0, nops, 1);
    assert(ln);
    k_def(ln)->operands[0] = NULL;
    cbae_cir_return(b, NULL, 0);

    rsx_t r; rsx_build_unchecked(&r, x.f);
    assert(cbae_reaching_stores_def_of(&r.rs, m1)->is_barrier);
    assert(cbae_reaching_stores_def_of(&r.rs, m2)->is_barrier);
    assert(!cbae_reaching_stores_def_of(&r.rs, s)->is_barrier);
    reaches(&r, "after malformed stores", k_def(l), SET(s, m1, m2), false);
    reaches(&r, "load with no address",   k_def(ln), SET(s, m1, m2), true);
    forwards(&r, "malformed", k_def(l), NULL);
    forwards(&r, "no address", k_def(ln), NULL);
    rsx_free(&r); fn_done(&x);

    {   /*   An operand count that says one although a second operand is still in its
         *   slot: the count rules, the stale slot is not a value being stored.
         *   b0: s = store [p], c  (operand_count then set to 1) ; l = load [p]
         *   s is a barrier: -> {s}, initial.                                         */
        fn_t y; fn_init(&y, "malformed_count");
        cbae_cir_builder_t *c0 = &y.bld;
        cbae_cir_value_t *q = cbae_cir_param(c0, CBAE_REG_RBX);
        cbae_cir_value_t *v = k_const(c0, 5);
        cbae_cir_instruction_t *st = k_store(c0, q, v);
        assert(st->operand_count == 2 && st->operands[1] == v);
        st->operand_count = 1;
        cbae_cir_value_t *ld = k_load(c0, q);
        cbae_cir_return(c0, NULL, 0);
        rsx_t r2; rsx_build_unchecked(&r2, y.f);
        assert(cbae_reaching_stores_def_of(&r2.rs, st)->is_barrier);
        reaches(&r2, "store with operand count 1", k_def(ld), SET(st), true);
        forwards(&r2, "store with operand count 1", k_def(ld), NULL);
        rsx_free(&r2); fn_done(&y);
    }
    printf("  [PASS] malformed instructions: unreadable stores are barriers, an addressless load reaches everything\n");
}

static void t_unreachable(void) {
    /*   b0: s0 = store [p] ; return        b1 (nothing enters it): l = load [p] ; return
     *   Nothing executes b1: no definition reaches it and nothing is initial there. */
    fn_t x; fn_init(&x, "unreachable");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c = k_const(b, 5);
    k_store(b, p, c);
    cbae_cir_return(b, NULL, 0);
    fn_at(&x, b1);
    cbae_cir_value_t *l = k_load(b, p);
    cbae_cir_return(b, l, 0);

    rsx_t r; rsx_build(&r, &x);
    reaches(&r, "load in unreachable code", k_def(l), EMPTY, false);
    forwards(&r, "unreachable", k_def(l), NULL);
    rsx_free(&r); fn_done(&x);

    {   /*   Writes inside unreachable code do not reach the load either:
         *   b0: p ; k0 = call ; jump b1       b1 (nothing enters it): k = call ; s = store [p] ;
         *   l = load [p] ; return
         *   The block never runs. Its own call and store are not an answer.            */
        fn_t y; fn_init(&y, "unreachable_writes");
        cbae_cir_block_t *u = fn_block(&y, 0x1010);
        cbae_cir_builder_t *b = &y.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        insn_t k0 = k_call(b, "f");
        cbae_cir_return(b, NULL, 0);
        fn_at(&y, u);
        insn_t k = k_call(b, "g");
        insn_t s = k_store(b, p, c);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r2; rsx_build(&r2, &y);
        reaches(&r2, "writes before a load in unreachable code", k_def(l), EMPTY, false);
        forwards(&r2, "writes before a load in unreachable code", k_def(l), NULL);
        assert(!cbae_reaching_stores_may_reach(&r2.rs, k_def(l), k));      /* nothing reaches a block that never runs */
        assert(!cbae_reaching_stores_may_reach(&r2.rs, k_def(l), s));
        assert(!cbae_reaching_stores_may_reach(&r2.rs, s, k));
        assert(!cbae_reaching_stores_may_reach(&r2.rs, k_def(l), k0));
        rsx_free(&r2); fn_done(&y);
    }
    {   /*   ... nor does what unreachable code writes flow into code that runs:
         *   b0: s0 = store [p] ; jump b2
         *   b1 (nothing enters it): s1 = store [p] ; k1 = call ; jump b2
         *   b2: l = load [p]
         *   Only s0 runs before l. -> {s0}, nothing initial, forwardable.             */
        fn_t y; fn_init(&y, "unreachable_feeds_reachable");
        cbae_cir_block_t *u = fn_block(&y, 0x1010), *j = fn_block(&y, 0x1020);
        cbae_cir_builder_t *b = &y.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        insn_t s0 = k_store(b, p, c);
        cbae_cir_jump(b, j, 0);
        fn_at(&y, u);
        k_store(b, p, c);
        k_call(b, "g");
        cbae_cir_jump(b, j, 0);
        fn_at(&y, j);
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, l, 0);
        rsx_t r2; rsx_build(&r2, &y);
        reaches(&r2, "unreachable predecessor", k_def(l), SET(s0), false);
        forwards(&r2, "unreachable predecessor", k_def(l), s0);
        rsx_free(&r2); fn_done(&y);
    }
    printf("  [PASS] unreachable code: empty answers, nothing initial, and nothing it writes reaches code that runs\n");
}

/* ── The raw fact ────────────────────────────────────────────────────── */

static void expect_reach(const rsx_t *x, insn_t at, insn_t def, bool want) {
    const bool g = cbae_reaching_stores_may_reach(&x->rs, at, def);
    if (g != want)
        fprintf(stderr, "FAIL may_reach: before #%u, definition #%u: want %d, got %d\n",
                at->id, def->id, (int)want, (int)g);
    assert(g == want);
}

static void t_may_reach(void) {
    {   /*   b0: p ; s1 = store [p] ; s2 = store [p] ; k = call ; l = load [p] ; return
         *   Before s1: nothing has run.               s1 no,  s2 no,  k no
         *   Before s2: s1 ran.                        s1 yes, s2 no,  k no
         *   Before k : s2 overwrote s1.               s1 no,  s2 yes, k no
         *   Before l : s2 and k.                      s1 no,  s2 yes, k yes
         *   Before the return: same (a load writes nothing).                    */
        fn_t x; fn_init(&x, "may_reach");
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        insn_t s1 = k_store(b, p, c);
        insn_t s2 = k_store(b, p, c);
        insn_t k  = k_call(b, "f");
        cbae_cir_value_t *l = k_load(b, p);
        cbae_cir_return(b, NULL, 0);
        insn_t ret = k_last(b);

        rsx_t r; rsx_build(&r, &x);
        expect_reach(&r, s1, s1, false); expect_reach(&r, s1, s2, false); expect_reach(&r, s1, k, false);
        expect_reach(&r, s2, s1, true);  expect_reach(&r, s2, s2, false); expect_reach(&r, s2, k, false);
        expect_reach(&r, k,  s1, false); expect_reach(&r, k,  s2, true);  expect_reach(&r, k,  k, false);
        expect_reach(&r, k_def(l), s1, false); expect_reach(&r, k_def(l), s2, true);
        expect_reach(&r, k_def(l), k, true);
        expect_reach(&r, ret, s1, false); expect_reach(&r, ret, s2, true); expect_reach(&r, ret, k, true);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   A loop: b1: sa = store [p] ; sb = store [p] ; cmp ; branch b1, b2 ; b2: return
         *   IN[b1] = {sb} (the previous iteration's last store; sa is hidden behind it).
         *   Before sa : sb yes, sa no.     Before sb : sa yes, sb no (sa rewrote it).
         *   Before cmp: sb yes, sa no.     In b2     : sb yes, sa no.             */
        fn_t x; fn_init(&x, "may_reach_loop");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        insn_t sa = k_store(b, p, c);
        insn_t sb = k_store(b, p, c);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, p, c, cir_type_i1(), 0);
        insn_t cmp = k_def(cond);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b2);
        cbae_cir_return(b, NULL, 0);
        insn_t ret = k_last(b);

        rsx_t r; rsx_build(&r, &x);
        expect_reach(&r, sa, sa, false);  expect_reach(&r, sa, sb, true);
        expect_reach(&r, sb, sa, true);   expect_reach(&r, sb, sb, false);
        expect_reach(&r, cmp, sa, false); expect_reach(&r, cmp, sb, true);
        expect_reach(&r, ret, sa, false); expect_reach(&r, ret, sb, true);
        rsx_free(&r); fn_done(&x);
    }
    {   /*   A lone store in a loop reaches itself around the back edge. */
        fn_t x; fn_init(&x, "may_reach_self");
        cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020);
        cbae_cir_builder_t *b = &x.bld;
        cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
        cbae_cir_value_t *c = k_const(b, 5);
        cbae_cir_jump(b, b1, 0);
        fn_at(&x, b1);
        insn_t s = k_store(b, p, c);
        cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, p, c, cir_type_i1(), 0);
        cbae_cir_branch(b, cond, b1, b2, 0);
        fn_at(&x, b2);
        cbae_cir_return(b, NULL, 0);
        rsx_t r; rsx_build(&r, &x);
        expect_reach(&r, s, s, true);
        expect_reach(&r, k_def(cond), s, true);
        rsx_free(&r); fn_done(&x);
    }
    printf("  [PASS] may_reach: replays each block's effects; a store reaches itself only around a loop\n");
}

/* ── API edges ───────────────────────────────────────────────────────── */

static void t_api(void) {
    fn_t x; fn_init(&x, "api");
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
    cbae_cir_value_t *c = k_const(b, 5);
    insn_t s1 = k_store(b, p, c);
    insn_t s2 = k_store(b, k_add(b, p, k_const(b, 8)), c);
    insn_t k  = k_call(b, "f");
    cbae_cir_value_t *l = k_load(b, q);                /* may be anything: {s1, s2, k}, initial */
    cbae_cir_value_t *sum = k_add(b, l, c);
    cbae_cir_return(b, sum, 0);
    insn_t load = k_def(l);

    rsx_t r; rsx_build(&r, &x);
    reaches(&r, "api load", load, SET(s1, s2, k), true);

    /* The total is reported even when the buffer is short or absent. */
    uint32_t n = 99; bool init = false;
    assert(cbae_reaching_stores_for_load(&r.rs, load, NULL, 0, &n, &init) == CBAE_OK);
    assert(n == 3 && init);
    const cbae_rs_def_t *two[2] = { NULL, NULL };
    n = 0;
    assert(cbae_reaching_stores_for_load(&r.rs, load, two, 2, &n, NULL) == CBAE_OK);
    assert(n == 3 && two[0]->insn == s1 && two[1]->insn == s2);
    assert(cbae_reaching_stores_for_load(&r.rs, load, NULL, 0, NULL, NULL) == CBAE_OK);

    /* What is not a LOAD of this function is refused, and the outputs say nothing. */
    n = 7; init = true;
    assert(cbae_reaching_stores_for_load(&r.rs, s1, NULL, 0, &n, &init) == CBAE_ERR_INVALID);
    assert(n == 0 && !init);
    assert(cbae_reaching_stores_for_load(&r.rs, NULL, NULL, 0, &n, &init) == CBAE_ERR_INVALID);
    assert(cbae_reaching_stores_for_load(NULL, load, NULL, 0, &n, &init) == CBAE_ERR_INVALID);
    fn_t y; fn_init(&y, "other");
    cbae_cir_value_t *yp = cbae_cir_param(&y.bld, CBAE_REG_RBX);
    cbae_cir_value_t *yl = k_load(&y.bld, yp);
    k_store(&y.bld, yp, k_const(&y.bld, 1));
    cbae_cir_return(&y.bld, yl, 0);
    assert(cbae_reaching_stores_for_load(&r.rs, k_def(yl), NULL, 0, &n, &init) == CBAE_ERR_INVALID);
    assert(!cbae_reaching_stores_forwardable(&r.rs, k_def(yl), NULL));
    assert(!cbae_reaching_stores_forwardable(&r.rs, s1, NULL));
    assert(!cbae_reaching_stores_forwardable(NULL, load, NULL));

    /* The definition table. */
    assert(cbae_reaching_stores_def_count(&r.rs) == 3);
    assert(cbae_reaching_stores_def(&r.rs, 0)->insn == s1 && cbae_reaching_stores_def(&r.rs, 0)->block_id == 0);
    assert(cbae_reaching_stores_def(&r.rs, 2)->insn == k  && cbae_reaching_stores_def(&r.rs, 2)->is_barrier);
    assert(cbae_reaching_stores_def(&r.rs, 3) == NULL);
    assert(cbae_reaching_stores_def_count(NULL) == 0 && cbae_reaching_stores_def(NULL, 0) == NULL);
    assert(cbae_reaching_stores_def_of(&r.rs, load) == NULL);          /* a load is not a write */
    assert(cbae_reaching_stores_def_of(&r.rs, k_def(sum)) == NULL);
    assert(cbae_reaching_stores_def_of(&r.rs, NULL) == NULL);
    assert(cbae_reaching_stores_def_of(&r.rs, k_last(&y.bld)) == NULL); /* another function's instruction */
    assert(cbae_reaching_stores_def_of(&r.rs, s1) == cbae_reaching_stores_def(&r.rs, 0));

    /* may_reach refuses what is not a definition or not ours. */
    assert(!cbae_reaching_stores_may_reach(&r.rs, k_def(sum), load));
    assert(!cbae_reaching_stores_may_reach(&r.rs, k_def(sum), NULL));
    assert(!cbae_reaching_stores_may_reach(&r.rs, NULL, s1));
    assert(!cbae_reaching_stores_may_reach(&r.rs, k_def(sum), k_last(&y.bld)));
    assert(!cbae_reaching_stores_may_reach(NULL, k_def(sum), s1));
    assert( cbae_reaching_stores_may_reach(&r.rs, k_def(sum), s1));

    /* Build refuses bad input; a failed build leaves nothing to destroy. */
    cbae_reaching_stores_t bad;
    assert(cbae_reaching_stores_build(&r.ud, &r.alias, NULL) == CBAE_ERR_INVALID);
    assert(cbae_reaching_stores_build(NULL, &r.alias, &bad) == CBAE_ERR_INVALID && bad.impl == NULL);
    assert(cbae_reaching_stores_build(&r.ud, NULL, &bad) == CBAE_ERR_INVALID && bad.impl == NULL);
    cbae_use_def_t yud; cbae_alias_ctx_t yalias;
    assert(cbae_use_def_build(y.f, &yud) == CBAE_OK);
    assert(cbae_alias_ctx_build(&yud, &yalias) == CBAE_OK);
    assert(cbae_reaching_stores_build(&r.ud, &yalias, &bad) == CBAE_ERR_INVALID && bad.impl == NULL);
    cbae_reaching_stores_destroy(&bad);                                /* harmless on a zeroed struct */
    cbae_reaching_stores_destroy(NULL);
    cbae_alias_ctx_destroy(&yalias);
    cbae_use_def_destroy(&yud);

    rsx_free(&r);
    cbae_reaching_stores_destroy(&r.rs);                               /* and on one already destroyed */
    fn_done(&y); fn_done(&x);
    printf("  [PASS] API: totals beyond the buffer, refusals, the definition table, safe destruction\n");
}

/* ── Limits and size ─────────────────────────────────────────────────── */

/* A chain of `nblocks` blocks, each storing to `per_block` distinct stable addresses. */
static void build_chain(fn_t *x, uint32_t nblocks, uint32_t per_block) {
    cbae_cir_block_t **blk = malloc(nblocks * sizeof *blk);
    assert(blk);
    blk[0] = x->b0;
    for (uint32_t i = 1; i < nblocks; i++) blk[i] = fn_block(x, 0x1000 + 0x10 * (cbae_addr_t)i);
    cbae_cir_builder_t *b = &x->bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c = k_const(b, 5);
    for (uint32_t i = 0; i < nblocks; i++) {
        fn_at(x, blk[i]);
        for (uint32_t k = 0; k < per_block; k++)
            k_store(b, k_add(b, p, k_const(b, 8 * (int64_t)(i * per_block + k))), c);
        if (i + 1 < nblocks) cbae_cir_jump(b, blk[i + 1], 0);
        else                 cbae_cir_return(b, NULL, 0);
    }
    free(blk);
}

static void t_state_limit(void) {
    {   /* 2000 blocks x 8 stores: 16001 bits per state, 32 million in all: fits. */
        fn_t x; fn_init_sized(&x, "chain_ok", 96u << 20);
        build_chain(&x, 2000, 8);
        rsx_t r; rsx_build(&r, &x);
        assert(cbae_reaching_stores_def_count(&r.rs) == 16000);
        rsx_free(&r); fn_done(&x);
    }
    {   /* 5000 blocks x 8 stores: 40001 bits per state, 200 million in all: over
         * CBAE_RS_MAX_STATE_BITS (134 million). Refused, not attempted. */
        fn_t x; fn_init_sized(&x, "chain_too_big", 160u << 20);
        build_chain(&x, 5000, 8);
        fn_verify(&x);
        cbae_use_def_t ud; cbae_alias_ctx_t alias; cbae_reaching_stores_t rs;
        assert(cbae_use_def_build(x.f, &ud) == CBAE_OK);
        assert(cbae_alias_ctx_build(&ud, &alias) == CBAE_OK);
        assert(cbae_reaching_stores_build(&ud, &alias, &rs) == CBAE_ERR_OVERFLOW);
        assert(rs.impl == NULL && cbae_reaching_stores_def_count(&rs) == 0);
        cbae_reaching_stores_destroy(&rs);
        cbae_alias_ctx_destroy(&alias);
        cbae_use_def_destroy(&ud);
        fn_done(&x);
    }
    printf("  [PASS] state limit: 32 million state bits solve, 200 million are refused with CBAE_ERR_OVERFLOW\n");
}

static void t_scale_smoke(void) {
    /* 1500 blocks in a chain with a back edge every 50 blocks (loops of 30 blocks),
     * a store and a load per block on one of 16 slots, a call every fifth block.
     * Not a derivation: a check that size does not hurt, and that every answer
     * is well formed. */
    const uint32_t N = 1500;
    fn_t x; fn_init_sized(&x, "scale", 64u << 20);
    cbae_cir_block_t **blk = malloc(N * sizeof *blk);
    assert(blk);
    blk[0] = x.b0;
    for (uint32_t i = 1; i < N; i++) blk[i] = fn_block(&x, 0x1000 + 0x10 * (cbae_addr_t)i);
    cbae_cir_builder_t *b = &x.bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_value_t *c = k_const(b, 5);
    for (uint32_t i = 0; i < N; i++) {
        fn_at(&x, blk[i]);
        k_store(b, k_add(b, p, k_const(b, 8 * (int64_t)(i % 16))), c);
        if (i % 5 == 0) k_call(b, "f");
        cbae_cir_value_t *l = k_load(b, k_add(b, p, k_const(b, 8 * (int64_t)((i + 3) % 16))));
        if (i + 1 == N) {
            cbae_cir_return(b, l, 0);
        } else if (i % 50 == 49) {
            cbae_cir_value_t *cond = cbae_cir_binop(b, CIR_OP_CMP, l, c, cir_type_i1(), 0);
            cbae_cir_branch(b, cond, blk[i + 1], blk[i - 30], 0);
        } else {
            cbae_cir_jump(b, blk[i + 1], 0);
        }
    }
    free(blk);

    const clock_t t0 = clock();
    rsx_t r; rsx_build(&r, &x);
    const clock_t t1 = clock();
    const uint32_t ndefs = cbae_reaching_stores_def_count(&r.rs);
    uint32_t nload = 0, nfwd = 0, maxset = 0;
    for (uint32_t bi = 0; bi < N; bi++) {
        const cbae_cir_block_t *blkp = *(cbae_cir_block_t **)cbae_vector_at(&x.f->blocks, bi);
        for (uint32_t k = 0; k < blkp->instruction_count; k++) {
            const cbae_cir_instruction_t *in = blkp->instructions[k];
            if (in->opcode != CIR_OP_LOAD) continue;
            const cbae_rs_def_t *got[8];
            uint32_t n = 0; bool init = false;
            assert(cbae_reaching_stores_for_load(&r.rs, in, got, 8, &n, &init) == CBAE_OK);
            assert(n <= ndefs);
            for (uint32_t j = 0; j < n && j < 8; j++) assert(got[j]->insn && got[j]->block_id < N);
            if (n > maxset) maxset = n;
            nload++;
            const cbae_cir_instruction_t *st = NULL;
            if (cbae_reaching_stores_forwardable(&r.rs, in, &st)) {
                assert(n == 1 && !init && st == got[0]->insn && st->opcode == CIR_OP_STORE);
                nfwd++;
            }
        }
    }
    const clock_t t2 = clock();
    printf("         (%u blocks, %u definitions, %u loads, %u forwardable, largest set %u; "
           "solve %.0f ms, all queries %.0f ms)\n", N, ndefs, nload, nfwd, maxset,
           1000.0 * (double)(t1 - t0) / CLOCKS_PER_SEC, 1000.0 * (double)(t2 - t1) / CLOCKS_PER_SEC);
    assert((double)(t2 - t0) / CLOCKS_PER_SEC < 20.0);
    rsx_free(&r); fn_done(&x);
    printf("  [PASS] 1500-block function: solves and answers every load in well under the limit\n");
}

/* ── Lifted machine code ─────────────────────────────────────────────── */

static void t_lifted(void) {
    {   /*   0x5000: 48 83 EC 28        sub rsp, 0x28
         *   0x5004: 48 89 4C 24 20     mov [rsp+0x20], rcx      store A  at entry-rsp -8
         *   0x5009: E8 F2 00 00 00     call 0x5100
         *   0x500E: 48 8B 44 24 20     mov rax, [rsp+0x20]      load  A  (after the call)
         *   0x5013: 48 89 54 24 18     mov [rsp+0x18], rdx      store B  at entry-rsp -16
         *   0x5018: 48 8B 74 24 18     mov rsi, [rsp+0x18]      load  B  (right after its store)
         *   0x501D: 48 83 C4 28        add rsp, 0x28
         *   0x5021: C3                 ret
         *   The call splits the code into two blocks. Load A: the call may have
         *   rewritten it -> {store A, call}. Load B: its own store covers it -> {store B}. */
        static const uint8_t code[] = {
            0x48,0x83,0xEC,0x28, 0x48,0x89,0x4C,0x24,0x20, 0xE8,0xF2,0x00,0x00,0x00,
            0x48,0x8B,0x44,0x24,0x20, 0x48,0x89,0x54,0x24,0x18, 0x48,0x8B,0x74,0x24,0x18,
            0x48,0x83,0xC4,0x28, 0xC3 };
        lifted_t L; lift_x86(&L, code, sizeof code, 0x5000, "frame");
        rsx_t r; rsx_build_unchecked(&r, L.func);
        insn_t sA = lh_nth_insn(L.func, CIR_OP_STORE, 0), sB = lh_nth_insn(L.func, CIR_OP_STORE, 1);
        insn_t call = lh_nth_insn(L.func, CIR_OP_CALL, 0);
        insn_t lA = lh_nth_insn(L.func, CIR_OP_LOAD, 0), lB = lh_nth_insn(L.func, CIR_OP_LOAD, 1);
        assert(sA && sB && call && lA && lB);
        reaches(&r, "lifted: load after a call", lA, SET(sA, call), false);
        reaches(&r, "lifted: load after its store", lB, SET(sB), false);
        forwards(&r, "lifted: load after a call", lA, NULL);
        forwards(&r, "lifted: load after its store", lB, sB);
        rsx_free(&r); lifted_destroy(&L);
    }
    {   /*   0x6000: 53                 push rbx
         *   0x6001: E8 FA 00 00 00     call 0x6100
         *   0x6006: 59                 pop rcx
         *   0x6007: C3                 ret
         *   push stores to [rsp-8], pop loads from the same slot: the same class,
         *   so the call between them is the only thing that may have changed it. */
        static const uint8_t code[] = { 0x53, 0xE8,0xFA,0x00,0x00,0x00, 0x59, 0xC3 };
        lifted_t L; lift_x86(&L, code, sizeof code, 0x6000, "pushpop");
        rsx_t r; rsx_build_unchecked(&r, L.func);
        insn_t st = lh_nth_insn(L.func, CIR_OP_STORE, 0), call = lh_nth_insn(L.func, CIR_OP_CALL, 0);
        insn_t ld = lh_nth_insn(L.func, CIR_OP_LOAD, 0);
        assert(st && call && ld);
        reaches(&r, "lifted: pop after push across a call", ld, SET(st, call), false);
        rsx_free(&r); lifted_destroy(&L);
    }
    {   /*   0x7000: 53                 push rbx
         *   0x7001: 59                 pop rcx
         *   0x7002: C3                 ret
         *   No call in between: pop's load is exactly push's store. */
        static const uint8_t code[] = { 0x53, 0x59, 0xC3 };
        lifted_t L; lift_x86(&L, code, sizeof code, 0x7000, "pushpop_nocall");
        rsx_t r; rsx_build_unchecked(&r, L.func);
        insn_t st = lh_nth_insn(L.func, CIR_OP_STORE, 0), ld = lh_nth_insn(L.func, CIR_OP_LOAD, 0);
        assert(st && ld);
        reaches(&r, "lifted: pop right after push", ld, SET(st), false);
        forwards(&r, "lifted: pop right after push", ld, st);
        rsx_free(&r); lifted_destroy(&L);
    }
    printf("  [PASS] lifted code: frame slots forward unless a call intervenes, push/pop pairs forward\n");
}

int main(void) {
    (void)show;
    printf("Reaching stores tests:\n");
    t_classification();
    t_straight_line();
    t_widths();
    t_may_alias_pointers();
    t_indexed_forwarding();
    t_calls_in_block();
    t_calls_across_blocks();
    t_join();
    t_loops();
    t_unstable_addresses();
    t_walk_pruning();
    t_cross_block_filters();
    t_budget_fallback();
    t_budget_fallback_filters();
    t_documented_limits();
    t_barrier_kinds();
    t_malformed();
    t_unreachable();
    t_may_reach();
    t_api();
    t_state_limit();
    t_scale_smoke();
    t_lifted();
    printf("All reaching stores tests passed.\n");
    return 0;
}
