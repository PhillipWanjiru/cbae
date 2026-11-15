/**
 * @file test_dominance_oom.c
 * @brief The dominator tree, the dominance frontier, the post-dominator tree and the SSA verifier
 *        when memory runs out: every allocation each of them makes is failed in turn, and so is the
 *        arena they build into.
 *
 * What a caller may rely on, and what this file holds the code to:
 *
 *   - An operation that cannot finish says so (CBAE_ERR_OOM, or for the SSA verifier, which has no
 *     error code, a verdict that is "not ok" and says what could not be done). It never answers with a
 *     success that is wrong or merely less complete: a tree whose intervals were never numbered says
 *     that every block dominates every other, a frontier with an empty set that should have members
 *     makes phi placement skip blocks, and a verifier that did not compute dominance and says "ok"
 *     passes broken SSA.
 *   - A build that fails leaves its output EMPTY (all zero): no half-built tree whose arrays look
 *     usable, and destroying it is a safe no-op.
 *   - Nothing leaks on any of those paths (this file shows the paths are taken; the AddressSanitizer
 *     and Valgrind runs show nothing is left behind).
 *   - A successful run, whenever one happens, is identical to the run without failures.
 *   - An arena that is too small is the same kind of failure: a clean CBAE_ERR_OOM and an empty
 *     output, from the first byte short up to nothing at all, and an arena of exactly the size the
 *     build uses is enough.
 *
 * The sweeps are strict: an allocation that failed in a run that still reported success is a failure
 * of the test (tests/unit/oom_sweep.h). Each shape below is swept, and so are random CFGs.
 *
 * With an argument, only that part runs (dom, frontier, pdom, verifier, arena); without, all of them.
 */
#include "alloc_inject.h"
#include "oom_sweep.h"
#include "cir_test_util.h"
#include "dom_reference.h"
#include "dataflow/dominator_tree.h"
#include "dataflow/post_dominator_tree.h"
#include "dataflow/ssa_verifier.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS(msg) printf("  [PASS] %s\n", (msg))

#define MAX_BLOCKS 16
#define WORK_BYTES (64 * 1024)

/* ── The CFGs ─────────────────────────────────────────────────────────── */

typedef struct { const char *name; uint32_t n, m; uint32_t e[8][2]; } shape_t;

static const shape_t SHAPES[] = {
    { "one block",                                       1, 0, { {0} } },
    { "straight line",                                   3, 2, { {0,1}, {1,2} } },
    { "diamond",                                         4, 4, { {0,1}, {0,2}, {1,3}, {2,3} } },
    { "loop with an exit",                               4, 4, { {0,1}, {1,2}, {2,1}, {1,3} } },
    { "the entry is a loop header",                      3, 3, { {0,1}, {1,0}, {1,2} } },
    { "irreducible loop",                                4, 5, { {0,1}, {0,2}, {1,2}, {2,1}, {1,3} } },
    { "an infinite loop beside an exit",                 4, 4, { {0,1}, {0,3}, {1,2}, {2,1} } },
    { "two infinite loops and no exit",                  4, 5, { {0,1}, {0,2}, {1,1}, {2,3}, {3,2} } },
    { "a way into an infinite loop that is not a sink",  5, 5, { {0,1}, {1,2}, {1,3}, {2,2}, {3,4} } },
};

typedef struct {
    char                 name[96];
    uint32_t             n;
    fn_t                 x;               /* the function, and the arena its blocks live in            */
    cbae_arena_t         keep;            /* holds the trees a run without failures builds             */
    cbae_arena_t         work;            /* what an operation under test is given; reset before a run */
    cbae_dom_tree_t      dom;
    cbae_dom_frontier_t  df;
    cbae_pdom_tree_t     pdom;
    size_t               dom_bytes, pdom_bytes;     /* what each build takes from an arena, to the byte */
} fixture_t;

static void fixture_init(fixture_t *fx, const char *name, uint32_t n, const uint32_t (*edges)[2], uint32_t m) {
    memset(fx, 0, sizeof *fx);
    snprintf(fx->name, sizeof fx->name, "%s", name);
    fx->n = n;
    fn_init(&fx->x, "cfg");
    cbae_cir_block_t *blk[MAX_BLOCKS];
    blk[0] = fx->x.b0;
    for (uint32_t i = 1; i < n; i++) blk[i] = fn_block(&fx->x, 0x1000u + 0x10u * i);
    for (uint32_t e = 0; e < m; e++) assert(cbae_cir_block_add_edge(blk[edges[e][0]], blk[edges[e][1]]) == CBAE_OK);

    assert(cbae_arena_init(&fx->keep, WORK_BYTES) == CBAE_OK);
    assert(cbae_arena_init(&fx->work, WORK_BYTES) == CBAE_OK);
    assert(cbae_dom_tree_build(fx->x.f, &fx->keep, &fx->dom) == CBAE_OK);
    assert(cbae_dom_frontier_compute(&fx->dom, &fx->df) == CBAE_OK);
    assert(cbae_pdom_tree_build(fx->x.f, &fx->keep, &fx->pdom) == CBAE_OK);

    cbae_dom_tree_t d;
    assert(cbae_dom_tree_build(fx->x.f, &fx->work, &d) == CBAE_OK);
    fx->dom_bytes = cbae_arena_used(&fx->work);
    cbae_dom_tree_destroy(&d);
    cbae_arena_reset(&fx->work);
    cbae_pdom_tree_t p;
    assert(cbae_pdom_tree_build(fx->x.f, &fx->work, &p) == CBAE_OK);
    fx->pdom_bytes = cbae_arena_used(&fx->work);
    cbae_pdom_tree_destroy(&p);
    cbae_arena_reset(&fx->work);
}

static void fixture_free(fixture_t *fx) {
    cbae_dom_frontier_destroy(&fx->df);
    cbae_dom_tree_destroy(&fx->dom);
    cbae_pdom_tree_destroy(&fx->pdom);
    cbae_arena_destroy(&fx->keep);
    cbae_arena_destroy(&fx->work);
    fn_done(&fx->x);
}

/* ── Comparisons ──────────────────────────────────────────────────────── */

static bool all_zero(const void *p, size_t n) {
    const uint8_t *q = p;
    for (size_t i = 0; i < n; i++) if (q[i]) return false;
    return true;
}

static bool vec_same(const cbae_vector_t *a, const cbae_vector_t *b) {
    if (cbae_vector_count(a) != cbae_vector_count(b)) return false;
    for (size_t i = 0; i < cbae_vector_count(a); i++)
        if (*(const uint32_t *)cbae_vector_at(a, i) != *(const uint32_t *)cbae_vector_at(b, i)) return false;
    return true;
}

static bool dom_same(const cbae_dom_tree_t *a, const cbae_dom_tree_t *b) {
    if (a->func != b->func || a->block_count != b->block_count) return false;
    const size_t bytes = sizeof(uint32_t) * a->block_count;
    if (memcmp(a->idom, b->idom, bytes) || memcmp(a->rpo_order, b->rpo_order, bytes) ||
        memcmp(a->rpo_number, b->rpo_number, bytes) || memcmp(a->dt_enter, b->dt_enter, bytes) ||
        memcmp(a->dt_exit, b->dt_exit, bytes)) return false;
    for (uint32_t i = 0; i < a->block_count; i++)
        if (!vec_same(&a->children[i], &b->children[i])) return false;
    return true;
}

static bool pdom_same(const cbae_pdom_tree_t *a, const cbae_pdom_tree_t *b) {
    if (a->func != b->func || a->block_count != b->block_count) return false;
    const size_t bytes = sizeof(uint32_t) * (a->block_count + 1u);      /* the blocks and the virtual exit */
    if (memcmp(a->ipdom, b->ipdom, bytes) || memcmp(a->rpo_order, b->rpo_order, bytes) ||
        memcmp(a->rpo_number, b->rpo_number, bytes) || memcmp(a->dt_enter, b->dt_enter, bytes) ||
        memcmp(a->dt_exit, b->dt_exit, bytes)) return false;
    for (uint32_t i = 0; i <= a->block_count; i++)
        if (!vec_same(&a->children[i], &b->children[i])) return false;
    return true;
}

static bool df_same(const cbae_dom_frontier_t *a, const cbae_dom_frontier_t *b) {
    if (a->block_count != b->block_count) return false;
    for (uint32_t i = 0; i < a->block_count; i++)
        if (!vec_same(&a->frontier[i], &b->frontier[i])) return false;
    return true;
}

/* ── The operations, as oom_sweep wants them ──────────────────────────── */

static cbae_err_t dom_body(void *ctx, uint64_t failing) {
    fixture_t *fx = ctx;
    cbae_arena_reset(&fx->work);
    cbae_dom_tree_t dt;
    memset(&dt, 0xA5, sizeof dt);                                    /* the build must overwrite all of it */
    const cbae_err_t rc = cbae_dom_tree_build(fx->x.f, &fx->work, &dt);
    if (rc != CBAE_OK) {
        if (rc != CBAE_ERR_OOM || !all_zero(&dt, sizeof dt))
            fprintf(stderr, "[%s] dominator tree, allocation %llu failing: returned %d, tree %s\n", fx->name,
                    (unsigned long long)failing, (int)rc, all_zero(&dt, sizeof dt) ? "empty" : "NOT empty");
        assert(rc == CBAE_ERR_OOM);
        assert(all_zero(&dt, sizeof dt));
        cbae_dom_tree_destroy(&dt);                                  /* a no-op on an empty tree */
        return rc;
    }
    assert(dom_same(&fx->dom, &dt));
    cbae_dom_tree_destroy(&dt);
    return CBAE_OK;
}

static cbae_err_t frontier_body(void *ctx, uint64_t failing) {
    fixture_t *fx = ctx;
    cbae_dom_frontier_t df;
    memset(&df, 0xA5, sizeof df);
    const cbae_err_t rc = cbae_dom_frontier_compute(&fx->dom, &df);
    if (rc != CBAE_OK) {
        if (rc != CBAE_ERR_OOM || !all_zero(&df, sizeof df))
            fprintf(stderr, "[%s] dominance frontier, allocation %llu failing: returned %d, frontier %s\n", fx->name,
                    (unsigned long long)failing, (int)rc, all_zero(&df, sizeof df) ? "empty" : "NOT empty");
        assert(rc == CBAE_ERR_OOM);
        assert(all_zero(&df, sizeof df));
        cbae_dom_frontier_destroy(&df);
        return rc;
    }
    assert(df_same(&fx->df, &df));
    cbae_dom_frontier_destroy(&df);
    return CBAE_OK;
}

static cbae_err_t pdom_body(void *ctx, uint64_t failing) {
    fixture_t *fx = ctx;
    cbae_arena_reset(&fx->work);
    cbae_pdom_tree_t pt;
    memset(&pt, 0xA5, sizeof pt);
    const cbae_err_t rc = cbae_pdom_tree_build(fx->x.f, &fx->work, &pt);
    if (rc != CBAE_OK) {
        if (rc != CBAE_ERR_OOM || !all_zero(&pt, sizeof pt))
            fprintf(stderr, "[%s] post-dominator tree, allocation %llu failing: returned %d, tree %s\n", fx->name,
                    (unsigned long long)failing, (int)rc, all_zero(&pt, sizeof pt) ? "empty" : "NOT empty");
        assert(rc == CBAE_ERR_OOM);
        assert(all_zero(&pt, sizeof pt));
        cbae_pdom_tree_destroy(&pt);
        return rc;
    }
    assert(pdom_same(&fx->pdom, &pt));
    cbae_pdom_tree_destroy(&pt);
    return CBAE_OK;
}

static cbae_err_t dom_arena_body(void *ctx, size_t bytes) {
    fixture_t *fx = ctx;
    cbae_arena_t a;
    assert(cbae_arena_init(&a, bytes) == CBAE_OK);
    cbae_dom_tree_t dt;
    memset(&dt, 0xA5, sizeof dt);
    const cbae_err_t rc = cbae_dom_tree_build(fx->x.f, &a, &dt);
    if (rc != CBAE_OK) {
        assert(rc == CBAE_ERR_OOM);                                  /* a full arena is out of memory, not a bad function */
        assert(all_zero(&dt, sizeof dt));
        cbae_dom_tree_destroy(&dt);
    } else {
        assert(dom_same(&fx->dom, &dt));
        cbae_dom_tree_destroy(&dt);
    }
    cbae_arena_destroy(&a);
    return rc;
}

static cbae_err_t pdom_arena_body(void *ctx, size_t bytes) {
    fixture_t *fx = ctx;
    cbae_arena_t a;
    assert(cbae_arena_init(&a, bytes) == CBAE_OK);
    cbae_pdom_tree_t pt;
    memset(&pt, 0xA5, sizeof pt);
    const cbae_err_t rc = cbae_pdom_tree_build(fx->x.f, &a, &pt);
    if (rc != CBAE_OK) {
        assert(rc == CBAE_ERR_OOM);
        assert(all_zero(&pt, sizeof pt));
        cbae_pdom_tree_destroy(&pt);
    } else {
        assert(pdom_same(&fx->pdom, &pt));
        cbae_pdom_tree_destroy(&pt);
    }
    cbae_arena_destroy(&a);
    return rc;
}

/* ── The sweeps over one CFG ──────────────────────────────────────────── */

static bool want(const char *only, const char *part) { return !only || strcmp(only, part) == 0; }

static void sweep_cfg(fixture_t *fx, const char *only, uint64_t *runs, uint64_t *errors) {
    if (want(only, "dom")) {
        const oom_report_t r = oom_sweep(dom_body, fx, true);
        assert(r.allocations > 0 && r.runs == 2 * r.allocations && r.reported > 0);
        *runs += r.runs; *errors += r.reported;
    }
    if (want(only, "frontier")) {
        const oom_report_t r = oom_sweep(frontier_body, fx, true);
        assert(r.allocations > 0 && r.runs == 2 * r.allocations && r.reported > 0);
        *runs += r.runs; *errors += r.reported;
    }
    if (want(only, "pdom")) {
        const oom_report_t r = oom_sweep(pdom_body, fx, true);
        assert(r.allocations > 0 && r.runs == 2 * r.allocations && r.reported > 0);
        *runs += r.runs; *errors += r.reported;
    }
    if (want(only, "arena")) {
        size_t first = oom_sweep_arena(dom_arena_body, fx, 1, fx->dom_bytes + 16, 1);
        if (first != fx->dom_bytes)
            fprintf(stderr, "[%s] dominator tree: an arena of %zu bytes is enough, the build uses %zu\n", fx->name, first, fx->dom_bytes);
        assert(first == fx->dom_bytes);
        first = oom_sweep_arena(pdom_arena_body, fx, 1, fx->pdom_bytes + 16, 1);
        if (first != fx->pdom_bytes)
            fprintf(stderr, "[%s] post-dominator tree: an arena of %zu bytes is enough, the build uses %zu\n", fx->name, first, fx->pdom_bytes);
        assert(first == fx->pdom_bytes);
        *runs += fx->dom_bytes + fx->pdom_bytes + 32;
    }
}

static void test_cfg_sweeps(const char *only) {
    if (!(want(only, "dom") || want(only, "frontier") || want(only, "pdom") || want(only, "arena"))) return;
    uint64_t runs = 0, errors = 0;
    uint32_t cfgs = 0;
    for (size_t i = 0; i < sizeof SHAPES / sizeof SHAPES[0]; i++) {
        fixture_t fx;
        fixture_init(&fx, SHAPES[i].name, SHAPES[i].n, SHAPES[i].e, SHAPES[i].m);
        sweep_cfg(&fx, only, &runs, &errors);
        fixture_free(&fx);
        cfgs++;
    }
    rng_t rng = { 0x9E3779B97F4A7C15ull };
    for (uint32_t k = 0; k < 24; k++) {
        const uint32_t n = 2 + rng_next(&rng) % 11;
        rgraph_t g;
        rg_generate(&g, &rng, n);
        char name[64];
        snprintf(name, sizeof name, "random CFG %u (%u blocks, %u edges)", k, g.n, g.m);
        const rgraph_t *cg = &g;                                     /* so that cg->e is an array of const (no pedantic warning) */
        fixture_t fx;
        fixture_init(&fx, name, cg->n, cg->e, cg->m);
        sweep_cfg(&fx, only, &runs, &errors);
        fixture_free(&fx);
        cfgs++;
    }
    char msg[320];
    snprintf(msg, sizeof msg, "%u CFGs (%zu shapes, the rest random): %llu runs with an allocation or an arena byte short, each a clean error "
             "with an empty output or the same tree as without failures, none swallowed, no leak", cfgs,
             sizeof SHAPES / sizeof SHAPES[0], (unsigned long long)runs);
    PASS(msg);
    (void)errors;
}

/* ── The SSA verifier ─────────────────────────────────────────────────── */

typedef struct {
    fn_t                      x;
    cbae_cir_verify_result_t  golden;
} vfix_t;

/*   b0: p, q = params ; c = cmp p, 0 ; a = p + 1 ; branch c, b1, b2
 *   b1: x1 = a + 2 ; jump b3          b2: x2 = a * 3 ; jump b3
 *   b3: ph = phi [x1, b1] [x2, b2] ; r = ph + q ; ret r
 * When `broken`, r uses x1 instead of ph: x1 is defined in b1, which does not dominate b3 (b2 reaches it too). */
static void vfix_init(vfix_t *v, bool broken) {
    memset(v, 0, sizeof *v);
    fn_init(&v->x, broken ? "broken" : "valid");
    fn_t *x = &v->x;
    cbae_cir_block_t *b1 = fn_block(x, 0x1010), *b2 = fn_block(x, 0x1020), *b3 = fn_block(x, 0x1030);
    cbae_cir_builder_t *b = &x->bld;
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RBX), *q = cbae_cir_param(b, CBAE_REG_RCX);
    cbae_cir_value_t *c = cbae_cir_binop(b, CIR_OP_CMP, p, k_const(b, 0), cir_type_i1(), 0);
    cbae_cir_value_t *a = k_add(b, p, k_const(b, 1));
    cbae_cir_branch(b, c, b1, b2, 0);
    fn_at(x, b1);
    cbae_cir_value_t *x1 = k_add(&x->bld, a, k_const(&x->bld, 2));
    cbae_cir_jump(&x->bld, b3, 0);
    fn_at(x, b2);
    cbae_cir_value_t *x2 = k_mul(&x->bld, a, k_const(&x->bld, 3));
    cbae_cir_jump(&x->bld, b3, 0);
    cbae_cir_value_t *ph = cbae_cir_phi_create(x->f, b3, T64);
    assert(cbae_cir_phi_add_incoming(x->f, ph->u.def_insn, x1, b1->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x->f, ph->u.def_insn, x2, b2->id) == CBAE_OK);
    fn_at(x, b3);
    cbae_cir_value_t *r = k_add(&x->bld, ph, q);
    cbae_cir_return(&x->bld, r, 0);
    fn_verify(x);
    if (broken) k_def(r)->operands[0] = x1;

    v->golden = cbae_ssa_verify_function(x->f);
    assert(v->golden.ok == !broken);
    if (broken) assert(strstr(v->golden.message, "does not dominate block3") != NULL);
}

static cbae_err_t verify_body(void *ctx, uint64_t failing) {
    vfix_t *v = ctx;
    const cbae_cir_verify_result_t r = cbae_ssa_verify_function(v->x.f);
    if (r.ok == v->golden.ok && strcmp(r.message, v->golden.message) == 0) return CBAE_OK;       /* the true verdict */
    /* an admission that names what failed: the structural verifier says "allocation failed", the two steps after it say
     * "could not ..." and the error code, CBAE_ERR_OOM (-2) */
    if (r.ok || (!strstr(r.message, "(error -2)") && !strstr(r.message, "allocation failed"))) {
        fprintf(stderr, "[%s] allocation %llu failing: the verifier said ok=%d '%s' -- neither the verdict without failures "
                "nor an admission that it could not finish\n", v->x.f->name, (unsigned long long)failing, (int)r.ok, r.message);
        assert(!"a verdict that is neither the true one nor an honest failure");
    }
    return CBAE_ERR_OOM;
}

static void test_verifier(const char *only) {
    if (!want(only, "verifier")) return;
    uint64_t runs = 0, errors = 0;
    for (int broken = 0; broken < 2; broken++) {
        vfix_t v;
        vfix_init(&v, broken);
        const oom_report_t r = oom_sweep(verify_body, &v, true);
        assert(r.allocations > 0 && r.runs == 2 * r.allocations && r.reported == r.runs);
        runs += r.runs; errors += r.reported;
        fn_done(&v.x);
    }
    char msg[256];
    snprintf(msg, sizeof msg, "SSA verifier, a valid function and one whose use is not dominated: %llu runs with an allocation failing, "
             "%llu ended in a verdict that says it could not finish, none in the verdict without failures or in \"ok\"",
             (unsigned long long)runs, (unsigned long long)errors);
    PASS(msg);
}

int main(int argc, char **argv) {
    printf("=== test_dominance_oom ===\n");
    const char *only = argc > 1 ? argv[1] : NULL;
    test_cfg_sweeps(only);
    test_verifier(only);
    printf("All dominance out-of-memory tests passed.\n");
    return 0;
}
