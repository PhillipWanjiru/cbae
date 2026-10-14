/**
 * @file test_alias_soundness.c
 * @brief The alias analysis checked against real executions of random functions.
 *
 * Hand-derived cases (test_alias_analysis.c) show the analysis is right where
 * somebody thought to look. This test asks the question the analysis exists
 * to answer, on functions nobody designed: build a random valid-SSA function
 * (cir_random.h), run it for real several times with different initial
 * registers and memory, and compare what happened with what was claimed.
 *
 * THREE LAYERS, EACH CHECKED DIRECTLY
 *   1. Stability.  Every value the analysis calls stable is defined at most
 *      once per run. (Checks the cycle detection on graphs nobody drew.)
 *   2. Decomposition.  Whenever an instruction defines a 64-bit value whose
 *      linear form has only stable atoms, the value defined equals
 *      offset + sum(coeff * atom) evaluated on the atoms' actual values, mod
 *      2^64. This is the identity every NO/MUST answer rests on, tested for
 *      every ADD/SUB/MUL/SHL/NEG/COPY, every redundant phi, every width mix.
 *   3. Queries.  For every pair of static memory accesses, per run:
 *        NO    no byte is ever touched by both,
 *        MUST  every execution of either touches exactly one and the same
 *              range (so both always do, and with equal size).
 *      MAY claims nothing and is never checked.
 *
 * THE TEST CHECKS ITSELF
 *   A checker that can never fail proves nothing. After the real run, the same
 *   checks are repeated on deliberately false claims (every MAY upgraded to NO,
 *   to MUST; offsets nudged; every value called stable) and each such forgery
 *   must be caught. Statistics at the end show the claims were exercised.
 *
 * Environment (for longer runs): CBAE_SOUNDNESS_FUNCS, CBAE_SOUNDNESS_SEED0,
 * CBAE_SOUNDNESS_RUNS, CBAE_SOUNDNESS_STEPS.
 */
#include "cir_random.h"
#include "dataflow/alias_analysis.h"
#include "dataflow/use_def.h"
#include "cir/cir_printer.h"
#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t env_u64(const char *name, uint64_t dflt) {
    const char *s = getenv(name);
    if (!s || !*s) return dflt;
    char *end = NULL;
    const unsigned long long v = strtoull(s, &end, 10);
    return (end && !*end) ? (uint64_t)v : dflt;
}

/* ── Statistics ──────────────────────────────────────────────────────── */

typedef struct {
    uint64_t funcs, blocks, loop_funcs, accesses, runs, steps, executions;
    uint64_t pairs_no, pairs_must, pairs_may;
    uint64_t checks_no, checks_must;
    uint64_t overlap_pairs, overlap_may, overlap_must;
    uint64_t id_checks, id_skipped, stab_checks;
    uint64_t terms_hist[CBAE_ALIAS_MAX_TERMS + 1];   /* identity-checked forms by term count          */
    uint64_t opaque_forms;                            /* expandable values left as one atom (the caps) */
    uint64_t multi_atom_stable;                       /* checked forms with 3 or more atoms            */
} stats_t;

/* ── Per-function facts ──────────────────────────────────────────────── */

typedef struct {
    const cbae_cir_function_t *f;
    uint64_t                   seed;
    cbae_use_def_t             ud;
    cbae_alias_ctx_t           ctx;

    uint32_t                   nacc;
    const cbae_cir_instruction_t **acc;       /* [nacc]            */
    const cbae_cir_value_t   **addr;          /* [nacc]            */
    uint32_t                  *size;          /* [nacc]            */
    uint32_t                  *acc_of;        /* [next_insn_id]    */
    uint8_t                   *claim;         /* [nacc * nacc]     */
    uint8_t                   *overlap;       /* [nacc * nacc]  observed in any run, x < y */

    uint32_t                   nvals;
    cbae_addr_info_t          *form;          /* [nvals]           */
    uint8_t                   *form_ok;       /* [nvals]  identity is checked for this value */
    uint8_t                   *stable;        /* [nvals]  instruction result called stable   */

    int                        reported;
} fctx_t;

/* What a run checks against. Normally the analysis' own answers; the
 * self-checks substitute forged ones. */
typedef struct {
    const uint8_t          *claim;
    const cbae_addr_info_t *form;
    const uint8_t          *form_ok;
    const uint8_t          *stable;
} view_t;

static bool is_trivial_form(const cbae_addr_info_t *fi, const cbae_cir_value_t *v) {
    return fi->term_count == 1 && fi->offset == 0 && fi->terms[0].coeff == 1 && fi->terms[0].value == v;
}

static void fctx_init(fctx_t *fx, const cbae_cir_function_t *f, uint64_t seed, stats_t *st) {
    memset(fx, 0, sizeof *fx);
    fx->f = f;
    fx->seed = seed;
    cbae_err_t rc = cbae_use_def_build(f, &fx->ud);
    assert(rc == CBAE_OK);
    rc = cbae_alias_ctx_build(&fx->ud, &fx->ctx);
    assert(rc == CBAE_OK);
    (void)rc;

    const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
    st->blocks += nb;
    for (uint32_t b = 0; b < nb; b++)
        if (cbae_alias_block_on_cycle(&fx->ctx, b)) { st->loop_funcs++; break; }

    /* Static memory accesses. */
    uint32_t n = 0;
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_value_t *a; uint32_t sz;
            if (cbae_alias_mem_access(blk->instructions[i], &a, &sz)) n++;
        }
    }
    fx->nacc    = n;
    fx->acc     = calloc(n ? n : 1, sizeof *fx->acc);
    fx->addr    = calloc(n ? n : 1, sizeof *fx->addr);
    fx->size    = calloc(n ? n : 1, sizeof *fx->size);
    fx->acc_of  = malloc(sizeof(uint32_t) * (f->next_insn_id ? f->next_insn_id : 1));
    fx->claim   = calloc((size_t)n * n + 1, 1);
    fx->overlap = calloc((size_t)n * n + 1, 1);
    fx->nvals   = f->next_value_id;
    fx->form    = calloc(fx->nvals ? fx->nvals : 1, sizeof *fx->form);
    fx->form_ok = calloc(fx->nvals ? fx->nvals : 1, 1);
    fx->stable  = calloc(fx->nvals ? fx->nvals : 1, 1);
    assert(fx->acc && fx->addr && fx->size && fx->acc_of && fx->claim && fx->overlap &&
           fx->form && fx->form_ok && fx->stable);
    for (uint32_t i = 0; i < f->next_insn_id; i++) fx->acc_of[i] = UINT32_MAX;

    cbae_addr_info_t *dec = calloc(n ? n : 1, sizeof *dec);
    assert(dec);
    uint32_t k = 0;
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            const cbae_cir_value_t *a; uint32_t sz;
            if (!cbae_alias_mem_access(in, &a, &sz)) continue;
            fx->acc[k] = in; fx->addr[k] = a; fx->size[k] = sz;
            fx->acc_of[in->id] = k;
            const bool ok = cbae_alias_decompose(&fx->ctx, a, &dec[k]);
            assert(ok);
            (void)ok;
            k++;
        }
    }

    /* The claims: every ordered pair, symmetry checked, and the one-shot
     * query agrees with the decompose-then-query path. */
    for (uint32_t x = 0; x < n; x++)
        for (uint32_t y = 0; y < n; y++) {
            const cbae_alias_result_t r =
                cbae_alias_query_info(&fx->ctx, &dec[x], fx->size[x], &dec[y], fx->size[y]);
            fx->claim[x * n + y] = (uint8_t)r;
            if (y < x) assert(fx->claim[y * n + x] == (uint8_t)r && "alias relation is not symmetric");
            if (n <= 24)
                assert(cbae_alias_query(&fx->ctx, fx->addr[x], fx->size[x], fx->addr[y], fx->size[y]) == r);
            if (y >= x) {
                if (r == CBAE_ALIAS_NO)        st->pairs_no++;
                else if (r == CBAE_ALIAS_MUST) st->pairs_must++;
                else                           st->pairs_may++;
            }
        }
    free(dec);
    st->accesses += n;

    /* Linear forms of every 64-bit instruction result, and which results are stable. */
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_value_t *res = blk->instructions[i]->result;
            if (!res) continue;
            if (cbae_alias_value_is_stable(&fx->ctx, res)) fx->stable[res->id] = 1;
            if (cir_type_bits(res->type) != 64) continue;
            cbae_addr_info_t fi;
            const bool ok = cbae_alias_decompose(&fx->ctx, res, &fi);
            assert(ok);
            (void)ok;
            bool all_stable = true;
            for (uint32_t t = 0; t < fi.term_count; t++)
                if (!cbae_alias_value_is_stable(&fx->ctx, fi.terms[t].value)) all_stable = false;
            const cbae_cir_instruction_t *di = res->u.def_insn;
            const bool expandable = di && (di->opcode == CIR_OP_ADD || di->opcode == CIR_OP_SUB);
            if (expandable && is_trivial_form(&fi, res)) {
                bool reads_other = false;
                for (uint32_t o = 0; o < di->operand_count; o++)
                    if (di->operands[o]->kind == CIR_VAL_PARAM && di->operands[o]->u.param_reg == CBAE_REG_OTHER)
                        reads_other = true;
                if (!reads_other) st->opaque_forms++;
            }
            if (all_stable && !is_trivial_form(&fi, res)) {
                fx->form[res->id] = fi;
                fx->form_ok[res->id] = 1;
                st->terms_hist[fi.term_count]++;
                if (fi.term_count >= 3) st->multi_atom_stable++;
            }
        }
    }
}

static void fctx_free(fctx_t *fx) {
    cbae_alias_ctx_destroy(&fx->ctx);
    cbae_use_def_destroy(&fx->ud);
    free(fx->acc); free(fx->addr); free(fx->size); free(fx->acc_of);
    free(fx->claim); free(fx->overlap);
    free(fx->form); free(fx->form_ok); free(fx->stable);
}

/* ── One run ─────────────────────────────────────────────────────────── */

typedef struct { uint64_t byte; uint32_t acc; } rec_t;

typedef struct {
    fctx_t     *fx;
    view_t      view;
    stats_t    *st;
    bool        quiet;
    uint64_t    seed;
    int         violations;

    uint64_t   *cur;           /* [nvals] latest value of each instruction result */
    uint8_t    *defd;
    uint32_t   *execs;

    uint8_t    *executed;      /* [nacc] */
    uint64_t   *a0;
    uint32_t   *s0;
    uint8_t    *poly;
    rec_t      *recs;
    size_t      nrecs, caprecs;
} run_t;

static void report(run_t *r, const char *fmt, ...) {
    r->violations++;
    if (r->quiet) return;
    fctx_t *fx = r->fx;
    if (fx->reported == 0) {
        fprintf(stderr, "\n=== SOUNDNESS VIOLATION: function seed %" PRIu64 ", run seed %" PRIu64 " ===\n",
                fx->seed, r->seed);
        cbae_cir_print_function(fx->f, stderr);
    }
    if (fx->reported++ < 8) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputc('\n', stderr);
    }
}

static void on_def(void *u, const cbae_cir_instruction_t *insn, uint64_t value, uint64_t step) {
    (void)step;
    run_t *r = u;
    const cbae_cir_value_t *res = insn->result;
    const uint32_t id = res->id;
    r->cur[id]  = value;
    r->defd[id] = 1;
    r->execs[id]++;

    if (r->view.stable[id]) {
        r->st->stab_checks++;
        if (r->execs[id] > 1)
            report(r, "insn #%u (%%v%u) is called stable but was defined %u times in one run",
                   insn->id, id, r->execs[id]);
    }
    if (!r->view.form_ok[id]) return;

    const cbae_addr_info_t *fi = &r->view.form[id];
    uint64_t sum = (uint64_t)fi->offset;
    for (uint32_t t = 0; t < fi->term_count; t++) {
        const cbae_cir_value_t *a = fi->terms[t].value;
        uint64_t av;
        if (a->kind == CIR_VAL_CONST || a->kind == CIR_VAL_PARAM) av = cirx_leaf_value(r->seed, a);
        else if (r->defd[a->id])                                   av = r->cur[a->id];
        else { r->st->id_skipped++; return; }
        sum += (uint64_t)fi->terms[t].coeff * av;
    }
    r->st->id_checks++;
    if (sum != value)
        report(r, "insn #%u (%%v%u): defined 0x%" PRIx64 " but its form evaluates to 0x%" PRIx64,
               insn->id, id, value, sum);
}

static void on_access(void *u, const cbae_cir_instruction_t *insn, uint64_t addr, uint32_t size,
                      bool is_store, uint64_t step) {
    (void)is_store; (void)step;
    run_t *r = u;
    const uint32_t a = r->fx->acc_of[insn->id];
    assert(a != UINT32_MAX && size == r->fx->size[a]);
    r->st->executions++;
    if (!r->executed[a]) { r->executed[a] = 1; r->a0[a] = addr; r->s0[a] = size; }
    else if (r->a0[a] != addr || r->s0[a] != size) r->poly[a] = 1;
    for (uint32_t i = 0; i < size; i++) {
        if (r->nrecs == r->caprecs) {
            r->caprecs = r->caprecs ? r->caprecs * 2 : 4096;
            r->recs = realloc(r->recs, r->caprecs * sizeof *r->recs);
            assert(r->recs);
        }
        r->recs[r->nrecs].byte = addr + i;
        r->recs[r->nrecs].acc  = a;
        r->nrecs++;
    }
}

static int cmp_rec(const void *p, const void *q) {
    const rec_t *a = p, *b = q;
    if (a->byte != b->byte) return a->byte < b->byte ? -1 : 1;
    return a->acc < b->acc ? -1 : a->acc > b->acc ? 1 : 0;
}

static void check_queries(run_t *r) {
    fctx_t *fx = r->fx;
    const uint32_t n = fx->nacc;
    const uint8_t *claim = r->view.claim;

    /* NO: no byte touched by two different static accesses that were
     * claimed disjoint. Records sorted by (byte, access), duplicates dropped. */
    if (r->nrecs > 1) qsort(r->recs, r->nrecs, sizeof r->recs[0], cmp_rec);
    size_t u = 0;
    for (size_t i = 0; i < r->nrecs; i++)
        if (u == 0 || r->recs[i].byte != r->recs[u - 1].byte || r->recs[i].acc != r->recs[u - 1].acc)
            r->recs[u++] = r->recs[i];
    for (size_t i = 0; i < u; ) {
        size_t j = i;
        while (j < u && r->recs[j].byte == r->recs[i].byte) j++;
        for (size_t a = i; a < j; a++)
            for (size_t b = a + 1; b < j; b++) {
                const uint32_t x = r->recs[a].acc, y = r->recs[b].acc;     /* x < y */
                if (!fx->overlap[x * n + y]) {
                    fx->overlap[x * n + y] = 1;
                    r->st->overlap_pairs++;
                    if (claim[x * n + y] == CBAE_ALIAS_MAY)       r->st->overlap_may++;
                    else if (claim[x * n + y] == CBAE_ALIAS_MUST) r->st->overlap_must++;
                }
                if (claim[x * n + y] == CBAE_ALIAS_NO)
                    report(r, "NO violated: insn #%u and insn #%u both touched byte 0x%" PRIx64,
                           fx->acc[x]->id, fx->acc[y]->id, r->recs[a].byte);
            }
        i = j;
    }

    /* NO checked once per run per pair that actually executed; MUST: both
     * executed, each only ever touched one range, and it was the same. */
    for (uint32_t x = 0; x < n; x++)
        for (uint32_t y = x; y < n; y++) {
            if (!r->executed[x] || !r->executed[y]) continue;
            const uint8_t c = claim[x * n + y];
            if (c == CBAE_ALIAS_NO) r->st->checks_no++;
            if (c != CBAE_ALIAS_MUST) continue;
            r->st->checks_must++;
            if (r->poly[x] || r->poly[y] || r->a0[x] != r->a0[y] || r->s0[x] != r->s0[y])
                report(r, "MUST violated: insn #%u (%s) and insn #%u (%s): [0x%" PRIx64 ",+%u)%s vs "
                          "[0x%" PRIx64 ",+%u)%s",
                       fx->acc[x]->id, fx->acc[x]->opcode == CIR_OP_STORE ? "store" : "load",
                       fx->acc[y]->id, fx->acc[y]->opcode == CIR_OP_STORE ? "store" : "load",
                       r->a0[x], r->s0[x], r->poly[x] ? " and others" : "",
                       r->a0[y], r->s0[y], r->poly[y] ? " and others" : "");
        }
}

/* Run the function once and check everything against `view`; returns the
 * number of violations found. */
static int run_one(fctx_t *fx, const view_t *view, stats_t *st, bool quiet,
                   uint64_t run_seed, uint64_t max_steps) {
    run_t r;
    memset(&r, 0, sizeof r);
    r.fx = fx; r.view = *view; r.st = st; r.quiet = quiet; r.seed = run_seed;
    const uint32_t nv = fx->nvals ? fx->nvals : 1, n = fx->nacc ? fx->nacc : 1;
    r.cur = calloc(nv, sizeof *r.cur);
    r.defd = calloc(nv, 1);
    r.execs = calloc(nv, sizeof *r.execs);
    r.executed = calloc(n, 1);
    r.a0 = calloc(n, sizeof *r.a0);
    r.s0 = calloc(n, sizeof *r.s0);
    r.poly = calloc(n, 1);
    assert(r.cur && r.defd && r.execs && r.executed && r.a0 && r.s0 && r.poly);

    cirx_hooks_t hk;
    memset(&hk, 0, sizeof hk);
    hk.user = &r;
    hk.on_def = on_def;
    hk.on_access = on_access;
    cirx_result_t res;
    cirx_run(fx->f, run_seed, max_steps, &hk, &res);
    st->runs++;
    st->steps += res.steps;

    check_queries(&r);

    free(r.cur); free(r.defd); free(r.execs); free(r.executed);
    free(r.a0); free(r.s0); free(r.poly); free(r.recs);
    return r.violations;
}

/* ── Forged views for the self-check ─────────────────────────────────── */

enum { FORGE_MAY_TO_NO, FORGE_MAY_TO_MUST, FORGE_ALL_NO, FORGE_FORM_OFFSET, FORGE_ALL_STABLE, FORGE_N };
static const char *const FORGE_NAME[FORGE_N] = {
    "every MAY called NO", "every MAY called MUST", "every pair called NO",
    "every form's offset nudged", "every value called stable" };

static void forge(const fctx_t *fx, int kind, view_t *v, uint8_t **own_u8, cbae_addr_info_t **own_form) {
    const uint32_t n = fx->nacc;
    *own_u8 = NULL;
    *own_form = NULL;
    v->claim = fx->claim; v->form = fx->form; v->form_ok = fx->form_ok; v->stable = fx->stable;
    switch (kind) {
        case FORGE_MAY_TO_NO:
        case FORGE_MAY_TO_MUST:
        case FORGE_ALL_NO: {
            uint8_t *c = malloc((size_t)n * n + 1);
            assert(c);
            for (uint32_t i = 0; i < n * n; i++) {
                const uint8_t o = fx->claim[i];
                c[i] = kind == FORGE_ALL_NO ? CBAE_ALIAS_NO
                     : o != CBAE_ALIAS_MAY ? o
                     : kind == FORGE_MAY_TO_NO ? CBAE_ALIAS_NO : CBAE_ALIAS_MUST;
            }
            *own_u8 = c;
            v->claim = c;
            break;
        }
        case FORGE_FORM_OFFSET: {
            cbae_addr_info_t *f = malloc((fx->nvals ? fx->nvals : 1) * sizeof *f);
            assert(f);
            memcpy(f, fx->form, (fx->nvals ? fx->nvals : 1) * sizeof *f);
            for (uint32_t i = 0; i < fx->nvals; i++)                  /* wraps at INT64_MAX: unsigned add */
                f[i].offset = (int64_t)((uint64_t)f[i].offset + 1u);
            *own_form = f;
            v->form = f;
            break;
        }
        case FORGE_ALL_STABLE: {
            uint8_t *s = malloc(fx->nvals ? fx->nvals : 1);
            assert(s);
            memset(s, 1, fx->nvals ? fx->nvals : 1);
            *own_u8 = s;
            v->stable = s;
            break;
        }
        default: assert(0);
    }
}

/* ── Driver ──────────────────────────────────────────────────────────── */

int main(void) {
    const uint64_t nfuncs = env_u64("CBAE_SOUNDNESS_FUNCS", 1500);
    const uint64_t seed0  = env_u64("CBAE_SOUNDNESS_SEED0", 1);
    const uint64_t nruns  = env_u64("CBAE_SOUNDNESS_RUNS", 4);
    const uint64_t steps  = env_u64("CBAE_SOUNDNESS_STEPS", 600);
    const uint64_t teeth_funcs = nfuncs < 150 ? nfuncs : 150;

    stats_t st;
    memset(&st, 0, sizeof st);
    uint64_t caught[FORGE_N] = { 0 };

    for (uint64_t fi = 0; fi < nfuncs; fi++) {
        const uint64_t seed = seed0 + fi;
        const cirg_params_t p = cirg_params_for_seed(seed);
        cirg_t *g = NULL;
        const bool built = cirg_build(&g, seed, &p);
        assert(built);
        (void)built;

        fctx_t fx;
        fctx_init(&fx, g->f, seed, &st);
        st.funcs++;

        const view_t real = { fx.claim, fx.form, fx.form_ok, fx.stable };
        for (uint64_t run = 0; run < nruns; run++) {
            const int viol = run_one(&fx, &real, &st, false, seed * 7919 + run, steps);
            if (viol) {
                fprintf(stderr, "FAILED: %d violation(s), function seed %" PRIu64 "\n", viol, seed);
                return 1;
            }
        }

        if (fi < teeth_funcs) {
            stats_t scratch;
            for (int kind = 0; kind < FORGE_N; kind++) {
                view_t v;
                uint8_t *own_u8;
                cbae_addr_info_t *own_form;
                forge(&fx, kind, &v, &own_u8, &own_form);
                for (uint64_t run = 0; run < nruns; run++) {
                    memset(&scratch, 0, sizeof scratch);
                    caught[kind] += (uint64_t)run_one(&fx, &v, &scratch, true, seed * 7919 + run, steps);
                }
                free(own_u8);
                free(own_form);
            }
        }

        fctx_free(&fx);
        cirg_free(g);
    }

    printf("alias soundness: %" PRIu64 " random functions (%" PRIu64 " blocks, %" PRIu64 " with loops), "
           "%" PRIu64 " runs, %" PRIu64 " steps\n",
           st.funcs, st.blocks, st.loop_funcs, st.runs, st.steps);
    printf("  static: %" PRIu64 " memory accesses; pairs NO=%" PRIu64 " MUST=%" PRIu64 " MAY=%" PRIu64 "\n",
           st.accesses, st.pairs_no, st.pairs_must, st.pairs_may);
    printf("  dynamic: %" PRIu64 " access executions\n", st.executions);
    printf("  NO checked on %" PRIu64 " (pair,run) cases, MUST on %" PRIu64 "\n", st.checks_no, st.checks_must);
    printf("  pairs observed overlapping: %" PRIu64 " (analysis said MAY for %" PRIu64 ", MUST for %" PRIu64
           ", NO for 0)\n", st.overlap_pairs, st.overlap_may, st.overlap_must);
    printf("  decomposition identity checked %" PRIu64 " times (%" PRIu64 " skipped), stability %" PRIu64 " times\n",
           st.id_checks, st.id_skipped, st.stab_checks);
    printf("  forms by atom count (static, stable): 0:%" PRIu64 " 1:%" PRIu64 " 2:%" PRIu64 " 3:%" PRIu64 " 4:%" PRIu64
           "; %" PRIu64 " ADD/SUB results left opaque by the term caps\n",
           st.terms_hist[0], st.terms_hist[1], st.terms_hist[2], st.terms_hist[3], st.terms_hist[4], st.opaque_forms);
    for (int kind = 0; kind < FORGE_N; kind++)
        printf("  self-check '%s': %" PRIu64 " violations caught\n", FORGE_NAME[kind], caught[kind]);

    /* Every forgery must have been detected, or the checks above prove nothing. */
    for (int kind = 0; kind < FORGE_N; kind++) assert(caught[kind] > 0);

    /* The claims must have been exercised in volume, not trivially true. */
    if (nfuncs >= 1000) {
        assert(st.pairs_no   >= 5000);
        assert(st.pairs_must >= 2000);
        assert(st.checks_no   >= 5000);
        assert(st.checks_must >= 2000);
        assert(st.overlap_pairs >= 5000);
        assert(st.id_checks >= 100000);
        assert(st.stab_checks >= 10000);
        assert(st.multi_atom_stable >= 500);    /* the term caps are exercised ...            */
        assert(st.opaque_forms >= 100);         /* ... including the opaque-atom fallback     */
    }
    assert(st.id_skipped == 0);

    printf("test_alias_soundness: OK\n");
    return 0;
}
