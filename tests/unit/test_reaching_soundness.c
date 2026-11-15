/**
 * @file test_reaching_soundness.c
 * @brief Reaching stores checked against real executions of random functions.
 *
 * test_reaching_stores.c holds the cases somebody worked out on paper. This
 * test asks the question the analysis exists to answer on functions nobody
 * designed: build a random valid-SSA function (cir_random.h), run it for real
 * several times with different initial registers and memory, and compare what
 * happened with what was claimed. The interpreter remembers, for every byte of
 * memory, which instruction wrote it last (a STORE, or a CALL / API_CALL, which
 * overwrite memory in ways CIR does not describe).
 *
 * WHAT IS CHECKED (reaching_stores.h, SOUNDNESS CLAIM)
 *   1. Loads.  For every dynamic LOAD and every byte it reads:
 *        - the byte's last writer w is in cbae_reaching_stores_for_load(load);
 *        - a byte nobody has written yet implies may_be_initial.
 *   2. Raw dataflow.  Before every instruction executes, every STORE or CALL
 *      that is the last writer of at least one byte satisfies
 *      cbae_reaching_stores_may_reach(at, writer).
 *   3. Forwarding.  Whenever a load that cbae_reaching_stores_forwardable
 *      approves executes, the value it reads is, bit for bit, the value the
 *      approving store last stored. (The store must also have run.)
 *   Statically, for every load: the answer has no duplicates and is in
 *   definition order, a short output buffer gets the first entries and the full
 *   count, the answer is a subset of the raw dataflow, and "forwardable" holds
 *   exactly when the answer is one store, no initial content, and an alias MUST.
 *   For every instruction: it is a definition exactly when
 *   cbae_rs_classify_opcode says so, numbered by block and position.
 *
 * THE TEST CHECKS ITSELF
 *   A checker that can never fail proves nothing. After the real runs, the same
 *   runs are checked against deliberately false claims (empty answers, answers
 *   without barriers, answers without stores, no initial content, one element
 *   dropped from every answer of two or more, forwarding to any store, raw
 *   dataflow that never reaches / never reaches from barriers / never reaches
 *   from stores) and each forgery must be caught. Statistics at the end show
 *   the claims were exercised in volume: bytes last written by a store, by a
 *   call and by nobody, forwarded executions, loads with several possible
 *   writers.
 *
 * Environment (for longer runs): CBAE_SOUNDNESS_FUNCS, CBAE_SOUNDNESS_SEED0,
 * CBAE_SOUNDNESS_RUNS, CBAE_SOUNDNESS_STEPS.
 */
#include "cir_random.h"
#include "cir/cir_printer.h"
#include "dataflow/alias_analysis.h"
#include "dataflow/reaching_stores.h"
#include "dataflow/use_def.h"
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

#define HIST_N 8      /* answer sizes 0 1 2 3 4 5-8 9-16 17+ */

typedef struct {
    uint64_t funcs, blocks, loop_funcs;
    uint64_t defs, stores, barriers;
    uint64_t loads, loads_fwd, loads_initial;
    uint64_t hist[HIST_N];
    uint64_t claimed_elems, observed_elems;     /* answer elements, and those some run actually used */
    uint64_t init_claims, init_observed;
    uint64_t runs, steps;
    uint64_t load_execs, mixed_writer_execs, mixed_initial_execs;
    uint64_t bytes, bytes_store, bytes_call, bytes_initial;
    uint64_t raw_checks, fwd_execs;
} stats_t;

static unsigned hist_bin(uint32_t n) {
    return n <= 4 ? n : n <= 8 ? 5 : n <= 16 ? 6 : 7;
}

/* ── Per-function facts ──────────────────────────────────────────────── */

typedef struct {
    const cbae_cir_function_t *f;
    uint64_t                   seed;
    cbae_use_def_t             ud;
    cbae_alias_ctx_t           alias;
    cbae_reaching_stores_t     rs;

    uint32_t                   ndefs;
    const cbae_rs_def_t      **def;          /* [ndefs]                                     */
    int32_t                   *def_of_id;    /* [next_insn_id]  definition index, or -1     */

    uint32_t                   nloads;
    const cbae_cir_instruction_t **load;     /* [nloads]                                    */
    int32_t                   *load_of_id;   /* [next_insn_id]  load index, or -1           */
    uint8_t                   *in_set;       /* [nloads * ndefs] the claimed answer         */
    uint8_t                   *initial;      /* [nloads]         the claimed may_be_initial */
    int32_t                   *fwd;          /* [nloads]  forwarding store (def index), -1  */
    uint8_t                   *obs;          /* [nloads * ndefs] seen as a last writer      */
    uint8_t                   *obs_init;     /* [nloads]         initial content seen       */

    int                        reported;
} fctx_t;

/* How the raw dataflow claim is taken for a check. */
enum { RAW_REAL = 0, RAW_NEVER, RAW_NO_BARRIERS, RAW_NO_STORES };

/* What a run checks against: normally the analysis' own answers, in the
 * self-checks forged ones. */
typedef struct {
    const uint8_t *in_set;
    const uint8_t *initial;
    const int32_t *fwd;
    int            raw;
} view_t;

static void check_load_static(fctx_t *fx, uint32_t li, stats_t *st) {
    const cbae_cir_instruction_t *ld = fx->load[li];
    const uint32_t nd = fx->ndefs;

    uint32_t cnt = 0;
    bool init = false;
    cbae_err_t rc = cbae_reaching_stores_for_load(&fx->rs, ld, NULL, 0, &cnt, &init);
    assert(rc == CBAE_OK);
    assert(cnt <= nd);

    const cbae_rs_def_t **buf = calloc((size_t)cnt + 1, sizeof *buf);
    assert(buf);
    uint32_t cnt2 = 0;
    bool init2 = !init;
    rc = cbae_reaching_stores_for_load(&fx->rs, ld, buf, cnt, &cnt2, &init2);
    assert(rc == CBAE_OK && cnt2 == cnt && init2 == init);

    /* A short buffer gets the first entries and the full count; either output may be omitted. */
    if (cnt >= 2) {
        const cbae_rs_def_t *part[1] = { NULL };
        uint32_t c3 = 0;
        rc = cbae_reaching_stores_for_load(&fx->rs, ld, part, 1, &c3, NULL);
        assert(rc == CBAE_OK && c3 == cnt && part[0] == buf[0]);
    }
    {
        bool i4 = !init;
        uint32_t c4 = 0;
        rc = cbae_reaching_stores_for_load(&fx->rs, ld, NULL, 0, NULL, &i4);
        assert(rc == CBAE_OK && i4 == init);
        rc = cbae_reaching_stores_for_load(&fx->rs, ld, NULL, 0, &c4, NULL);
        assert(rc == CBAE_OK && c4 == cnt);
    }

    /* Definition order, no duplicates, and nothing the raw dataflow denies. */
    int64_t prev = -1;
    for (uint32_t i = 0; i < cnt; i++) {
        const int32_t d = fx->def_of_id[buf[i]->insn->id];
        assert(d >= 0 && fx->def[d] == buf[i]);
        assert((int64_t)d > prev && "answer is not in definition order, or repeats an entry");
        prev = d;
        fx->in_set[(size_t)li * nd + (uint32_t)d] = 1;
        assert(cbae_reaching_stores_may_reach(&fx->rs, ld, buf[i]->insn) &&
               "the refined answer contains a definition the raw dataflow says cannot reach");
    }
    fx->initial[li] = init;

    /* Forwarding holds exactly when its definition says so. */
    const cbae_cir_instruction_t *via = NULL;
    const bool fw = cbae_reaching_stores_forwardable(&fx->rs, ld, &via);
    bool want = false;
    if (cnt == 1 && !init && !buf[0]->is_barrier) {
        const cbae_cir_value_t *la, *sa;
        uint32_t lsz, ssz;
        const bool a = cbae_alias_mem_access(ld, &la, &lsz);
        const bool b = cbae_alias_mem_access(buf[0]->insn, &sa, &ssz);
        assert(a && b);
        (void)a; (void)b;
        want = cbae_alias_query(&fx->alias, sa, ssz, la, lsz) == CBAE_ALIAS_MUST;
    }
    assert(fw == want && "forwardable() disagrees with its definition");
    assert(cbae_reaching_stores_forwardable(&fx->rs, ld, NULL) == fw);
    if (fw) {
        assert(via == buf[0]->insn);
        fx->fwd[li] = fx->def_of_id[via->id];
        st->loads_fwd++;
    } else {
        fx->fwd[li] = -1;
    }

    st->loads++;
    if (init) st->loads_initial++;
    st->hist[hist_bin(cnt)]++;
    free(buf);
}

static void fctx_init(fctx_t *fx, const cbae_cir_function_t *f, uint64_t seed, stats_t *st) {
    memset(fx, 0, sizeof *fx);
    fx->f = f;
    fx->seed = seed;
    cbae_err_t rc = cbae_use_def_build(f, &fx->ud);
    assert(rc == CBAE_OK);
    rc = cbae_alias_ctx_build(&fx->ud, &fx->alias);
    assert(rc == CBAE_OK);
    rc = cbae_reaching_stores_build(&fx->ud, &fx->alias, &fx->rs);
    assert(rc == CBAE_OK);
    (void)rc;

    const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
    st->blocks += nb;
    for (uint32_t b = 0; b < nb; b++)
        if (cbae_alias_block_on_cycle(&fx->alias, b)) { st->loop_funcs++; break; }

    const size_t nid = f->next_insn_id ? f->next_insn_id : 1;
    fx->def_of_id  = malloc(nid * sizeof *fx->def_of_id);
    fx->load_of_id = malloc(nid * sizeof *fx->load_of_id);
    assert(fx->def_of_id && fx->load_of_id);
    for (size_t i = 0; i < nid; i++) { fx->def_of_id[i] = -1; fx->load_of_id[i] = -1; }

    fx->ndefs = cbae_reaching_stores_def_count(&fx->rs);
    fx->def = calloc(fx->ndefs ? fx->ndefs : 1, sizeof *fx->def);
    assert(fx->def);
    for (uint32_t i = 0; i < fx->ndefs; i++) {
        const cbae_rs_def_t *d = cbae_reaching_stores_def(&fx->rs, i);
        assert(d);
        fx->def[i] = d;
        fx->def_of_id[d->insn->id] = (int32_t)i;
        if (d->is_barrier) st->barriers++; else st->stores++;
    }
    assert(cbae_reaching_stores_def(&fx->rs, fx->ndefs) == NULL);
    st->defs += fx->ndefs;

    /* Every instruction is a definition exactly when its opcode says so, and the
     * definitions are numbered by block and then position. */
    uint32_t nloads = 0, seen_defs = 0;
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            const cbae_rs_def_t *d = cbae_reaching_stores_def_of(&fx->rs, in);
            switch (cbae_rs_classify_opcode(in->opcode)) {
                case CBAE_RS_OP_READONLY: assert(d == NULL); break;
                case CBAE_RS_OP_BARRIER:  assert(d && d->is_barrier); break;
                case CBAE_RS_OP_STORE:    assert(d && !d->is_barrier && in->operand_count >= 2); break;
            }
            if (d) {
                assert(d->insn == in && d->block_id == b);
                assert(seen_defs < fx->ndefs && fx->def[seen_defs] == d);
                seen_defs++;
            }
            if (in->opcode == CIR_OP_LOAD) nloads++;
        }
    }
    assert(seen_defs == fx->ndefs);

    fx->nloads   = nloads;
    fx->load     = calloc(nloads ? nloads : 1, sizeof *fx->load);
    fx->in_set   = calloc((size_t)nloads * fx->ndefs + 1, 1);
    fx->initial  = calloc(nloads ? nloads : 1, 1);
    fx->fwd      = malloc((nloads ? nloads : 1) * sizeof *fx->fwd);
    fx->obs      = calloc((size_t)nloads * fx->ndefs + 1, 1);
    fx->obs_init = calloc(nloads ? nloads : 1, 1);
    assert(fx->load && fx->in_set && fx->initial && fx->fwd && fx->obs && fx->obs_init);

    uint32_t k = 0;
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++)
            if (blk->instructions[i]->opcode == CIR_OP_LOAD) {
                fx->load[k] = blk->instructions[i];
                fx->load_of_id[blk->instructions[i]->id] = (int32_t)k;
                k++;
            }
    }
    for (uint32_t li = 0; li < nloads; li++) check_load_static(fx, li, st);
}

/* The analysis' answer against what the runs saw, for the loads of one function:
 * how much of each answer was ever needed. Informational. */
static void tally_tightness(const fctx_t *fx, stats_t *st) {
    for (uint32_t li = 0; li < fx->nloads; li++) {
        for (uint32_t d = 0; d < fx->ndefs; d++)
            if (fx->in_set[(size_t)li * fx->ndefs + d]) {
                st->claimed_elems++;
                if (fx->obs[(size_t)li * fx->ndefs + d]) st->observed_elems++;
            }
        if (fx->initial[li]) {
            st->init_claims++;
            if (fx->obs_init[li]) st->init_observed++;
        }
    }
}

static void fctx_free(fctx_t *fx) {
    cbae_reaching_stores_destroy(&fx->rs);
    cbae_alias_ctx_destroy(&fx->alias);
    cbae_use_def_destroy(&fx->ud);
    free(fx->def); free(fx->def_of_id);
    free(fx->load); free(fx->load_of_id);
    free(fx->in_set); free(fx->initial); free(fx->fwd);
    free(fx->obs); free(fx->obs_init);
}

/* ── One run ─────────────────────────────────────────────────────────── */

typedef struct {
    fctx_t   *fx;
    view_t    view;
    stats_t  *st;
    bool      quiet;
    uint64_t  seed;
    int       violations;

    uint64_t *last_val;       /* [ndefs] data of the latest execution of each STORE  */
    uint8_t  *have_last;      /* [ndefs] it has executed                              */
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

static const char *kind_name(const cbae_cir_instruction_t *in) {
    return in->opcode == CIR_OP_STORE ? "store" : in->opcode == CIR_OP_CALL ? "call" : "api_call";
}

/* Claim 2: before `insn` executes, every instruction that is the last writer
 * of some byte is one the raw dataflow says may reach this point. */
static void on_step(void *u, const cbae_cir_instruction_t *insn, const uint32_t *live, uint64_t step) {
    (void)step;
    run_t *r = u;
    fctx_t *fx = r->fx;
    for (uint32_t d = 0; d < fx->ndefs; d++) {
        const cbae_cir_instruction_t *w = fx->def[d]->insn;
        if (live[w->id] == 0) continue;
        bool claim = cbae_reaching_stores_may_reach(&fx->rs, insn, w);
        switch (r->view.raw) {
            case RAW_NEVER:        claim = false; break;
            case RAW_NO_BARRIERS:  if (fx->def[d]->is_barrier)  claim = false; break;
            case RAW_NO_STORES:    if (!fx->def[d]->is_barrier) claim = false; break;
            default: break;
        }
        r->st->raw_checks++;
        if (!claim)
            report(r, "%s #%u is the last writer of %u byte(s) just before insn #%u (block %u), "
                      "but may_reach says it cannot reach there",
                   kind_name(w), w->id, live[w->id], insn->id, cbae_use_def_block_of(&fx->ud, insn));
    }
}

static void on_store(void *u, const cbae_cir_instruction_t *insn, uint64_t addr, uint32_t size,
                     uint64_t data) {
    (void)addr; (void)size;
    run_t *r = u;
    const int32_t d = r->fx->def_of_id[insn->id];
    if (d < 0) { report(r, "store #%u executed but is not a definition", insn->id); return; }
    r->last_val[d]  = data;
    r->have_last[d] = 1;
}

/* Claim 1: every byte a load reads was last written by something in its answer. */
static void on_load(void *u, const cbae_cir_instruction_t *insn, uint64_t addr, uint32_t size,
                    const int32_t *writers) {
    run_t *r = u;
    fctx_t *fx = r->fx;
    const int32_t li = fx->load_of_id[insn->id];
    assert(li >= 0);
    const uint32_t nd = fx->ndefs;
    stats_t *st = r->st;

    st->load_execs++;
    int32_t first = writers[0];
    bool mixed = false, has_initial = false, has_written = false;
    for (uint32_t i = 0; i < size; i++) {
        const int32_t w = writers[i];
        if (w != first) mixed = true;
        st->bytes++;
        if (w < 0) {
            has_initial = true;
            st->bytes_initial++;
            if (!r->quiet) fx->obs_init[li] = 1;
            if (!r->view.initial[li])
                report(r, "load #%u read byte +%u of [0x%" PRIx64 ",+%u) still holding its initial content, "
                          "but may_be_initial is false", insn->id, i, addr, size);
            continue;
        }
        has_written = true;
        const int32_t d = fx->def_of_id[w];
        if (d < 0) {
            report(r, "load #%u read a byte last written by insn #%d, which is not a definition",
                   insn->id, w);
            continue;
        }
        if (fx->def[d]->is_barrier) st->bytes_call++; else st->bytes_store++;
        if (!r->quiet) fx->obs[(size_t)li * nd + (uint32_t)d] = 1;
        if (!r->view.in_set[(size_t)li * nd + (uint32_t)d])
            report(r, "load #%u read byte +%u of [0x%" PRIx64 ",+%u) last written by %s #%d, "
                      "which is not in its reaching set",
                   insn->id, i, addr, size, kind_name(fx->def[d]->insn), w);
    }
    if (mixed) st->mixed_writer_execs++;
    if (has_initial && has_written) st->mixed_initial_execs++;
}

/* Claim 3: a forwarded load reads the value its store last stored. */
static void on_def(void *u, const cbae_cir_instruction_t *insn, uint64_t value, uint64_t step) {
    (void)step;
    if (insn->opcode != CIR_OP_LOAD) return;
    run_t *r = u;
    const fctx_t *fx = r->fx;
    const int32_t li = fx->load_of_id[insn->id];
    assert(li >= 0);
    const int32_t d = r->view.fwd[li];
    if (d < 0) return;
    r->st->fwd_execs++;
    if (!r->have_last[d])
        report(r, "load #%u is forwarded from store #%u, which has not executed",
               insn->id, fx->def[d]->insn->id);
    else if (r->last_val[d] != value)
        report(r, "load #%u read 0x%" PRIx64 " but forwarding from store #%u predicts 0x%" PRIx64,
               insn->id, value, fx->def[d]->insn->id, r->last_val[d]);
}

/* Run the function once and check everything against `view`; returns the
 * number of violations found. */
static int run_one(fctx_t *fx, const view_t *view, stats_t *st, bool quiet,
                   uint64_t run_seed, uint64_t max_steps) {
    run_t r;
    memset(&r, 0, sizeof r);
    r.fx = fx; r.view = *view; r.st = st; r.quiet = quiet; r.seed = run_seed;
    const size_t nd = fx->ndefs ? fx->ndefs : 1;
    r.last_val  = calloc(nd, sizeof *r.last_val);
    r.have_last = calloc(nd, 1);
    assert(r.last_val && r.have_last);

    cirx_hooks_t hk;
    memset(&hk, 0, sizeof hk);
    hk.user = &r;
    hk.on_def   = on_def;
    hk.on_load  = on_load;
    hk.on_store = on_store;
    hk.on_step  = on_step;
    cirx_result_t res;
    cirx_run(fx->f, run_seed, max_steps, &hk, &res);
    st->runs++;
    st->steps += res.steps;

    free(r.last_val);
    free(r.have_last);
    return r.violations;
}

/* ── Forged views for the self-check ─────────────────────────────────── */

enum {
    FORGE_SETS_EMPTY, FORGE_SETS_NO_BARRIERS, FORGE_SETS_NO_STORES, FORGE_NOT_INITIAL,
    FORGE_DROP_ONE, FORGE_FWD_ANY, FORGE_RAW_NEVER, FORGE_RAW_NO_BARRIERS, FORGE_RAW_NO_STORES,
    FORGE_N
};
static const char *const FORGE_NAME[FORGE_N] = {
    "every answer empty", "barriers dropped from every answer", "stores dropped from every answer",
    "no initial content anywhere", "one element dropped from every answer of two or more",
    "every load forwarded from a store of its answer", "raw dataflow reaches nothing",
    "raw dataflow ignores barriers", "raw dataflow ignores stores" };

typedef struct { uint8_t *set; uint8_t *init; int32_t *fwd; } own_t;

static view_t forged_view(const fctx_t *fx, int kind, own_t *own) {
    const uint32_t nd = fx->ndefs, nl = fx->nloads;
    const size_t ns = (size_t)nl * nd + 1;
    view_t v = { fx->in_set, fx->initial, fx->fwd, RAW_REAL };
    memset(own, 0, sizeof *own);
    switch (kind) {
        case FORGE_SETS_EMPTY:
            own->set = calloc(ns, 1);
            assert(own->set);
            v.in_set = own->set;
            break;
        case FORGE_SETS_NO_BARRIERS:
        case FORGE_SETS_NO_STORES:
        case FORGE_DROP_ONE:
            own->set = malloc(ns);
            assert(own->set);
            memcpy(own->set, fx->in_set, ns);
            for (uint32_t li = 0; li < nl; li++) {
                uint32_t n = 0;
                for (uint32_t d = 0; d < nd; d++) n += fx->in_set[(size_t)li * nd + d];
                bool dropped = false;
                for (uint32_t d = 0; d < nd; d++) {
                    uint8_t *bit = &own->set[(size_t)li * nd + d];
                    if (!*bit) continue;
                    if (kind == FORGE_SETS_NO_BARRIERS && fx->def[d]->is_barrier)  *bit = 0;
                    if (kind == FORGE_SETS_NO_STORES   && !fx->def[d]->is_barrier) *bit = 0;
                    if (kind == FORGE_DROP_ONE && n >= 2 && !dropped) { *bit = 0; dropped = true; }
                }
            }
            v.in_set = own->set;
            break;
        case FORGE_NOT_INITIAL:
            own->init = calloc(nl ? nl : 1, 1);
            assert(own->init);
            v.initial = own->init;
            break;
        case FORGE_FWD_ANY:
            own->fwd = malloc((nl ? nl : 1) * sizeof *own->fwd);
            assert(own->fwd);
            for (uint32_t li = 0; li < nl; li++) {
                own->fwd[li] = -1;
                for (uint32_t d = 0; d < nd; d++)
                    if (fx->in_set[(size_t)li * nd + d] && !fx->def[d]->is_barrier) {
                        own->fwd[li] = (int32_t)d;
                        break;
                    }
            }
            v.fwd = own->fwd;
            break;
        case FORGE_RAW_NEVER:       v.raw = RAW_NEVER; break;
        case FORGE_RAW_NO_BARRIERS: v.raw = RAW_NO_BARRIERS; break;
        case FORGE_RAW_NO_STORES:   v.raw = RAW_NO_STORES; break;
        default: assert(0);
    }
    return v;
}

/* ── Driver ──────────────────────────────────────────────────────────── */

/* Memory-clobbering density and the amount of store-then-reload code vary with
 * the seed, independently of the size class cirg_params_for_seed picks and of
 * each other: calls from the generator's base rate up to a third of all
 * instructions, reloads from none to most loads. Every combination recurs
 * every 36 seeds. */
static cirg_params_t params_for_seed(uint64_t seed) {
    static const uint32_t BARRIER_PCT[4] = { 0, 8, 18, 35 };
    static const uint32_t RELOAD_PCT[3]  = { 0, 30, 70 };
    cirg_params_t p = cirg_params_for_seed(seed);
    p.barrier_pct = BARRIER_PCT[(seed / 3) % 4];
    p.reload_pct  = RELOAD_PCT[(seed / 12) % 3];
    return p;
}

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
        const cirg_params_t p = params_for_seed(seed);
        cirg_t *g = NULL;
        const bool built = cirg_build(&g, seed, &p);
        assert(built);
        (void)built;

        fctx_t fx;
        fctx_init(&fx, g->f, seed, &st);
        st.funcs++;

        const view_t real = { fx.in_set, fx.initial, fx.fwd, RAW_REAL };
        for (uint64_t run = 0; run < nruns; run++) {
            const int viol = run_one(&fx, &real, &st, false, seed * 7919 + run, steps);
            if (viol) {
                fprintf(stderr, "FAILED: %d violation(s), function seed %" PRIu64 "\n", viol, seed);
                return 1;
            }
        }
        tally_tightness(&fx, &st);

        if (fi < teeth_funcs) {
            stats_t scratch;
            for (int kind = 0; kind < FORGE_N; kind++) {
                own_t own;
                const view_t v = forged_view(&fx, kind, &own);
                for (uint64_t run = 0; run < nruns; run++) {
                    memset(&scratch, 0, sizeof scratch);
                    caught[kind] += (uint64_t)run_one(&fx, &v, &scratch, true, seed * 7919 + run, steps);
                }
                free(own.set); free(own.init); free(own.fwd);
            }
        }

        fctx_free(&fx);
        cirg_free(g);
    }

    printf("reaching-stores soundness: %" PRIu64 " random functions (%" PRIu64 " blocks, %" PRIu64
           " with loops), %" PRIu64 " runs, %" PRIu64 " steps\n",
           st.funcs, st.blocks, st.loop_funcs, st.runs, st.steps);
    printf("  static: %" PRIu64 " definitions (%" PRIu64 " stores, %" PRIu64 " barriers), %" PRIu64
           " loads (%" PRIu64 " forwardable, %" PRIu64 " may read initial content)\n",
           st.defs, st.stores, st.barriers, st.loads, st.loads_fwd, st.loads_initial);
    printf("  answer sizes: 0:%" PRIu64 " 1:%" PRIu64 " 2:%" PRIu64 " 3:%" PRIu64 " 4:%" PRIu64
           " 5-8:%" PRIu64 " 9-16:%" PRIu64 " 17+:%" PRIu64 "\n",
           st.hist[0], st.hist[1], st.hist[2], st.hist[3], st.hist[4], st.hist[5], st.hist[6], st.hist[7]);
    printf("  dynamic: %" PRIu64 " load executions, %" PRIu64 " bytes read: %" PRIu64 " last written by a store, %"
           PRIu64 " by a call, %" PRIu64 " by nobody\n",
           st.load_execs, st.bytes, st.bytes_store, st.bytes_call, st.bytes_initial);
    printf("  loads reading bytes of several writers: %" PRIu64 "; of both written and initial bytes: %" PRIu64 "\n",
           st.mixed_writer_execs, st.mixed_initial_execs);
    printf("  raw dataflow checked %" PRIu64 " times; %" PRIu64 " forwarded executions checked\n",
           st.raw_checks, st.fwd_execs);
    printf("  tightness: %" PRIu64 " of %" PRIu64 " answer elements and %" PRIu64 " of %" PRIu64
           " initial-content claims were needed by some run\n",
           st.observed_elems, st.claimed_elems, st.init_observed, st.init_claims);
    for (int kind = 0; kind < FORGE_N; kind++)
        printf("  self-check '%s': %" PRIu64 " violations caught\n", FORGE_NAME[kind], caught[kind]);

    /* Every forgery must have been detected, or the checks above prove nothing. */
    for (int kind = 0; kind < FORGE_N; kind++) assert(caught[kind] > 0);

    /* The claims must have been exercised in volume, not trivially true. */
    if (nfuncs >= 1000) {
        assert(st.loads >= 10000);
        assert(st.bytes_store   >= 40000);
        assert(st.bytes_call    >= 80000);
        assert(st.bytes_initial >= 150000);
        assert(st.raw_checks    >= 2000000);
        assert(st.mixed_writer_execs  >= 2000);
        assert(st.mixed_initial_execs >= 1000);
        assert(st.loads_fwd >= 500);
        assert(st.fwd_execs >= 2500);
    }

    printf("test_reaching_soundness: OK\n");
    return 0;
}
