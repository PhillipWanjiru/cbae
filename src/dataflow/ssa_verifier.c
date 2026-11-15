/**
 * @file ssa_verifier.c
 * @brief SSA dominance verification. The rules, and what counts as a
 *        violation, are in ssa_verifier.h; this file is the how.
 *
 * DOMINANCE is computed over the blocks the entry can reach, and only those.
 * The reachable blocks are found first and renumbered densely, then the shared
 * Cooper-Harvey-Kennedy core (dom_core.c) runs on that subgraph. The
 * production dominator tree refuses a function with an unreachable block --
 * such a block has no dominator -- which is right for an analysis and wrong for
 * a verifier, whose job is to look at exactly the functions that may be broken.
 *
 * The structural verifier has run first (cbae_ssa_verify_function), so ids,
 * block and successor numbers, operand slots and phi shapes can be trusted here.
 */
#include "dataflow/ssa_verifier.h"
#include "dataflow/use_def.h"
#include "dom_core.h"
#include "platform/vector.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NONE UINT32_MAX

static void fail(cbae_cir_verify_result_t *r, const char *fmt, ...) {
    if (!r->ok) return;                              /* the first violation wins */
    r->ok = false;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->message, CIR_VERIFY_MSG_MAX, fmt, ap);
    va_end(ap);
}

static const cbae_cir_block_t *block_at(const cbae_cir_function_t *f, uint32_t b) {
    return *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
}

/* ── Dominance over the reachable blocks ──────────────────────────────── */

typedef struct {
    uint32_t *dense;    /* [block id] -> index among the reachable blocks (entry = 0), or NONE */
    uint32_t *enter;    /* [dense index] interval in the dominator tree                        */
    uint32_t *leave;
} dominance_t;

static void dominance_free(dominance_t *d) {
    free(d->dense); free(d->enter); free(d->leave);
    memset(d, 0, sizeof *d);
}

static bool reachable(const dominance_t *d, uint32_t b) { return d->dense[b] != NONE; }

/* Does `a` dominate `b`, inclusive? Both must be reachable. */
static bool dominates(const dominance_t *d, uint32_t a, uint32_t b) {
    const uint32_t x = d->dense[a], y = d->dense[b];
    return d->enter[x] <= d->enter[y] && d->leave[y] <= d->leave[x];
}

static cbae_err_t dominance_build(const cbae_cir_function_t *f, dominance_t *d) {
    memset(d, 0, sizeof *d);
    const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
    d->dense = malloc(sizeof(uint32_t) * nb);
    uint32_t *queue = malloc(sizeof(uint32_t) * nb);
    if (!d->dense || !queue) {
        free(queue); dominance_free(d);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "ssa verifier: alloc failed");
    }
    for (uint32_t i = 0; i < nb; i++) d->dense[i] = NONE;

    /* Breadth-first from block 0: the visiting order is the dense numbering. */
    uint32_t n = 0, head = 0, cap = 0;
    d->dense[0] = n;
    queue[n++] = 0;
    while (head < n) {
        const cbae_cir_block_t *blk = block_at(f, queue[head++]);
        cap += blk->successor_count;
        for (uint32_t k = 0; k < blk->successor_count; k++) {
            const uint32_t s = blk->successors[k];
            if (d->dense[s] == NONE) { d->dense[s] = n; queue[n++] = s; }
        }
    }

    uint32_t *from = malloc(sizeof(uint32_t) * (cap ? cap : 1));
    uint32_t *to   = malloc(sizeof(uint32_t) * (cap ? cap : 1));
    if (!from || !to) {
        free(from); free(to); free(queue); dominance_free(d);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "ssa verifier: alloc failed");
    }
    uint32_t ne = 0;
    for (uint32_t i = 0; i < n; i++) {
        const cbae_cir_block_t *blk = block_at(f, queue[i]);
        for (uint32_t k = 0; k < blk->successor_count; k++) {
            from[ne] = i;
            to[ne]   = d->dense[blk->successors[k]];
            ne++;
        }
    }
    free(queue);

    dom_csr_t csr;
    cbae_err_t rc = dom_csr_build(n, from, to, ne, &csr);
    free(from); free(to);
    if (rc != CBAE_OK) { dominance_free(d); return rc; }

    uint32_t *idom = malloc(sizeof(uint32_t) * n);
    uint32_t *rpo_order = malloc(sizeof(uint32_t) * n);
    uint32_t *rpo_number = malloc(sizeof(uint32_t) * n);
    cbae_vector_t *children = malloc(sizeof(cbae_vector_t) * n);
    d->enter = malloc(sizeof(uint32_t) * n);
    d->leave = malloc(sizeof(uint32_t) * n);
    if (!idom || !rpo_order || !rpo_number || !children || !d->enter || !d->leave) {
        free(idom); free(rpo_order); free(rpo_number); free(children);
        dom_csr_free(&csr); dominance_free(d);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "ssa verifier: alloc failed");
    }

    const dom_graph_t g = { n, 0, csr.succ_off, csr.succ_adj, csr.pred_off, csr.pred_adj };
    rc = dom_core_compute(&g, "ssa verifier", idom, rpo_order, rpo_number);
    dom_csr_free(&csr);
    if (rc == CBAE_OK) rc = dom_core_build_children(n, 0, idom, children);
    if (rc == CBAE_OK) {
        rc = dom_core_number_tree(n, 0, children, d->enter, d->leave);
        for (uint32_t i = 0; i < n; i++) cbae_vector_destroy(&children[i]);
    }
    free(idom); free(rpo_order); free(rpo_number); free(children);
    if (rc != CBAE_OK) dominance_free(d);
    return rc;
}

/* ── Is a value available at a use? ───────────────────────────────────── */

typedef enum {
    AV_OK = 0,
    AV_NO_DEF,            /* not defined by any instruction                              */
    AV_DEF_MISMATCH,      /* named by an instruction whose result is another value       */
    AV_NOT_PLACED,        /* defined by an instruction that is in no block               */
    AV_DEF_UNREACHABLE,   /* defined where the entry cannot reach                        */
    AV_SAME_BLOCK,        /* defined in the use's block, but not before the use          */
    AV_NOT_DOMINATED      /* defined in a block that does not dominate the use's block   */
} av_t;

typedef struct { uint32_t def_insn, def_block, def_pos; } why_t;

/* `ub` is a reachable block. `upos` is the position of the using instruction in it,
 * or NONE for a use at the END of the block (a phi incoming). */
static av_t availability(const cbae_use_def_t *ud, const dominance_t *dom,
                         const cbae_cir_value_t *v, uint32_t ub, uint32_t upos, why_t *why) {
    why->def_insn = why->def_block = why->def_pos = NONE;
    if (v->kind != CIR_VAL_INSN_RESULT)
        return AV_OK;          /* a constant or a parameter: available from function entry (the structural
                                * check has refused every other kind of value, placeholders included) */
    const cbae_cir_instruction_t *d = v->u.def_insn;
    if (!d) return AV_NO_DEF;
    why->def_insn = d->id;
    if (d->result != v) return AV_DEF_MISMATCH;
    const uint32_t db = cbae_use_def_block_of(ud, d);
    if (db == CBAE_USE_DEF_NO_BLOCK) return AV_NOT_PLACED;
    why->def_block = db;
    why->def_pos   = cbae_use_def_pos_of(ud, d);
    if (!reachable(dom, db)) return AV_DEF_UNREACHABLE;
    if (db == ub)              /* a use at the END of the block has upos == NONE, past every position in it */
        return why->def_pos < upos ? AV_OK : AV_SAME_BLOCK;
    return dominates(dom, db, ub) ? AV_OK : AV_NOT_DOMINATED;
}

static void describe(char *buf, size_t n, av_t av, const why_t *w, uint32_t ub, uint32_t upos) {
    switch (av) {
        case AV_NO_DEF:
            snprintf(buf, n, "not defined by any instruction"); break;
        case AV_DEF_MISMATCH:
            snprintf(buf, n, "claimed by insn#%u, which produces a different value", w->def_insn); break;
        case AV_NOT_PLACED:
            snprintf(buf, n, "defined by insn#%u, which is in no block", w->def_insn); break;
        case AV_DEF_UNREACHABLE:
            snprintf(buf, n, "defined by insn#%u in block%u, which the entry cannot reach",
                     w->def_insn, w->def_block); break;
        case AV_SAME_BLOCK:
            snprintf(buf, n, "used before its definition: insn#%u defines it at position %u of this "
                     "block, the use is at position %u", w->def_insn, w->def_pos, upos); break;
        default:    /* AV_NOT_DOMINATED */
            snprintf(buf, n, "defined by insn#%u in block%u, which does not dominate block%u",
                     w->def_insn, w->def_block, ub); break;
    }
}

/* ── The scan ─────────────────────────────────────────────────────────── */

cbae_cir_verify_result_t cbae_ssa_verify_function(const cbae_cir_function_t *f) {
    cbae_cir_verify_result_t r = cbae_cir_verify_function(f);
    if (!r.ok) return r;
    const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
    if (nb == 0) return r;

    cbae_use_def_t ud;
    cbae_err_t rc = cbae_use_def_build(f, &ud);
    if (rc != CBAE_OK) {
        fail(&r, "ssa verifier: could not build the use-def index (error %d)", (int)rc);
        return r;
    }
    dominance_t dom;
    rc = dominance_build(f, &dom);
    if (rc != CBAE_OK) {
        cbae_use_def_destroy(&ud);
        fail(&r, "ssa verifier: could not compute dominance (error %d)", (int)rc);
        return r;
    }

    char why_text[160];
    for (uint32_t b = 0; b < nb && r.ok; b++) {
        if (!reachable(&dom, b)) continue;                 /* uses in unreachable blocks are exempt */
        const cbae_cir_block_t *blk = block_at(f, b);

        for (uint32_t i = 0; i < blk->instruction_count && r.ok; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            why_t why;

            if (in->opcode == CIR_OP_PHI) {                                /* rule 2 */
                for (uint32_t k = 0; k < in->phi_incoming_count && r.ok; k++) {
                    const uint32_t pb = in->phi_incoming_blocks[k];
                    if (!reachable(&dom, pb)) continue;    /* an unreachable predecessor never runs */
                    const cbae_cir_value_t *v = in->phi_incoming_values[k];
                    const av_t av = availability(&ud, &dom, v, pb, NONE, &why);
                    if (av != AV_OK) {
                        describe(why_text, sizeof why_text, av, &why, pb, NONE);
                        fail(&r, "block%u insn#%u: phi incoming %u (%%v%u) from block%u is %s",
                             b, in->id, k, v->id, pb, why_text);
                    }
                }
            } else {                                                       /* rules 1 and 3 */
                for (uint32_t oi = 0; oi < in->operand_count && r.ok; oi++) {
                    const cbae_cir_value_t *v = in->operands[oi];
                    const av_t av = availability(&ud, &dom, v, b, i, &why);
                    if (av != AV_OK) {
                        describe(why_text, sizeof why_text, av, &why, b, i);
                        fail(&r, "block%u insn#%u: operand %u (%%v%u) is %s", b, in->id, oi, v->id, why_text);
                    }
                }
            }
        }
    }

    dominance_free(&dom);
    cbae_use_def_destroy(&ud);
    return r;
}
