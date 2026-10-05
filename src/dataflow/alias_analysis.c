/**
 * @file alias_analysis.c
 * @brief Linear-form alias analysis. See alias_analysis.h for the model,
 *        the soundness argument and the limits.
 */
#include "dataflow/alias_analysis.h"
#include "cfg_graph.h"
#include "graph_scc.h"
#include "platform/logging.h"
#include <stdlib.h>
#include <string.h>

#define PHI_NONE      UINT32_MAX
#define WORK_TERMS    8u      /* working capacity before collapsing to an
                               * opaque atom; the public form keeps 4       */

/* ── Working form ────────────────────────────────────────────────────── */

typedef struct { const cbae_cir_value_t *v; uint64_t k; } wterm_t;

typedef struct {
    uint64_t off;
    uint32_t n;
    bool     overflow;
    wterm_t  t[WORK_TERMS];
} wform_t;

typedef struct {
    const cbae_alias_ctx_t *ctx;
    uint32_t                budget;
    wform_t                 f;
} expander_t;

static bool owns_value(const cbae_alias_ctx_t *ctx, const cbae_cir_value_t *v) {
    return ctx && ctx->ud && v && v->id < ctx->ud->value_count &&
           ctx->ud->value_by_id[v->id] == v;
}

static uint32_t phi_slot(const cbae_alias_ctx_t *ctx, const cbae_cir_value_t *v) {
    return owns_value(ctx, v) ? ctx->phi_slot_by_value[v->id] : PHI_NONE;
}

/* Add k*v to the form (k is never 0: expand() stops at a zero multiplier). A
 * coefficient that cancels to zero removes the atom. */
static void add_term(wform_t *f, const cbae_cir_value_t *v, uint64_t k) {
    for (uint32_t i = 0; i < f->n; i++) {
        if (f->t[i].v != v) continue;
        f->t[i].k += k;
        if (f->t[i].k == 0) f->t[i] = f->t[--f->n];
        return;
    }
    if (f->n == WORK_TERMS) { f->overflow = true; return; }
    f->t[f->n].v = v;
    f->t[f->n].k = k;
    f->n++;
}

static bool const_of(const cbae_cir_value_t *v, int64_t *out) {
    if (v && v->kind == CIR_VAL_CONST) { *out = v->u.const_val; return true; }
    return false;
}

/* Expand `mult * v` into the form; `v` is never NULL. Everything here is an
 * identity over 64-bit wrapping arithmetic, so stopping early anywhere
 * (budget, depth, a malformed instruction) only costs precision: the
 * unexpanded value simply becomes an atom. */
static void expand(expander_t *x, const cbae_cir_value_t *v, uint64_t mult, uint32_t depth) {
    if (mult == 0 || x->f.overflow) return;

    if (v->kind == CIR_VAL_CONST) {
        x->f.off += mult * (uint64_t)v->u.const_val;
        return;
    }
    if (v->kind != CIR_VAL_INSN_RESULT || !v->u.def_insn ||
        x->budget == 0 || depth > CBAE_ALIAS_EXPAND_DEPTH) {
        add_term(&x->f, v, mult);
        return;
    }
    x->budget--;
    const cbae_cir_instruction_t *in = v->u.def_insn;

    if (in->opcode == CIR_OP_PHI) {
        const uint32_t slot = phi_slot(x->ctx, v);
        if (slot != PHI_NONE && x->ctx->phi_resolved[slot]) {
            const cbae_addr_info_t *pf = &x->ctx->phi_form[slot];
            x->f.off += mult * (uint64_t)pf->offset;
            for (uint32_t i = 0; i < pf->term_count; i++)
                expand(x, pf->terms[i].value, mult * (uint64_t)pf->terms[i].coeff, depth + 1);
            return;
        }
        add_term(&x->f, v, mult);
        return;
    }

    /* Narrower results wrap at their own width, not at 2^64. */
    if (cir_type_bits(v->type) != 64) { add_term(&x->f, v, mult); return; }

    /* A missing operand (a malformed function) makes this instruction an atom. */
    for (uint32_t k = 0; k < in->operand_count; k++) {
        if (!in->operands[k]) { add_term(&x->f, v, mult); return; }
    }

    int64_t c;
    switch (in->opcode) {
        case CIR_OP_ADD:
            if (in->operand_count >= 2) {
                expand(x, in->operands[0], mult, depth + 1);
                expand(x, in->operands[1], mult, depth + 1);
                return;
            }
            break;
        case CIR_OP_SUB:
            if (in->operand_count >= 2) {
                expand(x, in->operands[0], mult, depth + 1);
                expand(x, in->operands[1], (uint64_t)0 - mult, depth + 1);
                return;
            }
            break;
        case CIR_OP_MUL:
            if (in->operand_count >= 2) {
                if (const_of(in->operands[1], &c)) {
                    expand(x, in->operands[0], mult * (uint64_t)c, depth + 1);
                    return;
                }
                if (const_of(in->operands[0], &c)) {
                    expand(x, in->operands[1], mult * (uint64_t)c, depth + 1);
                    return;
                }
            }
            break;
        case CIR_OP_SHL:
            if (in->operand_count >= 2 && const_of(in->operands[1], &c) && c >= 0 && c < 64) {
                expand(x, in->operands[0], mult << c, depth + 1);
                return;
            }
            break;
        case CIR_OP_NEG:
            if (in->operand_count >= 1) {
                expand(x, in->operands[0], (uint64_t)0 - mult, depth + 1);
                return;
            }
            break;
        case CIR_OP_COPY:
            if (in->operand_count >= 1) {
                expand(x, in->operands[0], mult, depth + 1);
                return;
            }
            break;
        default:
            break;
    }
    add_term(&x->f, v, mult);
}

/* ── Public form ─────────────────────────────────────────────────────── */

static void make_opaque(const cbae_cir_value_t *top, cbae_addr_info_t *out) {
    memset(out, 0, sizeof *out);
    out->term_count = 1;
    out->terms[0].value = top;
    out->terms[0].coeff = 1;
}

/* Once the working form overflows, expand() stops adding anything, so n is
 * WORK_TERMS and the form is over the public limit; that is what makes an
 * overflowed form collapse here. */
_Static_assert(WORK_TERMS > CBAE_ALIAS_MAX_TERMS, "an overflowed working form must exceed the public cap");

static void finalize(const cbae_cir_value_t *top, const wform_t *f, cbae_addr_info_t *out) {
    if (f->n > CBAE_ALIAS_MAX_TERMS) { make_opaque(top, out); return; }

    wterm_t t[WORK_TERMS];
    memcpy(t, f->t, sizeof(wterm_t) * f->n);
    for (uint32_t i = 1; i < f->n; i++) {           /* sort by value id */
        wterm_t key = t[i];
        uint32_t j = i;
        while (j > 0 && t[j - 1].v->id > key.v->id) { t[j] = t[j - 1]; j--; }
        t[j] = key;
    }
    memset(out, 0, sizeof *out);
    out->offset     = (int64_t)f->off;
    out->term_count = f->n;
    for (uint32_t i = 0; i < f->n; i++) {
        out->terms[i].value = t[i].v;
        out->terms[i].coeff = (int64_t)t[i].k;
    }
}

static bool decompose_raw(const cbae_alias_ctx_t *ctx, const cbae_cir_value_t *v,
                          cbae_addr_info_t *out) {
    if (!v) { memset(out, 0, sizeof *out); return false; }
    expander_t x;
    memset(&x, 0, sizeof x);
    x.ctx    = ctx;
    x.budget = CBAE_ALIAS_EXPAND_BUDGET;
    expand(&x, v, 1, 0);
    finalize(v, &x.f, out);
    return true;
}

bool cbae_alias_decompose(const cbae_alias_ctx_t *ctx, const cbae_cir_value_t *addr,
                          cbae_addr_info_t *out) {
    if (!out) return false;
    if (!ctx) { memset(out, 0, sizeof *out); return false; }
    return decompose_raw(ctx, addr, out);
}

static bool same_terms(const cbae_addr_info_t *a, const cbae_addr_info_t *b) {
    if (a->term_count != b->term_count) return false;
    for (uint32_t i = 0; i < a->term_count; i++)
        if (a->terms[i].value != b->terms[i].value || a->terms[i].coeff != b->terms[i].coeff)
            return false;
    return true;
}

/* ── Redundant phis ──────────────────────────────────────────────────── */

static bool form_is_self(const cbae_addr_info_t *f, const cbae_cir_value_t *self) {
    return f->offset == 0 && f->term_count == 1 &&
           f->terms[0].value == self && f->terms[0].coeff == 1;
}

static bool form_mentions(const cbae_addr_info_t *f, const cbae_cir_value_t *v) {
    for (uint32_t i = 0; i < f->term_count; i++)
        if (f->terms[i].value == v) return true;
    return false;
}

/* Record phi == F whenever every incoming value other than the phi itself
 * has the same form F (and F does not mention the phi). Repeat until a pass
 * resolves nothing: resolving one phi can make another's incomings equal.
 * The number of passes is capped so that a hostile function (a long chain
 * of phis, each resolvable only after the next) costs linear, not quadratic,
 * time; a phi left unresolved is simply an atom. */
static void resolve_phis(cbae_alias_ctx_t *c) {
    bool changed;
    uint32_t pass = 0;
    do {
        changed = false;
        for (uint32_t s = 0; s < c->phi_count; s++) {
            if (c->phi_resolved[s]) continue;
            const cbae_cir_instruction_t *phi = c->phi_insn[s];
            const cbae_cir_value_t *self = phi->result;

            cbae_addr_info_t cand, fx;
            memset(&cand, 0, sizeof cand);
            bool have = false, ok = true;
            for (uint32_t k = 0; k < phi->phi_incoming_count; k++) {
                if (!decompose_raw(c, phi->phi_incoming_values[k], &fx)) { ok = false; break; }
                if (form_is_self(&fx, self)) continue;
                if (!have) { cand = fx; have = true; }
                else if (cand.offset != fx.offset || !same_terms(&cand, &fx)) { ok = false; break; }
            }
            if (ok && have && !form_mentions(&cand, self)) {
                c->phi_form[s]     = cand;
                c->phi_resolved[s] = true;
                changed = true;
            }
        }
    } while (changed && ++pass < CBAE_ALIAS_RESOLVE_PASSES);
}

/* ── Context ─────────────────────────────────────────────────────────── */

void cbae_alias_ctx_destroy(cbae_alias_ctx_t *ctx) {
    if (!ctx) return;
    free(ctx->block_on_cycle);
    free(ctx->phi_slot_by_value);
    free((void *)ctx->phi_insn);
    free(ctx->phi_resolved);
    free(ctx->phi_form);
    memset(ctx, 0, sizeof *ctx);
}

cbae_err_t cbae_alias_ctx_build(const cbae_use_def_t *ud, cbae_alias_ctx_t *out) {
    if (!ud || !out || !ud->func)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "alias analysis: null argument");

    memset(out, 0, sizeof *out);
    out->ud = ud;
    const cbae_cir_function_t *f = ud->func;
    const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);
    out->block_count = nb;

    out->block_on_cycle    = calloc(nb ? nb : 1, sizeof(bool));
    out->phi_slot_by_value = malloc(sizeof(uint32_t) * (ud->value_count ? ud->value_count : 1));
    if (!out->block_on_cycle || !out->phi_slot_by_value) {
        cbae_alias_ctx_destroy(out);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "alias analysis: array alloc failed");
    }
    for (uint32_t i = 0; i < ud->value_count; i++) out->phi_slot_by_value[i] = PHI_NONE;

    if (nb > 0) {
        dom_csr_t csr;
        cbae_err_t rc = cfg_csr_build(f, &csr);
        if (rc != CBAE_OK) { cbae_alias_ctx_destroy(out); return rc; }
        rc = graph_scc_on_cycle(nb, csr.succ_off, csr.succ_adj, out->block_on_cycle);
        dom_csr_free(&csr);
        if (rc != CBAE_OK) { cbae_alias_ctx_destroy(out); return rc; }
    }

    /* Index the phis whose result is one of the function's own values. */
    uint32_t nphi = 0;
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            if (in->opcode == CIR_OP_PHI && owns_value(out, in->result)) nphi++;
        }
    }
    out->phi_insn      = malloc(sizeof(*out->phi_insn) * (nphi ? nphi : 1));
    out->phi_resolved  = calloc(nphi ? nphi : 1, sizeof(bool));
    out->phi_form      = calloc(nphi ? nphi : 1, sizeof(cbae_addr_info_t));
    if (!out->phi_insn || !out->phi_resolved || !out->phi_form) {
        cbae_alias_ctx_destroy(out);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "alias analysis: phi table alloc failed");
    }
    uint32_t slot = 0;
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            if (in->opcode != CIR_OP_PHI || !owns_value(out, in->result)) continue;
            out->phi_insn[slot] = in;
            out->phi_slot_by_value[in->result->id] = slot;
            slot++;
        }
    }
    out->phi_count = nphi;

    resolve_phis(out);
    return CBAE_OK;
}

/* ── Queries ─────────────────────────────────────────────────────────── */

bool cbae_alias_block_on_cycle(const cbae_alias_ctx_t *ctx, uint32_t block_id) {
    return ctx && block_id < ctx->block_count && ctx->block_on_cycle[block_id];
}

bool cbae_alias_value_is_stable(const cbae_alias_ctx_t *ctx, const cbae_cir_value_t *v) {
    if (!owns_value(ctx, v)) return false;
    switch (v->kind) {
        case CIR_VAL_CONST:
            return true;
        case CIR_VAL_PARAM:
            /* Every narrow register lifts to this one parameter, so it does
             * not denote a single run-time value. */
            return v->u.param_reg != CBAE_REG_OTHER;
        case CIR_VAL_INSN_RESULT: {
            const uint32_t b = cbae_use_def_block_of(ctx->ud, v->u.def_insn);
            return b != CBAE_USE_DEF_NO_BLOCK && b < ctx->block_count &&
                   !ctx->block_on_cycle[b];
        }
        default:
            return false;
    }
}

cbae_alias_result_t cbae_alias_query_info(const cbae_alias_ctx_t *ctx,
                                          const cbae_addr_info_t *a, uint32_t size_a,
                                          const cbae_addr_info_t *b, uint32_t size_b) {
    if (!ctx || !a || !b) return CBAE_ALIAS_MAY;
    if (size_a == CBAE_ALIAS_UNKNOWN_SIZE || size_b == CBAE_ALIAS_UNKNOWN_SIZE ||
        size_a > CBAE_ALIAS_MAX_ACCESS_SIZE || size_b > CBAE_ALIAS_MAX_ACCESS_SIZE)
        return CBAE_ALIAS_MAY;
    if (!same_terms(a, b)) return CBAE_ALIAS_MAY;
    for (uint32_t i = 0; i < a->term_count; i++)
        if (!cbae_alias_value_is_stable(ctx, a->terms[i].value)) return CBAE_ALIAS_MAY;

    /* Both ranges start at the same unknown-but-fixed point plus a constant:
     * A = [0, size_a), B = [d, d + size_b) relative to A's start. d is the
     * signed distance mod 2^64; sizes are small, so no range can wrap onto
     * the other. */
    const int64_t d = (int64_t)((uint64_t)b->offset - (uint64_t)a->offset);
    if (d == 0 && size_a == size_b) return CBAE_ALIAS_MUST;
    if (d >= (int64_t)size_a || d <= -(int64_t)size_b) return CBAE_ALIAS_NO;
    return CBAE_ALIAS_MAY;
}

cbae_alias_result_t cbae_alias_query(const cbae_alias_ctx_t *ctx,
                                     const cbae_cir_value_t *a, uint32_t size_a,
                                     const cbae_cir_value_t *b, uint32_t size_b) {
    if (!ctx || !a || !b) return CBAE_ALIAS_MAY;
    cbae_addr_info_t ia, ib;
    if (!cbae_alias_decompose(ctx, a, &ia) || !cbae_alias_decompose(ctx, b, &ib))
        return CBAE_ALIAS_MAY;
    return cbae_alias_query_info(ctx, &ia, size_a, &ib, size_b);
}

bool cbae_alias_mem_access(const cbae_cir_instruction_t *insn,
                           const cbae_cir_value_t **addr, uint32_t *size) {
    if (!insn || !addr || !size) return false;
    if (insn->opcode == CIR_OP_LOAD && insn->operand_count >= 1) {
        *addr = insn->operands[0];
        *size = insn->result ? cir_type_bytes(insn->result->type) : CBAE_ALIAS_UNKNOWN_SIZE;
        return true;
    }
    if (insn->opcode == CIR_OP_STORE && insn->operand_count >= 2) {
        *addr = insn->operands[0];
        *size = insn->operands[1] ? cir_type_bytes(insn->operands[1]->type)
                                  : CBAE_ALIAS_UNKNOWN_SIZE;
        return true;
    }
    return false;
}
