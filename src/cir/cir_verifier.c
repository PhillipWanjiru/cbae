/**
 * @file cir_verifier.c
 * @brief Structural validator for a CIR function: ids, operands, results,
 *        phis, branch targets and edges. SSA dominance (every use dominated by
 *        its definition) is NOT checked here -- it needs the dominator tree --
 *        so it lives in dataflow/ssa_verifier.h, which runs this check first.
 *        Types and operand counts per opcode are not checked at all.
 *
 * Every analysis indexes its tables by block, value and instruction id and
 * reads operand slots and successor lists without a second look; what they may
 * assume of a function that passed is exactly this list. The first violation
 * found is reported, in this order:
 *   1. No block slot is empty; block ids equal their indices; no block has more
 *      than CIR_BLOCK_MAX_SUCCESSORS successors; the entry (block 0) has no
 *      predecessors (SSA construction cannot give a live-in register its
 *      function-entry value otherwise).
 *   2. No value or instruction slot is empty; a value's kind is a real one;
 *      value ids are unique and below the function's id counter, and so are
 *      instruction ids.
 *   3. Per instruction: at most CIR_MAX_OPERANDS operands, none of the counted
 *      slots empty, none an unresolved CIR_VAL_REG_ENTRY placeholder, each a
 *      value the function registered (catches use of a foreign or freed value).
 *   4. An instruction's result is an instruction result whose defining
 *      instruction is that instruction, and the function registered it.
 *   5. Phis come first in their block (none follows a non-phi). Each has at
 *      least one incoming, and as many as the block has predecessors, from
 *      exactly those blocks, each incoming a registered, resolved value.
 *   6. Every BRANCH/JUMP target is a block that exists.
 *   7. Every edge is recorded on both sides, once: each successor lists the
 *      block as a predecessor and each predecessor lists it as a successor, and
 *      neither list repeats an entry. (The builder's cbae_cir_block_add_edge
 *      keeps both in step; checking anyway catches any code that writes
 *      successors[] or predecessors directly.)
 *
 * COST: linear in the size of the function. Scratch marks indexed by block id
 * replace every "is this id in that list" search, so a block with thousands of
 * predecessors (a shared epilogue, a switch's join) costs no more per edge than
 * any other.
 */
#include "cir/cir_verifier.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    cbae_cir_value_t **by_id;   /* [value id] -> the registered value, or NULL                    */
    uint32_t          *stamp;   /* [block id] scratch: equals `gen` for the members of the set
                                 * being checked. Every set gets a new `gen`, so nothing is cleared. */
    uint32_t           gen;
    uint32_t           nvals;   /* the function's value id counter */
    uint32_t           nblocks;
} ctx_t;

static void set_error(cbae_cir_verify_result_t *r, const char *fmt, ...) {
    if (!r->ok) return;                                  /* the first violation wins */
    r->ok = false;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->message, CIR_VERIFY_MSG_MAX, fmt, ap);
    va_end(ap);
}

static const cbae_cir_block_t *block_at(const cbae_cir_function_t *f, uint32_t b) {
    return *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
}

/* Is `v` a value this function registered? */
static bool known_value(const ctx_t *c, const cbae_cir_value_t *v) {
    return v && v->id < c->nvals && c->by_id[v->id] == v;
}

static bool known_block(const ctx_t *c, uint32_t b) { return b < c->nblocks; }

static bool lists_successor(const cbae_cir_block_t *blk, uint32_t s) {
    for (uint32_t k = 0; k < blk->successor_count; k++)
        if (blk->successors[k] == s) return true;
    return false;
}

/* ── Rule 1 ───────────────────────────────────────────────────────────── */

static void check_blocks(cbae_cir_verify_result_t *r, const cbae_cir_function_t *f, uint32_t nblocks) {
    for (uint32_t b = 0; b < nblocks && r->ok; b++) {
        const cbae_cir_block_t *blk = block_at(f, b);
        if (!blk)
            set_error(r, "block slot %u is NULL", b);
        else if (blk->id != b)
            set_error(r, "block at index %u has id %u (ids must equal indices)", b, blk->id);
        else if (blk->successor_count > CIR_BLOCK_MAX_SUCCESSORS)
            set_error(r, "block%u has %u successors (at most %u)", b, blk->successor_count,
                      (unsigned)CIR_BLOCK_MAX_SUCCESSORS);
    }
    if (r->ok && nblocks > 0) {
        const uint32_t np = (uint32_t)cbae_vector_count(&block_at(f, 0)->predecessors);
        if (np != 0)
            set_error(r, "block0 (the entry) has %u predecessors; the entry must have none", np);
    }
}

/* ── Rule 2 ───────────────────────────────────────────────────────────── */

/* Fills ctx->by_id with the registered values as it goes. */
static void check_ids(cbae_cir_verify_result_t *r, const cbae_cir_function_t *f, ctx_t *c,
                      uint8_t *insn_seen, uint32_t ninsn) {
    const uint32_t nvalues = (uint32_t)cbae_vector_count(&f->values);
    for (uint32_t i = 0; i < nvalues && r->ok; i++) {
        cbae_cir_value_t *v = *(cbae_cir_value_t **)cbae_vector_at(&f->values, i);
        if (!v)
            set_error(r, "value slot %u is NULL", i);
        else if (v->kind == CIR_VAL_INVALID || (unsigned)v->kind > (unsigned)CIR_VAL_REG_ENTRY)
            set_error(r, "value id %u has an invalid kind (%d)", v->id, (int)v->kind);
        else if (v->id >= c->nvals)
            set_error(r, "value id %u is out of range (the function allocated %u)", v->id, c->nvals);
        else if (c->by_id[v->id])
            set_error(r, "value id %u is registered twice", v->id);
        else
            c->by_id[v->id] = v;
    }
    for (uint32_t b = 0; b < c->nblocks && r->ok; b++) {
        const cbae_cir_block_t *blk = block_at(f, b);
        for (uint32_t i = 0; i < blk->instruction_count && r->ok; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            if (!in)
                set_error(r, "block%u: instruction slot %u is NULL", b, i);
            else if (in->id >= ninsn)
                set_error(r, "block%u: instruction id %u is out of range (the function allocated %u)",
                          b, in->id, ninsn);
            else if (insn_seen[in->id])
                set_error(r, "block%u: instruction id %u appears twice", b, in->id);
            else
                insn_seen[in->id] = 1;
        }
    }
}

/* ── Rules 3 to 6, per instruction ────────────────────────────────────── */

/* Rule 3 for one operand slot. */
static void check_operand(cbae_cir_verify_result_t *r, const ctx_t *c, uint32_t b,
                          const cbae_cir_instruction_t *in, uint32_t oi) {
    const cbae_cir_value_t *op = in->operands[oi];
    if (!op) {
        set_error(r, "block%u insn#%u: operand %u is NULL", b, in->id, oi);
    } else if (op->kind == CIR_VAL_REG_ENTRY) {
        set_error(r, "block%u insn#%u: unresolved CIR_VAL_REG_ENTRY operand (SSA construction incomplete)",
                  b, in->id);
    } else if (!known_value(c, op)) {
        set_error(r, "block%u insn#%u: operand %u references a value this function never defined",
                  b, in->id, oi);
    }
}

/* Rule 4. */
static void check_result(cbae_cir_verify_result_t *r, const ctx_t *c, uint32_t b,
                         const cbae_cir_instruction_t *in) {
    const cbae_cir_value_t *v = in->result;
    if (!v) return;
    if (v->kind != CIR_VAL_INSN_RESULT || v->u.def_insn != in)
        set_error(r, "block%u insn#%u: its result is not an instruction result defined by it", b, in->id);
    else if (!known_value(c, v))
        set_error(r, "block%u insn#%u: its result is not registered in the function", b, in->id);
}

/* Rule 5 for one phi (its position in the block is checked by the caller). */
static void check_phi(cbae_cir_verify_result_t *r, ctx_t *c, const cbae_cir_block_t *blk,
                      const cbae_cir_instruction_t *in) {
    const uint32_t nin   = in->phi_incoming_count;
    const uint32_t npred = (uint32_t)cbae_vector_count(&blk->predecessors);
    if (nin == 0) {
        set_error(r, "block%u insn#%u: phi has no incoming values", blk->id, in->id);
        return;
    }
    if (nin > in->phi_incoming_capacity) {
        set_error(r, "block%u insn#%u: phi has %u incoming values but room for only %u",
                  blk->id, in->id, nin, in->phi_incoming_capacity);
        return;
    }
    if (nin != npred) {
        set_error(r, "block%u insn#%u: phi has %u incoming values but block has %u predecessors",
                  blk->id, in->id, nin, npred);
        return;
    }

    /* The incoming blocks, as a set; every predecessor must be in it. Both lists have as many
     * entries as the block has predecessors, and a predecessor repeated is rule 7's finding,
     * so "every predecessor present" is "the two sets are equal". */
    const uint32_t gen = ++c->gen;
    for (uint32_t ci = 0; ci < nin; ci++) {
        const uint32_t pb = in->phi_incoming_blocks[ci];
        if (!known_block(c, pb)) {
            set_error(r, "block%u insn#%u: phi incoming block%u does not exist", blk->id, in->id, pb);
            return;
        }
        c->stamp[pb] = gen;
    }
    for (uint32_t pi = 0; pi < npred; pi++) {
        const uint32_t pred = *(const uint32_t *)cbae_vector_at(&blk->predecessors, pi);
        if (!known_block(c, pred) || c->stamp[pred] != gen) {
            set_error(r, "block%u insn#%u: phi missing an incoming value for predecessor block%u",
                      blk->id, in->id, pred);
            return;
        }
    }
    for (uint32_t ci = 0; ci < nin; ci++) {
        const cbae_cir_value_t *v = in->phi_incoming_values[ci];
        if (v && v->kind == CIR_VAL_REG_ENTRY) {
            set_error(r, "block%u insn#%u: phi incoming value at index %u is an unresolved "
                      "CIR_VAL_REG_ENTRY placeholder", blk->id, in->id, ci);
            return;
        }
        if (!known_value(c, v)) {
            set_error(r, "block%u insn#%u: phi incoming value at index %u references an unknown value",
                      blk->id, in->id, ci);
            return;
        }
    }
}

/* Rule 6. */
static void check_targets(cbae_cir_verify_result_t *r, const ctx_t *c, uint32_t b,
                          const cbae_cir_instruction_t *in) {
    if (in->opcode != CIR_OP_BRANCH && in->opcode != CIR_OP_JUMP) return;
    if (!known_block(c, in->branch_true_block))
        set_error(r, "block%u insn#%u: branch/jump true target block%u does not exist",
                  b, in->id, in->branch_true_block);
    else if (in->opcode == CIR_OP_BRANCH && !known_block(c, in->branch_false_block))
        set_error(r, "block%u insn#%u: branch false target block%u does not exist",
                  b, in->id, in->branch_false_block);
}

static void check_instructions(cbae_cir_verify_result_t *r, const cbae_cir_function_t *f, ctx_t *c) {
    for (uint32_t b = 0; b < c->nblocks && r->ok; b++) {
        const cbae_cir_block_t *blk = block_at(f, b);
        bool seen_non_phi = false;
        for (uint32_t i = 0; i < blk->instruction_count && r->ok; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];

            if (in->operand_count > CIR_MAX_OPERANDS) {
                set_error(r, "block%u insn#%u: %u operands (at most %u)", b, in->id,
                          (unsigned)in->operand_count, (unsigned)CIR_MAX_OPERANDS);
                return;
            }
            for (uint32_t oi = 0; oi < in->operand_count && r->ok; oi++)
                check_operand(r, c, b, in, oi);
            if (r->ok) check_result(r, c, b, in);
            if (!r->ok) return;

            if (in->opcode == CIR_OP_PHI) {
                if (seen_non_phi)
                    set_error(r, "block%u insn#%u: phi after a non-phi instruction (phis must come first)",
                              b, in->id);
                else
                    check_phi(r, c, blk, in);
            } else {
                seen_non_phi = true;
            }
            if (r->ok) check_targets(r, c, b, in);
        }
    }
}

/* ── Rule 7 ───────────────────────────────────────────────────────────── */

static void check_edges(cbae_cir_verify_result_t *r, const cbae_cir_function_t *f, ctx_t *c) {
    /* from_succ[b]: how many blocks list b as a successor. */
    uint32_t *from_succ = calloc(c->nblocks ? c->nblocks : 1, sizeof *from_succ);
    if (!from_succ) {
        set_error(r, "verifier: allocation failed");
        return;
    }

    for (uint32_t b = 0; b < c->nblocks && r->ok; b++) {
        const cbae_cir_block_t *blk = block_at(f, b);
        for (uint32_t k = 0; k < blk->successor_count && r->ok; k++) {
            const uint32_t s = blk->successors[k];
            if (!known_block(c, s)) {
                set_error(r, "block%u: successor block%u does not exist", b, s);
                break;
            }
            for (uint32_t j = 0; j < k; j++)
                if (blk->successors[j] == s) {
                    set_error(r, "block%u: successor block%u listed twice", b, s);
                    break;
                }
            from_succ[s]++;
        }
    }

    /* Each block's predecessor list: members exist, are distinct, and each lists the block as a
     * successor. That makes the list a subset of the blocks that list this one as a successor, so
     * the two are equal exactly when they have the same size. */
    for (uint32_t b = 0; b < c->nblocks && r->ok; b++) {
        const cbae_cir_block_t *blk = block_at(f, b);
        const uint32_t npred = (uint32_t)cbae_vector_count(&blk->predecessors);
        const uint32_t gen = ++c->gen;
        for (uint32_t pi = 0; pi < npred && r->ok; pi++) {
            const uint32_t p = *(const uint32_t *)cbae_vector_at(&blk->predecessors, pi);
            if (!known_block(c, p)) {
                set_error(r, "block%u: predecessor block%u does not exist", b, p);
            } else if (c->stamp[p] == gen) {
                set_error(r, "block%u: predecessor block%u listed twice", b, p);
            } else {
                c->stamp[p] = gen;
                if (!lists_successor(block_at(f, p), b))
                    set_error(r, "block%u: predecessor block%u has no matching successor entry "
                              "(asymmetric edge)", b, p);
            }
        }
        if (r->ok && npred != from_succ[b]) {
            /* Some block lists b as a successor and b does not list it back: name the first. */
            for (uint32_t q = 0; q < c->nblocks && r->ok; q++)
                if (c->stamp[q] != gen && lists_successor(block_at(f, q), b))
                    set_error(r, "block%u: successor block%u has no matching predecessor entry "
                              "(asymmetric edge)", q, b);
        }
    }
    free(from_succ);
}

/* ── Entry point ──────────────────────────────────────────────────────── */

cbae_cir_verify_result_t cbae_cir_verify_function(const cbae_cir_function_t *f) {
    cbae_cir_verify_result_t result;
    result.ok = true;
    result.message[0] = '\0';

    if (!f) { set_error(&result, "null function"); return result; }

    const uint32_t nblocks = (uint32_t)cbae_vector_count(&f->blocks);
    check_blocks(&result, f, nblocks);
    if (!result.ok) return result;

    ctx_t c;
    memset(&c, 0, sizeof c);
    c.nblocks = nblocks;
    c.nvals   = f->next_value_id;
    const uint32_t ninsn = f->next_insn_id;

    c.by_id = calloc(c.nvals ? c.nvals : 1, sizeof *c.by_id);
    c.stamp = calloc(nblocks ? nblocks : 1, sizeof *c.stamp);
    uint8_t *insn_seen = calloc(ninsn ? ninsn : 1, 1);
    if (!c.by_id || !c.stamp || !insn_seen) {
        free(c.by_id); free(c.stamp); free(insn_seen);
        set_error(&result, "verifier: allocation failed");
        return result;
    }

    check_ids(&result, f, &c, insn_seen, ninsn);
    free(insn_seen);
    if (result.ok) check_instructions(&result, f, &c);
    if (result.ok) check_edges(&result, f, &c);

    free(c.by_id);
    free(c.stamp);
    return result;
}
