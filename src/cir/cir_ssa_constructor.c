/**
 * @file cir_ssa_constructor.c
 * @brief Braun-et-al. SSA construction via recursive value lookup with
 *        lazy phi creation and cycle-breaking memoization.
 *
 * LOAD-BEARING INVARIANT: func->blocks[i]->id == i for every block --
 * every block is created via cbae_cir_block_create(), which assigns
 * ids sequentially (func->next_block_id++) and immediately pushes onto
 * func->blocks with no removal ever happening afterward. This lets
 * block-id-to-block-pointer lookups be a direct O(1) vector index
 * (cbae_vector_at(&func->blocks, id)) rather than needing a hashmap.
 *
 * TWO DIFFERENT QUESTIONS, TWO DIFFERENT FUNCTIONS -- this is the part
 * that took real care to get right (see PHASE4.md for the full trace
 * that caught this before any test was written):
 *
 *   resolve_entry_value(reg, block) answers "what should a placeholder
 *   CREATED WITHIN this exact block resolve to?" A CIR_VAL_REG_ENTRY
 *   placeholder only ever exists because, at the moment the lifter
 *   created it, `block` had NOT yet locally written `reg` -- so this
 *   must NEVER consult block's own final_reg_state (that would
 *   incorrectly pick up a write that happens AFTER the point this
 *   particular read occurred). It goes straight to predecessor logic.
 *
 *   read_predecessor_value(reg, pred_block) answers a DIFFERENT
 *   question: "what does pred_block CONTRIBUTE, having run to
 *   completion, to whichever successor is asking?" This DOES need
 *   pred_block's final_reg_state checked FIRST -- if pred_block wrote
 *   reg itself, THAT write is what flows out of it, full stop.
 *
 * Conflating these two questions into one function is exactly the bug
 * that would turn a loop induction variable's phi into a self-
 * referential value that never picks up the loop body's actual
 * computation (i = phi[0, entry], [i, loop] instead of the correct
 * i = phi[0, entry], [i_next, loop]) -- silently wrong SSA that a
 * naive single-block test would never catch, since it only shows up
 * once a predecessor both PARTICIPATES in a cycle (needing the
 * memoization cache) AND has its own real local write shadowing what
 * the cache would otherwise return. The fix: final_reg_state is always
 * checked BEFORE the cycle-breaking cache in read_predecessor_value,
 * since a real local write can never itself be part of an unresolved
 * cycle (it terminates recursion immediately) -- the cache only ever
 * matters for the pass-through case where no block in the cycle
 * writes the register at all.
 */
#include "cir/cir_ssa.h"
#include "cir/cir_builder.h"
#include "platform/hashmap.h"
#include "platform/logging.h"
#include <string.h>

typedef struct ssa_ctx {
    cbae_cir_function_t *func;
    cbae_hashmap_t        current_def;  /* (block_id,reg) key -> value* */
    cbae_hashmap_t        param_cache;  /* reg -> CIR_VAL_PARAM value*  */
} ssa_ctx_t;

static uint64_t def_key(uint32_t block_id, cbae_reg_t reg) {
    return ((uint64_t)block_id << 8) | (uint64_t)reg;
}

static cbae_cir_value_t *get_or_create_param(ssa_ctx_t *ctx, cbae_reg_t reg) {
    void *v;
    if (cbae_hashmap_get(&ctx->param_cache, (uint64_t)reg, &v))
        return (cbae_cir_value_t *)v;

    cbae_cir_value_t *p = CBAE_ARENA_ALLOC(ctx->func->arena, cbae_cir_value_t);
    p->kind = CIR_VAL_PARAM;
    p->type = cir_type_i(64);
    p->id   = ctx->func->next_value_id++;
    p->u.param_reg = reg;
    cbae_vector_push(&ctx->func->values, &p);
    cbae_hashmap_insert(&ctx->param_cache, (uint64_t)reg, p);
    return p;
}

static cbae_cir_value_t *read_variable_recursive(ssa_ctx_t *ctx, cbae_reg_t reg,
                                                  cbae_cir_block_t *block);

/** What does `pred_block` CONTRIBUTE to a successor's resolution, having
 * run to completion? Checks its own real local write FIRST -- see the
 * file header for why this ordering (before the cycle-breaking cache)
 * is both necessary and safe. */
static cbae_cir_value_t *read_predecessor_value(ssa_ctx_t *ctx, cbae_reg_t reg,
                                                 cbae_cir_block_t *pred_block) {
    if (reg > CBAE_REG_NONE && (int)reg < CIR_BLOCK_REG_SLOTS &&
        pred_block->final_reg_state[reg] &&
        pred_block->final_reg_state[reg]->kind != CIR_VAL_REG_ENTRY) {
        return pred_block->final_reg_state[reg];
    }

    void *v;
    if (cbae_hashmap_get(&ctx->current_def, def_key(pred_block->id, reg), &v))
        return (cbae_cir_value_t *)v;
    return read_variable_recursive(ctx, reg, pred_block);
}

static cbae_cir_value_t *read_variable_recursive(ssa_ctx_t *ctx, cbae_reg_t reg,
                                                  cbae_cir_block_t *block) {
    uint32_t npred = (uint32_t)cbae_vector_count(&block->predecessors);
    cbae_cir_value_t *val;

    if (npred == 0) {
        val = get_or_create_param(ctx, reg);
    } else if (npred == 1) {
        uint32_t *pred_id = cbae_vector_at(&block->predecessors, 0);
        cbae_cir_block_t **pred_blk = cbae_vector_at(&ctx->func->blocks, *pred_id);
        val = read_predecessor_value(ctx, reg, *pred_blk);
    } else {
        /* Memoize the (not-yet-fully-filled) phi BEFORE recursing --
         * this is what breaks infinite recursion on loop back-edges. */
        cbae_cir_value_t *phi = cbae_cir_phi_create(ctx->func, block, cir_type_i(64));
        cbae_hashmap_insert(&ctx->current_def, def_key(block->id, reg), phi);

        for (uint32_t i = 0; i < npred; i++) {
            uint32_t *pred_id = cbae_vector_at(&block->predecessors, i);
            cbae_cir_block_t **pred_blk = cbae_vector_at(&ctx->func->blocks, *pred_id);
            cbae_cir_value_t *incoming = read_predecessor_value(ctx, reg, *pred_blk);
            cbae_cir_phi_add_incoming(ctx->func, phi->u.def_insn, incoming, *pred_id);
        }
        val = phi;
    }

    cbae_hashmap_insert(&ctx->current_def, def_key(block->id, reg), val);
    return val;
}

/** What should a CIR_VAL_REG_ENTRY placeholder CREATED WITHIN `block`
 * resolve to? Never checks block's own final_reg_state -- see the file
 * header for why that would be wrong here specifically. */
static cbae_cir_value_t *resolve_entry_value(ssa_ctx_t *ctx, cbae_reg_t reg,
                                              cbae_cir_block_t *block) {
    void *v;
    if (cbae_hashmap_get(&ctx->current_def, def_key(block->id, reg), &v))
        return (cbae_cir_value_t *)v;
    return read_variable_recursive(ctx, reg, block);
}

cbae_err_t cbae_cir_construct_ssa(cbae_cir_function_t *func) {
    if (!func) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null function");

    ssa_ctx_t ctx;
    ctx.func = func;
    CBAE_CHECK(cbae_hashmap_init(&ctx.current_def, 32));
    cbae_err_t e = cbae_hashmap_init(&ctx.param_cache, 16);
    if (e != CBAE_OK) { cbae_hashmap_destroy(&ctx.current_def); return e; }

    uint32_t nblocks = (uint32_t)cbae_vector_count(&func->blocks);
    for (uint32_t bi = 0; bi < nblocks; bi++) {
        cbae_cir_block_t **bp = cbae_vector_at(&func->blocks, bi);
        cbae_cir_block_t *blk = *bp;

        /* Snapshot the count: cbae_cir_phi_create(), triggered from
         * inside resolve_entry_value/read_predecessor_value while
         * walking THIS block's own operands, only ever inserts phis at
         * the FRONT of OTHER (predecessor/join) blocks -- never this
         * one mid-iteration -- but capturing instruction_count upfront
         * makes that guarantee obviously safe rather than relying on
         * reasoning about it while reading this loop. */
        uint32_t icount = blk->instruction_count;
        for (uint32_t ii = 0; ii < icount; ii++) {
            cbae_cir_instruction_t *insn = blk->instructions[ii];
            if (insn->opcode == CIR_OP_PHI) continue;

            for (uint8_t oi = 0; oi < insn->operand_count; oi++) {
                cbae_cir_value_t *op = insn->operands[oi];
                if (op && op->kind == CIR_VAL_REG_ENTRY) {
                    cbae_cir_block_t **owning_bp =
                        cbae_vector_at(&func->blocks, op->u.reg_entry.block_id);
                    cbae_cir_value_t *resolved =
                        resolve_entry_value(&ctx, op->u.reg_entry.reg, *owning_bp);
                    insn->operands[oi] = resolved;
                }
            }
        }
    }

    cbae_hashmap_destroy(&ctx.current_def);
    cbae_hashmap_destroy(&ctx.param_cache);
    LOG_DEBUG("SSA construction complete for function '%s'", func->name);
    return CBAE_OK;
}
