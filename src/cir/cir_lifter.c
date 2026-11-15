/**
 * @file cir_lifter.c
 * @brief Dispatch: x86-64 -> correct lifter module.
 *
 * TWO PASSES:
 *   1. Create a CIR block for every Phase 3 CFG block, so any
 *      branch/jump target lookup in pass 2 succeeds regardless of
 *      visitation order.
 *   2. Walk each block's x86 instructions in order, dispatching on
 *      cbae_insn_class_t to the matching specialized lifter.
 *
 * Also implements the shared per-block register map (cir_lift_read_reg
 * / cir_lift_write_reg) and Phase-3-operand-to-CIR-value conversion
 * every specialized lifter calls into -- see cir_lifter_internal.h for
 * the full design rationale.
 */
#include "cir_lifter_internal.h"
#include "cir/cir_lifter.h"
#include "platform/logging.h"
#include <string.h>

/* ── Shared register map ──────────────────────────────────────────── */

void cir_lift_reg_map_reset(cir_lift_ctx_t *ctx) {
    memset(ctx->reg_map, 0, sizeof(ctx->reg_map));
}

cbae_cir_value_t *cir_lift_read_reg(cir_lift_ctx_t *ctx, cbae_reg_t reg) {
    /* CBAE_REG_OTHER is Phase 3's catch-all for every narrow (32/16/8-bit)
     * register form -- EAX, AX, AL, EBX, BX, ... all map to this SAME
     * enum value. Caching/tracking it as a single reg_map slot would
     * incorrectly alias unrelated narrow registers together. Rather
     * than track it wrongly, every read of a CBAE_REG_OTHER operand
     * gets its own FRESH, never-cached placeholder -- correctly
     * unresolvable rather than silently wrong. Compiler-generated
     * kernel driver code overwhelmingly uses full 64-bit or 32-bit
     * (Capstone-mapped) register forms for the registers CBAE tracks;
     * this only affects the narrow-form edge cases already documented
     * as a known simplification. */
    if (reg == CBAE_REG_OTHER) {
        cbae_cir_value_t *v = CBAE_ARENA_ALLOC(ctx->func->arena, cbae_cir_value_t);
        if (!v) return NULL;
        v->kind = CIR_VAL_REG_ENTRY;
        v->type = cir_type_i(64);
        v->id   = ctx->func->next_value_id++;
        v->u.reg_entry.reg      = reg;
        v->u.reg_entry.block_id = ctx->cir_block->id;
        cbae_vector_push(&ctx->func->values, &v);
        return v;
    }

    if (reg <= CBAE_REG_NONE || (int)reg >= CIR_REG_MAP_SIZE) return NULL;
    if (ctx->reg_map[reg]) return ctx->reg_map[reg];

    /* Not yet written in this block -- create (and cache) an unresolved
     * placeholder. Caching matters: two reads of the same unwritten
     * register before any local write must return the SAME value. */
    cbae_cir_value_t *v = CBAE_ARENA_ALLOC(ctx->func->arena, cbae_cir_value_t);
    if (!v) return NULL;
    v->kind = CIR_VAL_REG_ENTRY;
    v->type = cir_type_i(64);
    v->id   = ctx->func->next_value_id++;
    v->u.reg_entry.reg      = reg;
    v->u.reg_entry.block_id = ctx->cir_block->id;
    cbae_vector_push(&ctx->func->values, &v);

    ctx->reg_map[reg] = v;
    return v;
}

void cir_lift_write_reg(cir_lift_ctx_t *ctx, cbae_reg_t reg, cbae_cir_value_t *value) {
    /* Writes to a CBAE_REG_OTHER (narrow-form) destination are silently
     * dropped rather than corrupting the shared slot -- see the read
     * side's comment above for why this register class can't be
     * tracked precisely in Phase 4's model. */
    if (reg == CBAE_REG_OTHER) return;
    if (reg <= CBAE_REG_NONE || (int)reg >= CIR_REG_MAP_SIZE) return;
    ctx->reg_map[reg] = value;
}

/* ── Operand conversion (REG/IMM/MEM -> CIR value) ───────────────────── */

cbae_cir_value_t *cir_lift_operand_value(cir_lift_ctx_t *ctx,
                                          const cbae_operand_t *op,
                                          const cbae_instruction_t *insn) {
    switch (op->kind) {
        case CBAE_OPND_REG:
            return cir_lift_read_reg(ctx, op->u.reg.reg);

        case CBAE_OPND_IMM:
            return cbae_cir_const(&ctx->builder, cir_type_i(64), op->u.imm.value);

        case CBAE_OPND_MEM: {
            if (op->u.mem.base == CBAE_REG_RIP) {
                /* RIP-relative displacement is relative to the address
                 * AFTER this instruction -- same formula validated in
                 * Phase 3's call_graph_builder.c. The absolute address
                 * is therefore a compile-time constant here. */
                cbae_addr_t abs = insn->address + insn->length +
                                   (cbae_addr_t)op->u.mem.disp;
                return cbae_cir_const(&ctx->builder, cir_type_ptr(), (int64_t)abs);
            }

            cbae_cir_value_t *addr = NULL;
            if (op->u.mem.base != CBAE_REG_NONE)
                addr = cir_lift_read_reg(ctx, op->u.mem.base);

            if (op->u.mem.index != CBAE_REG_NONE) {
                cbae_cir_value_t *idx = cir_lift_read_reg(ctx, op->u.mem.index);
                cbae_cir_value_t *scale =
                    cbae_cir_const(&ctx->builder, cir_type_i(64), op->u.mem.scale);
                cbae_cir_value_t *scaled =
                    cbae_cir_binop(&ctx->builder, CIR_OP_MUL, idx, scale,
                                   cir_type_ptr(), insn->address);
                addr = addr
                    ? cbae_cir_binop(&ctx->builder, CIR_OP_ADD, addr, scaled,
                                     cir_type_ptr(), insn->address)
                    : scaled;
            }

            if (op->u.mem.disp != 0) {
                cbae_cir_value_t *disp =
                    cbae_cir_const(&ctx->builder, cir_type_ptr(), op->u.mem.disp);
                addr = addr
                    ? cbae_cir_binop(&ctx->builder, CIR_OP_ADD, addr, disp,
                                     cir_type_ptr(), insn->address)
                    : disp;
            }

            if (!addr) /* base=none, index=none, disp=0: degenerate [0] */
                addr = cbae_cir_const(&ctx->builder, cir_type_ptr(), 0);

            return addr;
        }

        default:
            return NULL;
    }
}

/* ── Dispatcher ────────────────────────────────────────────────────── */

cbae_err_t cbae_cir_lift_function(const cbae_binary_image_t *img,
                                   const cbae_cfg_t *cfg,
                                   const cbae_call_graph_t *cg,
                                   cbae_arena_t *arena,
                                   const char *name,
                                   cbae_cir_function_t **out) {
    if (!img || !cfg || !arena || !out)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    cbae_cir_function_t *func;
    CBAE_CHECK(cbae_cir_function_create(arena, cfg->entry_addr, name, &func));

    uint32_t nblocks = cbae_cfg_block_count(cfg);

    /* CIR INVARIANT: block 0 is the function entry and has NO
     * predecessors (the same rule LLVM IR enforces). Machine code can
     * break it: when the first instruction is also a branch target
     * (`foo: dec rcx; jnz foo; ret`) the entry block has a real
     * predecessor, and then "the value of rcx on entry" is a merge of
     * the caller's rcx and the loop's -- a phi whose one incoming edge
     * comes from "the function's caller", which no block represents.
     * The SSA constructor would have nothing to hang that incoming
     * value on (and recurses forever looking for one).
     *
     * So in that case a SYNTHETIC entry block is created FIRST (id 0)
     * whose only job is to jump to the real entry block. It stands for
     * the function's entry edge: it has no predecessors, nothing in it
     * writes a register, so every live-in register resolves through it
     * to a CIR_VAL_PARAM, and the real entry block becomes an ordinary
     * join (synthetic block + back edges) that gets a normal phi.
     *
     * The synthetic block shares the entry address. That is harmless:
     * cbae_cir_block_create() registers it under that address first,
     * and the real entry block's creation then re-points the address
     * to itself, so cbae_cir_function_block_at(f, entry_addr) keeps
     * answering "the real entry block", as it does for every function.
     * Functions whose entry is NOT a branch target get no synthetic
     * block and are lifted exactly as before. */
    bool entry_is_branch_target = false;
    for (uint32_t i = 0; i < nblocks && !entry_is_branch_target; i++) {
        cbae_basic_block_t *xb = cbae_cfg_block_at_index(cfg, i);
        for (int si = 0; si < xb->successor_count; si++) {
            if (xb->successors[si].target == cfg->entry_addr) {
                entry_is_branch_target = true;
                break;
            }
        }
    }

    cbae_cir_block_t *synthetic_entry = NULL;
    if (entry_is_branch_target) {
        cbae_err_t e = cbae_cir_block_create(func, cfg->entry_addr, &synthetic_entry);
        if (e != CBAE_OK) { cbae_cir_function_destroy(func); return e; }
    }

    /* Pass 1: pre-create every CIR block. */
    for (uint32_t i = 0; i < nblocks; i++) {
        cbae_basic_block_t *xb = cbae_cfg_block_at_index(cfg, i);
        cbae_cir_block_t *cb;
        cbae_err_t e = cbae_cir_block_create(func, xb->start_addr, &cb);
        if (e != CBAE_OK) { cbae_cir_function_destroy(func); return e; }
    }

    /* Wire the synthetic entry to the real one BEFORE pass 2 adds the
     * back edges, so it is the real entry block's FIRST predecessor and
     * its phis list the function-entry value first, like any loop. */
    if (synthetic_entry) {
        cbae_cir_block_t *real_entry = cbae_cir_function_block_at(func, cfg->entry_addr);
        if (!real_entry || real_entry == synthetic_entry) {
            cbae_cir_function_destroy(func);
            CBAE_RETURN_ERR(CBAE_ERR_INVALID,
                "CFG has no block at its own entry address 0x%llx",
                (unsigned long long)cfg->entry_addr);
        }
        cbae_cir_builder_t entry_builder;
        cbae_cir_builder_init(&entry_builder, func, synthetic_entry);
        cbae_cir_jump(&entry_builder, real_entry, cfg->entry_addr);
    }

    /* Pass 2: lift each block's instructions. */
    cir_lift_ctx_t ctx;
    ctx.img = img;
    ctx.cfg = cfg;
    ctx.cg  = cg;
    ctx.func = func;

    for (uint32_t i = 0; i < nblocks; i++) {
        cbae_basic_block_t *xb = cbae_cfg_block_at_index(cfg, i);
        cbae_cir_block_t *cb = cbae_cir_function_block_at(func, xb->start_addr);
        if (!cb) continue; /* unreachable: pass 1 created all blocks */

        ctx.cir_block = cb;
        cbae_cir_builder_init(&ctx.builder, func, cb);
        cir_lift_reg_map_reset(&ctx);

        for (uint32_t ii = 0; ii < xb->instruction_count; ii++) {
            const cbae_instruction_t *insn = &xb->instructions[ii];
            switch (insn->iclass) {
                case CBAE_ICLASS_MOV:
                case CBAE_ICLASS_LEA:
                case CBAE_ICLASS_STACK:
                    cir_lift_memory_insn(&ctx, insn);
                    break;
                case CBAE_ICLASS_IO:
                case CBAE_ICLASS_MSR:
                    cir_lift_io_insn(&ctx, insn);
                    break;
                case CBAE_ICLASS_CALL:
                    cir_lift_call_insn(&ctx, insn);
                    break;
                case CBAE_ICLASS_ARITH:
                case CBAE_ICLASS_CMP:
                    cir_lift_arithmetic_insn(&ctx, insn);
                    break;
                case CBAE_ICLASS_JMP:
                case CBAE_ICLASS_JCC:
                case CBAE_ICLASS_RET:
                    cir_lift_branch_insn(&ctx, insn, xb);
                    break;
                case CBAE_ICLASS_NOP:
                case CBAE_ICLASS_INT:
                case CBAE_ICLASS_PRIV:
                default:
                    /* No CIR effect modelled yet: NOP is a genuine
                     * no-op; INT3/CLI/STI/HLT etc. have real hardware
                     * effects but no data-flow to represent in Phase 4.
                     * Silently skipped -- not an error. */
                    break;
            }
        }

        /* Persist this block's ending register state -- the SSA
         * constructor needs it to know what THIS block contributes to
         * a successor's phi, which is a different question from what
         * an unresolved placeholder created WITHIN this block should
         * resolve to. See cir_block.h's final_reg_state comment and
         * cir_ssa_constructor.c's resolve_entry_value vs
         * read_predecessor_value for the full reasoning. */
        memcpy(cb->final_reg_state, ctx.reg_map, sizeof(ctx.reg_map));

        /* Uniformly connect every edge Phase 3 recorded for this
         * block, regardless of what caused the block to end.
         * cir_lift_branch_insn's JCC/JMP handling already created
         * these via cbae_cir_branch()/cbae_cir_jump() internally, so
         * those get a harmless idempotent no-op here -- but CALL-
         * ending blocks (whose CALL_RETURN successor cir_lift_call_insn
         * never wires up) and blocks that end via pure STRUCTURAL
         * convergence (falling into an already-known block boundary
         * with no branch/jump/call instruction at the transition point
         * at all -- exactly what happens to a block truncated by
         * Phase 3's mid-block split logic) would otherwise never get a
         * CIR-level predecessor/successor edge at all, silently
         * breaking the SSA constructor's cross-block resolution. */
        for (int si = 0; si < xb->successor_count; si++) {
            cbae_addr_t succ_addr = xb->successors[si].target;
            cbae_cir_block_t *succ_cb = cbae_cir_function_block_at(func, succ_addr);
            if (succ_cb) cbae_cir_block_add_edge(cb, succ_cb);
        }
    }

    *out = func;
    return CBAE_OK;
}
