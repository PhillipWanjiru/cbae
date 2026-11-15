/**
 * @file indirect_call_resolver.c
 * @brief CALL [reg]: single-block backward pattern matching to upgrade
 *        a scoped subset of CBAE_CALL_INDIRECT edges.
 *
 * SCOPE (see call_graph.h's cbae_resolve_indirect_calls documentation):
 *   Only handles `call reg` where the register was loaded by an
 *   immediately-preceding, single-definition `mov reg, imm64` or
 *   `lea reg, [rip+disp]` within the SAME basic block as the call. Any
 *   intervening write to that register invalidates the match. This is
 *   deliberately NOT full dataflow analysis (no cross-block constant
 *   propagation, no WDF dispatch table modelling) -- that is Phase 5/6
 *   territory. What's here is a real, bounded, honest first pass.
 */
#include "disasm/call_graph.h"
#include "disasm/instruction.h"
#include "platform/logging.h"
#include <string.h>

static cbae_basic_block_t *find_block_for_call(const cbae_cfg_t *cfg,
                                                 cbae_addr_t call_site) {
    uint32_t n = cbae_cfg_block_count(cfg);
    for (uint32_t i = 0; i < n; i++) {
        cbae_basic_block_t *b = cbae_cfg_block_at_index(cfg, i);
        if (call_site >= b->start_addr && call_site < b->end_addr)
            return b;
    }
    return NULL;
}

/*
 * Scan backward from the CALL instruction (always the LAST instruction
 * of its block, per cfg_builder.c's design -- CALL always ends a block)
 * for the most recent instruction that writes target_reg, and check
 * whether that write encodes a statically-known address.
 *
 * NOTE: this checks operand[0] BY POSITION rather than the per-operand
 * access/write flag, since Capstone's access field is not populated in
 * DIET builds and this resolver's correctness must not depend on it.
 * For MOV/LEA (and x86 generally, in Capstone's Intel-syntax operand
 * ordering) operand[0] is always the destination.
 */
static bool backward_resolve_register(const cbae_basic_block_t *blk,
                                       cbae_reg_t target_reg,
                                       cbae_addr_t *out_addr) {
    if (blk->instruction_count < 2) return false;

    for (int32_t i = (int32_t)blk->instruction_count - 2; i >= 0; i--) {
        const cbae_instruction_t *insn = &blk->instructions[i];

        if (insn->iclass == CBAE_ICLASS_MOV &&
            insn->operand_count == 2 &&
            insn->operands[0].kind == CBAE_OPND_REG &&
            insn->operands[0].u.reg.reg == target_reg &&
            insn->operands[1].kind == CBAE_OPND_IMM) {
            *out_addr = (cbae_addr_t)insn->operands[1].u.imm.value;
            return true;
        }

        if (insn->iclass == CBAE_ICLASS_LEA &&
            insn->operand_count == 2 &&
            insn->operands[0].kind == CBAE_OPND_REG &&
            insn->operands[0].u.reg.reg == target_reg &&
            insn->operands[1].kind == CBAE_OPND_MEM &&
            insn->operands[1].u.mem.base == CBAE_REG_RIP) {
            cbae_addr_t next = insn->address + insn->length;
            *out_addr = next + (cbae_addr_t)insn->operands[1].u.mem.disp;
            return true;
        }

        /* Any OTHER instruction whose destination (operand[0], by
         * position) is target_reg invalidates the single-definition
         * assumption -- stop searching. CMP/TEST never write their
         * operands, so they're excluded from this check. */
        if (insn->operand_count >= 1 &&
            insn->operands[0].kind == CBAE_OPND_REG &&
            insn->operands[0].u.reg.reg == target_reg &&
            insn->iclass != CBAE_ICLASS_CMP) {
            return false;
        }
    }
    return false;
}

uint32_t cbae_resolve_indirect_calls(cbae_call_graph_t *cg,
                                      const cbae_binary_image_t *img,
                                      const cbae_cfg_t *cfg) {
    uint32_t upgraded = 0;
    uint32_t n = cbae_call_graph_edge_count(cg);

    for (uint32_t i = 0; i < n; i++) {
        /* Mutable view into the same backing storage cbae_call_graph_edge_at
         * exposes as const -- both index into cg->edges directly. */
        cbae_call_edge_t *edge = (cbae_call_edge_t *)cbae_vector_at(&cg->edges, i);
        if (edge->kind != CBAE_CALL_INDIRECT) continue;

        cbae_basic_block_t *blk = find_block_for_call(cfg, edge->call_site);
        if (!blk || blk->instruction_count == 0) continue;

        const cbae_instruction_t *call_insn =
            &blk->instructions[blk->instruction_count - 1];
        if (call_insn->operand_count < 1 ||
            call_insn->operands[0].kind != CBAE_OPND_REG)
            continue; /* only handling `call reg` in this pass */

        cbae_reg_t reg = call_insn->operands[0].u.reg.reg;
        cbae_addr_t resolved;
        if (!backward_resolve_register(blk, reg, &resolved)) continue;

        cbae_import_entry_t *imp = cbae_image_import_at_iat(img, resolved);
        if (imp) {
            edge->kind = CBAE_CALL_IMPORT;
            edge->import_name = imp->name;
            edge->target = CBAE_ADDR_INVALID;
        } else {
            edge->kind = CBAE_CALL_DIRECT;
            edge->target = resolved;
        }
        upgraded++;
        LOG_DEBUG("resolved indirect call at 0x%llx -> 0x%llx",
                  (unsigned long long)edge->call_site,
                  (unsigned long long)resolved);
    }
    return upgraded;
}
