/**
 * @file cir_verifier.c
 * @brief SSA dominance + type consistency validator -- structural scope,
 *        per cir_verifier.h's documented boundary with Phase 5.
 *
 * Checks, in order:
 *   1. No CIR_VAL_REG_ENTRY placeholder remains anywhere (SSA
 *      construction must have fully resolved every one).
 *   2. Every operand references a value this function actually defined
 *      (present in f->values -- catches use of a foreign or freed
 *      value, which should never happen but is cheap to confirm).
 *   3. Every phi's incoming-block set exactly matches its block's real
 *      predecessor set (same cardinality, same members).
 *   4. Every phi's incoming VALUES also reference real, known values.
 *   5. Every BRANCH/JUMP target is a block that actually exists.
 *   6. Every successor edge has a matching predecessor entry on the
 *      target side (this should be structurally guaranteed by
 *      cbae_cir_block_add_edge always updating both sides together --
 *      verifying it anyway catches any future bug that bypasses that
 *      API and writes to successors[]/predecessors directly).
 */
#include "cir/cir_verifier.h"
#include "platform/hashmap.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void set_error(cbae_cir_verify_result_t *r, const char *fmt, ...) {
    r->ok = false;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->message, CIR_VERIFY_MSG_MAX, fmt, ap);
    va_end(ap);
}

cbae_cir_verify_result_t cbae_cir_verify_function(const cbae_cir_function_t *f) {
    cbae_cir_verify_result_t result;
    result.ok = true;
    result.message[0] = '\0';

    if (!f) { set_error(&result, "null function"); return result; }

    cbae_hashmap_t known_values;
    if (cbae_hashmap_init(&known_values, 64) != CBAE_OK) {
        set_error(&result, "verifier: hashmap init failed");
        return result;
    }
    uint32_t nvalues = (uint32_t)cbae_vector_count(&f->values);
    for (uint32_t i = 0; i < nvalues; i++) {
        cbae_cir_value_t **vp = cbae_vector_at(&f->values, i);
        cbae_hashmap_insert(&known_values, (uint64_t)(uintptr_t)(*vp), (void *)1);
    }

    cbae_hashmap_t known_blocks;
    if (cbae_hashmap_init(&known_blocks, 16) != CBAE_OK) {
        cbae_hashmap_destroy(&known_values);
        set_error(&result, "verifier: hashmap init failed");
        return result;
    }
    uint32_t nblocks = (uint32_t)cbae_vector_count(&f->blocks);
    for (uint32_t i = 0; i < nblocks; i++) {
        cbae_cir_block_t **bp = cbae_vector_at(&f->blocks, i);
        cbae_hashmap_insert(&known_blocks, (uint64_t)(*bp)->id, (void *)1);
    }

    for (uint32_t bi = 0; bi < nblocks && result.ok; bi++) {
        cbae_cir_block_t **bp = cbae_vector_at(&f->blocks, bi);
        cbae_cir_block_t *blk = *bp;

        for (uint32_t ii = 0; ii < blk->instruction_count && result.ok; ii++) {
            cbae_cir_instruction_t *insn = blk->instructions[ii];

            for (uint8_t oi = 0; oi < insn->operand_count; oi++) {
                cbae_cir_value_t *op = insn->operands[oi];
                if (!op) continue;
                if (op->kind == CIR_VAL_REG_ENTRY) {
                    set_error(&result,
                        "block%u insn#%u: unresolved CIR_VAL_REG_ENTRY "
                        "operand (SSA construction incomplete)",
                        blk->id, insn->id);
                    break;
                }
                void *v;
                if (!cbae_hashmap_get(&known_values, (uint64_t)(uintptr_t)op, &v)) {
                    set_error(&result,
                        "block%u insn#%u: operand references a value this "
                        "function never defined", blk->id, insn->id);
                    break;
                }
            }
            if (!result.ok) break;

            if (insn->opcode == CIR_OP_PHI) {
                uint32_t npred = (uint32_t)cbae_vector_count(&blk->predecessors);
                if (insn->phi_incoming_count != npred) {
                    set_error(&result,
                        "block%u insn#%u: phi has %u incoming values but "
                        "block has %u predecessors", blk->id, insn->id,
                        insn->phi_incoming_count, npred);
                    break;
                }
                for (uint32_t pi = 0; pi < npred; pi++) {
                    uint32_t *pred_id = cbae_vector_at(&blk->predecessors, pi);
                    bool found = false;
                    for (uint32_t ci = 0; ci < insn->phi_incoming_count; ci++)
                        if (insn->phi_incoming_blocks[ci] == *pred_id) { found = true; break; }
                    if (!found) {
                        set_error(&result,
                            "block%u insn#%u: phi missing an incoming value "
                            "for predecessor block%u", blk->id, insn->id, *pred_id);
                        break;
                    }
                }
                if (!result.ok) break;
                for (uint32_t ci = 0; ci < insn->phi_incoming_count; ci++) {
                    void *v;
                    if (!cbae_hashmap_get(&known_values,
                            (uint64_t)(uintptr_t)insn->phi_incoming_values[ci], &v)) {
                        set_error(&result,
                            "block%u insn#%u: phi incoming value at index %u "
                            "references an unknown value", blk->id, insn->id, ci);
                        break;
                    }
                    if (!cbae_hashmap_get(&known_blocks,
                            (uint64_t)insn->phi_incoming_blocks[ci], &v)) {
                        set_error(&result,
                            "block%u insn#%u: phi incoming block%u does not "
                            "exist", blk->id, insn->id, insn->phi_incoming_blocks[ci]);
                        break;
                    }
                }
                if (!result.ok) break;
            }

            if (insn->opcode == CIR_OP_BRANCH || insn->opcode == CIR_OP_JUMP) {
                void *v;
                if (!cbae_hashmap_get(&known_blocks,
                        (uint64_t)insn->branch_true_block, &v)) {
                    set_error(&result,
                        "block%u insn#%u: branch/jump true target block%u "
                        "does not exist", blk->id, insn->id, insn->branch_true_block);
                    break;
                }
                if (insn->opcode == CIR_OP_BRANCH &&
                    !cbae_hashmap_get(&known_blocks,
                        (uint64_t)insn->branch_false_block, &v)) {
                    set_error(&result,
                        "block%u insn#%u: branch false target block%u "
                        "does not exist", blk->id, insn->id, insn->branch_false_block);
                    break;
                }
            }
        }
    }

    for (uint32_t bi = 0; bi < nblocks && result.ok; bi++) {
        cbae_cir_block_t **bp = cbae_vector_at(&f->blocks, bi);
        cbae_cir_block_t *blk = *bp;
        for (uint32_t si = 0; si < blk->successor_count; si++) {
            cbae_cir_block_t **succ_bp = cbae_vector_at(&f->blocks, blk->successors[si]);
            if (!succ_bp) {
                set_error(&result, "block%u: successor block%u does not exist",
                          blk->id, blk->successors[si]);
                break;
            }
            cbae_cir_block_t *succ = *succ_bp;
            bool found = false;
            uint32_t nsp = (uint32_t)cbae_vector_count(&succ->predecessors);
            for (uint32_t pi = 0; pi < nsp; pi++) {
                uint32_t *p = cbae_vector_at(&succ->predecessors, pi);
                if (*p == blk->id) { found = true; break; }
            }
            if (!found) {
                set_error(&result,
                    "block%u: successor block%u has no matching predecessor "
                    "entry (asymmetric edge)", blk->id, blk->successors[si]);
                break;
            }
        }
    }

    cbae_hashmap_destroy(&known_values);
    cbae_hashmap_destroy(&known_blocks);
    return result;
}
