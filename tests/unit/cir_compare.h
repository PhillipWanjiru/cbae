/**
 * @file cir_compare.h
 * @brief Test support: an independent structural comparison of two CIR functions.
 *
 * Two functions are the same when every value, block, instruction, operand, branch target and phi input has the same
 * identity (ids, kinds, constants, opcodes, addresses) and no object is shared between them. It is written against the
 * data structures, not against the serializer, so it can judge a round trip. Used by the serializer test and by the
 * disassembler-to-CIR integration test.
 */
#ifndef CBAE_TEST_CIR_COMPARE_H
#define CBAE_TEST_CIR_COMPARE_H

#include "cir/cir_function.h"
#include "platform/vector.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

/** The id of a value, or an id no value has for NULL. */
static inline uint32_t cir_vid(const cbae_cir_value_t *v) { return v ? v->id : 0xFFFFFFFFu; }

static inline void cir_same_function(const cbae_cir_function_t *a, const cbae_cir_function_t *b) {
    assert(a->entry_addr == b->entry_addr && strcmp(a->name, b->name) == 0);
    assert(cbae_vector_count(&a->values) == cbae_vector_count(&b->values));
    assert(cbae_vector_count(&a->blocks) == cbae_vector_count(&b->blocks));
    assert(a->next_value_id == b->next_value_id && a->next_insn_id == b->next_insn_id && a->next_block_id == b->next_block_id);
    for (size_t i = 0; i < cbae_vector_count(&a->values); i++) {
        const cbae_cir_value_t *x = *(cbae_cir_value_t **)cbae_vector_at(&a->values, i);
        const cbae_cir_value_t *y = *(cbae_cir_value_t **)cbae_vector_at(&b->values, i);
        assert(x != y && x->id == y->id && x->kind == y->kind && x->type.kind == y->type.kind);
        switch (x->kind) {
            case CIR_VAL_CONST:       assert(x->u.const_val == y->u.const_val); break;
            case CIR_VAL_PARAM:       assert(x->u.param_reg == y->u.param_reg); break;
            case CIR_VAL_INSN_RESULT: assert(x->u.def_insn->id == y->u.def_insn->id && y->u.def_insn->result == y); break;
            case CIR_VAL_REG_ENTRY:   assert(x->u.reg_entry.reg == y->u.reg_entry.reg && x->u.reg_entry.block_id == y->u.reg_entry.block_id); break;
            default: assert(!"a value of an unknown kind");
        }
    }
    for (size_t bi = 0; bi < cbae_vector_count(&a->blocks); bi++) {
        const cbae_cir_block_t *x = *(cbae_cir_block_t **)cbae_vector_at(&a->blocks, bi);
        const cbae_cir_block_t *y = *(cbae_cir_block_t **)cbae_vector_at(&b->blocks, bi);
        assert(x != y && x->id == y->id && x->start_addr == y->start_addr);
        assert(x->successor_count == y->successor_count && x->instruction_count == y->instruction_count);
        assert(y->instruction_capacity >= y->instruction_count && (y->instruction_count == 0 || y->instructions));   /* room to build on */
        for (uint32_t i = 0; i < x->successor_count; i++) assert(x->successors[i] == y->successors[i]);
        assert(cbae_vector_count(&x->predecessors) == cbae_vector_count(&y->predecessors));
        for (size_t i = 0; i < cbae_vector_count(&x->predecessors); i++)
            assert(*(uint32_t *)cbae_vector_at(&x->predecessors, i) == *(uint32_t *)cbae_vector_at(&y->predecessors, i));
        for (uint32_t ii = 0; ii < x->instruction_count; ii++) {
            const cbae_cir_instruction_t *p = x->instructions[ii], *q = y->instructions[ii];
            assert(p != q && p->id == q->id && p->opcode == q->opcode && cir_vid(p->result) == cir_vid(q->result));
            assert(p->operand_count == q->operand_count && p->source_addr == q->source_addr);
            for (uint8_t o = 0; o < p->operand_count; o++) assert(cir_vid(p->operands[o]) == cir_vid(q->operands[o]));
            for (uint8_t o = p->operand_count; o < CIR_MAX_OPERANDS; o++) assert(q->operands[o] == NULL);
            assert((p->call_target_name == NULL) == (q->call_target_name == NULL));
            if (p->call_target_name) assert(strcmp(p->call_target_name, q->call_target_name) == 0);
            assert(p->branch_true_block == q->branch_true_block && p->branch_false_block == q->branch_false_block);
            assert(p->phi_incoming_count == q->phi_incoming_count);
            for (uint32_t k = 0; k < p->phi_incoming_count; k++) {
                assert(cir_vid(p->phi_incoming_values[k]) == cir_vid(q->phi_incoming_values[k]));
                assert(p->phi_incoming_blocks[k] == q->phi_incoming_blocks[k]);
            }
        }
    }
}

#endif /* CBAE_TEST_CIR_COMPARE_H */
