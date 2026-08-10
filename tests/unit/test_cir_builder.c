/**
 * @file test_cir_builder.c
 * @brief Unit tests for the CIR builder API, exercised directly (no
 *        lifter involved yet) to validate the foundational data model
 *        in isolation before anything is built on top of it.
 */
#include "cir/cir_builder.h"
#include "cir/cir_printer.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void t_straight_line(void) {
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64 * 1024);

    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(&arena, 0x1000, "test_straight", &f) == CBAE_OK);

    cbae_cir_block_t *entry;
    assert(cbae_cir_block_create(f, 0x1000, &entry) == CBAE_OK);
    assert(entry->id == 0);

    cbae_cir_builder_t b;
    cbae_cir_builder_init(&b, f, entry);

    cbae_cir_value_t *c42  = cbae_cir_const(&b, cir_type_i(64), 42);
    cbae_cir_value_t *prax = cbae_cir_param(&b, CBAE_REG_RAX);
    cbae_cir_value_t *sum  = cbae_cir_binop(&b, CIR_OP_ADD, c42, prax, cir_type_i(64), 0x1004);
    cbae_cir_return(&b, sum, 0x1008);

    assert(c42 != NULL && c42->kind == CIR_VAL_CONST && c42->u.const_val == 42);
    assert(prax != NULL && prax->kind == CIR_VAL_PARAM && prax->u.param_reg == CBAE_REG_RAX);
    assert(sum != NULL && sum->kind == CIR_VAL_INSN_RESULT);
    assert(sum->u.def_insn->opcode == CIR_OP_ADD);
    assert(sum->u.def_insn->operands[0] == c42);
    assert(sum->u.def_insn->operands[1] == prax);

    assert(entry->instruction_count == 2);
    assert(entry->instructions[0]->opcode == CIR_OP_ADD);
    assert(entry->instructions[1]->opcode == CIR_OP_RETURN);
    assert(entry->successor_count == 0);

    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] straight-line: const/param/add/return wired correctly\n");
}

static void t_diamond_with_phi(void) {
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64 * 1024);

    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(&arena, 0x2000, "test_diamond", &f) == CBAE_OK);

    cbae_cir_block_t *entry, *left, *right, *join;
    assert(cbae_cir_block_create(f, 0x2000, &entry) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x2010, &left)  == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x2020, &right) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x2030, &join)  == CBAE_OK);

    cbae_cir_builder_t b;
    cbae_cir_builder_init(&b, f, entry);
    cbae_cir_value_t *cond = cbae_cir_const(&b, cir_type_i1(), 1);
    cbae_cir_branch(&b, cond, left, right, 0x2004);

    cbae_cir_builder_init(&b, f, left);
    cbae_cir_value_t *v10 = cbae_cir_const(&b, cir_type_i(64), 10);
    cbae_cir_jump(&b, join, 0x2014);

    cbae_cir_builder_init(&b, f, right);
    cbae_cir_value_t *v20 = cbae_cir_const(&b, cir_type_i(64), 20);
    cbae_cir_jump(&b, join, 0x2024);

    cbae_cir_value_t *phi_val = cbae_cir_phi_create(f, join, cir_type_i(64));
    assert(cbae_cir_phi_add_incoming(f, phi_val->u.def_insn, v10, left->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(f, phi_val->u.def_insn, v20, right->id) == CBAE_OK);
    cbae_cir_builder_init(&b, f, join);
    cbae_cir_return(&b, phi_val, 0x2034);

    assert(entry->successor_count == 2);
    assert(entry->successors[0] == left->id);
    assert(entry->successors[1] == right->id);

    assert(cbae_vector_count(&left->predecessors) == 1);
    assert(*(uint32_t *)cbae_vector_at(&left->predecessors, 0) == entry->id);
    assert(cbae_vector_count(&right->predecessors) == 1);
    assert(*(uint32_t *)cbae_vector_at(&right->predecessors, 0) == entry->id);

    assert(cbae_vector_count(&join->predecessors) == 2);
    uint32_t p0 = *(uint32_t *)cbae_vector_at(&join->predecessors, 0);
    uint32_t p1 = *(uint32_t *)cbae_vector_at(&join->predecessors, 1);
    assert((p0 == left->id && p1 == right->id) || (p0 == right->id && p1 == left->id));

    assert(join->instruction_count == 2);
    assert(join->instructions[0]->opcode == CIR_OP_PHI);
    assert(join->instructions[1]->opcode == CIR_OP_RETURN);

    cbae_cir_instruction_t *phi = join->instructions[0];
    assert(phi->phi_incoming_count == 2);
    bool saw_left = false, saw_right = false;
    for (uint32_t i = 0; i < phi->phi_incoming_count; i++) {
        if (phi->phi_incoming_blocks[i] == left->id) {
            assert(phi->phi_incoming_values[i] == v10);
            saw_left = true;
        }
        if (phi->phi_incoming_blocks[i] == right->id) {
            assert(phi->phi_incoming_values[i] == v20);
            saw_right = true;
        }
    }
    assert(saw_left && saw_right);
    assert(join->instructions[1]->operands[0] == phi_val);

    printf("\n--- printed CIR for test_diamond ---\n");
    cbae_cir_print_function(f, stdout);
    printf("--- end ---\n\n");

    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] diamond+phi: edges, predecessors, and phi incoming correct\n");
}

static void t_many_instructions_grow_array(void) {
    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);

    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(&arena, 0x3000, "test_grow", &f) == CBAE_OK);
    cbae_cir_block_t *blk;
    assert(cbae_cir_block_create(f, 0x3000, &blk) == CBAE_OK);

    cbae_cir_builder_t b;
    cbae_cir_builder_init(&b, f, blk);

    cbae_cir_value_t *prev = cbae_cir_const(&b, cir_type_i(64), 0);
    for (int i = 1; i <= 50; i++) {
        cbae_cir_value_t *c = cbae_cir_const(&b, cir_type_i(64), i);
        prev = cbae_cir_binop(&b, CIR_OP_ADD, prev, c, cir_type_i(64), 0x3000 + (uint32_t)i);
    }
    cbae_cir_return(&b, prev, 0x4000);

    assert(blk->instruction_count == 51);
    assert(blk->instructions[0]->opcode == CIR_OP_ADD);
    assert(blk->instructions[0]->source_addr == 0x3001);
    assert(blk->instructions[49]->opcode == CIR_OP_ADD);
    assert(blk->instructions[49]->source_addr == 0x3032);
    assert(blk->instructions[50]->opcode == CIR_OP_RETURN);

    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] instruction array growth (51 instructions, multiple grows)\n");
}

int main(void) {
    printf("=== test_cir_builder ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);

    t_straight_line();
    t_diamond_with_phi();
    t_many_instructions_grow_array();

    printf("All CIR builder tests passed.\n");
    return 0;
}
