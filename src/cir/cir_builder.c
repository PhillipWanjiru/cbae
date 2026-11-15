/**
 * @file cir_builder.c
 * @brief Programmatic CIR construction API.
 *
 * GROWTH STRATEGY: a block's instructions[] is an arena-backed array of
 * POINTERS, grown by doubling (allocate a bigger array, copy pointers
 * across) when full. This is safe even though phi nodes elsewhere hold
 * direct pointers to specific instructions: growing the pointer ARRAY
 * never moves the pointed-to cbae_cir_instruction_t objects themselves
 * -- each is its own separate, stable arena allocation.
 */
#include "cir/cir_builder.h"
#include "platform/logging.h"
#include <string.h>
#include <stdlib.h>

#define CIR_BLOCK_INSN_INIT_CAP 8
#define CIR_PHI_INIT_CAP        4

cbae_err_t cbae_cir_function_create(cbae_arena_t *arena, cbae_addr_t entry_addr,
                                     const char *name, cbae_cir_function_t **out) {
    if (!arena || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    cbae_cir_function_t *f = CBAE_ARENA_ALLOC(arena, cbae_cir_function_t);
    if (!f) CBAE_RETURN_ERR(CBAE_ERR_OOM, "cir function alloc failed");

    f->entry_addr = entry_addr;
    memset(f->name, 0, sizeof(f->name));
    if (name) strncpy(f->name, name, sizeof(f->name) - 1);
    f->arena = arena;
    f->next_value_id = 0;
    f->next_insn_id  = 0;
    f->next_block_id = 0;

    cbae_err_t e = cbae_vector_init(&f->blocks, sizeof(cbae_cir_block_t *), 8);
    if (e != CBAE_OK) return e;
    e = cbae_hashmap_init(&f->addr_to_block, 16);
    if (e != CBAE_OK) { cbae_vector_destroy(&f->blocks); return e; }
    e = cbae_vector_init(&f->values, sizeof(cbae_cir_value_t *), 32);
    if (e != CBAE_OK) {
        cbae_vector_destroy(&f->blocks);
        cbae_hashmap_destroy(&f->addr_to_block);
        return e;
    }

    *out = f;
    return CBAE_OK;
}

void cbae_cir_function_destroy(cbae_cir_function_t *func) {
    if (!func) return;
    uint32_t n = (uint32_t)cbae_vector_count(&func->blocks);
    for (uint32_t i = 0; i < n; i++) {
        cbae_cir_block_t **bp = cbae_vector_at(&func->blocks, i);
        cbae_vector_destroy(&(*bp)->predecessors);
    }
    cbae_vector_destroy(&func->blocks);
    cbae_hashmap_destroy(&func->addr_to_block);
    cbae_vector_destroy(&func->values);
}

cbae_err_t cbae_cir_block_create(cbae_cir_function_t *func, cbae_addr_t start_addr,
                                  cbae_cir_block_t **out) {
    if (!func || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    cbae_cir_block_t *b = CBAE_ARENA_ALLOC(func->arena, cbae_cir_block_t);
    if (!b) CBAE_RETURN_ERR(CBAE_ERR_OOM, "cir block alloc failed");

    b->id         = func->next_block_id++;
    b->start_addr = start_addr;
    b->instructions = CBAE_ARENA_ALLOC_N(func->arena, cbae_cir_instruction_t *,
                                          CIR_BLOCK_INSN_INIT_CAP);
    if (!b->instructions) CBAE_RETURN_ERR(CBAE_ERR_OOM, "block insn array alloc failed");
    b->instruction_count    = 0;
    b->instruction_capacity = CIR_BLOCK_INSN_INIT_CAP;
    b->successor_count       = 0;
    memset(b->final_reg_state, 0, sizeof(b->final_reg_state));

    cbae_err_t e = cbae_vector_init(&b->predecessors, sizeof(uint32_t), 4);
    if (e != CBAE_OK) return e;

    e = cbae_vector_push(&func->blocks, &b);
    if (e != CBAE_OK) { cbae_vector_destroy(&b->predecessors); return e; }
    e = cbae_hashmap_insert(&func->addr_to_block, (uint64_t)start_addr, b);
    if (e != CBAE_OK) return e;

    *out = b;
    return CBAE_OK;
}

cbae_cir_block_t *cbae_cir_function_block_at(const cbae_cir_function_t *func,
                                              cbae_addr_t x86_addr) {
    void *v;
    if (!cbae_hashmap_get(&func->addr_to_block, (uint64_t)x86_addr, &v)) return NULL;
    return (cbae_cir_block_t *)v;
}

cbae_err_t cbae_cir_block_add_edge(cbae_cir_block_t *from, cbae_cir_block_t *to) {
    if (!from || !to) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null block");

    /* Idempotent: calling this twice for the same from->to edge is a
     * no-op, not an error. This lets a dispatcher-level sweep safely
     * re-add edges that a builder call (cbae_cir_branch/cbae_cir_jump)
     * already created, so the sweep can uniformly cover the cases that
     * DON'T go through those builder calls (CALL-ending blocks, and
     * blocks that end via pure structural convergence with no explicit
     * branch/jump/call instruction at the transition point at all)
     * without needing to track "was this edge already added" state. */
    for (uint32_t i = 0; i < from->successor_count; i++)
        if (from->successors[i] == to->id) return CBAE_OK;

    if (from->successor_count >= CIR_BLOCK_MAX_SUCCESSORS)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "block already has max successors");
    from->successors[from->successor_count++] = to->id;
    return cbae_vector_push(&to->predecessors, &from->id);
}

static cbae_err_t block_append_insn(cbae_cir_block_t *blk, cbae_arena_t *arena,
                                     cbae_cir_instruction_t *insn) {
    if (blk->instruction_count >= blk->instruction_capacity) {
        uint32_t new_cap = blk->instruction_capacity * 2;
        cbae_cir_instruction_t **new_arr =
            CBAE_ARENA_ALLOC_N(arena, cbae_cir_instruction_t *, new_cap);
        if (!new_arr) CBAE_RETURN_ERR(CBAE_ERR_OOM, "block insn array grow failed");
        memcpy(new_arr, blk->instructions,
               sizeof(cbae_cir_instruction_t *) * blk->instruction_count);
        blk->instructions = new_arr;
        blk->instruction_capacity = new_cap;
    }
    blk->instructions[blk->instruction_count++] = insn;
    return CBAE_OK;
}

void cbae_cir_builder_init(cbae_cir_builder_t *b, cbae_cir_function_t *func,
                            cbae_cir_block_t *block) {
    b->func  = func;
    b->block = block;
}

cbae_cir_value_t *cbae_cir_const(cbae_cir_builder_t *b, cbae_cir_type_t type, int64_t val) {
    cbae_cir_value_t *v = CBAE_ARENA_ALLOC(b->func->arena, cbae_cir_value_t);
    if (!v) return NULL;
    v->kind = CIR_VAL_CONST;
    v->type = type;
    v->id   = b->func->next_value_id++;
    v->u.const_val = val;
    cbae_vector_push(&b->func->values, &v);
    return v;
}

cbae_cir_value_t *cbae_cir_param(cbae_cir_builder_t *b, cbae_reg_t reg) {
    cbae_cir_value_t *v = CBAE_ARENA_ALLOC(b->func->arena, cbae_cir_value_t);
    if (!v) return NULL;
    v->kind = CIR_VAL_PARAM;
    v->type = cir_type_i(64);
    v->id   = b->func->next_value_id++;
    v->u.param_reg = reg;
    cbae_vector_push(&b->func->values, &v);
    return v;
}

static cbae_cir_instruction_t *emit_insn(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                                          cbae_cir_type_t result_type,
                                          cbae_addr_t source_addr,
                                          cbae_cir_value_t **operands,
                                          uint8_t operand_count) {
    if (!b || !b->func || !b->block) return NULL;
    if (operand_count > CIR_MAX_OPERANDS) operand_count = CIR_MAX_OPERANDS;

    cbae_cir_instruction_t *insn = CBAE_ARENA_ALLOC(b->func->arena, cbae_cir_instruction_t);
    if (!insn) return NULL;

    insn->id             = b->func->next_insn_id++;
    insn->opcode          = op;
    insn->source_addr      = source_addr;
    insn->call_target_name  = NULL;
    insn->branch_true_block  = 0;
    insn->branch_false_block = 0;
    insn->phi_incoming_values   = NULL;
    insn->phi_incoming_blocks    = NULL;
    insn->phi_incoming_count      = 0;
    insn->phi_incoming_capacity    = 0;

    insn->operand_count = operand_count;
    for (uint8_t i = 0; i < operand_count; i++) insn->operands[i] = operands[i];
    for (uint8_t i = operand_count; i < CIR_MAX_OPERANDS; i++) insn->operands[i] = NULL;

    if (result_type.kind != CIR_TYPE_VOID) {
        cbae_cir_value_t *res = CBAE_ARENA_ALLOC(b->func->arena, cbae_cir_value_t);
        if (!res) return NULL;
        res->kind = CIR_VAL_INSN_RESULT;
        res->type = result_type;
        res->id   = b->func->next_value_id++;
        res->u.def_insn = insn;
        insn->result = res;
        cbae_vector_push(&b->func->values, &res);
    } else {
        insn->result = NULL;
    }

    if (block_append_insn(b->block, b->func->arena, insn) != CBAE_OK) return NULL;
    return insn;
}

cbae_cir_value_t *cbae_cir_emit(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                                 cbae_cir_type_t result_type, cbae_addr_t source_addr,
                                 cbae_cir_value_t **operands, uint8_t operand_count) {
    cbae_cir_instruction_t *insn =
        emit_insn(b, op, result_type, source_addr, operands, operand_count);
    return insn ? insn->result : NULL;
}

cbae_cir_value_t *cbae_cir_load(cbae_cir_builder_t *b, cbae_cir_value_t *addr,
                                 cbae_cir_type_t type, cbae_addr_t src) {
    cbae_cir_value_t *ops[1] = { addr };
    return cbae_cir_emit(b, CIR_OP_LOAD, type, src, ops, 1);
}

void cbae_cir_store(cbae_cir_builder_t *b, cbae_cir_value_t *addr,
                     cbae_cir_value_t *val, cbae_addr_t src) {
    cbae_cir_value_t *ops[2] = { addr, val };
    cbae_cir_emit(b, CIR_OP_STORE, cir_type_void(), src, ops, 2);
}

cbae_cir_value_t *cbae_cir_binop(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                                  cbae_cir_value_t *lhs, cbae_cir_value_t *rhs,
                                  cbae_cir_type_t result_type, cbae_addr_t src) {
    cbae_cir_value_t *ops[2] = { lhs, rhs };
    return cbae_cir_emit(b, op, result_type, src, ops, 2);
}

void cbae_cir_branch(cbae_cir_builder_t *b, cbae_cir_value_t *cond,
                      cbae_cir_block_t *true_blk, cbae_cir_block_t *false_blk,
                      cbae_addr_t src) {
    cbae_cir_value_t *ops[1] = { cond };
    cbae_cir_instruction_t *insn =
        emit_insn(b, CIR_OP_BRANCH, cir_type_void(), src, ops, 1);
    if (!insn) return;
    insn->branch_true_block  = true_blk->id;
    insn->branch_false_block = false_blk->id;
    cbae_cir_block_add_edge(b->block, true_blk);
    cbae_cir_block_add_edge(b->block, false_blk);
}

void cbae_cir_jump(cbae_cir_builder_t *b, cbae_cir_block_t *target, cbae_addr_t src) {
    cbae_cir_instruction_t *insn =
        emit_insn(b, CIR_OP_JUMP, cir_type_void(), src, NULL, 0);
    if (!insn) return;
    insn->branch_true_block = target->id;
    cbae_cir_block_add_edge(b->block, target);
}

cbae_cir_value_t *cbae_cir_call(cbae_cir_builder_t *b, const char *target_name,
                                 cbae_cir_value_t **args, uint8_t argc,
                                 cbae_cir_type_t result_type, cbae_addr_t src) {
    cbae_cir_instruction_t *insn =
        emit_insn(b, CIR_OP_CALL, result_type, src, args, argc);
    if (!insn) return NULL;
    insn->call_target_name = target_name;
    return insn->result;
}

void cbae_cir_return(cbae_cir_builder_t *b, cbae_cir_value_t *retval, cbae_addr_t src) {
    if (retval) {
        cbae_cir_value_t *ops[1] = { retval };
        emit_insn(b, CIR_OP_RETURN, cir_type_void(), src, ops, 1);
    } else {
        emit_insn(b, CIR_OP_RETURN, cir_type_void(), src, NULL, 0);
    }
}

cbae_cir_value_t *cbae_cir_phi_create(cbae_cir_function_t *func, cbae_cir_block_t *block,
                                       cbae_cir_type_t type) {
    cbae_cir_instruction_t *insn = CBAE_ARENA_ALLOC(func->arena, cbae_cir_instruction_t);
    if (!insn) return NULL;

    insn->id                 = func->next_insn_id++;
    insn->opcode               = CIR_OP_PHI;
    insn->source_addr           = block->start_addr;
    insn->call_target_name       = NULL;
    insn->branch_true_block       = 0;
    insn->branch_false_block       = 0;
    insn->operand_count             = 0;
    for (int i = 0; i < CIR_MAX_OPERANDS; i++) insn->operands[i] = NULL;

    insn->phi_incoming_values = CBAE_ARENA_ALLOC_N(func->arena, cbae_cir_value_t *,
                                                    CIR_PHI_INIT_CAP);
    insn->phi_incoming_blocks = CBAE_ARENA_ALLOC_N(func->arena, uint32_t, CIR_PHI_INIT_CAP);
    if (!insn->phi_incoming_values || !insn->phi_incoming_blocks) return NULL;
    insn->phi_incoming_count    = 0;
    insn->phi_incoming_capacity = CIR_PHI_INIT_CAP;

    cbae_cir_value_t *res = CBAE_ARENA_ALLOC(func->arena, cbae_cir_value_t);
    if (!res) return NULL;
    res->kind = CIR_VAL_INSN_RESULT;
    res->type = type;
    res->id   = func->next_value_id++;
    res->u.def_insn = insn;
    insn->result = res;
    cbae_vector_push(&func->values, &res);

    if (block->instruction_count >= block->instruction_capacity) {
        uint32_t new_cap = block->instruction_capacity * 2;
        cbae_cir_instruction_t **new_arr =
            CBAE_ARENA_ALLOC_N(func->arena, cbae_cir_instruction_t *, new_cap);
        if (!new_arr) return NULL;
        memcpy(new_arr, block->instructions,
               sizeof(cbae_cir_instruction_t *) * block->instruction_count);
        block->instructions = new_arr;
        block->instruction_capacity = new_cap;
    }
    memmove(&block->instructions[1], &block->instructions[0],
            sizeof(cbae_cir_instruction_t *) * block->instruction_count);
    block->instructions[0] = insn;
    block->instruction_count++;

    return res;
}

cbae_err_t cbae_cir_phi_add_incoming(cbae_cir_function_t *func, cbae_cir_instruction_t *phi,
                                      cbae_cir_value_t *value, uint32_t from_block_id) {
    if (!phi || phi->opcode != CIR_OP_PHI)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "not a phi instruction");

    if (phi->phi_incoming_count >= phi->phi_incoming_capacity) {
        uint32_t new_cap = phi->phi_incoming_capacity * 2;
        cbae_cir_value_t **new_vals = CBAE_ARENA_ALLOC_N(func->arena, cbae_cir_value_t *, new_cap);
        uint32_t          *new_blks = CBAE_ARENA_ALLOC_N(func->arena, uint32_t, new_cap);
        if (!new_vals || !new_blks)
            CBAE_RETURN_ERR(CBAE_ERR_OOM, "phi incoming array grow failed");
        memcpy(new_vals, phi->phi_incoming_values,
               sizeof(cbae_cir_value_t *) * phi->phi_incoming_count);
        memcpy(new_blks, phi->phi_incoming_blocks,
               sizeof(uint32_t) * phi->phi_incoming_count);
        phi->phi_incoming_values    = new_vals;
        phi->phi_incoming_blocks     = new_blks;
        phi->phi_incoming_capacity    = new_cap;
    }
    phi->phi_incoming_values[phi->phi_incoming_count] = value;
    phi->phi_incoming_blocks[phi->phi_incoming_count] = from_block_id;
    phi->phi_incoming_count++;
    return CBAE_OK;
}
