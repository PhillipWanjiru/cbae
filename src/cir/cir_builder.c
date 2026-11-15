/**
 * @file cir_builder.c
 * @brief Programmatic CIR construction API. What a call promises is written in cir_builder.h.
 *
 * HOW A CALL KEEPS ITS PROMISE. Everything that can fail - the arena allocations, the heap growth of the function's
 * vectors, the checks on counters and arguments - happens first, into a pending_t that nothing else can see. Only then
 * does the call commit, and a commit is plain stores and pushes into room that was reserved, which cannot fail. A failed
 * call has therefore touched nothing but the arena, which cannot give memory back, and the spare capacity of a vector.
 *
 * GROWTH STRATEGY: a block's instructions[] is an arena-backed array of POINTERS, doubled when it is full (the larger
 * array is allocated and filled while the call prepares, and installed when it commits). This is safe even though phi
 * nodes elsewhere hold direct pointers to specific instructions: growing the pointer ARRAY never moves the
 * cbae_cir_instruction_t objects it points to - each is its own, stable arena allocation.
 */
#include "cir/cir_builder.h"
#include <assert.h>
#include <string.h>

#define CIR_BLOCK_INSN_INIT_CAP 8     /* instruction pointers a new block has room for */
#define CIR_BLOCK_PRED_INIT_CAP 4     /* predecessors a new block has room for */
#define CIR_PHI_INIT_CAP        4     /* incoming pairs a phi has room for once it has its first */
#define CIR_FUNC_BLOCKS_CAP     8
#define CIR_FUNC_ADDRS_CAP      16
#define CIR_FUNC_VALUES_CAP     32

/* ── what an argument may be ─────────────────────────────────────────── */

static bool valid_type(cbae_cir_type_t t) { return (unsigned)t.kind <= (unsigned)CIR_TYPE_PTR; }
static bool sized_type(cbae_cir_type_t t) { return valid_type(t) && t.kind != CIR_TYPE_VOID; }

/* A value or block that is one of @p f's own: its id is the index it is registered at. */
static bool value_of(const cbae_cir_function_t *f, const cbae_cir_value_t *v) {
    return v && v->id < cbae_vector_count(&f->values) && CBAE_VEC_AT(&f->values, cbae_cir_value_t *, v->id) == v;
}

static bool block_of(const cbae_cir_function_t *f, const cbae_cir_block_t *b) {
    return b && b->id < cbae_vector_count(&f->blocks) && CBAE_VEC_AT(&f->blocks, cbae_cir_block_t *, b->id) == b;
}

static cbae_err_t need_function(const cbae_cir_builder_t *b) {
    if (!b || !b->func) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "the builder has no function");
    return CBAE_OK;
}

static cbae_err_t need_block(const cbae_cir_builder_t *b) {
    CBAE_CHECK(need_function(b));
    if (!b->block) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "the builder has no block to add to");
    if (!block_of(b->func, b->block))
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "the builder's block (id %u) is not a block of its function", b->block->id);
    return CBAE_OK;
}

/* ── function and block lifecycle ────────────────────────────────────── */

cbae_err_t cbae_cir_function_create(cbae_arena_t *arena, cbae_addr_t entry_addr,
                                     const char *name, cbae_cir_function_t **out) {
    if (out) *out = NULL;
    if (!arena || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cir function: null argument");

    cbae_cir_function_t *f = CBAE_ARENA_ALLOC(arena, cbae_cir_function_t);
    if (!f) CBAE_RETURN_ERR(CBAE_ERR_OOM, "the arena is out of memory for a cir function");

    f->entry_addr = entry_addr;
    if (name) memcpy(f->name, name, strnlen(name, sizeof f->name - 1));      /* the arena's memory is zero: the NUL is there */
    f->arena = arena;

    CBAE_CHECK(cbae_vector_init(&f->blocks, sizeof(cbae_cir_block_t *), CIR_FUNC_BLOCKS_CAP));
    cbae_err_t e = cbae_hashmap_init(&f->addr_to_block, CIR_FUNC_ADDRS_CAP);
    if (e == CBAE_OK) e = cbae_vector_init(&f->values, sizeof(cbae_cir_value_t *), CIR_FUNC_VALUES_CAP);
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
    const size_t n = cbae_vector_count(&func->blocks);
    for (size_t i = 0; i < n; i++) {
        cbae_cir_block_t *blk = CBAE_VEC_AT(&func->blocks, cbae_cir_block_t *, i);
        if (blk) cbae_vector_destroy(&blk->predecessors);
    }
    cbae_vector_destroy(&func->blocks);
    cbae_hashmap_destroy(&func->addr_to_block);
    cbae_vector_destroy(&func->values);
}

cbae_err_t cbae_cir_block_create(cbae_cir_function_t *func, cbae_addr_t start_addr,
                                  cbae_cir_block_t **out) {
    if (out) *out = NULL;
    if (!func || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cir block: null argument");
    if (func->next_block_id == UINT32_MAX) CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "a function has at most %u blocks", UINT32_MAX);

    cbae_cir_block_t *b = CBAE_ARENA_ALLOC(func->arena, cbae_cir_block_t);
    if (!b) CBAE_RETURN_ERR(CBAE_ERR_OOM, "the arena is out of memory for a cir block");
    b->instructions = CBAE_ARENA_ALLOC_N(func->arena, cbae_cir_instruction_t *, CIR_BLOCK_INSN_INIT_CAP);
    if (!b->instructions) CBAE_RETURN_ERR(CBAE_ERR_OOM, "the arena is out of memory for a block's instructions");
    b->id                   = func->next_block_id;
    b->start_addr           = start_addr;
    b->instruction_capacity = CIR_BLOCK_INSN_INIT_CAP;

    CBAE_CHECK(cbae_vector_init(&b->predecessors, sizeof(uint32_t), CIR_BLOCK_PRED_INIT_CAP));
    cbae_err_t e = cbae_vector_reserve(&func->blocks, cbae_vector_count(&func->blocks) + 1);
    /* The map goes last: it is the step that may replace an entry (a second block at an address), and a failed insert
     * changes nothing. */
    if (e == CBAE_OK) e = cbae_hashmap_insert(&func->addr_to_block, (uint64_t)start_addr, b);
    if (e != CBAE_OK) {
        cbae_vector_destroy(&b->predecessors);
        return e;
    }
    const cbae_err_t pushed = cbae_vector_push(&func->blocks, &b);      /* the room was reserved */
    assert(pushed == CBAE_OK);
    (void)pushed;
    func->next_block_id++;
    *out = b;
    return CBAE_OK;
}

cbae_cir_block_t *cbae_cir_function_block_at(const cbae_cir_function_t *func,
                                              cbae_addr_t x86_addr) {
    void *v;
    if (!func || !cbae_hashmap_get(&func->addr_to_block, (uint64_t)x86_addr, &v)) return NULL;
    return (cbae_cir_block_t *)v;
}

/* ── edges ───────────────────────────────────────────────────────────── */

static bool has_successor(const cbae_cir_block_t *from, const cbae_cir_block_t *to) {
    for (uint32_t i = 0; i < from->successor_count; i++)
        if (from->successors[i] == to->id) return true;
    return false;
}

/* Checks that the edges @p from -> targets[0..n) can be added, and makes the room for them; adds none. An edge that is
 * there is not new, and a block listed twice is one edge. */
static cbae_err_t reserve_edges(const cbae_cir_block_t *from, cbae_cir_block_t *const *targets, unsigned n) {
    unsigned fresh = 0;
    for (unsigned i = 0; i < n; i++) {
        if (has_successor(from, targets[i])) continue;
        bool listed = false;
        for (unsigned j = 0; j < i; j++) listed = listed || targets[j] == targets[i];
        if (!listed) fresh++;
    }
    if (from->successor_count + fresh > CIR_BLOCK_MAX_SUCCESSORS)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "block %u has %u successors and cannot take %u more: a block has at most %d",
                        from->id, from->successor_count, fresh, CIR_BLOCK_MAX_SUCCESSORS);
    for (unsigned i = 0; i < n; i++)
        if (!has_successor(from, targets[i]))
            CBAE_CHECK(cbae_vector_reserve(&targets[i]->predecessors, cbae_vector_count(&targets[i]->predecessors) + 1));
    return CBAE_OK;
}

/* Adds an edge that reserve_edges has checked. */
static void commit_edge(cbae_cir_block_t *from, cbae_cir_block_t *to) {
    if (has_successor(from, to)) return;
    from->successors[from->successor_count++] = to->id;
    const cbae_err_t pushed = cbae_vector_push(&to->predecessors, &from->id);      /* the room was reserved */
    assert(pushed == CBAE_OK);
    (void)pushed;
}

cbae_err_t cbae_cir_block_add_edge(cbae_cir_block_t *from, cbae_cir_block_t *to) {
    if (!from || !to) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cir edge: null block");
    CBAE_CHECK(reserve_edges(from, &to, 1));
    commit_edge(from, to);
    return CBAE_OK;
}

/* ── values ──────────────────────────────────────────────────────────── */

/* Room for one more value: an id that does not wrap (0xFFFFFFFF means "none" in the serialized form) and a slot in the
 * function's vector. The value itself is the caller's. */
static cbae_err_t reserve_value(cbae_cir_function_t *f) {
    if (f->next_value_id == UINT32_MAX) CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "a function has at most %u values", UINT32_MAX);
    return cbae_vector_reserve(&f->values, cbae_vector_count(&f->values) + 1);
}

/* Registers a value whose room reserve_value made. */
static void register_value(cbae_cir_function_t *f, cbae_cir_value_t *v) {
    v->id = f->next_value_id++;
    const cbae_err_t pushed = cbae_vector_push(&f->values, &v);
    assert(pushed == CBAE_OK);
    (void)pushed;
}

/* A value of @p kind and @p type that is not registered yet: everything that can fail is done. */
static cbae_err_t new_value(cbae_cir_function_t *f, cbae_cir_value_kind_t kind, cbae_cir_type_t type, cbae_cir_value_t **out) {
    CBAE_CHECK(reserve_value(f));
    cbae_cir_value_t *v = CBAE_ARENA_ALLOC(f->arena, cbae_cir_value_t);
    if (!v) CBAE_RETURN_ERR(CBAE_ERR_OOM, "the arena is out of memory for a value");
    v->kind = kind;
    v->type = type;
    *out = v;
    return CBAE_OK;
}

void cbae_cir_builder_init(cbae_cir_builder_t *b, cbae_cir_function_t *func,
                            cbae_cir_block_t *block) {
    if (!b) return;
    b->func  = func;
    b->block = block;
}

cbae_cir_value_t *cbae_cir_const(cbae_cir_builder_t *b, cbae_cir_type_t type, int64_t val) {
    if (need_function(b) != CBAE_OK) return NULL;
    if (!sized_type(type)) {
        CBAE_SET_ERR(CBAE_ERR_INVALID, "a constant has a width or is a pointer: type kind %u is neither", (unsigned)type.kind);
        return NULL;
    }
    cbae_cir_value_t *v;
    if (new_value(b->func, CIR_VAL_CONST, type, &v) != CBAE_OK) return NULL;
    v->u.const_val = val;
    register_value(b->func, v);
    return v;
}

cbae_cir_value_t *cbae_cir_param(cbae_cir_builder_t *b, cbae_reg_t reg) {
    if (need_function(b) != CBAE_OK) return NULL;
    if ((unsigned)reg > (unsigned)CBAE_REG_OTHER) {
        CBAE_SET_ERR(CBAE_ERR_INVALID, "register %u does not exist", (unsigned)reg);
        return NULL;
    }
    cbae_cir_value_t *v;
    if (new_value(b->func, CIR_VAL_PARAM, cir_type_i(64), &v) != CBAE_OK) return NULL;
    v->u.param_reg = reg;
    register_value(b->func, v);
    return v;
}

/* ── instructions ────────────────────────────────────────────────────── */

/* An instruction that is made but not yet in its block. */
typedef struct {
    cbae_cir_instruction_t  *insn;
    cbae_cir_value_t        *result;       /* NULL: the instruction has none */
    cbae_cir_instruction_t **grown;        /* the block's instruction array after growth, filled; NULL if the old one has room */
    uint32_t                 grown_cap;
} pending_t;

/* Makes room in @p blk for one more instruction pointer. */
static cbae_err_t reserve_insn_slot(cbae_arena_t *arena, const cbae_cir_block_t *blk, pending_t *p) {
    if (blk->instruction_count < blk->instruction_capacity) return CBAE_OK;
    if (blk->instruction_capacity > UINT32_MAX / 2)
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "block %u cannot hold more than %u instructions", blk->id, blk->instruction_capacity);
    const uint32_t cap = blk->instruction_capacity ? blk->instruction_capacity * 2 : CIR_BLOCK_INSN_INIT_CAP;
    cbae_cir_instruction_t **arr = CBAE_ARENA_ALLOC_N(arena, cbae_cir_instruction_t *, cap);
    if (!arr) CBAE_RETURN_ERR(CBAE_ERR_OOM, "the arena is out of memory for the instructions of block %u", blk->id);
    if (blk->instruction_count) memcpy(arr, blk->instructions, sizeof *arr * blk->instruction_count);
    p->grown     = arr;
    p->grown_cap = cap;
    return CBAE_OK;
}

/* Checks the arguments and makes the instruction, its result, its call name and the room for all of them in @p blk of
 * @p f; changes nothing that is visible. */
static cbae_err_t prepare_insn(cbae_cir_function_t *f, cbae_cir_block_t *blk, cbae_cir_opcode_t op,
                               cbae_cir_type_t type, cbae_addr_t src, cbae_cir_value_t *const *operands, unsigned n,
                               const char *call_name, pending_t *p) {
    memset(p, 0, sizeof *p);
    if ((unsigned)op <= (unsigned)CIR_OP_INVALID || (unsigned)op >= (unsigned)CIR_OP_COUNT)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "opcode %u does not exist", (unsigned)op);
    if (!valid_type(type)) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "type kind %u does not exist", (unsigned)type.kind);
    if (n > CIR_MAX_OPERANDS) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "an instruction has at most %d operands, not %u", CIR_MAX_OPERANDS, n);
    if (n && !operands) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "%u operands and no operand array", n);
    for (unsigned i = 0; i < n; i++)
        if (!value_of(f, operands[i]))
            CBAE_RETURN_ERR(CBAE_ERR_INVALID, "operand %u is NULL or not a value of this function", i);
    const size_t name_len = call_name ? strnlen(call_name, (size_t)CIR_MAX_CALL_NAME + 1) : 0;
    if (name_len > CIR_MAX_CALL_NAME)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "a call target name has at most %u bytes", CIR_MAX_CALL_NAME);
    if (f->next_insn_id == UINT32_MAX) CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "a function has at most %u instructions", UINT32_MAX);

    cbae_cir_instruction_t *insn = CBAE_ARENA_ALLOC(f->arena, cbae_cir_instruction_t);
    if (!insn) CBAE_RETURN_ERR(CBAE_ERR_OOM, "the arena is out of memory for an instruction");
    insn->opcode        = op;
    insn->source_addr   = src;
    insn->operand_count = (uint8_t)n;
    for (unsigned i = 0; i < n; i++) insn->operands[i] = operands[i];

    if (type.kind != CIR_TYPE_VOID) {
        CBAE_CHECK(reserve_value(f));
        cbae_cir_value_t *res = CBAE_ARENA_ALLOC(f->arena, cbae_cir_value_t);
        if (!res) CBAE_RETURN_ERR(CBAE_ERR_OOM, "the arena is out of memory for an instruction's result");
        res->kind       = CIR_VAL_INSN_RESULT;
        res->type       = type;
        res->u.def_insn = insn;
        insn->result    = res;
        p->result       = res;
    }
    if (name_len) {
        char *copy = CBAE_ARENA_ALLOC_N(f->arena, char, name_len + 1);
        if (!copy) CBAE_RETURN_ERR(CBAE_ERR_OOM, "the arena is out of memory for a call target name");
        memcpy(copy, call_name, name_len);
        copy[name_len] = '\0';
        insn->call_target_name = copy;
    }
    CBAE_CHECK(reserve_insn_slot(f->arena, blk, p));
    p->insn = insn;
    return CBAE_OK;
}

/* Puts a prepared instruction in @p blk, at the end or (a phi) at the front. Cannot fail. */
static void commit_insn(cbae_cir_function_t *f, cbae_cir_block_t *blk, const pending_t *p, bool at_front) {
    if (p->grown) {
        blk->instructions         = p->grown;
        blk->instruction_capacity = p->grown_cap;
    }
    p->insn->id = f->next_insn_id++;
    if (p->result) register_value(f, p->result);
    if (at_front)
        memmove(&blk->instructions[1], &blk->instructions[0], sizeof *blk->instructions * blk->instruction_count);
    blk->instructions[at_front ? 0 : blk->instruction_count] = p->insn;
    blk->instruction_count++;
}

cbae_err_t cbae_cir_emit_insn(cbae_cir_builder_t *b, cbae_cir_opcode_t op, cbae_cir_type_t result_type,
                               cbae_addr_t source_addr, cbae_cir_value_t *const *operands, uint8_t operand_count,
                               cbae_cir_instruction_t **out) {
    if (out) *out = NULL;
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "emit: no place to return the instruction");
    CBAE_CHECK(need_block(b));
    pending_t p;
    CBAE_CHECK(prepare_insn(b->func, b->block, op, result_type, source_addr, operands, operand_count, NULL, &p));
    commit_insn(b->func, b->block, &p, false);
    *out = p.insn;
    return CBAE_OK;
}

cbae_cir_value_t *cbae_cir_emit(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                                 cbae_cir_type_t result_type, cbae_addr_t source_addr,
                                 cbae_cir_value_t *const *operands, uint8_t operand_count) {
    cbae_cir_instruction_t *insn;
    if (cbae_cir_emit_insn(b, op, result_type, source_addr, operands, operand_count, &insn) != CBAE_OK) return NULL;
    return insn->result;
}

cbae_cir_value_t *cbae_cir_load(cbae_cir_builder_t *b, cbae_cir_value_t *addr,
                                 cbae_cir_type_t type, cbae_addr_t src) {
    if (!sized_type(type)) {
        CBAE_SET_ERR(CBAE_ERR_INVALID, "a load has a width or is a pointer: type kind %u is neither", (unsigned)type.kind);
        return NULL;
    }
    cbae_cir_value_t *ops[1] = { addr };
    return cbae_cir_emit(b, CIR_OP_LOAD, type, src, ops, 1);
}

cbae_err_t cbae_cir_store(cbae_cir_builder_t *b, cbae_cir_value_t *addr,
                           cbae_cir_value_t *val, cbae_addr_t src) {
    cbae_cir_value_t *ops[2] = { addr, val };
    cbae_cir_instruction_t *insn;
    return cbae_cir_emit_insn(b, CIR_OP_STORE, cir_type_void(), src, ops, 2, &insn);
}

cbae_cir_value_t *cbae_cir_binop(cbae_cir_builder_t *b, cbae_cir_opcode_t op,
                                  cbae_cir_value_t *lhs, cbae_cir_value_t *rhs,
                                  cbae_cir_type_t result_type, cbae_addr_t src) {
    if (!sized_type(result_type)) {
        CBAE_SET_ERR(CBAE_ERR_INVALID, "a binary operation has a result of a width or a pointer: type kind %u is neither", (unsigned)result_type.kind);
        return NULL;
    }
    cbae_cir_value_t *ops[2] = { lhs, rhs };
    return cbae_cir_emit(b, op, result_type, src, ops, 2);
}

cbae_err_t cbae_cir_branch(cbae_cir_builder_t *b, cbae_cir_value_t *cond,
                            cbae_cir_block_t *true_blk, cbae_cir_block_t *false_blk,
                            cbae_addr_t src) {
    CBAE_CHECK(need_block(b));
    if (!block_of(b->func, true_blk) || !block_of(b->func, false_blk))
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "a branch needs two blocks of the function");
    cbae_cir_value_t *ops[1] = { cond };
    cbae_cir_block_t *targets[2] = { true_blk, false_blk };
    pending_t p;
    CBAE_CHECK(prepare_insn(b->func, b->block, CIR_OP_BRANCH, cir_type_void(), src, ops, 1, NULL, &p));
    CBAE_CHECK(reserve_edges(b->block, targets, 2));
    p.insn->branch_true_block  = true_blk->id;
    p.insn->branch_false_block = false_blk->id;
    commit_insn(b->func, b->block, &p, false);
    commit_edge(b->block, true_blk);
    commit_edge(b->block, false_blk);
    return CBAE_OK;
}

cbae_err_t cbae_cir_jump(cbae_cir_builder_t *b, cbae_cir_block_t *target, cbae_addr_t src) {
    CBAE_CHECK(need_block(b));
    if (!block_of(b->func, target)) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "a jump needs a block of the function");
    pending_t p;
    CBAE_CHECK(prepare_insn(b->func, b->block, CIR_OP_JUMP, cir_type_void(), src, NULL, 0, NULL, &p));
    CBAE_CHECK(reserve_edges(b->block, &target, 1));
    p.insn->branch_true_block = target->id;
    commit_insn(b->func, b->block, &p, false);
    commit_edge(b->block, target);
    return CBAE_OK;
}

cbae_cir_value_t *cbae_cir_call(cbae_cir_builder_t *b, const char *target_name,
                                 cbae_cir_value_t *const *args, uint8_t argc,
                                 cbae_cir_type_t result_type, cbae_addr_t src) {
    if (need_block(b) != CBAE_OK) return NULL;
    pending_t p;
    if (prepare_insn(b->func, b->block, CIR_OP_CALL, result_type, src, args, argc, target_name, &p) != CBAE_OK) return NULL;
    commit_insn(b->func, b->block, &p, false);
    return p.result;
}

cbae_err_t cbae_cir_return(cbae_cir_builder_t *b, cbae_cir_value_t *retval, cbae_addr_t src) {
    cbae_cir_value_t *ops[1] = { retval };
    cbae_cir_instruction_t *insn;
    return cbae_cir_emit_insn(b, CIR_OP_RETURN, cir_type_void(), src, ops, retval ? 1 : 0, &insn);
}

/* ── phi ─────────────────────────────────────────────────────────────── */

cbae_cir_value_t *cbae_cir_phi_create(cbae_cir_function_t *func, cbae_cir_block_t *block,
                                       cbae_cir_type_t type) {
    if (!func || !block) {
        CBAE_SET_ERR(CBAE_ERR_INVALID, "phi: null function or block");
        return NULL;
    }
    if (!block_of(func, block)) {
        CBAE_SET_ERR(CBAE_ERR_INVALID, "phi: block %u is not a block of the function", block->id);
        return NULL;
    }
    if (!sized_type(type)) {
        CBAE_SET_ERR(CBAE_ERR_INVALID, "a phi has a width or is a pointer: type kind %u is neither", (unsigned)type.kind);
        return NULL;
    }
    pending_t p;
    if (prepare_insn(func, block, CIR_OP_PHI, type, block->start_addr, NULL, 0, NULL, &p) != CBAE_OK) return NULL;
    commit_insn(func, block, &p, true);
    return p.result;
}

cbae_err_t cbae_cir_phi_add_incoming(cbae_cir_function_t *func, cbae_cir_instruction_t *phi,
                                      cbae_cir_value_t *value, uint32_t from_block_id) {
    if (!func || !phi) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "phi: null function or instruction");
    if (phi->opcode != CIR_OP_PHI) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "instruction %u is not a phi", phi->id);
    if (!value_of(func, value)) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "a phi's incoming value is NULL or not a value of this function");
    if (from_block_id >= cbae_vector_count(&func->blocks))
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "a phi's incoming block %u does not exist", from_block_id);

    if (phi->phi_incoming_count >= phi->phi_incoming_capacity) {
        if (phi->phi_incoming_capacity > UINT32_MAX / 2)
            CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "a phi cannot have more than %u incoming values", phi->phi_incoming_capacity);
        const uint32_t cap = phi->phi_incoming_capacity ? phi->phi_incoming_capacity * 2 : CIR_PHI_INIT_CAP;
        cbae_cir_value_t **vals = CBAE_ARENA_ALLOC_N(func->arena, cbae_cir_value_t *, cap);
        uint32_t          *blks = CBAE_ARENA_ALLOC_N(func->arena, uint32_t, cap);
        if (!vals || !blks) CBAE_RETURN_ERR(CBAE_ERR_OOM, "the arena is out of memory for the incoming values of a phi");
        if (phi->phi_incoming_count) {
            memcpy(vals, phi->phi_incoming_values, sizeof *vals * phi->phi_incoming_count);
            memcpy(blks, phi->phi_incoming_blocks, sizeof *blks * phi->phi_incoming_count);
        }
        phi->phi_incoming_values   = vals;
        phi->phi_incoming_blocks   = blks;
        phi->phi_incoming_capacity = cap;
    }
    phi->phi_incoming_values[phi->phi_incoming_count] = value;
    phi->phi_incoming_blocks[phi->phi_incoming_count] = from_block_id;
    phi->phi_incoming_count++;
    return CBAE_OK;
}
