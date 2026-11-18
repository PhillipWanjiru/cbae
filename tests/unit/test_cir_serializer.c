/**
 * @file test_cir_serializer.c
 * @brief The CIR serializer and deserializer, tested against a second, independent implementation of the format.
 *
 * The oracle is the writer below: it emits the documented layout (cir_serializer.c, top comment) field by field from
 * a plain C model, so the serializer is never checked only against itself. The model can also say what no real function
 * says (a count that is too big, an id that does not exist, a successor list of 3), which is how every way a blob can
 * be wrong is covered. A blob is untrusted input: whatever it holds, deserializing it must end in a function that is
 * safe to walk, print and verify, or in an error - never in a write outside an object, an unbounded allocation, or a
 * leak. The fuzz at the end changes every byte of two valid blobs to ten other values and holds the result to exactly
 * that, with the strongest check available: an accepted blob must serialize back to the same bytes.
 */
#include "alloc_inject.h"
#include "cir_compare.h"
#include "oom_sweep.h"
#include "cir/cir_builder.h"
#include "cir/cir_printer.h"
#include "cir/cir_serializer.h"
#include "cir/cir_verifier.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUICK (getenv("CBAE_TEST_QUICK") != NULL)
#define PASS(msg) printf("  [PASS] %s\n", (msg))

/* ── the independent writer ───────────────────────────────────────────── */

typedef struct { uint8_t *p; size_t n, cap; } blob_t;

static void bl_put(blob_t *b, const void *src, size_t n) {
    if (b->n + n > b->cap) {
        b->cap = (b->n + n) * 2 + 64;
        b->p = realloc(b->p, b->cap);
        assert(b->p);
    }
    memcpy(b->p + b->n, src, n);
    b->n += n;
}
#define PUT(b, T, v) do { T t_ = (T)(v); bl_put((b), &t_, sizeof t_); } while (0)

typedef struct { uint32_t decl, n, v[8]; } list_t;       /* a count, and the elements that follow it (they may differ) */
static list_t lst(uint32_t n, uint32_t a, uint32_t b, uint32_t c) { list_t l = { n, n, { a, b, c, 0, 0, 0, 0, 0 } }; return l; }

typedef struct { uint32_t id; uint8_t kind, type; int64_t cval; uint8_t reg; uint32_t def_insn, block; } mval_t;

typedef struct {
    uint32_t id; uint8_t op; uint32_t result;
    uint8_t nops_decl; uint32_t nops, ops[8];
    uint64_t src;
    uint16_t name_len; uint32_t name_n; uint8_t name[16];
    uint32_t t, f;
    uint32_t nphi_decl, nphi, pv[4], pb[4];
} minsn_t;

typedef struct {
    uint32_t id; uint64_t addr; list_t preds, succs;
    uint32_t ninsn_decl, ninsn; minsn_t insn[8];
} mblock_t;

typedef struct {
    uint32_t magic, version; uint64_t entry; uint8_t name[128];
    uint32_t nblocks_decl, nvals_decl;
    uint32_t nvals; mval_t vals[16];
    uint32_t nblocks; mblock_t blocks[4];
    uint32_t trailing;
} mfunc_t;

#define NO_VALUE 0xFFFFFFFFu

static blob_t write_model(const mfunc_t *m) {
    blob_t b = { 0, 0, 0 };
    PUT(&b, uint32_t, m->magic); PUT(&b, uint32_t, m->version); PUT(&b, uint64_t, m->entry);
    bl_put(&b, m->name, sizeof m->name);
    PUT(&b, uint32_t, m->nblocks_decl); PUT(&b, uint32_t, m->nvals_decl);
    for (uint32_t i = 0; i < m->nvals; i++) {
        const mval_t *v = &m->vals[i];
        PUT(&b, uint32_t, v->id); PUT(&b, uint8_t, v->kind); PUT(&b, uint8_t, v->type);
        switch (v->kind) {
            case CIR_VAL_CONST:       PUT(&b, int64_t, v->cval); break;
            case CIR_VAL_PARAM:       PUT(&b, uint8_t, v->reg); break;
            case CIR_VAL_INSN_RESULT: PUT(&b, uint32_t, v->def_insn); break;
            case CIR_VAL_REG_ENTRY:   PUT(&b, uint8_t, v->reg); PUT(&b, uint32_t, v->block); break;
            default: break;
        }
    }
    for (uint32_t bi = 0; bi < m->nblocks; bi++) {
        const mblock_t *k = &m->blocks[bi];
        PUT(&b, uint32_t, k->id); PUT(&b, uint64_t, k->addr);
        PUT(&b, uint32_t, k->preds.decl);
        for (uint32_t i = 0; i < k->preds.n; i++) PUT(&b, uint32_t, k->preds.v[i]);
        PUT(&b, uint32_t, k->succs.decl);
        for (uint32_t i = 0; i < k->succs.n; i++) PUT(&b, uint32_t, k->succs.v[i]);
        PUT(&b, uint32_t, k->ninsn_decl);
    }
    for (uint32_t bi = 0; bi < m->nblocks; bi++) {
        for (uint32_t ii = 0; ii < m->blocks[bi].ninsn; ii++) {
            const minsn_t *x = &m->blocks[bi].insn[ii];
            PUT(&b, uint32_t, x->id); PUT(&b, uint8_t, x->op); PUT(&b, uint32_t, x->result); PUT(&b, uint8_t, x->nops_decl);
            for (uint32_t i = 0; i < x->nops; i++) PUT(&b, uint32_t, x->ops[i]);
            PUT(&b, uint64_t, x->src);
            PUT(&b, uint16_t, x->name_len);
            bl_put(&b, x->name, x->name_n);
            PUT(&b, uint32_t, x->t); PUT(&b, uint32_t, x->f);
            PUT(&b, uint32_t, x->nphi_decl);
            for (uint32_t i = 0; i < x->nphi; i++) { PUT(&b, uint32_t, x->pv[i]); PUT(&b, uint32_t, x->pb[i]); }
        }
    }
    for (uint32_t i = 0; i < m->trailing; i++) PUT(&b, uint8_t, 0xAB);
    return b;
}

static minsn_t ins(uint32_t id, uint8_t op, uint32_t result, uint32_t nops, uint32_t a, uint32_t b, uint32_t c) {
    minsn_t x;
    memset(&x, 0, sizeof x);
    x.id = id; x.op = op; x.result = result;
    x.nops_decl = (uint8_t)nops; x.nops = nops; x.ops[0] = a; x.ops[1] = b; x.ops[2] = c;
    x.src = 0x1000u + id * 4u;
    return x;
}

/* A valid function that has one of everything the format can say: three blocks, six values of three kinds, a call with
 * a name, a branch, a jump, a phi, and operands that are results of earlier instructions. */
static mfunc_t base_model(void) {
    mfunc_t m;
    memset(&m, 0, sizeof m);
    m.magic = 0x52494243u; m.version = 1; m.entry = 0x140001000ull;
    memcpy(m.name, "DriverEntry", 11);
    m.nvals = m.nvals_decl = 6;
    m.vals[0] = (mval_t){ 0, CIR_VAL_PARAM,       CIR_TYPE_I64, 0,  CBAE_REG_RAX, 0, 0 };
    m.vals[1] = (mval_t){ 1, CIR_VAL_CONST,       CIR_TYPE_I64, 42, 0,            0, 0 };
    m.vals[2] = (mval_t){ 2, CIR_VAL_INSN_RESULT, CIR_TYPE_I64, 0,  0,            0, 0 };
    m.vals[3] = (mval_t){ 3, CIR_VAL_INSN_RESULT, CIR_TYPE_I1,  0,  0,            1, 0 };
    m.vals[4] = (mval_t){ 4, CIR_VAL_INSN_RESULT, CIR_TYPE_PTR, 0,  0,            3, 0 };
    m.vals[5] = (mval_t){ 5, CIR_VAL_INSN_RESULT, CIR_TYPE_I64, 0,  0,            5, 0 };
    m.nblocks = m.nblocks_decl = 3;

    mblock_t *b0 = &m.blocks[0], *b1 = &m.blocks[1], *b2 = &m.blocks[2];
    b0->id = 0; b0->addr = 0x140001000ull; b0->preds = lst(0, 0, 0, 0); b0->succs = lst(2, 1, 2, 0);
    b1->id = 1; b1->addr = 0x140001020ull; b1->preds = lst(1, 0, 0, 0); b1->succs = lst(1, 2, 0, 0);
    b2->id = 2; b2->addr = 0x140001040ull; b2->preds = lst(2, 0, 1, 0); b2->succs = lst(0, 0, 0, 0);
    b0->ninsn = b0->ninsn_decl = 3; b1->ninsn = b1->ninsn_decl = 2; b2->ninsn = b2->ninsn_decl = 2;

    b0->insn[0] = ins(0, CIR_OP_ADD,    2, 2, 0, 1, 0);
    b0->insn[1] = ins(1, CIR_OP_CMP,    3, 2, 2, 1, 0);
    b0->insn[2] = ins(2, CIR_OP_BRANCH, NO_VALUE, 1, 3, 0, 0);
    b0->insn[2].t = 1; b0->insn[2].f = 2;
    b1->insn[0] = ins(3, CIR_OP_CALL,   4, 1, 2, 0, 0);
    memcpy(b1->insn[0].name, "ExAllocatePool", 14);
    b1->insn[0].name_len = 14; b1->insn[0].name_n = 14;
    b1->insn[1] = ins(4, CIR_OP_JUMP,   NO_VALUE, 0, 0, 0, 0);
    b1->insn[1].t = 2;
    b2->insn[0] = ins(5, CIR_OP_PHI,    5, 0, 0, 0, 0);
    b2->insn[0].nphi_decl = b2->insn[0].nphi = 2;
    b2->insn[0].pv[0] = 2; b2->insn[0].pb[0] = 0; b2->insn[0].pv[1] = 4; b2->insn[0].pb[1] = 1;
    b2->insn[1] = ins(6, CIR_OP_RETURN, NO_VALUE, 1, 5, 0, 0);
    return m;
}

/* A header and nothing else: no values, no blocks. The tests that need other shapes add to it. */
static mfunc_t blank_model(void) {
    mfunc_t m;
    memset(&m, 0, sizeof m);
    m.magic = 0x52494243u; m.version = 1; m.entry = 0x2000ull;
    memcpy(m.name, "Blank", 5);
    return m;
}

/* ── functions to serialize ───────────────────────────────────────────── */

static cbae_cir_function_t *rich_function(cbae_arena_t *arena, bool with_reg_entry) {
    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(arena, 0x140001000ull, "RichDriverRoutine", &f) == CBAE_OK);
    cbae_cir_block_t *b0, *b1, *b2, *b3;
    assert(cbae_cir_block_create(f, 0x140001000ull, &b0) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x140001020ull, &b1) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x140001040ull, &b2) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x140001060ull, &b3) == CBAE_OK);

    cbae_cir_builder_t b;
    cbae_cir_builder_init(&b, f, b0);
    cbae_cir_value_t *rax = cbae_cir_param(&b, CBAE_REG_RAX), *rcx = cbae_cir_param(&b, CBAE_REG_RCX);
    cbae_cir_value_t *c42 = cbae_cir_const(&b, cir_type_i(64), 42);
    cbae_cir_value_t *cmin = cbae_cir_const(&b, cir_type_i(64), INT64_MIN);
    cbae_cir_value_t *cptr = cbae_cir_const(&b, cir_type_ptr(), (int64_t)0xFFFF800000000000ull);
    cbae_cir_value_t *c1 = cbae_cir_const(&b, cir_type_i1(), 1);
    cbae_cir_value_t *ld = cbae_cir_load(&b, cptr, cir_type_i(32), 0x140001004ull);
    cbae_cir_value_t *sum = cbae_cir_binop(&b, CIR_OP_ADD, rax, c42, cir_type_i(64), 0x140001008ull);
    cbae_cir_value_t *four[4] = { sum, rcx, ld, c1 };
    cbae_cir_value_t *mix = cbae_cir_emit(&b, CIR_OP_DMA_MAP, cir_type_i(64), 0x14000100Cull, four, 4);
    cbae_cir_value_t *cmp = cbae_cir_binop(&b, CIR_OP_CMP, mix, cmin, cir_type_i1(), 0x140001010ull);
    cbae_cir_branch(&b, cmp, b1, b2, 0x140001014ull);

    cbae_cir_builder_init(&b, f, b1);
    cbae_cir_value_t *args[2] = { sum, rcx };
    cbae_cir_value_t *call = cbae_cir_call(&b, "ExAllocatePoolWithTag", args, 2, cir_type_i(64), 0x140001020ull);
    cbae_cir_store(&b, cptr, call, 0x140001024ull);
    cbae_cir_jump(&b, b3, 0x140001028ull);

    cbae_cir_builder_init(&b, f, b2);
    cbae_cir_value_t *x = NULL;
    if (with_reg_entry) {                                            /* the placeholder the lifter leaves for the SSA constructor */
        cbae_cir_value_t *re = CBAE_ARENA_ALLOC(arena, cbae_cir_value_t);
        assert(re);
        re->kind = CIR_VAL_REG_ENTRY; re->type = cir_type_i(64); re->id = f->next_value_id++;
        re->u.reg_entry.reg = CBAE_REG_RBX; re->u.reg_entry.block_id = b2->id;
        assert(cbae_vector_push(&f->values, &re) == CBAE_OK);
        x = cbae_cir_binop(&b, CIR_OP_XOR, re, c42, cir_type_i(64), 0x140001040ull);
    } else {
        x = cbae_cir_binop(&b, CIR_OP_XOR, rax, c42, cir_type_i(64), 0x140001040ull);
    }
    cbae_cir_jump(&b, b3, 0x140001044ull);

    cbae_cir_value_t *phi = cbae_cir_phi_create(f, b3, cir_type_i(64));
    assert(phi && cbae_cir_phi_add_incoming(f, phi->u.def_insn, call, b1->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(f, phi->u.def_insn, x, b2->id) == CBAE_OK);
    cbae_cir_builder_init(&b, f, b3);
    cbae_cir_return(&b, phi, 0x140001064ull);
    return f;
}

static cbae_cir_function_t *empty_function(cbae_arena_t *arena) {
    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(arena, 0, "", &f) == CBAE_OK);
    return f;
}

/* More of everything than the constructors start with: 12 blocks (they start with room for 8), 56 values (32), a block of
 * 14 instructions (8), a block that 7 blocks lead to (4 predecessors), and a call with a name. Blocks 0..5 lead to block 11,
 * and 6..10 each to the next. */
static cbae_cir_function_t *scale_function(cbae_arena_t *arena) {
    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(arena, 0x400000ull, "ScaleDriverRoutine", &f) == CBAE_OK);
    cbae_cir_block_t *blk[12];
    for (uint32_t i = 0; i < 12; i++) assert(cbae_cir_block_create(f, 0x400000ull + 0x40ull * i, &blk[i]) == CBAE_OK);
    cbae_cir_builder_t b;
    cbae_cir_builder_init(&b, f, blk[0]);
    cbae_cir_value_t *acc = cbae_cir_param(&b, CBAE_REG_RAX);
    assert(acc);
    for (uint32_t i = 0; i < 40; i++) {
        cbae_cir_value_t *c = cbae_cir_const(&b, cir_type_i(64), (int64_t)i * 1000 - 7);
        assert(c);
        if (i < 14) {
            acc = cbae_cir_binop(&b, CIR_OP_ADD, acc, c, cir_type_i(64), 0x400000ull + i);
            assert(acc);
        }
    }
    cbae_cir_builder_init(&b, f, blk[1]);
    assert(cbae_cir_call(&b, "ExFreePoolWithTag", &acc, 1, cir_type_i(64), 0x400040ull));
    for (uint32_t i = 0; i < 6; i++) assert(cbae_cir_block_add_edge(blk[i], blk[11]) == CBAE_OK);
    for (uint32_t i = 6; i < 11; i++) assert(cbae_cir_block_add_edge(blk[i], blk[i + 1]) == CBAE_OK);
    return f;
}

/* Deserializes into an arena of its own (of @p arena_bytes); the function lives until the next call, which releases it.
 * The blob is read from a copy of exactly its size, so a read of one byte past the end is an error that AddressSanitizer
 * and Valgrind see. The allocation counters start when the deserializer does: ai_max_request() afterwards is the largest
 * request the deserializer made, not the arena's or the copy's. */
static cbae_err_t deserialize_blob_in(const blob_t *b, size_t arena_bytes, cbae_cir_function_t **out) {
    static cbae_arena_t arena;
    static cbae_cir_function_t *prev;
    static bool live;
    if (prev) cbae_cir_function_destroy(prev);
    if (live) cbae_arena_destroy(&arena);
    prev = NULL;
    assert(cbae_arena_init(&arena, arena_bytes) == CBAE_OK);
    live = true;
    uint8_t *exact = malloc(b->n ? b->n : 1);
    assert(exact);
    if (b->n) memcpy(exact, b->p, b->n);
    *out = (cbae_cir_function_t *)1;                                 /* garbage: an error must clear it */
    ai_reset();
    const cbae_err_t rc = cbae_cir_deserialize_function(exact, b->n, &arena, out);
    ai_disarm();
    free(exact);
    prev = rc == CBAE_OK ? *out : NULL;
    return rc;
}

static cbae_err_t deserialize_blob(const blob_t *b, cbae_cir_function_t **out) { return deserialize_blob_in(b, 1 << 20, out); }

/* ── the format, byte for byte ────────────────────────────────────────── */

static void test_the_format(void) {
    mfunc_t m = base_model();
    blob_t golden = write_model(&m);
    cbae_cir_function_t *f;
    assert(deserialize_blob(&golden, &f) == CBAE_OK && f);
    assert(strcmp(f->name, "DriverEntry") == 0 && f->entry_addr == 0x140001000ull);
    assert(cbae_vector_count(&f->values) == 6 && cbae_vector_count(&f->blocks) == 3);
    assert(f->next_value_id == 6 && f->next_insn_id == 7 && f->next_block_id == 3);
    const cbae_cir_block_t *b1 = *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, 1);
    assert(b1->instructions[0]->opcode == CIR_OP_CALL && strcmp(b1->instructions[0]->call_target_name, "ExAllocatePool") == 0);
    assert(b1->instructions[0]->operands[0]->id == 2 && b1->instructions[0]->result->id == 4);
    assert(cbae_cir_function_block_at(f, 0x140001020ull) == b1);     /* the address index is rebuilt */
    cbae_cir_verify_result_t vr = cbae_cir_verify_function(f);
    if (!vr.ok) fprintf(stderr, "verifier: %s\n", vr.message);
    assert(vr.ok);

    uint8_t *again = NULL;
    size_t again_n = 0;
    assert(cbae_cir_serialize_function(f, &again, &again_n) == CBAE_OK);
    assert(again_n == golden.n && memcmp(again, golden.p, golden.n) == 0);   /* the serializer writes the documented layout */
    free(again);
    free(golden.p);

    /* what a model says that is legal, if unusual, is accepted: an empty phi, a NULL operand, a placeholder value, a
     * value nobody uses, a block with no instructions and no edges */
    mfunc_t u = base_model();
    u.blocks[2].insn[0].nphi_decl = u.blocks[2].insn[0].nphi = 0;
    u.blocks[0].insn[0].ops[1] = NO_VALUE;
    u.vals[6] = (mval_t){ 6, CIR_VAL_REG_ENTRY, CIR_TYPE_I64, 0, CBAE_REG_RBX, 0, 2 };
    u.vals[7] = (mval_t){ 7, CIR_VAL_CONST, CIR_TYPE_I8, -1, 0, 0, 0 };
    u.nvals = u.nvals_decl = 8;
    u.blocks[3].id = 3; u.blocks[3].addr = 0x140001060ull; u.blocks[3].preds = lst(0, 0, 0, 0); u.blocks[3].succs = lst(0, 0, 0, 0);
    u.nblocks = u.nblocks_decl = 4;
    blob_t ub = write_model(&u);
    assert(deserialize_blob(&ub, &f) == CBAE_OK);
    assert((*(cbae_cir_block_t **)cbae_vector_at(&f->blocks, 2))->instructions[0]->phi_incoming_count == 0);
    assert((*(cbae_cir_block_t **)cbae_vector_at(&f->blocks, 0))->instructions[0]->operands[1] == NULL);
    assert(cbae_vector_count(&f->values) == 8 && cbae_vector_count(&f->blocks) == 4 && f->next_block_id == 4);
    uint8_t *ub_again = NULL;
    size_t ub_n = 0;
    assert(cbae_cir_serialize_function(f, &ub_again, &ub_n) == CBAE_OK && ub_n == ub.n && memcmp(ub_again, ub.p, ub.n) == 0);
    free(ub_again);
    free(ub.p);

    mfunc_t four = base_model();
    four.blocks[0].insn[0].nops_decl = 4; four.blocks[0].insn[0].nops = 4;
    four.blocks[0].insn[0].ops[2] = 1; four.blocks[0].insn[0].ops[3] = 0;   /* the most an instruction can have */
    blob_t fb = write_model(&four);
    assert(deserialize_blob(&fb, &f) == CBAE_OK && f->next_insn_id == 7);
    assert((*(cbae_cir_block_t **)cbae_vector_at(&f->blocks, 0))->instructions[0]->operand_count == 4);
    free(fb.p);

    mfunc_t none = base_model();                                     /* nothing at all */
    none.nvals = none.nvals_decl = 0; none.nblocks = none.nblocks_decl = 0;
    blob_t nb = write_model(&none);
    assert(deserialize_blob(&nb, &f) == CBAE_OK && cbae_vector_count(&f->values) == 0 && cbae_vector_count(&f->blocks) == 0);
    assert(f->next_value_id == 0 && f->next_insn_id == 0 && f->next_block_id == 0);
    free(nb.p);

    mfunc_t longname = base_model();                                 /* a name of 127 characters, the longest that fits */
    memset(longname.name, 'n', 127); longname.name[127] = 0;
    blob_t lb = write_model(&longname);
    assert(deserialize_blob(&lb, &f) == CBAE_OK && strlen(f->name) == 127);
    free(lb.p);

    mfunc_t nullphi = base_model();                                  /* a phi that has a NULL incoming value */
    nullphi.blocks[2].insn[0].pv[0] = NO_VALUE;
    blob_t pb = write_model(&nullphi);
    assert(deserialize_blob(&pb, &f) == CBAE_OK);
    const cbae_cir_instruction_t *np = (*(cbae_cir_block_t **)cbae_vector_at(&f->blocks, 2))->instructions[0];
    assert(np->phi_incoming_count == 2 && np->phi_incoming_values[0] == NULL && np->phi_incoming_values[1] != NULL);
    uint8_t *pb_again = NULL;
    size_t pb_n = 0;
    assert(cbae_cir_serialize_function(f, &pb_again, &pb_n) == CBAE_OK && pb_n == pb.n && memcmp(pb_again, pb.p, pb.n) == 0);
    free(pb_again);
    free(pb.p);
    PASS("the format: the model's blob parses to the expected function, the serializer writes the same bytes, legal oddities are accepted");
}

/* ── round trips ──────────────────────────────────────────────────────── */

static void round_trip(const cbae_cir_function_t *orig) {
    uint8_t *blob = NULL;
    size_t n = 0;
    ai_reset();
    assert(cbae_cir_serialize_function(orig, &blob, &n) == CBAE_OK && blob && n > 0);
    assert(ai_max_request() == n);                                   /* the buffer is exactly the blob: the size that is summed is the size that is written */
    ai_disarm();
    cbae_arena_t a2;
    assert(cbae_arena_init(&a2, 256 * 1024) == CBAE_OK);
    cbae_cir_function_t *copy = NULL;
    assert(cbae_cir_deserialize_function(blob, n, &a2, &copy) == CBAE_OK && copy);
    cir_same_function(orig, copy);
    uint8_t *blob2 = NULL;
    size_t n2 = 0;
    assert(cbae_cir_serialize_function(copy, &blob2, &n2) == CBAE_OK);
    assert(n2 == n && memcmp(blob, blob2, n) == 0);                  /* serialize . deserialize is the identity on bytes */
    free(blob2);
    cbae_cir_function_destroy(copy);
    cbae_arena_destroy(&a2);
    free(blob);
}

static void test_round_trips(void) {
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 256 * 1024) == CBAE_OK);
    cbae_cir_function_t *rich = rich_function(&arena, false);
    assert(cbae_cir_verify_function(rich).ok);
    round_trip(rich);
    cbae_cir_function_t *rich_re = rich_function(&arena, true);
    round_trip(rich_re);                                             /* with a placeholder value: the format carries pre-SSA functions too */
    cbae_cir_function_t *empty = empty_function(&arena);
    round_trip(empty);
    cbae_cir_function_destroy(empty);
    cbae_cir_function_destroy(rich);
    cbae_cir_function_destroy(rich_re);
    cbae_arena_destroy(&arena);

    /* the longest call name the format holds */
    assert(cbae_arena_init(&arena, 512 * 1024) == CBAE_OK);
    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(&arena, 0x10, "big", &f) == CBAE_OK);
    cbae_cir_block_t *blk;
    assert(cbae_cir_block_create(f, 0x10, &blk) == CBAE_OK);
    char *name = malloc(65536);
    assert(name);
    memset(name, 'q', 65535); name[65535] = '\0';
    cbae_cir_builder_t b;
    cbae_cir_builder_init(&b, f, blk);
    assert(cbae_cir_call(&b, name, NULL, 0, cir_type_i(64), 0x10) != NULL);
    round_trip(f);
    free(name);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    PASS("round trips: a function with every kind of value and instruction, one with placeholders, an empty one, a 65535-byte name - structure and bytes identical");
}

/* A deserialized function is a function like any other: it can be built on, and a phi it holds can grow. */
static void test_deserialized_function_is_usable(void) {
    mfunc_t m = base_model();
    m.blocks[2].insn[0].nphi_decl = m.blocks[2].insn[0].nphi = 0;    /* an empty phi */
    blob_t blob = write_model(&m);
    cbae_cir_function_t *f;
    assert(deserialize_blob(&blob, &f) == CBAE_OK);
    free(blob.p);
    cbae_cir_block_t *b2 = *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, 2);
    cbae_cir_instruction_t *phi = b2->instructions[0];
    assert(phi->opcode == CIR_OP_PHI && phi->phi_incoming_count == 0);
    cbae_cir_value_t *v0 = *(cbae_cir_value_t **)cbae_vector_at(&f->values, 0);
    for (uint32_t i = 0; i < 9; i++)                                 /* past its capacity several times over */
        assert(cbae_cir_phi_add_incoming(f, phi, v0, i % 3) == CBAE_OK);
    assert(phi->phi_incoming_count == 9);
    for (uint32_t i = 0; i < 9; i++) assert(phi->phi_incoming_values[i] == v0 && phi->phi_incoming_blocks[i] == i % 3);

    cbae_cir_block_t *nb;
    assert(cbae_cir_block_create(f, 0x999, &nb) == CBAE_OK && nb->id == 3);
    cbae_cir_builder_t b;
    cbae_cir_builder_init(&b, f, nb);
    cbae_cir_value_t *c = cbae_cir_const(&b, cir_type_i(64), 7);
    assert(c && c->id == 6);
    cbae_cir_value_t *s = cbae_cir_binop(&b, CIR_OP_ADD, c, c, cir_type_i(64), 0x999);
    assert(s && s->id == 7 && s->u.def_insn->id == 7);               /* ids go on from where the blob left off */
    PASS("a deserialized function can be built on: new blocks, values and instructions continue the ids, an empty phi grows");
}

/* ── hostile blobs ────────────────────────────────────────────────────── */

typedef void (*mutator_fn)(mfunc_t *);
typedef struct { const char *what; mutator_fn fn; } hostile_t;

#define MUT(name, ...) static void name(mfunc_t *m) { __VA_ARGS__ }
#define COR(name, ...) static void name(cbae_cir_function_t *f) { __VA_ARGS__ }

MUT(h_magic,        m->magic ^= 1;)
MUT(h_version0,     m->version = 0;)
MUT(h_version2,     m->version = 2;)
MUT(h_blocks_huge,  m->nblocks_decl = 0xFFFFFFFFu;)
MUT(h_blocks_big,   m->nblocks_decl = 0x10000000u;)
MUT(h_values_huge,  m->nvals_decl = 0xFFFFFFFFu;)
MUT(h_values_big,   m->nvals_decl = 0x10000000u;)
MUT(h_blocks_more,  m->nblocks_decl = m->nblocks + 1;)
MUT(h_values_more,  m->nvals_decl = m->nvals + 1;)
MUT(h_values_fewer, m->nvals_decl = m->nvals - 1;)
MUT(h_blocks_fewer, m->nblocks_decl = m->nblocks - 1;)
MUT(h_name_open,    memset(m->name, 'x', sizeof m->name);)
MUT(h_name_dirty,   m->name[40] = 'z';)

MUT(h_kind0,        m->vals[1].kind = 0;)
MUT(h_kind5,        m->vals[1].kind = 5;)
MUT(h_kind255,      m->vals[1].kind = 255;)
MUT(h_type7,        m->vals[1].type = 7;)
MUT(h_type255,      m->vals[1].type = 255;)
MUT(h_val_gap,      m->vals[1].id = 7;)
MUT(h_val_dup,      m->vals[1].id = 0;)
MUT(h_val_order,    m->vals[1].id = 2; m->vals[2].id = 1;)
MUT(h_param_reg,    m->vals[0].reg = CBAE_REG_OTHER + 1;)
MUT(h_param_reg255, m->vals[0].reg = 255;)
MUT(h_entry_reg,    m->vals[1].kind = CIR_VAL_REG_ENTRY; m->vals[1].reg = 200; m->vals[1].block = 0;)
MUT(h_entry_block,  m->vals[1].kind = CIR_VAL_REG_ENTRY; m->vals[1].reg = 3; m->vals[1].block = 3;)
MUT(h_def_unknown,  m->vals[2].def_insn = 99;)
MUT(h_def_other,    m->vals[2].def_insn = 1;)
MUT(h_def_shared,   m->vals[3].def_insn = 0;)
MUT(h_def_huge,     m->vals[2].def_insn = 0xFFFFFFFFu;)

MUT(h_blk_id,       m->blocks[1].id = 5;)
MUT(h_blk_id_swap,  m->blocks[1].id = 2; m->blocks[2].id = 1;)
MUT(h_npred_huge,   m->blocks[1].preds.decl = 0xFFFFFFFFu;)
MUT(h_npred_more,   m->blocks[1].preds.decl = 2;)
MUT(h_pred_range,   m->blocks[1].preds.v[0] = 9;)
MUT(h_succ3,        m->blocks[0].succs = lst(3, 1, 2, 1);)
MUT(h_succ_huge,    m->blocks[0].succs.decl = 0xFFFFFFFFu;)
MUT(h_succ_range,   m->blocks[0].succs.v[1] = 3;)
MUT(h_succ_none,    m->blocks[0].succs.v[0] = NO_VALUE;)
MUT(h_ninsn_huge,   m->blocks[1].ninsn_decl = 0xFFFFFFFFu;)
MUT(h_ninsn_more,   m->blocks[0].ninsn_decl += 1;)
MUT(h_ninsn_fewer,  m->blocks[0].ninsn_decl -= 1;)

MUT(h_op0,          m->blocks[0].insn[0].op = CIR_OP_INVALID;)
MUT(h_op_count,     m->blocks[0].insn[0].op = CIR_OP_COUNT;)
MUT(h_op255,        m->blocks[0].insn[0].op = 255;)
MUT(h_nops5,        m->blocks[0].insn[0].nops_decl = 5; m->blocks[0].insn[0].nops = 5;)
MUT(h_nops255,      m->blocks[0].insn[0].nops_decl = 255; m->blocks[0].insn[0].nops = 0;)
MUT(h_nops_mismatch, m->blocks[0].insn[0].nops_decl = 3;)
MUT(h_operand_id,   m->blocks[0].insn[0].ops[0] = 99;)
MUT(h_operand_huge, m->blocks[0].insn[0].ops[1] = 0xFFFFFFFEu;)
MUT(h_result_id,    m->blocks[0].insn[0].result = 99;)
MUT(h_result_kind,  m->blocks[0].insn[0].result = 0;)
MUT(h_result_other, m->blocks[0].insn[0].result = 3;)
MUT(h_name_len,     m->blocks[1].insn[0].name_len = 0xFFFF;)
MUT(h_name_long,    m->blocks[1].insn[0].name_len = 15;)
MUT(h_name_nul,     m->blocks[1].insn[0].name[3] = 0;)
MUT(h_name_ghost,   m->blocks[0].insn[0].name_len = 2; m->blocks[0].insn[0].name_n = 2; m->blocks[0].insn[0].name[0] = 'a'; m->blocks[0].insn[0].name[1] = 0;)
MUT(h_branch_true,  m->blocks[0].insn[2].t = 9;)
MUT(h_branch_false, m->blocks[0].insn[2].f = 3;)
MUT(h_jump_target,  m->blocks[1].insn[1].t = 77;)
MUT(h_nphi_huge,    m->blocks[2].insn[0].nphi_decl = 0xFFFFFFFFu;)
MUT(h_nphi_more,    m->blocks[2].insn[0].nphi_decl = 3;)
MUT(h_phi_value,    m->blocks[2].insn[0].pv[1] = 40;)
MUT(h_phi_block,    m->blocks[2].insn[0].pb[1] = 7;)
MUT(h_insn_dup,     m->blocks[0].insn[1].id = 0;)
MUT(h_insn_range,   m->blocks[0].insn[1].id = 7;)
MUT(h_insn_huge,    m->blocks[0].insn[1].id = 0xFFFFFFFFu;)
MUT(h_trail1,       m->trailing = 1;)
MUT(h_trail4,       m->trailing = 4;)
MUT(h_trail100,     m->trailing = 100;)

/* The ends of each range: the id that is one past the last (a count of 3 blocks means 0, 1, 2 exist). */
MUT(h_name_last,        m->name[127] = 'z';)
MUT(h_pred_edge,        m->blocks[1].preds.v[0] = 3;)
MUT(h_operand_edge,     m->blocks[0].insn[0].ops[0] = 6;)
MUT(h_result_edge,      m->blocks[0].insn[0].result = 6;)
MUT(h_branch_true_edge, m->blocks[0].insn[2].t = 3;)
MUT(h_jump_edge,        m->blocks[1].insn[1].t = 3;)
MUT(h_phi_value_edge,   m->blocks[2].insn[0].pv[1] = 6;)
MUT(h_phi_block_edge,   m->blocks[2].insn[0].pb[1] = 3;)
MUT(h_entry_block_edge, m->vals[1].kind = CIR_VAL_REG_ENTRY; m->vals[1].reg = CBAE_REG_OTHER; m->vals[1].block = 3;)
MUT(h_entry_reg_edge,   m->vals[1].kind = CIR_VAL_REG_ENTRY; m->vals[1].reg = CBAE_REG_OTHER + 1; m->vals[1].block = 2;)
/* A result that is a parameter, with nothing else wrong: the constant takes the place of the value that instruction 0
 * defined, so that the instruction is the only one that can be blamed. */
MUT(h_result_param_clean, m->vals[2].kind = CIR_VAL_CONST; m->vals[2].cval = 7; m->blocks[0].insn[0].result = 0;)
/* A value that says an instruction defines it, and an instruction that has no result: the value is claimed by nobody. */
MUT(h_value_unclaimed,      m->blocks[0].insn[1].result = NO_VALUE;)
MUT(h_last_value_unclaimed, m->blocks[2].insn[0].result = NO_VALUE;)
/* The last instruction of the blob (the return in block 2) with a name that the bytes left cannot cover, and every byte after
 * its length non-zero: nothing but the check of the length stops a scan for a NUL from running past the end. */
MUT(h_name_len_open,     minsn_t *r = &m->blocks[2].insn[1]; r->name_len = 0xFFFF; r->name_n = 0; r->t = r->f = r->nphi_decl = 0x01010101u; r->nphi = 0;)
MUT(h_name_len_one_over, minsn_t *r = &m->blocks[2].insn[1]; r->name_len = 13;     r->name_n = 0; r->t = r->f = r->nphi_decl = 0x01010101u; r->nphi = 0;)

static const hostile_t HOSTILE[] = {
    { "a wrong magic number", h_magic }, { "version 0", h_version0 }, { "a version from the future", h_version2 },
    { "0xFFFFFFFF blocks declared, none of the bytes for them", h_blocks_huge },
    { "0x10000000 blocks declared", h_blocks_big },
    { "0xFFFFFFFF values declared", h_values_huge }, { "0x10000000 values declared", h_values_big },
    { "one more block declared than present", h_blocks_more }, { "one more value declared than present", h_values_more },
    { "one value too few declared", h_values_fewer }, { "one block too few declared", h_blocks_fewer },
    { "a name with no terminator", h_name_open }, { "bytes after the name's terminator", h_name_dirty },
    { "value kind 0 (invalid)", h_kind0 }, { "value kind 5", h_kind5 }, { "value kind 255", h_kind255 },
    { "type kind 7", h_type7 }, { "type kind 255", h_type255 },
    { "a gap in the value ids", h_val_gap }, { "a duplicate value id", h_val_dup }, { "value ids out of order", h_val_order },
    { "a parameter register that does not exist", h_param_reg }, { "parameter register 255", h_param_reg255 },
    { "a placeholder register that does not exist", h_entry_reg }, { "a placeholder block that does not exist", h_entry_block },
    { "a result whose defining instruction does not exist", h_def_unknown },
    { "a result whose defining instruction has another result", h_def_other },
    { "two values defined by one instruction", h_def_shared }, { "a defining instruction id of 0xFFFFFFFF", h_def_huge },
    { "a block id that is not its index", h_blk_id }, { "two blocks with each other's ids", h_blk_id_swap },
    { "0xFFFFFFFF predecessors", h_npred_huge }, { "a predecessor count above the list", h_npred_more },
    { "a predecessor that is not a block", h_pred_range },
    { "3 successors (a block has at most 2: the arrays that hold them would be overrun)", h_succ3 },
    { "0xFFFFFFFF successors", h_succ_huge }, { "a successor that is not a block", h_succ_range },
    { "a successor of 0xFFFFFFFF", h_succ_none },
    { "0xFFFFFFFF instructions in a block", h_ninsn_huge }, { "one more instruction than present", h_ninsn_more },
    { "one instruction too few declared", h_ninsn_fewer },
    { "opcode 0 (invalid)", h_op0 }, { "opcode CIR_OP_COUNT", h_op_count }, { "opcode 255", h_op255 },
    { "5 operands (the array holds 4)", h_nops5 }, { "255 operands declared", h_nops255 },
    { "an operand count that disagrees with the operands present", h_nops_mismatch },
    { "an operand that is not a value", h_operand_id }, { "an operand id of 0xFFFFFFFE", h_operand_huge },
    { "a result that is not a value", h_result_id }, { "a result that is a parameter", h_result_kind },
    { "a result that belongs to another instruction", h_result_other },
    { "a name longer than the bytes left", h_name_len }, { "a name one byte longer than present", h_name_long },
    { "a name with a NUL inside", h_name_nul }, { "a name that ends in a NUL byte", h_name_ghost },
    { "a branch's true target that is not a block", h_branch_true }, { "a branch's false target that is not a block", h_branch_false },
    { "a jump to a block that does not exist", h_jump_target },
    { "0xFFFFFFFF phi incoming values", h_nphi_huge }, { "more phi incoming values than present", h_nphi_more },
    { "a phi incoming value that is not a value", h_phi_value }, { "a phi incoming block that does not exist", h_phi_block },
    { "a duplicate instruction id", h_insn_dup }, { "an instruction id beyond the instruction count", h_insn_range },
    { "an instruction id of 0xFFFFFFFF", h_insn_huge },
    { "one trailing byte", h_trail1 }, { "four trailing bytes", h_trail4 }, { "a hundred trailing bytes", h_trail100 },
    { "a name field whose last byte is not zero", h_name_last },
    { "a predecessor that is the block after the last", h_pred_edge }, { "an operand that is the value after the last", h_operand_edge },
    { "a result that is the value after the last", h_result_edge },
    { "a branch to the block after the last", h_branch_true_edge }, { "a jump to the block after the last", h_jump_edge },
    { "a phi incoming value that is the value after the last", h_phi_value_edge },
    { "a phi incoming block that is the block after the last", h_phi_block_edge },
    { "a placeholder in the block after the last", h_entry_block_edge },
    { "a placeholder for the register after the last", h_entry_reg_edge },
    { "a result that is a parameter and nothing else is wrong", h_result_param_clean },
    { "a value that no instruction defines", h_value_unclaimed },
    { "the last value, that no instruction defines", h_last_value_unclaimed },
    { "a call name of 65535 bytes with 12 bytes left, none of them NUL", h_name_len_open },
    { "a call name one byte longer than the bytes left, none of them NUL", h_name_len_one_over },
};

static void test_hostile_blobs(void) {
    mfunc_t base = base_model();
    blob_t ok = write_model(&base);
    cbae_cir_function_t *f;
    assert(deserialize_blob(&ok, &f) == CBAE_OK);                    /* the model itself is fine: only the one change can be the reason */
    free(ok.p);

    for (size_t i = 0; i < sizeof HOSTILE / sizeof HOSTILE[0]; i++) {
        mfunc_t m = base_model();
        HOSTILE[i].fn(&m);
        blob_t b = write_model(&m);
        cbae_error_clear();
        ai_reset();
        const cbae_err_t rc = deserialize_blob(&b, &f);
        assert(ai_max_request() < 4 * 1024 * 1024);                  /* a count in the blob never sizes an allocation beyond the bytes that hold it */
        if (rc != CBAE_ERR_PARSE || f != NULL)
            fprintf(stderr, "hostile blob '%s': returned %d (expected CBAE_ERR_PARSE), function %p\n", HOSTILE[i].what, (int)rc, (void *)f);
        assert(rc == CBAE_ERR_PARSE && f == NULL);                   /* refused, and the output is empty */
        assert(cbae_error_get_context()->message[0] != '\0');        /* and the reason is said */
        free(b.p);
    }
    char msg[160];
    snprintf(msg, sizeof msg, "%zu ways for a blob to be wrong, each refused as CBAE_ERR_PARSE with a message and an empty output", sizeof HOSTILE / sizeof HOSTILE[0]);
    PASS(msg);
}

static void test_arguments(void) {
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 1 << 16) == CBAE_OK);
    cbae_cir_function_t *f = (cbae_cir_function_t *)1;
    uint8_t byte = 0;
    assert(cbae_cir_deserialize_function(NULL, 0, &arena, &f) == CBAE_ERR_INVALID && f == NULL);
    assert(cbae_cir_deserialize_function(&byte, 1, NULL, &f) == CBAE_ERR_INVALID);
    assert(cbae_cir_deserialize_function(&byte, 1, &arena, NULL) == CBAE_ERR_INVALID);
    f = (cbae_cir_function_t *)1;
    assert(cbae_cir_deserialize_function(&byte, 0, &arena, &f) == CBAE_ERR_PARSE && f == NULL);   /* an empty buffer is a truncated blob */
    assert(cbae_cir_deserialize_function(&byte, 1, &arena, &f) == CBAE_ERR_PARSE && f == NULL);

    cbae_arena_t a2;
    assert(cbae_arena_init(&a2, 1 << 16) == CBAE_OK);
    cbae_cir_function_t *fn = empty_function(&a2);
    uint8_t *buf = (uint8_t *)1;
    size_t n = 99;
    assert(cbae_cir_serialize_function(NULL, &buf, &n) == CBAE_ERR_INVALID && buf == NULL && n == 0);
    assert(cbae_cir_serialize_function(fn, NULL, &n) == CBAE_ERR_INVALID);
    assert(cbae_cir_serialize_function(fn, &buf, NULL) == CBAE_ERR_INVALID);
    cbae_cir_function_destroy(fn);
    cbae_arena_destroy(&a2);
    cbae_arena_destroy(&arena);
    PASS("arguments: NULLs and empty buffers are refused, outputs are left empty");
}

/* The message of a refusal says that the blob is short. A short read hands back zeros, and a reader that did not stop at it
 * would complain about those zeros ("value 5 has the id 0") instead of about the missing bytes. */
static bool says_short(const char *message) { return strstr(message, "truncated") || strstr(message, "more than the data"); }

/* Every prefix of a valid blob is refused as a short blob. Each prefix is read from a buffer of exactly its length. */
static size_t every_prefix(const uint8_t *blob, size_t n) {
    size_t tried = 0;
    for (size_t len = 0; len < n; len++) {
        uint8_t *exact = malloc(len ? len : 1);
        assert(exact);
        if (len) memcpy(exact, blob, len);
        cbae_arena_t a;
        assert(cbae_arena_init(&a, 256 * 1024) == CBAE_OK);
        cbae_cir_function_t *f = (cbae_cir_function_t *)1;
        cbae_error_clear();
        const cbae_err_t rc = cbae_cir_deserialize_function(exact, len, &a, &f);
        if (rc != CBAE_ERR_PARSE || f != NULL || !says_short(cbae_error_get_context()->message))
            fprintf(stderr, "the first %zu of %zu bytes: returned %d, function %p, message '%s'\n", len, n, (int)rc, (void *)f, cbae_error_get_context()->message);
        assert(rc == CBAE_ERR_PARSE && f == NULL);
        assert(says_short(cbae_error_get_context()->message));
        cbae_arena_destroy(&a);
        free(exact);
        tried++;
    }
    return tried;
}

static void test_every_prefix(void) {
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 256 * 1024) == CBAE_OK);
    cbae_cir_function_t *rich = rich_function(&arena, true);
    uint8_t *blob;
    size_t n;
    assert(cbae_cir_serialize_function(rich, &blob, &n) == CBAE_OK);
    size_t tried = every_prefix(blob, n);
    free(blob);
    cbae_cir_function_destroy(rich);
    cbae_arena_destroy(&arena);

    /* Shapes where the short read is not caught by a count that is checked against the bytes left: twelve constants and
     * nothing after them (the values are the end of the blob), and a function with no values at all whose instructions have
     * NULL operands (a zero from a short read would be a value that does not exist). */
    mfunc_t consts = blank_model();
    consts.nvals = consts.nvals_decl = 12;
    for (uint32_t i = 0; i < 12; i++) consts.vals[i] = (mval_t){ i, CIR_VAL_CONST, CIR_TYPE_I64, 100 + i, 0, 0, 0 };
    blob_t cb = write_model(&consts);
    tried += every_prefix(cb.p, cb.n);
    free(cb.p);

    mfunc_t bare = blank_model();
    bare.nblocks = bare.nblocks_decl = 2;
    bare.blocks[0].id = 0; bare.blocks[0].addr = 0x2000ull; bare.blocks[0].preds = lst(0, 0, 0, 0); bare.blocks[0].succs = lst(1, 1, 0, 0);
    bare.blocks[1].id = 1; bare.blocks[1].addr = 0x2010ull; bare.blocks[1].preds = lst(1, 0, 0, 0); bare.blocks[1].succs = lst(0, 0, 0, 0);
    bare.blocks[0].ninsn = bare.blocks[0].ninsn_decl = 2; bare.blocks[1].ninsn = bare.blocks[1].ninsn_decl = 1;
    bare.blocks[0].insn[0] = ins(0, CIR_OP_CALL, NO_VALUE, 1, NO_VALUE, 0, 0);
    memcpy(bare.blocks[0].insn[0].name, "abc", 3); bare.blocks[0].insn[0].name_len = 3; bare.blocks[0].insn[0].name_n = 3;
    bare.blocks[0].insn[1] = ins(1, CIR_OP_JUMP, NO_VALUE, 0, 0, 0, 0);
    bare.blocks[0].insn[1].t = 1;
    bare.blocks[1].insn[0] = ins(2, CIR_OP_RETURN, NO_VALUE, 1, NO_VALUE, 0, 0);
    blob_t bb = write_model(&bare);
    cbae_cir_function_t *f;
    assert(deserialize_blob(&bb, &f) == CBAE_OK);                    /* the shape itself is a valid blob */
    tried += every_prefix(bb.p, bb.n);
    free(bb.p);

    /* The instructions are counted against the bytes left, for the whole function and again for each block, by giving every
     * instruction the least it can take (32 bytes). A cut in the last 31 bytes of the last instruction of a block is therefore
     * refused before the instruction is read; it is the instructions that come after a BIG one in the same block that the
     * instruction reader has to stop at itself. It must, in the header (which a reader that went on would take for instruction
     * 0 again, or for opcode 0) and in the operand (a zero from a short read would be a value, and this function has none).
     * A phi with four incoming values is the big one; the return after it is cut at each of its 36 bytes. */
    mfunc_t fat = blank_model();
    fat.nblocks = fat.nblocks_decl = 1;
    fat.blocks[0].id = 0; fat.blocks[0].addr = 0x2000ull; fat.blocks[0].preds = lst(0, 0, 0, 0); fat.blocks[0].succs = lst(0, 0, 0, 0);
    fat.blocks[0].ninsn = fat.blocks[0].ninsn_decl = 2;
    fat.blocks[0].insn[0] = ins(0, CIR_OP_PHI, NO_VALUE, 0, 0, 0, 0);
    fat.blocks[0].insn[0].nphi_decl = fat.blocks[0].insn[0].nphi = 4;
    for (uint32_t k = 0; k < 4; k++) { fat.blocks[0].insn[0].pv[k] = NO_VALUE; fat.blocks[0].insn[0].pb[k] = 0; }
    fat.blocks[0].insn[1] = ins(1, CIR_OP_RETURN, NO_VALUE, 1, NO_VALUE, 0, 0);
    blob_t fb = write_model(&fat);
    assert(deserialize_blob(&fb, &f) == CBAE_OK);
    tried += every_prefix(fb.p, fb.n);
    free(fb.p);

    char msg[160];
    snprintf(msg, sizeof msg, "all %zu truncations of four valid blobs are refused as CBAE_ERR_PARSE, each saying that the blob is short, none leaks", tried);
    PASS(msg);
}

/* ── what the serializer refuses to write ─────────────────────────────── */

typedef void (*corrupt_fn)(cbae_cir_function_t *);
typedef struct { const char *what; corrupt_fn fn; cbae_err_t expect; } corruption_t;

static cbae_cir_block_t *blk_at(cbae_cir_function_t *f, size_t i) { return *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, i); }
static cbae_cir_value_t *val_at(cbae_cir_function_t *f, size_t i) { return *(cbae_cir_value_t **)cbae_vector_at(&f->values, i); }

static cbae_cir_value_t *first_result(cbae_cir_function_t *f) {
    for (size_t i = 0; i < cbae_vector_count(&f->values); i++)
        if (val_at(f, i)->kind == CIR_VAL_INSN_RESULT) return val_at(f, i);
    return NULL;
}

static char *g_long_name;                                              /* 65536 bytes */

COR(c_def_null,      first_result(f)->u.def_insn = NULL;)
COR(c_succ3,         blk_at(f, 0)->successor_count = 3;)
COR(c_succ_range,    blk_at(f, 0)->successors[0] = 40;)
COR(c_pred_range,    *(uint32_t *)cbae_vector_at(&blk_at(f, 1)->predecessors, 0) = 40;)
COR(c_blk_id,        blk_at(f, 1)->id = 9;)
COR(c_operands5,     blk_at(f, 0)->instructions[0]->operand_count = 5;)
COR(c_name_long,     blk_at(f, 1)->instructions[0]->call_target_name = g_long_name;)
COR(c_opcode0,       blk_at(f, 0)->instructions[0]->opcode = CIR_OP_INVALID;)
COR(c_opcode_big,    blk_at(f, 0)->instructions[0]->opcode = (cbae_cir_opcode_t)200;)
COR(c_val_kind,      val_at(f, 2)->kind = (cbae_cir_value_kind_t)9;)
COR(c_val_kind0,     val_at(f, 2)->kind = CIR_VAL_INVALID;)
COR(c_type_kind,     val_at(f, 2)->type.kind = (cbae_cir_type_kind_t)40;)
COR(c_val_id,        val_at(f, 2)->id = 77;)
COR(c_param_reg,     val_at(f, 0)->u.param_reg = (cbae_reg_t)60;)
COR(c_operand_foreign, static cbae_cir_value_t stranger; stranger.kind = CIR_VAL_CONST; stranger.id = 2;
                     blk_at(f, 0)->instructions[0]->operands[0] = &stranger;)
COR(c_result_foreign,  static cbae_cir_value_t stranger; stranger.kind = CIR_VAL_CONST; stranger.id = 2;
                     blk_at(f, 0)->instructions[0]->result = &stranger;)
COR(c_insn_id_dup,   blk_at(f, 0)->instructions[1]->id = blk_at(f, 0)->instructions[0]->id;)
COR(c_insn_id_big,   blk_at(f, 0)->instructions[1]->id = 5000;)
COR(c_branch_target, blk_at(f, 0)->instructions[blk_at(f, 0)->instruction_count - 1]->branch_true_block = 50;)
COR(c_phi_block,     blk_at(f, 3)->instructions[0]->phi_incoming_blocks[0] = 50;)
COR(c_phi_value,     static cbae_cir_value_t stranger; stranger.kind = CIR_VAL_CONST; stranger.id = 0;
                     blk_at(f, 3)->instructions[0]->phi_incoming_values[0] = &stranger;)
COR(c_def_wrong,     first_result(f)->u.def_insn = blk_at(f, 0)->instructions[1];)
COR(c_slot_null,     blk_at(f, 0)->instructions[1] = NULL;)
COR(c_val_null,      *(cbae_cir_value_t **)cbae_vector_at(&f->values, 3) = NULL;)
COR(c_blk_null,      cbae_vector_destroy(&blk_at(f, 2)->predecessors);      /* the test empties the slot, so the test frees what it held */
                     *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, 2) = NULL;)
COR(c_entry_block,   for (size_t i = 0; i < cbae_vector_count(&f->values); i++)
                         if (val_at(f, i)->kind == CIR_VAL_REG_ENTRY) val_at(f, i)->u.reg_entry.block_id = 50;)

/* The parts of rich_function that the corruptions below aim at: block 0 ends in the branch, block 1 is the call, the store and
 * the jump, block 3 holds the phi (two incoming pairs) and the return; value 2 is a constant. */
static cbae_cir_instruction_t *the_branch(cbae_cir_function_t *f) { cbae_cir_block_t *b = blk_at(f, 0); return b->instructions[b->instruction_count - 1]; }
static cbae_cir_instruction_t *the_store(cbae_cir_function_t *f)  { return blk_at(f, 1)->instructions[1]; }
static cbae_cir_instruction_t *the_jump(cbae_cir_function_t *f)   { return blk_at(f, 1)->instructions[2]; }
static cbae_cir_instruction_t *the_phi(cbae_cir_function_t *f)    { return blk_at(f, 3)->instructions[0]; }
static uint32_t block_count(const cbae_cir_function_t *f) { return (uint32_t)cbae_vector_count(&f->blocks); }
static uint32_t value_count(const cbae_cir_function_t *f) { return (uint32_t)cbae_vector_count(&f->values); }
static uint32_t insn_count(cbae_cir_function_t *f) {
    uint32_t n = 0;
    for (size_t i = 0; i < cbae_vector_count(&f->blocks); i++) n += blk_at(f, i)->instruction_count;
    return n;
}

/* A value in the function's table that no instruction uses: only the check of the table itself can see what is wrong with it. */
static cbae_cir_value_t *stray_value(cbae_cir_function_t *f, cbae_cir_value_kind_t kind) {
    cbae_cir_value_t *v = CBAE_ARENA_ALLOC(f->arena, cbae_cir_value_t);
    assert(v);
    v->id = f->next_value_id++;
    v->kind = kind;
    v->type = cir_type_i(64);
    assert(cbae_vector_push(&f->values, &v) == CBAE_OK);
    return v;
}

/* Each of these breaks one rule of the format and nothing else, and sits at an edge of a range or where only one check can see it. */
COR(c_name_open,         memset(f->name, 'x', sizeof f->name);)
COR(c_opcode_count,      blk_at(f, 0)->instructions[0]->opcode = CIR_OP_COUNT;)
COR(c_insn_id_edge,      blk_at(f, 0)->instructions[0]->id = insn_count(f);)
COR(c_insn_id_dup_void,  blk_at(f, 3)->instructions[1]->id = the_jump(f)->id;)       /* the return takes the jump's id: both are void, no value gives it away */
COR(c_void_result_stranger, static cbae_cir_value_t stranger; stranger.kind = CIR_VAL_INSN_RESULT; stranger.type = cir_type_i(64);
                         stranger.id = 0; stranger.u.def_insn = the_store(f); the_store(f)->result = &stranger;)
COR(c_void_result_alias, cbae_cir_value_t *c = val_at(f, 2); c->u.const_val = (int64_t)(intptr_t)the_store(f); the_store(f)->result = c;)
COR(c_void_result_other, the_store(f)->result = first_result(f);)
COR(c_branch_false,      the_branch(f)->branch_false_block = 50;)
COR(c_branch_true_edge,  the_branch(f)->branch_true_block = block_count(f);)
COR(c_branch_false_edge, the_branch(f)->branch_false_block = block_count(f);)
COR(c_jump_target,       the_jump(f)->branch_true_block = 50;)
COR(c_jump_edge,         the_jump(f)->branch_true_block = block_count(f);)
COR(c_phi_values_null,   the_phi(f)->phi_incoming_values = NULL;)
COR(c_phi_blocks_null,   the_phi(f)->phi_incoming_blocks = NULL;)
COR(c_phi_block_edge,    the_phi(f)->phi_incoming_blocks[0] = block_count(f);)
COR(c_phi_last_block,    the_phi(f)->phi_incoming_blocks[1] = 50;)
COR(c_phi_last_value,    static cbae_cir_value_t stranger; stranger.kind = CIR_VAL_CONST; stranger.id = 0; the_phi(f)->phi_incoming_values[1] = &stranger;)
COR(c_insns_null,        blk_at(f, 0)->instructions = NULL;)
COR(c_succ_edge,         blk_at(f, 0)->successors[0] = block_count(f);)
COR(c_succ_last,         blk_at(f, 0)->successors[1] = 50;)
COR(c_pred_edge,         *(uint32_t *)cbae_vector_at(&blk_at(f, 1)->predecessors, 0) = block_count(f);)
COR(c_operand_edge,      static cbae_cir_value_t stranger; stranger.kind = CIR_VAL_CONST; stranger.id = value_count(f);
                         blk_at(f, 0)->instructions[0]->operands[0] = &stranger;)    /* a value that is not in the table, whose id is the one after the last */
COR(c_stray_slot_null,   stray_value(f, CIR_VAL_CONST); *(cbae_cir_value_t **)cbae_vector_at(&f->values, value_count(f) - 1) = NULL;)
COR(c_stray_id,          stray_value(f, CIR_VAL_CONST)->id = 3;)
COR(c_val_kind_edge,     val_at(f, 2)->kind = (cbae_cir_value_kind_t)(CIR_VAL_REG_ENTRY + 1);)
COR(c_type_kind_edge,    val_at(f, 2)->type.kind = (cbae_cir_type_kind_t)(CIR_TYPE_PTR + 1);)
COR(c_stray_def_null,    stray_value(f, CIR_VAL_INSN_RESULT)->u.def_insn = NULL;)
COR(c_stray_def_big,     static cbae_cir_instruction_t alien; cbae_cir_value_t *s = stray_value(f, CIR_VAL_INSN_RESULT);
                         alien.id = 5000; alien.result = s; s->u.def_insn = &alien;)
COR(c_stray_def_alien,   static cbae_cir_instruction_t alien; cbae_cir_value_t *s = stray_value(f, CIR_VAL_INSN_RESULT);
                         alien.id = 0; alien.result = s; s->u.def_insn = &alien;)    /* an id that is the id of one of the function's, an instruction that is not */
COR(c_stray_def_other,   stray_value(f, CIR_VAL_INSN_RESULT)->u.def_insn = blk_at(f, 0)->instructions[0];)   /* an instruction of the function whose result is another value */
COR(c_entry_reg,         for (size_t i = 0; i < cbae_vector_count(&f->values); i++)
                             if (val_at(f, i)->kind == CIR_VAL_REG_ENTRY) val_at(f, i)->u.reg_entry.reg = (cbae_reg_t)(CBAE_REG_OTHER + 1);)
COR(c_entry_edge,        for (size_t i = 0; i < cbae_vector_count(&f->values); i++)
                             if (val_at(f, i)->kind == CIR_VAL_REG_ENTRY) val_at(f, i)->u.reg_entry.block_id = block_count(f);)

static const corruption_t CORRUPTIONS[] = {
    { "an instruction result whose defining instruction is NULL", c_def_null, CBAE_ERR_INVALID },
    { "a block with 3 successors", c_succ3, CBAE_ERR_INVALID },
    { "a successor that is not a block", c_succ_range, CBAE_ERR_INVALID },
    { "a predecessor that is not a block", c_pred_range, CBAE_ERR_INVALID },
    { "a block whose id is not its index", c_blk_id, CBAE_ERR_INVALID },
    { "an instruction with 5 operands", c_operands5, CBAE_ERR_INVALID },
    { "a call target name of 65536 bytes (the length field is 16 bits)", c_name_long, CBAE_ERR_OVERFLOW },
    { "opcode 0", c_opcode0, CBAE_ERR_INVALID }, { "opcode 200", c_opcode_big, CBAE_ERR_INVALID },
    { "value kind 9", c_val_kind, CBAE_ERR_INVALID }, { "value kind 0", c_val_kind0, CBAE_ERR_INVALID },
    { "type kind 40", c_type_kind, CBAE_ERR_INVALID },
    { "a value whose id is not its index", c_val_id, CBAE_ERR_INVALID },
    { "a parameter register that does not exist", c_param_reg, CBAE_ERR_INVALID },
    { "an operand that is not one of the function's values", c_operand_foreign, CBAE_ERR_INVALID },
    { "a result that is not one of the function's values", c_result_foreign, CBAE_ERR_INVALID },
    { "two instructions with one id", c_insn_id_dup, CBAE_ERR_INVALID },
    { "an instruction id beyond the instruction count", c_insn_id_big, CBAE_ERR_INVALID },
    { "a branch target that is not a block", c_branch_target, CBAE_ERR_INVALID },
    { "a phi incoming block that does not exist", c_phi_block, CBAE_ERR_INVALID },
    { "a phi incoming value that is not one of the function's values", c_phi_value, CBAE_ERR_INVALID },
    { "a result defined by another instruction than the one it is attached to", c_def_wrong, CBAE_ERR_INVALID },
    { "an empty instruction slot", c_slot_null, CBAE_ERR_INVALID },
    { "an empty value slot", c_val_null, CBAE_ERR_INVALID },
    { "an empty block slot", c_blk_null, CBAE_ERR_INVALID },
    { "a placeholder for a block that does not exist", c_entry_block, CBAE_ERR_INVALID },
    { "a function name with no terminator", c_name_open, CBAE_ERR_INVALID },
    { "opcode CIR_OP_COUNT", c_opcode_count, CBAE_ERR_INVALID },
    { "an instruction id equal to the number of instructions", c_insn_id_edge, CBAE_ERR_INVALID },
    { "two void instructions with one id (no value gives it away)", c_insn_id_dup_void, CBAE_ERR_INVALID },
    { "a void instruction with a result that is not in the table", c_void_result_stranger, CBAE_ERR_INVALID },
    { "a void instruction whose result is a constant that reads as a pointer to the instruction", c_void_result_alias, CBAE_ERR_INVALID },
    { "a void instruction whose result is defined by another instruction", c_void_result_other, CBAE_ERR_INVALID },
    { "a branch whose false target is not a block", c_branch_false, CBAE_ERR_INVALID },
    { "a branch whose true target is the block after the last", c_branch_true_edge, CBAE_ERR_INVALID },
    { "a branch whose false target is the block after the last", c_branch_false_edge, CBAE_ERR_INVALID },
    { "a jump to a block that does not exist", c_jump_target, CBAE_ERR_INVALID },
    { "a jump to the block after the last", c_jump_edge, CBAE_ERR_INVALID },
    { "a phi with incoming values and no array for them", c_phi_values_null, CBAE_ERR_INVALID },
    { "a phi with incoming blocks and no array for them", c_phi_blocks_null, CBAE_ERR_INVALID },
    { "a phi incoming block that is the block after the last", c_phi_block_edge, CBAE_ERR_INVALID },
    { "the last phi incoming block that does not exist", c_phi_last_block, CBAE_ERR_INVALID },
    { "the last phi incoming value that is not one of the function's", c_phi_last_value, CBAE_ERR_INVALID },
    { "a block with instructions and no array for them", c_insns_null, CBAE_ERR_INVALID },
    { "a successor that is the block after the last", c_succ_edge, CBAE_ERR_INVALID },
    { "the second successor that is not a block", c_succ_last, CBAE_ERR_INVALID },
    { "a predecessor that is the block after the last", c_pred_edge, CBAE_ERR_INVALID },
    { "an operand that is not in the table, with the id after the last value", c_operand_edge, CBAE_ERR_INVALID },
    { "an empty slot in the table of an unused value", c_stray_slot_null, CBAE_ERR_INVALID },
    { "an unused value whose id is not its index", c_stray_id, CBAE_ERR_INVALID },
    { "the value kind after the last", c_val_kind_edge, CBAE_ERR_INVALID },
    { "the type kind after the last", c_type_kind_edge, CBAE_ERR_INVALID },
    { "an instruction result with no instruction, that no instruction attaches", c_stray_def_null, CBAE_ERR_INVALID },
    { "an instruction result whose instruction has an id beyond the count", c_stray_def_big, CBAE_ERR_INVALID },
    { "an instruction result whose instruction is not the one in the table under its id", c_stray_def_alien, CBAE_ERR_INVALID },
    { "an instruction result whose instruction has another result", c_stray_def_other, CBAE_ERR_INVALID },
    { "a placeholder for the register after the last", c_entry_reg, CBAE_ERR_INVALID },
    { "a placeholder in the block after the last", c_entry_edge, CBAE_ERR_INVALID },
};

static void test_refusals(void) {
    g_long_name = malloc(65537);
    assert(g_long_name);
    memset(g_long_name, 'n', 65536); g_long_name[65536] = '\0';
    for (size_t i = 0; i < sizeof CORRUPTIONS / sizeof CORRUPTIONS[0]; i++) {
        cbae_arena_t arena;
        assert(cbae_arena_init(&arena, 256 * 1024) == CBAE_OK);
        cbae_cir_function_t *f = rich_function(&arena, true);
        CORRUPTIONS[i].fn(f);
        uint8_t *buf = (uint8_t *)1;
        size_t n = 99;
        cbae_error_clear();
        const cbae_err_t rc = cbae_cir_serialize_function(f, &buf, &n);
        if (rc != CORRUPTIONS[i].expect || buf != NULL || n != 0)
            fprintf(stderr, "corruption '%s': returned %d (expected %d), buffer %p, size %zu\n", CORRUPTIONS[i].what, (int)rc, (int)CORRUPTIONS[i].expect, (void *)buf, n);
        assert(rc == CORRUPTIONS[i].expect && buf == NULL && n == 0);
        assert(cbae_error_get_context()->message[0] != '\0');
        cbae_cir_function_destroy(f);
        cbae_arena_destroy(&arena);
    }
    free(g_long_name);
    char msg[160];
    snprintf(msg, sizeof msg, "%zu ways for a function to be unwritable, each refused with an error, a message and empty outputs (none reads past an array)", sizeof CORRUPTIONS / sizeof CORRUPTIONS[0]);
    PASS(msg);
}

/* ── out of memory ────────────────────────────────────────────────────── */

typedef struct { const cbae_cir_function_t *orig; const uint8_t *blob; size_t n; cbae_arena_t *arena; } oom_ctx_t;

static cbae_err_t ser_body(void *vctx, uint64_t failing) {
    const oom_ctx_t *c = (const oom_ctx_t *)vctx;
    uint8_t *buf = (uint8_t *)1;
    size_t n = 77;
    const cbae_err_t rc = cbae_cir_serialize_function(c->orig, &buf, &n);
    if (rc != CBAE_OK) {
        assert(failing != 0 && rc == CBAE_ERR_OOM && buf == NULL && n == 0);
        return rc;
    }
    ai_disarm();
    assert(n == c->n && memcmp(buf, c->blob, n) == 0);              /* complete and correct, not partial */
    free(buf);
    return CBAE_OK;
}

static cbae_err_t des_body(void *vctx, uint64_t failing) {
    const oom_ctx_t *c = (const oom_ctx_t *)vctx;
    cbae_arena_reset(c->arena);
    cbae_cir_function_t *f = (cbae_cir_function_t *)1;
    const cbae_err_t rc = cbae_cir_deserialize_function(c->blob, c->n, c->arena, &f);
    if (rc != CBAE_OK) {
        assert(failing != 0 && rc == CBAE_ERR_OOM && f == NULL);
        return rc;
    }
    ai_disarm();
    cir_same_function(c->orig, f);
    cbae_cir_function_destroy(f);
    return CBAE_OK;
}

static cbae_err_t arena_body(void *vctx, size_t bytes) {
    const oom_ctx_t *c = (const oom_ctx_t *)vctx;
    cbae_arena_t a;
    if (cbae_arena_init(&a, bytes) != CBAE_OK) return CBAE_ERR_OOM;
    cbae_cir_function_t *f = (cbae_cir_function_t *)1;
    const cbae_err_t rc = cbae_cir_deserialize_function(c->blob, c->n, &a, &f);
    if (rc == CBAE_OK) {
        cir_same_function(c->orig, f);
        cbae_cir_function_destroy(f);
    } else {
        assert(rc == CBAE_ERR_OOM && f == NULL);                     /* a full arena is out of memory, not a malformed blob */
    }
    cbae_arena_destroy(&a);
    return rc;
}

/* The sweeps over one function: serialize and deserialize with each allocation failing, and deserialize with each arena size. */
static void sweep_function(const char *label, cbae_cir_function_t *fn, uint64_t least_ser, uint64_t least_des, size_t arena_hi, size_t arena_step) {
    cbae_arena_t work;
    assert(cbae_arena_init(&work, 512 * 1024) == CBAE_OK);
    uint8_t *blob;
    size_t n;
    assert(cbae_cir_serialize_function(fn, &blob, &n) == CBAE_OK);
    oom_ctx_t ctx = { fn, blob, n, &work };

    oom_report_t r = oom_sweep(ser_body, &ctx, true);
    assert(r.allocations >= least_ser && r.runs == 2 * r.allocations && r.reported == r.runs);
    char msg[320];
    snprintf(msg, sizeof msg, "%s - serialize: out of memory at each of its %llu allocations (alone, and with every later one failing): %llu errors, none swallowed, no leak",
             label, (unsigned long long)r.allocations, (unsigned long long)r.reported);
    PASS(msg);

    r = oom_sweep(des_body, &ctx, true);
    assert(r.allocations >= least_des && r.runs == 2 * r.allocations && r.reported == r.runs);
    snprintf(msg, sizeof msg, "%s - deserialize: out of memory at each of its %llu allocations: %llu errors, none swallowed, partial functions released, no leak",
             label, (unsigned long long)r.allocations, (unsigned long long)r.reported);
    PASS(msg);

    const size_t first = oom_sweep_arena(arena_body, &ctx, 64, arena_hi, arena_step);
    assert(first > 64 && first <= arena_hi);
    snprintf(msg, sizeof msg, "%s - deserialize: an arena below %zu bytes is out of memory, every size from there up succeeds (never a failure after a success)", label, first);
    PASS(msg);

    free(blob);
    cbae_arena_destroy(&work);
}

/* One block of 24 instructions. An instruction takes more arena than the pointer array that holds 14 of them, but not more than
 * the array for 24, so there are arena sizes at which the array does not fit and the next instruction would: a reader that did
 * not stop at the missing array would write the first instruction through NULL. */
static cbae_cir_function_t *long_block_function(cbae_arena_t *arena) {
    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(arena, 0x500000ull, "LongBlock", &f) == CBAE_OK);
    cbae_cir_block_t *blk;
    assert(cbae_cir_block_create(f, 0x500000ull, &blk) == CBAE_OK);
    cbae_cir_builder_t b;
    cbae_cir_builder_init(&b, f, blk);
    cbae_cir_value_t *acc = cbae_cir_param(&b, CBAE_REG_RAX);
    assert(acc);
    for (uint32_t i = 0; i < 24; i++) {
        acc = cbae_cir_binop(&b, CIR_OP_ADD, acc, acc, cir_type_i(64), 0x500000ull + i);
        assert(acc);
    }
    assert(blk->instruction_count == 24);
    return f;
}

static void test_out_of_memory(void) {
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 512 * 1024) == CBAE_OK);
    cbae_cir_function_t *rich = rich_function(&arena, true);
    sweep_function("a function with every kind of value and instruction", rich, 2, 5, 64 * 1024, 8);
    cbae_cir_function_destroy(rich);
    cbae_cir_function_t *longblock = long_block_function(&arena);
    sweep_function("a block of 24 instructions", longblock, 2, 5, 16 * 1024, 1);
    cbae_cir_function_destroy(longblock);
    /* more than the constructors start with, so that the tables and arrays that the deserializer reserves are allocated too */
    cbae_cir_function_t *scale = scale_function(&arena);
    sweep_function("a function of 12 blocks and 56 values", scale, 2, 20, 128 * 1024, 64);
    cbae_cir_function_destroy(scale);
    cbae_arena_destroy(&arena);
}

/* ── fuzz ─────────────────────────────────────────────────────────────── */

static FILE *g_null;

/* Returns whether the blob was accepted. */
static bool check_changed_blob(const uint8_t *b, size_t n) {
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 256 * 1024) == CBAE_OK);
    cbae_cir_function_t *f = (cbae_cir_function_t *)1;
    const cbae_err_t rc = cbae_cir_deserialize_function(b, n, &arena, &f);
    if (rc != CBAE_OK) {
        assert(rc == CBAE_ERR_PARSE && f == NULL);                   /* refused cleanly (the arena is big enough for any blob this small) */
    } else {
        assert(f);
        const cbae_cir_verify_result_t vr = cbae_cir_verify_function(f);   /* every consumer may walk it: no crash, whatever the verdict */
        (void)vr;
        cbae_cir_print_function(f, g_null);
        uint8_t *again = NULL;
        size_t m = 0;
        assert(cbae_cir_serialize_function(f, &again, &m) == CBAE_OK);
        assert(m == n && memcmp(again, b, n) == 0);                 /* an accepted blob is exactly what the serializer would write */
        free(again);
        cbae_cir_function_destroy(f);
    }
    cbae_arena_destroy(&arena);
    return rc == CBAE_OK;
}

static size_t fuzz_blob(const uint8_t *blob, size_t n, size_t *accepted) {
    uint8_t *w = malloc(n);
    assert(w);
    size_t runs = 0;
    const size_t stride = QUICK ? 3 : 1;
    for (size_t i = 0; i < n; i += stride) {
        const uint8_t o = blob[i];
        const uint8_t variants[10] = { 0x00, 0x01, 0x02, 0x7F, 0x80, 0xFF, (uint8_t)(o ^ 0x01), (uint8_t)(o ^ 0x80), (uint8_t)(o + 1), (uint8_t)(o - 1) };
        for (int k = 0; k < 10; k++) {
            if (variants[k] == o) continue;
            memcpy(w, blob, n);
            w[i] = variants[k];
            *accepted += check_changed_blob(w, n);
            runs++;
        }
    }
    free(w);
    return runs;
}

static void test_fuzz(void) {
    g_null = fopen("/dev/null", "w");
    assert(g_null);
    mfunc_t m = base_model();
    blob_t base = write_model(&m);
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 256 * 1024) == CBAE_OK);
    cbae_cir_function_t *rich = rich_function(&arena, true);
    uint8_t *blob;
    size_t n;
    assert(cbae_cir_serialize_function(rich, &blob, &n) == CBAE_OK);

    size_t accepted = 0;
    size_t runs = fuzz_blob(base.p, base.n, &accepted);
    runs += fuzz_blob(blob, n, &accepted);
    assert(accepted > runs / 50 && accepted < runs);                 /* the fuzz reaches both the accepting and the refusing paths */
    char msg[200];
    snprintf(msg, sizeof msg, "fuzz: %zu one-byte changes of two valid blobs, %zu accepted (each serializes back to the same bytes), the rest refused as CBAE_ERR_PARSE", runs, accepted);
    PASS(msg);

    free(blob);
    free(base.p);
    cbae_cir_function_destroy(rich);
    cbae_arena_destroy(&arena);
    fclose(g_null);
}

/* ── limits that are met exactly ──────────────────────────────────────── */

/* The model's blob is accepted, and the function that is read serializes to the same bytes. */
static void accepted_exactly(const mfunc_t *m) {
    blob_t b = write_model(m);
    cbae_cir_function_t *f;
    assert(deserialize_blob(&b, &f) == CBAE_OK);
    uint8_t *again = NULL;
    size_t n = 0;
    assert(cbae_cir_serialize_function(f, &again, &n) == CBAE_OK && n == b.n && memcmp(again, b.p, b.n) == 0);
    free(again);
    free(b.p);
}

static void test_boundaries(void) {
    /* The shortest blobs that the format allows for what they declare. Every count is checked against the bytes that remain,
     * with the least that one record takes (a parameter 7 bytes, a block 24, an instruction 32), so a blob that is exactly
     * that short must be accepted: a bound that is off by one refuses a legal function. */
    mfunc_t params = blank_model();
    params.nvals = params.nvals_decl = 16;
    for (uint32_t i = 0; i < 16; i++) params.vals[i] = (mval_t){ i, CIR_VAL_PARAM, CIR_TYPE_I64, 0, i == 15 ? CBAE_REG_OTHER : (uint8_t)i, 0, 0 };
    accepted_exactly(&params);                                       /* 16 parameters, the last of them in the register at the end of the range */

    mfunc_t blocks = blank_model();
    blocks.nblocks = blocks.nblocks_decl = 4;
    for (uint32_t i = 0; i < 4; i++) { blocks.blocks[i].id = i; blocks.blocks[i].addr = 0x3000ull + 0x10ull * i; }
    accepted_exactly(&blocks);                                       /* 4 blocks, nothing in them */

    mfunc_t insns = blank_model();
    insns.nblocks = insns.nblocks_decl = 1;
    insns.blocks[0].id = 0; insns.blocks[0].addr = 0x3000ull;
    insns.blocks[0].ninsn = insns.blocks[0].ninsn_decl = 8;
    for (uint32_t k = 0; k < 8; k++) insns.blocks[0].insn[k] = ins(k, CIR_OP_RETURN, NO_VALUE, 0, 0, 0, 0);
    accepted_exactly(&insns);                                        /* 8 instructions of 32 bytes */

    mfunc_t both = blank_model();
    both.nvals = both.nvals_decl = 3;
    for (uint32_t i = 0; i < 3; i++) both.vals[i] = (mval_t){ i, CIR_VAL_PARAM, CIR_TYPE_I64, 0, CBAE_REG_RAX, 0, 0 };
    both.nblocks = both.nblocks_decl = 2;
    for (uint32_t i = 0; i < 2; i++) { both.blocks[i].id = i; both.blocks[i].addr = 0x3000ull + 0x10ull * i; }
    accepted_exactly(&both);                                         /* values and blocks add up to the bound together */

    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 512 * 1024) == CBAE_OK);

    /* The registers at both ends of the range, for a parameter and for the placeholder that the lifter leaves. */
    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(&arena, 0x10, "Registers", &f) == CBAE_OK);
    cbae_cir_block_t *blk;
    assert(cbae_cir_block_create(f, 0x10, &blk) == CBAE_OK);
    cbae_cir_builder_t b;
    cbae_cir_builder_init(&b, f, blk);
    cbae_cir_value_t *lo = cbae_cir_param(&b, CBAE_REG_RAX), *hi = cbae_cir_param(&b, CBAE_REG_OTHER);
    assert(lo && hi);
    cbae_cir_value_t *re = CBAE_ARENA_ALLOC(&arena, cbae_cir_value_t);
    assert(re);
    re->kind = CIR_VAL_REG_ENTRY; re->type = cir_type_i(64); re->id = f->next_value_id++;
    re->u.reg_entry.reg = CBAE_REG_OTHER; re->u.reg_entry.block_id = blk->id;
    assert(cbae_vector_push(&f->values, &re) == CBAE_OK);
    assert(cbae_cir_binop(&b, CIR_OP_ADD, lo, hi, cir_type_i(64), 0x10));
    assert(cbae_cir_binop(&b, CIR_OP_XOR, re, hi, cir_type_i(64), 0x14));
    round_trip(f);
    cbae_cir_function_destroy(f);

    /* More than the constructors start with: the arrays that were allocated for 8 instructions and 4 predecessors, the tables for
     * 32 values and 8 blocks. The deserialized function must have room that is as large as what it holds, and be built on. */
    cbae_cir_function_t *scale = scale_function(&arena);
    assert(cbae_vector_count(&scale->values) == 56 && cbae_vector_count(&scale->blocks) == 12);
    assert(blk_at(scale, 0)->instruction_count == 14 && cbae_vector_count(&blk_at(scale, 11)->predecessors) == 7);
    round_trip(scale);

    uint8_t *blob;
    size_t n;
    assert(cbae_cir_serialize_function(scale, &blob, &n) == CBAE_OK);
    cbae_arena_t a2;
    assert(cbae_arena_init(&a2, 256 * 1024) == CBAE_OK);
    cbae_cir_function_t *back;
    assert(cbae_cir_deserialize_function(blob, n, &a2, &back) == CBAE_OK);
    free(blob);
    cbae_cir_block_t *big = blk_at(back, 0);
    assert(big->instruction_count == 14 && big->instruction_capacity >= 14);
    cbae_cir_value_t *k = val_at(back, 1);
    cbae_cir_builder_init(&b, back, big);
    for (uint32_t i = 0; i < 40; i++) assert(cbae_cir_binop(&b, CIR_OP_ADD, k, k, cir_type_i(64), 0x500000ull + i));
    assert(big->instruction_count == 54 && big->instruction_capacity >= 54);
    for (uint32_t i = 0; i < 54; i++) assert(big->instructions[i]->id == (i < 14 ? i : i + 1));   /* the call took id 14: the new ones go on from 15 */
    cbae_cir_function_destroy(back);
    cbae_arena_destroy(&a2);
    cbae_cir_function_destroy(scale);
    cbae_arena_destroy(&arena);
    PASS("limits met exactly: the shortest blobs for 16 parameters, 4 blocks, 8 instructions and both together; the registers at the ends of the range; "
         "12 blocks, 56 values, a block of 14 instructions and one with 7 predecessors round trip and are built on");
}

/* ── counts are not trusted ───────────────────────────────────────────── */

/* A blob declares one more of something than the bytes that remain could hold. It is refused as malformed, and nothing of the size of
 * the count was asked of the heap (@p heap_limit) or of the arena (which is given so little that a request for the count would run
 * it out, and the error would be CBAE_ERR_OOM instead of CBAE_ERR_PARSE). */
static void refused_cheaply(const mfunc_t *m, const char *what, size_t arena_bytes, size_t heap_limit) {
    blob_t b = write_model(m);
    cbae_cir_function_t *f;
    cbae_error_clear();
    const cbae_err_t rc = deserialize_blob_in(&b, arena_bytes, &f);
    const size_t asked = ai_max_request();
    if (rc != CBAE_ERR_PARSE || f != NULL || asked >= heap_limit)
        fprintf(stderr, "%s: returned %d (expected %d), function %p, the largest request was %zu bytes (limit %zu)\n",
                what, (int)rc, (int)CBAE_ERR_PARSE, (void *)f, asked, heap_limit);
    assert(rc == CBAE_ERR_PARSE && f == NULL);
    assert(asked < heap_limit);
    free(b.p);
}

static void test_counts_are_not_trusted(void) {
    mfunc_t m = blank_model();
    m.trailing = 7000; m.nvals_decl = 7000 / 7 + 1;
    refused_cheaply(&m, "1001 values with 7000 bytes after the header", 1 << 16, 1024);

    m = blank_model();
    m.trailing = 2400; m.nblocks_decl = 2400 / 24 + 1;
    refused_cheaply(&m, "101 blocks with 2400 bytes after the header", 1 << 16, 1024);

    mfunc_t one = blank_model();                                     /* one block with nothing in it */
    one.nblocks = one.nblocks_decl = 1;
    one.blocks[0].id = 0; one.blocks[0].addr = 0x2000ull;

    m = one; m.trailing = 8000; m.blocks[0].preds.decl = (8 + 8000) / 4 + 1;        /* 8000 bytes, and the 8 of the two counts that follow */
    refused_cheaply(&m, "2003 predecessors with 8008 bytes after their count", 1 << 16, 1024);

    m = one; m.trailing = 32 * 1000; m.blocks[0].ninsn_decl = 1001;
    refused_cheaply(&m, "1001 instructions with 32000 bytes after the block headers", 1 << 16, 1024);

    /* The sum over the blocks lets this through: the first block's instruction takes 36 bytes, 4 more than the least, so that when the
     * second block's turn comes there is room for one instruction fewer than the sum had counted on. The arena is the resource. */
    m = blank_model();
    m.nblocks = m.nblocks_decl = 2;
    m.blocks[0].id = 0; m.blocks[0].addr = 0x2000ull; m.blocks[0].ninsn = m.blocks[0].ninsn_decl = 1;
    m.blocks[0].insn[0] = ins(0, CIR_OP_RETURN, NO_VALUE, 1, NO_VALUE, 0, 0);
    m.blocks[1].id = 1; m.blocks[1].addr = 0x2010ull; m.blocks[1].ninsn_decl = 1101;
    m.trailing = 28 + 32 * 1100;
    refused_cheaply(&m, "1101 instructions in the second block with 35228 bytes left once the first block's is read", 8192, 16384);

    m = one;
    m.blocks[0].ninsn = m.blocks[0].ninsn_decl = 1;
    m.blocks[0].insn[0] = ins(0, CIR_OP_PHI, NO_VALUE, 0, 0, 0, 0);
    m.blocks[0].insn[0].nphi_decl = 1201; m.blocks[0].insn[0].nphi = 0;
    m.trailing = 9600;
    refused_cheaply(&m, "1201 incoming values with 9600 bytes after their count", 8192, 1024);
    PASS("counts are not trusted: one more value, block, predecessor, instruction (in all, and in one block) or phi incoming value than the bytes could hold "
         "is refused as malformed with no allocation of the size of the count, from the heap or from the arena");
}

/* ── counts that do not fit the format ────────────────────────────────── */

static void test_counts_that_do_not_fit(void) {
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 256 * 1024) == CBAE_OK);
    cbae_cir_function_t *f = rich_function(&arena, true);
    uint8_t *buf;
    size_t n;

    /* The counts are 32 bits wide. A function with 2**32 values has to be told from its count alone, so the count is faked: nothing
     * reads the table before the count is refused. */
    const size_t nvalues = f->values.count;
    f->values.count = (size_t)UINT32_MAX + 1;
    buf = (uint8_t *)1; n = 99; cbae_error_clear();
    assert(cbae_cir_serialize_function(f, &buf, &n) == CBAE_ERR_OVERFLOW && buf == NULL && n == 0);
    assert(cbae_error_get_context()->message[0] != '\0');
    f->values.count = nvalues;

    const size_t nblocks = f->blocks.count;
    f->blocks.count = (size_t)UINT32_MAX + 1;
    buf = (uint8_t *)1; n = 99; cbae_error_clear();
    assert(cbae_cir_serialize_function(f, &buf, &n) == CBAE_ERR_OVERFLOW && buf == NULL && n == 0);
    assert(cbae_error_get_context()->message[0] != '\0');
    f->blocks.count = nblocks;

    /* Two blocks that claim 2**31 instructions each: 2**32 in all. The sum is taken before any instruction is read. */
    cbae_cir_block_t *b0 = blk_at(f, 0), *b1 = blk_at(f, 1);
    const uint32_t c0 = b0->instruction_count, c1 = b1->instruction_count;
    b0->instruction_count = b1->instruction_count = 0x80000000u;
    buf = (uint8_t *)1; n = 99; cbae_error_clear();
    assert(cbae_cir_serialize_function(f, &buf, &n) == CBAE_ERR_OVERFLOW && buf == NULL && n == 0);
    assert(cbae_error_get_context()->message[0] != '\0');
    b0->instruction_count = c0; b1->instruction_count = c1;

    assert(cbae_cir_serialize_function(f, &buf, &n) == CBAE_OK && buf && n > 0);          /* the function is as it was */
    free(buf);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    PASS("counts that do not fit the format: 2**32 values, 2**32 blocks and 2**32 instructions are refused as CBAE_ERR_OVERFLOW before anything is read");
}

typedef struct { const char *name; void (*run)(void); } group_t;

static const group_t GROUPS[] = {
    { "format", test_the_format }, { "round_trips", test_round_trips }, { "usable", test_deserialized_function_is_usable },
    { "hostile", test_hostile_blobs }, { "arguments", test_arguments }, { "prefixes", test_every_prefix },
    { "refusals", test_refusals }, { "boundaries", test_boundaries }, { "counts", test_counts_are_not_trusted },
    { "overflow", test_counts_that_do_not_fit }, { "oom", test_out_of_memory }, { "fuzz", test_fuzz },
};

/* No argument runs every group; a name runs that group alone (to see each defect on its own). */
int main(int argc, char **argv) {
    printf("=== test_cir_serializer ===\n");
    cbae_log_init(CBAE_LOG_ERROR, NULL, 0);
    for (size_t i = 0; i < sizeof GROUPS / sizeof GROUPS[0]; i++)
        if (argc < 2 || strcmp(argv[1], GROUPS[i].name) == 0) GROUPS[i].run();
    printf("All CIR serializer tests passed.\n");
    return 0;
}
