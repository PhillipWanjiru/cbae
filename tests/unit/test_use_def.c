/**
 * @file test_use_def.c
 * @brief Use-def chains.
 *
 * Three kinds of evidence:
 *
 *   1. HAND-DERIVED use lists on two small functions built with the CIR
 *      builder -- a diamond that ends in a phi, and a loop whose phi takes
 *      a value defined later in the loop body. Every expected use list is
 *      written out below by reading the function, not by running the code.
 *
 *   2. A TWO-WAY CROSS-CHECK that makes no assumptions about what the
 *      functions look like: every operand slot of every instruction must
 *      appear exactly once in the right value's list, and every list entry
 *      must point at a slot that really holds that value. Run on the
 *      hand-built functions and on functions lifted from machine code.
 *
 *   3. REJECTION of corrupt functions (foreign values, duplicate or
 *      out-of-range ids, a NULL phi input, mismatched block ids), and
 *      queries about things the index does not own.
 */
#include "dataflow/use_def.h"
#include "cir/cir_builder.h"
#include "platform/logging.h"
#include "lift_helpers.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ── The two-way cross-check ─────────────────────────────────────────── */

static const cbae_cir_value_t *slot_value(const cbae_cir_instruction_t *insn, uint32_t k) {
    return insn->opcode == CIR_OP_PHI ? insn->phi_incoming_values[k] : insn->operands[k];
}

static uint32_t slot_count(const cbae_cir_instruction_t *insn) {
    return insn->opcode == CIR_OP_PHI ? insn->phi_incoming_count : insn->operand_count;
}

static void check_bijection(const cbae_cir_function_t *f, const cbae_use_def_t *ud) {
    uint32_t slots = 0;
    const uint32_t nb = (uint32_t)cbae_vector_count(&f->blocks);

    /* Forward: every slot is listed exactly once, under the right value. */
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = lh_block(f, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *insn = blk->instructions[i];
            assert(ud->insn_by_id[insn->id] == insn);
            assert(cbae_use_def_block_of(ud, insn) == b);
            assert(cbae_use_def_pos_of(ud, insn) == i);

            const bool is_phi = insn->opcode == CIR_OP_PHI;
            for (uint32_t k = 0; k < slot_count(insn); k++) {
                const cbae_cir_value_t *v = slot_value(insn, k);
                if (!v) continue;
                slots++;
                cbae_use_list_t l = cbae_use_def_uses(ud, v);
                uint32_t hits = 0;
                for (uint32_t u = 0; u < l.count; u++) {
                    if (l.uses[u].insn != insn || l.uses[u].index != k) continue;
                    hits++;
                    assert(l.uses[u].block_id == b);
                    assert(l.uses[u].kind ==
                           (is_phi ? CBAE_USE_PHI_INCOMING : CBAE_USE_OPERAND));
                }
                assert(hits == 1);
            }
        }
    }

    /* Backward: every list entry names a slot that holds that value; each
     * list is in strictly increasing (block, position, index) order. */
    uint32_t listed = 0;
    for (uint32_t id = 0; id < ud->value_count; id++) {
        const cbae_cir_value_t *v = ud->value_by_id[id];
        if (!v) continue;
        cbae_use_list_t l = cbae_use_def_uses(ud, v);
        listed += l.count;
        for (uint32_t u = 0; u < l.count; u++) {
            const cbae_use_t *use = &l.uses[u];
            assert(use->index < slot_count(use->insn));
            assert(slot_value(use->insn, use->index) == v);
            assert(cbae_use_def_block_of(ud, use->insn) == use->block_id);
            if (u == 0) continue;
            const cbae_use_t *prev = &l.uses[u - 1];
            const uint32_t pp = cbae_use_def_pos_of(ud, prev->insn);
            const uint32_t cp = cbae_use_def_pos_of(ud, use->insn);
            const bool increasing =
                prev->block_id < use->block_id ||
                (prev->block_id == use->block_id &&
                 (pp < cp || (pp == cp && prev->index < use->index)));
            assert(increasing);
        }
    }
    assert(listed == slots);
    assert(ud->use_off[ud->value_count] == slots);
}

/* ── Expected-use tables ─────────────────────────────────────────────── */

typedef struct {
    const cbae_cir_instruction_t *insn;
    uint32_t         block_id;     /* block containing insn            */
    uint32_t         index;        /* operand / phi-incoming index     */
    cbae_use_kind_t  kind;
    uint32_t         point_block;  /* where the value must be available */
} exp_use_t;

static void expect_uses(const cbae_use_def_t *ud, const cbae_cir_value_t *v,
                        const exp_use_t *exp, uint32_t n, const char *name) {
    cbae_use_list_t l = cbae_use_def_uses(ud, v);
    if (l.count != n)
        fprintf(stderr, "value %s: expected %u uses, got %u\n", name, n, l.count);
    assert(l.count == n);
    assert(cbae_use_def_use_count(ud, v) == n);
    assert(cbae_use_def_is_dead(ud, v) == (n == 0));
    for (uint32_t i = 0; i < n; i++) {
        const cbae_use_t *u = &l.uses[i];
        if (u->insn != exp[i].insn || u->block_id != exp[i].block_id ||
            u->index != exp[i].index || u->kind != exp[i].kind ||
            cbae_use_point_block(u) != exp[i].point_block)
            fprintf(stderr, "value %s: use #%u differs from the hand-derived table\n",
                    name, i);
        assert(u->insn == exp[i].insn);
        assert(u->block_id == exp[i].block_id);
        assert(u->index == exp[i].index);
        assert(u->kind == exp[i].kind);
        assert(cbae_use_point_block(u) == exp[i].point_block);
    }
}

#define OPD(insn, blk, idx)      { (insn), (blk), (idx), CBAE_USE_OPERAND,      (blk) }
#define PHI(insn, blk, idx, pt)  { (insn), (blk), (idx), CBAE_USE_PHI_INCOMING, (pt)  }

/* ── Function 1: diamond ending in a phi ─────────────────────────────────
 *
 *   block0:  a   = add p, c8
 *            l   = load a
 *            cmp = cmp l, c8
 *            branch cmp, block1, block2
 *   block1:  x    = add l, c8
 *            dead = xor c99, c99         (result never read)
 *            jump block3
 *   block2:  y   = sub l, c8
 *            jump block3
 *   block3:  m = phi [x, block1] [y, block2]
 *            store a, m                   (operand 0 = address, 1 = value)
 *            return m
 *
 *   pz is an unused parameter.
 *
 * Positions: block0 a=0 l=1 cmp=2 branch=3; block1 x=0 dead=1 jump=2;
 * block2 y=0 jump=1; block3 phi=0 store=1 return=2. */
typedef struct {
    cbae_arena_t         arena;
    cbae_cir_function_t *f;
    cbae_cir_block_t    *b0, *b1, *b2, *b3;
    cbae_cir_value_t    *p, *pz, *c8, *c99;
    cbae_cir_value_t    *a, *l, *cmp, *x, *dead, *y, *m;
    cbae_cir_instruction_t *i_a, *i_l, *i_cmp, *i_br, *i_x, *i_dead, *i_j1,
                           *i_y, *i_j2, *i_phi, *i_store, *i_ret;
} diamond_t;

static void build_diamond(diamond_t *d) {
    memset(d, 0, sizeof(*d));
    cbae_arena_init(&d->arena, 64 * 1024);
    assert(cbae_cir_function_create(&d->arena, 0x1000, "diamond", &d->f) == CBAE_OK);
    cbae_cir_function_t *f = d->f;
    assert(cbae_cir_block_create(f, 0x1000, &d->b0) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x1010, &d->b1) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x1020, &d->b2) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x1030, &d->b3) == CBAE_OK);

    const cbae_cir_type_t i64 = cir_type_i(64);
    cbae_cir_builder_t bld;

    cbae_cir_builder_init(&bld, f, d->b0);
    d->p   = cbae_cir_param(&bld, CBAE_REG_RAX);
    d->pz  = cbae_cir_param(&bld, CBAE_REG_RDX);
    d->c8  = cbae_cir_const(&bld, i64, 8);
    d->c99 = cbae_cir_const(&bld, i64, 99);
    d->a   = cbae_cir_binop(&bld, CIR_OP_ADD, d->p, d->c8, i64, 0x1000);
    d->l   = cbae_cir_load(&bld, d->a, i64, 0x1004);
    d->cmp = cbae_cir_binop(&bld, CIR_OP_CMP, d->l, d->c8, cir_type_i1(), 0x1008);
    cbae_cir_branch(&bld, d->cmp, d->b1, d->b2, 0x100C);

    cbae_cir_builder_init(&bld, f, d->b1);
    d->x    = cbae_cir_binop(&bld, CIR_OP_ADD, d->l, d->c8, i64, 0x1010);
    d->dead = cbae_cir_binop(&bld, CIR_OP_XOR, d->c99, d->c99, i64, 0x1014);
    cbae_cir_jump(&bld, d->b3, 0x1018);

    cbae_cir_builder_init(&bld, f, d->b2);
    d->y = cbae_cir_binop(&bld, CIR_OP_SUB, d->l, d->c8, i64, 0x1020);
    cbae_cir_jump(&bld, d->b3, 0x1024);

    /* The phi is created last on purpose: it must still land at position 0. */
    d->m = cbae_cir_phi_create(f, d->b3, i64);
    assert(cbae_cir_phi_add_incoming(f, d->m->u.def_insn, d->x, d->b1->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(f, d->m->u.def_insn, d->y, d->b2->id) == CBAE_OK);
    cbae_cir_builder_init(&bld, f, d->b3);
    cbae_cir_store(&bld, d->a, d->m, 0x1030);
    cbae_cir_return(&bld, d->m, 0x1034);

    d->i_a    = d->a->u.def_insn;
    d->i_l    = d->l->u.def_insn;
    d->i_cmp  = d->cmp->u.def_insn;
    d->i_br   = d->b0->instructions[3];
    d->i_x    = d->x->u.def_insn;
    d->i_dead = d->dead->u.def_insn;
    d->i_j1   = d->b1->instructions[2];
    d->i_y    = d->y->u.def_insn;
    d->i_j2   = d->b2->instructions[1];
    d->i_phi  = d->m->u.def_insn;
    d->i_store = d->b3->instructions[1];
    d->i_ret   = d->b3->instructions[2];

    assert(d->i_br->opcode == CIR_OP_BRANCH && d->i_j1->opcode == CIR_OP_JUMP &&
           d->i_j2->opcode == CIR_OP_JUMP && d->i_store->opcode == CIR_OP_STORE &&
           d->i_ret->opcode == CIR_OP_RETURN && d->b3->instructions[0] == d->i_phi);
}

static void destroy_diamond(diamond_t *d) {
    cbae_cir_function_destroy(d->f);
    cbae_arena_destroy(&d->arena);
}

static void t_diamond_use_lists(void) {
    diamond_t d;
    build_diamond(&d);
    cbae_use_def_t ud;
    assert(cbae_use_def_build(d.f, &ud) == CBAE_OK);

    /* Hand-derived, read straight off the function above. */
    const exp_use_t p_uses[]    = { OPD(d.i_a, 0, 0) };
    const exp_use_t c8_uses[]   = { OPD(d.i_a, 0, 1), OPD(d.i_cmp, 0, 1),
                                    OPD(d.i_x, 1, 1), OPD(d.i_y, 2, 1) };
    const exp_use_t a_uses[]    = { OPD(d.i_l, 0, 0), OPD(d.i_store, 3, 0) };
    const exp_use_t l_uses[]    = { OPD(d.i_cmp, 0, 0), OPD(d.i_x, 1, 0), OPD(d.i_y, 2, 0) };
    const exp_use_t cmp_uses[]  = { OPD(d.i_br, 0, 0) };
    /* A phi reads each incoming value on the EDGE: x is used in block3
     * (where the phi sits) but must be available at the end of block1. */
    const exp_use_t x_uses[]    = { PHI(d.i_phi, 3, 0, 1) };
    const exp_use_t y_uses[]    = { PHI(d.i_phi, 3, 1, 2) };
    const exp_use_t m_uses[]    = { OPD(d.i_store, 3, 1), OPD(d.i_ret, 3, 0) };
    /* One instruction reading the same value twice = two uses. */
    const exp_use_t c99_uses[]  = { OPD(d.i_dead, 1, 0), OPD(d.i_dead, 1, 1) };

    expect_uses(&ud, d.p,    p_uses,   1, "p");
    expect_uses(&ud, d.c8,   c8_uses,  4, "c8");
    expect_uses(&ud, d.a,    a_uses,   2, "a");
    expect_uses(&ud, d.l,    l_uses,   3, "l");
    expect_uses(&ud, d.cmp,  cmp_uses, 1, "cmp");
    expect_uses(&ud, d.x,    x_uses,   1, "x");
    expect_uses(&ud, d.y,    y_uses,   1, "y");
    expect_uses(&ud, d.m,    m_uses,   2, "m");
    expect_uses(&ud, d.c99,  c99_uses, 2, "c99");
    expect_uses(&ud, d.dead, NULL,     0, "dead");
    expect_uses(&ud, d.pz,   NULL,     0, "pz");

    /* 1+4+2+3+1+1+1+2+2 = 17 uses. Counting operand slots independently:
     * block0 2+1+2+1=6, block1 2+2+0=4, block2 2+0=2, block3 phi 2 + store 2
     * + return 1 = 5  ->  17. */
    assert(ud.use_off[ud.value_count] == 17);

    /* Instruction placement. */
    assert(cbae_use_def_block_of(&ud, d.i_a) == 0   && cbae_use_def_pos_of(&ud, d.i_a) == 0);
    assert(cbae_use_def_block_of(&ud, d.i_l) == 0   && cbae_use_def_pos_of(&ud, d.i_l) == 1);
    assert(cbae_use_def_block_of(&ud, d.i_cmp) == 0 && cbae_use_def_pos_of(&ud, d.i_cmp) == 2);
    assert(cbae_use_def_block_of(&ud, d.i_br) == 0  && cbae_use_def_pos_of(&ud, d.i_br) == 3);
    assert(cbae_use_def_block_of(&ud, d.i_x) == 1   && cbae_use_def_pos_of(&ud, d.i_x) == 0);
    assert(cbae_use_def_block_of(&ud, d.i_dead) == 1 && cbae_use_def_pos_of(&ud, d.i_dead) == 1);
    assert(cbae_use_def_block_of(&ud, d.i_j1) == 1  && cbae_use_def_pos_of(&ud, d.i_j1) == 2);
    assert(cbae_use_def_block_of(&ud, d.i_y) == 2   && cbae_use_def_pos_of(&ud, d.i_y) == 0);
    assert(cbae_use_def_block_of(&ud, d.i_j2) == 2  && cbae_use_def_pos_of(&ud, d.i_j2) == 1);
    assert(cbae_use_def_block_of(&ud, d.i_phi) == 3 && cbae_use_def_pos_of(&ud, d.i_phi) == 0);
    assert(cbae_use_def_block_of(&ud, d.i_store) == 3 && cbae_use_def_pos_of(&ud, d.i_store) == 1);
    assert(cbae_use_def_block_of(&ud, d.i_ret) == 3 && cbae_use_def_pos_of(&ud, d.i_ret) == 2);

    /* Where each value becomes available. Parameters and constants belong
     * to no instruction; they are available from the entry block. */
    assert(cbae_use_def_def_block(&ud, d.p)   == 0);
    assert(cbae_use_def_def_block(&ud, d.pz)  == 0);
    assert(cbae_use_def_def_block(&ud, d.c8)  == 0);
    assert(cbae_use_def_def_block(&ud, d.a)   == 0);
    assert(cbae_use_def_def_block(&ud, d.l)   == 0);
    assert(cbae_use_def_def_block(&ud, d.cmp) == 0);
    assert(cbae_use_def_def_block(&ud, d.x)   == 1);
    assert(cbae_use_def_def_block(&ud, d.dead) == 1);
    assert(cbae_use_def_def_block(&ud, d.y)   == 2);
    assert(cbae_use_def_def_block(&ud, d.m)   == 3);

    check_bijection(d.f, &ud);

    cbae_use_def_destroy(&ud);
    destroy_diamond(&d);
    printf("  [PASS] diamond: 11 hand-derived use lists, placement, def blocks, 17 uses total\n");
}

/* ── Function 2: a loop whose phi takes a value defined later ────────────
 *
 *   block0:  c0 = const 0 ; jump block1
 *   block1:  i   = phi [c0, block0] [i2, block2]
 *            cmp = cmp i, cN
 *            branch cmp, block2, block3
 *   block2:  i2 = add i, c1 ; jump block1
 *   block3:  return i
 *
 * The phi (block1) reads i2, which is defined in block2 -- LATER in the
 * function. The use is listed where the phi sits (block1), but must be
 * available at the end of block2, the back-edge predecessor. */
static void t_loop_use_lists(void) {
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64 * 1024);
    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(&arena, 0x3000, "loop", &f) == CBAE_OK);
    cbae_cir_block_t *b0, *b1, *b2, *b3;
    assert(cbae_cir_block_create(f, 0x3000, &b0) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x3010, &b1) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x3020, &b2) == CBAE_OK);
    assert(cbae_cir_block_create(f, 0x3030, &b3) == CBAE_OK);

    const cbae_cir_type_t i64 = cir_type_i(64);
    cbae_cir_builder_t bld;

    cbae_cir_builder_init(&bld, f, b0);
    cbae_cir_value_t *c0 = cbae_cir_const(&bld, i64, 0);
    cbae_cir_value_t *cN = cbae_cir_const(&bld, i64, 10);
    cbae_cir_value_t *c1 = cbae_cir_const(&bld, i64, 1);
    cbae_cir_jump(&bld, b1, 0x3000);

    /* b1's predecessors are recorded in jump-emission order: b0, then b2. */
    cbae_cir_value_t *i = cbae_cir_phi_create(f, b1, i64);
    cbae_cir_builder_init(&bld, f, b1);
    cbae_cir_value_t *cmp = cbae_cir_binop(&bld, CIR_OP_CMP, i, cN, cir_type_i1(), 0x3010);
    cbae_cir_branch(&bld, cmp, b2, b3, 0x3014);

    cbae_cir_builder_init(&bld, f, b2);
    cbae_cir_value_t *i2 = cbae_cir_binop(&bld, CIR_OP_ADD, i, c1, i64, 0x3020);
    cbae_cir_jump(&bld, b1, 0x3024);

    cbae_cir_builder_init(&bld, f, b3);
    cbae_cir_return(&bld, i, 0x3030);

    assert(cbae_cir_phi_add_incoming(f, i->u.def_insn, c0, b0->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(f, i->u.def_insn, i2, b2->id) == CBAE_OK);

    cbae_cir_instruction_t *i_phi = i->u.def_insn;
    cbae_cir_instruction_t *i_cmp = cmp->u.def_insn;
    cbae_cir_instruction_t *i_add = i2->u.def_insn;
    cbae_cir_instruction_t *i_br  = b1->instructions[2];
    cbae_cir_instruction_t *i_ret = b3->instructions[0];
    assert(b1->instructions[0] == i_phi && i_br->opcode == CIR_OP_BRANCH &&
           i_ret->opcode == CIR_OP_RETURN);

    cbae_use_def_t ud;
    assert(cbae_use_def_build(f, &ud) == CBAE_OK);

    /* Program order for i: block1 (cmp), block2 (add), block3 (return). */
    const exp_use_t c0_uses[]  = { PHI(i_phi, 1, 0, 0) };
    const exp_use_t i2_uses[]  = { PHI(i_phi, 1, 1, 2) };
    const exp_use_t i_uses[]   = { OPD(i_cmp, 1, 0), OPD(i_add, 2, 0), OPD(i_ret, 3, 0) };
    const exp_use_t cN_uses[]  = { OPD(i_cmp, 1, 1) };
    const exp_use_t c1_uses[]  = { OPD(i_add, 2, 1) };
    const exp_use_t cmp_uses[] = { OPD(i_br, 1, 0) };

    expect_uses(&ud, c0,  c0_uses,  1, "c0");
    expect_uses(&ud, i2,  i2_uses,  1, "i2");
    expect_uses(&ud, i,   i_uses,   3, "i");
    expect_uses(&ud, cN,  cN_uses,  1, "cN");
    expect_uses(&ud, c1,  c1_uses,  1, "c1");
    expect_uses(&ud, cmp, cmp_uses, 1, "cmp");
    assert(ud.use_off[ud.value_count] == 8);

    /* The phi's use of i2 is a use in block1 of a value defined in block2. */
    assert(cbae_use_def_def_block(&ud, i2) == 2);
    assert(cbae_use_def_block_of(&ud, i_phi) == 1);

    check_bijection(f, &ud);

    cbae_use_def_destroy(&ud);
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);
    printf("  [PASS] loop: back-edge phi use is listed in the header, available at the latch\n");
}

/* ── Lifted functions: the cross-check on real lifter + SSA output ───── */

static void t_lifted_functions(void) {
    /* Same three inputs the Phase 4 SSA tests use: a diamond that merges
     * two constants, a counted loop, and a loop whose header is the
     * function's first instruction (which gets a synthetic entry block). */
    static const uint8_t diamond[] = {
        0x0F,0x84,0x0F,0x00,0x00,0x00,
        0x48,0xB8,0x0A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xE9,0x0A,0x00,0x00,0x00,
        0x48,0xB8,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xC3 };
    static const uint8_t loop[] = {
        0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x48,0x83,0xC0,0x01,
        0x48,0x83,0xF8,0x0A,
        0x0F,0x8C,0xF2,0xFF,0xFF,0xFF,
        0xC3 };
    static const uint8_t entry_loop[] = { 0x48,0xFF,0xC9, 0x75,0xFB, 0xC3 };

    struct { const uint8_t *code; size_t len; cbae_addr_t base; const char *name; } cases[] = {
        { diamond,    sizeof diamond,    0x1000, "diamond"    },
        { loop,       sizeof loop,       0x2000, "loop"       },
        { entry_loop, sizeof entry_loop, 0x2000, "entry_loop" },
    };
    for (size_t c = 0; c < sizeof cases / sizeof cases[0]; c++) {
        lifted_t L;
        lift_x86(&L, cases[c].code, cases[c].len, cases[c].base, cases[c].name);
        cbae_use_def_t ud;
        assert(cbae_use_def_build(L.func, &ud) == CBAE_OK);
        check_bijection(L.func, &ud);
        cbae_use_def_destroy(&ud);
        lifted_destroy(&L);
    }

    /* Hand-derived check on the counted loop (see test_ssa_construction.c):
     *   head:  phi = [const 0 from entry, add from head]
     *          add = phi + 1 ; cmp = add ? 10 ; branch
     *   exit:  return add
     * so  phi.result -> [add operand 0]
     *     add.result -> {phi incoming (back edge, from head itself),
     *                    cmp operand 0, return operand 0}
     *     const 0    -> [phi incoming from the entry block]
     * (add.result's three uses are ordered by block id; see below.)      */
    lifted_t L;
    lift_x86(&L, loop, sizeof loop, 0x2000, "loop");
    cbae_use_def_t ud;
    assert(cbae_use_def_build(L.func, &ud) == CBAE_OK);

    cbae_cir_instruction_t *phi = lh_nth_insn(L.func, CIR_OP_PHI, 0);
    cbae_cir_instruction_t *add = lh_nth_insn(L.func, CIR_OP_ADD, 0);
    cbae_cir_instruction_t *cmp = lh_nth_insn(L.func, CIR_OP_CMP, 0);
    cbae_cir_instruction_t *ret = lh_nth_insn(L.func, CIR_OP_RETURN, 0);
    assert(phi && add && cmp && ret);
    assert(lh_nth_insn(L.func, CIR_OP_PHI, 1) == NULL);   /* exactly one phi */

    const uint32_t head  = cbae_use_def_block_of(&ud, phi);
    const uint32_t entry = 0;
    assert(head != entry);

    const exp_use_t phi_uses[] = { OPD(add, head, 0) };
    expect_uses(&ud, phi->result, phi_uses, 1, "phi.result");

    const uint32_t exit_blk = cbae_use_def_block_of(&ud, ret);
    /* Which incoming index is the back edge depends on predecessor order;
     * find it instead of assuming it. */
    const uint32_t back_idx = (phi->phi_incoming_values[0] == add->result) ? 0u : 1u;
    assert(phi->phi_incoming_values[back_idx] == add->result);
    assert(phi->phi_incoming_blocks[back_idx] == head);   /* the head is its own latch */
    /* Lists are ordered by block ID, and the lifter numbers blocks in its own
     * creation order -- not by address, and not necessarily with the exit
     * after the loop (here the exit is block1 and the loop head block2).
     * So derive the order from the ids rather than assuming it:
     * the phi (position 0) and the cmp (position 2) are both in the head;
     * the return is alone in the exit block. */
    assert(exit_blk != head);
    const exp_use_t add_uses_exit_first[] = { OPD(ret, exit_blk, 0),
                                              PHI(phi, head, back_idx, head),
                                              OPD(cmp, head, 0) };
    const exp_use_t add_uses_head_first[] = { PHI(phi, head, back_idx, head),
                                              OPD(cmp, head, 0),
                                              OPD(ret, exit_blk, 0) };
    expect_uses(&ud, add->result,
                exit_blk < head ? add_uses_exit_first : add_uses_head_first, 3,
                "add.result");

    const uint32_t const_idx = 1u - back_idx;
    const cbae_cir_value_t *zero = phi->phi_incoming_values[const_idx];
    assert(zero->kind == CIR_VAL_CONST && zero->u.const_val == 0);
    const exp_use_t zero_uses[] = { PHI(phi, head, const_idx, entry) };
    expect_uses(&ud, zero, zero_uses, 1, "const 0");

    cbae_use_def_destroy(&ud);
    lifted_destroy(&L);
    printf("  [PASS] lifted: two-way cross-check on 3 functions, counted-loop lists hand-derived\n");
}

/* ── Corrupt functions ───────────────────────────────────────────────── */

static void expect_rejected(const cbae_cir_function_t *f, const char *what) {
    cbae_use_def_t ud;
    memset(&ud, 0xAB, sizeof ud);            /* prove build() initialises `out` */
    cbae_err_t e = cbae_use_def_build(f, &ud);
    if (e != CBAE_ERR_INVALID)
        fprintf(stderr, "corruption not rejected: %s\n", what);
    assert(e == CBAE_ERR_INVALID);
    /* A failed build leaves nothing allocated and nothing dangling. */
    assert(ud.uses == NULL && ud.use_off == NULL && ud.value_by_id == NULL &&
           ud.insn_by_id == NULL && ud.insn_block == NULL && ud.insn_pos == NULL);
    assert(ud.value_count == 0 && ud.insn_count == 0);
    cbae_use_def_destroy(&ud);               /* and destroy of that is a no-op */
}

static void t_rejects_corrupt(void) {
    cbae_use_def_t ud;
    diamond_t d;

    /* NULL arguments. */
    build_diamond(&d);
    assert(cbae_use_def_build(NULL, &ud) == CBAE_ERR_INVALID);
    assert(cbae_use_def_build(d.f, NULL) == CBAE_ERR_INVALID);

    /* The un-corrupted function builds, so each rejection below is caused by
     * its one change and nothing else. */
    assert(cbae_use_def_build(d.f, &ud) == CBAE_OK);
    cbae_use_def_destroy(&ud);

    /* Foreign values -- one whose id collides with a real value of this
     * function, one whose id is out of range. */
    {
        cbae_cir_function_t *g;
        assert(cbae_cir_function_create(&d.arena, 0x9000, "other", &g) == CBAE_OK);
        cbae_cir_block_t *gb;
        assert(cbae_cir_block_create(g, 0x9000, &gb) == CBAE_OK);
        cbae_cir_builder_t gbld;
        cbae_cir_builder_init(&gbld, g, gb);
        cbae_cir_value_t *g_first = cbae_cir_const(&gbld, cir_type_i(64), 7);   /* id 0 */
        cbae_cir_value_t *g_last = g_first;
        for (int k = 0; k < 80; k++) g_last = cbae_cir_const(&gbld, cir_type_i(64), k);
        assert(g_first->id == 0 && g_last->id >= d.f->next_value_id);

        d.i_x->operands[0] = g_first;                        /* x = add l, c8 */
        expect_rejected(d.f, "operand is another function's value (in-range id)");
        d.i_x->operands[0] = g_last;
        expect_rejected(d.f, "operand is another function's value (out-of-range id)");
        d.i_x->operands[0] = d.l;                            /* restore */

        /* The same two foreign values, as queries against a VALID index. */
        assert(cbae_use_def_build(d.f, &ud) == CBAE_OK);
        assert(cbae_use_def_uses(&ud, g_first).count == 0);  /* id 0 is `p` here */
        assert(cbae_use_def_uses(&ud, g_last).count == 0);
        assert(cbae_use_def_def_block(&ud, g_first) == CBAE_USE_DEF_NO_BLOCK);
        assert(cbae_use_def_def_block(&ud, g_last)  == CBAE_USE_DEF_NO_BLOCK);
        assert(cbae_use_def_use_count(&ud, d.p) == 1);       /* and p is untouched */

        /* A foreign instruction with an in-range id (insn id 0 of `other`). */
        cbae_cir_value_t *g_add = cbae_cir_binop(&gbld, CIR_OP_ADD, g_first, g_first,
                                                 cir_type_i(64), 0x9004);
        assert(g_add->u.def_insn->id == 0);
        assert(cbae_use_def_block_of(&ud, g_add->u.def_insn) == CBAE_USE_DEF_NO_BLOCK);
        assert(cbae_use_def_pos_of(&ud, g_add->u.def_insn)   == CBAE_USE_DEF_NO_POS);
        assert(cbae_use_def_block_of(&ud, d.i_a) == 0);      /* ours has id 0 too */
        cbae_use_def_destroy(&ud);
        cbae_cir_function_destroy(g);
    }

    /* A NULL phi input. */
    d.i_phi->phi_incoming_values[1] = NULL;
    expect_rejected(d.f, "NULL phi incoming value");
    d.i_phi->phi_incoming_values[1] = d.y;

    /* Duplicate and out-of-range instruction ids. */
    const uint32_t l_id = d.i_l->id;
    d.i_l->id = d.i_a->id;
    expect_rejected(d.f, "duplicate instruction id");
    d.i_l->id = 9999;
    expect_rejected(d.f, "out-of-range instruction id");
    d.i_l->id = l_id;

    /* Duplicate and out-of-range value ids. */
    const uint32_t lv_id = d.l->id;
    d.l->id = d.a->id;
    expect_rejected(d.f, "duplicate value id");
    d.l->id = 9999;
    expect_rejected(d.f, "out-of-range value id");
    d.l->id = lv_id;

    /* Two values nothing reads, sharing an id. Here no later check can notice
     * (neither is ever looked up), so only the duplicate-id check catches it. */
    const uint32_t pz_id = d.pz->id;
    d.pz->id = d.dead->id;
    expect_rejected(d.f, "duplicate value id between two unused values");
    d.pz->id = pz_id;

    /* A block whose id is not its index. */
    d.b2->id = 7;
    expect_rejected(d.f, "block id != block index");
    d.b2->id = 2;

    /* Everything restored: builds and passes the cross-check again. */
    assert(cbae_use_def_build(d.f, &ud) == CBAE_OK);
    check_bijection(d.f, &ud);
    cbae_use_def_destroy(&ud);

    /* NULL index: queries answer "nothing", never crash. */
    assert(cbae_use_def_uses(NULL, d.p).count == 0);
    assert(cbae_use_def_uses(NULL, NULL).count == 0);
    assert(cbae_use_def_block_of(NULL, d.i_a) == CBAE_USE_DEF_NO_BLOCK);
    assert(cbae_use_def_pos_of(NULL, d.i_a)   == CBAE_USE_DEF_NO_POS);
    assert(cbae_use_def_def_block(NULL, d.p)  == CBAE_USE_DEF_NO_BLOCK);
    cbae_use_def_destroy(NULL);

    destroy_diamond(&d);
    printf("  [PASS] corrupt input: 9 corruptions rejected with nothing left allocated, foreign queries answer \"not found\"\n");
}

/* ── Degenerate functions ────────────────────────────────────────────── */

static void t_degenerate(void) {
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64 * 1024);
    cbae_use_def_t ud;

    /* No blocks, no values. */
    cbae_cir_function_t *f;
    assert(cbae_cir_function_create(&arena, 0x100, "empty", &f) == CBAE_OK);
    assert(cbae_use_def_build(f, &ud) == CBAE_OK);
    assert(ud.value_count == 0 && ud.insn_count == 0 && ud.use_off[0] == 0);
    cbae_use_def_destroy(&ud);
    cbae_use_def_destroy(&ud);                       /* double destroy is safe */
    cbae_cir_function_destroy(f);

    /* Values but no instructions. */
    assert(cbae_cir_function_create(&arena, 0x200, "consts", &f) == CBAE_OK);
    cbae_cir_block_t *b;
    assert(cbae_cir_block_create(f, 0x200, &b) == CBAE_OK);
    cbae_cir_builder_t bld;
    cbae_cir_builder_init(&bld, f, b);
    cbae_cir_value_t *c = cbae_cir_const(&bld, cir_type_i(64), 5);
    cbae_cir_value_t *p = cbae_cir_param(&bld, CBAE_REG_RCX);
    assert(cbae_use_def_build(f, &ud) == CBAE_OK);
    assert(ud.value_count == 2 && ud.insn_count == 0);
    assert(cbae_use_def_is_dead(&ud, c) && cbae_use_def_is_dead(&ud, p));
    check_bijection(f, &ud);
    cbae_use_def_destroy(&ud);

    /* An unresolved register-entry placeholder: it is a value of the
     * function, but nowhere is it "defined". */
    cbae_cir_value_t *ph = CBAE_ARENA_ALLOC(&arena, cbae_cir_value_t);
    assert(ph);
    memset(ph, 0, sizeof *ph);
    ph->kind = CIR_VAL_REG_ENTRY;
    ph->type = cir_type_i(64);
    ph->id   = f->next_value_id++;
    ph->u.reg_entry.reg = CBAE_REG_RAX;
    ph->u.reg_entry.block_id = 0;
    assert(cbae_vector_push(&f->values, &ph) == CBAE_OK);
    assert(cbae_use_def_build(f, &ud) == CBAE_OK);
    assert(cbae_use_def_def_block(&ud, ph) == CBAE_USE_DEF_NO_BLOCK);
    assert(cbae_use_def_is_dead(&ud, ph));
    cbae_use_def_destroy(&ud);
    cbae_cir_function_destroy(f);

    cbae_arena_destroy(&arena);
    printf("  [PASS] degenerate: empty function, no instructions, unresolved placeholder\n");
}

int main(void) {
    printf("Use-def chain tests:\n");
    t_diamond_use_lists();
    t_loop_use_lists();
    t_lifted_functions();
    t_rejects_corrupt();
    t_degenerate();
    printf("All use-def tests passed.\n");
    return 0;
}
