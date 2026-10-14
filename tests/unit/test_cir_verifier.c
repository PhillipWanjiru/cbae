/**
 * @file test_cir_verifier.c
 * @brief The structural verifier, cbae_cir_verify_function(): every rule it
 *        enforces is shown to fire on a function broken in exactly that one
 *        way, and valid functions of every shape are shown to pass.
 *
 * Until now the verifier was exercised only on functions that were meant to
 * pass; a verifier that accepted everything would have passed every test. Each
 * negative test below builds the same small valid function, makes ONE
 * corruption through the data structures directly (the builder would not let
 * a test write most of these), and checks both that the verdict is "invalid"
 * and that the message names the rule that fired.
 *
 *   rule 1  block slots filled, ids equal indices, successor count bounded, the entry has no predecessors
 *   rule 2  value / instruction slots filled, value kinds real, ids unique and in range
 *   rule 3  operand count bounded, slots non-NULL, no placeholder, registered
 *   rule 4  a result belongs to its instruction and is registered
 *   rule 5  phis lead their block, have incomings that match the predecessors and are resolved values
 *   rule 6  branch / jump targets exist
 *   rule 7  edges are recorded on both sides, once
 *   plus    the first violation (in rule order) is the one reported, and the edge and phi rules
 *           agree with a brute-force oracle on thousands of random corruptions
 */
#include "cir/cir_verifier.h"
#include "cir_test_util.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef cbae_cir_value_t *val_t;
typedef cbae_cir_instruction_t *ins_t;

/* ── The function every negative test starts from ─────────────────────────
 *   b0: p = param ; c = cmp p, 0 ; a = p + 1 ; branch c, b1, b2
 *   b1: x1 = a + 2 ; jump b3          b2: x2 = a * 3 ; jump b3
 *   b3: ph = phi [x1, b1] [x2, b2] ; q = param used only by qph ; qph = phi [q, b1] [q, b2]
 *       r = ph + qph ; ret r                                                               */
typedef struct {
    fn_t x;
    cbae_cir_block_t *b1, *b2, *b3;
    val_t p, q, c, a, x1, x2, ph, qph, r;
    ins_t br, jmp1, jmp2, ret;
} base_t;

static void base_build(base_t *B) {
    memset(B, 0, sizeof *B);
    fn_init(&B->x, "base");
    fn_t *x = &B->x;
    B->b1 = fn_block(x, 0x1010); B->b2 = fn_block(x, 0x1020); B->b3 = fn_block(x, 0x1030);
    cbae_cir_builder_t *b = &x->bld;
    B->p = cbae_cir_param(b, CBAE_REG_RBX);
    B->q = cbae_cir_param(b, CBAE_REG_RCX);
    B->c = cbae_cir_binop(b, CIR_OP_CMP, B->p, k_const(b, 0), cir_type_i1(), 0);
    B->a = k_add(b, B->p, k_const(b, 1));
    cbae_cir_branch(b, B->c, B->b1, B->b2, 0);
    B->br = k_last(b);

    fn_at(x, B->b1);
    B->x1 = k_add(&x->bld, B->a, k_const(&x->bld, 2));
    cbae_cir_jump(&x->bld, B->b3, 0);
    B->jmp1 = k_last(&x->bld);

    fn_at(x, B->b2);
    B->x2 = k_mul(&x->bld, B->a, k_const(&x->bld, 3));
    cbae_cir_jump(&x->bld, B->b3, 0);
    B->jmp2 = k_last(&x->bld);

    B->ph  = cbae_cir_phi_create(x->f, B->b3, T64);
    B->qph = cbae_cir_phi_create(x->f, B->b3, T64);
    assert(cbae_cir_phi_add_incoming(x->f, B->ph->u.def_insn, B->x1, B->b1->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x->f, B->ph->u.def_insn, B->x2, B->b2->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x->f, B->qph->u.def_insn, B->q, B->b1->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x->f, B->qph->u.def_insn, B->q, B->b2->id) == CBAE_OK);
    fn_at(x, B->b3);
    B->r = k_add(&x->bld, B->ph, B->qph);
    cbae_cir_return(&x->bld, B->r, 0);
    B->ret = k_last(&x->bld);
}

static void base_done(base_t *B) { fn_done(&B->x); }

static void expect_ok(const cbae_cir_function_t *f, const char *what) {
    const cbae_cir_verify_result_t vr = cbae_cir_verify_function(f);
    if (!vr.ok) fprintf(stderr, "FAIL [%s]: valid function rejected: %s\n", what, vr.message);
    assert(vr.ok);
    assert(vr.message[0] == '\0');
}

/* The corrupted function must be rejected, with a message naming the rule. */
static void expect_bad(const cbae_cir_function_t *f, const char *what, const char *needle) {
    const cbae_cir_verify_result_t vr = cbae_cir_verify_function(f);
    if (vr.ok || !strstr(vr.message, needle))
        fprintf(stderr, "FAIL [%s]: ok=%d message='%s', wanted a rejection mentioning '%s'\n",
                what, (int)vr.ok, vr.message, needle);
    assert(!vr.ok);
    assert(strstr(vr.message, needle) != NULL);
}

#define CASE(name) \
    base_t B; base_build(&B); \
    expect_ok(B.x.f, name " (before)");

#define END(name) \
    base_done(&B); \
    printf("  [PASS] %s\n", name);

/* ── Valid functions ──────────────────────────────────────────────────── */

static void t_valid(void) {
    base_t B; base_build(&B);
    expect_ok(B.x.f, "diamond with phis");
    base_done(&B);

    /* a loop: b0 -> b1 (header, phi) <-> b2 (body) ; b1 -> b3 (exit) */
    fn_t x; fn_init(&x, "loop");
    cbae_cir_block_t *b1 = fn_block(&x, 0x1010), *b2 = fn_block(&x, 0x1020), *b3 = fn_block(&x, 0x1030);
    cbae_cir_builder_t *b = &x.bld;
    val_t p = cbae_cir_param(b, CBAE_REG_RBX);
    cbae_cir_jump(b, b1, 0);
    val_t iv = cbae_cir_phi_create(x.f, b1, T64);
    fn_at(&x, b1);
    val_t c = cbae_cir_binop(&x.bld, CIR_OP_CMP, iv, p, cir_type_i1(), 0);
    cbae_cir_branch(&x.bld, c, b2, b3, 0);
    fn_at(&x, b2);
    val_t next = k_add(&x.bld, iv, k_const(&x.bld, 1));
    cbae_cir_jump(&x.bld, b1, 0);
    assert(cbae_cir_phi_add_incoming(x.f, iv->u.def_insn, k_const(&x.bld, 0), x.b0->id) == CBAE_OK);
    assert(cbae_cir_phi_add_incoming(x.f, iv->u.def_insn, next, b2->id) == CBAE_OK);
    fn_at(&x, b3);
    cbae_cir_return(&x.bld, iv, 0);
    expect_ok(x.f, "loop with a back edge");
    fn_done(&x);

    /* a block the entry cannot reach is structurally fine (and so is a block with no instructions) */
    fn_t y; fn_init(&y, "dead");
    cbae_cir_block_t *dead = fn_block(&y, 0x2000);
    (void)dead;
    cbae_cir_return(&y.bld, NULL, 0);
    expect_ok(y.f, "an empty unreachable block");
    fn_done(&y);

    /* a function with no blocks at all has nothing to violate */
    cbae_arena_t arena; cbae_cir_function_t *f = NULL;
    assert(cbae_arena_init(&arena, 64 * 1024) == CBAE_OK);
    assert(cbae_cir_function_create(&arena, 0x1000, "empty", &f) == CBAE_OK);
    expect_ok(f, "no blocks");
    cbae_cir_function_destroy(f);
    cbae_arena_destroy(&arena);

    const cbae_cir_verify_result_t vr = cbae_cir_verify_function(NULL);
    assert(!vr.ok && strstr(vr.message, "null function"));
    printf("  [PASS] valid functions of every shape pass; a null function is reported\n");
}

/* ── Rule 1: block ids and the entry ──────────────────────────────────── */

static void t_rule1(void) {
    { CASE("block id")
      B.b2->id = 7;
      expect_bad(B.x.f, "block id != index", "ids must equal indices");
      B.b2->id = 2;
      END("rule 1: a block whose id is not its index") }
    { CASE("entry preds")
      assert(cbae_cir_block_add_edge(B.b3, B.x.b0) == CBAE_OK);          /* an edge back into the entry */
      expect_bad(B.x.f, "entry has a predecessor", "the entry must have none");
      END("rule 1: the entry block has a predecessor") }
    { CASE("empty block slot")
      cbae_cir_block_t **slot = cbae_vector_at(&B.x.f->blocks, 2);
      cbae_cir_block_t *keep = *slot;
      *slot = NULL;
      expect_bad(B.x.f, "NULL block slot", "block slot 2 is NULL");
      *slot = keep;
      END("rule 1: an empty block slot") }
    { CASE("successor count")
      B.b1->successor_count = 3;                                         /* the array holds 2 */
      expect_bad(B.x.f, "successor count beyond the array", "block1 has 3 successors (at most 2)");
      B.b1->successor_count = 1;
      END("rule 1: a successor count beyond the successor array") }
    { CASE("block id below its index")
      B.b2->id = 1;                                                      /* another block's id, and LOWER than the index */
      expect_bad(B.x.f, "block id < index", "block at index 2 has id 1 (ids must equal indices)");
      B.b2->id = 2;
      END("rule 1: a block whose id is lower than its index (the check is equality, not 'too big')") }
    { CASE("empty entry slot")
      cbae_cir_block_t **slot = cbae_vector_at(&B.x.f->blocks, 0);
      cbae_cir_block_t *keep = *slot;
      *slot = NULL;                                                      /* the entry check reads block 0: it must not run on this */
      expect_bad(B.x.f, "NULL entry slot", "block slot 0 is NULL");
      *slot = keep;
      END("rule 1: an empty entry slot is reported and the entry check does not read it") }
}

/* ── Rule 2: ids ──────────────────────────────────────────────────────── */

static void t_rule2(void) {
    { CASE("value id range")
      B.a->id = 999;
      expect_bad(B.x.f, "value id out of range", "value id 999 is out of range");
      END("rule 2: a value id beyond the function's counter") }
    { CASE("value id twice")
      B.x1->id = B.a->id;                                               /* two values, one id */
      expect_bad(B.x.f, "value id shared", "registered twice");
      END("rule 2: two values with one id") }
    { CASE("value registered twice")
      cbae_cir_value_t *a = B.a;
      assert(cbae_vector_push(&B.x.f->values, &a) == CBAE_OK);          /* one value, registered twice */
      expect_bad(B.x.f, "value pushed twice", "registered twice");
      END("rule 2: one value registered twice") }
    { CASE("insn id range")
      k_def(B.a)->id = 999;
      expect_bad(B.x.f, "instruction id out of range", "instruction id 999 is out of range");
      END("rule 2: an instruction id beyond the function's counter") }
    { CASE("insn id twice")
      k_def(B.x1)->id = k_def(B.a)->id;
      expect_bad(B.x.f, "instruction id shared", "appears twice");
      END("rule 2: two instructions with one id") }
    { CASE("empty value slot")
      cbae_cir_value_t **slot = cbae_vector_at(&B.x.f->values, 3);
      cbae_cir_value_t *keep = *slot;
      *slot = NULL;
      expect_bad(B.x.f, "NULL value slot", "value slot 3 is NULL");
      *slot = keep;
      END("rule 2: an empty value slot") }
    { CASE("value kind invalid")
      B.p->kind = CIR_VAL_INVALID;                                       /* a value nobody filled in */
      expect_bad(B.x.f, "invalid kind", "has an invalid kind (0)");
      B.p->kind = CIR_VAL_PARAM;
      END("rule 2: a value of kind CIR_VAL_INVALID") }
    { CASE("value kind out of range")
      B.p->kind = (cbae_cir_value_kind_t)99;
      expect_bad(B.x.f, "kind beyond the enum", "has an invalid kind (99)");
      B.p->kind = CIR_VAL_PARAM;
      END("rule 2: a value whose kind is not one of the kinds") }
    { CASE("empty instruction slot")
      ins_t keep = B.b1->instructions[0];
      B.b1->instructions[0] = NULL;
      expect_bad(B.x.f, "NULL instruction slot", "block1: instruction slot 0 is NULL");
      B.b1->instructions[0] = keep;
      END("rule 2: an empty instruction slot") }
    { CASE("value id at the counter")
      B.a->id = B.x.f->next_value_id;                                    /* the first id the function has NOT handed out */
      char want[64];
      snprintf(want, sizeof want, "value id %u is out of range", B.a->id);
      expect_bad(B.x.f, "value id == counter", want);
      END("rule 2: a value id equal to the counter is already out of range") }
    { CASE("insn id at the counter")
      k_def(B.a)->id = B.x.f->next_insn_id;
      char want[64];
      snprintf(want, sizeof want, "instruction id %u is out of range", k_def(B.a)->id);
      expect_bad(B.x.f, "instruction id == counter", want);
      END("rule 2: an instruction id equal to the counter is already out of range") }
}

/* ── Rule 3: operands ─────────────────────────────────────────────────── */

static void t_rule3(void) {
    { CASE("operand count")
      k_def(B.a)->operand_count = 5;                                     /* CIR_MAX_OPERANDS is 4 */
      expect_bad(B.x.f, "too many operands", "at most 4");
      END("rule 3: more operands than an instruction can hold") }
    { CASE("NULL operand")
      k_def(B.a)->operands[1] = NULL;
      expect_bad(B.x.f, "NULL operand", "operand 1 is NULL");
      END("rule 3: a counted operand slot that is empty") }
    { CASE("NULL first operand")
      k_def(B.a)->operands[0] = NULL;
      expect_bad(B.x.f, "NULL first operand", "operand 0 is NULL");
      END("rule 3: the first operand slot empty") }
    { CASE("slot beyond the count")
      k_def(B.a)->operands[3] = NULL;                                    /* beyond operand_count: not counted */
      expect_ok(B.x.f, "an empty slot beyond the count");
      END("rule 3: slots beyond the operand count are not inspected") }
    { CASE("placeholder")
      B.p->kind = CIR_VAL_REG_ENTRY;
      expect_bad(B.x.f, "unresolved placeholder", "unresolved CIR_VAL_REG_ENTRY operand");
      B.p->kind = CIR_VAL_PARAM;
      END("rule 3: an unresolved register-entry placeholder operand") }
    { CASE("foreign operand")
      fn_t y; fn_init(&y, "foreign");
      val_t fv = k_const(&y.bld, 5);
      k_def(B.a)->operands[1] = fv;
      expect_bad(B.x.f, "foreign operand", "never defined");
      fn_done(&y);
      END("rule 3: an operand that belongs to another function") }
    { CASE("same id, other value")
      fn_t y; fn_init(&y, "foreign");
      val_t fv = k_const(&y.bld, 5);
      fv->id = B.a->id;                                                  /* a stranger wearing a local id */
      k_def(B.x1)->operands[0] = fv;
      expect_bad(B.x.f, "foreign operand with a local id", "never defined");
      fn_done(&y);
      END("rule 3: a foreign operand cannot pass by carrying a local value's id") }
    { CASE("id beyond the table")
      fn_t y; fn_init(&y, "foreign");
      val_t fv = k_const(&y.bld, 5);
      fv->id = 5000;                                                     /* a big function's value: past this function's table */
      k_def(B.x1)->operands[0] = fv;
      expect_bad(B.x.f, "foreign operand with a huge id", "never defined");
      k_def(B.x1)->operands[0] = B.a;
      k_def(B.ph)->phi_incoming_values[0] = fv;
      expect_bad(B.x.f, "foreign phi incoming with a huge id", "references an unknown value");
      fn_done(&y);
      END("rule 3: a foreign value with an id past the end of the table is refused, not looked up") }
    /* The same, at the exact edge. A huge id may land in memory that happens to be mapped, so
     * under a memory checker only an id at or just past the end of the table is certain to be
     * caught if the verifier ever indexes the table with it. */
    { CASE("id at the end of the table")
      fn_t y; fn_init(&y, "foreign");
      val_t fv = k_const(&y.bld, 5);
      for (uint32_t extra = 0; extra < 3; extra++) {
          fv->id = B.x.f->next_value_id + extra;                         /* the counter, and the two ids after it */
          k_def(B.x1)->operands[0] = fv;
          expect_bad(B.x.f, "foreign operand at the table's end", "never defined");
          k_def(B.x1)->operands[0] = B.a;
          k_def(B.ph)->phi_incoming_values[0] = fv;
          expect_bad(B.x.f, "foreign phi incoming at the table's end", "references an unknown value");
          k_def(B.ph)->phi_incoming_values[0] = B.x1;
      }
      expect_ok(B.x.f, "put back");
      fn_done(&y);
      END("rule 3: a foreign value whose id is the counter, or just above it, is refused without a lookup") }
    { fn_t y; fn_init(&y, "four operands");                              /* the most the format holds is allowed */
      cbae_cir_builder_t *b = &y.bld;
      val_t args[CIR_MAX_OPERANDS] = { cbae_cir_param(b, CBAE_REG_RDI), cbae_cir_param(b, CBAE_REG_RSI),
                                       k_const(b, 1), k_const(b, 2) };
      val_t r = cbae_cir_call(b, "callee", args, CIR_MAX_OPERANDS, T64, 0);
      assert(r && k_def(r)->operand_count == CIR_MAX_OPERANDS);          /* the test builds what it claims */
      cbae_cir_return(b, r, 0);
      expect_ok(y.f, "an instruction with CIR_MAX_OPERANDS operands");
      fn_done(&y);
      printf("  [PASS] rule 3: exactly CIR_MAX_OPERANDS operands is valid, one more is not\n"); }
}

/* ── Rule 4: results ──────────────────────────────────────────────────── */

static void t_rule4(void) {
    { CASE("result kind")
      B.a->kind = CIR_VAL_PARAM;
      expect_bad(B.x.f, "result of the wrong kind", "not an instruction result defined by it");
      END("rule 4: a result that is not an instruction result") }
    { CASE("result def")
      B.a->u.def_insn = k_def(B.c);                                      /* claims another instruction */
      expect_bad(B.x.f, "result of another instruction", "not an instruction result defined by it");
      END("rule 4: a result whose defining instruction is another one") }
    { CASE("result unregistered")
      fn_t y; fn_init(&y, "foreign");
      val_t fv = k_add(&y.bld, k_const(&y.bld, 1), k_const(&y.bld, 2));
      fv->u.def_insn = k_def(B.a);                                       /* points back, but is not ours */
      k_def(B.a)->result = fv;
      expect_bad(B.x.f, "unregistered result", "not registered in the function");
      k_def(B.a)->result = B.a;
      fn_done(&y);
      END("rule 4: a result the function never registered") }
}

/* ── Rule 5: phis ─────────────────────────────────────────────────────── */

static void t_rule5(void) {
    { CASE("phi count")
      k_def(B.ph)->phi_incoming_count = 1;
      expect_bad(B.x.f, "phi with too few incomings", "1 incoming values but block has 2 predecessors");
      END("rule 5: fewer incomings than predecessors") }
    { CASE("phi count high")
      k_def(B.ph)->phi_incoming_count = 3;                               /* capacity is larger: reads a stale slot */
      expect_bad(B.x.f, "phi with too many incomings", "3 incoming values but block has 2 predecessors");
      END("rule 5: more incomings than predecessors") }
    { CASE("phi pred missing")
      k_def(B.ph)->phi_incoming_blocks[1] = B.b1->id;                    /* [b1, b1]: b2 has no incoming */
      expect_bad(B.x.f, "phi missing a predecessor", "missing an incoming value for predecessor block2");
      END("rule 5: an incoming set that leaves a predecessor out") }
    { CASE("phi unknown value")
      fn_t y; fn_init(&y, "foreign");
      val_t fv = k_const(&y.bld, 5);
      k_def(B.ph)->phi_incoming_values[0] = fv;
      expect_bad(B.x.f, "phi incoming of another function", "phi incoming value at index 0 references an unknown value");
      fn_done(&y);
      END("rule 5: a phi incoming that belongs to another function") }
    { CASE("phi NULL value")
      k_def(B.ph)->phi_incoming_values[1] = NULL;
      expect_bad(B.x.f, "phi NULL incoming", "phi incoming value at index 1 references an unknown value");
      END("rule 5: a phi incoming that is NULL") }
    { CASE("phi placeholder")
      B.q->kind = CIR_VAL_REG_ENTRY;                                     /* q is read only by qph */
      expect_bad(B.x.f, "phi placeholder incoming", "unresolved CIR_VAL_REG_ENTRY placeholder");
      B.q->kind = CIR_VAL_PARAM;
      END("rule 5: a phi incoming that is an unresolved placeholder") }
    { CASE("phi incoming block missing")
      *(uint32_t *)cbae_vector_at(&B.b3->predecessors, 1) = 77;          /* a predecessor that is not a block */
      k_def(B.ph)->phi_incoming_blocks[1] = 77;
      k_def(B.qph)->phi_incoming_blocks[1] = 77;
      expect_bad(B.x.f, "phi incoming from a block that does not exist", "phi incoming block77 does not exist");
      END("rule 5: an incoming block that does not exist") }
    { CASE("phi incoming block at the count")
      const uint32_t nb = (uint32_t)cbae_vector_count(&B.x.f->blocks);   /* ids 0..nb-1 exist */
      *(uint32_t *)cbae_vector_at(&B.b3->predecessors, 1) = nb;
      k_def(B.ph)->phi_incoming_blocks[1] = nb;
      k_def(B.qph)->phi_incoming_blocks[1] = nb;
      char want[64];
      snprintf(want, sizeof want, "phi incoming block%u does not exist", nb);
      expect_bad(B.x.f, "phi incoming from block == count", want);
      END("rule 5: an incoming block numbered exactly one past the last block") }
    { CASE("predecessor that is not a block")
      const uint32_t nb = (uint32_t)cbae_vector_count(&B.x.f->blocks);
      *(uint32_t *)cbae_vector_at(&B.b3->predecessors, 1) = nb;          /* the list names a block that does not exist ... */
      char want[96];                                                     /* ... while every phi incoming block is fine     */
      snprintf(want, sizeof want, "phi missing an incoming value for predecessor block%u", nb);
      expect_bad(B.x.f, "phi block with a predecessor that does not exist", want);
      END("rule 5: a predecessor numbered one past the last block is reported, not used as an index") }
    { CASE("phi after a non-phi")
      ins_t *ins = B.b3->instructions;                                   /* [qph, ph, r, ret] -> [qph, r, ph, ret] */
      assert(ins[0] == k_def(B.qph) && ins[1] == k_def(B.ph) && ins[2] == k_def(B.r));      /* a phi is inserted FIRST */
      ins_t t = ins[1]; ins[1] = ins[2]; ins[2] = t;
      expect_bad(B.x.f, "phi behind an add", "phi after a non-phi instruction (phis must come first)");
      t = ins[1]; ins[1] = ins[2]; ins[2] = t;
      expect_ok(B.x.f, "put back");
      END("rule 5: a phi that follows an ordinary instruction") }
    { CASE("phi without incomings")
      k_def(B.ph)->phi_incoming_count = 0;
      expect_bad(B.x.f, "phi with none", "phi has no incoming values");
      END("rule 5: a phi with no incoming values") }
    { CASE("phi beyond its capacity")
      ins_t d = k_def(B.ph);
      d->phi_incoming_count = d->phi_incoming_capacity + 1;             /* reads past the arrays */
      expect_bad(B.x.f, "phi count above capacity", "room for only");
      END("rule 5: more incomings than the phi has room for") }
    { fn_t y; fn_init(&y, "entry phi");                                  /* the entry has no predecessors, so no incomings */
      val_t ph = cbae_cir_phi_create(y.f, y.b0, T64);
      assert(ph);
      cbae_cir_return(&y.bld, NULL, 0);
      expect_bad(y.f, "phi in the entry block", "phi has no incoming values");
      fn_done(&y);
      printf("  [PASS] rule 5: a phi in the entry block has nothing to choose from\n"); }
}

/* ── Rule 6: branch targets ───────────────────────────────────────────── */

static void t_rule6(void) {
    { CASE("branch true")
      B.br->branch_true_block = 77;
      expect_bad(B.x.f, "branch true target", "true target block77 does not exist");
      END("rule 6: a branch whose true target does not exist") }
    { CASE("branch false")
      B.br->branch_false_block = 77;
      expect_bad(B.x.f, "branch false target", "false target block77 does not exist");
      END("rule 6: a branch whose false target does not exist") }
    { CASE("jump")
      B.jmp1->branch_true_block = 77;
      expect_bad(B.x.f, "jump target", "true target block77 does not exist");
      END("rule 6: a jump whose target does not exist") }
    { CASE("branch target at the count")
      const uint32_t nb = (uint32_t)cbae_vector_count(&B.x.f->blocks);
      B.br->branch_true_block = nb;
      char want[64];
      snprintf(want, sizeof want, "true target block%u does not exist", nb);
      expect_bad(B.x.f, "branch true target == count", want);
      B.br->branch_true_block = B.b1->id;
      B.br->branch_false_block = nb;
      snprintf(want, sizeof want, "false target block%u does not exist", nb);
      expect_bad(B.x.f, "branch false target == count", want);
      END("rule 6: a target numbered exactly one past the last block") }
    { CASE("jump false is unused")
      B.jmp1->branch_false_block = 77;                                   /* a JUMP has no false target */
      expect_ok(B.x.f, "a jump's false target is not looked at");
      END("rule 6: a jump's unused false target is not checked") }
}

/* ── Rule 7: edges ────────────────────────────────────────────────────── */

static void t_rule7(void) {
    { CASE("successor without predecessor")
      B.b1->successors[B.b1->successor_count++] = B.b2->id;              /* b1 -> b2, recorded on one side */
      expect_bad(B.x.f, "one-sided successor", "block1: successor block2 has no matching predecessor entry");
      END("rule 7: a successor edge the target does not record") }
    { CASE("predecessor without successor")
      uint32_t id = B.b3->id;
      assert(cbae_vector_push(&B.b2->predecessors, &id) == CBAE_OK);     /* b2 claims b3 as a predecessor */
      expect_bad(B.x.f, "one-sided predecessor", "block2: predecessor block3 has no matching successor entry");
      END("rule 7: a predecessor edge the source does not record") }
    { CASE("successor missing")
      B.b1->successors[0] = 77;
      expect_bad(B.x.f, "successor to nowhere", "successor block77 does not exist");
      END("rule 7: a successor that is not a block") }
    { CASE("predecessor missing")
      *(uint32_t *)cbae_vector_at(&B.b2->predecessors, 0) = 77;
      expect_bad(B.x.f, "predecessor from nowhere", "predecessor block77 does not exist");
      END("rule 7: a predecessor that is not a block") }
    { CASE("successor and predecessor at the count")
      const uint32_t nb = (uint32_t)cbae_vector_count(&B.x.f->blocks);
      B.b1->successors[0] = nb;
      char want[64];
      snprintf(want, sizeof want, "successor block%u does not exist", nb);
      expect_bad(B.x.f, "successor == count", want);
      B.b1->successors[0] = B.b3->id;
      *(uint32_t *)cbae_vector_at(&B.b2->predecessors, 0) = nb;
      snprintf(want, sizeof want, "predecessor block%u does not exist", nb);
      expect_bad(B.x.f, "predecessor == count", want);
      END("rule 7: a successor or predecessor numbered exactly one past the last block") }
    { CASE("successor twice")
      B.b1->successors[B.b1->successor_count++] = B.b3->id;              /* b1 -> [b3, b3] */
      expect_bad(B.x.f, "repeated successor", "block1: successor block3 listed twice");
      END("rule 7: a successor listed twice") }
    { CASE("predecessor twice")
      uint32_t id = B.x.b0->id;
      assert(cbae_vector_push(&B.b1->predecessors, &id) == CBAE_OK);     /* b1 has no phi: b0 twice is rule 7's */
      expect_bad(B.x.f, "repeated predecessor", "block1: predecessor block0 listed twice");
      END("rule 7: a predecessor listed twice") }
    { CASE("successor edge blamed on the block that lists it")
      B.b2->successors[B.b2->successor_count++] = B.b1->id;              /* b2 -> b1, recorded on b2's side only */
      /* block1's predecessor list is [b0]: b0 is accounted for, b1 itself is missing from it but does not
       * list b1 as a successor, and b2 is the block that does. The message must name b2, not the first
       * block absent from the list. */
      expect_bad(B.x.f, "blame the lister", "block2: successor block1 has no matching predecessor entry");
      END("rule 7: an unrecorded edge is blamed on the block that lists it") }
}

/* ── The first violation is the one reported ──────────────────────────── */

static void t_first_wins(void) {
    CASE("first violation")
    /* three independent corruptions, in rule order: a block id (rule 1), a NULL operand (rule 3),
     * a jump target (rule 6). Only the earliest in rule order may be reported. */
    B.b2->id = 7;
    k_def(B.a)->operands[1] = NULL;
    B.jmp1->branch_true_block = 77;
    expect_bad(B.x.f, "rule 1 first", "ids must equal indices");
    B.b2->id = 2;
    expect_bad(B.x.f, "rule 3 next", "operand 1 is NULL");
    k_def(B.a)->operands[1] = k_const(&B.x.bld, 1);
    expect_bad(B.x.f, "rule 6 last", "true target block77 does not exist");
    /* two violations of one rule, in two instructions: the earlier instruction (block order) is named */
    k_def(B.x2)->operands[0] = NULL;                                     /* in b2 */
    k_def(B.x1)->operands[0] = NULL;                                     /* in b1, which comes first */
    expect_bad(B.x.f, "earlier instruction first", "block1 insn#");
    END("the first violation, in rule and block order, is the one reported")
}

/* ── Random corruptions against a brute-force oracle ─────────────────────
 * The edge rule and the phi rule use scratch marks and a counting argument instead
 * of searching a list for each entry. Whether that is exactly as strict as the plain
 * set statement is checked here: random small graphs whose successor and predecessor
 * lists are then corrupted (entries added, dropped, repeated), against an oracle that
 * says what rule 7 and rule 5 MEAN with a matrix, and nothing else.                  */

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(uint32_t n) {
    rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
    return (uint32_t)((rng_state >> 11) % n);
}

#define MAXN 8

static void t_edges_differential(void) {
    int valid = 0, invalid = 0;
    for (int trial = 0; trial < 30000; trial++) {
        const uint32_t n = 2 + rnd(MAXN - 1);                            /* 2 .. 8 blocks */
        fn_t x; fn_init_sized(&x, "edges", 64 * 1024);
        cbae_cir_block_t *blk[MAXN];
        blk[0] = x.b0;
        for (uint32_t i = 1; i < n; i++) blk[i] = fn_block(&x, 0x1000 + 0x10 * i);

        /* consistent edges first (the builder keeps both sides), none into the entry */
        for (uint32_t i = 0; i < n; i++)
            for (uint32_t k = rnd(3); k > 0; k--)
                assert(cbae_cir_block_add_edge(blk[i], blk[1 + rnd(n - 1)]) == CBAE_OK);

        /* then up to three corruptions of the raw lists */
        for (uint32_t c = rnd(4); c > 0; c--) {
            const uint32_t i = rnd(n), j = 1 + rnd(n - 1);
            switch (rnd(5)) {
                case 0: { uint32_t id = i; assert(cbae_vector_push(&blk[j]->predecessors, &id) == CBAE_OK); break; }
                case 1: if (cbae_vector_count(&blk[j]->predecessors) > 0) {
                            const uint32_t last = (uint32_t)cbae_vector_count(&blk[j]->predecessors) - 1;
                            const uint32_t at = rnd(last + 1);
                            uint32_t *v = cbae_vector_at(&blk[j]->predecessors, at);
                            *v = *(uint32_t *)cbae_vector_at(&blk[j]->predecessors, last);
                            cbae_vector_pop(&blk[j]->predecessors, NULL);
                        } break;
                case 2: if (blk[i]->successor_count < CIR_BLOCK_MAX_SUCCESSORS)
                            blk[i]->successors[blk[i]->successor_count++] = j;
                        break;
                case 3: if (blk[i]->successor_count == 1 && blk[i]->successors[0] != 0)
                            blk[i]->successors[blk[i]->successor_count++] = blk[i]->successors[0];
                        break;
                default: if (blk[i]->successor_count > 0) blk[i]->successor_count--; break;
            }
        }

        /* the oracle: both lists repeat nothing, and name the same edges */
        bool se[MAXN][MAXN] = {{false}}, pe[MAXN][MAXN] = {{false}};
        bool ok = true;
        for (uint32_t i = 0; i < n; i++) {
            for (uint32_t k = 0; k < blk[i]->successor_count; k++) {
                const uint32_t t = blk[i]->successors[k];
                if (se[i][t]) ok = false;
                se[i][t] = true;
            }
            const uint32_t np = (uint32_t)cbae_vector_count(&blk[i]->predecessors);
            for (uint32_t k = 0; k < np; k++) {
                const uint32_t p = *(uint32_t *)cbae_vector_at(&blk[i]->predecessors, k);
                if (pe[p][i]) ok = false;
                pe[p][i] = true;
            }
        }
        for (uint32_t a = 0; a < n; a++)
            for (uint32_t b = 0; b < n; b++)
                if (se[a][b] != pe[a][b]) ok = false;
        const bool entry_has_preds = cbae_vector_count(&blk[0]->predecessors) > 0;
        assert(!entry_has_preds);                  /* the corruptions never touch block 0's list */

        const cbae_cir_verify_result_t vr = cbae_cir_verify_function(x.f);
        if (vr.ok != ok)
            fprintf(stderr, "FAIL [edges trial %d, n=%u]: verifier ok=%d oracle ok=%d, message '%s'\n",
                    trial, n, (int)vr.ok, (int)ok, vr.message);
        assert(vr.ok == ok);
        if (!ok) assert(strstr(vr.message, "successor") || strstr(vr.message, "predecessor"));
        ok ? valid++ : invalid++;
        fn_done(&x);
    }
    assert(valid > 3000 && invalid > 3000);                              /* both verdicts are well exercised */
    printf("  [PASS] edge rule == oracle on 30000 random graphs with corrupted lists (%d valid, %d invalid)\n",
           valid, invalid);
}

static void t_phi_differential(void) {
    int valid = 0, invalid = 0;
    for (int trial = 0; trial < 30000; trial++) {
        const uint32_t n = 2 + rnd(MAXN - 1);
        fn_t x; fn_init_sized(&x, "phis", 64 * 1024);
        cbae_cir_block_t *blk[MAXN];
        blk[0] = x.b0;
        for (uint32_t i = 1; i < n; i++) blk[i] = fn_block(&x, 0x1000 + 0x10 * i);
        for (uint32_t i = 0; i < n; i++)
            for (uint32_t k = rnd(3); k > 0; k--)
                assert(cbae_cir_block_add_edge(blk[i], blk[1 + rnd(n - 1)]) == CBAE_OK);

        /* one to three phis in one block; each gets a random list of incoming blocks */
        const uint32_t t = rnd(n);                                       /* block 0 included: no predecessors */
        const uint32_t npred = (uint32_t)cbae_vector_count(&blk[t]->predecessors);
        bool ok = true;
        for (uint32_t ph = 1 + rnd(3); ph > 0; ph--) {
            val_t p = cbae_cir_phi_create(x.f, blk[t], T64);
            assert(p);
            /* start from the right answer (every predecessor once, shuffled), then corrupt it 0-2 times */
            uint32_t from[16], m = 0;
            for (uint32_t k = 0; k < npred; k++) from[m++] = *(uint32_t *)cbae_vector_at(&blk[t]->predecessors, k);
            for (uint32_t k = m; k > 1; k--) { const uint32_t j = rnd(k), tmp = from[k - 1]; from[k - 1] = from[j]; from[j] = tmp; }
            for (uint32_t c = rnd(3); c > 0; c--) {
                switch (rnd(4)) {
                    case 0:  if (m > 0) m--;                              break;   /* drop one          */
                    case 1:  if (m > 0) { const uint32_t at = rnd(m); from[at] = rnd(n); } break;   /* retarget one */
                    case 2:  if (m < 15) { const uint32_t nb = rnd(n); from[m++] = nb; }   break;   /* add an extra */
                    default: if (m > 0 && m < 15) { const uint32_t dup = from[rnd(m)]; from[m++] = dup; } break; /* repeat one */
                }
            }
            for (uint32_t k = 0; k < m; k++)
                assert(cbae_cir_phi_add_incoming(x.f, p->u.def_insn, k_const(&x.bld, (int64_t)k), from[k]) == CBAE_OK);
            /* the oracle: at least one incoming, one per predecessor, from exactly the predecessors */
            bool this_ok = m >= 1 && m == npred;
            for (uint32_t k = 0; k < npred && this_ok; k++) {
                const uint32_t pr = *(uint32_t *)cbae_vector_at(&blk[t]->predecessors, k);
                bool found = false;
                for (uint32_t q = 0; q < m; q++) found = found || from[q] == pr;
                this_ok = found;
            }
            ok = ok && this_ok;
        }

        const cbae_cir_verify_result_t vr = cbae_cir_verify_function(x.f);
        if (vr.ok != ok)
            fprintf(stderr, "FAIL [phi trial %d, n=%u, block %u with %u preds]: verifier ok=%d oracle ok=%d, '%s'\n",
                    trial, n, t, npred, (int)vr.ok, (int)ok, vr.message);
        assert(vr.ok == ok);
        if (!ok) assert(strstr(vr.message, "phi"));
        ok ? valid++ : invalid++;
        fn_done(&x);
    }
    assert(valid > 2000 && invalid > 3000);
    printf("  [PASS] phi rule == oracle on 30000 random phis with random incoming lists (%d valid, %d invalid)\n",
           valid, invalid);
}

int main(void) {
    t_valid();
    t_rule1();
    t_rule2();
    t_rule3();
    t_rule4();
    t_rule5();
    t_rule6();
    t_rule7();
    t_first_wins();
    t_edges_differential();
    t_phi_differential();
    printf("All CIR verifier tests passed.\n");
    return 0;
}
