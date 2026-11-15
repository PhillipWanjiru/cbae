/**
 * @file test_cir_builder_hostile.c
 * @brief The CIR builder when it is given what it should refuse and when memory runs out.
 *
 * A builder call has three outcomes: it does what was asked; it refuses (CBAE_ERR_INVALID for an argument that cannot be
 * right, CBAE_ERR_OVERFLOW for a counter that would wrap); or it runs out of memory (CBAE_ERR_OOM). In the last two the
 * function must be exactly as it was: no id used up, no value registered that no instruction defines, no edge with one
 * end. The second half of that is the hard one, and it is tested the hard way: a script that builds a function is run
 * once with memory that never runs out, and then again, step by step, with the first allocation of the step failing,
 * then the second, and so on until the step succeeds - and again with the function's arena too small by 0, 8, 16 ...
 * bytes. After every failed step the function is compared with the state before it and checked for consistency; at the
 * end it must be the very function the uninterrupted run built. The function's containers are made to start with room
 * for one element, so that nearly every step has to grow one of them, and the script has a block with a ninth
 * instruction, a block that is full when its phi arrives, a join with six predecessors and a phi with six incoming
 * values, so that every array the builder grows is grown under failure.
 */
#include "alloc_inject.h"
#include "cir/cir_builder.h"
#include "cir/cir_serializer.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS(msg) printf("  [PASS] %s\n", (msg))

/* The first builder returned void from four of its calls. The same test can be built against it, so that what it does
 * wrong is seen as failed assertions: -DCIR_BUILDER_VOID turns the four into calls that report success. */
#ifdef CIR_BUILDER_VOID
static cbae_err_t B_store(cbae_cir_builder_t *b, cbae_cir_value_t *a, cbae_cir_value_t *v, cbae_addr_t s) { cbae_cir_store(b, a, v, s); return CBAE_OK; }
static cbae_err_t B_branch(cbae_cir_builder_t *b, cbae_cir_value_t *c, cbae_cir_block_t *t, cbae_cir_block_t *f, cbae_addr_t s) { cbae_cir_branch(b, c, t, f, s); return CBAE_OK; }
static cbae_err_t B_jump(cbae_cir_builder_t *b, cbae_cir_block_t *t, cbae_addr_t s) { cbae_cir_jump(b, t, s); return CBAE_OK; }
static cbae_err_t B_return(cbae_cir_builder_t *b, cbae_cir_value_t *v, cbae_addr_t s) { cbae_cir_return(b, v, s); return CBAE_OK; }
#else
#define B_store  cbae_cir_store
#define B_branch cbae_cir_branch
#define B_jump   cbae_cir_jump
#define B_return cbae_cir_return
#endif

#define NB   9          /* blocks of the script */
#define MAXB 16         /* blocks a snapshot covers */

/* ── the state of a function, and what must hold of it ────────────────── */

typedef struct {
    size_t   nblocks, nvalues;
    uint32_t next_value, next_insn, next_block;
    uint32_t icount[MAXB], scount[MAXB];
    size_t   pcount[MAXB];
    uint64_t ihash[MAXB], ehash[MAXB];             /* the instruction pointers, and the edges, of each block */
    uint32_t phi_count, phi_cap;
    void    *phi_values, *phi_blocks;
} snap_t;

static cbae_cir_block_t *blk(const cbae_cir_function_t *f, size_t i) { return CBAE_VEC_AT(&f->blocks, cbae_cir_block_t *, i); }
static cbae_cir_value_t *val(const cbae_cir_function_t *f, size_t i) { return CBAE_VEC_AT(&f->values, cbae_cir_value_t *, i); }
static uint64_t mix64(uint64_t h, uint64_t x) { return (h ^ x) * 0x100000001b3ull + 0x9e3779b97f4a7c15ull; }

static snap_t take(const cbae_cir_function_t *f, const cbae_cir_instruction_t *phi) {
    snap_t s;
    memset(&s, 0, sizeof s);
    s.nblocks = cbae_vector_count(&f->blocks);
    s.nvalues = cbae_vector_count(&f->values);
    s.next_value = f->next_value_id; s.next_insn = f->next_insn_id; s.next_block = f->next_block_id;
    for (size_t i = 0; i < s.nblocks && i < MAXB; i++) {
        const cbae_cir_block_t *b = blk(f, i);
        s.icount[i] = b->instruction_count; s.scount[i] = b->successor_count; s.pcount[i] = cbae_vector_count(&b->predecessors);
        uint64_t h = 0, e = 0;
        for (uint32_t k = 0; k < b->instruction_count; k++) h = mix64(h, (uint64_t)(uintptr_t)b->instructions[k]);
        for (uint32_t k = 0; k < b->successor_count; k++) e = mix64(e, b->successors[k]);
        for (size_t k = 0; k < s.pcount[i]; k++) e = mix64(e, *(uint32_t *)cbae_vector_at(&b->predecessors, k) + 0x100000000ull);
        s.ihash[i] = h; s.ehash[i] = e;
    }
    if (phi) { s.phi_count = phi->phi_incoming_count; s.phi_cap = phi->phi_incoming_capacity; s.phi_values = phi->phi_incoming_values; s.phi_blocks = phi->phi_incoming_blocks; }
    return s;
}

static bool same_snap(const snap_t *a, const snap_t *b) {
    return a->nblocks == b->nblocks && a->nvalues == b->nvalues && a->next_value == b->next_value && a->next_insn == b->next_insn
        && a->next_block == b->next_block && memcmp(a->icount, b->icount, sizeof a->icount) == 0 && memcmp(a->scount, b->scount, sizeof a->scount) == 0
        && memcmp(a->pcount, b->pcount, sizeof a->pcount) == 0 && memcmp(a->ihash, b->ihash, sizeof a->ihash) == 0
        && memcmp(a->ehash, b->ehash, sizeof a->ehash) == 0 && a->phi_count == b->phi_count && a->phi_cap == b->phi_cap
        && a->phi_values == b->phi_values && a->phi_blocks == b->phi_blocks;
}

static bool has_edge(const uint32_t *succ, uint32_t n, uint32_t to) {
    for (uint32_t i = 0; i < n; i++) if (succ[i] == to) return true;
    return false;
}

/* What every function the builder has touched must satisfy, finished or not: ids are the indices and are dense, every
 * value is the result of an instruction that is in a block (or is not an instruction result), every result is
 * registered, every operand and phi value is a value of the function, and an edge has both its ends. */
static void check_consistent(const cbae_cir_function_t *f) {
    const size_t nb = cbae_vector_count(&f->blocks), nv = cbae_vector_count(&f->values);
    assert(f->next_block_id == nb && f->next_value_id == nv);
    uint32_t ninsn = 0;
    for (size_t i = 0; i < nb; i++) {
        const cbae_cir_block_t *b = blk(f, i);
        assert(b->id == i && b->instruction_count <= b->instruction_capacity && b->successor_count <= CIR_BLOCK_MAX_SUCCESSORS);
        ninsn += b->instruction_count;
    }
    assert(f->next_insn_id == ninsn);
    uint8_t *seen = calloc(ninsn ? ninsn : 1, 1);
    assert(seen);
    for (size_t i = 0; i < nb; i++) {
        const cbae_cir_block_t *b = blk(f, i);
        for (uint32_t k = 0; k < b->instruction_count; k++) {
            const cbae_cir_instruction_t *in = b->instructions[k];
            assert(in && in->id < ninsn && !seen[in->id]);
            seen[in->id] = 1;
            if (in->result) assert(in->result->id < nv && val(f, in->result->id) == in->result && in->result->kind == CIR_VAL_INSN_RESULT && in->result->u.def_insn == in);
            for (uint8_t o = 0; o < in->operand_count; o++) assert(in->operands[o] && in->operands[o]->id < nv && val(f, in->operands[o]->id) == in->operands[o]);
            assert(in->phi_incoming_count <= in->phi_incoming_capacity);
            if (in->phi_incoming_count) assert(in->phi_incoming_values && in->phi_incoming_blocks);
            for (uint32_t p = 0; p < in->phi_incoming_count; p++) {
                assert(in->phi_incoming_values[p]->id < nv && val(f, in->phi_incoming_values[p]->id) == in->phi_incoming_values[p]);
                assert(in->phi_incoming_blocks[p] < nb);
            }
        }
        for (uint32_t k = 0; k < b->successor_count; k++) {
            assert(b->successors[k] < nb);
            const cbae_cir_block_t *to = blk(f, b->successors[k]);
            size_t found = 0;
            for (size_t p = 0; p < cbae_vector_count(&to->predecessors); p++) found += *(uint32_t *)cbae_vector_at(&to->predecessors, p) == b->id;
            assert(found == 1);
        }
        for (size_t p = 0; p < cbae_vector_count(&b->predecessors); p++) {
            const uint32_t from = *(uint32_t *)cbae_vector_at(&b->predecessors, p);
            assert(from < nb && has_edge(blk(f, from)->successors, blk(f, from)->successor_count, b->id));
        }
    }
    for (size_t i = 0; i < nv; i++) {
        const cbae_cir_value_t *v = val(f, i);
        assert(v->id == i);
        if (v->kind == CIR_VAL_INSN_RESULT) assert(v->u.def_insn && v->u.def_insn->id < ninsn && seen[v->u.def_insn->id] && v->u.def_insn->result == v);
    }
    free(seen);
}

/* ── the script ───────────────────────────────────────────────────────── */

typedef struct {
    cbae_cir_block_t       *b[NB];
    cbae_cir_value_t       *rax, *rcx, *c42, *cmin, *cptr, *c1, *ld, *sum, *mix, *cmp, *call, *x, *phi;
    cbae_cir_instruction_t *phi_insn;
} handles_t;

typedef struct {
    cbae_arena_t         arena;
    cbae_cir_function_t *f;
    handles_t            h;
    cbae_cir_builder_t   bld;
} world_t;

static void world_init(world_t *w, size_t arena_bytes) {
    memset(w, 0, sizeof *w);
    assert(cbae_arena_init(&w->arena, arena_bytes) == CBAE_OK);
    assert(cbae_cir_function_create(&w->arena, 0x1000, "script", &w->f) == CBAE_OK);
    /* The containers start with room for 8 blocks, 16 addresses and 32 values; here they start with room for one. */
    cbae_vector_destroy(&w->f->blocks);
    assert(cbae_vector_init(&w->f->blocks, sizeof(cbae_cir_block_t *), 1) == CBAE_OK);
    cbae_vector_destroy(&w->f->values);
    assert(cbae_vector_init(&w->f->values, sizeof(cbae_cir_value_t *), 1) == CBAE_OK);
    cbae_hashmap_destroy(&w->f->addr_to_block);
    assert(cbae_hashmap_init(&w->f->addr_to_block, 1) == CBAE_OK);
}

static void world_destroy(world_t *w) {
    cbae_cir_function_destroy(w->f);
    cbae_arena_destroy(&w->arena);
}

/* What an operation that returns a pointer reports: the pointer, and the reason in the error context. */
static cbae_err_t by_ptr(const void *p) {
    if (p) return CBAE_OK;
    const cbae_err_t code = cbae_error_get_context()->code;
    assert(code != CBAE_OK && cbae_error_get_context()->message[0] != '\0');     /* a failure says why */
    return code;
}

#define VALUE_OP(name, field, call) \
    static cbae_err_t name(world_t *w) { cbae_cir_value_t *v = (call); const cbae_err_t e = by_ptr(v); if (!e) w->h.field = v; return e; }
#define BLOCK_OP(i) \
    static cbae_err_t op_block##i(world_t *w) { return cbae_cir_block_create(w->f, 0x1000u + 0x20u * (i), &w->h.b[i]); } \
    static cbae_err_t op_at_b##i(world_t *w) { cbae_cir_builder_init(&w->bld, w->f, w->h.b[i]); return CBAE_OK; }
BLOCK_OP(0) BLOCK_OP(1) BLOCK_OP(2) BLOCK_OP(3) BLOCK_OP(4) BLOCK_OP(5) BLOCK_OP(6) BLOCK_OP(7) BLOCK_OP(8)

VALUE_OP(op_rax,  rax,  cbae_cir_param(&w->bld, CBAE_REG_RAX))
VALUE_OP(op_rcx,  rcx,  cbae_cir_param(&w->bld, CBAE_REG_RCX))
VALUE_OP(op_c42,  c42,  cbae_cir_const(&w->bld, cir_type_i(64), 42))
VALUE_OP(op_cmin, cmin, cbae_cir_const(&w->bld, cir_type_i(64), INT64_MIN))
VALUE_OP(op_cptr, cptr, cbae_cir_const(&w->bld, cir_type_ptr(), 0x7000))
VALUE_OP(op_c1,   c1,   cbae_cir_const(&w->bld, cir_type_i1(), 1))
VALUE_OP(op_ld,   ld,   cbae_cir_load(&w->bld, w->h.cptr, cir_type_i(32), 0x1004))
VALUE_OP(op_sum,  sum,  cbae_cir_binop(&w->bld, CIR_OP_ADD, w->h.rax, w->h.c42, cir_type_i(64), 0x1008))
VALUE_OP(op_cmp,  cmp,  cbae_cir_binop(&w->bld, CIR_OP_CMP, w->h.mix, w->h.cmin, cir_type_i1(), 0x1010))
VALUE_OP(op_x,    x,    cbae_cir_binop(&w->bld, CIR_OP_XOR, w->h.rax, w->h.c42, cir_type_i(64), 0x1040))
VALUE_OP(op_call, call, cbae_cir_call(&w->bld, "ExAllocatePoolWithTag", (cbae_cir_value_t *[]){ w->h.sum, w->h.rcx }, 2, cir_type_i(64), 0x1020))
VALUE_OP(op_mix,  mix,  cbae_cir_emit(&w->bld, CIR_OP_DMA_MAP, cir_type_i(64), 0x100C, (cbae_cir_value_t *[]){ w->h.sum, w->h.rcx, w->h.ld, w->h.c1 }, 4))

static cbae_err_t op_pad(world_t *w) { return by_ptr(cbae_cir_binop(&w->bld, CIR_OP_ADD, w->h.rax, w->h.c42, cir_type_i(64), 0x1100)); }
static cbae_err_t op_branch12(world_t *w) { return B_branch(&w->bld, w->h.cmp, w->h.b[1], w->h.b[2], 0x1014); }
static cbae_err_t op_store(world_t *w) { return B_store(&w->bld, w->h.cptr, w->h.call, 0x1024); }
static cbae_err_t op_jump3(world_t *w) { return B_jump(&w->bld, w->h.b[3], 0x1028); }
static cbae_err_t op_phi(world_t *w) {
    cbae_cir_value_t *v = cbae_cir_phi_create(w->f, w->h.b[3], cir_type_i(64));
    const cbae_err_t e = by_ptr(v);
    if (!e) { w->h.phi = v; w->h.phi_insn = v->u.def_insn; }
    return e;
}
static cbae_err_t op_phi8(world_t *w) { return by_ptr(cbae_cir_phi_create(w->f, w->h.b[8], cir_type_i(32))); }
static cbae_err_t op_in1(world_t *w) { return cbae_cir_phi_add_incoming(w->f, w->h.phi_insn, w->h.call, 1); }
static cbae_err_t op_in2(world_t *w) { return cbae_cir_phi_add_incoming(w->f, w->h.phi_insn, w->h.x, 2); }
static cbae_err_t op_in3(world_t *w) { return cbae_cir_phi_add_incoming(w->f, w->h.phi_insn, w->h.c42, 4); }
static cbae_err_t op_in4(world_t *w) { return cbae_cir_phi_add_incoming(w->f, w->h.phi_insn, w->h.rax, 5); }     /* the fourth fills the first arrays ... */
static cbae_err_t op_in5(world_t *w) { return cbae_cir_phi_add_incoming(w->f, w->h.phi_insn, w->h.rcx, 6); }     /* ... the fifth and sixth make them grow */
static cbae_err_t op_in6(world_t *w) { return cbae_cir_phi_add_incoming(w->f, w->h.phi_insn, w->h.cmin, 7); }
static cbae_err_t op_return(world_t *w) { return B_return(&w->bld, w->h.phi, 0x1064); }
static cbae_err_t op_edge30(world_t *w) { return cbae_cir_block_add_edge(w->h.b[3], w->h.b[0]); }
static cbae_err_t op_edge30_again(world_t *w) { return cbae_cir_block_add_edge(w->h.b[3], w->h.b[0]); }

typedef struct { const char *name; cbae_err_t (*run)(world_t *); } step_t;

#define STEP(fn) { #fn, fn }
static const step_t SCRIPT[] = {
    STEP(op_block0), STEP(op_block1), STEP(op_block2), STEP(op_block3), STEP(op_block4), STEP(op_block5), STEP(op_block6), STEP(op_block7), STEP(op_block8),
    STEP(op_at_b0),
    STEP(op_rax), STEP(op_rcx), STEP(op_c42), STEP(op_cmin), STEP(op_cptr), STEP(op_c1),
    STEP(op_ld), STEP(op_sum), STEP(op_mix), STEP(op_cmp),
    STEP(op_pad), STEP(op_pad), STEP(op_pad), STEP(op_pad),                       /* eight instructions: the block is full ... */
    STEP(op_branch12),                                                            /* ... and the ninth grows its array */
    STEP(op_at_b1), STEP(op_call), STEP(op_store), STEP(op_jump3),
    STEP(op_at_b2), STEP(op_x), STEP(op_jump3),
    STEP(op_at_b4), STEP(op_jump3), STEP(op_at_b5), STEP(op_jump3), STEP(op_at_b6), STEP(op_jump3), STEP(op_at_b7), STEP(op_jump3),   /* six predecessors for b3 */
    STEP(op_phi), STEP(op_in1), STEP(op_in2), STEP(op_in3), STEP(op_in4), STEP(op_in5), STEP(op_in6),
    STEP(op_at_b3), STEP(op_return), STEP(op_edge30), STEP(op_edge30_again),
    STEP(op_at_b8),
    STEP(op_pad), STEP(op_pad), STEP(op_pad), STEP(op_pad), STEP(op_pad), STEP(op_pad), STEP(op_pad), STEP(op_pad),
    STEP(op_phi8),                                                                /* the block is full when its phi arrives */
};
#define NSTEPS (sizeof SCRIPT / sizeof SCRIPT[0])

/* Runs the script up to and including its first step @p last. */
static void run_through(world_t *w, cbae_err_t (*last)(world_t *)) {
    for (size_t s = 0; s < NSTEPS; s++) {
        assert(SCRIPT[s].run(w) == CBAE_OK);
        if (SCRIPT[s].run == last) return;
    }
    assert(!"the step is not in the script");
}

typedef enum { FAIL_MALLOC, FAIL_ARENA } failure_t;

/* Runs the script, making each step fail in every way its allocations allow. Returns how many failures were injected. */
static uint64_t run_script(failure_t kind, const uint8_t *want, size_t want_n) {
    world_t w;
    world_init(&w, 1 << 20);
    uint64_t injected = 0;
    for (size_t s = 0; s < NSTEPS; s++) {
        const snap_t before = take(w.f, w.h.phi_insn);
        const handles_t held = w.h;                                  /* a step sets its handle only when it succeeds */
        for (uint64_t j = 1;; j++) {
            cbae_err_t rc;
            bool failed;
            cbae_error_clear();
            if (kind == FAIL_MALLOC) {
                ai_reset();
                ai_fail_at(j);
                rc = SCRIPT[s].run(&w);
                failed = ai_failed() != 0;
                ai_disarm();
            } else {
                const size_t cap = w.arena.capacity;
                w.arena.capacity = w.arena.used + 8 * (j - 1);
                rc = SCRIPT[s].run(&w);
                failed = rc != CBAE_OK;
                w.arena.capacity = cap;
            }
            if (!failed) { assert(rc == CBAE_OK); break; }
            injected++;
            if (rc != CBAE_ERR_OOM)
                fprintf(stderr, "step %s: failure number %llu was answered with %d, not CBAE_ERR_OOM\n", SCRIPT[s].name, (unsigned long long)j, (int)rc);
            assert(rc == CBAE_ERR_OOM);
            const snap_t after = take(w.f, w.h.phi_insn);
            if (!same_snap(&before, &after)) fprintf(stderr, "step %s: failure number %llu changed the function\n", SCRIPT[s].name, (unsigned long long)j);
            assert(same_snap(&before, &after));                       /* a failed step changed nothing ... */
            check_consistent(w.f);                                    /* ... and left a function that holds together */
            assert(memcmp(&w.h, &held, sizeof w.h) == 0);             /* nor did it hand out a pointer */
            assert(j < 400);
        }
        check_consistent(w.f);
    }
    uint8_t *got = NULL;
    size_t got_n = 0;
    assert(cbae_cir_serialize_function(w.f, &got, &got_n) == CBAE_OK);
    assert(got_n == want_n && memcmp(got, want, want_n) == 0);        /* the interrupted build is the uninterrupted one */
    free(got);
    world_destroy(&w);
    return injected;
}

static void test_script_under_failure(void) {
    world_t ref;
    world_init(&ref, 1 << 20);
    uint64_t allocations = 0;                                          /* what the uninterrupted build asks of malloc: each is to be failed once */
    for (size_t s = 0; s < NSTEPS; s++) {
        ai_reset();
        assert(SCRIPT[s].run(&ref) == CBAE_OK);
        allocations += ai_count();
    }
    ai_reset();
    check_consistent(ref.f);
    uint8_t *want = NULL;
    size_t want_n = 0;
    assert(cbae_cir_serialize_function(ref.f, &want, &want_n) == CBAE_OK);
    assert(cbae_vector_count(&ref.f->blocks) == NB && ref.f->next_insn_id == 29 && ref.f->next_value_id == 26);
    assert(ref.h.phi_insn->phi_incoming_count == 6 && ref.h.phi_insn->phi_incoming_capacity >= 6);
    assert(ref.h.b[0]->instruction_count == 9 && ref.h.b[8]->instruction_count == 9 && cbae_vector_count(&ref.h.b[3]->predecessors) == 6);
    assert(ref.h.b[3]->instructions[0] == ref.h.phi_insn && ref.h.b[3]->instructions[1]->opcode == CIR_OP_RETURN);      /* a phi goes first */
    assert(ref.h.b[8]->instructions[0]->opcode == CIR_OP_PHI && ref.h.b[8]->instructions[1]->opcode == CIR_OP_ADD);

    const uint64_t m = run_script(FAIL_MALLOC, want, want_n);
    const uint64_t a = run_script(FAIL_ARENA, want, want_n);
    assert(allocations >= 15 && m == allocations);                    /* every allocation of the build was failed, once, and reported */
    assert(a > 400);
    char msg[320];
    snprintf(msg, sizeof msg, "a %zu-step build with each step failing at each of its allocations (%llu failures) and with the arena short by 0, 8, 16 ... bytes (%llu): a failed step changes nothing, leaves a consistent function and hands out nothing; the end result is the uninterrupted build",
             NSTEPS, (unsigned long long)m, (unsigned long long)a);
    PASS(msg);
    free(want);
    world_destroy(&ref);
}

/* ── refusals ─────────────────────────────────────────────────────────── */

static void expect_code(cbae_err_t rc, cbae_err_t want) {
    assert(rc == want);
    assert(cbae_error_get_context()->code == want && cbae_error_get_context()->message[0] != '\0');
}

#define REFUSED_PTR_AS(expr, want) do { cbae_error_clear(); assert((expr) == NULL); expect_code(cbae_error_get_context()->code, (want)); } while (0)
#define REFUSED_ERR_AS(expr, want) do { cbae_error_clear(); expect_code((expr), (want)); } while (0)
#define REFUSED_PTR(expr) REFUSED_PTR_AS(expr, CBAE_ERR_INVALID)
#define REFUSED_ERR(expr) REFUSED_ERR_AS(expr, CBAE_ERR_INVALID)

static void test_refusals(void) {
    world_t w, other;
    world_init(&w, 1 << 20);
    world_init(&other, 1 << 20);
    run_through(&w, op_cmp);                                          /* blocks, values and instructions; the builder is in block 0 */
    run_through(&other, op_c42);
    cbae_cir_builder_t *b = &w.bld;
    const snap_t before = take(w.f, NULL);

    cbae_cir_value_t *five[5] = { w.h.rax, w.h.rcx, w.h.c42, w.h.cmin, w.h.c1 };
    cbae_cir_value_t *holey[2] = { w.h.rax, NULL };
    cbae_cir_value_t *two[2] = { w.h.rax, w.h.rcx };
    cbae_cir_value_t *foreign[2] = { w.h.rax, other.h.c42 };

    REFUSED_PTR(cbae_cir_emit(b, CIR_OP_ADD, cir_type_i(64), 0, five, 5));                /* the instruction holds 4 operands: no silent cut to 4 */
    REFUSED_PTR(cbae_cir_emit(b, CIR_OP_ADD, cir_type_i(64), 0, NULL, 1));
    REFUSED_PTR(cbae_cir_emit(b, CIR_OP_ADD, cir_type_i(64), 0, holey, 2));
    REFUSED_PTR(cbae_cir_emit(b, CIR_OP_ADD, cir_type_i(64), 0, foreign, 2));             /* an operand that is another function's */
    REFUSED_PTR(cbae_cir_emit(b, CIR_OP_INVALID, cir_type_i(64), 0, two, 2));
    REFUSED_PTR(cbae_cir_emit(b, CIR_OP_COUNT, cir_type_i(64), 0, two, 2));
    REFUSED_PTR(cbae_cir_emit(b, (cbae_cir_opcode_t)255, cir_type_i(64), 0, two, 2));
    cbae_cir_type_t bad_type = cir_type_i(64);
    bad_type.kind = (cbae_cir_type_kind_t)40;
    REFUSED_PTR(cbae_cir_emit(b, CIR_OP_ADD, bad_type, 0, two, 2));
    REFUSED_PTR(cbae_cir_const(b, bad_type, 1));
    REFUSED_PTR(cbae_cir_const(b, cir_type_void(), 1));                                   /* a constant has a width */
    REFUSED_PTR(cbae_cir_param(b, (cbae_reg_t)(CBAE_REG_OTHER + 1)));
    REFUSED_PTR(cbae_cir_param(b, (cbae_reg_t)200));
    REFUSED_PTR(cbae_cir_load(b, NULL, cir_type_i(32), 0));
    REFUSED_PTR(cbae_cir_load(b, w.h.cptr, cir_type_void(), 0));                          /* a load that gives no value */
    REFUSED_PTR(cbae_cir_load(b, other.h.cptr, cir_type_i(32), 0));
    REFUSED_ERR(B_store(b, NULL, w.h.c42, 0));
    REFUSED_ERR(B_store(b, w.h.cptr, NULL, 0));
    REFUSED_ERR(B_store(b, w.h.cptr, other.h.c42, 0));
    REFUSED_PTR(cbae_cir_binop(b, CIR_OP_ADD, NULL, w.h.c42, cir_type_i(64), 0));
    REFUSED_PTR(cbae_cir_binop(b, CIR_OP_ADD, w.h.c42, NULL, cir_type_i(64), 0));
    REFUSED_PTR(cbae_cir_binop(b, CIR_OP_ADD, w.h.c42, w.h.rax, cir_type_void(), 0));      /* a result that does not exist */
    REFUSED_PTR(cbae_cir_call(b, "f", five, 5, cir_type_i(64), 0));                       /* five arguments */
    REFUSED_PTR(cbae_cir_call(b, "f", NULL, 2, cir_type_i(64), 0));
    REFUSED_PTR(cbae_cir_call(b, "f", holey, 2, cir_type_i(64), 0));
    REFUSED_PTR(cbae_cir_call(b, "f", foreign, 2, cir_type_i(64), 0));
    char *long_name = malloc(65537);
    assert(long_name);
    memset(long_name, 'n', 65536); long_name[65536] = '\0';
    REFUSED_PTR(cbae_cir_call(b, long_name, two, 2, cir_type_i(64), 0));                  /* the format holds 65535 */
    free(long_name);
    REFUSED_ERR(B_branch(b, NULL, w.h.b[1], w.h.b[2], 0));
    REFUSED_ERR(B_branch(b, w.h.cmp, NULL, w.h.b[2], 0));
    REFUSED_ERR(B_branch(b, w.h.cmp, w.h.b[1], NULL, 0));
    REFUSED_ERR(B_branch(b, w.h.cmp, other.h.b[1], w.h.b[2], 0));                         /* a block of another function */
    REFUSED_ERR(B_branch(b, other.h.c1, w.h.b[1], w.h.b[2], 0));
    REFUSED_ERR(B_jump(b, NULL, 0));
    REFUSED_ERR(B_jump(b, other.h.b[1], 0));
    REFUSED_ERR(B_return(b, other.h.c42, 0));
    REFUSED_PTR(cbae_cir_phi_create(w.f, NULL, cir_type_i(64)));
    REFUSED_PTR(cbae_cir_phi_create(NULL, w.h.b[3], cir_type_i(64)));
    REFUSED_PTR(cbae_cir_phi_create(w.f, w.h.b[3], cir_type_void()));
    REFUSED_PTR(cbae_cir_phi_create(w.f, w.h.b[3], bad_type));
    REFUSED_PTR(cbae_cir_phi_create(w.f, other.h.b[3], cir_type_i(64)));
    {   /* a value and a block of another function whose ids are exactly the number this function has: one past its end */
        world_t big;
        world_init(&big, 1 << 20);
        for (size_t k = 0; k < NSTEPS; k++) assert(SCRIPT[k].run(&big) == CBAE_OK);
        cbae_cir_value_t *past_ops[2] = { w.h.rax, val(big.f, cbae_vector_count(&w.f->values)) };
        REFUSED_PTR(cbae_cir_emit(b, CIR_OP_ADD, cir_type_i(64), 0, past_ops, 2));
        cbae_cir_block_t *past;
        assert(cbae_cir_block_create(big.f, 0x9999, &past) == CBAE_OK && past->id == cbae_vector_count(&w.f->blocks));
        REFUSED_ERR(B_jump(b, past, 0));
        REFUSED_ERR(B_branch(b, w.h.cmp, past, w.h.b[1], 0));
        REFUSED_PTR(cbae_cir_phi_create(w.f, past, cir_type_i(64)));
        cbae_cir_builder_t at_past;
        cbae_cir_builder_init(&at_past, w.f, past);
        REFUSED_PTR(cbae_cir_binop(&at_past, CIR_OP_ADD, w.h.rax, w.h.rcx, cir_type_i(64), 0));
        world_destroy(&big);
    }
    const snap_t refused = take(w.f, NULL);
    assert(same_snap(&before, &refused));                                                  /* none of that changed anything */

    cbae_cir_value_t *pv = cbae_cir_phi_create(w.f, w.h.b[3], cir_type_i(64));
    assert(pv);
    const snap_t with_phi = take(w.f, pv->u.def_insn);
    REFUSED_ERR(cbae_cir_phi_add_incoming(w.f, NULL, w.h.rax, 0));
    REFUSED_ERR(cbae_cir_phi_add_incoming(w.f, pv->u.def_insn, NULL, 0));
    REFUSED_ERR(cbae_cir_phi_add_incoming(w.f, pv->u.def_insn, other.h.c42, 0));
    REFUSED_ERR(cbae_cir_phi_add_incoming(w.f, pv->u.def_insn, w.h.rax, NB));            /* there are NB blocks: 0 to NB-1 */
    REFUSED_ERR(cbae_cir_phi_add_incoming(w.f, pv->u.def_insn, w.h.rax, 0xFFFFFFFFu));
    REFUSED_ERR(cbae_cir_phi_add_incoming(w.f, w.h.ld->u.def_insn, w.h.rax, 0));          /* an instruction that is not a phi */
    REFUSED_ERR(cbae_cir_phi_add_incoming(NULL, pv->u.def_insn, w.h.rax, 0));
    const snap_t phi_after = take(w.f, pv->u.def_insn);
    assert(same_snap(&with_phi, &phi_after));
    REFUSED_ERR(cbae_cir_block_add_edge(NULL, w.h.b[1]));
    REFUSED_ERR(cbae_cir_block_add_edge(w.h.b[1], NULL));
    cbae_cir_block_t *nb = (cbae_cir_block_t *)1;
    REFUSED_ERR(cbae_cir_block_create(NULL, 0, &nb));
    assert(nb == NULL);                                                                    /* a refusal leaves no pointer behind */
    REFUSED_ERR(cbae_cir_block_create(w.f, 0, NULL));
    cbae_cir_function_t *nf = (cbae_cir_function_t *)1;
    REFUSED_ERR(cbae_cir_function_create(NULL, 0, "x", &nf));
    assert(nf == NULL);
    REFUSED_ERR(cbae_cir_function_create(&w.arena, 0, "x", NULL));

    cbae_cir_builder_t nobody;
    cbae_cir_builder_init(&nobody, NULL, w.h.b[0]);
    REFUSED_PTR(cbae_cir_const(&nobody, cir_type_i(64), 1));
    REFUSED_PTR(cbae_cir_param(&nobody, CBAE_REG_RAX));
    cbae_cir_builder_init(&nobody, w.f, NULL);
    REFUSED_PTR(cbae_cir_binop(&nobody, CIR_OP_ADD, w.h.rax, w.h.rcx, cir_type_i(64), 0));
    REFUSED_ERR(B_jump(&nobody, w.h.b[1], 0));
    cbae_cir_builder_init(&nobody, w.f, other.h.b[0]);                                     /* a block of another function */
    REFUSED_PTR(cbae_cir_binop(&nobody, CIR_OP_ADD, w.h.rax, w.h.rcx, cir_type_i(64), 0));
    REFUSED_PTR(cbae_cir_call(&nobody, "f", two, 2, cir_type_i(64), 0));
    REFUSED_PTR(cbae_cir_const(NULL, cir_type_i(64), 1));
    cbae_cir_builder_init(NULL, w.f, w.h.b[0]);                                            /* accepted, and does nothing */

    check_consistent(w.f);
    check_consistent(other.f);
    world_destroy(&other);
    world_destroy(&w);
    PASS("refusals: NULLs, a fifth operand, an opcode, type or register that does not exist, a void constant or load, a name too long for the format, another function's value or block, a phi edge from a block that does not exist: CBAE_ERR_INVALID with a message, nothing changed");
}

/* The counters stop one short of 0xFFFFFFFF (which means "none" in the serialized form). */
static void test_counters_at_the_limit(void) {
    world_t w;
    world_init(&w, 1 << 20);
    run_through(&w, op_cmp);
    cbae_cir_builder_t *b = &w.bld;
    cbae_cir_value_t *two[2] = { w.h.rax, w.h.rcx };
    const snap_t before = take(w.f, NULL);

    w.f->next_value_id = UINT32_MAX;                                  /* no value can be made ... */
    REFUSED_PTR_AS(cbae_cir_const(b, cir_type_i(64), 1), CBAE_ERR_OVERFLOW);
    REFUSED_PTR_AS(cbae_cir_param(b, CBAE_REG_RDX), CBAE_ERR_OVERFLOW);
    REFUSED_PTR_AS(cbae_cir_binop(b, CIR_OP_ADD, w.h.rax, w.h.rcx, cir_type_i(64), 0), CBAE_ERR_OVERFLOW);
    REFUSED_PTR_AS(cbae_cir_load(b, w.h.cptr, cir_type_i(32), 0), CBAE_ERR_OVERFLOW);
    REFUSED_PTR_AS(cbae_cir_call(b, "f", two, 2, cir_type_i(64), 0), CBAE_ERR_OVERFLOW);
    REFUSED_PTR_AS(cbae_cir_phi_create(w.f, w.h.b[3], cir_type_i(64)), CBAE_ERR_OVERFLOW);
    w.f->next_value_id = before.next_value;
    assert(same_snap(&before, &(snap_t){ .nblocks = 0 }) == false);   /* (the comparison is not vacuous) */
    {   const snap_t after = take(w.f, NULL);
        assert(same_snap(&before, &after)); }

    w.f->next_insn_id = UINT32_MAX;                                   /* ... or an instruction */
    REFUSED_ERR_AS(B_store(b, w.h.cptr, w.h.c42, 0), CBAE_ERR_OVERFLOW);
    REFUSED_ERR_AS(B_jump(b, w.h.b[3], 0), CBAE_ERR_OVERFLOW);
    REFUSED_ERR_AS(B_return(b, NULL, 0), CBAE_ERR_OVERFLOW);
    REFUSED_PTR_AS(cbae_cir_binop(b, CIR_OP_ADD, w.h.rax, w.h.rcx, cir_type_i(64), 0), CBAE_ERR_OVERFLOW);
    REFUSED_PTR_AS(cbae_cir_phi_create(w.f, w.h.b[3], cir_type_i(64)), CBAE_ERR_OVERFLOW);
    assert(cbae_cir_const(b, cir_type_i(64), 5) != NULL);             /* a value is not an instruction */
    w.f->next_insn_id = before.next_insn;
    cbae_vector_pop(&w.f->values, NULL);                              /* take back the constant that was just made ... */
    w.f->next_value_id--;
    {   const snap_t after = take(w.f, NULL);
        assert(same_snap(&before, &after)); }                         /* ... and nothing else changed */

    w.f->next_block_id = UINT32_MAX;                                  /* ... or a block */
    cbae_cir_block_t *nb = (cbae_cir_block_t *)1;
    REFUSED_ERR_AS(cbae_cir_block_create(w.f, 0x9000, &nb), CBAE_ERR_OVERFLOW);
    assert(nb == NULL && cbae_cir_function_block_at(w.f, 0x9000) == NULL);
    w.f->next_block_id = before.next_block;
    {   const snap_t after = take(w.f, NULL);
        assert(same_snap(&before, &after)); }

    check_consistent(w.f);
    world_destroy(&w);
    PASS("a function whose value, instruction or block counter is at its limit refuses what needs the next id (CBAE_ERR_OVERFLOW) and changes nothing; what needs a different counter still works");
}

/* A block has two successors at most. A branch or a jump that would need a third refuses, before it appends or links
 * anything. */
static void test_third_successor(void) {
    world_t w;
    world_init(&w, 1 << 20);
    for (int i = 0; i < 4; i++) assert(cbae_cir_block_create(w.f, 0x1000u + 0x20u * (unsigned)i, &w.h.b[i]) == CBAE_OK);
    assert(op_at_b0(&w) == CBAE_OK && op_c1(&w) == CBAE_OK);
    assert(cbae_cir_block_add_edge(w.h.b[0], w.h.b[1]) == CBAE_OK && cbae_cir_block_add_edge(w.h.b[0], w.h.b[2]) == CBAE_OK);
    assert(cbae_cir_block_add_edge(w.h.b[0], w.h.b[1]) == CBAE_OK);                       /* an edge that is there is not added twice */
    assert(w.h.b[0]->successor_count == 2 && cbae_vector_count(&w.h.b[1]->predecessors) == 1);
    const snap_t before = take(w.f, NULL);
    REFUSED_ERR(cbae_cir_block_add_edge(w.h.b[0], w.h.b[3]));
    REFUSED_ERR(B_jump(&w.bld, w.h.b[3], 0x10));
    REFUSED_ERR(B_branch(&w.bld, w.h.c1, w.h.b[3], w.h.b[1], 0x10));
    REFUSED_ERR(B_branch(&w.bld, w.h.c1, w.h.b[3], w.h.b[3], 0x10));
    REFUSED_ERR(B_branch(&w.bld, w.h.c1, w.h.b[3], w.h.b[2], 0x10));
    const snap_t after = take(w.f, NULL);
    assert(same_snap(&before, &after));                                                   /* no instruction, no edge */
    assert(B_jump(&w.bld, w.h.b[1], 0x20) == CBAE_OK);                                    /* a jump to a successor it has is fine */
    assert(B_branch(&w.bld, w.h.c1, w.h.b[2], w.h.b[1], 0x24) == CBAE_OK);
    assert(w.h.b[0]->successor_count == 2 && cbae_vector_count(&w.h.b[1]->predecessors) == 1 && cbae_vector_count(&w.h.b[2]->predecessors) == 1);
    assert(w.h.b[0]->instruction_count == 2 && w.f->next_insn_id == 2);

    /* both targets the same block is one edge */
    cbae_cir_builder_init(&w.bld, w.f, w.h.b[3]);
    assert(B_branch(&w.bld, w.h.c1, w.h.b[1], w.h.b[1], 0x30) == CBAE_OK);
    assert(w.h.b[3]->successor_count == 1 && cbae_vector_count(&w.h.b[1]->predecessors) == 2);
    assert(w.h.b[3]->instruction_count == 1 && w.h.b[3]->instructions[0]->branch_true_block == 1 && w.h.b[3]->instructions[0]->branch_false_block == 1);

    /* a block that has one successor already: a branch to one new block twice needs one more edge, not two */
    assert(cbae_cir_block_add_edge(w.h.b[2], w.h.b[1]) == CBAE_OK);
    cbae_cir_builder_init(&w.bld, w.f, w.h.b[2]);
    assert(B_branch(&w.bld, w.h.c1, w.h.b[3], w.h.b[3], 0x40) == CBAE_OK);
    assert(w.h.b[2]->successor_count == 2 && w.h.b[2]->successors[0] == 1 && w.h.b[2]->successors[1] == 3 && cbae_vector_count(&w.h.b[3]->predecessors) == 1);
    check_consistent(w.f);
    world_destroy(&w);
    PASS("a block's third successor is refused by add_edge, jump and branch alike, with no instruction and no edge left behind; edges that exist are not added twice; a branch to one block twice is one edge");
}

/* ── what a call keeps ────────────────────────────────────────────────── */

static void test_call_name_is_copied(void) {
    world_t w;
    world_init(&w, 1 << 20);
    for (int i = 0; i < 4; i++) assert(cbae_cir_block_create(w.f, 0x1000u + 0x20u * (unsigned)i, &w.h.b[i]) == CBAE_OK);
    assert(op_at_b0(&w) == CBAE_OK);
    char name[32];
    snprintf(name, sizeof name, "%s", "ExFreePoolWithTag");
    cbae_cir_value_t *c = cbae_cir_call(&w.bld, name, NULL, 0, cir_type_i(64), 0x40);
    assert(c);
    memset(name, 'X', sizeof name - 1);                                                  /* the caller's buffer is reused ... */
    assert(strcmp(c->u.def_insn->call_target_name, "ExFreePoolWithTag") == 0);           /* ... the instruction's name is its own */
    assert(c->u.def_insn->call_target_name != name);

    cbae_cir_value_t *e = cbae_cir_call(&w.bld, "", NULL, 0, cir_type_i(64), 0x44);
    assert(e && e->u.def_insn->call_target_name == NULL);                                /* an empty name is no name */
    cbae_cir_value_t *n = cbae_cir_call(&w.bld, NULL, NULL, 0, cir_type_i(64), 0x48);
    assert(n && n->u.def_insn->call_target_name == NULL);

    char *longest = malloc(65536);
    assert(longest);
    memset(longest, 'L', 65535); longest[65535] = '\0';
    cbae_cir_value_t *l = cbae_cir_call(&w.bld, longest, NULL, 0, cir_type_i(64), 0x4C);
    assert(l && strlen(l->u.def_insn->call_target_name) == 65535);
    free(longest);

    /* names of every length up to 40, with an instruction after each: a name is kept whole with its end (the next
     * allocation must not be able to take the NUL), whatever its length and the arena's alignment */
    cbae_cir_value_t *named[41] = { NULL };
    for (size_t len = 1; len <= 40; len++) {
        char nm[64];
        memset(nm, (int)('a' + len % 26), len);
        nm[len] = '\0';
        named[len] = cbae_cir_call(&w.bld, nm, NULL, 0, cir_type_i(64), 0x100 + len);
        assert(named[len]);
        assert(cbae_cir_call(&w.bld, NULL, NULL, 0, cir_type_i(64), 0x200 + len));
    }
    for (size_t len = 1; len <= 40; len++) {
        const char *got = named[len]->u.def_insn->call_target_name;
        assert(strlen(got) == len && got[0] == (char)('a' + len % 26) && got[len - 1] == (char)('a' + len % 26));
    }
    check_consistent(w.f);
    world_destroy(&w);
    PASS("a call copies its target name (the caller's buffer can be reused), an empty name is no name, 65535 bytes are kept whole");
}

#ifndef CIR_BUILDER_VOID
/* emit_insn is the call that can tell a refusal from an instruction without a result. */
static void test_emit_insn(void) {
    world_t w;
    world_init(&w, 1 << 20);
    run_through(&w, op_c1);
    assert(op_at_b0(&w) == CBAE_OK);
    cbae_cir_value_t *ops[2] = { w.h.cptr, w.h.c42 };

    cbae_cir_instruction_t *in = (cbae_cir_instruction_t *)1;
    assert(cbae_cir_emit_insn(&w.bld, CIR_OP_STORE, cir_type_void(), 0x10, ops, 2, &in) == CBAE_OK);
    assert(in && in->result == NULL && in->opcode == CIR_OP_STORE && in->operand_count == 2);   /* no result, and not a failure */
    cbae_error_clear();
    assert(cbae_cir_emit(&w.bld, CIR_OP_STORE, cir_type_void(), 0x14, ops, 2) == NULL);          /* the wrapper cannot tell: that is why emit_insn is */
    assert(cbae_error_get_context()->code == CBAE_OK);

    in = (cbae_cir_instruction_t *)1;
    assert(cbae_cir_emit_insn(&w.bld, CIR_OP_ADD, cir_type_i(64), 0x18, ops, 2, &in) == CBAE_OK);
    assert(in && in->result && in->result->u.def_insn == in && in->result->type.kind == CIR_TYPE_I64);
    in = (cbae_cir_instruction_t *)1;
    assert(cbae_cir_emit_insn(&w.bld, CIR_OP_INVALID, cir_type_i(64), 0, ops, 2, &in) == CBAE_ERR_INVALID && in == NULL);
    assert(cbae_cir_emit_insn(&w.bld, CIR_OP_ADD, cir_type_i(64), 0, ops, 2, NULL) == CBAE_ERR_INVALID);

    /* instructions made with operand counts the opcode does not take are the verifier's to judge, not the builder's */
    assert(cbae_cir_emit_insn(&w.bld, CIR_OP_ADD, cir_type_i(64), 0, NULL, 0, &in) == CBAE_OK && in->operand_count == 0);
    assert(cbae_cir_emit_insn(&w.bld, CIR_OP_BRANCH, cir_type_void(), 0, NULL, 0, &in) == CBAE_OK && in->result == NULL);
    check_consistent(w.f);
    world_destroy(&w);
    PASS("emit_insn tells a refusal from an instruction that has no result; operand counts that do not fit the opcode are left to the verifier");
}
#endif

/* ── lifecycle ────────────────────────────────────────────────────────── */

static cbae_err_t create_once(cbae_arena_t *arena) {
    cbae_cir_function_t *f = (cbae_cir_function_t *)1;
    const cbae_err_t rc = cbae_cir_function_create(arena, 0x77, "creation", &f);
    if (rc != CBAE_OK) {
        assert(rc == CBAE_ERR_OOM && f == NULL);
        return rc;
    }
    ai_disarm();
    assert(f && f->entry_addr == 0x77 && strcmp(f->name, "creation") == 0 && cbae_vector_count(&f->blocks) == 0 && f->next_value_id == 0);
    cbae_cir_function_destroy(f);
    return CBAE_OK;
}

static void test_lifecycle(void) {
    /* creation under failure: every allocation it makes is one whose failure is reported, with nothing left behind (a
     * leak is the sanitizer gates' to find) */
    cbae_arena_t arena;
    assert(cbae_arena_init(&arena, 1 << 16) == CBAE_OK);
    ai_reset();
    assert(create_once(&arena) == CBAE_OK);
    const uint64_t total = ai_count();
    assert(total >= 3);                                               /* the block vector, the address map, the value vector */
    for (uint64_t j = 1; j <= total; j++) {
        ai_reset();
        ai_fail_at(j);
        assert(create_once(&arena) == CBAE_ERR_OOM);
        ai_disarm();
    }
    ai_reset();
    assert(create_once(&arena) == CBAE_OK);
    cbae_arena_destroy(&arena);

    /* a function whose arena is too small to hold it */
    assert(cbae_arena_init(&arena, 16) == CBAE_OK);
    cbae_cir_function_t *f = (cbae_cir_function_t *)1;
    cbae_error_clear();
    assert(cbae_cir_function_create(&arena, 0, "x", &f) == CBAE_ERR_OOM && f == NULL);
    cbae_arena_destroy(&arena);

    /* a name that is NULL is empty; one that is too long is cut to fit and still ends in a NUL */
    assert(cbae_arena_init(&arena, 1 << 16) == CBAE_OK);
    assert(cbae_cir_function_create(&arena, 1, NULL, &f) == CBAE_OK && f->name[0] == '\0');
    cbae_cir_function_destroy(f);
    char big[300];
    memset(big, 'z', sizeof big - 1); big[sizeof big - 1] = '\0';
    assert(cbae_cir_function_create(&arena, 1, big, &f) == CBAE_OK && strlen(f->name) == sizeof f->name - 1);
    cbae_cir_function_destroy(f);

    /* destroy: NULL, twice, and a function whose block slot was emptied */
    cbae_cir_function_destroy(NULL);
    assert(cbae_cir_function_create(&arena, 1, "d", &f) == CBAE_OK);
    cbae_cir_block_t *b0, *b1;
    assert(cbae_cir_block_create(f, 0x10, &b0) == CBAE_OK && cbae_cir_block_create(f, 0x20, &b1) == CBAE_OK);
    cbae_vector_destroy(&b0->predecessors);                           /* the test empties the slot, so the test frees what it held */
    *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, 0) = NULL;
    cbae_cir_function_destroy(f);
    cbae_cir_function_destroy(f);
    assert(cbae_cir_function_block_at(NULL, 0x10) == NULL);
    cbae_arena_destroy(&arena);
    PASS("lifecycle: creation reports each of its allocations failing (and leaves nothing) and a full arena, odd names, destroy accepts NULL, a second call and an emptied block slot");
}

/* A block address the lifter registers twice (the synthetic entry and the real entry) points at the later block. */
static void test_block_addresses(void) {
    world_t w;
    world_init(&w, 1 << 20);
    cbae_cir_block_t *first, *second, *other;
    assert(cbae_cir_block_create(w.f, 0x500, &first) == CBAE_OK && cbae_cir_block_create(w.f, 0x500, &second) == CBAE_OK);
    assert(cbae_cir_block_create(w.f, 0x600, &other) == CBAE_OK);
    assert(first->id == 0 && second->id == 1 && other->id == 2);
    assert(first->start_addr == 0x500 && second->start_addr == 0x500 && other->start_addr == 0x600);
    assert(cbae_cir_function_block_at(w.f, 0x500) == second && cbae_cir_function_block_at(w.f, 0x600) == other);
    assert(cbae_cir_function_block_at(w.f, 0x700) == NULL);
    assert(cbae_cir_function_block_at(w.f, 0xFFFFFFFFFFFFFFF0ull) == NULL);
    check_consistent(w.f);
    world_destroy(&w);
    PASS("two blocks at one address are both blocks; the address finds the later one; unknown addresses find nothing");
}

/* ── scale ────────────────────────────────────────────────────────────── */

/* Nothing fails: a join with 300 predecessors and a phi with 300 incoming values, blocks of 100 instructions. Every
 * array doubles several times and what was put in is what is found. */
static void test_scale(void) {
    enum { N = 300, K = 100 };
    world_t w;
    world_init(&w, 1 << 24);
    cbae_cir_block_t *join;
    assert(cbae_cir_block_create(w.f, 0x100, &join) == CBAE_OK);
    cbae_cir_builder_t b;
    cbae_cir_builder_init(&b, w.f, join);
    cbae_cir_value_t *seed = cbae_cir_param(&b, CBAE_REG_RAX);
    assert(seed);
    cbae_cir_value_t *phi = cbae_cir_phi_create(w.f, join, cir_type_i(64));
    assert(phi);
    for (uint32_t i = 1; i <= N; i++) {
        cbae_cir_block_t *p;
        assert(cbae_cir_block_create(w.f, 0x1000u + 0x100u * i, &p) == CBAE_OK && p->id == i);
        cbae_cir_builder_init(&b, w.f, p);
        cbae_cir_value_t *last = seed;
        for (int k = 0; k < K; k++) {
            last = cbae_cir_binop(&b, CIR_OP_ADD, last, seed, cir_type_i(64), 0x1000u + i);
            assert(last);
        }
        assert(B_jump(&b, join, 0x2000u + i) == CBAE_OK);
        assert(cbae_cir_phi_add_incoming(w.f, phi->u.def_insn, last, i) == CBAE_OK);
    }
    check_consistent(w.f);
    assert(cbae_vector_count(&join->predecessors) == N && phi->u.def_insn->phi_incoming_count == N);
    for (uint32_t i = 0; i < N; i++) {
        assert(*(uint32_t *)cbae_vector_at(&join->predecessors, i) == i + 1);
        assert(phi->u.def_insn->phi_incoming_blocks[i] == i + 1);
        const cbae_cir_block_t *p = blk(w.f, i + 1);
        assert(p->instruction_count == K + 1 && phi->u.def_insn->phi_incoming_values[i] == p->instructions[K - 1]->result);
        assert(p->instructions[K]->opcode == CIR_OP_JUMP && p->instructions[K]->branch_true_block == 0);
    }
    assert(join->instruction_count == 1 && join->instructions[0] == phi->u.def_insn);
    assert(w.f->next_insn_id == 1 + (uint32_t)N * (K + 1) && w.f->next_value_id == 2 + (uint32_t)N * K);

    uint8_t *blob = NULL;
    size_t n = 0;
    assert(cbae_cir_serialize_function(w.f, &blob, &n) == CBAE_OK);
    cbae_arena_t arena2;
    assert(cbae_arena_init(&arena2, 1 << 24) == CBAE_OK);
    cbae_cir_function_t *back = NULL;
    assert(cbae_cir_deserialize_function(blob, n, &arena2, &back) == CBAE_OK);
    uint8_t *blob2 = NULL;
    size_t n2 = 0;
    assert(cbae_cir_serialize_function(back, &blob2, &n2) == CBAE_OK && n2 == n && memcmp(blob, blob2, n) == 0);
    free(blob); free(blob2);
    cbae_cir_function_destroy(back);
    cbae_arena_destroy(&arena2);

    /* Growth is geometric: a block of 5000 instructions and a phi of 5000 incoming values take memory in proportion to
     * their size. (Growing by a fixed step would copy and abandon an array per element: 5000 * 5000 / 2 pointers.) */
    cbae_cir_block_t *big;
    assert(cbae_cir_block_create(w.f, 0x900000, &big) == CBAE_OK);
    cbae_cir_builder_init(&b, w.f, big);
    const size_t used0 = w.arena.used;
    for (unsigned k = 0; k < 5000; k++) assert(cbae_cir_binop(&b, CIR_OP_ADD, seed, seed, cir_type_i(64), 0x5000u + k));
    assert(w.arena.used - used0 < 5000 * (sizeof(cbae_cir_instruction_t) + sizeof(cbae_cir_value_t) + 4 * sizeof(void *)));
    cbae_cir_value_t *big_phi = cbae_cir_phi_create(w.f, big, cir_type_i(64));
    assert(big_phi);
    const size_t used1 = w.arena.used;
    for (unsigned k = 0; k < 5000; k++) assert(cbae_cir_phi_add_incoming(w.f, big_phi->u.def_insn, seed, 0) == CBAE_OK);
    assert(w.arena.used - used1 < 5000 * 4 * (sizeof(void *) + sizeof(uint32_t)));
    assert(big->instruction_count == 5001 && big_phi->u.def_insn->phi_incoming_count == 5000);
    check_consistent(w.f);
    world_destroy(&w);
    PASS("scale: 301 blocks of 100 instructions, a join with 300 predecessors and a phi with 300 incoming values: every array doubled and kept what it was given; the function serializes and reads back identical");
}

/* Adding an edge that is there asks for no memory: a sweep that adds every edge a block needs must not be able to fail on
 * the ones it already has, however full the predecessor vector of the target is. */
static void test_edge_that_exists(void) {
    world_t w;
    world_init(&w, 1 << 20);
    cbae_cir_block_t *to, *from[16];
    assert(cbae_cir_block_create(w.f, 0x10, &to) == CBAE_OK);
    size_t n = 0;
    while (cbae_vector_count(&to->predecessors) < to->predecessors.capacity) {           /* until the predecessor vector is full */
        assert(n < 16 && cbae_cir_block_create(w.f, 0x20u + 0x10u * (unsigned)n, &from[n]) == CBAE_OK);
        assert(cbae_cir_block_add_edge(from[n], to) == CBAE_OK);
        n++;
    }
    assert(n >= 1 && cbae_vector_count(&to->predecessors) == to->predecessors.capacity);
    cbae_cir_builder_t bld;
    cbae_cir_builder_init(&bld, w.f, from[0]);
    cbae_cir_value_t *cond = cbae_cir_const(&bld, cir_type_i1(), 1);
    assert(cond);
    ai_reset();
    ai_fail_from(1);                                                                      /* from here on no allocation succeeds */
    for (size_t i = 0; i < n; i++) assert(cbae_cir_block_add_edge(from[i], to) == CBAE_OK);
    assert(B_jump(&bld, to, 0x40) == CBAE_OK);
    assert(B_branch(&bld, cond, to, to, 0x44) == CBAE_OK);
    ai_disarm();
    assert(cbae_vector_count(&to->predecessors) == to->predecessors.capacity && from[0]->successor_count == 1 && from[0]->instruction_count == 2);
    check_consistent(w.f);
    world_destroy(&w);
    PASS("an edge that is there is added without asking for memory, by add_edge, jump and branch, with the target's predecessor vector full");
}

static cbae_cir_instruction_t *last_insn(const cbae_cir_block_t *b) { return b->instructions[b->instruction_count - 1]; }

/* Every field of what the builder makes is what it was asked for. */
static void test_fields(void) {
    world_t w;
    world_init(&w, 1 << 20);
    for (unsigned i = 0; i < 4; i++) {
        assert(cbae_cir_block_create(w.f, 0x1000u + 0x20u * i, &w.h.b[i]) == CBAE_OK);
        assert(w.h.b[i]->id == i && w.h.b[i]->start_addr == 0x1000u + 0x20u * i && w.h.b[i]->instruction_count == 0 && w.h.b[i]->successor_count == 0);
        assert(cbae_cir_function_block_at(w.f, 0x1000u + 0x20u * i) == w.h.b[i]);
    }
    cbae_cir_builder_t *b = &w.bld;
    cbae_cir_builder_init(b, w.f, w.h.b[0]);
    assert(b->func == w.f && b->block == w.h.b[0]);
    cbae_cir_value_t *c = cbae_cir_const(b, cir_type_i(32), -5);
    assert(c && c->id == 0 && c->kind == CIR_VAL_CONST && c->type.kind == CIR_TYPE_I32 && c->u.const_val == -5);
    cbae_cir_value_t *p = cbae_cir_param(b, CBAE_REG_RDX);
    assert(p && p->id == 1 && p->kind == CIR_VAL_PARAM && p->type.kind == CIR_TYPE_I64 && p->u.param_reg == CBAE_REG_RDX);
    cbae_cir_value_t *po = cbae_cir_param(b, CBAE_REG_OTHER);                      /* the last register that exists */
    assert(po && po->id == 2 && po->u.param_reg == CBAE_REG_OTHER);
    cbae_cir_value_t *ptr = cbae_cir_const(b, cir_type_ptr(), 0x7000);
    assert(ptr && ptr->id == 3 && ptr->type.kind == CIR_TYPE_PTR && ptr->u.const_val == 0x7000);

    cbae_cir_value_t *ld = cbae_cir_load(b, ptr, cir_type_i(16), 0x40);
    cbae_cir_instruction_t *in = last_insn(w.h.b[0]);
    assert(ld && in->id == 0 && in->opcode == CIR_OP_LOAD && in->source_addr == 0x40 && in->operand_count == 1 && in->operands[0] == ptr);
    assert(in->result == ld && ld->id == 4 && ld->kind == CIR_VAL_INSN_RESULT && ld->type.kind == CIR_TYPE_I16 && ld->u.def_insn == in);
    cbae_cir_value_t *sub = cbae_cir_binop(b, CIR_OP_SUB, c, p, cir_type_i(8), 0x44);
    in = last_insn(w.h.b[0]);
    assert(sub && sub->id == 5 && sub->type.kind == CIR_TYPE_I8 && in->id == 1 && in->opcode == CIR_OP_SUB && in->source_addr == 0x44);
    assert(in->operand_count == 2 && in->operands[0] == c && in->operands[1] == p && in->result == sub);
    assert(B_store(b, ptr, sub, 0x48) == CBAE_OK);
    in = last_insn(w.h.b[0]);
    assert(in->id == 2 && in->opcode == CIR_OP_STORE && in->source_addr == 0x48 && in->operand_count == 2 && in->operands[0] == ptr && in->operands[1] == sub && in->result == NULL);
    cbae_cir_value_t *cargs[2] = { p, c };
    cbae_cir_value_t *call = cbae_cir_call(b, "f", cargs, 2, cir_type_i1(), 0x4C);
    in = last_insn(w.h.b[0]);
    assert(call && call->id == 6 && call->type.kind == CIR_TYPE_I1 && in->id == 3 && in->opcode == CIR_OP_CALL && in->source_addr == 0x4C);
    assert(in->operand_count == 2 && in->operands[0] == p && in->operands[1] == c && strcmp(in->call_target_name, "f") == 0 && in->result == call);
    cbae_cir_value_t *cc1 = cbae_cir_const(b, cir_type_i1(), 1);
    assert(cc1 && cc1->id == 7);
    assert(B_branch(b, cc1, w.h.b[1], w.h.b[2], 0x50) == CBAE_OK);
    in = last_insn(w.h.b[0]);
    assert(in->id == 4 && in->opcode == CIR_OP_BRANCH && in->source_addr == 0x50 && in->operand_count == 1 && in->operands[0] == cc1 && in->result == NULL);
    assert(in->branch_true_block == 1 && in->branch_false_block == 2);
    assert(w.h.b[0]->successor_count == 2 && w.h.b[0]->successors[0] == 1 && w.h.b[0]->successors[1] == 2);
    assert(cbae_vector_count(&w.h.b[1]->predecessors) == 1 && *(uint32_t *)cbae_vector_at(&w.h.b[1]->predecessors, 0) == 0);
    assert(cbae_vector_count(&w.h.b[2]->predecessors) == 1 && *(uint32_t *)cbae_vector_at(&w.h.b[2]->predecessors, 0) == 0);

    cbae_cir_builder_init(b, w.f, w.h.b[1]);
    assert(B_jump(b, w.h.b[3], 0x54) == CBAE_OK);
    in = last_insn(w.h.b[1]);
    assert(in->id == 5 && in->opcode == CIR_OP_JUMP && in->source_addr == 0x54 && in->operand_count == 0 && in->result == NULL && in->branch_true_block == 3);
    assert(w.h.b[1]->successor_count == 1 && w.h.b[1]->successors[0] == 3 && cbae_vector_count(&w.h.b[3]->predecessors) == 1 && *(uint32_t *)cbae_vector_at(&w.h.b[3]->predecessors, 0) == 1);

    cbae_cir_builder_init(b, w.f, w.h.b[3]);
    assert(B_return(b, sub, 0x58) == CBAE_OK);
    in = last_insn(w.h.b[3]);
    assert(in->id == 6 && in->opcode == CIR_OP_RETURN && in->source_addr == 0x58 && in->operand_count == 1 && in->operands[0] == sub && in->result == NULL);
    assert(B_return(b, NULL, 0x5C) == CBAE_OK);
    in = last_insn(w.h.b[3]);
    assert(in->id == 7 && in->opcode == CIR_OP_RETURN && in->source_addr == 0x5C && in->operand_count == 0);

    cbae_cir_value_t *phi = cbae_cir_phi_create(w.f, w.h.b[3], cir_type_i(32));
    in = w.h.b[3]->instructions[0];
    assert(phi && phi->id == 8 && phi->type.kind == CIR_TYPE_I32 && phi->kind == CIR_VAL_INSN_RESULT && in == phi->u.def_insn && in->result == phi);
    assert(in->id == 8 && in->opcode == CIR_OP_PHI && in->source_addr == 0x1060 && in->operand_count == 0 && in->phi_incoming_count == 0);
    assert(w.h.b[3]->instruction_count == 3 && w.h.b[3]->instructions[1]->opcode == CIR_OP_RETURN && w.h.b[3]->instructions[2]->opcode == CIR_OP_RETURN);
    assert(cbae_cir_phi_add_incoming(w.f, in, c, 1) == CBAE_OK && cbae_cir_phi_add_incoming(w.f, in, p, 2) == CBAE_OK);
    assert(in->phi_incoming_count == 2 && in->phi_incoming_values[0] == c && in->phi_incoming_blocks[0] == 1);
    assert(in->phi_incoming_values[1] == p && in->phi_incoming_blocks[1] == 2);
    check_consistent(w.f);
    world_destroy(&w);
    PASS("fields: every kind, type, id, opcode, source address, operand (in order), name, branch target, edge and incoming pair is what it was asked to be");
}

/* The arrays the builder grows when they are full, at their limits. */
static void test_growth_edges(void) {
    world_t w;
    world_init(&w, 1 << 20);
    run_through(&w, op_cmp);
    cbae_cir_builder_t *b = &w.bld;

    /* a block whose array is as large as it can be: it would not double in 32 bits */
    cbae_cir_block_t *b0 = w.h.b[0];
    const uint32_t cnt = b0->instruction_count, cap = b0->instruction_capacity;
    b0->instruction_count = b0->instruction_capacity = 0x80000001u;       /* (a lie: the call refuses before it looks at the array) */
    REFUSED_ERR_AS(B_store(b, w.h.cptr, w.h.c42, 0), CBAE_ERR_OVERFLOW);
    b0->instruction_count = cnt;
    b0->instruction_capacity = cap;
    check_consistent(w.f);

    /* a block with no array at all (one that something else made) gets the usual one */
    cbae_cir_block_t *b5 = w.h.b[5];
    b5->instructions = NULL;
    b5->instruction_capacity = 0;
    cbae_cir_builder_t at5;
    cbae_cir_builder_init(&at5, w.f, b5);
    assert(B_store(&at5, w.h.cptr, w.h.c42, 0x30) == CBAE_OK);
    assert(b5->instruction_count == 1 && b5->instruction_capacity >= 1 && b5->instructions[0]->opcode == CIR_OP_STORE);
    check_consistent(w.f);

    /* a phi whose arrays are as large as they can be */
    cbae_cir_value_t *pv = cbae_cir_phi_create(w.f, w.h.b[3], cir_type_i(64));
    assert(pv);
    cbae_cir_instruction_t *phi = pv->u.def_insn;
    phi->phi_incoming_count = phi->phi_incoming_capacity = 0x80000001u;
    REFUSED_ERR_AS(cbae_cir_phi_add_incoming(w.f, phi, w.h.rax, 0), CBAE_ERR_OVERFLOW);
    phi->phi_incoming_count = phi->phi_incoming_capacity = 0;
    assert(cbae_cir_phi_add_incoming(w.f, phi, w.h.rax, 0) == CBAE_OK && phi->phi_incoming_count == 1);
    check_consistent(w.f);
    world_destroy(&w);
    PASS("growth: an instruction array or a phi's arrays that cannot double are refused (CBAE_ERR_OVERFLOW) untouched; a block with no array gets one");
}

typedef struct { const char *name; void (*run)(void); } group_t;

static const group_t GROUPS[] = {
    { "script", test_script_under_failure }, { "refusals", test_refusals }, { "limits", test_counters_at_the_limit },
    { "fields", test_fields }, { "growth", test_growth_edges }, { "idempotent", test_edge_that_exists },
    { "successors", test_third_successor }, { "names", test_call_name_is_copied },
#ifndef CIR_BUILDER_VOID
    { "emit_insn", test_emit_insn },
#endif
    { "lifecycle", test_lifecycle }, { "addresses", test_block_addresses }, { "scale", test_scale },
};

int main(int argc, char **argv) {
    printf("=== test_cir_builder_hostile ===\n");
    cbae_log_init(CBAE_LOG_ERROR, NULL, 0);
    for (size_t i = 0; i < sizeof GROUPS / sizeof GROUPS[0]; i++)
        if (argc < 2 || strcmp(argv[1], GROUPS[i].name) == 0) GROUPS[i].run();
    printf("All CIR builder hostile-input tests passed.\n");
    return 0;
}
