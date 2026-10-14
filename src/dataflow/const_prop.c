/**
 * @file const_prop.c
 * @brief Constant propagation. What it claims, and what it refuses to, is
 *        documented in const_prop.h; this file is the how.
 *
 * ALGORITHM: the standard sparse conditional scheme with two work lists.
 *   - Block 0 is executable. Making a block executable queues it; visiting it
 *     evaluates every instruction in order and then opens its outgoing edges.
 *   - Evaluating an instruction recomputes its result from the operands'
 *     lattice values and MEETS the answer into the stored one. The meet keeps
 *     the descent monotone (UNREACHED -> CONSTANT -> VARYING) whatever the
 *     transfer function returns, so the loop terminates by construction. That
 *     the answer does not depend on the ORDER of evaluation is a separate
 *     property, and needs every transfer function to be monotone itself: a
 *     result computed from a not-yet-known operand (UNREACHED) must be at least
 *     as high as the one computed once it is known. test_const_prop_soundness
 *     checks it against a reference that evaluates in a different order.
 *   - When a value falls, each user in an executable block is queued: an
 *     instruction operand or a phi incoming alike (cbae_use_def_uses).
 *   - A BRANCH is re-evaluated when its condition falls; an edge that becomes
 *     executable either makes its target executable or re-queues the target's
 *     phis (a new incoming value now counts).
 *
 * STATE: one byte (kind) and one word (value) per value id, one byte per
 * block, one byte per (block, successor slot).
 */
#include "dataflow/const_prop.h"
#include "platform/logging.h"
#include <stdlib.h>
#include <string.h>

enum { LAT_TOP = 0, LAT_CONST = 1, LAT_BOTTOM = 2 };

typedef struct { uint8_t k; uint64_t v; } lat_t;

struct cbae_cp_impl {
    uint32_t   nvals;
    uint32_t   nblocks;
    uint32_t   ninsn;
    cbae_cir_value_t *const *owner;   /* the use-def's value index: owner[id] is the function's own value */
    uint8_t   *kind;        /* [nvals]                      */
    uint64_t  *val;         /* [nvals]                      */
    uint8_t   *bexec;       /* [nblocks]                    */
    uint8_t   *eexec;       /* [nblocks * 2]                */

    uint32_t  *bstack;      /* blocks to visit, each pushed once        */
    uint32_t   bsp;
    uint32_t  *istack;      /* instruction ids to re-evaluate           */
    uint32_t   isp;
    uint8_t   *in_istack;   /* [ninsn]                                  */
};

static void impl_free(struct cbae_cp_impl *p) {
    if (!p) return;
    free(p->kind); free(p->val); free(p->bexec); free(p->eexec);
    free(p->bstack); free(p->istack); free(p->in_istack);
    free(p);
}

static inline unsigned bits_of(const cbae_cir_value_t *v) { return cir_type_bits(v->type); }

static inline uint64_t wmask(unsigned bits) {
    return bits >= 64 ? ~0ull : ((1ull << bits) - 1ull);       /* (bits == 0 gives 0) */
}

static inline lat_t mk(uint8_t k, uint64_t v) { lat_t r; r.k = k; r.v = v; return r; }

static inline const cbae_cir_block_t *block_at(const cbae_cir_function_t *f, uint32_t b) {
    return *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
}

/* Is `v` one of the analysed function's own values? A value of another function can carry an
 * in-range id, so the id alone is not enough: the pointer must match too. Asked wherever a value
 * arrives that use-def has not vouched for: an instruction's RESULT (it only scans operands) and
 * a value handed in through the public lookups. */
static bool owned(const struct cbae_cp_impl *p, const cbae_cir_value_t *v) {
    return v->id < p->nvals && p->owner[v->id] == v;
}

/* The lattice value of an operand. Every operand and phi incoming of the function is one of its
 * own values: cbae_use_def_build refuses a function in which one is not, so the id can be trusted
 * here. (A NULL operand slot is allowed and unknown; a void-typed constant needs no case of its
 * own, every caller turns an operand of width 0 away before its value is looked at.) */
static lat_t lat_of(const struct cbae_cp_impl *p, const cbae_cir_value_t *v) {
    if (!v) return mk(LAT_BOTTOM, 0);
    switch (v->kind) {
        case CIR_VAL_CONST:
            return mk(LAT_CONST, (uint64_t)v->u.const_val & wmask(bits_of(v)));
        case CIR_VAL_INSN_RESULT:
            return mk(p->kind[v->id], p->val[v->id]);
        default:                                    /* parameters, placeholders: unknown */
            return mk(LAT_BOTTOM, 0);
    }
}

/* ── Folding ──────────────────────────────────────────────────────────── */

/* The lifter's conflated narrow register: each read may be a different number. */
static bool is_other_param(const cbae_cir_value_t *v) {
    return v->kind == CIR_VAL_PARAM && v->u.param_reg == CBAE_REG_OTHER;
}

/* The instruction has exactly `n` operands and none of them is missing. */
static bool shape_ok(const cbae_cir_instruction_t *in, uint8_t n) {
    if (in->operand_count != n) return false;
    for (uint8_t k = 0; k < n; k++)
        if (!in->operands[k]) return false;
    return true;
}

/* Every operand (all present: see shape_ok) is at least `rw` bits wide, and `rw` is a real width.
 * The result then depends on the low `rw` bits of the operands alone, so no question of how a
 * narrow operand is extended arises. */
static bool wide_enough(const cbae_cir_instruction_t *in, unsigned rw) {
    if (rw == 0) return false;
    for (uint8_t k = 0; k < in->operand_count; k++)
        if (bits_of(in->operands[k]) < rw) return false;
    return true;
}

static lat_t eval_arith2(const struct cbae_cp_impl *p, const cbae_cir_instruction_t *in) {
    const cbae_cir_opcode_t op = in->opcode;
    if (!shape_ok(in, 2)) return mk(LAT_BOTTOM, 0);
    const unsigned rw = bits_of(in->result);
    if (!wide_enough(in, rw)) return mk(LAT_BOTTOM, 0);
    const uint64_t m = wmask(rw);

    const cbae_cir_value_t *x = in->operands[0], *y = in->operands[1];
    const lat_t a = lat_of(p, x), b = lat_of(p, y);

    if (x == y && !is_other_param(x) && (op == CIR_OP_XOR || op == CIR_OP_SUB))
        return mk(LAT_CONST, 0);
    const bool a0 = a.k == LAT_CONST && (a.v & m) == 0, b0 = b.k == LAT_CONST && (b.v & m) == 0;
    const bool a1 = a.k == LAT_CONST && (a.v & m) == m, b1 = b.k == LAT_CONST && (b.v & m) == m;
    if ((op == CIR_OP_AND || op == CIR_OP_MUL) && (a0 || b0)) return mk(LAT_CONST, 0);
    if (op == CIR_OP_OR && (a1 || b1)) return mk(LAT_CONST, m);

    /* TOP is tested BEFORE BOTTOM. The function must be monotone: an operand that is
     * not known yet (TOP) may still turn into the annihilator above, so the result
     * with it must not be lower than the result once it is known. Testing BOTTOM
     * first returned BOTTOM for (TOP, BOTTOM) while (0, BOTTOM) is 0, and the stored
     * value, which only ever falls, kept the lower answer for good: the result then
     * depended on the order values happened to be evaluated in. */
    if (a.k == LAT_TOP || b.k == LAT_TOP) return mk(LAT_TOP, 0);
    if (a.k == LAT_BOTTOM || b.k == LAT_BOTTOM) return mk(LAT_BOTTOM, 0);

    uint64_t r;
    switch (op) {
        case CIR_OP_ADD: r = a.v + b.v; break;
        case CIR_OP_SUB: r = a.v - b.v; break;
        case CIR_OP_MUL: r = a.v * b.v; break;
        case CIR_OP_AND: r = a.v & b.v; break;
        case CIR_OP_OR:  r = a.v | b.v; break;
        case CIR_OP_XOR: r = a.v ^ b.v; break;
        default: return mk(LAT_BOTTOM, 0);
    }
    return mk(LAT_CONST, r & m);
}

static lat_t eval_unary(const struct cbae_cp_impl *p, const cbae_cir_instruction_t *in) {
    if (!shape_ok(in, 1)) return mk(LAT_BOTTOM, 0);
    const unsigned rw = bits_of(in->result);
    if (!wide_enough(in, rw)) return mk(LAT_BOTTOM, 0);       /* includes COPY to a wider type */
    const lat_t a = lat_of(p, in->operands[0]);
    if (a.k != LAT_CONST) return a;
    uint64_t r;
    switch (in->opcode) {
        case CIR_OP_NOT:  r = ~a.v; break;
        case CIR_OP_NEG:  r = (uint64_t)0 - a.v; break;
        case CIR_OP_COPY: r = a.v; break;
        default: return mk(LAT_BOTTOM, 0);
    }
    return mk(LAT_CONST, r & wmask(rw));
}

static lat_t eval_shift(const struct cbae_cp_impl *p, const cbae_cir_instruction_t *in) {
    if (!shape_ok(in, 2)) return mk(LAT_BOTTOM, 0);
    if (bits_of(in->result) != 64 || bits_of(in->operands[0]) != 64 || bits_of(in->operands[1]) < 8)
        return mk(LAT_BOTTOM, 0);
    const lat_t a = lat_of(p, in->operands[0]), n = lat_of(p, in->operands[1]);
    if (a.k == LAT_CONST && a.v == 0) return mk(LAT_CONST, 0);
    if (a.k == LAT_TOP || n.k == LAT_TOP) return mk(LAT_TOP, 0);          /* TOP before BOTTOM: see eval_arith2 */
    if (a.k == LAT_BOTTOM || n.k == LAT_BOTTOM) return mk(LAT_BOTTOM, 0);
    const unsigned c = (unsigned)(n.v & 63u);
    uint64_t r;
    switch (in->opcode) {
        case CIR_OP_SHL: r = a.v << c; break;
        case CIR_OP_SHR: r = a.v >> c; break;
        case CIR_OP_SAR: r = (uint64_t)((int64_t)a.v >> c); break;
        default: return mk(LAT_BOTTOM, 0);
    }
    return mk(LAT_CONST, r);
}

/* Is the edge from block `pb` into block `to` executable? */
static bool edge_open(const struct cbae_cp_impl *p, const cbae_cir_function_t *f, uint32_t pb, uint32_t to) {
    if (pb >= p->nblocks) return false;                    /* (an edge is only ever opened from an executable block) */
    const cbae_cir_block_t *blk = block_at(f, pb);
    for (uint32_t k = 0; k < blk->successor_count; k++)
        if (blk->successors[k] == to) return p->eexec[(size_t)pb * 2 + k] != 0;
    return false;
}

static lat_t meet(lat_t a, lat_t b) {
    if (a.k == LAT_TOP) return b;
    if (b.k == LAT_TOP) return a;
    if (a.k == LAT_CONST && b.k == LAT_CONST && a.v == b.v) return a;
    return mk(LAT_BOTTOM, 0);
}

static lat_t eval_phi(const struct cbae_cp_impl *p, const cbae_cir_function_t *f,
                      const cbae_cir_instruction_t *in, uint32_t block_id) {
    const unsigned pw = bits_of(in->result);
    lat_t acc = mk(LAT_TOP, 0);
    for (uint32_t k = 0; k < in->phi_incoming_count; k++) {
        if (!edge_open(p, f, in->phi_incoming_blocks[k], block_id)) continue;
        const cbae_cir_value_t *v = in->phi_incoming_values[k];                /* never NULL: use-def */
        if (pw == 0 || bits_of(v) < pw) return mk(LAT_BOTTOM, 0);             /* would need an extension */
        lat_t l = lat_of(p, v);
        if (l.k == LAT_CONST) l.v &= wmask(pw);
        acc = meet(acc, l);
        if (acc.k == LAT_BOTTOM) break;
    }
    return acc;
}

/* ── Worklists ────────────────────────────────────────────────────────── */

/* Every instruction pushed here is one of the function's own (use-def indexed it, ids in range). */
static void push_insn(struct cbae_cp_impl *p, const cbae_cir_instruction_t *in) {
    if (p->in_istack[in->id]) return;
    p->in_istack[in->id] = 1;
    p->istack[p->isp++] = in->id;
}

/* Make block `b` (which must exist) executable. False if it already was. */
static bool mark_block(struct cbae_cp_impl *p, uint32_t b) {
    if (p->bexec[b]) return false;
    p->bexec[b] = 1;
    p->bstack[p->bsp++] = b;
    return true;
}

static void mark_edge(struct cbae_cp_impl *p, const cbae_cir_function_t *f, uint32_t from, uint32_t k) {
    uint8_t *e = &p->eexec[(size_t)from * 2 + k];
    if (*e) return;
    *e = 1;
    const uint32_t to = block_at(f, from)->successors[k];
    if (to >= p->nblocks || mark_block(p, to)) return;       /* a new block is visited whole, phis included */
    const cbae_cir_block_t *tb = block_at(f, to);            /* an old one: its phis have a new incoming edge */
    for (uint32_t i = 0; i < tb->instruction_count && tb->instructions[i]->opcode == CIR_OP_PHI; i++)
        push_insn(p, tb->instructions[i]);
}

static void mark_all_edges(struct cbae_cp_impl *p, const cbae_cir_function_t *f, uint32_t b) {
    const cbae_cir_block_t *blk = block_at(f, b);
    for (uint32_t k = 0; k < blk->successor_count; k++) mark_edge(p, f, b, k);
}

/* A BRANCH ending block `b`: open the edge(s) its condition allows. */
static void eval_branch(struct cbae_cp_impl *p, const cbae_cir_function_t *f,
                        const cbae_cir_instruction_t *in, uint32_t b) {
    const cbae_cir_block_t *blk = block_at(f, b);
    const cbae_cir_value_t *c = in->operand_count >= 1 ? in->operands[0] : NULL;
    lat_t l = lat_of(p, c);
    if (l.k == LAT_CONST && bits_of(c) != 1) l = mk(LAT_BOTTOM, 0);          /* only an i1 is unambiguous */
    if (l.k == LAT_TOP) return;                                              /* not known yet: no edge */
    if (l.k == LAT_CONST) {
        const uint32_t target = l.v ? in->branch_true_block : in->branch_false_block;       /* an i1: 0 or 1 */
        bool found = false;
        for (uint32_t k = 0; k < blk->successor_count; k++)
            if (blk->successors[k] == target) { mark_edge(p, f, b, k); found = true; }
        if (found) return;                                                   /* else: inconsistent, open all */
    }
    mark_all_edges(p, f, b);
}

/* Lower the stored value of `vid` by `nl` (a meet). Returns true if it changed. */
static bool lower(struct cbae_cp_impl *p, uint32_t vid, lat_t nl) {
    const uint8_t ok = p->kind[vid];
    if (ok == LAT_BOTTOM || nl.k == LAT_TOP) return false;
    if (ok == LAT_TOP) { p->kind[vid] = nl.k; p->val[vid] = nl.v; return true; }
    if (nl.k == LAT_CONST && nl.v == p->val[vid]) return false;
    p->kind[vid] = LAT_BOTTOM;
    p->val[vid] = 0;
    return true;
}

static void push_users(struct cbae_cp_impl *p, const cbae_use_def_t *ud, const cbae_cir_value_t *v) {
    const cbae_use_list_t ul = cbae_use_def_uses(ud, v);
    for (uint32_t i = 0; i < ul.count; i++) push_insn(p, ul.uses[i].insn);   /* dead users are skipped when popped */
}

static void eval_insn(struct cbae_cp_impl *p, const cbae_use_def_t *ud, const cbae_cir_instruction_t *in,
                      uint32_t b) {
    const cbae_cir_function_t *f = ud->func;
    if (in->opcode == CIR_OP_BRANCH) {
        const cbae_cir_block_t *blk = block_at(f, b);
        if (blk->instructions[blk->instruction_count - 1] == in)       /* (the block holds `in`: count >= 1) */
            eval_branch(p, f, in, b);                      /* only a last instruction is a terminator */
        return;
    }
    if (!in->result || !owned(p, in->result)) return;        /* no value, or not this function's */

    lat_t r;
    switch (in->opcode) {
        case CIR_OP_ADD: case CIR_OP_SUB: case CIR_OP_MUL:
        case CIR_OP_AND: case CIR_OP_OR:  case CIR_OP_XOR:
            r = eval_arith2(p, in); break;
        case CIR_OP_NOT: case CIR_OP_NEG: case CIR_OP_COPY:
            r = eval_unary(p, in); break;
        case CIR_OP_SHL: case CIR_OP_SHR: case CIR_OP_SAR:
            r = eval_shift(p, in); break;
        case CIR_OP_PHI:
            r = eval_phi(p, f, in, b); break;
        default:
            r = mk(LAT_BOTTOM, 0); break;                  /* loads, calls, comparisons, ...: unknown */
    }
    if (lower(p, in->result->id, r)) push_users(p, ud, in->result);
}

static void visit_block(struct cbae_cp_impl *p, const cbae_use_def_t *ud, uint32_t b) {
    const cbae_cir_function_t *f = ud->func;
    const cbae_cir_block_t *blk = block_at(f, b);
    for (uint32_t i = 0; i < blk->instruction_count; i++) eval_insn(p, ud, blk->instructions[i], b);
    if (blk->instruction_count == 0 || blk->instructions[blk->instruction_count - 1]->opcode != CIR_OP_BRANCH)
        mark_all_edges(p, f, b);                           /* jump, fallthrough, return: every edge there is */
}

/* ── Public API ───────────────────────────────────────────────────────── */

cbae_err_t cbae_const_prop_run(const cbae_use_def_t *ud, cbae_const_prop_t *out) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "const prop: null output");
    memset(out, 0, sizeof(*out));
    if (!ud || !ud->func) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "const prop: needs a use-def index");
    const uint32_t nb = (uint32_t)cbae_vector_count(&ud->func->blocks);
    if (nb == 0) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "const prop: function has no blocks");

    struct cbae_cp_impl *p = calloc(1, sizeof(*p));
    if (!p) CBAE_RETURN_ERR(CBAE_ERR_OOM, "const prop: alloc failed");
    p->nvals = ud->value_count;
    p->nblocks = nb;
    p->ninsn = ud->insn_count;
    p->owner = ud->value_by_id;
    const size_t nv = p->nvals ? p->nvals : 1, ni = p->ninsn ? p->ninsn : 1;
    p->kind      = calloc(nv, 1);
    p->val       = calloc(nv, sizeof(uint64_t));
    p->bexec     = calloc(nb, 1);
    p->eexec     = calloc((size_t)nb * 2, 1);
    p->bstack    = malloc(sizeof(uint32_t) * nb);
    p->istack    = malloc(sizeof(uint32_t) * ni);
    p->in_istack = calloc(ni, 1);
    if (!p->kind || !p->val || !p->bexec || !p->eexec || !p->bstack || !p->istack || !p->in_istack) {
        impl_free(p);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "const prop: state alloc failed");
    }

    mark_block(p, 0);
    while (p->bsp || p->isp) {
        while (p->isp) {
            const uint32_t id = p->istack[--p->isp];
            p->in_istack[id] = 0;
            const uint32_t b = ud->insn_block[id];
            if (p->bexec[b]) eval_insn(p, ud, ud->insn_by_id[id], b);
        }
        if (p->bsp) visit_block(p, ud, p->bstack[--p->bsp]);
    }

    LOG_DEBUG("const prop: %u values, %u blocks", p->nvals, nb);
    out->ud = ud;
    out->impl = p;
    return CBAE_OK;
}

void cbae_const_prop_destroy(cbae_const_prop_t *cp) {
    if (!cp) return;
    impl_free(cp->impl);
    memset(cp, 0, sizeof(*cp));
}

cbae_cp_value_t cbae_const_prop_value(const cbae_const_prop_t *cp, const cbae_cir_value_t *v) {
    cbae_cp_value_t r = { CBAE_CP_VARYING, 0 };
    if (!cp || !cp->impl || !v) return r;
    if (v->kind == CIR_VAL_CONST) {
        if (bits_of(v) == 0) return r;
        r.kind = CBAE_CP_CONSTANT;
        r.value = (uint64_t)v->u.const_val & wmask(bits_of(v));
        return r;
    }
    if (v->kind != CIR_VAL_INSN_RESULT || !owned(cp->impl, v))
        return r;                                   /* parameters, placeholders, foreign values */
    switch (cp->impl->kind[v->id]) {
        case LAT_TOP:   r.kind = CBAE_CP_UNREACHED; break;
        case LAT_CONST: r.kind = CBAE_CP_CONSTANT; r.value = cp->impl->val[v->id]; break;
        default:        break;
    }
    return r;
}

bool cbae_const_prop_is_constant(const cbae_const_prop_t *cp, const cbae_cir_value_t *v, uint64_t *out) {
    const cbae_cp_value_t r = cbae_const_prop_value(cp, v);
    if (r.kind != CBAE_CP_CONSTANT) return false;
    if (out) *out = r.value;
    return true;
}

bool cbae_const_prop_block_executable(const cbae_const_prop_t *cp, uint32_t block_id) {
    return cp && cp->impl && block_id < cp->impl->nblocks && cp->impl->bexec[block_id];
}

bool cbae_const_prop_edge_executable(const cbae_const_prop_t *cp, uint32_t from, uint32_t to) {
    if (!cp || !cp->impl) return false;
    return edge_open(cp->impl, cp->ud->func, from, to);
}
