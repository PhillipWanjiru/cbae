/**
 * @file reaching_stores.c
 * @brief Reaching stores. The model, the precision limits and the soundness
 *        claim are documented in reaching_stores.h; this file is the how.
 *
 * BUILD, in order
 *   1. scan       every write to memory becomes a definition (numbered by
 *                 block, then position); every LOAD and every well-formed
 *                 STORE becomes an access with its decomposed address.
 *   2. classes    stable accesses with identical (size, offset, atoms) are
 *                 grouped by sorting; each group is a class.
 *   3. bits       one bit per definition, one universal "initial content"
 *                 bit, and per class an E bit (if it has a load) and an F bit
 *                 (if it has a load and a store).
 *   4. summaries  a sequential pass over each block yields its KILL and GEN
 *                 vectors, composed instruction by instruction.
 *   5. solve      forward may-analysis on the shared engine; the IN vector of
 *                 every block is kept.
 *
 * STATE LAYOUT (bit index)
 *       [0, def_count)      definition bits
 *       def_count           E_universal: "the function's entry state reaches here"
 *       then                per class: E (initial content possible), F
 *                           (a barrier ran after the class's last store)
 *   A class with loads and no stores has nothing that could clear its E bit,
 *   so it shares E_universal.
 *
 * EFFECT OF ONE INSTRUCTION  (state' = (state & ~kill) | gen)
 *       barrier         gen  {itself} + every F bit              kill  nothing
 *       store, class c  gen  {itself}                            kill  every store
 *                       of the class, E_c, F_c
 *       store, no class gen  {itself}                            kill  nothing
 *   Block 0 additionally starts with every E bit set: IN[0] | ALL_E.
 */
#include "dataflow/reaching_stores.h"
#include "dataflow/dataflow_engine.h"
#include "platform/logging.h"
#include "platform/memory.h"
#include <stdlib.h>
#include <string.h>

#define NONE UINT32_MAX

/* Arena the solver gets on the first attempt is sized for this many values
 * per block; a failure doubles it up to the cap, so a pathological function
 * costs time, not a wrong answer. */
#define RS_ARENA_VALUES_PER_BLOCK 12u
#define RS_ARENA_MAX_BYTES        ((size_t)1 << 30)

/* ── Opcode classification ────────────────────────────────────────────── */

cbae_rs_opclass_t cbae_rs_classify_opcode(cbae_cir_opcode_t op) {
    switch (op) {
        case CIR_OP_LOAD: case CIR_OP_LEA:
        case CIR_OP_MMIO_READ: case CIR_OP_PORT_READ: case CIR_OP_MSR_READ:
        case CIR_OP_PCI_CONFIG_READ:
        case CIR_OP_ADD: case CIR_OP_SUB: case CIR_OP_MUL: case CIR_OP_DIV:
        case CIR_OP_AND: case CIR_OP_OR:  case CIR_OP_XOR:
        case CIR_OP_NOT: case CIR_OP_NEG:
        case CIR_OP_SHL: case CIR_OP_SHR: case CIR_OP_SAR:
        case CIR_OP_CMP: case CIR_OP_TEST:
        case CIR_OP_COPY: case CIR_OP_PHI:
        case CIR_OP_BRANCH: case CIR_OP_JUMP: case CIR_OP_RETURN:
            return CBAE_RS_OP_READONLY;
        case CIR_OP_STORE:
            return CBAE_RS_OP_STORE;
        default:
            return CBAE_RS_OP_BARRIER;
    }
}

/* A STORE we can reason about: address and value both present. */
static bool well_formed_store(const cbae_cir_instruction_t *in) {
    return in->opcode == CIR_OP_STORE && in->operand_count >= 2 &&
           in->operands[0] && in->operands[1];
}

/* ── Private data ─────────────────────────────────────────────────────── */

typedef struct rs_access {
    const cbae_cir_instruction_t *insn;
    cbae_addr_info_t              info;      /* valid when `known`                      */
    uint32_t                      size;      /* bytes; 0 = unknown; always set          */
    uint32_t                      cls;       /* class id, or NONE                       */
    uint32_t                      def;       /* definition index (stores) or NONE       */
    bool                          is_store;
    bool                          known;     /* `info` is valid (address present)       */
    bool                          stable;    /* known, usable size, stable atoms        */
} rs_access_t;

typedef struct rs_class {
    uint32_t e_bit;          /* NONE if the class has no load                           */
    uint32_t f_bit;          /* NONE unless the class has both loads and stores         */
    uint32_t store_first;    /* its stores: class_stores[store_first .. +store_count)   */
    uint32_t store_count;
    uint32_t load_count;
} rs_class_t;

struct cbae_rs_impl {
    uint32_t        block_count;
    uint32_t        insn_count;
    uint32_t        words;                   /* 64-bit words per state vector           */

    uint32_t        def_count;
    cbae_rs_def_t  *defs;                    /* [def_count]                             */
    uint32_t       *first_def;               /* [block_count + 1]: block b owns defs
                                              * first_def[b] .. first_def[b+1]-1        */
    uint32_t       *acc_of_def;              /* [def_count] access index, NONE: barrier */
    uint32_t       *def_of_insn;             /* [insn_count] definition index or NONE   */

    uint32_t        access_count;
    rs_access_t    *acc;                     /* [access_count]                          */
    uint32_t       *acc_of_insn;             /* [insn_count] access index or NONE       */

    uint32_t        class_count;
    rs_class_t     *classes;                 /* [class_count]                           */
    uint32_t       *class_stores;            /* definition indices, grouped by class    */

    uint32_t        e_universal;             /* bit index                               */
    uint64_t       *in;                      /* [block_count * words], block 0 includes ALL_E */
};

static void impl_free(struct cbae_rs_impl *p) {
    if (!p) return;
    free(p->defs);
    free(p->first_def);
    free(p->acc_of_def);
    free(p->def_of_insn);
    free(p->acc);
    free(p->acc_of_insn);
    free(p->classes);
    free(p->class_stores);
    free(p->in);
    free(p);
}

/* ── Bit vectors ──────────────────────────────────────────────────────── */

static inline uint32_t ctz64(uint64_t x) {        /* x != 0 */
#if defined(__GNUC__) || defined(__clang__)
    return (uint32_t)__builtin_ctzll(x);
#else
    uint32_t n = 0;
    while (!(x & 1u)) { x >>= 1; n++; }
    return n;
#endif
}

static inline bool bit_test(const uint64_t *w, uint32_t i) { return (w[i >> 6] >> (i & 63u)) & 1u; }
static inline void bit_set(uint64_t *w, uint32_t i)        { w[i >> 6] |= 1ull << (i & 63u); }
static inline void bit_clear(uint64_t *w, uint32_t i)      { w[i >> 6] &= ~(1ull << (i & 63u)); }

static inline const cbae_cir_block_t *block_at(const cbae_cir_function_t *f, uint32_t b) {
    return *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, b);
}

static bool owns_insn(const cbae_use_def_t *ud, const cbae_cir_instruction_t *insn) {
    return ud && insn && insn->id < ud->insn_count && ud->insn_by_id[insn->id] == insn;
}

/* Can the two accesses touch a common byte? Anything not proved disjoint can. */
static bool may_overlap(const cbae_alias_ctx_t *alias, const rs_access_t *a, const rs_access_t *b) {
    if (!a->known || !b->known) return true;
    return cbae_alias_query_info(alias, &a->info, a->size, &b->info, b->size) != CBAE_ALIAS_NO;
}

/* ── Step 1: scan ─────────────────────────────────────────────────────── */

static void init_access(rs_access_t *a, const cbae_alias_ctx_t *alias,
                        const cbae_cir_instruction_t *insn, bool is_store, uint32_t def) {
    memset(a, 0, sizeof(*a));
    a->insn     = insn;
    a->is_store = is_store;
    a->def      = def;
    a->cls      = NONE;

    const cbae_cir_value_t *addr = NULL;
    uint32_t size = 0;
    if (!cbae_alias_mem_access(insn, &addr, &size)) return;
    a->size = size;
    if (!addr || !cbae_alias_decompose(alias, addr, &a->info)) return;
    a->known = true;
    a->stable = size != CBAE_ALIAS_UNKNOWN_SIZE && size <= CBAE_ALIAS_MAX_ACCESS_SIZE &&
                cbae_alias_query_info(alias, &a->info, size, &a->info, size) == CBAE_ALIAS_MUST;
}

static cbae_err_t scan(struct cbae_rs_impl *p, const cbae_use_def_t *ud,
                       const cbae_alias_ctx_t *alias) {
    const cbae_cir_function_t *f = ud->func;
    const uint32_t nb = p->block_count;

    uint32_t ndefs = 0, naccess = 0;
    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = block_at(f, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            if (in->opcode == CIR_OP_LOAD) { naccess++; continue; }
            switch (cbae_rs_classify_opcode(in->opcode)) {
                case CBAE_RS_OP_READONLY: break;
                case CBAE_RS_OP_STORE:
                    ndefs++;
                    if (well_formed_store(in)) naccess++;
                    break;
                case CBAE_RS_OP_BARRIER:  ndefs++; break;
            }
        }
    }

    const size_t ni = p->insn_count ? p->insn_count : 1;
    p->defs        = malloc(sizeof(*p->defs)       * (ndefs ? ndefs : 1));
    p->first_def   = malloc(sizeof(uint32_t)       * ((size_t)nb + 1));
    p->acc_of_def  = malloc(sizeof(uint32_t)       * (ndefs ? ndefs : 1));
    p->def_of_insn = malloc(sizeof(uint32_t)       * ni);
    p->acc         = malloc(sizeof(*p->acc)        * (naccess ? naccess : 1));
    p->acc_of_insn = malloc(sizeof(uint32_t)       * ni);
    if (!p->defs || !p->first_def || !p->acc_of_def || !p->def_of_insn || !p->acc || !p->acc_of_insn)
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "reaching stores: scan arrays alloc failed");
    for (size_t i = 0; i < ni; i++) p->def_of_insn[i] = p->acc_of_insn[i] = NONE;

    for (uint32_t b = 0; b < nb; b++) {
        const cbae_cir_block_t *blk = block_at(f, b);
        p->first_def[b] = p->def_count;
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const cbae_cir_instruction_t *in = blk->instructions[i];
            if (in->opcode == CIR_OP_LOAD) {
                p->acc_of_insn[in->id] = p->access_count;
                init_access(&p->acc[p->access_count++], alias, in, false, NONE);
                continue;
            }
            const cbae_rs_opclass_t oc = cbae_rs_classify_opcode(in->opcode);
            if (oc == CBAE_RS_OP_READONLY) continue;

            const uint32_t k = p->def_count++;
            p->def_of_insn[in->id] = k;
            p->defs[k].insn       = in;
            p->defs[k].block_id   = b;
            p->defs[k].is_barrier = !(oc == CBAE_RS_OP_STORE && well_formed_store(in));
            p->acc_of_def[k]      = NONE;
            if (!p->defs[k].is_barrier) {
                p->acc_of_def[k]       = p->access_count;
                p->acc_of_insn[in->id] = p->access_count;
                init_access(&p->acc[p->access_count++], alias, in, true, k);
            }
        }
    }
    p->first_def[nb] = p->def_count;
    return CBAE_OK;
}

/* ── Step 2: classes ──────────────────────────────────────────────────── */

static int key_cmp(const rs_access_t *a, const rs_access_t *b) {
    if (a->size != b->size) return a->size < b->size ? -1 : 1;
    if (a->info.offset != b->info.offset) return a->info.offset < b->info.offset ? -1 : 1;
    if (a->info.term_count != b->info.term_count)
        return a->info.term_count < b->info.term_count ? -1 : 1;
    for (uint32_t k = 0; k < a->info.term_count; k++) {
        const uint32_t va = a->info.terms[k].value->id, vb = b->info.terms[k].value->id;
        if (va != vb) return va < vb ? -1 : 1;
        if (a->info.terms[k].coeff != b->info.terms[k].coeff)
            return a->info.terms[k].coeff < b->info.terms[k].coeff ? -1 : 1;
    }
    return 0;
}

static int sort_cmp(const void *pa, const void *pb) {
    const rs_access_t *a = *(const rs_access_t *const *)pa;
    const rs_access_t *b = *(const rs_access_t *const *)pb;
    const int c = key_cmp(a, b);
    if (c) return c;
    return a->insn->id < b->insn->id ? -1 : a->insn->id > b->insn->id ? 1 : 0;
}

static cbae_err_t build_classes(struct cbae_rs_impl *p) {
    uint32_t nstable = 0;
    for (uint32_t i = 0; i < p->access_count; i++) nstable += p->acc[i].stable;
    if (nstable == 0) return CBAE_OK;

    rs_access_t **order = malloc(sizeof(*order) * nstable);
    if (!order) CBAE_RETURN_ERR(CBAE_ERR_OOM, "reaching stores: class sort alloc failed");
    uint32_t n = 0;
    for (uint32_t i = 0; i < p->access_count; i++)
        if (p->acc[i].stable) order[n++] = &p->acc[i];
    qsort(order, nstable, sizeof(*order), sort_cmp);

    uint32_t ncls = 0;
    for (uint32_t i = 0; i < nstable; i++)
        if (i == 0 || key_cmp(order[i - 1], order[i]) != 0) ncls++;

    p->classes = calloc(ncls, sizeof(*p->classes));
    if (!p->classes) { free(order); CBAE_RETURN_ERR(CBAE_ERR_OOM, "reaching stores: class alloc failed"); }
    p->class_count = ncls;

    uint32_t c = NONE, nstores = 0;
    for (uint32_t i = 0; i < nstable; i++) {
        if (i == 0 || key_cmp(order[i - 1], order[i]) != 0) c++;
        order[i]->cls = c;
        if (order[i]->is_store) { p->classes[c].store_count++; nstores++; }
        else                      p->classes[c].load_count++;
    }
    free(order);

    p->class_stores = malloc(sizeof(uint32_t) * (nstores ? nstores : 1));
    if (!p->class_stores) CBAE_RETURN_ERR(CBAE_ERR_OOM, "reaching stores: class member alloc failed");
    uint32_t off = 0;
    for (uint32_t k = 0; k < ncls; k++) {
        p->classes[k].store_first = off;
        off += p->classes[k].store_count;
        p->classes[k].store_count = 0;          /* refilled below */
    }
    for (uint32_t i = 0; i < p->access_count; i++) {           /* accesses are in definition order */
        const rs_access_t *a = &p->acc[i];
        if (a->stable && a->is_store) {
            rs_class_t *cl = &p->classes[a->cls];
            p->class_stores[cl->store_first + cl->store_count++] = a->def;
        }
    }
    return CBAE_OK;
}

/* ── Steps 3-5: bits, summaries, solve ────────────────────────────────── */

typedef struct rs_solve {
    uint32_t         words;
    uint32_t         e_universal;   /* bit: "the entry state arrives here" = reachable   */
    const uint64_t  *kill;          /* [block_count * words]                             */
    const uint64_t  *gen;
    const uint64_t  *all_e;         /* [words]                                           */
} rs_solve_t;

static void *op_init(cbae_arena_t *arena, void *ud) {
    const rs_solve_t *s = ud;
    return cbae_arena_alloc(arena, (size_t)s->words * 8, 8);        /* zeroed by the arena */
}

static void *op_meet(cbae_arena_t *arena, void *a, void *b, void *ud) {
    const rs_solve_t *s = ud;
    uint64_t *r = cbae_arena_alloc(arena, (size_t)s->words * 8, 8);
    if (!r) return NULL;
    const uint64_t *x = a, *y = b;
    for (uint32_t w = 0; w < s->words; w++) r[w] = x[w] | y[w];
    return r;
}

static void *op_transfer(cbae_arena_t *arena, uint32_t block_id, void *in, void *ud) {
    const rs_solve_t *s = ud;
    uint64_t *r = cbae_arena_alloc(arena, (size_t)s->words * 8, 8);
    if (!r) return NULL;
    const uint64_t *i = in;
    const uint64_t *k = s->kill + (size_t)block_id * s->words;
    const uint64_t *g = s->gen  + (size_t)block_id * s->words;
    /* A block the entry does not reach never runs, so it passes nothing on. Its
     * E_universal bit says so: it is set at the entry, killed by nothing, and
     * so arrives exactly where some path from the entry does. (The arena
     * returns zeroed memory.) */
    if (block_id != 0 && !bit_test(i, s->e_universal)) return r;
    for (uint32_t w = 0; w < s->words; w++) {
        uint64_t v = i[w];
        if (block_id == 0) v |= s->all_e[w];
        r[w] = (v & ~k[w]) | g[w];
    }
    return r;
}

static bool op_equals(void *a, void *b, void *ud) {
    const rs_solve_t *s = ud;
    return memcmp(a, b, (size_t)s->words * 8) == 0;
}

static cbae_err_t solve(struct cbae_rs_impl *p, const cbae_use_def_t *ud) {
    const uint32_t nb = p->block_count;

    /* Bit numbering. */
    uint64_t nbits = p->def_count;
    p->e_universal = (uint32_t)nbits++;
    for (uint32_t c = 0; c < p->class_count; c++) {
        rs_class_t *cl = &p->classes[c];
        cl->e_bit = cl->f_bit = NONE;
        if (cl->load_count) {
            if (cl->store_count) { cl->e_bit = (uint32_t)nbits++; cl->f_bit = (uint32_t)nbits++; }
            else                   cl->e_bit = p->e_universal;
        }
        if (nbits > CBAE_RS_MAX_STATE_BITS) break;
    }
    if (nbits > CBAE_RS_MAX_STATE_BITS || (uint64_t)nb * nbits > CBAE_RS_MAX_STATE_BITS)
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW,
            "reaching stores: %u blocks x %llu state bits exceeds the limit of %u",
            nb, (unsigned long long)nbits, (unsigned)CBAE_RS_MAX_STATE_BITS);
    p->words = (uint32_t)((nbits + 63) / 64);
    const uint32_t W = p->words;

    uint64_t *kill  = calloc((size_t)nb * W, 8);
    uint64_t *gen   = calloc((size_t)nb * W, 8);
    uint64_t *all_e = calloc(W, 8);
    uint64_t *all_f = calloc(W, 8);
    uint32_t *stamp = calloc(p->class_count ? p->class_count : 1, sizeof(uint32_t));
    uint32_t *last  = calloc(p->class_count ? p->class_count : 1, sizeof(uint32_t));
    p->in = calloc((size_t)nb * W, 8);
    cbae_err_t rc = CBAE_OK;
    if (!kill || !gen || !all_e || !all_f || !stamp || !last || !p->in) {
        rc = CBAE_ERR_OOM;
        CBAE_SET_ERR(rc, "reaching stores: state alloc failed (%u blocks, %u words)", nb, W);
        goto done;
    }

    bit_set(all_e, p->e_universal);
    for (uint32_t c = 0; c < p->class_count; c++) {
        const rs_class_t *cl = &p->classes[c];
        if (cl->e_bit != NONE && cl->e_bit != p->e_universal) bit_set(all_e, cl->e_bit);
        if (cl->f_bit != NONE) bit_set(all_f, cl->f_bit);
    }

    /* Block summaries: compose each instruction's effect in order. */
    for (uint32_t b = 0; b < nb; b++) {
        uint64_t *K = kill + (size_t)b * W, *G = gen + (size_t)b * W;
        const cbae_cir_block_t *blk = block_at(ud->func, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            const uint32_t k = p->def_of_insn[blk->instructions[i]->id];
            if (k == NONE) continue;
            if (p->defs[k].is_barrier) {
                bit_set(G, k);
                for (uint32_t w = 0; w < W; w++) G[w] |= all_f[w];
                continue;
            }
            const rs_access_t *s = &p->acc[p->acc_of_def[k]];
            if (s->cls != NONE) {
                const rs_class_t *cl = &p->classes[s->cls];
                if (stamp[s->cls] != b + 1) {
                    /* First store of this class in the block: it kills every
                     * store of the class, and the class's E and F bits. Nothing
                     * of the class can be in GEN yet except a barrier's F bit. */
                    stamp[s->cls] = b + 1;
                    for (uint32_t m = 0; m < cl->store_count; m++)
                        bit_set(K, p->class_stores[cl->store_first + m]);
                    if (cl->e_bit != NONE) bit_set(K, cl->e_bit);
                } else {
                    bit_clear(G, last[s->cls]);          /* the earlier store of this block */
                }
                if (cl->f_bit != NONE) { bit_set(K, cl->f_bit); bit_clear(G, cl->f_bit); }
                last[s->cls] = k;
            }
            bit_set(G, k);
        }
    }

    /* Solve, growing the arena if the first guess was too small. */
    rs_solve_t sc = { W, p->e_universal, kill, gen, all_e };
    const cbae_dataflow_ops_t ops = { op_init, op_meet, op_transfer, op_equals };
    size_t cap = ((size_t)nb * RS_ARENA_VALUES_PER_BLOCK + 16) * ((size_t)W * 8 + 8) +
                 (size_t)nb * 16 + 4096;
    for (;;) {
        if (cap > RS_ARENA_MAX_BYTES) cap = RS_ARENA_MAX_BYTES;
        cbae_arena_t arena;
        rc = cbae_arena_init(&arena, cap);
        if (rc != CBAE_OK) goto done;
        cbae_dataflow_result_t res;
        rc = cbae_dataflow_run(ud->func, CBAE_DATAFLOW_FORWARD, &ops, &sc, &arena, &res);
        if (rc == CBAE_OK) {
            for (uint32_t b = 0; b < nb; b++)
                memcpy(p->in + (size_t)b * W, res.in_values[b], (size_t)W * 8);
            cbae_arena_destroy(&arena);
            break;
        }
        cbae_arena_destroy(&arena);
        if (rc != CBAE_ERR_OOM || cap >= RS_ARENA_MAX_BYTES) goto done;
        cap *= 2;
    }
    for (uint32_t w = 0; w < W; w++) p->in[w] |= all_e[w];       /* block 0: entry content */

    LOG_DEBUG("reaching stores: %u blocks, %u defs, %u accesses, %u classes, %u words/state",
              nb, p->def_count, p->access_count, p->class_count, W);
done:
    free(kill); free(gen); free(all_e); free(all_f); free(stamp); free(last);
    return rc;
}

/* ── Public API: build / destroy / inspect ────────────────────────────── */

cbae_err_t cbae_reaching_stores_build(const cbae_use_def_t *ud,
                                      const cbae_alias_ctx_t *alias,
                                      cbae_reaching_stores_t *out) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "reaching stores: null output");
    memset(out, 0, sizeof(*out));
    if (!ud || !alias || alias->ud != ud)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID,
            "reaching stores: needs a use-def index and an alias context built from it");

    const uint32_t nb = (uint32_t)cbae_vector_count(&ud->func->blocks);
    if (nb == 0) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "reaching stores: function has no blocks");

    struct cbae_rs_impl *p = calloc(1, sizeof(*p));
    if (!p) CBAE_RETURN_ERR(CBAE_ERR_OOM, "reaching stores: alloc failed");
    p->block_count = nb;
    p->insn_count  = ud->insn_count;

    cbae_err_t rc = scan(p, ud, alias);
    if (rc == CBAE_OK) rc = build_classes(p);
    if (rc == CBAE_OK) rc = solve(p, ud);
    if (rc != CBAE_OK) { impl_free(p); return rc; }

    out->ud    = ud;
    out->alias = alias;
    out->impl  = p;
    return CBAE_OK;
}

void cbae_reaching_stores_destroy(cbae_reaching_stores_t *rs) {
    if (!rs) return;
    impl_free(rs->impl);
    memset(rs, 0, sizeof(*rs));
}

uint32_t cbae_reaching_stores_def_count(const cbae_reaching_stores_t *rs) {
    return rs && rs->impl ? rs->impl->def_count : 0;
}

const cbae_rs_def_t *cbae_reaching_stores_def(const cbae_reaching_stores_t *rs, uint32_t index) {
    if (!rs || !rs->impl || index >= rs->impl->def_count) return NULL;
    return &rs->impl->defs[index];
}

const cbae_rs_def_t *cbae_reaching_stores_def_of(const cbae_reaching_stores_t *rs,
                                                 const cbae_cir_instruction_t *insn) {
    if (!rs || !rs->impl || !owns_insn(rs->ud, insn)) return NULL;
    const uint32_t k = rs->impl->def_of_insn[insn->id];
    return k == NONE ? NULL : &rs->impl->defs[k];
}

/* ── Queries ──────────────────────────────────────────────────────────── */

/* Queue the predecessors of `blk` that have not been queued before. */
static void push_preds(uint32_t nb, const cbae_cir_block_t *blk, uint64_t *visited,
                       uint32_t *stack, uint32_t *sp) {
    const uint32_t npred = (uint32_t)cbae_vector_count(&blk->predecessors);
    for (uint32_t j = 0; j < npred; j++) {
        const uint32_t pr = *(const uint32_t *)cbae_vector_at(&blk->predecessors, j);
        if (pr >= nb || bit_test(visited, pr)) continue;
        bit_set(visited, pr);
        stack[(*sp)++] = pr;
    }
}

/* Every definition found walking BACKWARDS along CFG edges from the top of
 * block `b`, never past a store of class `cls`. A block is scanned from its
 * last definition upward; if it holds a store of the class the scan ends at
 * that store (which is recorded) and the walk does not continue through the
 * block. A block is scanned once, so a loop body entered through its back edge
 * is scanned in full, including the part after the load. `wr` receives the
 * definitions; `visited` (one bit per block) must be zeroed and `stack` has one
 * slot per block. Returns false, with `wr` incomplete, if the work budget runs
 * out. */
static bool walk_back(const struct cbae_rs_impl *p, const cbae_cir_function_t *f, uint32_t b,
                      uint32_t cls, uint64_t *wr, uint64_t *visited, uint32_t *stack) {
    const uint32_t nb = p->block_count;
    int64_t budget = CBAE_RS_WALK_BUDGET;
    uint32_t sp = 0;

    push_preds(nb, block_at(f, b), visited, stack, &sp);
    while (sp > 0) {
        const uint32_t x = stack[--sp];
        const cbae_cir_block_t *blk = block_at(f, x);
        budget -= 1 + (int64_t)cbae_vector_count(&blk->predecessors);
        bool stopped = false;
        for (uint32_t k = p->first_def[x + 1]; k-- > p->first_def[x]; ) {
            if (--budget < 0) return false;
            bit_set(wr, k);
            if (!p->defs[k].is_barrier && p->acc[p->acc_of_def[k]].cls == cls) { stopped = true; break; }
        }
        if (budget < 0) return false;
        if (!stopped) push_preds(nb, blk, visited, stack, &sp);
    }
    return true;
}

cbae_err_t cbae_reaching_stores_for_load(const cbae_reaching_stores_t *rs,
                                         const cbae_cir_instruction_t *load,
                                         const cbae_rs_def_t **out, uint32_t capacity,
                                         uint32_t *count, bool *may_be_initial) {
    uint32_t n_ignored; bool init_ignored;
    if (!count) count = &n_ignored;
    if (!may_be_initial) may_be_initial = &init_ignored;
    *count = 0;
    *may_be_initial = false;

    if (!rs || !rs->impl || !load || load->opcode != CIR_OP_LOAD || !owns_insn(rs->ud, load))
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "reaching stores: not a LOAD of the indexed function");
    const struct cbae_rs_impl *p = rs->impl;
    const uint32_t b   = cbae_use_def_block_of(rs->ud, load);
    const uint32_t pos = cbae_use_def_pos_of(rs->ud, load);
    const uint32_t ai  = p->acc_of_insn[load->id];
    if (b == CBAE_USE_DEF_NO_BLOCK || ai == NONE)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "reaching stores: load is not placed in a block");
    const rs_access_t *L = &p->acc[ai];
    const uint32_t nb = p->block_count;
    const uint32_t W  = p->words;
    if (!bit_test(p->in + (size_t)b * W, p->e_universal))
        return CBAE_OK;                      /* no path from the entry reaches the load: nothing runs, count 0 */
    const uint32_t Wc = (p->class_count + 63) / 64;
    const uint32_t Wb = (nb + 63) / 64;

    /* Scratch, in one piece:
     *   res      the answer, one bit per definition
     *   cand     definitions from earlier blocks that survived the cheap tests
     *   wr       what the backward walk found
     *   seen     classes stored to between a definition under test and the load
     *   visited  blocks the walk has queued               (bits, zeroed)
     *   stack    the walk's work list, one slot per block (not zeroed)          */
    uint64_t stackbuf[256];
    uint64_t *scratch = stackbuf;
    const size_t zeroed = (size_t)W * 3 + Wc + Wb;
    const size_t need = zeroed + ((size_t)nb + 1) / 2;
    if (need > sizeof(stackbuf) / sizeof(stackbuf[0])) {
        scratch = malloc(need * 8);
        if (!scratch) CBAE_RETURN_ERR(CBAE_ERR_OOM, "reaching stores: query scratch alloc failed");
    }
    memset(scratch, 0, zeroed * 8);
    uint64_t *res = scratch, *cand = res + W, *wr = cand + W, *seen = wr + W, *visited = seen + Wc;
    uint32_t *stack = (uint32_t *)(visited + Wb);

    const cbae_cir_block_t *blk = block_at(rs->ud->func, b);
    bool covered = false;

    /* The instructions before the load, nearest first. */
    for (uint32_t j = pos; j-- > 0; ) {
        const uint32_t k = p->def_of_insn[blk->instructions[j]->id];
        if (k == NONE) continue;
        if (p->defs[k].is_barrier) { bit_set(res, k); continue; }
        const rs_access_t *s = &p->acc[p->acc_of_def[k]];
        if (s->cls != NONE) {
            if (bit_test(seen, s->cls)) continue;       /* a later store of its class killed it */
            bit_set(seen, s->cls);
        }
        if (may_overlap(rs->alias, s, L)) bit_set(res, k);
        if (L->cls != NONE && s->cls == L->cls) { covered = true; break; }
    }

    if (!covered) {
        /* Definitions that arrive at the top of the block. */
        const uint64_t *in_b = p->in + (size_t)b * W;
        const uint32_t fb = L->cls != NONE ? p->classes[L->cls].f_bit : NONE;
        const uint32_t eb = L->cls != NONE ? p->classes[L->cls].e_bit : p->e_universal;
        bool any = false;

        for (uint32_t w = 0; w * 64 < p->def_count; w++) {
            uint64_t bits = in_b[w];
            while (bits) {
                const uint32_t k = w * 64 + ctz64(bits);
                bits &= bits - 1;
                if (k >= p->def_count) break;
                if (p->defs[k].is_barrier) {
                    if (fb == NONE || bit_test(in_b, fb)) { bit_set(cand, k); any = true; }
                    continue;
                }
                const rs_access_t *s = &p->acc[p->acc_of_def[k]];
                if (s->cls != NONE && bit_test(seen, s->cls)) continue;   /* killed in this block */
                if (may_overlap(rs->alias, s, L)) { bit_set(cand, k); any = true; }
            }
        }
        *may_be_initial = bit_test(in_b, eb);

        /* The dataflow bits say a definition reaches the block along SOME path
         * and a barrier ran after the class's last store along SOME path. If
         * the load's own class is ever stored to, a definition that can only
         * get here by passing such a store is not the last writer: walk
         * backwards from the block, stopping at those stores, and keep only
         * what the walk finds. Skipped when the class is never stored to (no
         * store to stop at) or the walk exceeds its budget. */
        if (any && fb != NONE &&
            walk_back(p, rs->ud->func, b, L->cls, wr, visited, stack))
            for (uint32_t w = 0; w < W; w++) cand[w] &= wr[w];
        for (uint32_t w = 0; w < W; w++) res[w] |= cand[w];
    }

    uint32_t total = 0;
    for (uint32_t w = 0; w < W; w++) {
        uint64_t bits = res[w];
        while (bits) {
            const uint32_t k = w * 64 + ctz64(bits);
            bits &= bits - 1;
            if (out && total < capacity) out[total] = &p->defs[k];
            total++;
        }
    }
    *count = total;
    if (scratch != stackbuf) free(scratch);
    return CBAE_OK;
}

bool cbae_reaching_stores_forwardable(const cbae_reaching_stores_t *rs,
                                      const cbae_cir_instruction_t *load,
                                      const cbae_cir_instruction_t **store) {
    const cbae_rs_def_t *defs[2];
    uint32_t n = 0;
    bool initial = false;
    if (cbae_reaching_stores_for_load(rs, load, defs, 2, &n, &initial) != CBAE_OK) return false;
    if (n != 1 || initial || defs[0]->is_barrier) return false;

    /* The two tests below cannot fail here: initial content is excluded only by a
     * store of the load's own class, which is then in the answer, so the single
     * definition is that store, and a store of the same class is MUST. (A load the
     * entry cannot reach has an empty answer.) They are kept because the
     * documented contract is the conjunction, not the argument that it
     * collapses. */
    const struct cbae_rs_impl *p = rs->impl;
    const rs_access_t *s = &p->acc[p->acc_of_insn[defs[0]->insn->id]];
    const rs_access_t *l = &p->acc[p->acc_of_insn[load->id]];
    if (!s->known || !l->known ||
        cbae_alias_query_info(rs->alias, &s->info, s->size, &l->info, l->size) != CBAE_ALIAS_MUST)
        return false;
    if (store) *store = defs[0]->insn;
    return true;
}

bool cbae_reaching_stores_may_reach(const cbae_reaching_stores_t *rs,
                                    const cbae_cir_instruction_t *at,
                                    const cbae_cir_instruction_t *def) {
    if (!rs || !rs->impl || !owns_insn(rs->ud, at) || !owns_insn(rs->ud, def)) return false;
    const struct cbae_rs_impl *p = rs->impl;
    const uint32_t kd = p->def_of_insn[def->id];
    const uint32_t b  = cbae_use_def_block_of(rs->ud, at);
    const uint32_t pos = cbae_use_def_pos_of(rs->ud, at);
    if (kd == NONE || b == CBAE_USE_DEF_NO_BLOCK) return false;
    if (!bit_test(p->in + (size_t)b * p->words, p->e_universal)) return false;     /* `at` never runs */

    bool live = bit_test(p->in + (size_t)b * p->words, kd);
    /* Replay the block's effects before `at`, tracking only this definition:
     * itself sets it; a later store of its class clears it. */
    const uint32_t cd = p->defs[kd].is_barrier ? NONE : p->acc[p->acc_of_def[kd]].cls;
    const cbae_cir_block_t *blk = block_at(rs->ud->func, b);
    for (uint32_t j = 0; j < pos; j++) {
        const uint32_t k = p->def_of_insn[blk->instructions[j]->id];
        if (k == NONE) continue;
        if (k == kd) live = true;
        else if (cd != NONE && !p->defs[k].is_barrier && p->acc[p->acc_of_def[k]].cls == cd)
            live = false;
    }
    return live;
}
