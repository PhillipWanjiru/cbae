/**
 * @file dataflow_engine.c
 * @brief Generic iterative worklist dataflow solver. Contract, equations
 *        and memory model are documented in dataflow_engine.h.
 *
 * TWO ARRAYS, TWO ROLES -- the part that is easy to get wrong
 *   For each block the solver keeps two slots, and which of IN/OUT each
 *   one is depends on the direction:
 *
 *                      meet_side            xfer_side
 *      FORWARD         in_values            out_values
 *      BACKWARD        out_values           in_values
 *
 *   meet_side[b] is REASSIGNED on every visit of b, straight from the
 *   fresh meet over b's feeders (predecessors, forward / successors,
 *   backward). It is never compared against anything.
 *
 *   xfer_side[b] is the value that other blocks READ and that the
 *   fixed-point test watches. It starts as init_value() and is replaced
 *   only when transfer() produces something not equal to the current
 *   one, at which point b's dependents (successors, forward /
 *   predecessors, backward) are re-queued.
 *
 *   The two must never share an array: comparing the newly transferred
 *   value against a slot that was just overwritten with the meet result
 *   would compare the block against its own input.
 */
#include "dataflow/dataflow_engine.h"
#include "platform/vector.h"
#include "platform/logging.h"
#include <stdlib.h>
#include <string.h>

typedef struct solver {
    const cbae_cir_function_t *func;
    const cbae_dataflow_ops_t *ops;
    void          *userdata;
    cbae_arena_t  *arena;
    bool           forward;
    uint32_t       n;

    void         **meet_side;  /* see file comment */
    void         **xfer_side;

    bool          *pending;    /* [block_id] -> currently on the stack   */
    cbae_vector_t  stack;      /* uint32_t block ids, used as a LIFO     */
} solver_t;

/* ── CFG edge access, direction-agnostic ──────────────────────────────── */

/* use_preds=true  -> walk b's predecessors (vector of uint32_t)
 * use_preds=false -> walk b's successors   (fixed array)               */
static uint32_t edge_count(const cbae_cir_block_t *b, bool use_preds) {
    return use_preds ? (uint32_t)cbae_vector_count(&b->predecessors)
                     : b->successor_count;
}

static uint32_t edge_id(const cbae_cir_block_t *b, bool use_preds, uint32_t k) {
    if (use_preds) {
        const uint32_t *p = cbae_vector_at(&b->predecessors, k);
        return *p;
    }
    return b->successors[k];
}

static cbae_err_t check_id(const solver_t *s, const cbae_cir_block_t *b,
                            uint32_t other) {
    if (other >= s->n)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID,
            "dataflow: block %u references block %u, but the function has "
            "only %u blocks (corrupt CFG edge)", b->id, other, s->n);
    return CBAE_OK;
}

/* ── One block visit ──────────────────────────────────────────────────── */

/* Fold meet() over the transfer-side values of every feeder of `blk`.
 * No feeders: the boundary value, init_value(). */
static cbae_err_t compute_near_value(solver_t *s, const cbae_cir_block_t *blk,
                                      void **out_val) {
    const bool use_preds = s->forward;      /* feeders */
    const uint32_t cnt = edge_count(blk, use_preds);

    void *acc = NULL;
    for (uint32_t k = 0; k < cnt; k++) {
        uint32_t fid = edge_id(blk, use_preds, k);
        CBAE_CHECK(check_id(s, blk, fid));

        void *v = s->xfer_side[fid];
        if (!acc) {
            acc = v;
        } else {
            acc = s->ops->meet(s->arena, acc, v, s->userdata);
            if (!acc)
                CBAE_RETURN_ERR(CBAE_ERR_OOM,
                    "dataflow: meet() failed at block %u (arena exhausted?)",
                    blk->id);
        }
    }

    if (!acc) {
        acc = s->ops->init_value(s->arena, s->userdata);
        if (!acc)
            CBAE_RETURN_ERR(CBAE_ERR_OOM,
                "dataflow: init_value() failed at block %u (arena exhausted?)",
                blk->id);
    }

    *out_val = acc;
    return CBAE_OK;
}

static cbae_err_t requeue_dependents(solver_t *s, const cbae_cir_block_t *blk) {
    const bool use_preds = !s->forward;     /* dependents */
    const uint32_t cnt = edge_count(blk, use_preds);

    for (uint32_t k = 0; k < cnt; k++) {
        uint32_t did = edge_id(blk, use_preds, k);
        CBAE_CHECK(check_id(s, blk, did));
        if (!s->pending[did]) {
            s->pending[did] = true;
            CBAE_CHECK(cbae_vector_push(&s->stack, &did));
        }
    }
    return CBAE_OK;
}

/* ── The solver loop ──────────────────────────────────────────────────── */

static cbae_err_t solve(solver_t *s) {
    const cbae_dataflow_ops_t *ops = s->ops;

    for (uint32_t i = 0; i < s->n; i++) {
        s->xfer_side[i] = ops->init_value(s->arena, s->userdata);
        if (!s->xfer_side[i])
            CBAE_RETURN_ERR(CBAE_ERR_OOM,
                "dataflow: init_value() failed (arena exhausted?)");
    }

    /* Prime the stack with every block. LIFO, so the LAST push pops
     * FIRST: forward pushes n-1..0 (block 0 pops first, then roughly
     * increasing id, which tracks program order); backward pushes
     * 0..n-1 (highest id first). Only speed depends on this. */
    if (s->forward) {
        for (uint32_t i = s->n; i-- > 0; ) {
            s->pending[i] = true;
            CBAE_CHECK(cbae_vector_push(&s->stack, &i));
        }
    } else {
        for (uint32_t i = 0; i < s->n; i++) {
            s->pending[i] = true;
            CBAE_CHECK(cbae_vector_push(&s->stack, &i));
        }
    }

    const uint64_t budget = (uint64_t)s->n * CBAE_DATAFLOW_VISIT_BUDGET_PER_BLOCK;
    uint64_t visits = 0;

    while (cbae_vector_count(&s->stack) > 0) {
        uint32_t b;
        CBAE_CHECK(cbae_vector_pop(&s->stack, &b));
        s->pending[b] = false;

        if (++visits > budget)
            CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW,
                "dataflow: no fixed point after %llu block visits over %u "
                "blocks -- transfer() is not monotone or the value lattice "
                "has unbounded height",
                (unsigned long long)(visits - 1), s->n);

        cbae_cir_block_t *blk =
            *(cbae_cir_block_t **)cbae_vector_at(&s->func->blocks, b);

        void *near_val;
        CBAE_CHECK(compute_near_value(s, blk, &near_val));
        s->meet_side[b] = near_val;

        void *new_val = ops->transfer(s->arena, b, near_val, s->userdata);
        if (!new_val)
            CBAE_RETURN_ERR(CBAE_ERR_OOM,
                "dataflow: transfer() failed at block %u (arena exhausted?)", b);

        if (!ops->equals(new_val, s->xfer_side[b], s->userdata)) {
            s->xfer_side[b] = new_val;
            CBAE_CHECK(requeue_dependents(s, blk));
        }
    }

    LOG_DEBUG("dataflow: %s fixed point, %llu visits over %u blocks",
              s->forward ? "forward" : "backward",
              (unsigned long long)visits, s->n);
    return CBAE_OK;
}

/* ── Public API ───────────────────────────────────────────────────────── */

cbae_err_t cbae_dataflow_run(const cbae_cir_function_t *func,
                             cbae_dataflow_direction_t direction,
                             const cbae_dataflow_ops_t *ops,
                             void *userdata,
                             cbae_arena_t *arena,
                             cbae_dataflow_result_t *out) {
    if (!func || !ops || !arena || !out)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "dataflow: null argument");
    if (!ops->init_value || !ops->meet || !ops->transfer || !ops->equals)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID,
            "dataflow: ops must supply init_value, meet, transfer and equals");
    if (direction != CBAE_DATAFLOW_FORWARD && direction != CBAE_DATAFLOW_BACKWARD)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "dataflow: invalid direction %d",
                        (int)direction);

    memset(out, 0, sizeof(*out));
    const uint32_t n = (uint32_t)cbae_vector_count(&func->blocks);
    if (n == 0)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "dataflow: function has no blocks");

    out->block_count = n;
    out->in_values   = CBAE_ARENA_ALLOC_N(arena, void *, n);
    out->out_values  = CBAE_ARENA_ALLOC_N(arena, void *, n);
    if (!out->in_values || !out->out_values)
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "dataflow: result array alloc failed");

    solver_t s;
    memset(&s, 0, sizeof(s));
    s.func      = func;
    s.ops       = ops;
    s.userdata  = userdata;
    s.arena     = arena;
    s.forward   = (direction == CBAE_DATAFLOW_FORWARD);
    s.n         = n;
    s.meet_side = s.forward ? out->in_values  : out->out_values;
    s.xfer_side = s.forward ? out->out_values : out->in_values;

    s.pending = calloc(n, sizeof(bool));
    if (!s.pending)
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "dataflow: pending-flag alloc failed");

    cbae_err_t rc = cbae_vector_init(&s.stack, sizeof(uint32_t), n);
    if (rc != CBAE_OK) {
        free(s.pending);
        return rc;
    }

    rc = solve(&s);

    cbae_vector_destroy(&s.stack);
    free(s.pending);
    return rc;
}
