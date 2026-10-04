/**
 * @file use_def.c
 * @brief Use-def chain construction. See use_def.h for the model.
 *
 * Two passes over every instruction, sharing one traversal:
 *   pass 1 (count): how many uses does each value have?
 *   pass 2 (fill):  prefix-sum those counts into CSR offsets, then place
 *                   each use at its slot.
 * Sizing the arrays exactly means no per-value allocation and no
 * reallocation, and use lists come out contiguous.
 */
#include "dataflow/use_def.h"
#include "platform/logging.h"
#include <stdlib.h>
#include <string.h>

static void free_arrays(cbae_use_def_t *ud) {
    free(ud->value_by_id);
    free(ud->use_off);
    free(ud->uses);
    free(ud->insn_by_id);
    free(ud->insn_block);
    free(ud->insn_pos);
    memset(ud, 0, sizeof(*ud));
}

void cbae_use_def_destroy(cbae_use_def_t *ud) {
    if (ud) free_arrays(ud);
}

/* Record one use of `v` (or, when counting, just tally it). */
static cbae_err_t record_use(cbae_use_def_t *ud, uint32_t *cursor, bool fill,
                             const cbae_cir_value_t *v,
                             cbae_cir_instruction_t *insn, uint32_t block_id,
                             uint32_t index, cbae_use_kind_t kind) {
    if (!v || v->id >= ud->value_count || ud->value_by_id[v->id] != v)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID,
            "use-def: block%u insn#%u %s %u references a value this function "
            "never defined", block_id, insn->id,
            kind == CBAE_USE_PHI_INCOMING ? "phi incoming" : "operand", index);

    if (!fill) {
        ud->use_off[v->id + 1]++;
    } else {
        cbae_use_t *u = &ud->uses[cursor[v->id]++];
        u->insn     = insn;
        u->block_id = block_id;
        u->index    = index;
        u->kind     = kind;
    }
    return CBAE_OK;
}

static cbae_err_t scan_uses(cbae_use_def_t *ud, uint32_t *cursor, bool fill) {
    const uint32_t nblocks = (uint32_t)cbae_vector_count(&ud->func->blocks);
    for (uint32_t b = 0; b < nblocks; b++) {
        const cbae_cir_block_t *blk =
            *(cbae_cir_block_t **)cbae_vector_at(&ud->func->blocks, b);
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            cbae_cir_instruction_t *insn = blk->instructions[i];

            if (insn->opcode == CIR_OP_PHI) {
                for (uint32_t k = 0; k < insn->phi_incoming_count; k++)
                    CBAE_CHECK(record_use(ud, cursor, fill, insn->phi_incoming_values[k],
                                          insn, blk->id, k, CBAE_USE_PHI_INCOMING));
            } else {
                for (uint32_t oi = 0; oi < insn->operand_count; oi++) {
                    if (!insn->operands[oi]) continue;
                    CBAE_CHECK(record_use(ud, cursor, fill, insn->operands[oi],
                                          insn, blk->id, oi, CBAE_USE_OPERAND));
                }
            }
        }
    }
    return CBAE_OK;
}

cbae_err_t cbae_use_def_build(const cbae_cir_function_t *func, cbae_use_def_t *out) {
    if (!func || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "use-def: null argument");

    memset(out, 0, sizeof(*out));
    out->func        = func;
    out->value_count = func->next_value_id;
    out->insn_count  = func->next_insn_id;

    /* Sizes are at least 1 so a function with no values/instructions
     * still gets valid (if empty) arrays. */
    const size_t nv = out->value_count ? out->value_count : 1;
    const size_t ni = out->insn_count  ? out->insn_count  : 1;

    out->value_by_id = calloc(nv, sizeof(cbae_cir_value_t *));
    out->use_off     = calloc(nv + 1, sizeof(uint32_t));
    out->insn_by_id  = calloc(ni, sizeof(cbae_cir_instruction_t *));
    out->insn_block  = malloc(ni * sizeof(uint32_t));
    out->insn_pos    = malloc(ni * sizeof(uint32_t));
    uint32_t *cursor = malloc(nv * sizeof(uint32_t));
    if (!out->value_by_id || !out->use_off || !out->insn_by_id ||
        !out->insn_block || !out->insn_pos || !cursor) {
        free(cursor);
        free_arrays(out);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "use-def: array alloc failed");
    }
    for (size_t i = 0; i < ni; i++) {
        out->insn_block[i] = CBAE_USE_DEF_NO_BLOCK;
        out->insn_pos[i]   = CBAE_USE_DEF_NO_POS;
    }

    /* Index values by id. */
    const uint32_t nvalues = (uint32_t)cbae_vector_count(&func->values);
    for (uint32_t i = 0; i < nvalues; i++) {
        cbae_cir_value_t *v = *(cbae_cir_value_t **)cbae_vector_at(&func->values, i);
        if (v->id >= out->value_count || out->value_by_id[v->id]) {
            free(cursor);
            uint32_t bad = v->id;
            free_arrays(out);
            CBAE_RETURN_ERR(CBAE_ERR_INVALID,
                "use-def: value id %u is out of range or duplicated", bad);
        }
        out->value_by_id[v->id] = v;
    }

    /* Index instructions by id, and record where each one lives. */
    const uint32_t nblocks = (uint32_t)cbae_vector_count(&func->blocks);
    for (uint32_t b = 0; b < nblocks; b++) {
        const cbae_cir_block_t *blk = *(cbae_cir_block_t **)cbae_vector_at(&func->blocks, b);
        if (blk->id != b) {
            free(cursor);
            free_arrays(out);
            CBAE_RETURN_ERR(CBAE_ERR_INVALID,
                "use-def: block at index %u has id %u (ids must equal indices)", b, blk->id);
        }
        for (uint32_t i = 0; i < blk->instruction_count; i++) {
            cbae_cir_instruction_t *insn = blk->instructions[i];
            if (insn->id >= out->insn_count || out->insn_by_id[insn->id]) {
                free(cursor);
                uint32_t bad = insn->id;
                free_arrays(out);
                CBAE_RETURN_ERR(CBAE_ERR_INVALID,
                    "use-def: instruction id %u is out of range or duplicated", bad);
            }
            out->insn_by_id[insn->id] = insn;
            out->insn_block[insn->id] = b;
            out->insn_pos[insn->id]   = i;
        }
    }

    /* Pass 1: count uses per value. */
    cbae_err_t rc = scan_uses(out, NULL, false);
    if (rc != CBAE_OK) { free(cursor); free_arrays(out); return rc; }

    for (uint32_t i = 0; i < out->value_count; i++)
        out->use_off[i + 1] += out->use_off[i];
    const uint32_t total = out->use_off[out->value_count];

    out->uses = malloc(sizeof(cbae_use_t) * (total ? total : 1));
    if (!out->uses) {
        free(cursor);
        free_arrays(out);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "use-def: use array alloc failed");
    }

    /* Pass 2: place each use at its slot. */
    for (uint32_t i = 0; i < out->value_count; i++) cursor[i] = out->use_off[i];
    rc = scan_uses(out, cursor, true);
    free(cursor);
    if (rc != CBAE_OK) { free_arrays(out); return rc; }

    LOG_DEBUG("use-def built: %u values, %u instructions, %u uses",
              out->value_count, out->insn_count, total);
    return CBAE_OK;
}

/* True if `v` is one of the indexed function's own values. A pointer from
 * another function can carry an in-range id, so the id alone is not
 * enough -- compare the pointer too. */
static bool owns_value(const cbae_use_def_t *ud, const cbae_cir_value_t *v) {
    return ud && v && v->id < ud->value_count && ud->value_by_id[v->id] == v;
}

cbae_use_list_t cbae_use_def_uses(const cbae_use_def_t *ud, const cbae_cir_value_t *v) {
    cbae_use_list_t l = { NULL, 0 };
    if (!owns_value(ud, v)) return l;
    l.count = ud->use_off[v->id + 1] - ud->use_off[v->id];
    if (l.count) l.uses = &ud->uses[ud->use_off[v->id]];
    return l;
}

/* Same check for instructions. */
static bool owns_insn(const cbae_use_def_t *ud, const cbae_cir_instruction_t *insn) {
    return ud && insn && insn->id < ud->insn_count && ud->insn_by_id[insn->id] == insn;
}

uint32_t cbae_use_def_block_of(const cbae_use_def_t *ud, const cbae_cir_instruction_t *insn) {
    return owns_insn(ud, insn) ? ud->insn_block[insn->id] : CBAE_USE_DEF_NO_BLOCK;
}

uint32_t cbae_use_def_pos_of(const cbae_use_def_t *ud, const cbae_cir_instruction_t *insn) {
    return owns_insn(ud, insn) ? ud->insn_pos[insn->id] : CBAE_USE_DEF_NO_POS;
}

uint32_t cbae_use_def_def_block(const cbae_use_def_t *ud, const cbae_cir_value_t *v) {
    if (!owns_value(ud, v)) return CBAE_USE_DEF_NO_BLOCK;
    switch (v->kind) {
        case CIR_VAL_INSN_RESULT:
            return cbae_use_def_block_of(ud, v->u.def_insn);
        case CIR_VAL_PARAM:
        case CIR_VAL_CONST:
            return 0;
        default:
            return CBAE_USE_DEF_NO_BLOCK;
    }
}

uint32_t cbae_use_point_block(const cbae_use_t *use) {
    if (use->kind == CBAE_USE_PHI_INCOMING)
        return use->insn->phi_incoming_blocks[use->index];
    return use->block_id;
}
