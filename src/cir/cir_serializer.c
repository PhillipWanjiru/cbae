/**
 * @file cir_serializer.c
 * @brief CIR -> binary blob and back.
 *
 * FORMAT (native layout, see cir_serializer.h for the scope decision):
 *
 *   Header:    magic(u32) version(u32) entry_addr(u64) name(128 bytes)
 *              block_count(u32) value_count(u32)
 *   Values:    [value_count] * { id(u32) kind(u8) type_kind(u8) payload }
 *              payload depends on kind: CONST=int64, PARAM=u8 reg,
 *              INSN_RESULT=u32 defining-instruction-id
 *   Blocks:    [block_count] * { id(u32) start_addr(u64)
 *              pred_count(u32) preds(u32[]) succ_count(u32) succs(u32[])
 *              instruction_count(u32) }
 *   Instructions, per block in the same order: { id(u32) opcode(u8)
 *              result_value_id(u32, UINT32_MAX=none) operand_count(u8)
 *              operand_value_ids(u32[]) source_addr(u64)
 *              call_name_len(u16) call_name_bytes[]
 *              branch_true_block(u32) branch_false_block(u32)
 *              phi_incoming_count(u32) phi pairs: (value_id(u32) block_id(u32))[] }
 *
 * DESERIALIZATION IS THREE-PASS because values, instructions, and
 * blocks all cross-reference each other by numeric id:
 *   Pass 1: create every value (INSN_RESULT payload -- the defining
 *           instruction id -- is stashed in a side table, not yet a
 *           real pointer, since no instruction exists yet).
 *   Pass 2: create every block and every instruction (operand/result
 *           references resolved immediately via the value-id map built
 *           in pass 1, which is already complete).
 *   Pass 3: patch every INSN_RESULT value's def_insn pointer using the
 *           instruction-id map built in pass 2.
 */
#include "cir/cir_serializer.h"
#include "cir/cir_builder.h"
#include "platform/hashmap.h"
#include <stdlib.h>
#include <string.h>

#define CIR_SERIAL_MAGIC   0x52494243u  /* "CBIR" little-endian */
#define CIR_SERIAL_VERSION 1u
#define CIR_NO_VALUE       0xFFFFFFFFu

typedef struct wbuf {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} wbuf_t;

static bool wbuf_init(wbuf_t *w, size_t initial_cap) {
    w->data = malloc(initial_cap);
    w->len  = 0;
    w->cap  = w->data ? initial_cap : 0;
    return w->data != NULL;
}

static bool wbuf_ensure(wbuf_t *w, size_t more) {
    if (w->len + more <= w->cap) return true;
    size_t new_cap = w->cap ? w->cap * 2 : 256;
    while (new_cap < w->len + more) new_cap *= 2;
    uint8_t *p = realloc(w->data, new_cap);
    if (!p) return false;
    w->data = p;
    w->cap  = new_cap;
    return true;
}

static bool wbuf_write(wbuf_t *w, const void *src, size_t n) {
    if (!wbuf_ensure(w, n)) return false;
    memcpy(w->data + w->len, src, n);
    w->len += n;
    return true;
}
#define WPUT(w, val) wbuf_write((w), &(val), sizeof(val))

typedef struct rbuf {
    const uint8_t *data;
    size_t         len;
    size_t         pos;
    bool           ok;
} rbuf_t;

static bool rbuf_read(rbuf_t *r, void *dst, size_t n) {
    if (!r->ok || r->pos + n > r->len) { r->ok = false; return false; }
    memcpy(dst, r->data + r->pos, n);
    r->pos += n;
    return true;
}
#define RGET(r, val) rbuf_read((r), &(val), sizeof(val))

cbae_err_t cbae_cir_serialize_function(const cbae_cir_function_t *f,
                                        uint8_t **out_buf, size_t *out_size) {
    if (!f || !out_buf || !out_size) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    wbuf_t w;
    if (!wbuf_init(&w, 4096)) CBAE_RETURN_ERR(CBAE_ERR_OOM, "wbuf init failed");

    uint32_t magic = CIR_SERIAL_MAGIC, version = CIR_SERIAL_VERSION;
    uint32_t nblocks = (uint32_t)cbae_vector_count(&f->blocks);
    uint32_t nvalues = (uint32_t)cbae_vector_count(&f->values);
    char name[128];
    memset(name, 0, sizeof(name));
    strncpy(name, f->name, sizeof(name) - 1);

    if (!WPUT(&w, magic) || !WPUT(&w, version) || !WPUT(&w, f->entry_addr) ||
        !wbuf_write(&w, name, sizeof(name)) ||
        !WPUT(&w, nblocks) || !WPUT(&w, nvalues)) {
        free(w.data);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "header write failed");
    }

    for (uint32_t i = 0; i < nvalues; i++) {
        cbae_cir_value_t **vp = cbae_vector_at(&f->values, i);
        cbae_cir_value_t *v = *vp;
        uint8_t kind = (uint8_t)v->kind, type_kind = (uint8_t)v->type.kind;
        if (!WPUT(&w, v->id) || !WPUT(&w, kind) || !WPUT(&w, type_kind)) goto fail;

        switch (v->kind) {
            case CIR_VAL_CONST:
                if (!WPUT(&w, v->u.const_val)) goto fail;
                break;
            case CIR_VAL_PARAM: {
                uint8_t reg = (uint8_t)v->u.param_reg;
                if (!WPUT(&w, reg)) goto fail;
                break;
            }
            case CIR_VAL_INSN_RESULT: {
                uint32_t insn_id = v->u.def_insn->id;
                if (!WPUT(&w, insn_id)) goto fail;
                break;
            }
            case CIR_VAL_REG_ENTRY: {
                uint8_t reg = (uint8_t)v->u.reg_entry.reg;
                uint32_t blk = v->u.reg_entry.block_id;
                if (!WPUT(&w, reg) || !WPUT(&w, blk)) goto fail;
                break;
            }
            default: break;
        }
    }

    for (uint32_t bi = 0; bi < nblocks; bi++) {
        cbae_cir_block_t **bp = cbae_vector_at(&f->blocks, bi);
        cbae_cir_block_t *blk = *bp;
        uint32_t npred = (uint32_t)cbae_vector_count(&blk->predecessors);

        if (!WPUT(&w, blk->id) || !WPUT(&w, blk->start_addr) || !WPUT(&w, npred))
            goto fail;
        for (uint32_t pi = 0; pi < npred; pi++) {
            uint32_t *p = cbae_vector_at(&blk->predecessors, pi);
            if (!WPUT(&w, *p)) goto fail;
        }
        if (!WPUT(&w, blk->successor_count)) goto fail;
        for (uint32_t si = 0; si < blk->successor_count; si++)
            if (!WPUT(&w, blk->successors[si])) goto fail;
        if (!WPUT(&w, blk->instruction_count)) goto fail;
    }

    for (uint32_t bi = 0; bi < nblocks; bi++) {
        cbae_cir_block_t **bp = cbae_vector_at(&f->blocks, bi);
        cbae_cir_block_t *blk = *bp;

        for (uint32_t ii = 0; ii < blk->instruction_count; ii++) {
            cbae_cir_instruction_t *insn = blk->instructions[ii];
            uint8_t opcode = (uint8_t)insn->opcode;
            uint32_t result_id = insn->result ? insn->result->id : CIR_NO_VALUE;

            if (!WPUT(&w, insn->id) || !WPUT(&w, opcode) || !WPUT(&w, result_id) ||
                !WPUT(&w, insn->operand_count))
                goto fail;
            for (uint8_t oi = 0; oi < insn->operand_count; oi++) {
                uint32_t vid = insn->operands[oi] ? insn->operands[oi]->id : CIR_NO_VALUE;
                if (!WPUT(&w, vid)) goto fail;
            }
            if (!WPUT(&w, insn->source_addr)) goto fail;

            uint16_t name_len = insn->call_target_name
                ? (uint16_t)strlen(insn->call_target_name) : 0;
            if (!WPUT(&w, name_len)) goto fail;
            if (name_len && !wbuf_write(&w, insn->call_target_name, name_len))
                goto fail;

            if (!WPUT(&w, insn->branch_true_block) || !WPUT(&w, insn->branch_false_block))
                goto fail;

            if (!WPUT(&w, insn->phi_incoming_count)) goto fail;
            for (uint32_t pi = 0; pi < insn->phi_incoming_count; pi++) {
                uint32_t vid = insn->phi_incoming_values[pi]
                    ? insn->phi_incoming_values[pi]->id : CIR_NO_VALUE;
                uint32_t bid = insn->phi_incoming_blocks[pi];
                if (!WPUT(&w, vid) || !WPUT(&w, bid)) goto fail;
            }
        }
    }

    *out_buf  = w.data;
    *out_size = w.len;
    return CBAE_OK;

fail:
    free(w.data);
    CBAE_RETURN_ERR(CBAE_ERR_OOM, "serialize: write buffer growth failed");
}

cbae_err_t cbae_cir_deserialize_function(const uint8_t *buf, size_t size,
                                          cbae_arena_t *arena,
                                          cbae_cir_function_t **out) {
    if (!buf || !arena || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    rbuf_t r = { .data = buf, .len = size, .pos = 0, .ok = true };

    uint32_t magic, version;
    cbae_addr_t entry_addr;
    char name[128];
    uint32_t nblocks, nvalues;

    if (!RGET(&r, magic) || magic != CIR_SERIAL_MAGIC)
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "deserialize: bad magic");
    if (!RGET(&r, version) || version != CIR_SERIAL_VERSION)
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "deserialize: unsupported version");
    if (!RGET(&r, entry_addr) || !rbuf_read(&r, name, sizeof(name)) ||
        !RGET(&r, nblocks) || !RGET(&r, nvalues))
        CBAE_RETURN_ERR(CBAE_ERR_PARSE, "deserialize: truncated header");

    cbae_cir_function_t *func;
    CBAE_CHECK(cbae_cir_function_create(arena, entry_addr, name, &func));

    cbae_hashmap_t value_map, insn_map;
    if (cbae_hashmap_init(&value_map, 64) != CBAE_OK ||
        cbae_hashmap_init(&insn_map, 64) != CBAE_OK) {
        cbae_cir_function_destroy(func);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "deserialize: hashmap init failed");
    }

    cbae_hashmap_t pending_def_insn;
    cbae_hashmap_init(&pending_def_insn, 32);

    for (uint32_t i = 0; i < nvalues; i++) {
        uint32_t id; uint8_t kind, type_kind;
        if (!RGET(&r, id) || !RGET(&r, kind) || !RGET(&r, type_kind)) goto parse_fail;

        cbae_cir_value_t *v = CBAE_ARENA_ALLOC(arena, cbae_cir_value_t);
        if (!v) goto oom_fail;
        v->id = id;
        v->kind = (cbae_cir_value_kind_t)kind;
        v->type.kind = (cbae_cir_type_kind_t)type_kind;

        switch (v->kind) {
            case CIR_VAL_CONST:
                if (!RGET(&r, v->u.const_val)) goto parse_fail;
                break;
            case CIR_VAL_PARAM: {
                uint8_t reg;
                if (!RGET(&r, reg)) goto parse_fail;
                v->u.param_reg = (cbae_reg_t)reg;
                break;
            }
            case CIR_VAL_INSN_RESULT: {
                uint32_t insn_id;
                if (!RGET(&r, insn_id)) goto parse_fail;
                v->u.def_insn = NULL;
                cbae_hashmap_insert(&pending_def_insn, (uint64_t)id, (void *)(uintptr_t)insn_id);
                break;
            }
            case CIR_VAL_REG_ENTRY: {
                uint8_t reg; uint32_t blk;
                if (!RGET(&r, reg) || !RGET(&r, blk)) goto parse_fail;
                v->u.reg_entry.reg = (cbae_reg_t)reg;
                v->u.reg_entry.block_id = blk;
                break;
            }
            default: break;
        }

        cbae_vector_push(&func->values, &v);
        cbae_hashmap_insert(&value_map, (uint64_t)id, v);
        if (id >= func->next_value_id) func->next_value_id = id + 1;
    }

    {
        uint32_t *inst_counts = malloc(sizeof(uint32_t) * (nblocks ? nblocks : 1));
        for (uint32_t bi = 0; bi < nblocks; bi++) {
            uint32_t id; cbae_addr_t start_addr; uint32_t npred;
            if (!RGET(&r, id) || !RGET(&r, start_addr) || !RGET(&r, npred)) {
                free(inst_counts); goto parse_fail;
            }

            cbae_cir_block_t *blk;
            if (cbae_cir_block_create(func, start_addr, &blk) != CBAE_OK) {
                free(inst_counts); goto oom_fail;
            }

            for (uint32_t pi = 0; pi < npred; pi++) {
                uint32_t pred_id;
                if (!RGET(&r, pred_id)) { free(inst_counts); goto parse_fail; }
                cbae_vector_push(&blk->predecessors, &pred_id);
            }
            uint32_t nsucc;
            if (!RGET(&r, nsucc)) { free(inst_counts); goto parse_fail; }
            blk->successor_count = nsucc;
            for (uint32_t si = 0; si < nsucc; si++)
                if (!RGET(&r, blk->successors[si])) { free(inst_counts); goto parse_fail; }

            if (!RGET(&r, inst_counts[bi])) { free(inst_counts); goto parse_fail; }
            if (id >= func->next_block_id) func->next_block_id = id + 1;
        }

        for (uint32_t bi = 0; bi < nblocks; bi++) {
            cbae_cir_block_t **bp = cbae_vector_at(&func->blocks, bi);
            cbae_cir_block_t *blk = *bp;
            uint32_t icount = inst_counts[bi];

            cbae_cir_instruction_t **arr =
                CBAE_ARENA_ALLOC_N(arena, cbae_cir_instruction_t *, icount ? icount : 1);
            if (!arr) { free(inst_counts); goto oom_fail; }
            blk->instructions = arr;
            blk->instruction_capacity = icount ? icount : 1;

            for (uint32_t ii = 0; ii < icount; ii++) {
                uint32_t id; uint8_t opcode; uint32_t result_id; uint8_t opcount;
                if (!RGET(&r, id) || !RGET(&r, opcode) || !RGET(&r, result_id) ||
                    !RGET(&r, opcount)) { free(inst_counts); goto parse_fail; }

                cbae_cir_instruction_t *insn = CBAE_ARENA_ALLOC(arena, cbae_cir_instruction_t);
                if (!insn) { free(inst_counts); goto oom_fail; }
                insn->id = id;
                insn->opcode = (cbae_cir_opcode_t)opcode;
                insn->operand_count = opcount;

                for (uint8_t oi = 0; oi < opcount; oi++) {
                    uint32_t vid;
                    if (!RGET(&r, vid)) { free(inst_counts); goto parse_fail; }
                    void *vp = NULL;
                    if (vid != CIR_NO_VALUE) cbae_hashmap_get(&value_map, (uint64_t)vid, &vp);
                    insn->operands[oi] = (cbae_cir_value_t *)vp;
                }
                for (uint8_t oi = opcount; oi < CIR_MAX_OPERANDS; oi++)
                    insn->operands[oi] = NULL;

                if (result_id != CIR_NO_VALUE) {
                    void *vp = NULL;
                    cbae_hashmap_get(&value_map, (uint64_t)result_id, &vp);
                    insn->result = (cbae_cir_value_t *)vp;
                } else {
                    insn->result = NULL;
                }

                if (!RGET(&r, insn->source_addr)) { free(inst_counts); goto parse_fail; }

                uint16_t name_len;
                if (!RGET(&r, name_len)) { free(inst_counts); goto parse_fail; }
                if (name_len) {
                    char *namebuf = CBAE_ARENA_ALLOC_N(arena, char, name_len + 1);
                    if (!namebuf) { free(inst_counts); goto oom_fail; }
                    if (!rbuf_read(&r, namebuf, name_len)) { free(inst_counts); goto parse_fail; }
                    namebuf[name_len] = '\0';
                    insn->call_target_name = namebuf;
                } else {
                    insn->call_target_name = NULL;
                }

                if (!RGET(&r, insn->branch_true_block) || !RGET(&r, insn->branch_false_block))
                    { free(inst_counts); goto parse_fail; }

                uint32_t phi_count;
                if (!RGET(&r, phi_count)) { free(inst_counts); goto parse_fail; }
                insn->phi_incoming_count = phi_count;
                insn->phi_incoming_capacity = phi_count ? phi_count : 1;
                if (phi_count) {
                    insn->phi_incoming_values =
                        CBAE_ARENA_ALLOC_N(arena, cbae_cir_value_t *, phi_count);
                    insn->phi_incoming_blocks =
                        CBAE_ARENA_ALLOC_N(arena, uint32_t, phi_count);
                    if (!insn->phi_incoming_values || !insn->phi_incoming_blocks)
                        { free(inst_counts); goto oom_fail; }
                    for (uint32_t pi = 0; pi < phi_count; pi++) {
                        uint32_t vid, bid;
                        if (!RGET(&r, vid) || !RGET(&r, bid)) { free(inst_counts); goto parse_fail; }
                        void *vp = NULL;
                        if (vid != CIR_NO_VALUE) cbae_hashmap_get(&value_map, (uint64_t)vid, &vp);
                        insn->phi_incoming_values[pi] = (cbae_cir_value_t *)vp;
                        insn->phi_incoming_blocks[pi] = bid;
                    }
                } else {
                    insn->phi_incoming_values = NULL;
                    insn->phi_incoming_blocks = NULL;
                }

                blk->instructions[ii] = insn;
                cbae_hashmap_insert(&insn_map, (uint64_t)id, insn);
                if (id >= func->next_insn_id) func->next_insn_id = id + 1;
            }
            blk->instruction_count = icount;
        }
        free(inst_counts);
    }

    {
        uint32_t nv = (uint32_t)cbae_vector_count(&func->values);
        for (uint32_t i = 0; i < nv; i++) {
            cbae_cir_value_t **vp = cbae_vector_at(&func->values, i);
            cbae_cir_value_t *v = *vp;
            if (v->kind != CIR_VAL_INSN_RESULT) continue;
            void *pending = NULL;
            if (cbae_hashmap_get(&pending_def_insn, (uint64_t)v->id, &pending)) {
                uint32_t insn_id = (uint32_t)(uintptr_t)pending;
                void *ip = NULL;
                cbae_hashmap_get(&insn_map, (uint64_t)insn_id, &ip);
                v->u.def_insn = (cbae_cir_instruction_t *)ip;
            }
        }
    }

    cbae_hashmap_destroy(&value_map);
    cbae_hashmap_destroy(&insn_map);
    cbae_hashmap_destroy(&pending_def_insn);
    *out = func;
    return CBAE_OK;

parse_fail:
    cbae_hashmap_destroy(&value_map);
    cbae_hashmap_destroy(&insn_map);
    cbae_hashmap_destroy(&pending_def_insn);
    cbae_cir_function_destroy(func);
    CBAE_RETURN_ERR(CBAE_ERR_PARSE, "deserialize: truncated or malformed buffer");

oom_fail:
    cbae_hashmap_destroy(&value_map);
    cbae_hashmap_destroy(&insn_map);
    cbae_hashmap_destroy(&pending_def_insn);
    cbae_cir_function_destroy(func);
    CBAE_RETURN_ERR(CBAE_ERR_OOM, "deserialize: allocation failed");
}
