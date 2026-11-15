/**
 * @file cir_serializer.c
 * @brief CIR -> binary blob and back. A blob is untrusted input: see "WHAT A BLOB MUST SATISFY".
 *
 * FORMAT, version 1 (fixed-width fields in the host's byte order, which the build requires to be little-endian):
 *
 *   Header:    magic(u32) version(u32) entry_addr(u64) name(128 bytes) block_count(u32) value_count(u32)
 *   Values:    [value_count] * { id(u32) kind(u8) type_kind(u8) payload }
 *              payload by kind: CONST = int64; PARAM = reg(u8); INSN_RESULT = defining-instruction-id(u32);
 *              REG_ENTRY (the lifter's placeholder, before SSA construction) = reg(u8) block_id(u32)
 *   Blocks:    [block_count] * { id(u32) start_addr(u64) pred_count(u32) preds(u32[]) succ_count(u32) succs(u32[])
 *              instruction_count(u32) }
 *   Instructions, for each block in the order of the blocks:
 *              [instruction_count] * { id(u32) opcode(u8) result_value_id(u32, 0xFFFFFFFF = none) operand_count(u8)
 *              operand_value_ids(u32[], 0xFFFFFFFF = a NULL operand) source_addr(u64) call_name_len(u16)
 *              call_name_bytes[] branch_true_block(u32) branch_false_block(u32) phi_incoming_count(u32)
 *              phi_incoming: [phi_incoming_count] * { value_id(u32, 0xFFFFFFFF = NULL) block_id(u32) } }
 *
 * WHAT A BLOB MUST SATISFY. The deserializer refuses anything else as CBAE_ERR_PARSE and the serializer refuses to
 * write it (CBAE_ERR_INVALID), so whatever is written can be read back, and what is read is what the serializer writes:
 *   - the magic and the version; the name ends in a NUL within its 128 bytes and is zero after it; no byte follows the
 *     last field
 *   - value ids are 0, 1, 2 ... in order; the kind is INSN_RESULT, CONST, PARAM or REG_ENTRY; the type kind and every
 *     register exist; a placeholder's block exists
 *   - block ids are 0, 1, 2 ... in order; a block has at most CIR_BLOCK_MAX_SUCCESSORS successors; predecessors and
 *     successors are blocks
 *   - instruction ids are unique and below the number of instructions (so they are 0 .. n-1 in some order); the
 *     opcode exists; at most CIR_MAX_OPERANDS operands; an operand or phi value is a value of the function or NULL; a
 *     result is the INSN_RESULT value that names this instruction as its definition, and every INSN_RESULT value is the
 *     result of the instruction it names; a branch's targets and a jump's target are blocks; a phi's blocks are blocks;
 *     a call name has no NUL inside and at most 65535 bytes (an empty name is no name)
 *   - counts are never trusted: before records are allocated for a count, the bytes left must be enough for that many
 *     records of the smallest size, so nothing is allocated that the blob itself is not several times larger than.
 * The deserializer's result is safe to walk, print and verify. Whether it is well-formed CIR (SSA, types, operand
 * counts) is the verifier's question: a function that has operands that are NULL, or a phi that misses a
 * predecessor, is a function the format can hold.
 *
 * The deserializer does its work in the order of the blob: values, then block headers (the edges), then instructions,
 * which resolve their operands against the values and claim their results.
 */
#include "cir/cir_serializer.h"
#include "cir/cir_builder.h"
#include "platform/logging.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "the CIR blob is written in the host's byte order and is defined as little-endian");

#define SER_MAGIC        0x52494243u   /* "CBIR" little-endian */
#define SER_VERSION      1u
#define NO_VALUE         0xFFFFFFFFu
#define NAME_FIELD       128u
#define MAX_CALL_NAME    CIR_MAX_CALL_NAME   /* the length field is 16 bits */
#define HEADER_BYTES     (4u + 4u + 8u + NAME_FIELD + 4u + 4u)

/* The smallest record of each kind: a count is possible only if that many such records fit in the bytes that are left. */
#define MIN_VALUE_BYTES  7u            /* id, kind, type, and the least payload (a parameter's register) */
#define MIN_BLOCK_BYTES  24u
#define MIN_INSN_BYTES   32u

static bool valid_reg(unsigned r) { return r <= (unsigned)CBAE_REG_OTHER; }

/* ═════════════════════════════ serializer ═══════════════════════════════ */

typedef struct {
    const cbae_cir_function_t   *f;
    uint32_t                     nvalues, nblocks, ninsns;
    const cbae_cir_instruction_t **by_id;      /* [ninsns] the instruction with each id */
    size_t                       size;         /* the blob's size, summed while checking */
} ser_t;

static cbae_cir_block_t *block_at(const cbae_cir_function_t *f, size_t i) { return *(cbae_cir_block_t **)cbae_vector_at(&f->blocks, i); }
static cbae_cir_value_t *value_at(const cbae_cir_function_t *f, size_t i) { return *(cbae_cir_value_t **)cbae_vector_at(&f->values, i); }

/* A value that is one of the function's own. */
static bool registered(const ser_t *s, const cbae_cir_value_t *v) {
    return v->id < s->nvalues && value_at(s->f, v->id) == v;
}

static size_t payload_bytes(cbae_cir_value_kind_t kind) {
    switch (kind) {
        case CIR_VAL_CONST:       return 8;
        case CIR_VAL_PARAM:       return 1;
        case CIR_VAL_INSN_RESULT: return 4;
        case CIR_VAL_REG_ENTRY:   return 5;
        default:                  return 0;
    }
}

static cbae_err_t check_instruction(ser_t *s, const cbae_cir_instruction_t *in) {
    if (!in) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: a block has an empty instruction slot");
    if (in->id >= s->ninsns || s->by_id[in->id])
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: instruction id %u is repeated or not below the instruction count %u", in->id, s->ninsns);
    s->by_id[in->id] = in;
    if ((unsigned)in->opcode <= (unsigned)CIR_OP_INVALID || (unsigned)in->opcode >= (unsigned)CIR_OP_COUNT)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: instruction %u has the opcode %u, which does not exist", in->id, (unsigned)in->opcode);
    if (in->operand_count > CIR_MAX_OPERANDS)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: instruction %u has %u operands, at most %d", in->id, in->operand_count, CIR_MAX_OPERANDS);
    for (unsigned k = 0; k < in->operand_count; k++)
        if (in->operands[k] && !registered(s, in->operands[k]))
            CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: operand %u of instruction %u is not a value of the function", k, in->id);
    if (in->result && (!registered(s, in->result) || in->result->kind != CIR_VAL_INSN_RESULT || in->result->u.def_insn != in))
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: the result of instruction %u is not a value of the function that it defines", in->id);
    size_t name_len = 0;
    if (in->call_target_name) {
        name_len = strlen(in->call_target_name);
        if (name_len > MAX_CALL_NAME)
            CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "cannot serialize: the call target name of instruction %u is %zu bytes, the format holds %u", in->id, name_len, MAX_CALL_NAME);
    }
    if (in->opcode == CIR_OP_BRANCH && (in->branch_true_block >= s->nblocks || in->branch_false_block >= s->nblocks))
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: a branch (instruction %u) targets a block that does not exist", in->id);
    if (in->opcode == CIR_OP_JUMP && in->branch_true_block >= s->nblocks)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: a jump (instruction %u) targets a block that does not exist", in->id);
    if (in->phi_incoming_count && (!in->phi_incoming_values || !in->phi_incoming_blocks))
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: instruction %u has %u incoming values and no arrays for them", in->id, in->phi_incoming_count);
    for (uint32_t k = 0; k < in->phi_incoming_count; k++) {
        if (in->phi_incoming_values[k] && !registered(s, in->phi_incoming_values[k]))
            CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: incoming value %u of instruction %u is not a value of the function", k, in->id);
        if (in->phi_incoming_blocks[k] >= s->nblocks)
            CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: incoming block %u of instruction %u does not exist", k, in->id);
    }
    s->size += 32 + 4u * in->operand_count + name_len + 8u * (size_t)in->phi_incoming_count;
    return CBAE_OK;
}

static cbae_err_t check_block(ser_t *s, uint32_t index) {
    const cbae_cir_block_t *b = block_at(s->f, index);
    if (!b) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: block slot %u is empty", index);
    if (b->id != index) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: block %u has the id %u (ids must be their indices)", index, b->id);
    if (b->successor_count > CIR_BLOCK_MAX_SUCCESSORS)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: block %u has %u successors, at most %d", index, b->successor_count, CIR_BLOCK_MAX_SUCCESSORS);
    if (b->instruction_count && !b->instructions) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: block %u has %u instructions and no array for them", index, b->instruction_count);
    for (uint32_t k = 0; k < b->successor_count; k++)
        if (b->successors[k] >= s->nblocks)
            CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: successor %u of block %u does not exist", k, index);
    const size_t npred = cbae_vector_count(&b->predecessors);
    for (size_t k = 0; k < npred; k++)
        if (*(const uint32_t *)cbae_vector_at(&b->predecessors, k) >= s->nblocks)
            CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: predecessor %zu of block %u does not exist", k, index);
    s->size += 24 + 4 * npred + 4u * b->successor_count;
    return CBAE_OK;
}

static cbae_err_t check_value(ser_t *s, uint32_t index) {
    const cbae_cir_value_t *v = value_at(s->f, index);
    if (!v) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: value slot %u is empty", index);
    if (v->id != index) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: value %u has the id %u (ids must be their indices)", index, v->id);
    if ((unsigned)v->kind < (unsigned)CIR_VAL_INSN_RESULT || (unsigned)v->kind > (unsigned)CIR_VAL_REG_ENTRY)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: value %u has the kind %u, which does not exist", index, (unsigned)v->kind);
    if ((unsigned)v->type.kind > (unsigned)CIR_TYPE_PTR)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: value %u has the type kind %u, which does not exist", index, (unsigned)v->type.kind);
    switch (v->kind) {
        case CIR_VAL_INSN_RESULT: {
            const cbae_cir_instruction_t *d = v->u.def_insn;
            if (!d) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: value %u is an instruction result with no defining instruction", index);
            if (d->id >= s->ninsns || s->by_id[d->id] != d || d->result != v)
                CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: value %u names an instruction that is not in the function or does not produce it", index);
            break;
        }
        case CIR_VAL_PARAM:
            if (!valid_reg((unsigned)v->u.param_reg)) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: parameter value %u has the register %u, which does not exist", index, (unsigned)v->u.param_reg);
            break;
        case CIR_VAL_REG_ENTRY:
            if (!valid_reg((unsigned)v->u.reg_entry.reg) || v->u.reg_entry.block_id >= s->nblocks)
                CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: placeholder value %u names a register or block that does not exist", index);
            break;
        default: break;
    }
    s->size += 6 + payload_bytes(v->kind);
    return CBAE_OK;
}

/* Checks the whole function against the rules of the format and sums the size of its blob. */
static cbae_err_t check_function(ser_t *s) {
    const cbae_cir_function_t *f = s->f;
    const size_t nvalues = cbae_vector_count(&f->values), nblocks = cbae_vector_count(&f->blocks);
    if (nvalues > UINT32_MAX || nblocks > UINT32_MAX)
        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "cannot serialize: %zu values and %zu blocks, the counts are 32 bits", nvalues, nblocks);
    s->nvalues = (uint32_t)nvalues;
    s->nblocks = (uint32_t)nblocks;
    if (memchr(f->name, '\0', sizeof f->name) == NULL)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "cannot serialize: the function's name has no terminator");

    uint64_t total = 0;
    for (uint32_t i = 0; i < s->nblocks; i++) {
        const cbae_cir_block_t *b = block_at(f, i);
        if (b) total += b->instruction_count;                    /* an empty slot is refused below */
    }
    if (total > UINT32_MAX) CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, "cannot serialize: %llu instructions, the count is 32 bits", (unsigned long long)total);
    s->ninsns = (uint32_t)total;
    if (s->ninsns) {
        s->by_id = calloc(s->ninsns, sizeof *s->by_id);
        if (!s->by_id) CBAE_RETURN_ERR(CBAE_ERR_OOM, "cannot serialize: out of memory for %u instructions", s->ninsns);
    }

    s->size = HEADER_BYTES;
    for (uint32_t i = 0; i < s->nblocks; i++) CBAE_CHECK(check_block(s, i));
    for (uint32_t i = 0; i < s->nblocks; i++) {
        const cbae_cir_block_t *b = block_at(f, i);
        for (uint32_t k = 0; k < b->instruction_count; k++) CBAE_CHECK(check_instruction(s, b->instructions[k]));
    }
    for (uint32_t i = 0; i < s->nvalues; i++) CBAE_CHECK(check_value(s, i));
    return CBAE_OK;
}

typedef struct { uint8_t *p; size_t pos; } wr_t;     /* the buffer is exactly as large as check_function summed */

static void w_bytes(wr_t *w, const void *src, size_t n) { if (n) memcpy(w->p + w->pos, src, n); w->pos += n; }     /* (src is NULL for a call with no name) */
static void w8 (wr_t *w, uint8_t v)  { w_bytes(w, &v, sizeof v); }
static void w16(wr_t *w, uint16_t v) { w_bytes(w, &v, sizeof v); }
static void w32(wr_t *w, uint32_t v) { w_bytes(w, &v, sizeof v); }
static void w64(wr_t *w, uint64_t v) { w_bytes(w, &v, sizeof v); }

static void write_function(const ser_t *s, wr_t *w) {
    const cbae_cir_function_t *f = s->f;
    w32(w, SER_MAGIC);
    w32(w, SER_VERSION);
    w64(w, f->entry_addr);
    uint8_t name[NAME_FIELD] = { 0 };
    memcpy(name, f->name, strlen(f->name));
    w_bytes(w, name, sizeof name);
    w32(w, s->nblocks);
    w32(w, s->nvalues);

    for (uint32_t i = 0; i < s->nvalues; i++) {
        const cbae_cir_value_t *v = value_at(f, i);
        w32(w, v->id);
        w8(w, (uint8_t)v->kind);
        w8(w, (uint8_t)v->type.kind);
        switch (v->kind) {
            case CIR_VAL_CONST:       w64(w, (uint64_t)v->u.const_val); break;
            case CIR_VAL_PARAM:       w8(w, (uint8_t)v->u.param_reg); break;
            case CIR_VAL_INSN_RESULT: w32(w, v->u.def_insn->id); break;
            case CIR_VAL_REG_ENTRY:   w8(w, (uint8_t)v->u.reg_entry.reg); w32(w, v->u.reg_entry.block_id); break;
            default: break;
        }
    }
    for (uint32_t i = 0; i < s->nblocks; i++) {
        const cbae_cir_block_t *b = block_at(f, i);
        w32(w, b->id);
        w64(w, b->start_addr);
        w32(w, (uint32_t)cbae_vector_count(&b->predecessors));
        for (size_t k = 0; k < cbae_vector_count(&b->predecessors); k++) w32(w, *(const uint32_t *)cbae_vector_at(&b->predecessors, k));
        w32(w, b->successor_count);
        for (uint32_t k = 0; k < b->successor_count; k++) w32(w, b->successors[k]);
        w32(w, b->instruction_count);
    }
    for (uint32_t i = 0; i < s->nblocks; i++) {
        const cbae_cir_block_t *b = block_at(f, i);
        for (uint32_t k = 0; k < b->instruction_count; k++) {
            const cbae_cir_instruction_t *in = b->instructions[k];
            w32(w, in->id);
            w8(w, (uint8_t)in->opcode);
            w32(w, in->result ? in->result->id : NO_VALUE);
            w8(w, in->operand_count);
            for (uint8_t o = 0; o < in->operand_count; o++) w32(w, in->operands[o] ? in->operands[o]->id : NO_VALUE);
            w64(w, in->source_addr);
            const size_t name_len = in->call_target_name ? strlen(in->call_target_name) : 0;
            w16(w, (uint16_t)name_len);
            w_bytes(w, in->call_target_name, name_len);
            w32(w, in->branch_true_block);
            w32(w, in->branch_false_block);
            w32(w, in->phi_incoming_count);
            for (uint32_t p = 0; p < in->phi_incoming_count; p++) {
                w32(w, in->phi_incoming_values[p] ? in->phi_incoming_values[p]->id : NO_VALUE);
                w32(w, in->phi_incoming_blocks[p]);
            }
        }
    }
}

cbae_err_t cbae_cir_serialize_function(const cbae_cir_function_t *f, uint8_t **out_buf, size_t *out_size) {
    if (out_buf)  *out_buf = NULL;
    if (out_size) *out_size = 0;
    if (!f || !out_buf || !out_size) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    ser_t s = { .f = f };
    cbae_err_t err = check_function(&s);
    uint8_t *buf = NULL;
    if (err == CBAE_OK) {
        buf = malloc(s.size);
        if (!buf) {
            err = CBAE_ERR_OOM;
            CBAE_SET_ERR(err, "cannot serialize: out of memory for a blob of %zu bytes", s.size);
        }
    }
    if (err == CBAE_OK) {
        wr_t w = { buf, 0 };
        write_function(&s, &w);
        *out_buf = buf;
        *out_size = w.pos;
    }
    free(s.by_id);
    return err;
}

/* ═════════════════════════════ deserializer ═════════════════════════════ */

/* A reader that does not stop at the first short read: it returns 0 and remembers, and the caller checks once per record. */
typedef struct { const uint8_t *p; size_t len, pos; bool bad; } rd_t;

static size_t left(const rd_t *r) { return r->len - r->pos; }

static void rd_bytes(rd_t *r, void *dst, size_t n) {
    if (r->bad || n > left(r)) { r->bad = true; memset(dst, 0, n); return; }
    memcpy(dst, r->p + r->pos, n);
    r->pos += n;
}
static uint8_t  rd8 (rd_t *r) { uint8_t  v; rd_bytes(r, &v, sizeof v); return v; }
static uint16_t rd16(rd_t *r) { uint16_t v; rd_bytes(r, &v, sizeof v); return v; }
static uint32_t rd32(rd_t *r) { uint32_t v; rd_bytes(r, &v, sizeof v); return v; }
static uint64_t rd64(rd_t *r) { uint64_t v; rd_bytes(r, &v, sizeof v); return v; }

typedef struct {
    rd_t                    r;
    cbae_arena_t           *arena;
    cbae_cir_function_t    *f;
    uint32_t                nvalues, nblocks, ninsns;
    uint32_t               *def_of;          /* [nvalues] the defining instruction each INSN_RESULT value names (its pointer comes later) */
    cbae_cir_instruction_t **by_id;          /* [ninsns] the instruction read for each id */
} des_t;

static cbae_err_t parse_error(const des_t *d, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static cbae_err_t parse_error(const des_t *d, const char *fmt, ...) {
    char what[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(what, sizeof what, fmt, ap);
    va_end(ap);
    CBAE_RETURN_ERR(CBAE_ERR_PARSE, "CIR blob: %s (at byte %zu of %zu)", what, d->r.pos, d->r.len);
}

static cbae_err_t truncated(const des_t *d) { return parse_error(d, "truncated"); }

static cbae_err_t no_memory(const char *what) { CBAE_RETURN_ERR(CBAE_ERR_OOM, "CIR blob: out of memory for %s", what); }

static cbae_cir_value_t *vref(const des_t *d, uint32_t id) { return value_at(d->f, id); }

static cbae_err_t read_values(des_t *d) {
    for (uint32_t i = 0; i < d->nvalues; i++) {
        const uint32_t id = rd32(&d->r);
        const uint8_t kind = rd8(&d->r), type = rd8(&d->r);
        if (d->r.bad) return truncated(d);
        if (id != i) return parse_error(d, "value %u has the id %u (ids are 0, 1, 2 ... in order)", i, id);
        if (kind < CIR_VAL_INSN_RESULT || kind > CIR_VAL_REG_ENTRY) return parse_error(d, "value %u has the unknown kind %u", i, kind);
        if (type > CIR_TYPE_PTR) return parse_error(d, "value %u has the unknown type kind %u", i, type);

        cbae_cir_value_t *v = CBAE_ARENA_ALLOC(d->arena, cbae_cir_value_t);
        if (!v) return no_memory("a value");
        v->id = i;
        v->kind = (cbae_cir_value_kind_t)kind;
        v->type.kind = (cbae_cir_type_kind_t)type;
        switch (v->kind) {
            case CIR_VAL_CONST:       v->u.const_val = (int64_t)rd64(&d->r); break;
            case CIR_VAL_PARAM: {
                const uint8_t reg = rd8(&d->r);
                if (!valid_reg(reg)) return parse_error(d, "value %u is a parameter in the register %u, which does not exist", i, reg);
                v->u.param_reg = (cbae_reg_t)reg;
                break;
            }
            case CIR_VAL_INSN_RESULT: d->def_of[i] = rd32(&d->r); break;
            case CIR_VAL_REG_ENTRY: {
                const uint8_t reg = rd8(&d->r);
                const uint32_t block = rd32(&d->r);
                if (d->r.bad) return truncated(d);
                if (!valid_reg(reg)) return parse_error(d, "value %u is a placeholder for the register %u, which does not exist", i, reg);
                if (block >= d->nblocks) return parse_error(d, "value %u is a placeholder in block %u, which does not exist", i, block);
                v->u.reg_entry.reg = (cbae_reg_t)reg;
                v->u.reg_entry.block_id = block;
                break;
            }
            default: break;
        }
        if (d->r.bad) return truncated(d);
        CBAE_CHECK(cbae_vector_push(&d->f->values, &v));          /* the space was reserved: this cannot grow the vector */
    }
    return CBAE_OK;
}

/* The block headers carry the edges; the instruction counts are kept in the blocks until their instructions are read. */
static cbae_err_t read_blocks(des_t *d) {
    uint64_t total = 0;
    for (uint32_t i = 0; i < d->nblocks; i++) {
        const uint32_t id = rd32(&d->r);
        const uint64_t addr = rd64(&d->r);
        const uint32_t npred = rd32(&d->r);
        if (d->r.bad) return truncated(d);
        if (id != i) return parse_error(d, "block %u has the id %u (ids are 0, 1, 2 ... in order)", i, id);
        if (npred > left(&d->r) / 4) return parse_error(d, "block %u has %u predecessors, more than the data can hold", i, npred);

        cbae_cir_block_t *b;
        CBAE_CHECK(cbae_cir_block_create(d->f, addr, &b));
        CBAE_CHECK(cbae_vector_reserve(&b->predecessors, npred));
        for (uint32_t k = 0; k < npred; k++) {
            const uint32_t p = rd32(&d->r);
            if (d->r.bad) return truncated(d);
            if (p >= d->nblocks) return parse_error(d, "block %u has the predecessor %u, which does not exist", i, p);
            CBAE_CHECK(cbae_vector_push(&b->predecessors, &p));
        }
        const uint32_t nsucc = rd32(&d->r);
        if (d->r.bad) return truncated(d);
        if (nsucc > CIR_BLOCK_MAX_SUCCESSORS) return parse_error(d, "block %u has %u successors, at most %d", i, nsucc, CIR_BLOCK_MAX_SUCCESSORS);
        for (uint32_t k = 0; k < nsucc; k++) {
            const uint32_t s = rd32(&d->r);
            if (d->r.bad) return truncated(d);
            if (s >= d->nblocks) return parse_error(d, "block %u has the successor %u, which does not exist", i, s);
            b->successors[k] = s;
        }
        b->successor_count = nsucc;
        b->instruction_count = rd32(&d->r);
        if (d->r.bad) return truncated(d);
        total += b->instruction_count;
    }
    if (total > left(&d->r) / MIN_INSN_BYTES || total > UINT32_MAX) return parse_error(d, "%llu instructions declared, more than the data can hold", (unsigned long long)total);
    d->ninsns = (uint32_t)total;
    if (d->ninsns) {
        d->by_id = calloc(d->ninsns, sizeof *d->by_id);
        if (!d->by_id) return no_memory("the instruction table");
    }
    return CBAE_OK;
}

static cbae_err_t read_instruction(des_t *d, cbae_cir_block_t *blk) {
    rd_t *r = &d->r;
    const uint32_t id = rd32(r);
    const uint8_t opcode = rd8(r);
    const uint32_t result = rd32(r);
    const uint8_t nops = rd8(r);
    if (r->bad) return truncated(d);
    if (id >= d->ninsns || d->by_id[id]) return parse_error(d, "instruction id %u is repeated or not below the instruction count %u", id, d->ninsns);
    if (opcode == CIR_OP_INVALID || opcode >= CIR_OP_COUNT) return parse_error(d, "instruction %u has the unknown opcode %u", id, opcode);
    if (nops > CIR_MAX_OPERANDS) return parse_error(d, "instruction %u has %u operands, at most %d", id, nops, CIR_MAX_OPERANDS);

    uint32_t ops[CIR_MAX_OPERANDS];
    for (uint8_t k = 0; k < nops; k++) {
        ops[k] = rd32(r);
        if (r->bad) return truncated(d);
        if (ops[k] != NO_VALUE && ops[k] >= d->nvalues) return parse_error(d, "instruction %u has the operand %u, which is not a value", id, ops[k]);
    }
    const uint64_t src = rd64(r);
    const uint16_t name_len = rd16(r);
    if (r->bad) return truncated(d);
    if (name_len > left(r)) return parse_error(d, "instruction %u has a call name of %u bytes, more than the data holds", id, name_len);
    const uint8_t *name = r->p + r->pos;
    if (memchr(name, '\0', name_len)) return parse_error(d, "instruction %u has a NUL byte inside its call name", id);
    r->pos += name_len;
    const uint32_t t = rd32(r), f = rd32(r), nphi = rd32(r);
    if (r->bad) return truncated(d);
    if (opcode == CIR_OP_BRANCH && (t >= d->nblocks || f >= d->nblocks)) return parse_error(d, "branch %u targets a block that does not exist", id);
    if (opcode == CIR_OP_JUMP && t >= d->nblocks) return parse_error(d, "jump %u targets a block that does not exist", id);
    if (nphi > left(r) / 8) return parse_error(d, "instruction %u has %u incoming values, more than the data can hold", id, nphi);

    cbae_cir_value_t *res = NULL;
    if (result != NO_VALUE) {
        if (result >= d->nvalues) return parse_error(d, "instruction %u has the result %u, which is not a value", id, result);
        res = vref(d, result);
        if (res->kind != CIR_VAL_INSN_RESULT || d->def_of[result] != id)
            return parse_error(d, "instruction %u has the result %u, which is not defined by it", id, result);
    }

    cbae_cir_instruction_t *in = CBAE_ARENA_ALLOC(d->arena, cbae_cir_instruction_t);
    if (!in) return no_memory("an instruction");
    in->id = id;
    in->opcode = (cbae_cir_opcode_t)opcode;
    in->operand_count = nops;
    for (uint8_t k = 0; k < nops; k++) in->operands[k] = ops[k] == NO_VALUE ? NULL : vref(d, ops[k]);
    in->source_addr = src;
    if (name_len) {
        char *copy = CBAE_ARENA_ALLOC_N(d->arena, char, (size_t)name_len + 1u);
        if (!copy) return no_memory("a call name");
        memcpy(copy, name, name_len);
        in->call_target_name = copy;
    }
    in->branch_true_block = t;
    in->branch_false_block = f;
    if (nphi) {
        in->phi_incoming_values = CBAE_ARENA_ALLOC_N(d->arena, cbae_cir_value_t *, nphi);
        in->phi_incoming_blocks = CBAE_ARENA_ALLOC_N(d->arena, uint32_t, nphi);
        if (!in->phi_incoming_values || !in->phi_incoming_blocks) return no_memory("phi incoming values");
        in->phi_incoming_capacity = nphi;
        for (uint32_t k = 0; k < nphi; k++) {
            const uint32_t v = rd32(r), b = rd32(r);
            if (r->bad) return truncated(d);
            if (v != NO_VALUE && v >= d->nvalues) return parse_error(d, "phi %u has the incoming value %u, which is not a value", id, v);
            if (b >= d->nblocks) return parse_error(d, "phi %u has the incoming block %u, which does not exist", id, b);
            in->phi_incoming_values[k] = v == NO_VALUE ? NULL : vref(d, v);
            in->phi_incoming_blocks[k] = b;
        }
        in->phi_incoming_count = nphi;
    }
    if (res) { res->u.def_insn = in; in->result = res; }
    d->by_id[id] = in;
    blk->instructions[blk->instruction_count++] = in;
    return CBAE_OK;
}

static cbae_err_t read_instructions(des_t *d) {
    for (uint32_t bi = 0; bi < d->nblocks; bi++) {
        cbae_cir_block_t *b = block_at(d->f, bi);
        const uint32_t declared = b->instruction_count;
        if (declared > left(&d->r) / MIN_INSN_BYTES) return parse_error(d, "block %u has %u instructions, more than the data can hold", bi, declared);
        b->instruction_count = 0;
        if (declared > b->instruction_capacity) {
            b->instructions = CBAE_ARENA_ALLOC_N(d->arena, cbae_cir_instruction_t *, declared);
            if (!b->instructions) return no_memory("a block's instructions");
            b->instruction_capacity = declared;
        }
        for (uint32_t k = 0; k < declared; k++) CBAE_CHECK(read_instruction(d, b));
    }
    return CBAE_OK;
}

static cbae_err_t parse(des_t *d) {
    rd_t *r = &d->r;
    const uint32_t magic = rd32(r), version = rd32(r);
    const uint64_t entry = rd64(r);
    uint8_t name[NAME_FIELD];
    rd_bytes(r, name, sizeof name);
    d->nblocks = rd32(r);
    d->nvalues = rd32(r);
    if (r->bad) return truncated(d);
    if (magic != SER_MAGIC) return parse_error(d, "not a CIR blob (bad magic)");
    if (version != SER_VERSION) return parse_error(d, "version %u (this build reads version %u)", version, SER_VERSION);
    const uint8_t *nul = memchr(name, '\0', sizeof name);
    if (!nul) return parse_error(d, "the function name has no terminator");
    for (const uint8_t *c = nul; c < name + sizeof name; c++)
        if (*c) return parse_error(d, "the function name is followed by bytes that are not zero");
    if ((uint64_t)d->nvalues * MIN_VALUE_BYTES + (uint64_t)d->nblocks * MIN_BLOCK_BYTES > left(r))
        return parse_error(d, "%u values and %u blocks declared, more than the data can hold", d->nvalues, d->nblocks);

    CBAE_CHECK(cbae_cir_function_create(d->arena, entry, (const char *)name, &d->f));
    CBAE_CHECK(cbae_vector_reserve(&d->f->values, d->nvalues));
    CBAE_CHECK(cbae_vector_reserve(&d->f->blocks, d->nblocks));
    if (d->nvalues) {
        d->def_of = calloc(d->nvalues, sizeof *d->def_of);
        if (!d->def_of) return no_memory("the value table");
    }

    CBAE_CHECK(read_values(d));
    CBAE_CHECK(read_blocks(d));
    CBAE_CHECK(read_instructions(d));

    for (uint32_t i = 0; i < d->nvalues; i++) {
        const cbae_cir_value_t *v = vref(d, i);
        if (v->kind == CIR_VAL_INSN_RESULT && !v->u.def_insn)
            return parse_error(d, "value %u names instruction %u as its definition, which does not produce it", i, d->def_of[i]);
    }
    if (r->pos != r->len) return parse_error(d, "%zu bytes follow the last instruction", left(r));
    d->f->next_value_id = d->nvalues;
    d->f->next_insn_id = d->ninsns;
    return CBAE_OK;
}

cbae_err_t cbae_cir_deserialize_function(const uint8_t *buf, size_t size, cbae_arena_t *arena, cbae_cir_function_t **out) {
    if (out) *out = NULL;
    if (!buf || !arena || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    des_t d = { .r = { buf, size, 0, false }, .arena = arena };
    const cbae_err_t err = parse(&d);
    free(d.def_of);
    free(d.by_id);
    if (err != CBAE_OK) {
        if (d.f) cbae_cir_function_destroy(d.f);                   /* what was built is released; the arena keeps its bytes until it is reset */
        return err;
    }
    *out = d.f;
    return CBAE_OK;
}
