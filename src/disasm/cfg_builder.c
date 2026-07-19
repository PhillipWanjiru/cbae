/**
 * @file cfg_builder.c
 * @brief Recursive descent CFG construction from an entry point.
 *
 * ALGORITHM:
 *   Maintain a worklist of pending block-start addresses. Pop one at a
 *   time. If it's already a registered block start, skip. If it falls
 *   STRICTLY INSIDE an already-built block's instruction range, split
 *   that block at the exact instruction boundary. Otherwise, decode a
 *   brand new block: keep decoding instructions straight-line until
 *   hitting RET, an unconditional JMP, a JCC (two successors), a CALL
 *   (ends the block with a call-return successor), or running off
 *   mapped/backed memory.
 *
 * WHY MID-BLOCK SPLITTING IS SAFE WITH ARENA ALLOCATION:
 *   When a later worklist entry targets an address in the MIDDLE of an
 *   already-decoded block (the classic "two branches converge" pattern
 *   where the fallthrough path was fully decoded before the taken-branch
 *   path was processed), split_block_at() creates a new tail block whose
 *   `instructions` pointer is a SLICE into the SAME arena-backed array
 *   the original block already owns -- no copying, no reallocation. This
 *   is only safe because arena memory never moves and is never freed
 *   piecemeal; both the truncated head block and the new tail block can
 *   safely share the tail of one contiguous instruction array for the
 *   entire lifetime of the arena.
 *
 * WORKLIST ORDERING (why fallthrough is enqueued to pop before taken):
 *   Successors are enqueued in REVERSE storage order, so for a two-way
 *   Jcc (stored as [fallthrough, taken]) the fallthrough target is
 *   pushed LAST and therefore pops FIRST from this LIFO worklist. This
 *   means straight-line fallthrough code is generally decoded before
 *   its corresponding branch target is processed -- which is exactly
 *   what allows split_block_at() to actually trigger on typical
 *   if/else convergence patterns, where the branch target frequently
 *   lands mid-way through a block already decoded via the fallthrough
 *   path.
 */
#include "disasm/cfg.h"
#include "cfg_edge_classifier.h"
#include "platform/logging.h"
#include <string.h>
#include <stdlib.h>

#define CFG_WORKLIST_INITIAL_CAP 32
#define CFG_MAX_BLOCK_INSNS      4096  /* safety cap against runaway
                                          decode on corrupted input     */

/* ── Bridge to Phase 2: address -> raw bytes + remaining section length ── */
static const uint8_t *bytes_at(const cbae_binary_image_t *img, cbae_addr_t addr,
                                 cbae_size_t *out_remaining) {
    cbae_section_t *s = cbae_image_section_at_va(img, addr);
    if (!s || !s->data) { *out_remaining = 0; return NULL; }
    cbae_size_t off = addr - s->virt_addr;
    if (off >= s->file_size) { *out_remaining = 0; return NULL; } /* BSS tail */
    *out_remaining = s->file_size - off;
    return s->data + off;
}

static cbae_err_t register_block(cbae_cfg_t *cfg, cbae_basic_block_t *blk) {
    cbae_err_t e = cbae_vector_push(&cfg->block_ptrs, &blk);
    if (e != CBAE_OK) return e;
    return cbae_hashmap_insert(&cfg->addr_to_block, (uint64_t)blk->start_addr, blk);
}

static bool addr_is_known_start(cbae_cfg_t *cfg, cbae_addr_t addr) {
    void *v;
    return cbae_hashmap_get(&cfg->addr_to_block, (uint64_t)addr, &v);
}

/*
 * Split `block` at `addr`, which must be the exact address of one of
 * the instructions currently inside it. Returns the new tail block, or
 * NULL if `addr` does not align to an instruction boundary (logged as
 * a warning, not fatal -- can occur on obfuscated/overlapping code).
 */
static cbae_basic_block_t *split_block_at(cbae_cfg_t *cfg,
                                           cbae_basic_block_t *block,
                                           cbae_addr_t addr) {
    uint32_t split_idx = UINT32_MAX;
    for (uint32_t i = 0; i < block->instruction_count; i++) {
        if (block->instructions[i].address == addr) { split_idx = i; break; }
    }
    if (split_idx == UINT32_MAX || split_idx == 0) {
        LOG_WARN("cfg: cannot split block at 0x%llx (no aligned instruction "
                 "boundary found)", (unsigned long long)addr);
        return NULL;
    }

    cbae_basic_block_t *tail = CBAE_ARENA_ALLOC(cfg->arena, cbae_basic_block_t);
    if (!tail) return NULL;

    tail->start_addr        = addr;
    tail->end_addr          = block->end_addr;
    tail->instructions      = &block->instructions[split_idx];  /* slice, see file header */
    tail->instruction_count = block->instruction_count - split_idx;
    memcpy(tail->successors, block->successors, sizeof(block->successors));
    tail->successor_count            = block->successor_count;
    tail->ends_in_call               = block->ends_in_call;
    tail->ends_in_ret                = block->ends_in_ret;
    tail->ends_in_unresolved_branch  = block->ends_in_unresolved_branch;

    /* Truncate the original block: ends right before the split point,
     * with a single fallthrough edge into the new tail block. */
    block->end_addr          = addr;
    block->instruction_count = split_idx;
    block->successors[0].target = addr;
    block->successors[0].kind   = CBAE_EDGE_FALLTHROUGH;
    block->successor_count   = 1;
    block->ends_in_call              = false;
    block->ends_in_ret               = false;
    block->ends_in_unresolved_branch = false;

    if (register_block(cfg, tail) != CBAE_OK) return NULL;

    LOG_DEBUG("cfg: split at 0x%llx -- head 0x%llx now %u insns, tail %u insns",
              (unsigned long long)addr, (unsigned long long)block->start_addr,
              block->instruction_count, tail->instruction_count);
    return tail;
}

/* Enqueue `addr` if it isn't already pending. `pending` is a "seen" set
 * (value unused) preventing duplicate worklist entries. */
static void enqueue(cbae_vector_t *worklist, cbae_hashmap_t *pending,
                     cbae_addr_t addr) {
    if (addr == CBAE_ADDR_INVALID) return;
    if (cbae_hashmap_contains(pending, (uint64_t)addr)) return;
    cbae_hashmap_insert(pending, (uint64_t)addr, (void *)1);
    cbae_vector_push(worklist, &addr);
}

cbae_err_t cbae_cfg_build(const cbae_binary_image_t *img,
                           cbae_disassembler_t *d,
                           cbae_addr_t entry_addr,
                           cbae_arena_t *arena,
                           cbae_cfg_t *out) {
    if (!img || !d || !arena || !out)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument to cfg_build");

    memset(out, 0, sizeof(*out));
    out->entry_addr = entry_addr;
    out->arena      = arena;

    cbae_err_t e = cbae_vector_init(&out->block_ptrs, sizeof(cbae_basic_block_t *), 16);
    if (e != CBAE_OK) return e;
    e = cbae_hashmap_init(&out->addr_to_block, 32);
    if (e != CBAE_OK) { cbae_vector_destroy(&out->block_ptrs); return e; }

    cbae_vector_t  worklist;
    cbae_hashmap_t pending;
    e = cbae_vector_init(&worklist, sizeof(cbae_addr_t), CFG_WORKLIST_INITIAL_CAP);
    if (e != CBAE_OK) {
        cbae_vector_destroy(&out->block_ptrs);
        cbae_hashmap_destroy(&out->addr_to_block);
        return e;
    }
    e = cbae_hashmap_init(&pending, CFG_WORKLIST_INITIAL_CAP);
    if (e != CBAE_OK) {
        cbae_vector_destroy(&worklist);
        cbae_vector_destroy(&out->block_ptrs);
        cbae_hashmap_destroy(&out->addr_to_block);
        return e;
    }

    cbae_addr_t start = entry_addr;
    cbae_hashmap_insert(&pending, (uint64_t)start, (void *)1);
    cbae_vector_push(&worklist, &start);

    /* Scratch buffer for the block currently being decoded. Sized
     * generously and heap-allocated once; flushed into the arena only
     * once the block's final instruction count is known (arena
     * allocations can't be grown/resized in place). */
    cbae_instruction_t *scratch =
        malloc(sizeof(cbae_instruction_t) * CFG_MAX_BLOCK_INSNS);
    if (!scratch) {
        cbae_vector_destroy(&worklist);
        cbae_hashmap_destroy(&pending);
        cbae_vector_destroy(&out->block_ptrs);
        cbae_hashmap_destroy(&out->addr_to_block);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "cfg scratch buffer alloc failed");
    }

    while (cbae_vector_count(&worklist) > 0) {
        cbae_addr_t block_addr;
        cbae_vector_pop(&worklist, &block_addr);

        if (addr_is_known_start(out, block_addr)) continue;

        /* Does this address fall strictly inside an already-built
         * block? If so, split rather than re-decode. */
        {
            bool split_done = false;
            uint32_t existing = (uint32_t)cbae_vector_count(&out->block_ptrs);
            for (uint32_t i = 0; i < existing; i++) {
                cbae_basic_block_t **bp = cbae_vector_at(&out->block_ptrs, i);
                cbae_basic_block_t *b = *bp;
                if (block_addr > b->start_addr && block_addr < b->end_addr) {
                    split_block_at(out, b, block_addr);
                    split_done = true;
                    break;
                }
            }
            if (split_done) continue;
        }

        /* Decode a brand new block starting at block_addr. */
        uint32_t n = 0;
        cbae_addr_t cur = block_addr;
        cbae_bb_edge_t successors[CBAE_BB_MAX_SUCCESSORS];
        uint8_t succ_count = 0;
        bool ends_in_call = false, ends_in_ret = false, ends_in_unresolved = false;

        for (;;) {
            if (n > 0 && addr_is_known_start(out, cur)) {
                /* Converges into an already-known block: stop here with
                 * a plain fallthrough edge, no re-decoding. */
                successors[succ_count].target = cur;
                successors[succ_count].kind   = CBAE_EDGE_FALLTHROUGH;
                succ_count++;
                break;
            }
            if (n >= CFG_MAX_BLOCK_INSNS) {
                LOG_WARN("cfg: block at 0x%llx exceeded %d instructions, "
                         "truncating", (unsigned long long)block_addr,
                         CFG_MAX_BLOCK_INSNS);
                break;
            }

            cbae_size_t remaining = 0;
            const uint8_t *p = bytes_at(img, cur, &remaining);
            if (!p) break; /* ran off mapped/backed data */

            cbae_instruction_t insn;
            cbae_err_t derr = cbae_disasm_decode_one(d, p, remaining, cur, &insn);
            if (derr != CBAE_OK) break; /* invalid opcode -- data/padding
                                          * misidentified as code, or the
                                          * true end of a function's body */

            scratch[n++] = insn;
            cur = cur + insn.length;

            if (insn.is_ret) { ends_in_ret = true; break; }

            if (insn.is_call) {
                ends_in_call = true;
                successors[succ_count].target = cur;   /* return site */
                successors[succ_count].kind   = CBAE_EDGE_CALL_RETURN;
                succ_count++;
                break;
            }

            if (insn.iclass == CBAE_ICLASS_JCC) {
                successors[succ_count].target = cur;
                successors[succ_count].kind =
                    cbae_classify_edge(insn.address, cur, true);
                succ_count++;
                if (insn.branch_target_is_direct) {
                    successors[succ_count].target = insn.branch_target;
                    successors[succ_count].kind =
                        cbae_classify_edge(insn.address, insn.branch_target, false);
                    succ_count++;
                } else {
                    ends_in_unresolved = true; /* extremely rare for Jcc */
                }
                break;
            }

            if (insn.iclass == CBAE_ICLASS_JMP) {
                if (insn.branch_target_is_direct) {
                    successors[succ_count].target = insn.branch_target;
                    successors[succ_count].kind =
                        cbae_classify_edge(insn.address, insn.branch_target, false);
                    succ_count++;
                } else {
                    /* Indirect jmp -- jump table / computed goto. Target
                     * resolution for these is out of Phase 3's scope. */
                    ends_in_unresolved = true;
                }
                break;
            }
            /* Ordinary instruction -- keep decoding straight-line. */
        }

        if (n == 0) {
            LOG_WARN("cfg: no instructions decodable at 0x%llx",
                     (unsigned long long)block_addr);
            continue;
        }

        cbae_instruction_t *arena_insns =
            CBAE_ARENA_ALLOC_N(arena, cbae_instruction_t, n);
        cbae_basic_block_t *blk =
            arena_insns ? CBAE_ARENA_ALLOC(arena, cbae_basic_block_t) : NULL;
        if (!arena_insns || !blk) {
            free(scratch);
            cbae_vector_destroy(&worklist);
            cbae_hashmap_destroy(&pending);
            cbae_vector_destroy(&out->block_ptrs);
            cbae_hashmap_destroy(&out->addr_to_block);
            CBAE_RETURN_ERR(CBAE_ERR_OOM, "cfg block/instruction alloc failed");
        }
        memcpy(arena_insns, scratch, sizeof(cbae_instruction_t) * n);

        blk->start_addr        = block_addr;
        blk->end_addr          = cur;
        blk->instructions      = arena_insns;
        blk->instruction_count = n;
        memcpy(blk->successors, successors, sizeof(successors));
        blk->successor_count            = succ_count;
        blk->ends_in_call                = ends_in_call;
        blk->ends_in_ret                 = ends_in_ret;
        blk->ends_in_unresolved_branch   = ends_in_unresolved;

        cbae_err_t rerr = register_block(out, blk);
        if (rerr != CBAE_OK) {
            free(scratch);
            cbae_vector_destroy(&worklist);
            cbae_hashmap_destroy(&pending);
            cbae_vector_destroy(&out->block_ptrs);
            cbae_hashmap_destroy(&out->addr_to_block);
            return rerr;
        }

        /* Reverse order: see file header for why this matters for split
         * coverage. */
        for (int8_t i = (int8_t)succ_count - 1; i >= 0; i--)
            enqueue(&worklist, &pending, successors[i].target);
    }

    free(scratch);
    cbae_vector_destroy(&worklist);
    cbae_hashmap_destroy(&pending);

    LOG_DEBUG("cfg_build: entry=0x%llx blocks=%u",
              (unsigned long long)entry_addr,
              (uint32_t)cbae_vector_count(&out->block_ptrs));
    return CBAE_OK;
}

void cbae_cfg_destroy(cbae_cfg_t *cfg) {
    if (!cfg) return;
    cbae_vector_destroy(&cfg->block_ptrs);
    cbae_hashmap_destroy(&cfg->addr_to_block);
    /* Blocks and their instructions live in the caller-owned arena and
     * are NOT freed here -- the caller destroys the arena separately
     * once done with every CFG built from it. */
}

cbae_basic_block_t *cbae_cfg_block_at(const cbae_cfg_t *cfg, cbae_addr_t addr) {
    void *v;
    if (!cbae_hashmap_get(&cfg->addr_to_block, (uint64_t)addr, &v)) return NULL;
    return (cbae_basic_block_t *)v;
}

uint32_t cbae_cfg_block_count(const cbae_cfg_t *cfg) {
    return (uint32_t)cbae_vector_count(&cfg->block_ptrs);
}

cbae_basic_block_t *cbae_cfg_block_at_index(const cbae_cfg_t *cfg, uint32_t idx) {
    cbae_basic_block_t **bp = cbae_vector_at(&cfg->block_ptrs, idx);
    return bp ? *bp : NULL;
}
