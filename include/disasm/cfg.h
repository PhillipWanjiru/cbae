/**
 * @file cfg.h
 * @brief Control flow graph — recursive-descent construction from an
 *        entry point, with mid-block splitting on convergence.
 */
#ifndef CBAE_CFG_H
#define CBAE_CFG_H

#include "cbae/cbae_error.h"
#include "loader/binary_image.h"
#include "disasm/disassembler.h"
#include "disasm/basic_block.h"
#include "platform/hashmap.h"
#include "platform/vector.h"
#include "platform/memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_cfg {
    cbae_addr_t    entry_addr;
    cbae_vector_t  block_ptrs;      /* elem = cbae_basic_block_t*, heap-
                                      * backed bookkeeping array          */
    cbae_hashmap_t addr_to_block;   /* start_addr -> cbae_basic_block_t*  */
    cbae_arena_t  *arena;           /* BORROWED -- caller owns/frees it   */
} cbae_cfg_t;

/*
 * Build a CFG by recursive-descent disassembly starting at entry_addr.
 * All basic blocks and their instruction arrays are allocated from
 * `arena`, which the caller must keep alive at least as long as the
 * returned cfg is used. Call cbae_cfg_destroy() to free the CFG's own
 * bookkeeping (vector + hashmap) -- this does NOT touch the arena.
 */
cbae_err_t cbae_cfg_build(const cbae_binary_image_t *img,
                           cbae_disassembler_t *d,
                           cbae_addr_t entry_addr,
                           cbae_arena_t *arena,
                           cbae_cfg_t *out);

void cbae_cfg_destroy(cbae_cfg_t *cfg);

cbae_basic_block_t *cbae_cfg_block_at(const cbae_cfg_t *cfg, cbae_addr_t addr);
uint32_t             cbae_cfg_block_count(const cbae_cfg_t *cfg);
cbae_basic_block_t *cbae_cfg_block_at_index(const cbae_cfg_t *cfg, uint32_t idx);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CFG_H */
