/**
 * @file cir_function.h
 * @brief One lifted function: its blocks, its SSA value table, and the
 *        id counters the builder uses to name new instructions/values.
 */
#ifndef CBAE_CIR_FUNCTION_H
#define CBAE_CIR_FUNCTION_H

#include "cir_block.h"
#include "cir_value.h"
#include "cbae/cbae_types.h"
#include "platform/memory.h"
#include "platform/hashmap.h"
#include "platform/vector.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_cir_function {
    cbae_addr_t entry_addr;
    char        name[128];

    cbae_vector_t  blocks;
    cbae_hashmap_t addr_to_block;
    cbae_vector_t  values;

    uint32_t next_value_id;
    uint32_t next_insn_id;
    uint32_t next_block_id;

    cbae_arena_t *arena;
} cbae_cir_function_t;

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_FUNCTION_H */
