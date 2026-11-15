/**
 * @file call_graph.h
 * @brief Inter-procedural call graph — nodes and call edges.
 */
#ifndef CBAE_CALL_GRAPH_H
#define CBAE_CALL_GRAPH_H

#include "cbae/cbae_error.h"
#include "loader/binary_image.h"
#include "disasm/cfg.h"
#include "platform/hashmap.h"
#include "platform/vector.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_call_kind {
    CBAE_CALL_DIRECT = 0,   /* target address statically known           */
    CBAE_CALL_IMPORT,       /* target resolved via IAT / RELA import     */
    CBAE_CALL_INDIRECT,     /* target could not be statically resolved   */
} cbae_call_kind_t;

typedef struct cbae_call_edge {
    cbae_addr_t      call_site;    /* address of the CALL instruction     */
    cbae_addr_t      caller_entry; /* entry addr of the calling function  */
    cbae_addr_t      target;       /* callee entry, or CBAE_ADDR_INVALID  */
    cbae_call_kind_t kind;
    const char      *import_name;  /* set iff kind==CBAE_CALL_IMPORT;
                                     * interned pointer owned by the
                                     * binary_image, not this struct      */
} cbae_call_edge_t;

typedef struct cbae_call_graph {
    cbae_vector_t  edges;        /* elem = cbae_call_edge_t (by value)    */
    cbae_hashmap_t callers_of;   /* target_addr -> cbae_vector_t* of
                                   * caller_entry addrs (heap-owned)       */
} cbae_call_graph_t;

cbae_err_t cbae_call_graph_init(cbae_call_graph_t *cg);
void       cbae_call_graph_destroy(cbae_call_graph_t *cg);

/*
 * Scan every call-ending block in `cfg` and record a call edge.
 * Direct calls (immediate target) -> CBAE_CALL_DIRECT.
 * `call qword ptr [rip+disp]` landing on a known import's IAT slot
 * -> CBAE_CALL_IMPORT, resolved via img's import table.
 * Everything else (register-indirect, unresolved memory-indirect)
 * -> CBAE_CALL_INDIRECT; cbae_resolve_indirect_calls() may upgrade
 * some of these afterward.
 */
cbae_err_t cbae_call_graph_add_function(cbae_call_graph_t *cg,
                                         const cbae_binary_image_t *img,
                                         const cbae_cfg_t *cfg,
                                         cbae_addr_t caller_entry);

uint32_t cbae_call_graph_edge_count(const cbae_call_graph_t *cg);
const cbae_call_edge_t *cbae_call_graph_edge_at(const cbae_call_graph_t *cg, uint32_t idx);

/*
 * Attempt to resolve a scoped subset of CBAE_CALL_INDIRECT edges via
 * single-block backward pattern matching: if the register used in
 * `call reg` was loaded immediately beforehand in the SAME block by
 * `mov reg, imm64` or `lea reg, [rip+disp]`, upgrade the edge to
 * CBAE_CALL_DIRECT (or CBAE_CALL_IMPORT if the resolved address
 * matches a known import's IAT slot).
 *
 * Intentionally scoped to single-block, single-hop patterns. Full
 * dataflow-based resolution (constant propagation across blocks, WDF
 * dispatch table modelling) is Phase 5/6 territory, not attempted here.
 *
 * Returns the number of edges upgraded.
 */
uint32_t cbae_resolve_indirect_calls(cbae_call_graph_t *cg,
                                      const cbae_binary_image_t *img,
                                      const cbae_cfg_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CALL_GRAPH_H */
