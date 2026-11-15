/**
 * @file call_graph_builder.c
 * @brief Inter-procedural call graph — scans CALL-ending blocks in a CFG
 *        and records call edges.
 *
 * TARGET RESOLUTION per call site, in priority order:
 *   1. Direct: Capstone gave us an immediate branch target (call rel32).
 *   2. Import: `call qword ptr [rip+disp]` where the computed absolute
 *      address matches a known import's IAT slot -- the standard
 *      compiler-generated pattern for calling an imported kernel API
 *      through position-independent x64 PE code.
 *   3. Indirect (unresolved): register-indirect (`call reg`) or any
 *      other memory-indirect form not matching #2. Left for
 *      indirect_call_resolver.c to attempt afterward.
 *
 * RIP-RELATIVE ADDRESSING NOTE: the displacement in `[rip+disp]` is
 * relative to the address of the NEXT instruction (call_insn->address +
 * call_insn->length), not the CALL instruction's own start address --
 * an easy detail to get backwards.
 */
#include "disasm/call_graph.h"
#include "disasm/instruction.h"
#include "platform/logging.h"
#include <string.h>
#include <stdlib.h>

static void destroy_caller_vec(uint64_t key, void *value, void *ud) {
    (void)key; (void)ud;
    cbae_vector_t *v = (cbae_vector_t *)value;
    cbae_vector_destroy(v);
    free(v);
}

cbae_err_t cbae_call_graph_init(cbae_call_graph_t *cg) {
    if (!cg) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null call graph");
    cbae_err_t e = cbae_vector_init(&cg->edges, sizeof(cbae_call_edge_t), 32);
    if (e != CBAE_OK) return e;
    e = cbae_hashmap_init(&cg->callers_of, 32);
    if (e != CBAE_OK) { cbae_vector_destroy(&cg->edges); return e; }
    return CBAE_OK;
}

void cbae_call_graph_destroy(cbae_call_graph_t *cg) {
    if (!cg) return;
    cbae_hashmap_foreach(&cg->callers_of, destroy_caller_vec, NULL);
    cbae_vector_destroy(&cg->edges);
    cbae_hashmap_destroy(&cg->callers_of);
}

static bool is_rip_relative_mem(const cbae_operand_t *op) {
    return op->kind == CBAE_OPND_MEM && op->u.mem.base == CBAE_REG_RIP;
}

static cbae_err_t record_caller(cbae_call_graph_t *cg, cbae_addr_t target,
                                  cbae_addr_t caller_entry) {
    void *v = NULL;
    cbae_vector_t *list;
    if (cbae_hashmap_get(&cg->callers_of, (uint64_t)target, &v)) {
        list = (cbae_vector_t *)v;
    } else {
        list = malloc(sizeof(cbae_vector_t));
        if (!list) CBAE_RETURN_ERR(CBAE_ERR_OOM, "caller list alloc failed");
        cbae_err_t e = cbae_vector_init(list, sizeof(cbae_addr_t), 4);
        if (e != CBAE_OK) { free(list); return e; }
        cbae_err_t ie = cbae_hashmap_insert(&cg->callers_of, (uint64_t)target, list);
        if (ie != CBAE_OK) { cbae_vector_destroy(list); free(list); return ie; }
    }
    return cbae_vector_push(list, &caller_entry);
}

cbae_err_t cbae_call_graph_add_function(cbae_call_graph_t *cg,
                                         const cbae_binary_image_t *img,
                                         const cbae_cfg_t *cfg,
                                         cbae_addr_t caller_entry) {
    if (!cg || !img || !cfg) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");

    uint32_t nblocks = cbae_cfg_block_count(cfg);
    for (uint32_t bi = 0; bi < nblocks; bi++) {
        cbae_basic_block_t *blk = cbae_cfg_block_at_index(cfg, bi);
        if (!blk->ends_in_call || blk->instruction_count == 0) continue;

        const cbae_instruction_t *call_insn =
            &blk->instructions[blk->instruction_count - 1];

        cbae_call_edge_t edge;
        memset(&edge, 0, sizeof(edge));
        edge.call_site    = call_insn->address;
        edge.caller_entry = caller_entry;
        edge.target        = CBAE_ADDR_INVALID;
        edge.kind           = CBAE_CALL_INDIRECT;
        edge.import_name    = NULL;

        if (call_insn->branch_target_is_direct) {
            edge.target = call_insn->branch_target;
            edge.kind   = CBAE_CALL_DIRECT;
        } else if (call_insn->operand_count >= 1 &&
                   is_rip_relative_mem(&call_insn->operands[0])) {
            cbae_addr_t next_insn_addr = call_insn->address + call_insn->length;
            cbae_addr_t iat_va = next_insn_addr +
                                  (cbae_addr_t)call_insn->operands[0].u.mem.disp;
            cbae_import_entry_t *imp = cbae_image_import_at_iat(img, iat_va);
            if (imp) {
                edge.kind = CBAE_CALL_IMPORT;
                edge.import_name = imp->name; /* arena-owned by img, stable */
            }
        }
        /* else: register-indirect or unmatched memory-indirect -- left
         * as CBAE_CALL_INDIRECT for indirect_call_resolver.c.          */

        CBAE_CHECK(cbae_vector_push(&cg->edges, &edge));
        if (edge.target != CBAE_ADDR_INVALID)
            CBAE_CHECK(record_caller(cg, edge.target, caller_entry));
    }
    return CBAE_OK;
}

uint32_t cbae_call_graph_edge_count(const cbae_call_graph_t *cg) {
    return (uint32_t)cbae_vector_count(&cg->edges);
}

const cbae_call_edge_t *cbae_call_graph_edge_at(const cbae_call_graph_t *cg, uint32_t idx) {
    return (const cbae_call_edge_t *)cbae_vector_at(&cg->edges, idx);
}
