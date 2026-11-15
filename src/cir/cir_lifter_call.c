/**
 * @file cir_lifter_call.c
 * @brief CALL -> CIR_OP_CALL with API label seeding.
 *
 * "Seeding" means exactly this and nothing more: if Phase 3's call
 * graph already resolved this call site to a named import (the IAT-
 * relative or backward-register-resolved cases from call_graph.h),
 * that name is attached to the CIR_OP_CALL node's call_target_name
 * field. Phase 4 does NOT attempt to determine argument count or
 * types here -- that needs calling-convention awareness plus (for the
 * cases that matter most) the ACTUAL signature of a recognized API,
 * which only exists once Phase 6's API recognition pass has matched
 * the seeded name against the kernel API database. Recording
 * unconditional "argument" reads from RCX/RDX/R8/R9 here would
 * overclaim precision Phase 4 doesn't have -- honestly recording only
 * what's syntactically certain (a call happened, to what if resolved,
 * and that RAX holds its return value by convention) is the more
 * correct design.
 */
#include "cir_lifter_internal.h"

void cir_lift_call_insn(cir_lift_ctx_t *ctx, const cbae_instruction_t *insn) {
    const char *target_name = NULL;

    if (ctx->cg) {
        uint32_t n = cbae_call_graph_edge_count(ctx->cg);
        for (uint32_t i = 0; i < n; i++) {
            const cbae_call_edge_t *e = cbae_call_graph_edge_at(ctx->cg, i);
            if (e->call_site == insn->address) {
                if (e->kind == CBAE_CALL_IMPORT && e->import_name)
                    target_name = e->import_name;
                break;
            }
        }
    }

    cbae_cir_value_t *ret = cbae_cir_call(&ctx->builder, target_name, NULL, 0,
                                          cir_type_i(64), insn->address);
    cir_lift_write_reg(ctx, CBAE_REG_RAX, ret); /* return value convention */
}
