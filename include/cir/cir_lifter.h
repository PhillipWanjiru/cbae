/**
 * @file cir_lifter.h
 * @brief Public entry point: lift a Phase 3 CFG into a CIR function.
 */
#ifndef CBAE_CIR_LIFTER_H
#define CBAE_CIR_LIFTER_H

#include "cir_function.h"
#include "cir_builder.h"
#include "disasm/cfg.h"
#include "disasm/call_graph.h"
#include "loader/binary_image.h"
#include "cbae/cbae_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Lift every block in `cfg` into a new CIR function, in NON-SSA form
 * (register reads that cross a block boundary are left as
 * CIR_VAL_REG_ENTRY placeholders -- run the SSA constructor afterward
 * to resolve them into proper SSA form with phi nodes).
 *
 * `cg` may be NULL: without a call graph, CIR_OP_CALL nodes are still
 * emitted but never get a seeded call_target_name.
 */
cbae_err_t cbae_cir_lift_function(const cbae_binary_image_t *img,
                                   const cbae_cfg_t *cfg,
                                   const cbae_call_graph_t *cg,
                                   cbae_arena_t *arena,
                                   const char *name,
                                   cbae_cir_function_t **out);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_LIFTER_H */
