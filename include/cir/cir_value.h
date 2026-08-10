/**
 * @file cir_value.h
 * @brief SSA value -- either an instruction's result, a compile-time
 *        constant, a function-entry register parameter, or an
 *        unresolved register-entry placeholder awaiting SSA construction.
 */
#ifndef CBAE_CIR_VALUE_H
#define CBAE_CIR_VALUE_H

#include "cir_type.h"
#include "disasm/operand.h"   /* cbae_reg_t */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cbae_cir_instruction; /* forward decl, avoids a circular include */

typedef enum cbae_cir_value_kind {
    CIR_VAL_INVALID = 0,
    CIR_VAL_INSN_RESULT,  /* the result of a CIR instruction (true SSA def) */
    CIR_VAL_CONST,         /* compile-time constant                          */
    CIR_VAL_PARAM,          /* register's value at function entry             */

    /* UNRESOLVED PLACEHOLDER, produced only by the lifter, consumed only
     * by the SSA constructor. Means "whatever register `reg` held when
     * control entered `block_id`" -- the lifter emits this whenever an
     * instruction reads a register that wasn't already written earlier
     * in the SAME block, since resolving it properly may require
     * recursing into predecessors (possibly inserting a phi at a join
     * point), which is exactly the SSA constructor's job. No instruction
     * in a fully-SSA-constructed function should still reference one of
     * these -- the verifier checks for that. */
    CIR_VAL_REG_ENTRY,
} cbae_cir_value_kind_t;

typedef struct cbae_cir_value {
    cbae_cir_value_kind_t kind;
    cbae_cir_type_t         type;
    uint32_t                  id;   /* unique within the function; printed as %vN */

    union {
        struct cbae_cir_instruction *def_insn;  /* CIR_VAL_INSN_RESULT     */
        int64_t                      const_val; /* CIR_VAL_CONST           */
        cbae_reg_t                   param_reg; /* CIR_VAL_PARAM           */
        struct {
            cbae_reg_t reg;
            uint32_t   block_id;
        } reg_entry;                            /* CIR_VAL_REG_ENTRY       */
    } u;
} cbae_cir_value_t;

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_VALUE_H */
