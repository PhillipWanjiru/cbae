/**
 * @file operand.h
 * @brief Instruction operand model — reg, imm, mem, disp.
 */
#ifndef CBAE_OPERAND_H
#define CBAE_OPERAND_H

#include "cbae/cbae_types.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_operand_kind {
    CBAE_OPND_NONE = 0,
    CBAE_OPND_REG   = 1,
    CBAE_OPND_IMM   = 2,
    CBAE_OPND_MEM   = 3,
} cbae_operand_kind_t;

/* Coarse, architecture-neutral-ish register set covering the general
 * purpose + special registers CBAE's control-flow and resolver logic
 * actually branches on. Narrow (32/16/8-bit) and vector registers map
 * to CBAE_REG_OTHER -- cs_reg_id below retains the exact Capstone
 * register for any component (Phase 4 CIR lifting) that needs it.     */
typedef enum cbae_reg {
    CBAE_REG_NONE = 0,
    CBAE_REG_RAX, CBAE_REG_RBX, CBAE_REG_RCX, CBAE_REG_RDX,
    CBAE_REG_RSI, CBAE_REG_RDI, CBAE_REG_RBP, CBAE_REG_RSP,
    CBAE_REG_R8,  CBAE_REG_R9,  CBAE_REG_R10, CBAE_REG_R11,
    CBAE_REG_R12, CBAE_REG_R13, CBAE_REG_R14, CBAE_REG_R15,
    CBAE_REG_RIP,
    CBAE_REG_EFLAGS,
    CBAE_REG_OTHER,
} cbae_reg_t;

typedef struct cbae_operand {
    cbae_operand_kind_t kind;
    uint8_t  size;         /* operand width in bytes: 1,2,4,8            */

    /* NOTE: Capstone's per-operand access field (READ/WRITE) requires
     * detail mode and is not populated in DIET builds. CBAE's own
     * resolver logic never depends on these -- they are best-effort,
     * set when available, reserved for Phase 4 CIR lifting.            */
    bool     is_read;
    bool     is_write;

    uint16_t cs_reg_id;    /* raw Capstone x86_reg id, exact register
                             * even when u.reg.reg maps to REG_OTHER    */
    union {
        struct { cbae_reg_t reg; }      reg;
        struct { int64_t value; }       imm;
        struct {
            cbae_reg_t base;
            cbae_reg_t index;
            uint8_t    scale;
            int64_t    disp;
        } mem;
    } u;
} cbae_operand_t;

const char *cbae_reg_name(cbae_reg_t r);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_OPERAND_H */
