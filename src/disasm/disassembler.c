/**
 * @file disassembler.c
 * @brief Capstone wrapper: open, decode, iterate.
 *
 * Owns the Capstone engine handle and a single reusable cs_insn scratch
 * buffer (allocated once via cs_malloc, reused across every decode call
 * via cs_disasm_iter). This is Capstone's own recommended pattern for
 * high-frequency single-instruction decoding -- it avoids a malloc/free
 * pair on every instruction, which matters when decoding a driver's
 * entire .text section instruction-by-instruction.
 */
#include "disasm/disassembler.h"
#include "instruction_lifter.h"
#include "platform/logging.h"
#include <capstone/capstone.h>
#include <stdlib.h>
#include <string.h>

struct cbae_disassembler {
    csh                 handle;
    cbae_binary_arch_t  arch;
    cs_insn            *scratch;   /* reusable decode buffer             */
};

cbae_err_t cbae_disasm_create(cbae_binary_arch_t arch, cbae_disassembler_t **out) {
    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "out is NULL");
    if (arch != CBAE_ARCH_X86_64)
        CBAE_RETURN_ERR(CBAE_ERR_UNSUPPORTED,
                        "only x86_64 is supported in Phase 3");

    cbae_disassembler_t *d = calloc(1, sizeof(*d));
    if (!d) CBAE_RETURN_ERR(CBAE_ERR_OOM, "disassembler alloc failed");

    cs_err e = cs_open(CS_ARCH_X86, CS_MODE_64, &d->handle);
    if (e != CS_ERR_OK) {
        free(d);
        CBAE_RETURN_ERR(CBAE_ERR_GENERIC, "cs_open failed: %s", cs_strerror(e));
    }
    cs_option(d->handle, CS_OPT_DETAIL, CS_OPT_ON);

    d->scratch = cs_malloc(d->handle);
    if (!d->scratch) {
        cs_close(&d->handle);
        free(d);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "cs_malloc scratch buffer failed");
    }

    d->arch = arch;
    LOG_DEBUG("disassembler created (Capstone %u.%u, x86-64)",
              CS_VERSION_MAJOR, CS_VERSION_MINOR);
    *out = d;
    return CBAE_OK;
}

void cbae_disasm_destroy(cbae_disassembler_t **d) {
    if (!d || !*d) return;
    if ((*d)->scratch) cs_free((*d)->scratch, 1);
    cs_close(&(*d)->handle);
    free(*d);
    *d = NULL;
}

cbae_err_t cbae_disasm_decode_one(cbae_disassembler_t *d,
                                   const uint8_t *bytes, cbae_size_t max_len,
                                   cbae_addr_t addr,
                                   cbae_instruction_t *out) {
    if (!d || !bytes || !out || max_len == 0)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "invalid decode_one arguments");

    const uint8_t *code      = bytes;
    size_t         code_size = (size_t)max_len;
    uint64_t       address   = (uint64_t)addr;

    bool ok = cs_disasm_iter(d->handle, &code, &code_size, &address, d->scratch);
    if (!ok) {
        CBAE_RETURN_ERR(CBAE_ERR_PARSE,
                        "cs_disasm_iter failed at 0x%llx (incomplete or "
                        "invalid opcode)", (unsigned long long)addr);
    }

    cbae_lift_instruction(d->scratch, out);
    return CBAE_OK;
}
