/**
 * @file cir_opcodes.c
 * @brief Opcode mnemonic table and syntactic/semantic classification.
 */
#include "cir/cir_opcodes.h"

const char *cbae_cir_opcode_str(cbae_cir_opcode_t op) {
    switch (op) {
        case CIR_OP_INVALID:            return "invalid";
        case CIR_OP_LOAD:               return "load";
        case CIR_OP_STORE:              return "store";
        case CIR_OP_LEA:                return "lea";
        case CIR_OP_MMIO_READ:          return "mmio_read";
        case CIR_OP_MMIO_WRITE:         return "mmio_write";
        case CIR_OP_PORT_READ:          return "port_read";
        case CIR_OP_PORT_WRITE:         return "port_write";
        case CIR_OP_MSR_READ:           return "msr_read";
        case CIR_OP_MSR_WRITE:          return "msr_write";
        case CIR_OP_ADD:                return "add";
        case CIR_OP_SUB:                return "sub";
        case CIR_OP_MUL:                return "mul";
        case CIR_OP_DIV:                return "div";
        case CIR_OP_AND:                return "and";
        case CIR_OP_OR:                 return "or";
        case CIR_OP_XOR:                return "xor";
        case CIR_OP_NOT:                return "not";
        case CIR_OP_NEG:                return "neg";
        case CIR_OP_SHL:                return "shl";
        case CIR_OP_SHR:                return "shr";
        case CIR_OP_SAR:                return "sar";
        case CIR_OP_CMP:                return "cmp";
        case CIR_OP_TEST:               return "test";
        case CIR_OP_COPY:               return "copy";
        case CIR_OP_BRANCH:             return "branch";
        case CIR_OP_JUMP:               return "jump";
        case CIR_OP_CALL:               return "call";
        case CIR_OP_RETURN:             return "return";
        case CIR_OP_PUSH:               return "push";
        case CIR_OP_POP:                return "pop";
        case CIR_OP_PHI:                return "phi";
        case CIR_OP_SPINLOCK_ACQUIRE:   return "spinlock_acquire";
        case CIR_OP_SPINLOCK_RELEASE:   return "spinlock_release";
        case CIR_OP_MUTEX_LOCK:         return "mutex_lock";
        case CIR_OP_MUTEX_UNLOCK:       return "mutex_unlock";
        case CIR_OP_WAIT:               return "wait";
        case CIR_OP_IRQ_REGISTER:       return "irq_register";
        case CIR_OP_IRQ_UNREGISTER:     return "irq_unregister";
        case CIR_OP_IRQ_HANDLER_ENTRY:  return "irq_handler_entry";
        case CIR_OP_IRQ_HANDLER_EXIT:   return "irq_handler_exit";
        case CIR_OP_DPC_CALL:           return "dpc_call";
        case CIR_OP_DMA_ALLOC:          return "dma_alloc";
        case CIR_OP_DMA_FREE:           return "dma_free";
        case CIR_OP_DMA_MAP:            return "dma_map";
        case CIR_OP_DMA_SYNC:           return "dma_sync";
        case CIR_OP_PCI_CONFIG_READ:    return "pci_config_read";
        case CIR_OP_PCI_CONFIG_WRITE:   return "pci_config_write";
        case CIR_OP_POWER_STATE_ENTER:  return "power_state_enter";
        case CIR_OP_POWER_STATE_EXIT:   return "power_state_exit";
        case CIR_OP_API_CALL:           return "api_call";
        default:                        return "?";
    }
}

bool cbae_cir_opcode_is_syntactic(cbae_cir_opcode_t op) {
    switch (op) {
        case CIR_OP_LOAD: case CIR_OP_STORE: case CIR_OP_LEA:
        case CIR_OP_PORT_READ: case CIR_OP_PORT_WRITE:
        case CIR_OP_MSR_READ:  case CIR_OP_MSR_WRITE:
        case CIR_OP_ADD: case CIR_OP_SUB: case CIR_OP_MUL: case CIR_OP_DIV:
        case CIR_OP_AND: case CIR_OP_OR:  case CIR_OP_XOR:
        case CIR_OP_NOT: case CIR_OP_NEG:
        case CIR_OP_SHL: case CIR_OP_SHR: case CIR_OP_SAR:
        case CIR_OP_CMP: case CIR_OP_TEST:
        case CIR_OP_COPY:
        case CIR_OP_BRANCH: case CIR_OP_JUMP: case CIR_OP_CALL: case CIR_OP_RETURN:
        case CIR_OP_PUSH: case CIR_OP_POP:
        case CIR_OP_PHI:
            return true;
        default:
            return false;
    }
}
