/**
 * @file cir_printer.c
 * @brief Human-readable CIR text dump for debugging.
 */
#include "cir/cir_printer.h"
#include "cir/cir_opcodes.h"
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

void cbae_cir_format_value(const cbae_cir_value_t *v, char *buf, int bufsz) {
    if (!v) { snprintf(buf, (size_t)bufsz, "<null>"); return; }
    switch (v->kind) {
        case CIR_VAL_INSN_RESULT:
            snprintf(buf, (size_t)bufsz, "%%v%u", v->id);
            break;
        case CIR_VAL_CONST:
            snprintf(buf, (size_t)bufsz, "%" PRId64, v->u.const_val);
            break;
        case CIR_VAL_PARAM:
            snprintf(buf, (size_t)bufsz, "reg:%s", cbae_reg_name(v->u.param_reg));
            break;
        case CIR_VAL_REG_ENTRY:
            snprintf(buf, (size_t)bufsz, "<unresolved:%s@block%u>",
                     cbae_reg_name(v->u.reg_entry.reg), v->u.reg_entry.block_id);
            break;
        default:
            snprintf(buf, (size_t)bufsz, "<invalid>");
            break;
    }
}

void cbae_cir_print_instruction(const cbae_cir_instruction_t *insn, FILE *out) {
    char buf[64];
    if (insn->opcode == CIR_OP_PHI) {
        fprintf(out, "  ");
        cbae_cir_format_value(insn->result, buf, sizeof(buf));
        fprintf(out, "%s = phi %s ", buf, cir_type_str(insn->result->type));
        for (uint32_t i = 0; i < insn->phi_incoming_count; i++) {
            cbae_cir_format_value(insn->phi_incoming_values[i], buf, sizeof(buf));
            fprintf(out, "[%s, block%u]%s", buf, insn->phi_incoming_blocks[i],
                    (i + 1 < insn->phi_incoming_count) ? ", " : "");
        }
        fprintf(out, "\n");
        return;
    }

    fprintf(out, "  ");
    if (insn->result) {
        cbae_cir_format_value(insn->result, buf, sizeof(buf));
        fprintf(out, "%s = %s %s ", buf, cbae_cir_opcode_str(insn->opcode),
                cir_type_str(insn->result->type));
    } else {
        fprintf(out, "%s ", cbae_cir_opcode_str(insn->opcode));
    }

    for (uint8_t i = 0; i < insn->operand_count; i++) {
        cbae_cir_format_value(insn->operands[i], buf, sizeof(buf));
        fprintf(out, "%s%s", buf, (i + 1 < insn->operand_count) ? ", " : "");
    }

    if (insn->opcode == CIR_OP_BRANCH)
        fprintf(out, ", block%u, block%u", insn->branch_true_block, insn->branch_false_block);
    else if (insn->opcode == CIR_OP_JUMP)
        fprintf(out, "block%u", insn->branch_true_block);

    if (insn->opcode == CIR_OP_CALL && insn->call_target_name)
        fprintf(out, " <%s>", insn->call_target_name);

    fprintf(out, "  ; src=0x%llx\n", (unsigned long long)insn->source_addr);
}

void cbae_cir_print_block(const cbae_cir_block_t *blk, FILE *out) {
    fprintf(out, "block%u:  ; x86_addr=0x%llx  preds:", blk->id,
            (unsigned long long)blk->start_addr);
    uint32_t npred = (uint32_t)cbae_vector_count(&blk->predecessors);
    if (npred == 0) {
        fprintf(out, " (none)");
    } else {
        for (uint32_t i = 0; i < npred; i++) {
            uint32_t *p = cbae_vector_at(&blk->predecessors, i);
            fprintf(out, " block%u", *p);
        }
    }
    fprintf(out, "\n");

    for (uint32_t i = 0; i < blk->instruction_count; i++)
        cbae_cir_print_instruction(blk->instructions[i], out);
}

void cbae_cir_print_function(const cbae_cir_function_t *f, FILE *out) {
    fprintf(out, "function %s @0x%llx {\n", f->name[0] ? f->name : "(unnamed)",
            (unsigned long long)f->entry_addr);
    uint32_t n = (uint32_t)cbae_vector_count(&f->blocks);
    for (uint32_t i = 0; i < n; i++) {
        cbae_cir_block_t **bp = (cbae_cir_block_t **)cbae_vector_at(&f->blocks, i);
        cbae_cir_print_block(*bp, out);
    }
    fprintf(out, "}\n");
}
