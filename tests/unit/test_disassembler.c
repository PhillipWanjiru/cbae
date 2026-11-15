/**
 * @file test_disassembler.c
 * @brief Unit tests for the Capstone-backed disassembler against real,
 *        hand-verified x86-64 byte encodings covering the instruction
 *        groups CBAE's CFG builder and resolver logic depend on.
 */
#include "disasm/disassembler.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static cbae_disassembler_t *g_d;

static void t_nop(void) {
    uint8_t code[] = {0x90};
    cbae_instruction_t insn;
    assert(cbae_disasm_decode_one(g_d, code, sizeof(code), 0x1000, &insn) == CBAE_OK);
    assert(insn.length == 1);
    assert(insn.iclass == CBAE_ICLASS_NOP);
    assert(!strcmp(insn.mnemonic, "nop"));
    printf("  [PASS] NOP\n");
}

static void t_push_rbp(void) {
    uint8_t code[] = {0x55};
    cbae_instruction_t insn;
    assert(cbae_disasm_decode_one(g_d, code, sizeof(code), 0x1000, &insn) == CBAE_OK);
    assert(insn.length == 1);
    assert(insn.iclass == CBAE_ICLASS_STACK);
    assert(insn.operand_count == 1);
    assert(insn.operands[0].kind == CBAE_OPND_REG);
    assert(insn.operands[0].u.reg.reg == CBAE_REG_RBP);
    printf("  [PASS] PUSH RBP\n");
}

static void t_mov_rbp_rsp(void) {
    /* REX.W + 89 /r, ModRM=E5 (mod=11 reg=100/RSP rm=101/RBP)
     * -> MOV RBP, RSP (destination=rm=RBP, source=reg=RSP) */
    uint8_t code[] = {0x48,0x89,0xE5};
    cbae_instruction_t insn;
    assert(cbae_disasm_decode_one(g_d, code, sizeof(code), 0x1000, &insn) == CBAE_OK);
    assert(insn.length == 3);
    assert(insn.iclass == CBAE_ICLASS_MOV);
    assert(insn.operand_count == 2);
    assert(insn.operands[0].kind==CBAE_OPND_REG && insn.operands[0].u.reg.reg==CBAE_REG_RBP);
    assert(insn.operands[1].kind==CBAE_OPND_REG && insn.operands[1].u.reg.reg==CBAE_REG_RSP);
    printf("  [PASS] MOV RBP, RSP\n");
}

static void t_sub_rsp_imm8(void) {
    /* REX.W + 83 /5 ib, ModRM=EC (reg=101=/5 confirms SUB, rm=100/RSP) */
    uint8_t code[] = {0x48,0x83,0xEC,0x20};
    cbae_instruction_t insn;
    assert(cbae_disasm_decode_one(g_d, code, sizeof(code), 0x1000, &insn) == CBAE_OK);
    assert(insn.length == 4);
    assert(insn.iclass == CBAE_ICLASS_ARITH);
    assert(insn.operand_count == 2);
    assert(insn.operands[1].kind==CBAE_OPND_IMM && insn.operands[1].u.imm.value==0x20);
    printf("  [PASS] SUB RSP, 0x20\n");
}

static void t_ret(void) {
    uint8_t code[] = {0xC3};
    cbae_instruction_t insn;
    assert(cbae_disasm_decode_one(g_d, code, sizeof(code), 0x1000, &insn) == CBAE_OK);
    assert(insn.length == 1);
    assert(insn.iclass == CBAE_ICLASS_RET);
    assert(insn.is_ret);
    printf("  [PASS] RET\n");
}

static void t_call_rel32(void) {
    uint8_t code[] = {0xE8, 0x00,0x01,0x00,0x00}; /* rel32 = 0x100 */
    cbae_instruction_t insn;
    cbae_addr_t base = 0x2000;
    assert(cbae_disasm_decode_one(g_d, code, sizeof(code), base, &insn) == CBAE_OK);
    assert(insn.length == 5);
    assert(insn.iclass == CBAE_ICLASS_CALL);
    assert(insn.is_call);
    assert(insn.branch_target_is_direct);
    assert(insn.branch_target == base + 5 + 0x100);
    printf("  [PASS] CALL rel32 (target=0x%llx)\n",
           (unsigned long long)insn.branch_target);
}

static void t_jmp_rel32(void) {
    uint8_t code[] = {0xE9, 0x10,0x00,0x00,0x00}; /* rel32 = 0x10 */
    cbae_instruction_t insn;
    cbae_addr_t base = 0x3000;
    assert(cbae_disasm_decode_one(g_d, code, sizeof(code), base, &insn) == CBAE_OK);
    assert(insn.iclass == CBAE_ICLASS_JMP);
    assert(insn.branch_target_is_direct);
    assert(insn.branch_target == base + 5 + 0x10);
    printf("  [PASS] JMP rel32\n");
}

static void t_je_rel8(void) {
    uint8_t code[] = {0x74, 0x0A}; /* je +0x0a */
    cbae_instruction_t insn;
    cbae_addr_t base = 0x4000;
    assert(cbae_disasm_decode_one(g_d, code, sizeof(code), base, &insn) == CBAE_OK);
    assert(insn.length == 2);
    assert(insn.iclass == CBAE_ICLASS_JCC);
    assert(insn.is_conditional);
    assert(insn.branch_target_is_direct);
    assert(insn.branch_target == base + 2 + 0x0A);
    printf("  [PASS] JE rel8 (conditional jump group detection)\n");
}

static void t_mov_rax_imm64(void) {
    /* REX.W + B8 = MOV RAX, imm64 */
    uint8_t code[] = {0x48,0xB8, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    cbae_instruction_t insn;
    assert(cbae_disasm_decode_one(g_d, code, sizeof(code), 0x5000, &insn) == CBAE_OK);
    assert(insn.length == 10);
    assert(insn.iclass == CBAE_ICLASS_MOV);
    assert(insn.operands[1].kind == CBAE_OPND_IMM);
    assert((uint64_t)insn.operands[1].u.imm.value == 0x8877665544332211ULL);
    printf("  [PASS] MOV RAX, imm64\n");
}

static void t_call_rip_relative(void) {
    /* FF 15 disp32 -- CALL qword ptr [RIP+disp32]. This is THE standard
     * compiler-generated pattern for calling through an IAT slot on
     * position-independent x64 PE code. */
    uint8_t code[] = {0xFF,0x15, 0x00,0x10,0x00,0x00};
    cbae_instruction_t insn;
    cbae_addr_t base = 0x6000;
    assert(cbae_disasm_decode_one(g_d, code, sizeof(code), base, &insn) == CBAE_OK);
    assert(insn.length == 6);
    assert(insn.iclass == CBAE_ICLASS_CALL);
    assert(!insn.branch_target_is_direct); /* memory-indirect, not immediate */
    assert(insn.operand_count == 1);
    assert(insn.operands[0].kind == CBAE_OPND_MEM);
    assert(insn.operands[0].u.mem.base == CBAE_REG_RIP);
    assert(insn.operands[0].u.mem.disp == 0x1000);
    printf("  [PASS] CALL [RIP+disp] (IAT-style indirect call pattern)\n");
}

static void t_io_and_msr(void) {
    uint8_t in_al_dx[] = {0xEC};
    uint8_t rdmsr[]    = {0x0F,0x32};
    cbae_instruction_t insn;
    assert(cbae_disasm_decode_one(g_d, in_al_dx, sizeof(in_al_dx), 0x7000, &insn) == CBAE_OK);
    assert(insn.iclass == CBAE_ICLASS_IO);
    assert(cbae_disasm_decode_one(g_d, rdmsr, sizeof(rdmsr), 0x7001, &insn) == CBAE_OK);
    assert(insn.iclass == CBAE_ICLASS_MSR);
    printf("  [PASS] IN / RDMSR classified correctly\n");
}

static void t_incomplete_instruction(void) {
    /* A lone REX prefix with no following opcode byte within the given
     * buffer is not a complete instruction -- Capstone must fail to
     * decode it within 1 byte. This is a portable way to test the
     * failure path without depending on uncertain reserved-opcode
     * trivia. */
    uint8_t bad[] = {0x48};
    cbae_instruction_t insn;
    cbae_err_t e = cbae_disasm_decode_one(g_d, bad, sizeof(bad), 0x8000, &insn);
    assert(e == CBAE_ERR_PARSE);
    printf("  [PASS] incomplete instruction -> CBAE_ERR_PARSE\n");
}

int main(void) {
    printf("=== test_disassembler ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);
    assert(cbae_disasm_create(CBAE_ARCH_X86_64, &g_d) == CBAE_OK);

    t_nop();
    t_push_rbp();
    t_mov_rbp_rsp();
    t_sub_rsp_imm8();
    t_ret();
    t_call_rel32();
    t_jmp_rel32();
    t_je_rel8();
    t_mov_rax_imm64();
    t_call_rip_relative();
    t_io_and_msr();
    t_incomplete_instruction();

    cbae_disasm_destroy(&g_d);
    printf("All disassembler tests passed.\n");
    return 0;
}
