/**
 * @file test_cir_lifter.c
 * @brief Lift several carefully hand-traced x86-64 sequences covering
 *        every specialized lifter and verify the resulting CIR
 *        structure matches expectations computed by hand before
 *        running the test -- same rigor as Phase 3's mid-block-split
 *        test.
 *
 * All test bytes use 64-bit register forms exclusively (mov rax not
 * eax) -- Phase 3's operand decoder maps every narrow (32/16/8-bit)
 * register form to a single CBAE_REG_OTHER catch-all, which Phase 4's
 * lifter deliberately does NOT track precisely (see cir_lifter.c);
 * using narrow forms here would test a known, documented limitation
 * rather than the lifter's actual intended behavior.
 */
#include "cir/cir_lifter.h"
#include "cir/cir_printer.h"
#include "disasm/cfg.h"
#include "disasm/call_graph.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static cbae_binary_image_t *make_code_image(const uint8_t *code, size_t len,
                                              cbae_addr_t base) {
    cbae_binary_image_t *img = NULL;
    cbae_image_create(0, &img);
    img->format      = CBAE_FMT_PE32PLUS;
    img->arch        = CBAE_ARCH_X86_64;
    img->os_origin   = CBAE_OS_WINDOWS;
    img->load_base   = base;
    img->entry_point = base;

    img->sections = CBAE_ARENA_ALLOC(&img->arena, cbae_section_t);
    img->section_count = 1;
    uint8_t *data = cbae_arena_alloc(&img->arena, len, 1);
    memcpy(data, code, len);

    strncpy(img->sections[0].name, ".text", CBAE_SEC_NAME_MAX - 1);
    img->sections[0].virt_addr   = base;
    img->sections[0].virt_size   = len;
    img->sections[0].file_offset = 0;
    img->sections[0].file_size   = len;
    img->sections[0].flags       = CBAE_SEC_EXEC | CBAE_SEC_READ;
    img->sections[0].data        = data;

    cbae_image_build_indexes(img);
    return img;
}

static uint32_t count_opcode(const cbae_cir_block_t *blk, cbae_cir_opcode_t op) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < blk->instruction_count; i++)
        if (blk->instructions[i]->opcode == op) n++;
    return n;
}

static void t_prologue_epilogue(void) {
    /*   55                push rbp
     *   48 89 E5          mov rbp, rsp
     *   48 83 EC 20       sub rsp, 0x20
     *   90                nop
     *   48 89 EC          mov rsp, rbp
     *   5D                pop rbp
     *   C3                ret
     *
     * Hand-traced: push -> SUB+STORE; mov rbp,rsp -> pure propagation,
     * 0 instructions; sub rsp,0x20 -> SUB; nop -> 0 instructions;
     * mov rsp,rbp -> pure propagation, 0 instructions; pop -> LOAD+ADD;
     * ret -> RETURN. Total: 6 real CIR instructions.
     */
    uint8_t code[] = {
        0x55,
        0x48,0x89,0xE5,
        0x48,0x83,0xEC,0x20,
        0x90,
        0x48,0x89,0xEC,
        0x5D,
        0xC3
    };
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x1000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x1000, &arena, &cfg) == CBAE_OK);
    assert(cbae_cfg_block_count(&cfg) == 1);

    cbae_cir_function_t *f;
    assert(cbae_cir_lift_function(img, &cfg, NULL, &arena, "prologue", &f) == CBAE_OK);

    cbae_cir_block_t *blk = cbae_cir_function_block_at(f, 0x1000);
    assert(blk != NULL);

    printf("\n--- CIR for t_prologue_epilogue ---\n");
    cbae_cir_print_function(f, stdout);
    printf("--- end ---\n\n");

    assert(blk->instruction_count == 6);
    assert(count_opcode(blk, CIR_OP_SUB)    == 2);
    assert(count_opcode(blk, CIR_OP_STORE)  == 1);
    assert(count_opcode(blk, CIR_OP_LOAD)   == 1);
    assert(count_opcode(blk, CIR_OP_ADD)    == 1);
    assert(count_opcode(blk, CIR_OP_RETURN) == 1);

    cbae_cir_instruction_t *ret = blk->instructions[blk->instruction_count - 1];
    assert(ret->opcode == CIR_OP_RETURN);
    assert(ret->operand_count == 1);
    assert(ret->operands[0]->kind == CIR_VAL_REG_ENTRY);
    assert(ret->operands[0]->u.reg_entry.reg == CBAE_REG_RAX);

    cbae_cir_function_destroy(f);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] prologue/epilogue: 6 instructions, RAX correctly unresolved\n");
}

static void t_load_add_return(void) {
    uint8_t code[] = { 0x48,0x8B,0x03, 0x48,0x83,0xC0,0x05, 0xC3 };
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x2000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x2000, &arena, &cfg) == CBAE_OK);

    cbae_cir_function_t *f;
    assert(cbae_cir_lift_function(img, &cfg, NULL, &arena, "load_add", &f) == CBAE_OK);
    cbae_cir_block_t *blk = cbae_cir_function_block_at(f, 0x2000);
    assert(blk != NULL);
    assert(blk->instruction_count == 3);

    cbae_cir_instruction_t *load = blk->instructions[0];
    assert(load->opcode == CIR_OP_LOAD);
    assert(load->operands[0]->kind == CIR_VAL_REG_ENTRY);
    assert(load->operands[0]->u.reg_entry.reg == CBAE_REG_RBX);

    cbae_cir_instruction_t *add = blk->instructions[1];
    assert(add->opcode == CIR_OP_ADD);
    assert(add->operands[0] == load->result);
    assert(add->operands[1]->kind == CIR_VAL_CONST);
    assert(add->operands[1]->u.const_val == 5);

    cbae_cir_instruction_t *ret = blk->instructions[2];
    assert(ret->opcode == CIR_OP_RETURN);
    assert(ret->operands[0] == add->result);

    cbae_cir_function_destroy(f);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] load+add+return: correct value chaining LOAD->ADD->RETURN\n");
}

static void t_cmp_je_relay(void) {
    uint8_t code[] = { 0x48,0x39,0xD8, 0x74,0x02, 0xC3, 0x90, 0xC3 };
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x5000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x5000, &arena, &cfg) == CBAE_OK);

    cbae_cir_function_t *f;
    assert(cbae_cir_lift_function(img, &cfg, NULL, &arena, "cmp_je", &f) == CBAE_OK);
    cbae_cir_block_t *entry = cbae_cir_function_block_at(f, 0x5000);
    assert(entry != NULL);
    assert(entry->instruction_count == 2);

    cbae_cir_instruction_t *cmp = entry->instructions[0];
    assert(cmp->opcode == CIR_OP_CMP);
    assert(cmp->operands[0]->kind == CIR_VAL_REG_ENTRY &&
           cmp->operands[0]->u.reg_entry.reg == CBAE_REG_RAX);
    assert(cmp->operands[1]->kind == CIR_VAL_REG_ENTRY &&
           cmp->operands[1]->u.reg_entry.reg == CBAE_REG_RBX);

    cbae_cir_instruction_t *branch = entry->instructions[1];
    assert(branch->opcode == CIR_OP_BRANCH);
    assert(branch->operands[0] == cmp->result);

    cbae_cir_function_destroy(f);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] CMP+JE relay: branch condition is CMP's actual result\n");
}

static void t_diamond_branch_wiring(void) {
    uint8_t code[] = {0x74,0x04, 0x90, 0xEB,0x02, 0x90, 0xC3, 0xC3};
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x3000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x3000, &arena, &cfg) == CBAE_OK);
    assert(cbae_cfg_block_count(&cfg) == 4);

    cbae_cir_function_t *f;
    assert(cbae_cir_lift_function(img, &cfg, NULL, &arena, "diamond", &f) == CBAE_OK);

    cbae_cir_block_t *entry = cbae_cir_function_block_at(f, 0x3000);
    cbae_cir_block_t *jetgt = cbae_cir_function_block_at(f, 0x3006);
    cbae_cir_block_t *fall  = cbae_cir_function_block_at(f, 0x3002);
    cbae_cir_block_t *conv  = cbae_cir_function_block_at(f, 0x3007);
    assert(entry && jetgt && fall && conv);

    assert(entry->instruction_count == 1);
    assert(entry->instructions[0]->opcode == CIR_OP_BRANCH);
    assert(entry->instructions[0]->branch_true_block  == jetgt->id);
    assert(entry->instructions[0]->branch_false_block == fall->id);

    assert(fall->instruction_count == 1);
    assert(fall->instructions[0]->opcode == CIR_OP_JUMP);
    assert(fall->instructions[0]->branch_true_block == conv->id);

    assert(jetgt->instruction_count == 1);
    assert(jetgt->instructions[0]->opcode == CIR_OP_RETURN);
    assert(conv->instruction_count == 1);
    assert(conv->instructions[0]->opcode == CIR_OP_RETURN);

    assert(entry->successor_count == 2);
    assert(cbae_vector_count(&jetgt->predecessors) == 1);
    assert(cbae_vector_count(&conv->predecessors) == 1);

    cbae_cir_function_destroy(f);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] diamond branch wiring: all 4 blocks and edges correct\n");
}

static void t_call_seeds_import_name(void) {
    cbae_addr_t base   = 0x6000;
    cbae_addr_t iat_va = 0x9000;
    int32_t disp = (int32_t)(iat_va - (base + 6));

    uint8_t code[6];
    code[0] = 0xFF; code[1] = 0x15;
    memcpy(&code[2], &disp, 4);

    cbae_binary_image_t *img = make_code_image(code, sizeof(code), base);
    img->imports = CBAE_ARENA_ALLOC(&img->arena, cbae_import_entry_t);
    img->import_count = 1;
    memset(img->imports, 0, sizeof(cbae_import_entry_t));
    strncpy(img->imports[0].name, "ExAllocatePoolWithTag", CBAE_IMPORT_NAME_MAX - 1);
    strncpy(img->imports[0].module, "ntoskrnl.exe", CBAE_IMPORT_MODULE_MAX - 1);
    img->imports[0].iat_va = iat_va;
    img->imports[0].state  = CBAE_IMPORT_BY_NAME;
    cbae_image_build_indexes(img);

    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);
    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, base, &arena, &cfg) == CBAE_OK);

    cbae_call_graph_t cg;
    cbae_call_graph_init(&cg);
    assert(cbae_call_graph_add_function(&cg, img, &cfg, base) == CBAE_OK);

    cbae_cir_function_t *f;
    assert(cbae_cir_lift_function(img, &cfg, &cg, &arena, "call_test", &f) == CBAE_OK);

    cbae_cir_block_t *blk = cbae_cir_function_block_at(f, base);
    assert(blk && blk->instruction_count == 1);
    cbae_cir_instruction_t *call = blk->instructions[0];
    assert(call->opcode == CIR_OP_CALL);
    assert(call->call_target_name != NULL);
    assert(strcmp(call->call_target_name, "ExAllocatePoolWithTag") == 0);

    cbae_call_graph_destroy(&cg);
    cbae_cir_function_destroy(f);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] CALL seeded with resolved import name from Phase 3\n");
}

int main(void) {
    printf("=== test_cir_lifter ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);

    t_prologue_epilogue();
    t_load_add_return();
    t_cmp_je_relay();
    t_diamond_branch_wiring();
    t_call_seeds_import_name();

    printf("All CIR lifter tests passed.\n");
    return 0;
}
