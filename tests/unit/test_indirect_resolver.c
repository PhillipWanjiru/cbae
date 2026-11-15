/**
 * @file test_indirect_resolver.c
 * @brief Unit tests for call graph construction and indirect call
 *        resolution: direct calls, IAT-relative import calls, and
 *        register-indirect calls resolved via backward pattern match.
 */
#include "disasm/call_graph.h"
#include "disasm/cfg.h"
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

/* ── Test 1: direct call gets classified without needing the resolver ── */
static void t_direct_call(void) {
    uint8_t code[] = { 0xE8, 0x00,0x00,0x00,0x00, 0xC3 }; /* call +0; ret */
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x1000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64*1024);
    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x1000, &arena, &cfg) == CBAE_OK);

    cbae_call_graph_t cg;
    cbae_call_graph_init(&cg);
    assert(cbae_call_graph_add_function(&cg, img, &cfg, 0x1000) == CBAE_OK);
    assert(cbae_call_graph_edge_count(&cg) == 1);

    const cbae_call_edge_t *e = cbae_call_graph_edge_at(&cg, 0);
    assert(e->kind == CBAE_CALL_DIRECT);
    assert(e->target == 0x1005); /* call+0 targets the very next byte */

    cbae_call_graph_destroy(&cg);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] direct call classified CBAE_CALL_DIRECT\n");
}

/* ── Test 2: CALL [RIP+disp] landing on a known import's IAT slot ────── */
static void t_iat_call_resolved_directly(void) {
    cbae_addr_t base   = 0x2000;
    cbae_addr_t iat_va = 0x9000;
    int32_t disp = (int32_t)(iat_va - (base + 6)); /* insn end = base+6 */

    uint8_t code[6];
    code[0] = 0xFF; code[1] = 0x15;
    memcpy(&code[2], &disp, 4);

    cbae_binary_image_t *img = make_code_image(code, sizeof(code), base);

    /* Inject one import entry with the matching IAT VA, then re-index
     * so iat_to_import picks it up. */
    img->imports = CBAE_ARENA_ALLOC(&img->arena, cbae_import_entry_t);
    img->import_count = 1;
    memset(img->imports, 0, sizeof(cbae_import_entry_t));
    strncpy(img->imports[0].name, "ExAllocatePoolWithTag", CBAE_IMPORT_NAME_MAX-1);
    strncpy(img->imports[0].module, "ntoskrnl.exe", CBAE_IMPORT_MODULE_MAX-1);
    img->imports[0].iat_va = iat_va;
    img->imports[0].state  = CBAE_IMPORT_BY_NAME;
    cbae_image_build_indexes(img);

    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64*1024);
    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, base, &arena, &cfg) == CBAE_OK);

    cbae_call_graph_t cg;
    cbae_call_graph_init(&cg);
    assert(cbae_call_graph_add_function(&cg, img, &cfg, base) == CBAE_OK);
    assert(cbae_call_graph_edge_count(&cg) == 1);

    const cbae_call_edge_t *e = cbae_call_graph_edge_at(&cg, 0);
    assert(e->kind == CBAE_CALL_IMPORT);
    assert(e->import_name && !strcmp(e->import_name, "ExAllocatePoolWithTag"));

    cbae_call_graph_destroy(&cg);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] CALL [RIP+disp] resolved directly to import (RIP-relative math correct)\n");
}

/* ── Test 3: register-indirect call resolved via backward mov pattern ── */
static void t_resolve_mov_reg_call(void) {
    uint8_t code[] = {
        0x48,0xB8, 0x00,0x50,0x00,0x00,0x00,0x00,0x00,0x00, /* mov rax, 0x5000 */
        0xFF,0xD0,                                          /* call rax        */
        0xC3                                                /* ret             */
    };
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x6000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64*1024);
    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x6000, &arena, &cfg) == CBAE_OK);

    cbae_call_graph_t cg;
    cbae_call_graph_init(&cg);
    assert(cbae_call_graph_add_function(&cg, img, &cfg, 0x6000) == CBAE_OK);
    assert(cbae_call_graph_edge_count(&cg) == 1);

    const cbae_call_edge_t *before = cbae_call_graph_edge_at(&cg, 0);
    assert(before->kind == CBAE_CALL_INDIRECT); /* unresolved before the pass */

    uint32_t upgraded = cbae_resolve_indirect_calls(&cg, img, &cfg);
    assert(upgraded == 1);

    const cbae_call_edge_t *after = cbae_call_graph_edge_at(&cg, 0);
    assert(after->kind == CBAE_CALL_DIRECT);
    assert(after->target == 0x5000);

    cbae_call_graph_destroy(&cg);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] register-indirect call resolved via backward mov reg,imm64\n");
}

/* ── Test 4: resolver correctly declines when the register write is
 *           NOT a simple mov-imm/lea-rip (a memory load, in this case) ── */
static void t_unresolvable_stays_indirect(void) {
    uint8_t code[] = {
        0x48,0x8B,0x00,   /* mov rax, [rax]  -- not resolvable statically */
        0xFF,0xD0,        /* call rax                                    */
        0xC3              /* ret                                         */
    };
    cbae_binary_image_t *img = make_code_image(code, sizeof(code), 0x7000);
    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 64*1024);
    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x7000, &arena, &cfg) == CBAE_OK);

    cbae_call_graph_t cg;
    cbae_call_graph_init(&cg);
    assert(cbae_call_graph_add_function(&cg, img, &cfg, 0x7000) == CBAE_OK);

    uint32_t upgraded = cbae_resolve_indirect_calls(&cg, img, &cfg);
    assert(upgraded == 0); /* correctly declines -- no false positive */

    const cbae_call_edge_t *e = cbae_call_graph_edge_at(&cg, 0);
    assert(e->kind == CBAE_CALL_INDIRECT);

    cbae_call_graph_destroy(&cg);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] resolver correctly declines unresolvable pattern (no false positive)\n");
}

int main(void) {
    printf("=== test_indirect_resolver ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);

    t_direct_call();
    t_iat_call_resolved_directly();
    t_resolve_mov_reg_call();
    t_unresolvable_stays_indirect();

    printf("All indirect resolver tests passed.\n");
    return 0;
}
