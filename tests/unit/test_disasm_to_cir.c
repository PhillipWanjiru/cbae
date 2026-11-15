/**
 * @file test_disasm_to_cir.c
 * @brief End-to-end integration test: cbae_pe_load -> cbae_cfg_build ->
 *        cbae_cir_lift_function -> cbae_cir_construct_ssa ->
 *        cbae_cir_verify_function, plus a serializer round-trip.
 */
#include "loader/pe_loader.h"
#include "disasm/cfg.h"
#include "disasm/call_graph.h"
#include "cir/cir_lifter.h"
#include "cir/cir_ssa.h"
#include "cir/cir_verifier.h"
#include "cir/cir_serializer.h"
#include "cir/cir_printer.h"
#include "platform/logging.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define DOS_MAGIC     0x5A4D
#define PE_SIG        0x00004550
#define OPT_PE32P     0x020B
#define MACH_AMD64    0x8664
#define SUBSYS_NATIVE 1
#define IBASE         UINT64_C(0xFFFFF80000000000)

#pragma pack(push,1)
typedef struct { uint16_t magic; uint8_t _[58]; uint32_t lfanew; } t_dos;
typedef struct {
    uint16_t machine,nsec,ts0,ts1; uint32_t sp,ns; uint16_t optsz,chars;
} t_coff;
typedef struct { uint32_t rva,sz; } t_dd;
typedef struct {
    uint16_t magic,ml,mn; uint32_t cs,is,us,ep,cb;
    uint64_t ibase;
    uint32_t sa,fa; uint8_t _w[16];
    uint32_t imgsz,hdrsz,ck; uint16_t sub,dc;
    uint8_t _s[32]; uint32_t ndirs; t_dd dirs[16];
} t_opt;
typedef struct {
    uint8_t name[8]; uint32_t vsz,va,rsz,roff; uint8_t _[12]; uint32_t chars;
} t_sec;
#pragma pack(pop)

static char g_tmp[256];
static void cleanup(void) { if (g_tmp[0]) unlink(g_tmp); }

/*
 *   55                      push rbp
 *   48 89 E5                mov rbp, rsp
 *   48 B8 00 00 00 00 00 00 00 00   mov rax, 0        ; loop counter
 * loop_head:
 *   48 83 C0 01              add rax, 1
 *   48 83 F8 0A               cmp rax, 10
 *   0F 8C F2 FF FF FF          jl loop_head
 *   5D                         pop rbp
 *   C3                         ret
 */
static const uint8_t FUNC_BYTES[] = {
    0x55,
    0x48,0x89,0xE5,
    0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x48,0x83,0xC0,0x01,
    0x48,0x83,0xF8,0x0A,
    0x0F,0x8C,0xF2,0xFF,0xFF,0xFF,
    0x5D,
    0xC3
};
#define FUNC_LEN sizeof(FUNC_BYTES)

static void write_synthetic_pe(void) {
    uint8_t buf[0x600];
    memset(buf, 0, sizeof(buf));

    t_dos *dos = (t_dos *)buf;
    dos->magic = DOS_MAGIC;
    dos->lfanew = 0x40;
    *(uint32_t *)(buf + 0x40) = PE_SIG;

    t_coff *coff = (t_coff *)(buf + 0x44);
    coff->machine = MACH_AMD64;
    coff->nsec = 1;
    coff->optsz = (uint16_t)sizeof(t_opt);
    coff->chars = 0x0002;

    t_opt *opt = (t_opt *)(buf + 0x44 + sizeof(t_coff));
    opt->magic = OPT_PE32P;
    opt->ep = 0x1000;
    opt->ibase = IBASE;
    opt->sa = 0x1000;
    opt->fa = 0x200;
    opt->imgsz = 0x3000;
    opt->hdrsz = 0x400;
    opt->sub = SUBSYS_NATIVE;
    opt->ndirs = 16;

    t_sec *sec = (t_sec *)((uint8_t *)opt + sizeof(t_opt));
    memcpy(sec->name, ".text\0\0\0", 8);
    sec->vsz = 0x1000;
    sec->va = 0x1000;
    sec->rsz = (uint32_t)FUNC_LEN;
    sec->roff = 0x400;
    sec->chars = 0x60000020;

    memcpy(buf + 0x400, FUNC_BYTES, FUNC_LEN);

    snprintf(g_tmp, sizeof(g_tmp), "/tmp/cbae_disasm_to_cir_%d.sys", (int)getpid());
    atexit(cleanup);
    FILE *f = fopen(g_tmp, "wb");
    assert(f);
    fwrite(buf, 1, sizeof(buf), f);
    fclose(f);
}

static void t_full_pipeline_verifies_clean(void) {
    cbae_binary_image_t *img = NULL;
    assert(cbae_pe_load(g_tmp, &img) == CBAE_OK);

    cbae_disassembler_t *d;
    assert(cbae_disasm_create(CBAE_ARCH_X86_64, &d) == CBAE_OK);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 512 * 1024);

    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, img->entry_point, &arena, &cfg) == CBAE_OK);
    assert(cbae_cfg_block_count(&cfg) == 3);

    cbae_call_graph_t cg;
    cbae_call_graph_init(&cg);
    assert(cbae_call_graph_add_function(&cg, img, &cfg, img->entry_point) == CBAE_OK);

    cbae_cir_function_t *f;
    assert(cbae_cir_lift_function(img, &cfg, &cg, &arena, "DriverEntry", &f) == CBAE_OK);
    assert(cbae_cir_construct_ssa(f) == CBAE_OK);

    printf("\n--- Full pipeline CIR (post-SSA) ---\n");
    cbae_cir_print_function(f, stdout);
    printf("--- end ---\n\n");

    cbae_cir_verify_result_t vr = cbae_cir_verify_function(f);
    if (!vr.ok) fprintf(stderr, "VERIFIER FAILED: %s\n", vr.message);
    assert(vr.ok);

    cbae_call_graph_destroy(&cg);
    cbae_cir_function_destroy(f);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] full pipeline: loader->disasm->lift->SSA->verify, all clean\n");
}

static void t_serializer_round_trip(void) {
    uint8_t code[] = {
        0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x48,0x83,0xC0,0x01,
        0x48,0x83,0xF8,0x0A,
        0x0F,0x8C,0xF2,0xFF,0xFF,0xFF,
        0xC3
    };
    cbae_binary_image_t *img = NULL;
    cbae_image_create(0, &img);
    img->format = CBAE_FMT_PE32PLUS;
    img->arch = CBAE_ARCH_X86_64;
    img->os_origin = CBAE_OS_WINDOWS;
    img->load_base = 0x2000;
    img->entry_point = 0x2000;
    img->sections = CBAE_ARENA_ALLOC(&img->arena, cbae_section_t);
    img->section_count = 1;
    uint8_t *data = cbae_arena_alloc(&img->arena, sizeof(code), 1);
    memcpy(data, code, sizeof(code));
    strncpy(img->sections[0].name, ".text", CBAE_SEC_NAME_MAX - 1);
    img->sections[0].virt_addr = 0x2000;
    img->sections[0].virt_size = sizeof(code);
    img->sections[0].file_size = sizeof(code);
    img->sections[0].flags = CBAE_SEC_EXEC | CBAE_SEC_READ;
    img->sections[0].data = data;
    cbae_image_build_indexes(img);

    cbae_disassembler_t *d;
    cbae_disasm_create(CBAE_ARCH_X86_64, &d);
    cbae_arena_t arena;
    cbae_arena_init(&arena, 256 * 1024);
    cbae_cfg_t cfg;
    assert(cbae_cfg_build(img, d, 0x2000, &arena, &cfg) == CBAE_OK);

    cbae_cir_function_t *orig;
    assert(cbae_cir_lift_function(img, &cfg, NULL, &arena, "roundtrip", &orig) == CBAE_OK);
    assert(cbae_cir_construct_ssa(orig) == CBAE_OK);
    assert(cbae_cir_verify_function(orig).ok);

    uint8_t *blob = NULL;
    size_t blob_size = 0;
    assert(cbae_cir_serialize_function(orig, &blob, &blob_size) == CBAE_OK);
    assert(blob != NULL && blob_size > 0);

    cbae_arena_t arena2;
    cbae_arena_init(&arena2, 256 * 1024);
    cbae_cir_function_t *copy;
    assert(cbae_cir_deserialize_function(blob, blob_size, &arena2, &copy) == CBAE_OK);
    free(blob);

    cbae_cir_verify_result_t vr = cbae_cir_verify_function(copy);
    if (!vr.ok) fprintf(stderr, "ROUND-TRIP VERIFIER FAILED: %s\n", vr.message);
    assert(vr.ok);

    assert(cbae_vector_count(&copy->blocks) == cbae_vector_count(&orig->blocks));
    assert(cbae_vector_count(&copy->values) == cbae_vector_count(&orig->values));
    assert(copy->entry_addr == orig->entry_addr);
    assert(strcmp(copy->name, orig->name) == 0);

    cbae_cir_block_t *orig_head = cbae_cir_function_block_at(orig, 0x200A);
    cbae_cir_block_t *copy_head = cbae_cir_function_block_at(copy, 0x200A);
    assert(orig_head && copy_head);
    assert(orig_head->instruction_count == copy_head->instruction_count);
    assert(cbae_vector_count(&orig_head->predecessors) ==
           cbae_vector_count(&copy_head->predecessors));
    assert(copy_head->instructions[0]->opcode == CIR_OP_PHI);
    assert(copy_head->instructions[0]->phi_incoming_count == 2);

    bool saw_const0 = false;
    cbae_cir_instruction_t *phi = copy_head->instructions[0];
    for (uint32_t i = 0; i < phi->phi_incoming_count; i++) {
        cbae_cir_value_t *v = phi->phi_incoming_values[i];
        if (v->kind == CIR_VAL_CONST && v->u.const_val == 0) saw_const0 = true;
    }
    assert(saw_const0);

    cbae_cir_function_destroy(copy);
    cbae_arena_destroy(&arena2);
    cbae_cir_function_destroy(orig);
    cbae_cfg_destroy(&cfg);
    cbae_arena_destroy(&arena);
    cbae_disasm_destroy(&d);
    cbae_image_destroy(&img);
    printf("  [PASS] serializer round-trip: deserialized copy verifies clean, "
           "structurally matches original\n");
}

int main(void) {
    printf("=== test_disasm_to_cir ===\n");
    cbae_log_init(CBAE_LOG_WARN, NULL, 0);

    write_synthetic_pe();
    printf("  synthetic PE: %s\n", g_tmp);

    t_full_pipeline_verifies_clean();
    t_serializer_round_trip();

    printf("All disasm-to-CIR integration tests passed.\n");
    return 0;
}
