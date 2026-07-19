/**
 * @file function_boundary_finder.c
 * @brief Function entry point discovery from multiple sources, in
 *        priority order: entry point, symbol table, PE .pdata
 *        RUNTIME_FUNCTION table, prologue byte-pattern scan.
 *
 * .pdata IS GROUND TRUTH, NOT A HEURISTIC:
 *   Every x86-64 Windows function whose prologue allocates stack space
 *   or uses non-volatile registers gets a compiler-generated
 *   RUNTIME_FUNCTION entry in .pdata (required for structured exception
 *   handling and stack unwinding to work at all). Parsing this table
 *   gives exact [begin, end) ranges for the large majority of functions
 *   in a driver -- this is the single best source of function boundary
 *   truth available on PE64, better than any byte-pattern heuristic.
 *
 * The prologue scan (source 4) exists purely to fill gaps: leaf
 * functions that need no stack frame have no unwind data and won't
 * appear in .pdata at all.
 */
#include "disasm/function.h"
#include "platform/logging.h"
#include <string.h>

cbae_err_t cbae_function_set_init(cbae_function_set_t *fs) {
    if (!fs) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null function set");
    return cbae_vector_init(&fs->functions, sizeof(cbae_function_t), 32);
}

void cbae_function_set_destroy(cbae_function_set_t *fs) {
    if (!fs) return;
    cbae_vector_destroy(&fs->functions);
}

uint32_t cbae_function_set_count(const cbae_function_set_t *fs) {
    return (uint32_t)cbae_vector_count(&fs->functions);
}

cbae_function_t *cbae_function_set_at(const cbae_function_set_t *fs, uint32_t idx) {
    return (cbae_function_t *)cbae_vector_at(&fs->functions, idx);
}

cbae_function_t *cbae_function_set_find(const cbae_function_set_t *fs, cbae_addr_t addr) {
    uint32_t n = cbae_function_set_count(fs);
    for (uint32_t i = 0; i < n; i++) {
        cbae_function_t *f = cbae_function_set_at(fs, i);
        if (f->entry_addr == addr) return f;
    }
    return NULL;
}

static cbae_err_t add_function(cbae_function_set_t *fs, cbae_addr_t addr,
                                 const char *name, cbae_func_role_t role,
                                 cbae_func_source_t source) {
    if (cbae_function_set_find(fs, addr)) return CBAE_OK; /* dedup: lower-
        priority sources never override an already-discovered entry     */
    cbae_function_t f;
    memset(&f, 0, sizeof(f));
    f.entry_addr = addr;
    f.end_addr   = CBAE_ADDR_INVALID;
    if (name) strncpy(f.name, name, sizeof(f.name) - 1);
    f.role   = role;
    f.source = source;
    return cbae_vector_push(&fs->functions, &f);
}

/* ── Source 3: PE .pdata RUNTIME_FUNCTION table ─────────────────────── */
#pragma pack(push, 1)
typedef struct { uint32_t begin_rva, end_rva, unwind_rva; } pdata_entry_t;
#pragma pack(pop)

static cbae_err_t scan_pdata(const cbae_binary_image_t *img, cbae_function_set_t *fs) {
    if (img->format != CBAE_FMT_PE32PLUS) return CBAE_OK;
    cbae_section_t *pdata = cbae_image_section_by_name(img, ".pdata");
    if (!pdata || !pdata->data) return CBAE_OK;

    uint32_t n = (uint32_t)(pdata->file_size / sizeof(pdata_entry_t));
    const pdata_entry_t *entries = (const pdata_entry_t *)pdata->data;
    uint32_t added = 0;

    for (uint32_t i = 0; i < n; i++) {
        if (!entries[i].begin_rva) continue;
        cbae_addr_t entry_va = img->load_base + entries[i].begin_rva;
        cbae_addr_t end_va   = img->load_base + entries[i].end_rva;

        CBAE_CHECK(add_function(fs, entry_va, NULL, CBAE_ROLE_LOCAL, CBAE_FSRC_PDATA));

        cbae_function_t *f = cbae_function_set_find(fs, entry_va);
        if (f && f->source == CBAE_FSRC_PDATA) f->end_addr = end_va;
        added++;
    }
    LOG_DEBUG("  .pdata: %u RUNTIME_FUNCTION entries", added);
    return CBAE_OK;
}

/* ── Source 2: ELF .symtab / PE export-table function symbols ──────── */
static cbae_err_t scan_symbols(const cbae_binary_image_t *img, cbae_function_set_t *fs) {
    for (uint32_t i = 0; i < img->symbol_count; i++) {
        const cbae_symbol_t *s = &img->symbols[i];
        if (s->kind != CBAE_KIND_FUNCTION) continue;
        if (!cbae_symbol_is_resolved(s)) continue;
        cbae_func_role_t role = (s->type == CBAE_SYM_EXPORT)
                                 ? CBAE_ROLE_EXPORTED : CBAE_ROLE_LOCAL;
        CBAE_CHECK(add_function(fs, s->address, s->name, role, CBAE_FSRC_SYMBOL));
    }
    return CBAE_OK;
}

/* ── Source 4: best-effort prologue scan (lowest confidence) ───────── */
static bool looks_like_prologue(const uint8_t *p, cbae_size_t remaining) {
    if (remaining >= 4 && p[0]==0x55 &&
        p[1]==0x48 && p[2]==0x89 && p[3]==0xE5)      /* push rbp; mov rbp,rsp */
        return true;
    if (remaining >= 4 && p[0]==0x48 && p[1]==0x83 && p[2]==0xEC) /* sub rsp,imm8 */
        return true;
    if (remaining >= 7 && p[0]==0x48 && p[1]==0x81 && p[2]==0xEC) /* sub rsp,imm32*/
        return true;
    return false;
}

static cbae_err_t scan_prologues(const cbae_binary_image_t *img, cbae_function_set_t *fs) {
    for (uint32_t si = 0; si < img->section_count; si++) {
        cbae_section_t *s = &img->sections[si];
        if (!cbae_section_is_code(s) || !s->data) continue;

        for (cbae_size_t off = 0; off < s->file_size; off++) {
            cbae_addr_t addr = s->virt_addr + off;
            if (cbae_function_set_find(fs, addr)) continue;
            if (looks_like_prologue(s->data + off, s->file_size - off))
                CBAE_CHECK(add_function(fs, addr, NULL, CBAE_ROLE_LOCAL,
                                         CBAE_FSRC_PROLOGUE_SCAN));
        }
    }
    return CBAE_OK;
}

cbae_err_t cbae_find_functions(const cbae_binary_image_t *img,
                                cbae_function_set_t *out) {
    if (!img || !out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");
    CBAE_CHECK(cbae_function_set_init(out));

    /* Source 1: entry point */
    if (img->entry_point != CBAE_ADDR_INVALID && img->entry_point != 0) {
        const char *nm = (img->os_origin == CBAE_OS_WINDOWS)
                          ? "DriverEntry" : "module_init";
        CBAE_CHECK(add_function(out, img->entry_point, nm,
                                 CBAE_ROLE_ENTRY, CBAE_FSRC_ENTRY_POINT));
    }

    CBAE_CHECK(scan_symbols(img, out));
    CBAE_CHECK(scan_pdata(img, out));
    CBAE_CHECK(scan_prologues(img, out));

    LOG_INFO("function discovery: %u functions found",
             cbae_function_set_count(out));
    return CBAE_OK;
}
