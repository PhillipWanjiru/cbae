/**
 * @file binary_image.h
 * @brief Unified in-memory binary image — the central data structure of Phase 2.
 */
#ifndef CBAE_BINARY_IMAGE_H
#define CBAE_BINARY_IMAGE_H

#include "cbae/cbae_types.h"
#include "cbae/cbae_error.h"
#include "loader/section.h"
#include "loader/symbol.h"
#include "loader/import_entry.h"
#include "loader/relocation.h"
#include "platform/memory.h"
#include "platform/hashmap.h"
#include "platform/string_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_binary_format {
    CBAE_FMT_UNKNOWN  = 0,
    CBAE_FMT_PE32PLUS = 1,
    CBAE_FMT_ELF64    = 2,
} cbae_binary_format_t;

typedef enum cbae_binary_arch {
    CBAE_ARCH_UNKNOWN = 0,
    CBAE_ARCH_X86_64  = 1,
    CBAE_ARCH_ARM64   = 2,
} cbae_binary_arch_t;

typedef struct cbae_pe_meta {
    uint64_t image_base;
    uint32_t image_size;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t checksum;
    char     pdb_path[256];
    bool     is_driver;
} cbae_pe_meta_t;

typedef struct cbae_elf_meta {
    char     kernel_version[64];
    char     module_license[32];
    char     module_author[128];
    char     module_description[256];
    bool     has_ksymtab;
    uint32_t abi_crc;
} cbae_elf_meta_t;

typedef struct cbae_binary_image {
    char                  path[512];
    char                  sha256[65];
    cbae_binary_format_t  format;
    cbae_binary_arch_t    arch;
    cbae_os_t             os_origin;
    const uint8_t        *file_data;
    cbae_size_t           file_size;
    int                   mmap_fd;
    cbae_addr_t           load_base;
    cbae_addr_t           entry_point;
    cbae_section_t       *sections;
    uint32_t              section_count;
    cbae_symbol_t        *symbols;
    uint32_t              symbol_count;
    cbae_import_entry_t  *imports;
    uint32_t              import_count;
    cbae_relocation_t    *relocations;
    uint32_t              reloc_count;
    cbae_hashmap_t        va_to_section;
    cbae_hashmap_t        va_to_symbol;
    cbae_hashmap_t        iat_to_import;
    cbae_hashmap_t        name_to_symbol;
    cbae_string_pool_t   *strings;
    cbae_arena_t          arena;
    union {
        cbae_pe_meta_t  pe;
        cbae_elf_meta_t elf;
    } meta;
    int64_t db_id;
} cbae_binary_image_t;

cbae_err_t      cbae_image_create       (cbae_size_t arena_size,
                                          cbae_binary_image_t **out);
cbae_err_t      cbae_image_build_indexes(cbae_binary_image_t *img);
void            cbae_image_destroy      (cbae_binary_image_t **img);

cbae_section_t *cbae_image_section_at_va   (const cbae_binary_image_t *img,
                                             cbae_addr_t va);
cbae_section_t *cbae_image_section_by_name (const cbae_binary_image_t *img,
                                             const char *name);
const uint8_t  *cbae_image_va_to_ptr       (const cbae_binary_image_t *img,
                                             cbae_addr_t va);
cbae_addr_t     cbae_image_offset_to_va    (const cbae_binary_image_t *img,
                                             cbae_off_t offset);

cbae_symbol_t       *cbae_image_symbol_at_va  (const cbae_binary_image_t *img,
                                                cbae_addr_t va);
cbae_symbol_t       *cbae_image_symbol_by_name(const cbae_binary_image_t *img,
                                                const char *name);

cbae_import_entry_t *cbae_image_import_at_iat  (const cbae_binary_image_t *img,
                                                  cbae_addr_t iat_va);
cbae_import_entry_t *cbae_image_import_by_name (const cbae_binary_image_t *img,
                                                  const char *name);

void cbae_image_log_summary(const cbae_binary_image_t *img);

static inline const char *cbae_fmt_str(cbae_binary_format_t f) {
    switch(f) {
        case CBAE_FMT_PE32PLUS: return "PE32+";
        case CBAE_FMT_ELF64:    return "ELF64";
        default:                return "UNKNOWN";
    }
}

static inline const char *cbae_arch_str(cbae_binary_arch_t a) {
    switch(a) {
        case CBAE_ARCH_X86_64: return "x86_64";
        case CBAE_ARCH_ARM64:  return "arm64";
        default:               return "unknown";
    }
}

#ifdef __cplusplus
}
#endif

#endif /* CBAE_BINARY_IMAGE_H */
