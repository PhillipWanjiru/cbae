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

#define CBAE_IMAGE_NOTES_MAX 16
#define CBAE_IMAGE_NOTE_LEN  160

typedef struct cbae_binary_image {
    char                  path[512];
    char                  sha256[65];
    cbae_binary_format_t  format;
    cbae_binary_arch_t    arch;
    cbae_os_t             os_origin;
    /** The sample's bytes: one heap block of exactly file_size bytes, owned by the image (see
     *  cbae_image_adopt_file); NULL for an image assembled by hand. Section data pointers point into it. */
    const uint8_t        *file_data;
    cbae_size_t           file_size;
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

    /** What the loader noticed and dealt with instead of failing: a table cut short by the end of the
     *  file, a name that did not fit its field, sections that overlap. The first CBAE_IMAGE_NOTES_MAX
     *  are kept (text in notes[]); note_count counts all of them, so note_count > CBAE_IMAGE_NOTES_MAX
     *  means some were dropped. A clean file has none. */
    uint32_t              note_count;
    char                  notes[CBAE_IMAGE_NOTES_MAX][CBAE_IMAGE_NOTE_LEN];
} cbae_binary_image_t;

/**
 * Creates an empty image whose arena holds exactly @p arena_size bytes (0: 8 MiB, for images that are
 * assembled by hand). On any failure everything made so far is released and *out is NULL.
 */
cbae_err_t      cbae_image_create       (cbae_size_t arena_size,
                                          cbae_binary_image_t **out);

/**
 * Builds the lookup tables (VA -> section, VA -> symbol, name -> symbol, IAT slot -> import). Safe to
 * call again. When several symbols have the same address or the same name, the one that is resolved,
 * then the one that is exported or global, then the first in table order, is the one that is found.
 * Section and file symbols (CBAE_SYM_SECTION, CBAE_SYM_FILE) are left out of the address and name
 * indexes: they stand for a section or a source file, not for something a lookup should name.
 * An allocation failure is returned, never skipped: a half-built index would make lookups lie.
 */
cbae_err_t      cbae_image_build_indexes(cbae_binary_image_t *img);

/** Frees the image and everything it owns, including the sample's bytes. NULL and *img == NULL are fine. */
void            cbae_image_destroy      (cbae_binary_image_t **img);

/**
 * Gives the image the sample's bytes and fills in img->sha256. @p data must be a heap block from
 * malloc of exactly @p size bytes: the image owns it from now on and frees it in cbae_image_destroy.
 * (cbae_file_read returns such a block.) Any earlier bytes are freed.
 */
void            cbae_image_adopt_file   (cbae_binary_image_t *img, uint8_t *data, size_t size);

/** Records one thing the loader noticed (printf-style; the text is cut to CBAE_IMAGE_NOTE_LEN - 1). */
void            cbae_image_note         (cbae_binary_image_t *img, const char *fmt, ...) CBAE_PRINTF_FORMAT(2, 3);

cbae_section_t *cbae_image_section_at_va   (const cbae_binary_image_t *img,
                                             cbae_addr_t va);
cbae_section_t *cbae_image_section_by_name (const cbae_binary_image_t *img,
                                             const char *name);
const uint8_t  *cbae_image_va_to_ptr       (const cbae_binary_image_t *img,
                                             cbae_addr_t va);
/** The address of the byte at file offset @p offset, or CBAE_ADDR_INVALID if no loaded section holds it. */
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
