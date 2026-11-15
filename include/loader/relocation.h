/**
 * @file relocation.h
 * @brief Relocation record — one entry per address patch site.
 */
#ifndef CBAE_RELOCATION_H
#define CBAE_RELOCATION_H

#include "cbae/cbae_types.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_reloc_type {
    CBAE_RELOC_UNKNOWN   = 0,
    CBAE_RELOC_ABS64     = 1,
    CBAE_RELOC_ABS32     = 2,
    CBAE_RELOC_NOP       = 3,
    CBAE_RELOC_PC32      = 4,
    CBAE_RELOC_PLT32     = 5,
    CBAE_RELOC_64        = 6,
    CBAE_RELOC_32S       = 7,
    CBAE_RELOC_GOTPCREL  = 8,
} cbae_reloc_type_t;

/** The sym_index of a relocation that names no symbol: a PE base relocation, an ELF relocation against symbol 0. */
#define CBAE_RELOC_NO_SYMBOL UINT32_MAX

typedef struct cbae_relocation {
    cbae_addr_t       target_va;
    cbae_off_t        file_offset;
    cbae_reloc_type_t type;
    int64_t           addend;
    uint32_t          sym_index;        /* the symbol it names: an index into img->symbols[], or CBAE_RELOC_NO_SYMBOL */
    uint32_t          page_rva;
    bool              references_import;
    bool              applied;
    uint32_t          table_index;
} cbae_relocation_t;

static inline bool cbae_reloc_is_absolute(const cbae_relocation_t *r) {
    return r->type==CBAE_RELOC_ABS64||r->type==CBAE_RELOC_64||
           r->type==CBAE_RELOC_ABS32||r->type==CBAE_RELOC_32S;
}

static inline bool cbae_reloc_is_pc_relative(const cbae_relocation_t *r) {
    return r->type==CBAE_RELOC_PC32||r->type==CBAE_RELOC_PLT32||
           r->type==CBAE_RELOC_GOTPCREL;
}

static inline const char *cbae_reloc_type_str(cbae_reloc_type_t t) {
    switch(t) {
        case CBAE_RELOC_ABS64:    return "ABS64";
        case CBAE_RELOC_ABS32:    return "ABS32";
        case CBAE_RELOC_NOP:      return "NOP";
        case CBAE_RELOC_PC32:     return "PC32";
        case CBAE_RELOC_PLT32:    return "PLT32";
        case CBAE_RELOC_64:       return "64";
        case CBAE_RELOC_32S:      return "32S";
        case CBAE_RELOC_GOTPCREL: return "GOTPCREL";
        default:                  return "UNKNOWN";
    }
}

#ifdef __cplusplus
}
#endif

#endif /* CBAE_RELOCATION_H */
