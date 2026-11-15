/**
 * @file symbol.h
 * @brief Symbol record — one entry per named address in a binary.
 */
#ifndef CBAE_SYMBOL_H
#define CBAE_SYMBOL_H

#include "cbae/cbae_types.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_sym_type {
    CBAE_SYM_UNKNOWN = 0, CBAE_SYM_IMPORT = 1, CBAE_SYM_EXPORT = 2,
    CBAE_SYM_LOCAL = 3,   CBAE_SYM_SECTION = 4, CBAE_SYM_FILE = 5,
} cbae_sym_type_t;

typedef enum cbae_sym_binding {
    CBAE_BIND_LOCAL = 0, CBAE_BIND_GLOBAL = 1, CBAE_BIND_WEAK = 2,
} cbae_sym_binding_t;

typedef enum cbae_sym_kind {
    CBAE_KIND_UNKNOWN = 0, CBAE_KIND_FUNCTION = 1,
    CBAE_KIND_OBJECT = 2,  CBAE_KIND_NOTYPE = 3,
} cbae_sym_kind_t;

#define CBAE_SYM_NAME_MAX    128
#define CBAE_SYM_SOURCE_MAX   64

typedef struct cbae_symbol {
    char               name[CBAE_SYM_NAME_MAX];
    char               source[CBAE_SYM_SOURCE_MAX];
    cbae_addr_t        address;
    cbae_size_t        size;
    cbae_sym_type_t    type;
    cbae_sym_binding_t binding;
    cbae_sym_kind_t    kind;
    uint16_t           section_idx;
    bool               api_recognized;
    uint32_t           table_index;
} cbae_symbol_t;

static inline bool cbae_symbol_is_resolved(const cbae_symbol_t *s)
{ return s->address != CBAE_ADDR_INVALID && s->address != 0; }

static inline bool cbae_symbol_is_function(const cbae_symbol_t *s)
{ return s->kind == CBAE_KIND_FUNCTION; }

static inline bool cbae_symbol_is_kernel_import(const cbae_symbol_t *s)
{ return s->type == CBAE_SYM_IMPORT && s->kind == CBAE_KIND_FUNCTION; }

static inline const char *cbae_sym_type_str(cbae_sym_type_t t) {
    switch(t) {
        case CBAE_SYM_IMPORT:  return "import";
        case CBAE_SYM_EXPORT:  return "export";
        case CBAE_SYM_LOCAL:   return "local";
        case CBAE_SYM_SECTION: return "section";
        case CBAE_SYM_FILE:    return "file";
        default:               return "unknown";
    }
}

#ifdef __cplusplus
}
#endif

#endif /* CBAE_SYMBOL_H */
