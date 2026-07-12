/**
 * @file import_entry.h
 * @brief Import table entry — one record per external function call.
 */
#ifndef CBAE_IMPORT_ENTRY_H
#define CBAE_IMPORT_ENTRY_H

#include "cbae/cbae_types.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CBAE_IMPORT_NAME_MAX    128
#define CBAE_IMPORT_MODULE_MAX   64

typedef enum cbae_import_state {
    CBAE_IMPORT_UNRESOLVED = 0,
    CBAE_IMPORT_BY_NAME    = 1,
    CBAE_IMPORT_BY_ORDINAL = 2,
    CBAE_IMPORT_FORWARDED  = 3,
} cbae_import_state_t;

typedef struct cbae_import_entry {
    char  name[CBAE_IMPORT_NAME_MAX];
    char  module[CBAE_IMPORT_MODULE_MAX];
    cbae_addr_t         iat_va;
    uint16_t            hint;
    uint16_t            ordinal;
    cbae_off_t          rela_offset;
    uint32_t            rela_type;
    cbae_import_state_t state;
    bool                api_matched;
    uint32_t            table_index;
} cbae_import_entry_t;

static inline bool cbae_import_has_iat(const cbae_import_entry_t *e)
{ return e->iat_va != CBAE_ADDR_INVALID && e->iat_va != 0; }

static inline bool cbae_import_has_rela(const cbae_import_entry_t *e)
{ return e->rela_offset != (cbae_off_t)CBAE_ADDR_INVALID; }

static inline bool cbae_import_has_name(const cbae_import_entry_t *e)
{ return e->name[0] != '\0'; }

static inline void cbae_import_display(const cbae_import_entry_t *e,
                                        char *buf, int bufsz)
{
    if (cbae_import_has_name(e))
        snprintf(buf, (size_t)bufsz, "%s!%s", e->module, e->name);
    else
        snprintf(buf, (size_t)bufsz, "%s!ord#%u", e->module, e->ordinal);
}

#ifdef __cplusplus
}
#endif

#endif /* CBAE_IMPORT_ENTRY_H */
