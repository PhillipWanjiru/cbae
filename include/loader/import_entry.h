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

/** A buffer of this size holds any display string whole: "module!name" (63 + 1 + 127 characters) or "module!ord#65535". */
#define CBAE_IMPORT_DISPLAY_MAX (CBAE_IMPORT_MODULE_MAX + CBAE_IMPORT_NAME_MAX + 8)

/**
 * Writes "module!name", or "module!ord#N" for an import that has no name, into @p buf (@p bufsz bytes), cut to fit and
 * always NUL-terminated when bufsz > 0. Returns true if the whole string fitted, false if it was cut or buf is unusable.
 */
static inline bool cbae_import_display(const cbae_import_entry_t *e, char *buf, int bufsz)
{
    if (!e || !buf || bufsz <= 0) return false;
    char full[CBAE_IMPORT_DISPLAY_MAX];
    const int n = cbae_import_has_name(e) ? snprintf(full, sizeof full, "%s!%s", e->module, e->name)
                                          : snprintf(full, sizeof full, "%s!ord#%u", e->module, (unsigned)e->ordinal);
    const size_t len = n < 0 ? 0 : (size_t)n < sizeof full ? (size_t)n : sizeof full - 1;
    const size_t room = (size_t)bufsz - 1;
    const size_t take = len < room ? len : room;
    for (size_t i = 0; i < take; i++) buf[i] = full[i];
    buf[take] = '\0';
    return take == len;
}

#ifdef __cplusplus
}
#endif

#endif /* CBAE_IMPORT_ENTRY_H */
