/**
 * @file section.h
 * @brief Section descriptor — one record per binary section.
 */
#ifndef CBAE_SECTION_H
#define CBAE_SECTION_H

#include "cbae/cbae_types.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CBAE_SEC_EXEC   (1u << 0)
#define CBAE_SEC_READ   (1u << 1)
#define CBAE_SEC_WRITE  (1u << 2)
#define CBAE_SEC_INIT   (1u << 3)
#define CBAE_SEC_BSS    (1u << 4)
#define CBAE_SEC_INFO   (1u << 5)
#define CBAE_SEC_RELOC  (1u << 6)
#define CBAE_SEC_NAME_MAX  32

typedef struct cbae_section {
    char          name[CBAE_SEC_NAME_MAX];
    cbae_addr_t   virt_addr;
    cbae_size_t   virt_size;
    cbae_off_t    file_offset;
    cbae_size_t   file_size;
    uint32_t      flags;
    const uint8_t *data;
} cbae_section_t;

static inline bool cbae_section_contains_va(const cbae_section_t *s,
                                             cbae_addr_t va)
{ return va >= s->virt_addr && va < s->virt_addr + s->virt_size; }

static inline const uint8_t *cbae_section_va_to_ptr(const cbae_section_t *s,
                                                      cbae_addr_t va)
{
    if (!s->data || !cbae_section_contains_va(s, va)) return NULL;
    cbae_size_t off = va - s->virt_addr;
    if (off >= s->file_size) return NULL;
    return s->data + off;
}

static inline bool cbae_section_is_code(const cbae_section_t *s)
{ return (s->flags & CBAE_SEC_EXEC) != 0; }

#ifdef __cplusplus
}
#endif

#endif /* CBAE_SECTION_H */
