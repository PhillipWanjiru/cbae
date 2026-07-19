/**
 * @file function.h
 * @brief Function record and discovery — entry point, role tag, source.
 */
#ifndef CBAE_FUNCTION_H
#define CBAE_FUNCTION_H

#include "cbae/cbae_types.h"
#include "cbae/cbae_error.h"
#include "loader/binary_image.h"
#include "platform/vector.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum cbae_func_role {
    CBAE_ROLE_UNKNOWN = 0,
    CBAE_ROLE_ENTRY,      /* DriverEntry / module_init                  */
    CBAE_ROLE_UNLOAD,     /* DriverUnload / module_exit                 */
    CBAE_ROLE_EXPORTED,   /* exported symbol, role not yet classified   */
    CBAE_ROLE_LOCAL,      /* discovered internal function               */
} cbae_func_role_t;

typedef enum cbae_func_source {
    CBAE_FSRC_ENTRY_POINT = 0, /* img->entry_point                      */
    CBAE_FSRC_SYMBOL,          /* exported/local symbol table entry     */
    CBAE_FSRC_PDATA,           /* PE .pdata RUNTIME_FUNCTION table      */
    CBAE_FSRC_PROLOGUE_SCAN,   /* heuristic prologue byte-pattern match */
} cbae_func_source_t;

typedef struct cbae_function {
    cbae_addr_t         entry_addr;
    cbae_addr_t         end_addr;     /* CBAE_ADDR_INVALID if unknown    */
    char                name[128];    /* from symbol table, may be empty */
    cbae_func_role_t    role;
    cbae_func_source_t  source;
    bool                has_seh;      /* set by cbae_detect_seh_handlers */
} cbae_function_t;

typedef struct cbae_function_set {
    cbae_vector_t functions;   /* elem = cbae_function_t (by value)      */
} cbae_function_set_t;

cbae_err_t cbae_function_set_init   (cbae_function_set_t *fs);
void       cbae_function_set_destroy(cbae_function_set_t *fs);
uint32_t         cbae_function_set_count(const cbae_function_set_t *fs);
cbae_function_t *cbae_function_set_at   (const cbae_function_set_t *fs, uint32_t idx);
cbae_function_t *cbae_function_set_find (const cbae_function_set_t *fs, cbae_addr_t addr);

/*
 * Discover function entry points using, in priority order:
 *   1. img->entry_point           (DriverEntry / module_init)
 *   2. img->symbols[] with kind==FUNCTION and a resolved address
 *      (covers ELF .symtab entries and PE export-table entries)
 *   3. PE only: .pdata RUNTIME_FUNCTION table -- the ground-truth
 *      function boundary source on x86-64 Windows binaries (every
 *      non-leaf function has an entry here, compiler-generated;
 *      authoritative, not a heuristic)
 *   4. Best-effort prologue byte-pattern scan over remaining code
 *      ranges, matching the two most common x86-64 compiler prologues.
 *      Lowest-confidence source, used only to fill gaps.
 *
 * Deduplicates by address; a later, lower-priority source never
 * overrides an already-discovered entry.
 */
cbae_err_t cbae_find_functions(const cbae_binary_image_t *img,
                                cbae_function_set_t *out);

/*
 * Scan the PE .pdata section's UNWIND_INFO records for the
 * UNW_FLAG_EHANDLER / UNW_FLAG_UHANDLER bits, marking matching
 * functions' has_seh field. Windows/x64 only; no-op on ELF.
 * Returns the number of functions flagged.
 */
uint32_t cbae_detect_seh_handlers(const cbae_binary_image_t *img,
                                   cbae_function_set_t *fs);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_FUNCTION_H */
