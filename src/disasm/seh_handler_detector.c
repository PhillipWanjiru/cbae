/**
 * @file seh_handler_detector.c
 * @brief Windows x64 SEH detection via .pdata UNWIND_INFO flags.
 *
 * Every PE .pdata RUNTIME_FUNCTION entry points at an UNWIND_INFO
 * record. The first byte of that record packs a 3-bit version and a
 * 5-bit flags field (per the Microsoft x64 exception handling ABI):
 *
 *     UBYTE Version : 3
 *     UBYTE Flags   : 5
 *         UNW_FLAG_EHANDLER  0x01  -- function has a language-specific
 *                                     exception handler (__try/__except,
 *                                     __try/__finally)
 *         UNW_FLAG_UHANDLER  0x02  -- function has a termination handler
 *         UNW_FLAG_CHAININFO 0x04  -- this record chains to another
 *
 * Detecting SEH usage only requires reading this one byte per function
 * -- full UNWIND_CODE array decoding (which reconstructs the exact
 * prologue instruction-by-instruction unwind steps) is unnecessary for
 * a boolean has_seh flag and is out of Phase 3's scope.
 */
#include "disasm/function.h"
#include "platform/logging.h"

#pragma pack(push, 1)
typedef struct { uint32_t begin_rva, end_rva, unwind_rva; } rt_func_entry_t;
typedef struct { uint8_t version_flags, size_of_prolog, count_of_codes, frame_info; } unwind_hdr_t;
#pragma pack(pop)

#define UNW_FLAG_EHANDLER 0x01
#define UNW_FLAG_UHANDLER 0x02

uint32_t cbae_detect_seh_handlers(const cbae_binary_image_t *img,
                                   cbae_function_set_t *fs) {
    if (img->format != CBAE_FMT_PE32PLUS) return 0;
    cbae_section_t *pdata = cbae_image_section_by_name(img, ".pdata");
    if (!pdata || !pdata->data) return 0;

    uint32_t n = (uint32_t)(pdata->file_size / sizeof(rt_func_entry_t));
    const rt_func_entry_t *entries = (const rt_func_entry_t *)pdata->data;
    uint32_t flagged = 0;

    for (uint32_t i = 0; i < n; i++) {
        if (!entries[i].begin_rva || !entries[i].unwind_rva) continue;

        const uint8_t *uw =
            cbae_image_va_to_ptr(img, img->load_base + entries[i].unwind_rva);
        if (!uw) continue;

        const unwind_hdr_t *uh = (const unwind_hdr_t *)uw;
        uint8_t flags = (uint8_t)(uh->version_flags >> 3);

        if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
            cbae_addr_t entry_va = img->load_base + entries[i].begin_rva;
            cbae_function_t *f = cbae_function_set_find(fs, entry_va);
            if (f) { f->has_seh = true; flagged++; }
        }
    }
    LOG_DEBUG("seh detection: %u functions with exception handlers", flagged);
    return flagged;
}
