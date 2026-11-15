/**
 * @file pe_loader.h
 * @brief Loader for PE32+ images (x86-64 and ARM64 Windows drivers and DLLs).
 *
 * What the image holds
 *
 *  Sections    One per section header, in table order (a file with more than 96 is refused: the Windows loader
 *              does too). Names are the 8 bytes of the header up to the first NUL. virt_addr is ImageBase +
 *              RVA, virt_size is VirtualSize (SizeOfRawData when VirtualSize is 0), file_offset is
 *              PointerToRawData. file_size is what the file really holds of the section: the smallest of
 *              SizeOfRawData, virt_size and the bytes between PointerToRawData and the end of the file. The
 *              rest of virt_size is zero-filled in memory and has no bytes here, and a raw size beyond
 *              virt_size is file padding and is ignored. data points into the image's copy of the file
 *              (NULL when file_size is 0). Flags: EXEC, READ, WRITE from IMAGE_SCN_MEM_*, INIT and BSS from
 *              IMAGE_SCN_CNT_INITIALIZED_DATA and IMAGE_SCN_CNT_UNINITIALIZED_DATA; no other bit is a flag.
 *
 *  Addresses   Preferred addresses: ImageBase + RVA, with no base relocation applied. load_base is ImageBase,
 *              entry_point is ImageBase + AddressOfEntryPoint (CBAE_ADDR_INVALID when that is 0). A file whose
 *              ImageBase is so near the top of the address space that an address could wrap is refused. Where
 *              two sections overlap in memory the first in table order owns the address, and a note says so.
 *              The headers are file bytes too: RVAs below min(SizeOfHeaders, file size) are read from the
 *              start of the file, which is where a tiny PE keeps its tables; sections win over headers.
 *
 *  Symbols     The exports, all CBAE_SYM_EXPORT, binding global: first the named ones in name-table order,
 *              then the unnamed ones as "ord#<ordinal base + slot>". An address-table slot of 0 is not an
 *              export. At most 65536 slots are read (ordinals are 16 bits). A name that is not in the file
 *              leaves the export listed by ordinal. Names are cut at 127 bytes.
 *                forwarder    (the slot's RVA is inside the export directory) address CBAE_ADDR_INVALID, kind
 *                             FUNCTION, source "fwd:" and the first 56 characters of the forwarder string
 *                             ("fwd:" alone when the string is not in the file: noted)
 *                otherwise    address ImageBase + RVA; kind FUNCTION if the section that holds the RVA is
 *                             executable, OBJECT if it is not, NOTYPE if no section holds it
 *              COFF symbols (none in an image linked without them) are not read.
 *
 *  Imports     One per entry of each import descriptor's lookup table (the address table when the descriptor
 *              has no lookup table, as in a bound or tiny image), in file order. A by-name entry has its hint
 *              and name (cut at 127 bytes; bit 31 is not part of the RVA); a by-ordinal entry (bit 63) has the
 *              16-bit ordinal and the name "ord#<ordinal>". module is the DLL name (cut at 63 bytes).
 *              iat_va is ImageBase + FirstThunk + 8 * entry index; rela_offset is CBAE_ADDR_INVALID. The
 *              descriptor list ends at the first descriptor whose name RVA or FirstThunk is 0. At most
 *              262144 imports are kept; the rest are noted.
 *
 *  Relocations Every entry of every block of the base relocation directory, the ABSOLUTE padding entries too:
 *              page_rva is the block's page, target_va is ImageBase + page + the 12-bit offset (computed in 64
 *              bits: it never wraps), type is NOP (0), ABS32 (HIGHLOW, 3), ABS64 (DIR64, 10) or UNKNOWN.
 *              file_offset is where the bytes to be patched are in the file: CBAE_ADDR_INVALID when they are in
 *              a section's zero-filled tail, in no section or header, or past the first 4 GiB of RVAs.
 *              A block that declares fewer than 8 bytes ends the table (noted); one that declares more bytes
 *              than the directory holds is cut to what is there; an odd size drops the half entry.
 *
 *  Metadata    meta.pe: image_base, image_size (SizeOfImage as declared), subsystem, dll_characteristics,
 *              checksum (as declared, not verified), is_driver (subsystem NATIVE), pdb_path (from the first
 *              CodeView debug entry, type 2, with an RSDS record and a non-empty path; cut at 255 bytes).
 *
 *  Notes       Everything the loader clamped, skipped or cut instead of refusing is recorded in img->notes
 *              (binary_image.h); a clean file has none. Notes are made for: a data directory count above 16
 *              or above what the optional header has room for; a section whose raw data runs past the end of
 *              the file (only when bytes of the section are missing, not when only padding is); overlapping
 *              sections; a machine that is neither x86-64 nor ARM64; an entry point outside an executable
 *              section; a table that is not in the file or has no terminator inside it; a count that
 *              declares more entries than the file holds; a name that was cut; an export whose name or
 *              forwarder string is not in the file; a relocation block that is cut or too small; a debug
 *              record that is not in the file; a PDB path that was cut.
 */
#ifndef CBAE_PE_LOADER_H
#define CBAE_PE_LOADER_H

#include "loader/binary_image.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Loads the PE32+ file at @p path.
 *
 * The file is untrusted: every table is read through a bounded view of the file, so a header that
 * lies about a size or an offset can cost the file its tables, never the process its memory. What
 * can be loaded is loaded; what had to be clamped, skipped or cut is recorded in img->notes.
 *
 * @return CBAE_OK and a new image in *out; otherwise *out is NULL and
 *   CBAE_ERR_INVALID     NULL argument, or @p path is not a regular file
 *   CBAE_ERR_NOT_FOUND   no such file
 *   CBAE_ERR_IO          the file could not be read
 *   CBAE_ERR_OVERFLOW    the file is over CBAE_FILE_MAX_BYTES, or the tables it declares would need
 *                        more memory than an image may use (1 GiB)
 *   CBAE_ERR_PARSE       not a PE file, or its headers are damaged beyond use (also: empty file)
 *   CBAE_ERR_UNSUPPORTED a PE32 (32-bit) image
 *   CBAE_ERR_OOM         out of memory
 */
cbae_err_t cbae_pe_load(const char *path, cbae_binary_image_t **out);

/**
 * The same for a file that is already in memory. The bytes are copied (the image owns its copy), so
 * @p data may be freed or reused afterwards. @p name is recorded as the image's path; NULL is "".
 */
cbae_err_t cbae_pe_load_buffer(const uint8_t *data, size_t size, const char *name,
                               cbae_binary_image_t **out);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_PE_LOADER_H */
