/**
 * @file elf_loader.h
 * @brief Public API for the ELF64 loader (little-endian; relocatable objects such as Linux kernel
 *        modules first, linked executables and shared objects too).
 *
 * What the image holds
 *
 *  Sections    One per section header that is not SHT_NULL, in table order, so an image section is not
 *              necessarily the ELF section of the same index (symbol.section_idx is the ELF index).
 *              Names are cut at CBAE_SEC_NAME_MAX - 1 = 31 bytes. A section with SHF_ALLOC has an
 *              address range; any other (.symtab, .comment, .debug_*) has virt_addr 0 and virt_size 0
 *              and is not found by an address lookup, but its bytes are there (data, file_size) and it
 *              is found by name. file_size is what the file really holds: less than the header says
 *              when the file is cut short; 0 for SHT_NOBITS.
 *
 *  Addresses   In a relocatable object (ET_REL) every section is at address 0 and nothing has an address
 *              until it is linked, so the loader lays the SHF_ALLOC sections out itself, in table order:
 *              the first at CBAE_ELF_REL_BASE (0x400000), each starting at the first multiple of
 *              max(page size, sh_addralign) after the end of the one before. The gap between two
 *              sections is in no section, so code running off the end of one does not flow into the
 *              next. Three limits keep the layout finite, and each is noted: an alignment that is not a
 *              power of two counts as 1 (so the section is placed on a page boundary), an alignment
 *              above 1 MiB is cut to 1 MiB, and a section's address range is cut at 1 TiB. A layout
 *              that would end above 2^62 is refused (CBAE_ERR_OVERFLOW).
 *              In a linked file (ET_EXEC, ET_DYN) sh_addr is used as it is; a range that would run past
 *              the top of the address space is cut, and noted. load_base is 0 either way: an ELF image
 *              has no image base in the PE sense. entry_point is e_entry for a linked file with one, and
 *              CBAE_ADDR_INVALID otherwise (an object file has no entry point).
 *
 *  Symbols     Read from the first SHT_SYMTAB (".symtab") only; a second one is ignored and noted.
 *              SHT_DYNSYM (".dynsym") is not read, so a stripped shared object has no symbols, and the
 *              relocations that name symbols through .dynsym name none (noted).
 *              img->symbols[k] is ELF symbol k + 1 (symbol 0 is the reserved null entry), section and
 *              file symbols included (type CBAE_SYM_SECTION / CBAE_SYM_FILE; they are not entered in the
 *              by-address and by-name indexes, and a section symbol is named after its section, cut at
 *              127 bytes). A relocation's sym_index therefore indexes img->symbols directly. After them
 *              come pseudo-exports: a name in __ksymtab_strings that no defined global or weak symbol
 *              carries, in order, with address CBAE_ADDR_INVALID.
 *                undefined                     CBAE_SYM_IMPORT   (source "kernel", no address)
 *                defined, global or weak       CBAE_SYM_EXPORT
 *                defined, local                CBAE_SYM_LOCAL
 *              The address of a defined symbol is its section's address plus st_value in ET_REL (if
 *              st_value does not lie beyond the end of the section), st_value itself in a linked file,
 *              st_value for SHN_ABS; common, TLS and undefined symbols, and symbols in sections that
 *              are not loaded, have none (CBAE_ADDR_INVALID). A symbol whose section index is
 *              SHN_XINDEX takes its section number from the SHT_SYMTAB_SHNDX table that belongs to the
 *              symbol table; the values in that table are plain section numbers (a number such as
 *              0xFFF1 there is not SHN_ABS). section_idx is 16 bits wide: a section number of 0xFF00
 *              or more, which a 16-bit field cannot tell from the reserved values, is stored as 0xFFFF.
 *
 *  Relocations Only SHT_RELA sections are read (SHT_REL, with implicit addends, is not the x86-64 form and
 *              is noted). In an ET_REL file the entries whose target section is loaded (SHF_ALLOC) are
 *              kept, those of .debug_* and the like are dropped, as the kernel's module loader drops them,
 *              and noted; target_va is then the address of the bytes to be patched in the loader's layout
 *              and file_offset where those bytes are in the file (CBAE_ADDR_INVALID for SHT_NOBITS). In a
 *              linked file every entry is kept, r_offset is the address, and file_offset is
 *              CBAE_ADDR_INVALID. Types are those of the x86-64 ABI.
 *
 *  Imports     One per undefined symbol (not a section or file symbol) that a kept relocation names, in
 *              order of first mention, module "kernel". rela_offset and rela_type are the file offset of
 *              the patch site and the ELF relocation type of that first relocation.
 *
 *  Module      meta.elf.kernel_version, module_license, module_author and module_description come from
 *              .modinfo (vermagic, license, author, description: the first of each wins, a value longer
 *              than its field is cut and noted); meta.elf.has_ksymtab says there is a __ksymtab_strings
 *              section. Of several sections with either name the first is used.
 *
 *  Notes       Everything the loader clamped, skipped or cut instead of refusing is recorded in
 *              img->notes (binary_image.h); a clean file has none.
 *
 * Errors      CBAE_ERR_INVALID (NULL argument, or the path is not a regular file), CBAE_ERR_NOT_FOUND,
 *             CBAE_ERR_IO (cannot read), CBAE_ERR_PARSE (not an ELF64 little-endian file, or its headers
 *             do not hold together), CBAE_ERR_OVERFLOW (the file is over CBAE_FILE_MAX_BYTES, or the
 *             tables it describes would need more than an image may use, 1 GiB, or the layout does not
 *             fit), CBAE_ERR_OOM. On any error *out is NULL.
 */
#ifndef CBAE_ELF_LOADER_H
#define CBAE_ELF_LOADER_H

#include "loader/binary_image.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Where the first loaded section of a relocatable object is placed. */
#define CBAE_ELF_REL_BASE UINT64_C(0x400000)

/** Loads the ELF file at @p path. */
cbae_err_t cbae_elf_load(const char *path, cbae_binary_image_t **out);

/**
 * Loads ELF bytes already in memory. The loader copies them (the image owns the copy); @p name is only
 * recorded as the image's path.
 */
cbae_err_t cbae_elf_load_buffer(const uint8_t *data, size_t size, const char *name, cbae_binary_image_t **out);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_ELF_LOADER_H */
