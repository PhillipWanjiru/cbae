/**
 * @file elf_loader.h
 * @brief Public API for the ELF64 binary loader.
 */
#ifndef CBAE_ELF_LOADER_H
#define CBAE_ELF_LOADER_H

#include "loader/binary_image.h"

#ifdef __cplusplus
extern "C" {
#endif

cbae_err_t cbae_elf_load(const char *path, cbae_binary_image_t **out);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_ELF_LOADER_H */
