/**
 * @file pe_loader.h
 * @brief Public API for the PE32+ binary loader.
 */
#ifndef CBAE_PE_LOADER_H
#define CBAE_PE_LOADER_H

#include "loader/binary_image.h"

#ifdef __cplusplus
extern "C" {
#endif

cbae_err_t cbae_pe_load(const char *path, cbae_binary_image_t **out);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_PE_LOADER_H */
