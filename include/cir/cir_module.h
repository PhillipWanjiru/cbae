/**
 * @file cir_module.h
 * @brief A collection of lifted functions from one binary_image.
 */
#ifndef CBAE_CIR_MODULE_H
#define CBAE_CIR_MODULE_H

#include "cir_function.h"
#include "cbae/cbae_error.h"
#include "platform/memory.h"
#include "platform/vector.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_cir_module {
    cbae_vector_t  functions;
    cbae_arena_t  *arena;
} cbae_cir_module_t;

cbae_err_t cbae_cir_module_init(cbae_cir_module_t *mod, cbae_arena_t *arena);
void       cbae_cir_module_destroy(cbae_cir_module_t *mod);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_CIR_MODULE_H */
