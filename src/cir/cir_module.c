/**
 * @file cir_module.c
 * @brief Module-level lifecycle: a collection of lifted functions.
 */
#include "cir/cir_module.h"
#include "cir/cir_builder.h"
#include <string.h>

cbae_err_t cbae_cir_module_init(cbae_cir_module_t *mod, cbae_arena_t *arena) {
    if (!mod || !arena) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");
    memset(mod, 0, sizeof(*mod));
    mod->arena = arena;
    return cbae_vector_init(&mod->functions, sizeof(cbae_cir_function_t *), 4);
}

void cbae_cir_module_destroy(cbae_cir_module_t *mod) {
    if (!mod) return;
    uint32_t n = (uint32_t)cbae_vector_count(&mod->functions);
    for (uint32_t i = 0; i < n; i++) {
        cbae_cir_function_t **fp = cbae_vector_at(&mod->functions, i);
        cbae_cir_function_destroy(*fp);
    }
    cbae_vector_destroy(&mod->functions);
}
