/**
 * @file cbae_engine.h
 * @brief Top-level engine lifecycle and configuration.
 */
#ifndef CBAE_ENGINE_H
#define CBAE_ENGINE_H

#include "cbae_error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cbae_config {
    char   db_path[512];
    char   log_path[512];
    char   api_db_path[512];
    int    worker_count;
    int    capture_vm_count;
    size_t arena_size_mb;
    int    log_level;
    bool   log_json;
    float  api_confidence_min;
    float  dna_similarity_thresh;
} cbae_config_t;

typedef struct cbae_engine cbae_engine_t;

cbae_err_t           cbae_engine_init(const char *config_path,
                                       cbae_engine_t **out_engine);
void                 cbae_engine_shutdown(cbae_engine_t *engine);
const cbae_config_t *cbae_engine_config(const cbae_engine_t *engine);
void                 cbae_config_defaults(cbae_config_t *cfg);
cbae_err_t           cbae_config_load(const char *path, cbae_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_ENGINE_H */
