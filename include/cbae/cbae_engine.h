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

/**
 * Starts the engine: loads the configuration, opens the database and migrates its schema.
 * @p config_path NULL means the built-in defaults; a path that does not exist is CBAE_ERR_NOT_FOUND and
 * one that does not parse is CBAE_ERR_PARSE (the message names the file and line). *out_engine is NULL
 * on failure.
 */
cbae_err_t           cbae_engine_init(const char *config_path,
                                       cbae_engine_t **out_engine);
void                 cbae_engine_shutdown(cbae_engine_t *engine);
const cbae_config_t *cbae_engine_config(const cbae_engine_t *engine);
void                 cbae_config_defaults(cbae_config_t *cfg);
/**
 * Reads @p path into @p cfg. Strict: see src/engine/cbae_config.c for the format. On every error *cfg
 * holds the defaults (never a half-applied file): CBAE_ERR_NOT_FOUND for a missing file, CBAE_ERR_IO
 * when it cannot be read, CBAE_ERR_PARSE for a bad line (the message is "file:line: reason"),
 * CBAE_ERR_INVALID for a NULL argument.
 */
cbae_err_t           cbae_config_load(const char *path, cbae_config_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* CBAE_ENGINE_H */
