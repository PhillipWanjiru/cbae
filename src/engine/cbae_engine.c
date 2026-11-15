/**
 * @file cbae_engine.c
 * @brief Engine init: load config, open DB, initialise subsystems, teardown.
 */
#include "cbae/cbae_engine.h"
#include "db/db_connection.h"
#include "db/db_schema.h"
#include "platform/logging.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

struct cbae_engine {
    cbae_config_t config;
    cbae_db_t     db;
    bool          db_open;
};

cbae_err_t cbae_engine_init(const char *config_path, cbae_engine_t **out) {
    if(!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "out_engine is NULL");
    *out = NULL;
    cbae_engine_t *e = calloc(1, sizeof(*e));
    if(!e) CBAE_RETURN_ERR(CBAE_ERR_OOM, "failed to allocate engine");

    /* No path: the defaults. A path that cannot be loaded is an error (a misspelt --config must not
     * silently run an analysis with settings nobody chose). */
    cbae_err_t err = CBAE_OK;
    if(config_path) err = cbae_config_load(config_path, &e->config);
    else            cbae_config_defaults(&e->config);
    if(err != CBAE_OK) { free(e); return err; }

    cbae_log_init((cbae_log_level_t)e->config.log_level,
                  e->config.log_path[0] ? e->config.log_path : NULL,
                  e->config.log_json);
    LOG_INFO("CBAE engine starting — db: %s", e->config.db_path);

    err = cbae_db_open(&e->db, e->config.db_path);
    if(err != CBAE_OK) {
        LOG_ERROR("Failed to open database: %s", cbae_last_error());
        cbae_log_shutdown();
        free(e);
        return err;
    }
    e->db_open = true;

    err = cbae_schema_migrate(&e->db);
    if(err != CBAE_OK) {
        LOG_ERROR("Schema migration failed: %s", cbae_last_error());
        cbae_db_close(&e->db);
        cbae_log_shutdown();
        free(e);
        return err;
    }

    LOG_INFO("CBAE engine ready (schema v%d)", cbae_schema_version(&e->db));
    *out = e;
    return CBAE_OK;
}

void cbae_engine_shutdown(cbae_engine_t *e) {
    if(!e) return;
    LOG_INFO("CBAE engine shutting down");
    if(e->db_open) cbae_db_close(&e->db);
    cbae_log_shutdown();
    free(e);
}

const cbae_config_t *cbae_engine_config(const cbae_engine_t *e) {
    return e ? &e->config : NULL;
}
