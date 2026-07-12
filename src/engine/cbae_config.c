/**
 * @file cbae_config.c
 * @brief Parse cbae.conf key=value file into cbae_config_t.
 */
#include "cbae/cbae_engine.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>

void cbae_config_defaults(cbae_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->db_path, "/var/lib/cbae/analysis.db", sizeof(cfg->db_path)-1);
    cfg->worker_count         = 4;
    cfg->capture_vm_count     = 2;
    cfg->arena_size_mb        = 256;
    cfg->log_level            = 2;
    cfg->log_json             = false;
    cfg->api_confidence_min   = 0.75f;
    cfg->dna_similarity_thresh = 0.90f;
}

static void trim(char *s) {
    char *end;
    while(isspace((unsigned char)*s)) s++;
    end = s + strlen(s) - 1;
    while(end > s && isspace((unsigned char)*end)) *end-- = '\0';
}

cbae_err_t cbae_config_load(const char *path, cbae_config_t *cfg) {
    if(!path || !cfg) CBAE_RETURN_ERR(CBAE_ERR_INVALID, "null argument");
    cbae_config_defaults(cfg);
    FILE *f = fopen(path, "r");
    if(!f) return CBAE_OK; /* missing config = use defaults */
    char line[512];
    while(fgets(line, sizeof(line), f)) {
        char *hash = strchr(line, '#');
        if(hash) *hash = '\0';
        trim(line);
        if(!*line) continue;
        char *eq = strchr(line, '=');
        if(!eq) continue;
        *eq = '\0';
        char *key = line, *val = eq+1;
        trim(key); trim(val);
        if     (!strcmp(key,"db_path"))             strncpy(cfg->db_path,val,sizeof(cfg->db_path)-1);
        else if(!strcmp(key,"log_path"))             strncpy(cfg->log_path,val,sizeof(cfg->log_path)-1);
        else if(!strcmp(key,"api_db_path"))          strncpy(cfg->api_db_path,val,sizeof(cfg->api_db_path)-1);
        else if(!strcmp(key,"worker_count"))         cfg->worker_count=atoi(val);
        else if(!strcmp(key,"capture_vm_count"))     cfg->capture_vm_count=atoi(val);
        else if(!strcmp(key,"arena_size_mb"))        cfg->arena_size_mb=(size_t)atol(val);
        else if(!strcmp(key,"log_level"))            cfg->log_level=atoi(val);
        else if(!strcmp(key,"log_json"))             cfg->log_json=(bool)atoi(val);
        else if(!strcmp(key,"api_confidence_min"))   cfg->api_confidence_min=(float)atof(val);
        else if(!strcmp(key,"dna_similarity_thresh"))cfg->dna_similarity_thresh=(float)atof(val);
    }
    fclose(f);
    return CBAE_OK;
}
