/**
 * @file cfg_edge_classifier.c
 * @brief Fallthrough / branch / back edge classification.
 */
#include "cfg_edge_classifier.h"

cbae_edge_kind_t cbae_classify_edge(cbae_addr_t from_addr, cbae_addr_t target_addr,
                                     bool is_fallthrough) {
    if (is_fallthrough) return CBAE_EDGE_FALLTHROUGH;
    if (target_addr <= from_addr) return CBAE_EDGE_BACK;
    return CBAE_EDGE_BRANCH_TAKEN;
}
