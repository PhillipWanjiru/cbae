/**
 * @file cfg_edge_classifier.h
 * @brief PRIVATE — classifies a CFG edge as fallthrough/branch/back-edge.
 */
#ifndef CBAE_SRC_CFG_EDGE_CLASSIFIER_H
#define CBAE_SRC_CFG_EDGE_CLASSIFIER_H

#include "disasm/basic_block.h"

/* Classify the edge from `from_addr` (the branching instruction's own
 * address) to `target_addr`. Back-edge detection is a simple address
 * comparison (target <= source): correct for the vast majority of
 * compiler-generated loops without needing full dominator-tree analysis,
 * which arrives in Phase 5. */
cbae_edge_kind_t cbae_classify_edge(cbae_addr_t from_addr, cbae_addr_t target_addr,
                                     bool is_fallthrough);

#endif /* CBAE_SRC_CFG_EDGE_CLASSIFIER_H */
