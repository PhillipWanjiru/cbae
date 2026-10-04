/**
 * @file graph_scc.c
 * @brief Iterative Tarjan strongly-connected-components. See graph_scc.h.
 *
 * Tarjan's algorithm: a DFS numbers each node on entry (index) and tracks
 * the smallest index reachable through the DFS subtree plus at most one
 * edge back into a node still on the component stack (low). A node whose
 * low equals its own index is the root of a component; popping the
 * component stack down to it yields exactly that component.
 *
 * The DFS is driven by an explicit frame stack instead of recursion. Each
 * frame remembers which outgoing edge to look at next.
 */
#include "graph_scc.h"
#include "platform/logging.h"
#include <stdlib.h>

#define UNVISITED UINT32_MAX

typedef struct { uint32_t node; uint32_t next_edge; } frame_t;

cbae_err_t graph_scc_compute(uint32_t n, const uint32_t *succ_off,
                             const uint32_t *succ_adj, const bool *active,
                             uint32_t *comp, uint32_t *ncomp_out) {
    if (!succ_off || !succ_adj || !comp || !ncomp_out)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "scc: null argument");
    *ncomp_out = 0;
    if (n == 0) return CBAE_OK;

    uint32_t *index     = malloc(sizeof(uint32_t) * n);
    uint32_t *low       = malloc(sizeof(uint32_t) * n);
    uint32_t *scc_stack = malloc(sizeof(uint32_t) * n);
    frame_t  *frames    = malloc(sizeof(frame_t) * n);
    bool     *on_stack  = calloc(n, sizeof(bool));
    if (!index || !low || !scc_stack || !frames || !on_stack) {
        free(index); free(low); free(scc_stack); free(frames); free(on_stack);
        CBAE_RETURN_ERR(CBAE_ERR_OOM, "scc: scratch alloc failed");
    }
    for (uint32_t i = 0; i < n; i++) {
        index[i] = UNVISITED;
        comp[i]  = GRAPH_SCC_NONE;
    }

    uint32_t counter = 0, ncomp = 0, ssp = 0;

    for (uint32_t r = 0; r < n; r++) {
        if ((active && !active[r]) || index[r] != UNVISITED) continue;

        uint32_t sp = 0;
        frames[sp].node = r;
        frames[sp].next_edge = succ_off[r];
        sp++;
        index[r] = low[r] = counter++;
        scc_stack[ssp++] = r;
        on_stack[r] = true;

        while (sp > 0) {
            frame_t *top = &frames[sp - 1];
            const uint32_t v = top->node;

            if (top->next_edge < succ_off[v + 1]) {
                const uint32_t w = succ_adj[top->next_edge++];
                if (active && !active[w]) continue;      /* edge leaves the subgraph */
                if (index[w] == UNVISITED) {
                    index[w] = low[w] = counter++;
                    scc_stack[ssp++] = w;
                    on_stack[w] = true;
                    frames[sp].node = w;
                    frames[sp].next_edge = succ_off[w];
                    sp++;
                } else if (on_stack[w] && index[w] < low[v]) {
                    low[v] = index[w];
                }
            } else {
                if (low[v] == index[v]) {                /* v roots a component */
                    const uint32_t cid = ncomp++;
                    uint32_t w;
                    do {
                        w = scc_stack[--ssp];
                        on_stack[w] = false;
                        comp[w] = cid;
                    } while (w != v);
                }
                sp--;
                if (sp > 0) {
                    const uint32_t parent = frames[sp - 1].node;
                    if (low[v] < low[parent]) low[parent] = low[v];
                }
            }
        }
    }

    free(index); free(low); free(scc_stack); free(frames); free(on_stack);
    *ncomp_out = ncomp;
    return CBAE_OK;
}

cbae_err_t graph_scc_on_cycle(uint32_t n, const uint32_t *succ_off,
                              const uint32_t *succ_adj, bool *on_cycle) {
    if (!succ_off || !succ_adj || !on_cycle)
        CBAE_RETURN_ERR(CBAE_ERR_INVALID, "scc: null argument");
    if (n == 0) return CBAE_OK;

    uint32_t *comp = malloc(sizeof(uint32_t) * n);
    if (!comp) CBAE_RETURN_ERR(CBAE_ERR_OOM, "scc: scratch alloc failed");
    uint32_t ncomp = 0;
    cbae_err_t rc = graph_scc_compute(n, succ_off, succ_adj, NULL, comp, &ncomp);
    if (rc != CBAE_OK) { free(comp); return rc; }

    uint32_t *size = calloc(ncomp ? ncomp : 1, sizeof(uint32_t));
    if (!size) { free(comp); CBAE_RETURN_ERR(CBAE_ERR_OOM, "scc: scratch alloc failed"); }
    for (uint32_t x = 0; x < n; x++) size[comp[x]]++;

    for (uint32_t x = 0; x < n; x++) {
        bool cyc = size[comp[x]] > 1;
        for (uint32_t e = succ_off[x]; !cyc && e < succ_off[x + 1]; e++)
            if (succ_adj[e] == x) cyc = true;            /* self-loop */
        on_cycle[x] = cyc;
    }
    free(size);
    free(comp);
    return CBAE_OK;
}
