/**
 * @file dom_reference.h  (test support, header-only)
 * @brief Independent brute-force dominator reference and a random-CFG
 *        generator, used to cross-check the production dominator and
 *        post-dominator trees.
 *
 * The reference deliberately shares NO code or algorithm with the
 * production implementation: it is the textbook set-based dataflow
 * definition,
 *       Dom(root) = { root }
 *       Dom(b)    = { b } U ( intersection of Dom(p) over predecessors p )
 * iterated to a fixed point on 64-bit masks. An immediate dominator is
 * then read off as the strict dominator with the LARGEST dominator set
 * (strict dominators form a chain under dominance, and the immediate one
 * is the closest, so it is dominated by all the others).
 *
 * Post-dominance is checked by running the same reference on an
 * explicitly constructed reversed graph with a virtual exit node, built
 * here in the test -- not by calling anything from the production code.
 */
#ifndef CBAE_TEST_DOM_REFERENCE_H
#define CBAE_TEST_DOM_REFERENCE_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* ── Deterministic RNG (xorshift64*), so any failure is reproducible ──── */

typedef struct { uint64_t s; } rng_t;

static inline uint32_t rng_next(rng_t *r) {
    r->s ^= r->s >> 12;
    r->s ^= r->s << 25;
    r->s ^= r->s >> 27;
    return (uint32_t)((r->s * 0x2545F4914F6CDD1Dull) >> 32);
}

/* ── A small CFG as an edge list ──────────────────────────────────────── */

#define RG_MAX_NODES 16
#define RG_MAX_EDGES 48

typedef struct {
    uint32_t n;
    uint32_t m;
    uint32_t e[RG_MAX_EDGES][2];
    uint32_t outdeg[RG_MAX_NODES];
} rgraph_t;

static inline bool rg_has_edge(const rgraph_t *g, uint32_t u, uint32_t v) {
    for (uint32_t i = 0; i < g->m; i++)
        if (g->e[i][0] == u && g->e[i][1] == v) return true;
    return false;
}

static inline void rg_add_edge(rgraph_t *g, uint32_t u, uint32_t v) {
    g->e[g->m][0] = u;
    g->e[g->m][1] = v;
    g->m++;
    g->outdeg[u]++;
}

static inline void rg_dump(const rgraph_t *g) {
    fprintf(stderr, "  graph: n=%u edges:", g->n);
    for (uint32_t i = 0; i < g->m; i++)
        fprintf(stderr, " %u->%u", g->e[i][0], g->e[i][1]);
    fprintf(stderr, "\n");
}

/* A random CFG with the structural properties CIR guarantees: block 0 is
 * the entry, EVERY block is reachable from it, and no block has more than
 * CIR_BLOCK_MAX_SUCCESSORS (2) successors. Extra edges give back edges,
 * cross edges, self-loops and irreducible regions. */
static inline void rg_generate(rgraph_t *g, rng_t *r, uint32_t n) {
    memset(g, 0, sizeof(*g));
    g->n = n;

    /* Spanning skeleton: every block i>=1 gets one incoming edge from a
     * lower-numbered block that still has a free successor slot. Among
     * blocks 0..i-1 there are 2i slots and only i-1 are used, so a free
     * one always exists. */
    for (uint32_t i = 1; i < n; i++) {
        uint32_t cand[RG_MAX_NODES], nc = 0;
        for (uint32_t j = 0; j < i; j++)
            if (g->outdeg[j] < 2) cand[nc++] = j;
        rg_add_edge(g, cand[rng_next(r) % nc], i);
    }

    uint32_t extras = rng_next(r) % (n + 2);
    for (uint32_t k = 0; k < extras; k++) {
        uint32_t u = rng_next(r) % n, v = rng_next(r) % n;
        if (g->outdeg[u] < 2 && !rg_has_edge(g, u, v)) rg_add_edge(g, u, v);
    }
}

/* True if every block can reach a block with no successors. */
static inline bool rg_all_reach_exit(const rgraph_t *g) {
    bool reaches[RG_MAX_NODES] = { false };
    for (uint32_t b = 0; b < g->n; b++) reaches[b] = (g->outdeg[b] == 0);
    bool changed = true;
    while (changed) {
        changed = false;
        for (uint32_t i = 0; i < g->m; i++) {
            if (reaches[g->e[i][1]] && !reaches[g->e[i][0]]) {
                reaches[g->e[i][0]] = true;
                changed = true;
            }
        }
    }
    for (uint32_t b = 0; b < g->n; b++) if (!reaches[b]) return false;
    return true;
}

/* ── The reference ────────────────────────────────────────────────────── */

/* dom[b] = bitmask of every node that dominates b (including b). All
 * nodes must be reachable from `root`. n <= 64. */
static inline void ref_dominators(uint32_t n, uint32_t root,
                                  const uint32_t (*edges)[2], uint32_t m,
                                  uint64_t *dom) {
    const uint64_t all = (n >= 64) ? ~0ull : ((1ull << n) - 1);
    for (uint32_t i = 0; i < n; i++) dom[i] = all;
    dom[root] = 1ull << root;

    bool changed = true;
    while (changed) {
        changed = false;
        for (uint32_t b = 0; b < n; b++) {
            if (b == root) continue;
            uint64_t acc = all;
            for (uint32_t i = 0; i < m; i++)
                if (edges[i][1] == b) acc &= dom[edges[i][0]];
            acc |= 1ull << b;
            if (acc != dom[b]) { dom[b] = acc; changed = true; }
        }
    }
}

static inline uint32_t ref_idom(uint32_t n, uint32_t root,
                                const uint64_t *dom, uint32_t b) {
    if (b == root) return root;
    const uint64_t strict = dom[b] & ~(1ull << b);
    uint32_t best = UINT32_MAX;
    int best_size = -1;
    for (uint32_t d = 0; d < n; d++) {
        if (!((strict >> d) & 1)) continue;
        int size = __builtin_popcountll(dom[d]);
        if (size > best_size) { best_size = size; best = d; }
    }
    return best;
}

#endif /* CBAE_TEST_DOM_REFERENCE_H */
