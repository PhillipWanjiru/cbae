/**
 * @file test_graph_scc.c
 * @brief Strongly connected components (internal module graph_scc).
 *
 *   1. Hand-derived graphs, including the classic cross-edge shape that
 *      breaks a Tarjan implementation which forgets to test whether the
 *      target is still on the component stack.
 *   2. A 1,000,000-node chain and ring, to demonstrate the traversal does
 *      not recurse.
 *   3. 6000 random digraphs -- self-loops, parallel edges, isolated and
 *      unreachable nodes, random "active" subsets -- checked against the
 *      textbook definition: x and y share a component iff each reaches the
 *      other. The reference is a boolean transitive closure (Warshall),
 *      which shares no code or idea with Tarjan's algorithm.
 */
#include "graph_scc.h"
#include "dom_core.h"
#include "dom_reference.h"      /* rng_t only */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXN 12
#define MAXM 40

typedef struct {
    uint32_t n, m;
    uint32_t e[MAXM][2];
} tgraph_t;

static void dump(const tgraph_t *g, const bool *active) {
    fprintf(stderr, "  graph n=%u edges:", g->n);
    for (uint32_t i = 0; i < g->m; i++) fprintf(stderr, " %u->%u", g->e[i][0], g->e[i][1]);
    if (active) {
        fprintf(stderr, "  active:");
        for (uint32_t i = 0; i < g->n; i++) if (active[i]) fprintf(stderr, " %u", i);
    }
    fprintf(stderr, "\n");
}

typedef struct {
    dom_csr_t csr;
    uint32_t  comp[MAXN];
    uint32_t  ncomp;
    bool      on_cycle[MAXN];
} result_t;

static void run(const tgraph_t *g, const bool *active, result_t *r) {
    uint32_t from[MAXM + 1], to[MAXM + 1];
    for (uint32_t i = 0; i < g->m; i++) { from[i] = g->e[i][0]; to[i] = g->e[i][1]; }
    assert(dom_csr_build(g->n, from, to, g->m, &r->csr) == CBAE_OK);
    assert(graph_scc_compute(g->n, r->csr.succ_off, r->csr.succ_adj, active,
                             r->comp, &r->ncomp) == CBAE_OK);
    assert(graph_scc_on_cycle(g->n, r->csr.succ_off, r->csr.succ_adj,
                              r->on_cycle) == CBAE_OK);
}

static void done(result_t *r) { dom_csr_free(&r->csr); }

/* Edges as a literal: G(n, {u,v}, {u,v}, ...) */
#define EDGES(...) (const uint32_t[][2]){ __VA_ARGS__ }
static tgraph_t mk(uint32_t n, uint32_t m, const uint32_t (*e)[2]) {
    tgraph_t g; memset(&g, 0, sizeof g);
    g.n = n; g.m = m;
    for (uint32_t i = 0; i < m; i++) { g.e[i][0] = e[i][0]; g.e[i][1] = e[i][1]; }
    return g;
}

/* ── 1. Hand-derived ─────────────────────────────────────────────────── */

static void t_trivial(void) {
    /* n == 0: nothing to do, nothing to fail. */
    uint32_t off1[1] = {0}, adj1[1] = {0}, comp1[1], nc = 99;
    bool oc0[1];
    assert(graph_scc_compute(0, off1, adj1, NULL, comp1, &nc) == CBAE_OK && nc == 0);
    assert(graph_scc_on_cycle(0, off1, adj1, oc0) == CBAE_OK);

    /* One node, no edges: one component, not on a cycle. */
    tgraph_t g = mk(1, 0, NULL);
    result_t r; run(&g, NULL, &r);
    assert(r.ncomp == 1 && r.comp[0] == 0 && !r.on_cycle[0]);
    done(&r);

    /* One node with an edge to itself: still one component, now on a cycle. */
    g = mk(1, 1, EDGES({0, 0}));
    run(&g, NULL, &r);
    assert(r.ncomp == 1 && r.on_cycle[0]);
    done(&r);

    /* Null arguments are rejected. */
    assert(graph_scc_compute(1, NULL, adj1, NULL, comp1, &nc) == CBAE_ERR_INVALID);
    assert(graph_scc_compute(1, off1, NULL, NULL, comp1, &nc) == CBAE_ERR_INVALID);
    assert(graph_scc_compute(1, off1, adj1, NULL, NULL, &nc) == CBAE_ERR_INVALID);
    assert(graph_scc_compute(1, off1, adj1, NULL, comp1, NULL) == CBAE_ERR_INVALID);
    bool oc[1];
    assert(graph_scc_on_cycle(1, NULL, adj1, oc) == CBAE_ERR_INVALID);
    assert(graph_scc_on_cycle(1, off1, adj1, NULL) == CBAE_ERR_INVALID);
    printf("  [PASS] trivial: empty, single node, self-loop, null arguments\n");
}

static void t_line(void) {
    /*   0 -> 1 -> 2
     * Every node is its own component. Tarjan finishes 2 first, then 1,
     * then 0, so ids run the opposite way to the edges. */
    tgraph_t g = mk(3, 2, EDGES({0, 1}, {1, 2}));
    result_t r; run(&g, NULL, &r);
    assert(r.ncomp == 3);
    assert(r.comp[2] == 0 && r.comp[1] == 1 && r.comp[0] == 2);
    assert(!r.on_cycle[0] && !r.on_cycle[1] && !r.on_cycle[2]);
    done(&r);
    printf("  [PASS] line 0->1->2: three components, ids in reverse topological order\n");
}

static void t_cycle(void) {
    /*   0 -> 1 -> 2 -> 0 : one component, every node on the cycle. */
    tgraph_t g = mk(3, 3, EDGES({0, 1}, {1, 2}, {2, 0}));
    result_t r; run(&g, NULL, &r);
    assert(r.ncomp == 1 && r.comp[0] == r.comp[1] && r.comp[1] == r.comp[2]);
    assert(r.on_cycle[0] && r.on_cycle[1] && r.on_cycle[2]);
    done(&r);

    /*   figure eight: 0 <-> 1 and 0 <-> 2 share node 0, so all three are
     *   one component even though 1 and 2 are not directly connected. */
    g = mk(3, 4, EDGES({0, 1}, {1, 0}, {0, 2}, {2, 0}));
    run(&g, NULL, &r);
    assert(r.ncomp == 1 && r.on_cycle[0] && r.on_cycle[1] && r.on_cycle[2]);
    done(&r);

    /*   parallel edges change nothing: 0 => 1 -> 0. */
    g = mk(2, 3, EDGES({0, 1}, {0, 1}, {1, 0}));
    run(&g, NULL, &r);
    assert(r.ncomp == 1 && r.on_cycle[0] && r.on_cycle[1]);
    done(&r);
    printf("  [PASS] cycles: triangle, figure eight, parallel edges\n");
}

static void t_two_components(void) {
    /*   {0,1} -> {2,3}:   0->1 1->0 1->2 2->3 3->2
     * DFS from 0 completes {2,3} first (id 0), then {0,1} (id 1). The edge
     * 1->2 crosses components, so id({2,3}) < id({0,1}). */
    tgraph_t g = mk(4, 5, EDGES({0, 1}, {1, 0}, {1, 2}, {2, 3}, {3, 2}));
    result_t r; run(&g, NULL, &r);
    assert(r.ncomp == 2);
    assert(r.comp[0] == r.comp[1] && r.comp[2] == r.comp[3] && r.comp[0] != r.comp[2]);
    assert(r.comp[2] == 0 && r.comp[0] == 1);
    for (int i = 0; i < 4; i++) assert(r.on_cycle[i]);
    done(&r);
    printf("  [PASS] two cycles joined by one edge: ids {2,3}=0, {0,1}=1\n");
}

static void t_cross_edge_to_finished_component(void) {
    /*   0 -> 1, 0 -> 2, 2 -> 1.   No cycles at all.
     * DFS goes 0, 1 (finished: {1} is complete and popped), back to 0, then
     * 2, whose edge to 1 is a CROSS edge into a finished component. 1 has an
     * earlier index than 2, but it is no longer on the stack, so it must not
     * lower low[2]. An implementation that skips the on-stack test merges 2
     * with 0 here. Reverse topological order forces the ids: 1, 2, 0.   */
    tgraph_t g = mk(3, 3, EDGES({0, 1}, {0, 2}, {2, 1}));
    result_t r; run(&g, NULL, &r);
    assert(r.ncomp == 3);
    assert(r.comp[1] == 0 && r.comp[2] == 1 && r.comp[0] == 2);
    assert(!r.on_cycle[0] && !r.on_cycle[1] && !r.on_cycle[2]);
    done(&r);
    printf("  [PASS] cross edge into a finished component does not merge components\n");
}

static void t_self_loop_and_chain(void) {
    /*   0 -> 0, 0 -> 1:  0 is on a cycle (itself); 1 is not. */
    tgraph_t g = mk(2, 2, EDGES({0, 0}, {0, 1}));
    result_t r; run(&g, NULL, &r);
    assert(r.ncomp == 2 && r.on_cycle[0] && !r.on_cycle[1]);
    done(&r);
    printf("  [PASS] self-loop marks only its own node as cyclic\n");
}

static void t_active_mask(void) {
    /*   triangle 0->1->2->0, with only {0,1} active. The edge 1->2 leaves the
     *   subgraph and 2->0 starts outside it, so the cycle is gone: two
     *   singleton components, node 2 excluded. */
    tgraph_t g = mk(3, 3, EDGES({0, 1}, {1, 2}, {2, 0}));
    const bool active[3] = { true, true, false };
    result_t r; run(&g, active, &r);
    assert(r.ncomp == 2);
    assert(r.comp[2] == GRAPH_SCC_NONE);
    assert(r.comp[0] != r.comp[1]);
    assert(r.comp[1] == 0 && r.comp[0] == 1);
    done(&r);

    /* All inactive: zero components, everything NONE. */
    const bool none[3] = { false, false, false };
    run(&g, none, &r);
    assert(r.ncomp == 0);
    for (int i = 0; i < 3; i++) assert(r.comp[i] == GRAPH_SCC_NONE);
    done(&r);
    printf("  [PASS] active mask: an edge leaving the subgraph does not close a cycle\n");
}

/* ── 2. Depth ────────────────────────────────────────────────────────── */

static void t_deep(void) {
    const uint32_t N = 1000000;
    uint32_t *off = malloc(sizeof(uint32_t) * (N + 1));
    uint32_t *adj = malloc(sizeof(uint32_t) * N);
    uint32_t *comp = malloc(sizeof(uint32_t) * N);
    bool *oc = malloc(sizeof(bool) * N);
    assert(off && adj && comp && oc);

    /* Chain 0 -> 1 -> ... -> N-1 (last node has no successor). */
    for (uint32_t i = 0; i <= N; i++) off[i] = i < N ? i : N - 1;
    for (uint32_t i = 0; i + 1 < N; i++) adj[i] = i + 1;
    uint32_t nc = 0;
    assert(graph_scc_compute(N, off, adj, NULL, comp, &nc) == CBAE_OK);
    assert(nc == N);
    assert(comp[N - 1] == 0 && comp[0] == N - 1);
    assert(graph_scc_on_cycle(N, off, adj, oc) == CBAE_OK);
    for (uint32_t i = 0; i < N; i++) assert(!oc[i]);

    /* Ring: close the chain with N-1 -> 0. */
    for (uint32_t i = 0; i <= N; i++) off[i] = i;
    for (uint32_t i = 0; i < N; i++) adj[i] = (i + 1) % N;
    assert(graph_scc_compute(N, off, adj, NULL, comp, &nc) == CBAE_OK);
    assert(nc == 1);
    assert(graph_scc_on_cycle(N, off, adj, oc) == CBAE_OK);
    for (uint32_t i = 0; i < N; i++) assert(oc[i]);

    free(off); free(adj); free(comp); free(oc);
    printf("  [PASS] 1,000,000-node chain and ring: iterative, no recursion\n");
}

/* ── 3. Random graphs vs transitive closure ──────────────────────────── */

typedef bool closure_t[MAXN][MAXN];

/* R[i][j] = a NON-EMPTY path from i to j exists, using only active nodes. */
static void closure(const tgraph_t *g, const bool *active, closure_t R) {
    memset(R, 0, sizeof(closure_t));
    for (uint32_t i = 0; i < g->m; i++) {
        uint32_t u = g->e[i][0], v = g->e[i][1];
        if (active && (!active[u] || !active[v])) continue;
        R[u][v] = true;
    }
    for (uint32_t k = 0; k < g->n; k++)
        for (uint32_t i = 0; i < g->n; i++)
            for (uint32_t j = 0; j < g->n; j++)
                if (R[i][k] && R[k][j]) R[i][j] = true;
}

static void check_random(const tgraph_t *g, const bool *active) {
    result_t r; run(g, active, &r);
    closure_t R;
    closure(g, active, R);

    /* Partition agrees with mutual reachability. */
    uint32_t classes = 0;
    bool counted[MAXN] = {0};
    for (uint32_t x = 0; x < g->n; x++) {
        const bool act = !active || active[x];
        if (!act) {
            if (r.comp[x] != GRAPH_SCC_NONE) { dump(g, active); fprintf(stderr, "inactive %u has a component\n", x); abort(); }
            continue;
        }
        if (r.comp[x] >= r.ncomp) { dump(g, active); fprintf(stderr, "comp id out of range\n"); abort(); }
        if (!counted[x]) {
            classes++;
            counted[x] = true;
            for (uint32_t y = x + 1; y < g->n; y++)
                if ((!active || active[y]) && R[x][y] && R[y][x]) counted[y] = true;
        }
        for (uint32_t y = 0; y < g->n; y++) {
            if (y == x || (active && !active[y])) continue;
            const bool same_ref  = R[x][y] && R[y][x];
            const bool same_impl = r.comp[x] == r.comp[y];
            if (same_ref != same_impl) {
                dump(g, active);
                fprintf(stderr, "nodes %u,%u: reference says %s component, implementation %s\n",
                        x, y, same_ref ? "same" : "different", same_impl ? "same" : "different");
                abort();
            }
        }
    }
    if (classes != r.ncomp) { dump(g, active); fprintf(stderr, "ncomp %u, reference %u\n", r.ncomp, classes); abort(); }

    /* Ids are dense: every id in [0, ncomp) is used. */
    bool used[MAXN] = {0};
    for (uint32_t x = 0; x < g->n; x++)
        if ((!active || active[x])) used[r.comp[x]] = true;
    for (uint32_t c = 0; c < r.ncomp; c++)
        if (!used[c]) { dump(g, active); fprintf(stderr, "component id %u unused\n", c); abort(); }

    /* Reverse topological numbering across every crossing edge. */
    for (uint32_t i = 0; i < g->m; i++) {
        uint32_t u = g->e[i][0], v = g->e[i][1];
        if (active && (!active[u] || !active[v])) continue;
        if (r.comp[u] != r.comp[v] && !(r.comp[v] < r.comp[u])) {
            dump(g, active);
            fprintf(stderr, "edge %u->%u crosses components but ids are not reverse-topological\n", u, v);
            abort();
        }
    }

    /* on_cycle (whole graph, no mask) vs closure diagonal. */
    closure_t Rfull;
    closure(g, NULL, Rfull);
    for (uint32_t x = 0; x < g->n; x++)
        if (r.on_cycle[x] != Rfull[x][x]) {
            dump(g, NULL);
            fprintf(stderr, "node %u: on_cycle=%d, reference=%d\n", x, r.on_cycle[x], Rfull[x][x]);
            abort();
        }
    done(&r);
}

static void t_random(void) {
    rng_t rng = { 0x5CC5CC5CC5CC5CC5ull };
    uint32_t masked = 0, with_cycle = 0, multi = 0;
    for (int iter = 0; iter < 6000; iter++) {
        tgraph_t g; memset(&g, 0, sizeof g);
        g.n = 1 + rng_next(&rng) % MAXN;
        g.m = rng_next(&rng) % (MAXM + 1);
        for (uint32_t i = 0; i < g.m; i++) {
            g.e[i][0] = rng_next(&rng) % g.n;
            g.e[i][1] = rng_next(&rng) % g.n;      /* self-loops and duplicates allowed */
        }
        bool active[MAXN];
        const bool use_mask = (iter & 1);
        if (use_mask) {
            for (uint32_t i = 0; i < g.n; i++) active[i] = (rng_next(&rng) % 4) != 0;
            masked++;
        }
        check_random(&g, use_mask ? active : NULL);

        /* Track how interesting the sample was, so a degenerate generator
         * cannot pass silently. */
        closure_t R; closure(&g, NULL, R);
        bool cyc = false, big = false;
        for (uint32_t x = 0; x < g.n; x++) {
            if (R[x][x]) cyc = true;
            for (uint32_t y = 0; y < g.n; y++) if (x != y && R[x][y] && R[y][x]) big = true;
        }
        if (cyc) with_cycle++;
        if (big) multi++;
    }
    /* The sample must really exercise cycles and multi-node components. */
    assert(with_cycle > 3000 && multi > 2000 && masked == 3000);
    printf("  [PASS] 6000 random digraphs match the transitive-closure reference "
           "(%u with a cycle, %u with a multi-node component, %u masked)\n",
           with_cycle, multi, masked);
}

int main(void) {
    printf("Strongly connected components tests:\n");
    t_trivial();
    t_line();
    t_cycle();
    t_two_components();
    t_cross_edge_to_finished_component();
    t_self_loop_and_chain();
    t_active_mask();
    t_deep();
    t_random();
    printf("All SCC tests passed.\n");
    return 0;
}
