"""The mutants of the dominance code of src/dataflow/ssa_verifier.c (dominance_free, reachable, dominates, dominance_build):
(name, text that occurs exactly once, its replacement). A name starts with its tag. Used by run_mut.py (set MUT_TIMEOUT=60: a
mutant that hangs is killed by the timeout). A mutant that cannot be told from the original is named (equivalent: why); one that
cannot be reached, (unreachable: why). The rest of the verifier (the availability rules) is not mutated here."""
SRC = 'src/dataflow/ssa_verifier.c'
TESTS = ['test_ssa_verifier', 'test_dominance_oom', 'test_dominance_contracts', 'test_compiled_code']

_FREE = "    free(d->dense); free(d->enter); free(d->leave);\n"
_ALLOC1 = ("    if (!d->dense || !queue) {\n"
           "        free(queue); dominance_free(d);\n")
_ALLOC2 = ("    if (!from || !to) {\n"
           "        free(from); free(to); free(queue); dominance_free(d);\n")
_CHK3 = "    if (!idom || !rpo_order || !rpo_number || !children || !d->enter || !d->leave) {\n"
_FREE3 = ("        free(idom); free(rpo_order); free(rpo_number); free(children);\n"
          "        dom_csr_free(&csr); dominance_free(d);\n")
_ENDFREE = "    free(idom); free(rpo_order); free(rpo_number); free(children);\n    if (rc != CBAE_OK) dominance_free(d);"
_DOMINATES = "return d->enter[x] <= d->enter[y] && d->leave[y] <= d->leave[x];"
_BFS_ADD = "            if (d->dense[s] == NONE) { d->dense[s] = n; queue[n++] = s; }\n"
_EDGE = ("            from[ne] = i;\n"
         "            to[ne]   = d->dense[blk->successors[k]];\n"
         "            ne++;\n")

MUTANTS = [
 # dominance_free, reachable, dominates
 ("W01 free: the numbering is not freed", _FREE, "    free(d->enter); free(d->leave);\n"),
 ("W02 free: the entry times are not freed", _FREE, "    free(d->dense); free(d->leave);\n"),
 ("W03 free: the exit times are not freed", _FREE, "    free(d->dense); free(d->enter);\n"),
 ("W04 free: the freed struct is not cleared (equivalent: the verifier frees it once, and on a failure only the builder frees it and nobody looks at it again)",
  "    free(d->dense); free(d->enter); free(d->leave);\n    memset(d, 0, sizeof *d);\n", _FREE),
 ("W05 reachable: a block that was reached is not reachable", "return d->dense[b] != NONE;", "return d->dense[b] == NONE;"),
 ("W06 dominates: a block does not dominate itself (enter)", "d->enter[x] <= d->enter[y]", "d->enter[x] < d->enter[y]"),
 ("W07 dominates: a block does not dominate itself (leave)", "d->leave[y] <= d->leave[x]", "d->leave[y] < d->leave[x]"),
 ("W08 dominates: either end of the interval will do", _DOMINATES, "return d->enter[x] <= d->enter[y] || d->leave[y] <= d->leave[x];"),
 ("W09 dominates: the intervals are compared the wrong way round", _DOMINATES,
  "return d->enter[y] <= d->enter[x] && d->leave[x] <= d->leave[y];"),
 ("W10 dominates: only the entry times are compared", _DOMINATES, "return d->enter[x] <= d->enter[y];"),
 ("W11 dominates: only the exit times are compared", _DOMINATES, "return d->leave[y] <= d->leave[x];"),
 ("W12 dominates: the blocks are not numbered densely", "const uint32_t x = d->dense[a], y = d->dense[b];", "const uint32_t x = a, y = b;"),
 # dominance_build: the numbering
 ("W13 build: the struct is not cleared first", "    memset(d, 0, sizeof *d);\n    const uint32_t nb", "    const uint32_t nb"),
 ("W14 build: the numbering is too short", "    d->dense = malloc(sizeof(uint32_t) * nb);", "    d->dense = malloc(sizeof(uint32_t) * (nb / 2 + 1));"),
 ("W15 build: the queue is too short", "    uint32_t *queue = malloc(sizeof(uint32_t) * nb);", "    uint32_t *queue = malloc(sizeof(uint32_t) * (nb / 2 + 1));"),
 ("W16 build: the numbering is not checked", _ALLOC1, _ALLOC1.replace("if (!d->dense || !queue)", "if (!queue)")),
 ("W17 build: the queue is not checked", _ALLOC1, _ALLOC1.replace("if (!d->dense || !queue)", "if (!d->dense)")),
 ("W18 build: a failed allocation leaves the queue allocated", _ALLOC1, _ALLOC1.replace("free(queue); ", "")),
 ("W19 build: a failed allocation leaves the numbering allocated", _ALLOC1, _ALLOC1.replace(" dominance_free(d);", "")),
 ("W20 build: no block is marked as not reached", "    for (uint32_t i = 0; i < nb; i++) d->dense[i] = NONE;\n", ""),
 ("W21 build: the entry has no number", "    d->dense[0] = n;\n", ""),
 ("W22 build: the entry is not queued", "    queue[n++] = 0;\n", "    n++;\n"),
 ("W23 build: the edges of a block are counted without the earlier ones", "        cap += blk->successor_count;", "        cap = blk->successor_count;"),
 ("W24 build: the edges are not counted", "        cap += blk->successor_count;\n", ""),
 ("W25 build: a block that has a number is numbered again", _BFS_ADD, _BFS_ADD.replace("== NONE", "!= NONE")),
 ("W26 build: a successor is queued but not numbered", _BFS_ADD, _BFS_ADD.replace("d->dense[s] = n; ", "")),
 ("W27 build: a successor is numbered but not queued", _BFS_ADD, _BFS_ADD.replace(" queue[n++] = s;", " n++;")),
 ("W28 build: the search stops one block early", "    while (head < n) {", "    while (head + 1 < n) {"),
 # the edge lists
 ("W29 build: room for the edges whatever their number (equivalent: malloc of no bytes gives a block)",
  "    uint32_t *from = malloc(sizeof(uint32_t) * (cap ? cap : 1));", "    uint32_t *from = malloc(sizeof(uint32_t) * cap);"),
 ("W30 build: room for one edge", "    uint32_t *to   = malloc(sizeof(uint32_t) * (cap ? cap : 1));", "    uint32_t *to   = malloc(sizeof(uint32_t) * 1);"),
 ("W31 build: the first edge list is not checked", _ALLOC2, _ALLOC2.replace("if (!from || !to)", "if (!to)")),
 ("W32 build: the second edge list is not checked", _ALLOC2, _ALLOC2.replace("if (!from || !to)", "if (!from)")),
 ("W33 build: a failed allocation leaves the first edge list allocated", _ALLOC2, _ALLOC2.replace("free(from); ", "")),
 ("W34 build: a failed allocation leaves the second edge list allocated", _ALLOC2, _ALLOC2.replace("free(to); ", "")),
 ("W35 build: a failed allocation leaves the queue allocated", _ALLOC2, _ALLOC2.replace("free(queue); ", "")),
 ("W36 build: a failed allocation leaves the numbering allocated", _ALLOC2, _ALLOC2.replace(" dominance_free(d);", "")),
 ("W37 build: the edges start at the block, not at its number", "            from[ne] = i;\n", "            from[ne] = queue[i];\n"),
 ("W38 build: the edges end at the block, not at its number", "            to[ne]   = d->dense[blk->successors[k]];\n",
  "            to[ne]   = blk->successors[k];\n"),
 ("W39 build: the edge counter is not advanced", _EDGE, _EDGE.replace("            ne++;\n", "")),
 ("W40 build: the queue is not freed", "    free(queue);\n\n    dom_csr_t csr;", "\n    dom_csr_t csr;"),
 ("W41 build: the first edge list is not freed", "    free(from); free(to);\n    if (rc != CBAE_OK) { dominance_free(d); return rc; }",
  "    free(to);\n    if (rc != CBAE_OK) { dominance_free(d); return rc; }"),
 ("W42 build: the second edge list is not freed", "    free(from); free(to);\n    if (rc != CBAE_OK) { dominance_free(d); return rc; }",
  "    free(from);\n    if (rc != CBAE_OK) { dominance_free(d); return rc; }"),
 ("W43 build: a failure of the lists is not noticed", "    if (rc != CBAE_OK) { dominance_free(d); return rc; }\n", ""),
 ("W44 build: a failure of the lists leaves the numbering allocated", "    if (rc != CBAE_OK) { dominance_free(d); return rc; }\n",
  "    if (rc != CBAE_OK) { return rc; }\n"),
 ("W45 build: a failure of the lists is reported as success", "    if (rc != CBAE_OK) { dominance_free(d); return rc; }\n",
  "    if (rc != CBAE_OK) { dominance_free(d); return CBAE_OK; }\n"),
 # the arrays of the computation
 ("W46 build: the array of immediate dominators is not checked", _CHK3, _CHK3.replace("!idom || ", "")),
 ("W47 build: the array of orders is not checked", _CHK3, _CHK3.replace("!rpo_order || ", "")),
 ("W48 build: the array of numbers is not checked", _CHK3, _CHK3.replace("!rpo_number || ", "")),
 ("W49 build: the array of children lists is not checked", _CHK3, _CHK3.replace("!children || ", "")),
 ("W50 build: the array of entry times is not checked", _CHK3, _CHK3.replace("!d->enter || ", "")),
 ("W51 build: the array of exit times is not checked", _CHK3, _CHK3.replace(" || !d->leave", "")),
 ("W52 build: a failed allocation leaves the immediate dominators allocated", _FREE3, _FREE3.replace("free(idom); ", "")),
 ("W53 build: a failed allocation leaves the orders allocated", _FREE3, _FREE3.replace("free(rpo_order); ", "")),
 ("W54 build: a failed allocation leaves the numbers allocated", _FREE3, _FREE3.replace("free(rpo_number); ", "")),
 ("W55 build: a failed allocation leaves the children lists allocated", _FREE3, _FREE3.replace("free(children);", "")),
 ("W56 build: a failed allocation leaves the edge lists allocated", _FREE3, _FREE3.replace("dom_csr_free(&csr); ", "")),
 ("W57 build: a failed allocation leaves the numbering allocated", _FREE3, _FREE3.replace(" dominance_free(d);", "")),
 ("W58 build: the root is block 1", "    const dom_graph_t g = { n, 0, csr.succ_off", "    const dom_graph_t g = { n, 1, csr.succ_off"),
 ("W59 build: the edge lists are not freed", "    dom_csr_free(&csr);\n    if (rc == CBAE_OK) rc = dom_core_build_children(n, 0, idom, children);",
  "    if (rc == CBAE_OK) rc = dom_core_build_children(n, 0, idom, children);"),
 ("W60 build: the children lists are made even after a failure",
  "    if (rc == CBAE_OK) rc = dom_core_build_children(n, 0, idom, children);", "    rc = dom_core_build_children(n, 0, idom, children);"),
 ("W61 build: the tree is numbered even after a failure",
  "    if (rc == CBAE_OK) {\n        rc = dom_core_number_tree(n, 0, children, d->enter, d->leave);",
  "    {\n        rc = dom_core_number_tree(n, 0, children, d->enter, d->leave);"),
 ("W62 build: the children lists are not freed",
  "        for (uint32_t i = 0; i < n; i++) cbae_vector_destroy(&children[i]);\n", ""),
 ("W63 build: one children list too many",
  "        for (uint32_t i = 0; i < n; i++) cbae_vector_destroy(&children[i]);\n",
  "        for (uint32_t i = 0; i <= n; i++) cbae_vector_destroy(&children[i]);\n"),
 ("W64 build: the immediate dominators are not freed", _ENDFREE, _ENDFREE.replace("free(idom); ", "")),
 ("W65 build: the orders are not freed", _ENDFREE, _ENDFREE.replace("free(rpo_order); ", "")),
 ("W66 build: the numbers are not freed", _ENDFREE, _ENDFREE.replace("free(rpo_number); ", "")),
 ("W67 build: the array of children lists is not freed", _ENDFREE, _ENDFREE.replace("free(children);", "")),
 ("W68 build: a failure leaves the numbering allocated", _ENDFREE, "    free(idom); free(rpo_order); free(rpo_number); free(children);"),
 ("W69 build: a success frees the numbering", _ENDFREE, _ENDFREE.replace("if (rc != CBAE_OK) dominance_free(d);", "dominance_free(d);")),
]
