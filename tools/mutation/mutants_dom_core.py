"""The mutants of src/dataflow/dom_core.c: (name, text that occurs exactly once, its replacement). A name starts with its tag.
Used by run_mut.py (set MUT_TIMEOUT=60: a mutant that hangs is killed by the timeout). A mutant that cannot be told from the
original is named (equivalent: why); one that cannot be reached, (unreachable: why).

Not run, because the effect needs more memory than a test machine has: in dom_csr_build the limit `n > DOM_MAX_NODES` taken
away, or moved to `>=`, and the same for dom_core_number_tree; they allocate and then touch tables of 2 GiB each. Run by hand in
an unsanitized tree under `ulimit -v 1500000` they fail the tests: the allocation is refused, so the answer is OOM, not OVERFLOW."""
SRC = 'src/dataflow/dom_core.c'
TESTS = ['test_dominance_contracts', 'test_dominator_tree', 'test_post_dominator_tree', 'test_dominance_oom',
         'test_alias_analysis', 'test_compiled_code', 'test_ssa_verifier']

_COND = ("    if (!out->succ_off || !out->pred_off || !out->succ_adj || !out->pred_adj ||\n"
         "        !scur || !pcur) {")

MUTANTS = [
 # dom_csr_build: limits and the output
 ("D01 csr_build: the output is not cleared first", "    memset(out, 0, sizeof(*out));\n    if (n > DOM_MAX_NODES", "    if (n > DOM_MAX_NODES"),
 ("D02 csr_build: more edges than the limit are accepted", "if (n > DOM_MAX_NODES || m > 3u * DOM_MAX_NODES)", "if (n > DOM_MAX_NODES)"),
 ("D03 csr_build: the offsets have no slot for the end of the last node (successors)",
  "    out->succ_off = calloc((size_t)n + 1, sizeof(uint32_t));", "    out->succ_off = calloc((size_t)n, sizeof(uint32_t));"),
 ("D04 csr_build: the offsets have no slot for the end of the last node (predecessors)",
  "    out->pred_off = calloc((size_t)n + 1, sizeof(uint32_t));", "    out->pred_off = calloc((size_t)n, sizeof(uint32_t));"),
 ("D05 csr_build (equivalent: malloc(0) gives a pointer on glibc and in the sanitizer; the guard is for other libraries): the successor list of no edges is a zero-byte request",
  "    out->succ_adj = malloc(sizeof(uint32_t) * (m ? m : 1));", "    out->succ_adj = malloc(sizeof(uint32_t) * m);"),
 ("D06 csr_build (equivalent: as D05): the predecessor list of no edges is a zero-byte request",
  "    out->pred_adj = malloc(sizeof(uint32_t) * (m ? m : 1));", "    out->pred_adj = malloc(sizeof(uint32_t) * m);"),
 ("D07 csr_build (equivalent: as D05): the cursor of no nodes is a zero-byte request",
  "    uint32_t *scur = malloc(sizeof(uint32_t) * (n ? n : 1));", "    uint32_t *scur = malloc(sizeof(uint32_t) * n);"),
 ("D08 csr_build (equivalent: as D05): the second cursor of no nodes is a zero-byte request",
  "    uint32_t *pcur = malloc(sizeof(uint32_t) * (n ? n : 1));", "    uint32_t *pcur = malloc(sizeof(uint32_t) * n);"),

 # dom_csr_build: allocation failure
 ("D09 csr_build: a failed successor-offset table is not noticed", _COND,
  "    if (!out->pred_off || !out->succ_adj || !out->pred_adj ||\n        !scur || !pcur) {"),
 ("D10 csr_build: a failed predecessor-offset table is not noticed", _COND,
  "    if (!out->succ_off || !out->succ_adj || !out->pred_adj ||\n        !scur || !pcur) {"),
 ("D11 csr_build: a failed successor list is not noticed", _COND,
  "    if (!out->succ_off || !out->pred_off || !out->pred_adj ||\n        !scur || !pcur) {"),
 ("D12 csr_build: a failed predecessor list is not noticed", _COND,
  "    if (!out->succ_off || !out->pred_off || !out->succ_adj ||\n        !scur || !pcur) {"),
 ("D13 csr_build: a failed successor cursor is not noticed", _COND,
  "    if (!out->succ_off || !out->pred_off || !out->succ_adj || !out->pred_adj ||\n        !pcur) {"),
 ("D14 csr_build: a failed predecessor cursor is not noticed", _COND,
  "    if (!out->succ_off || !out->pred_off || !out->succ_adj || !out->pred_adj ||\n        !scur) {"),
 ("D15 csr_build: the cursors are not freed after a failed allocation",
  '        free(scur); free(pcur);\n        dom_csr_free(out);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominator core: CSR alloc failed");',
  '        dom_csr_free(out);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominator core: CSR alloc failed");'),
 ("D16 csr_build: the tables are not freed after a failed allocation",
  '        free(scur); free(pcur);\n        dom_csr_free(out);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominator core: CSR alloc failed");',
  '        free(scur); free(pcur);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominator core: CSR alloc failed");'),

 # dom_csr_build: edges out of range
 ("D17 csr_build: an edge from the node just past the end is accepted", "if (from[i] >= n || to[i] >= n) {", "if (from[i] > n || to[i] >= n) {"),
 ("D18 csr_build: an edge to the node just past the end is accepted", "if (from[i] >= n || to[i] >= n) {", "if (from[i] >= n || to[i] > n) {"),
 ("D19 csr_build: the source of an edge is not checked", "if (from[i] >= n || to[i] >= n) {", "if (to[i] >= n) {"),
 ("D20 csr_build: the target of an edge is not checked", "if (from[i] >= n || to[i] >= n) {", "if (from[i] >= n) {"),
 ("D21 csr_build: the cursors are not freed after an edge out of range",
  '            free(scur); free(pcur);\n            dom_csr_free(out);\n            CBAE_RETURN_ERR(CBAE_ERR_INVALID,',
  '            dom_csr_free(out);\n            CBAE_RETURN_ERR(CBAE_ERR_INVALID,'),
 ("D22 csr_build: the tables are not freed after an edge out of range",
  '            free(scur); free(pcur);\n            dom_csr_free(out);\n            CBAE_RETURN_ERR(CBAE_ERR_INVALID,',
  '            free(scur); free(pcur);\n            CBAE_RETURN_ERR(CBAE_ERR_INVALID,'),

 # dom_csr_build: the table itself
 ("D23 csr_build: the successors are not counted", "        out->succ_off[from[i] + 1]++;\n", ""),
 ("D24 csr_build: the predecessors are not counted", "        out->pred_off[to[i] + 1]++;\n", ""),
 ("D25 csr_build: the successor offsets are not summed", "        out->succ_off[i + 1] += out->succ_off[i];\n", ""),
 ("D26 csr_build: the predecessor offsets are not summed", "        out->pred_off[i + 1] += out->pred_off[i];\n", ""),
 ("D27 csr_build: the successor cursors start at 0", "        scur[i] = out->succ_off[i];", "        scur[i] = 0;"),
 ("D28 csr_build: the predecessor cursors start at 0", "        pcur[i] = out->pred_off[i];", "        pcur[i] = 0;"),
 ("D29 csr_build: the successor list holds the sources", "        out->succ_adj[scur[from[i]]++] = to[i];", "        out->succ_adj[scur[from[i]]++] = from[i];"),
 ("D30 csr_build: the predecessor list holds the targets", "        out->pred_adj[pcur[to[i]]++]   = from[i];", "        out->pred_adj[pcur[to[i]]++]   = to[i];"),
 ("D31 csr_build: the cursors are not freed", "    free(scur);\n    free(pcur);\n    return CBAE_OK;", "    return CBAE_OK;"),

 # dom_csr_free
 ("D32 csr_free: a NULL table is not allowed for", "    if (!c) return;\n", ""),
 ("D33 csr_free: the successor offsets are not freed", "    free(c->succ_off); free(c->succ_adj);\n", "    free(c->succ_adj);\n"),
 ("D34 csr_free: the successor list is not freed", "    free(c->succ_off); free(c->succ_adj);\n", "    free(c->succ_off);\n"),
 ("D35 csr_free: the predecessor offsets are not freed", "    free(c->pred_off); free(c->pred_adj);\n", "    free(c->pred_adj);\n"),
 ("D36 csr_free: the predecessor list is not freed", "    free(c->pred_off); free(c->pred_adj);\n", "    free(c->pred_off);\n"),
 ("D37 csr_free: the table is not cleared", "    free(c->pred_off); free(c->pred_adj);\n    memset(c, 0, sizeof(*c));", "    free(c->pred_off); free(c->pred_adj);"),

 # compute_rpo
 ("D38 rpo: the visited marks start as whatever malloc gives", "    bool        *visited   = calloc(n, sizeof(bool));", "    bool        *visited   = malloc(n * sizeof(bool));"),
 ("D39 rpo: a failed visited table is not noticed", "    if (!visited || !stack || !postorder) {", "    if (!stack || !postorder) {"),
 ("D40 rpo: a failed stack is not noticed", "    if (!visited || !stack || !postorder) {", "    if (!visited || !postorder) {"),
 ("D41 rpo: a failed postorder table is not noticed", "    if (!visited || !stack || !postorder) {", "    if (!visited || !stack) {"),
 ("D42 rpo: the scratch is not freed after a failed allocation",
  '        free(visited); free(stack); free(postorder);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, "%s: DFS scratch alloc failed", what);',
  '        CBAE_RETURN_ERR(CBAE_ERR_OOM, "%s: DFS scratch alloc failed", what);'),
 ("D43 rpo: the root is not marked visited", "    visited[g->root] = true;\n", ""),
 ("D44 rpo: the walk does not move on along the edges", "uint32_t succ = g->succ_adj[top->next_edge++];", "uint32_t succ = g->succ_adj[top->next_edge];"),
 ("D45 rpo: a node already visited is walked again", "            if (!visited[succ]) {", "            if (true) {"),
 ("D46 rpo: a node is not marked when it is walked", "                visited[succ] = true;\n", ""),
 ("D47 rpo (equivalent: a node is stacked once, so the count never passes n): the unreached test is a less-than",
  "    if (pcount != n) {", "    if (pcount < n) {"),
 ("D48 rpo: nodes not reached are accepted", "    if (pcount != n) {", "    if (pcount > n) {"),
 ("D49 rpo: the scratch is not freed after nodes not reached",
  '        free(visited); free(stack); free(postorder);\n        CBAE_RETURN_ERR(CBAE_ERR_INVALID,',
  '        CBAE_RETURN_ERR(CBAE_ERR_INVALID,'),
 ("D50 rpo: the order is the postorder, not its reverse", "        uint32_t node = postorder[n - 1 - i];", "        uint32_t node = postorder[i];"),
 ("D51 rpo: the order is not recorded", "        rpo_order[i] = node;\n", ""),
 ("D52 rpo: the numbers are not recorded", "        rpo_number[node] = i;\n", ""),
 ("D53 rpo: the scratch is not freed", "    free(visited);\n    free(stack);\n    free(postorder);\n    return CBAE_OK;", "    return CBAE_OK;"),

 # intersect
 ("D54 intersect: the first finger also climbs when the numbers are equal", "while (rpo_number[f1] > rpo_number[f2]) f1 = idom[f1];", "while (rpo_number[f1] >= rpo_number[f2]) f1 = idom[f1];"),
 ("D55 intersect: the second finger also climbs when the numbers are equal", "while (rpo_number[f2] > rpo_number[f1]) f2 = idom[f2];", "while (rpo_number[f2] >= rpo_number[f1]) f2 = idom[f2];"),
 ("D56 intersect: the first finger climbs the wrong way", "while (rpo_number[f1] > rpo_number[f2]) f1 = idom[f1];", "while (rpo_number[f1] < rpo_number[f2]) f1 = idom[f1];"),
 ("D57 intersect: the fingers are brought together once", "    while (f1 != f2) {", "    if (f1 != f2) {"),

 # dom_core_compute
 ("D58 compute: the root one past the end is accepted", "    if (g->root >= n)", "    if (g->root > n)"),
 ("D59 compute: the root is not its own immediate dominator", "    idom[g->root] = g->root;", "    (void)0;"),
 ("D60 compute: the root is visited by the loop too", "for (uint32_t rank = 1; rank < n; rank++) {", "for (uint32_t rank = 0; rank < n; rank++) {"),
 ("D61 compute: a predecessor without an answer yet is used", "                if (idom[p] == UNDEFINED_IDOM) continue;\n", ""),
 ("D62 compute: the last predecessor is the answer",
  "                new_idom = (new_idom == UNDEFINED_IDOM)\n                    ? p\n                    : intersect(idom, rpo_number, new_idom, p);",
  "                new_idom = p;"),
 ("D63 compute: a change is not remembered", "                idom[b] = new_idom;\n                changed = true;", "                idom[b] = new_idom;"),
 ("D64 compute: the loop does not start a pass with nothing changed", "        changed = false;\n", ""),
 ("D65 compute: every answer counts as a change", "            if (idom[b] != new_idom) {", "            if (true) {"),
 ("D66 compute: the answers do not start undefined", "    for (uint32_t i = 0; i < n; i++) idom[i] = UNDEFINED_IDOM;\n", ""),
 ("D67 compute: one predecessor too many is read", "e < g->pred_off[b + 1]; e++) {", "e <= g->pred_off[b + 1]; e++) {"),

 # dom_core_build_children
 ("D68 children: a failed list does not release the lists before it",
  "            for (uint32_t j = 0; j < i; j++) cbae_vector_destroy(&children[j]);\n            return rc;",
  "            return rc;"),
 ("D69 children (equivalent: a vector whose init failed is all zero, and destroying that is a no-op): the failed list is destroyed too",
  "for (uint32_t j = 0; j < i; j++) cbae_vector_destroy(&children[j]);", "for (uint32_t j = 0; j <= i; j++) cbae_vector_destroy(&children[j]);"),
 ("D70 children: a failed list is reported as success",
  "            for (uint32_t j = 0; j < i; j++) cbae_vector_destroy(&children[j]);\n            return rc;",
  "            for (uint32_t j = 0; j < i; j++) cbae_vector_destroy(&children[j]);\n            return CBAE_OK;"),
 ("D71 children: the root is a child too", "        if (b == root) continue;           /* the root has no parent */\n", ""),
 ("D72 children: a failed push is not noticed",
  "        cbae_err_t rc = cbae_vector_push(&children[idom[b]], &b);\n        if (rc != CBAE_OK) {\n            for (uint32_t j = 0; j < n; j++) cbae_vector_destroy(&children[j]);\n            return rc;\n        }",
  "        (void)cbae_vector_push(&children[idom[b]], &b);"),
 ("D73 children: a failed push does not release the lists",
  "            for (uint32_t j = 0; j < n; j++) cbae_vector_destroy(&children[j]);\n            return rc;",
  "            return rc;"),
 ("D74 children: a node is the child of itself", "cbae_vector_push(&children[idom[b]], &b)", "cbae_vector_push(&children[b], &b)"),

 # dom_core_number_tree
 ("D75 number: the root one past the end is accepted", "    if (root >= n)  ", "    if (root > n)  "),
 ("D76 number: more nodes than the limit are accepted", "    if (n > DOM_MAX_NODES)\n        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, \"dominator tree numbering", "    if (false)\n        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, \"dominator tree numbering"),
 ("D77 number: a failed stack is not noticed", '    if (!stack) CBAE_RETURN_ERR(CBAE_ERR_OOM, "dominator tree numbering: DFS stack alloc failed");\n', ""),
 ("D78 number: the entry times are not cleared first", "    for (uint32_t i = 0; i < n; i++) enter[i] = UNNUMBERED;\n", ""),
 ("D79 number: the root's entry does not take a time", "    enter[root] = timer++;", "    enter[root] = timer;"),
 ("D80 number: a child that does not exist is not noticed", "if (child >= n || enter[child] != UNNUMBERED) {", "if (enter[child] != UNNUMBERED) {"),
 ("D81 number: a node entered twice is not noticed", "if (child >= n || enter[child] != UNNUMBERED) {", "if (child >= n) {"),
 ("D82 number: the stack is not freed after children that are not a tree", "                free(stack);\n                CBAE_RETURN_ERR(CBAE_ERR_INVALID,", "                CBAE_RETURN_ERR(CBAE_ERR_INVALID,"),
 ("D83 number: a child's entry does not take a time", "            enter[child] = timer++;", "            enter[child] = timer;"),
 ("D84 number: the walk does not move on along the children", "            top->next_edge++;\n", ""),
 ("D85 number: a node's exit does not take a time", "            leave[top->node] = timer++;", "            leave[top->node] = timer;"),
 ("D86 number: a finished node stays on the stack", "            leave[top->node] = timer++;\n            sp--;", "            leave[top->node] = timer++;"),
 ("D87 number: the stack is not freed", "    free(stack);\n    if (timer != 2u * n)", "    if (timer != 2u * n)"),
 ("D88 number: nodes the root does not reach are accepted", "    if (timer != 2u * n)", "    if (false)"),
 ("D89 number: nodes the root does not reach are accepted (greater-than)", "    if (timer != 2u * n)", "    if (timer > 2u * n)"),
 ("D90 number (equivalent: every node is entered once, so the count never passes 2n): the count test is a less-than", "    if (timer != 2u * n)", "    if (timer < 2u * n)"),
 ("D91 number: the first child of a node is skipped", "    stack[sp].next_edge = 0;\n            sp++;", "    stack[sp].next_edge = 1;\n            sp++;"),
]
