"""The mutants of src/dataflow/post_dominator_tree.c: (name, text that occurs exactly once, its replacement). A name starts with its tag.
Used by run_mut.py (set MUT_TIMEOUT=60: a mutant that hangs is killed by the timeout). A mutant that cannot be told from the
original is named (equivalent: why); one that cannot be reached, (unreachable: why)."""
SRC = 'src/dataflow/post_dominator_tree.c'
TESTS = ['test_dominance_contracts', 'test_post_dominator_tree', 'test_dominator_tree', 'test_dominance_oom',
         'test_alias_analysis', 'test_compiled_code', 'test_ssa_verifier']

_CHK = "    if (!t.ipdom || !t.rpo_order || !t.rpo_number || !t.dt_enter || !t.dt_exit || !t.children)"
_ALLOC = ("A failed arena allocation takes nothing and `children`, the largest request, is refused as well, "
          "and that one is still checked")


def _arrays(tag, field, equivalent):
    new = _CHK.replace("!t.%s || " % field, "") if field == 'ipdom' else _CHK.replace(" || !t.%s" % field, "")
    name = "%s build: the %s array is not checked" % (tag, field)
    if equivalent:
        name += " (equivalent: %s)" % _ALLOC
    return (name, _CHK, new)


_STACK = ("        for (uint32_t e = fwd->pred_off[v]; e < fwd->pred_off[v + 1]; e++) {\n"
          "            uint32_t p = fwd->pred_adj[e];\n"
          "            if (!reaches[p]) {\n"
          "                reaches[p] = true;\n"
          "                stack[sp++] = p;       /* each node is pushed at most once */\n"
          "            }\n"
          "        }\n")
_SCC_ALLOC = ("    if (!active || !comp) {\n"
              "        free(active); free(comp);\n")
_SCC_ALLOC2 = ("    if (!rep || !has_out) {\n"
               "        free(active); free(comp); free(rep); free(has_out);\n")
_SCC_FAIL = "    if (rc != CBAE_OK) { free(active); free(comp); return rc; }\n"
_SCC_END = "    free(active); free(comp); free(rep); free(has_out);\n    return CBAE_OK;"
_ROOM = "    const size_t edge_room = (size_t)ncfg + n;"
_SCAN = "    if (!rf || !rt || !to_vexit || !reaches) {\n"
_FWD_FAIL = ("    if (rc != CBAE_OK) {\n"
             "        free(rf); free(rt); free(to_vexit); free(reaches);\n"
             "        return rc;\n"
             "    }\n\n"
             "    /* Steps 2 + 3")
_LINK_FAIL = ("    dom_csr_free(&fwd);\n"
              "    if (rc != CBAE_OK) {\n"
              "        free(rf); free(rt); free(to_vexit); free(reaches);\n"
              "        return rc;\n"
              "    }\n")
_DOM = "pt->dt_enter[a] <= pt->dt_enter[b] && pt->dt_exit[b] <= pt->dt_exit[a]"
_RANGE = "a >= pt->block_count || b >= pt->block_count"

MUTANTS = [
 # mark_reaching_exit
 ("R01 mark: a failed scratch allocation is not noticed",
  "    if (!stack) CBAE_RETURN_ERR(CBAE_ERR_OOM, \"post-dominator tree: scratch alloc failed\");\n", ""),
 ("R02 mark: the stack holds too few nodes", "    uint32_t *stack = malloc(sizeof(uint32_t) * n);", "    uint32_t *stack = malloc(sizeof(uint32_t) * (n / 2 + 1));"),
 ("R03 mark: an exit block is not marked as reaching an exit",
  "        if (to_vexit[b]) { reaches[b] = true; stack[sp++] = b; }", "        if (to_vexit[b]) { stack[sp++] = b; }"),
 ("R04 mark: an exit block is not walked back from",
  "        if (to_vexit[b]) { reaches[b] = true; stack[sp++] = b; }", "        if (to_vexit[b]) { reaches[b] = true; }"),
 ("R05 mark: the last stacked node is not walked back from", "    while (sp > 0) {", "    while (sp > 1) {"),
 ("R06 mark: one predecessor too many", "e < fwd->pred_off[v + 1]; e++) {\n            uint32_t p", "e <= fwd->pred_off[v + 1]; e++) {\n            uint32_t p"),
 ("R07 mark: a block is walked back from again and again", _STACK, _STACK.replace("if (!reaches[p]) {", "if (1) {")),
 ("R08 mark: a predecessor is not marked", _STACK, _STACK.replace("                reaches[p] = true;\n", "")),
 ("R09 mark: a predecessor is not walked back from", _STACK, _STACK.replace("                stack[sp++] = p;       /* each node is pushed at most once */\n", "")),
 ("R10 mark: the stack is not freed", "    free(stack);\n    return CBAE_OK;", "    return CBAE_OK;"),
 # link_sink_sccs
 ("R11 link: the array of active blocks is not checked", _SCC_ALLOC, _SCC_ALLOC.replace("if (!active || !comp)", "if (!comp)")),
 ("R12 link: the array of components is not checked", _SCC_ALLOC, _SCC_ALLOC.replace("if (!active || !comp)", "if (!active)")),
 ("R13 link: the active blocks are those that reach an exit", "active[b] = !reaches[b];", "active[b] = reaches[b];"),
 ("R14 link: a failure of the components is not noticed", _SCC_FAIL, ""),
 ("R15 link: a failure of the components leaves the scratch allocated", _SCC_FAIL, "    if (rc != CBAE_OK) { return rc; }\n"),
 ("R16 link: a failure of the components is reported as success", _SCC_FAIL, "    if (rc != CBAE_OK) { free(active); free(comp); return CBAE_OK; }\n"),
 ("R17 link: the array of representatives is not checked", _SCC_ALLOC2, _SCC_ALLOC2.replace("if (!rep || !has_out)", "if (!has_out)")),
 ("R18 link: the array of sinks is not checked", _SCC_ALLOC2, _SCC_ALLOC2.replace("if (!rep || !has_out)", "if (!rep)")),
 ("R19 link: a failed allocation leaves the representatives allocated",
  _SCC_ALLOC2, _SCC_ALLOC2.replace("free(active); free(comp); free(rep); free(has_out);", "free(active); free(comp); free(has_out);")),
 ("R20 link: a failed allocation leaves the sinks allocated",
  _SCC_ALLOC2, _SCC_ALLOC2.replace("free(active); free(comp); free(rep); free(has_out);", "free(active); free(comp); free(rep);")),
 ("R21 link: room for one component whatever their number", "calloc(ncomp ? ncomp : 1, sizeof(uint32_t));", "calloc(1, sizeof(uint32_t));"),
 ("R22 link: no room guard for the representatives (equivalent: a call comes only when a block cannot exit, so there is a component)",
  "calloc(ncomp ? ncomp : 1, sizeof(uint32_t));", "calloc(ncomp, sizeof(uint32_t));"),
 ("R23 link: the blocks that cannot be reached are not skipped", "        if (!active[u]) continue;\n", ""),
 ("R24 link: the representative is the last block seen (equivalent: the blocks are taken in increasing order, so the last is the highest)",
  "        if (u > rep[comp[u]]) rep[comp[u]] = u;\n", "        rep[comp[u]] = u;\n"),
 ("R25 link: the representative is not set", "        if (u > rep[comp[u]]) rep[comp[u]] = u;\n", ""),
 ("R26 link: an edge to a block that exits is looked at (equivalent: the successors of a block that cannot exit cannot exit either)",
  "if (active[w] && comp[w] != comp[u]) has_out[comp[u]] = true;", "if (comp[w] != comp[u]) has_out[comp[u]] = true;"),
 ("R27 link: an edge inside a component leaves it", "if (active[w] && comp[w] != comp[u]) has_out[comp[u]] = true;",
  "if (active[w] && comp[w] == comp[u]) has_out[comp[u]] = true;"),
 ("R28 link: the component that is entered is marked, not the one that is left",
  "has_out[comp[u]] = true;", "has_out[comp[w]] = true;"),
 ("R29 link: the first successor decides", "        for (uint32_t e = fwd->succ_off[u]; e < fwd->succ_off[u + 1]; e++) {\n            const uint32_t w",
  "        for (uint32_t e = fwd->succ_off[u]; e < fwd->succ_off[u] + 1 && e < fwd->succ_off[u + 1]; e++) {\n            const uint32_t w"),
 ("R30 link: a component with a way out is linked to the exit", "        if (!has_out[c]) link_to_exit[rep[c]] = true;", "        if (has_out[c]) link_to_exit[rep[c]] = true;"),
 ("R31 link: the component number is taken for a block", "link_to_exit[rep[c]] = true;", "link_to_exit[c] = true;"),
 ("R32 link: one component too many", "    for (uint32_t c = 0; c < ncomp; c++) {\n        if (!has_out[c])", "    for (uint32_t c = 0; c <= ncomp; c++) {\n        if (!has_out[c])"),
 ("R33 link: the scratch is not freed", _SCC_END, "    return CBAE_OK;"),
 ("R34 link: the representatives and sinks are not freed", _SCC_END, "    free(active); free(comp);\n    return CBAE_OK;"),
 # cbae_pdom_tree_build: arguments and limits
 ("R35 build: a null out is not refused",
  "    if (!out) CBAE_RETURN_ERR(CBAE_ERR_INVALID, \"post-dominator tree: null argument\");\n    memset(out, 0, sizeof(*out));",
  "    memset(out, 0, sizeof(*out));"),
 ("R36 build: *out is not cleared first", "    memset(out, 0, sizeof(*out));\n    if (!func || !arena)", "    if (!func || !arena)"),
 ("R37 build: a null function is not refused", "    if (!func || !arena)\n        CBAE_RETURN_ERR", "    if (!arena)\n        CBAE_RETURN_ERR"),
 ("R38 build: a null arena is not refused", "    if (!func || !arena)\n        CBAE_RETURN_ERR", "    if (!func)\n        CBAE_RETURN_ERR"),
 ("R39 build: a function without blocks is not refused",
  "    if (count == 0)\n        CBAE_RETURN_ERR(CBAE_ERR_INVALID, \"post-dominator tree: function has no blocks\");\n", ""),
 ("R40 build: no limit on the number of blocks",
  "    if (count > DOM_MAX_NODES)\n        CBAE_RETURN_ERR(CBAE_ERR_OVERFLOW, \"post-dominator tree: %zu blocks, more than the %u it takes\", count, DOM_MAX_NODES);\n", ""),
 ("R41 build: the limit is one block too small", "    if (count > DOM_MAX_NODES)\n", "    if (count >= DOM_MAX_NODES)\n"),
 ("R42 build: no room for the virtual exit", "    const uint32_t total = n + 1;", "    const uint32_t total = n;"),
 ("R43 build: the virtual exit is the last real block", "    const uint32_t vexit = n;", "    const uint32_t vexit = n - 1;"),
 ("R44 build: the tree does not remember its function", "    t.func        = func;\n", ""),
 ("R45 build: the tree does not remember its block count", "    t.block_count = n;\n", ""),
 _arrays("R46", "ipdom", True),
 _arrays("R47", "rpo_order", True),
 _arrays("R48", "rpo_number", True),
 _arrays("R49", "dt_enter", True),
 _arrays("R50", "dt_exit", True),
 _arrays("R51", "children", False),
 ("R52 build: a failed array allocation is not reported",
  _CHK + "\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, \"post-dominator tree: array alloc failed\");\n", ""),
 # the edge lists
 ("R53 build: no room for the edges to the virtual exit", _ROOM, "    const size_t edge_room = (size_t)ncfg;"),
 ("R54 build: room for one edge to the virtual exit", _ROOM, "    const size_t edge_room = (size_t)ncfg + 1;"),
 ("R55 build: the edge lists have room for the exit edges (equivalent: one more edge than can be needed is room not used)",
  _ROOM, "    const size_t edge_room = (size_t)ncfg + n + 1;"),
 ("R56 build: the first edge list is not checked", _SCAN, _SCAN.replace("!rf || ", "")),
 ("R57 build: the second edge list is not checked", _SCAN, _SCAN.replace("!rt || ", "")),
 ("R58 build: the list of exits is not checked", _SCAN, _SCAN.replace("!to_vexit || ", "")),
 ("R59 build: the list of blocks that reach an exit is not checked", _SCAN, _SCAN.replace(" || !reaches", "")),
 ("R60 build: a failed scratch allocation leaves the first edge list allocated",
  "        free(rf); free(rt); free(to_vexit); free(reaches);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, \"post-dominator tree: scratch alloc failed\");",
  "        free(rt); free(to_vexit); free(reaches);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, \"post-dominator tree: scratch alloc failed\");"),
 ("R61 build: a failed scratch allocation leaves the second edge list allocated",
  "        free(rf); free(rt); free(to_vexit); free(reaches);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, \"post-dominator tree: scratch alloc failed\");",
  "        free(rf); free(to_vexit); free(reaches);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, \"post-dominator tree: scratch alloc failed\");"),
 ("R62 build: a failed scratch allocation leaves the list of exits allocated",
  "        free(rf); free(rt); free(to_vexit); free(reaches);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, \"post-dominator tree: scratch alloc failed\");",
  "        free(rf); free(rt); free(reaches);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, \"post-dominator tree: scratch alloc failed\");"),
 ("R63 build: a failed scratch allocation leaves the list of reaching blocks allocated",
  "        free(rf); free(rt); free(to_vexit); free(reaches);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, \"post-dominator tree: scratch alloc failed\");",
  "        free(rf); free(rt); free(to_vexit);\n        CBAE_RETURN_ERR(CBAE_ERR_OOM, \"post-dominator tree: scratch alloc failed\");"),
 ("R64 build: the edges are not reversed", "            rf[ei] = blk->successors[k];\n            rt[ei] = b;", "            rf[ei] = b;\n            rt[ei] = blk->successors[k];"),
 ("R65 build: a block with a successor is an exit", "        if (blk->successor_count == 0) to_vexit[b] = true;", "        if (blk->successor_count != 0) to_vexit[b] = true;"),
 ("R66 build: no block is an exit", "        if (blk->successor_count == 0) to_vexit[b] = true;\n", ""),
 ("R67 build: the edge counter is not advanced", "            rt[ei] = b;\n            ei++;", "            rt[ei] = b;"),
 ("R68 build: the forward lists are built from the reversed edges", "dom_csr_build(n, rt, rf, ncfg, &fwd)", "dom_csr_build(n, rf, rt, ncfg, &fwd)"),
 ("R69 build: a failure of the forward lists is not noticed", _FWD_FAIL, "    /* Steps 2 + 3"),
 ("R70 build: a failure of the forward lists leaves the scratch allocated",
  _FWD_FAIL, _FWD_FAIL.replace("        free(rf); free(rt); free(to_vexit); free(reaches);\n", "")),
 ("R71 build: a failure of the forward lists is reported as success", _FWD_FAIL, _FWD_FAIL.replace("        return rc;", "        return CBAE_OK;")),
 ("R72 build: the blocks that reach an exit are looked for only when the first does not",
  "    rc = mark_reaching_exit(n, &fwd, to_vexit, reaches);\n    if (rc == CBAE_OK) {", "    rc = mark_reaching_exit(n, &fwd, to_vexit, reaches);\n    if (rc != CBAE_OK) {"),
 ("R73 build: every block is taken to reach an exit", "        bool all_reach = true;", "        bool all_reach = false;"),
 ("R74 build: no block is taken to reach an exit", "{ all_reach = false; break; }", "{ all_reach = true; break; }"),
 ("R75 build: the regions that cannot exit are looked at whether there are any or not (equivalent: with no such block there are no components and nothing is linked)",
  "        if (!all_reach) rc = link_sink_sccs(n, &fwd, reaches, to_vexit);", "        rc = link_sink_sccs(n, &fwd, reaches, to_vexit);"),
 ("R76 build: the search for a block that cannot exit goes on (equivalent: it only makes the scan longer)",
  "{ all_reach = false; break; }", "{ all_reach = false; }"),
 ("R77 build: the forward lists are not freed", _LINK_FAIL, _LINK_FAIL.replace("    dom_csr_free(&fwd);\n", "")),
 ("R78 build: a failure of the links is not noticed", _LINK_FAIL, "    dom_csr_free(&fwd);\n"),
 ("R79 build: a failure of the links leaves the scratch allocated",
  _LINK_FAIL, _LINK_FAIL.replace("        free(rf); free(rt); free(to_vexit); free(reaches);\n", "")),
 ("R80 build: a failure of the links is reported as success", _LINK_FAIL, _LINK_FAIL.replace("        return rc;", "        return CBAE_OK;")),
 # the virtual exit and the computation
 ("R81 build: an exit block is not linked to the virtual exit",
  "        if (to_vexit[b]) { rf[ei] = vexit; rt[ei] = b; ei++; }", "        if (to_vexit[b]) { rf[ei] = vexit; rt[ei] = b; }"),
 ("R82 build: the link points to the virtual exit", "        if (to_vexit[b]) { rf[ei] = vexit; rt[ei] = b; ei++; }",
  "        if (to_vexit[b]) { rf[ei] = b; rt[ei] = vexit; ei++; }"),
 ("R83 build: every block is linked to the virtual exit", "        if (to_vexit[b]) { rf[ei] = vexit;", "        if (1) { rf[ei] = vexit;"),
 ("R84 build: no block is linked to the virtual exit", "        if (to_vexit[b]) { rf[ei] = vexit; rt[ei] = b; ei++; }\n", ""),
 ("R85 build: the reversed lists leave out the last edge", "dom_csr_build(total, rf, rt, ei, &rev)", "dom_csr_build(total, rf, rt, ei - 1, &rev)"),
 ("R86 build: the scratch is not freed after the reversed lists",
  "    free(rf); free(rt); free(to_vexit); free(reaches);\n    CBAE_CHECK(rc);", "    CBAE_CHECK(rc);"),
 ("R87 build: a failure of the reversed lists is not noticed",
  "    free(rf); free(rt); free(to_vexit); free(reaches);\n    CBAE_CHECK(rc);", "    free(rf); free(rt); free(to_vexit); free(reaches);"),
 ("R88 build: the root is block 0", "    const dom_graph_t g = { total, vexit, rev.succ_off", "    const dom_graph_t g = { total, 0, rev.succ_off"),
 ("R89 build: the reversed lists are not freed", "    dom_csr_free(&rev);\n    CBAE_CHECK(rc);", "    CBAE_CHECK(rc);"),
 ("R90 build: a failure of the computation is not noticed", "    dom_csr_free(&rev);\n    CBAE_CHECK(rc);", "    dom_csr_free(&rev);"),
 ("R91 build: a failure to make the children lists is not noticed",
  "    CBAE_CHECK(dom_core_build_children(total, vexit, t.ipdom, t.children));",
  "    (void)dom_core_build_children(total, vexit, t.ipdom, t.children);"),
 ("R92 build: a failed numbering is not noticed",
  "    if (rc != CBAE_OK) {\n        for (uint32_t i = 0; i < total; i++) cbae_vector_destroy(&t.children[i]);\n        return rc;\n    }\n", ""),
 ("R93 build: a failed numbering leaves the children lists allocated",
  "        for (uint32_t i = 0; i < total; i++) cbae_vector_destroy(&t.children[i]);\n        return rc;", "        return rc;"),
 ("R94 build: a failed numbering is reported as success", "        return rc;\n    }\n\n    *out = t;", "        return CBAE_OK;\n    }\n\n    *out = t;"),
 ("R95 build: the tree is not handed over", "    *out = t;\n", ""),
 ("R96 build: the debug line (equivalent: a log line)", "    LOG_DEBUG(\"post-dominator tree built: %u blocks + virtual exit\", n);\n", ""),
 # destroy and the queries
 ("R97 destroy: a null tree is not refused",
  "    if (!pt || pt->block_count == 0) return;", "    if (pt->block_count == 0) return;"),
 ("R98 destroy: a tree without blocks is not refused",
  "    if (!pt || pt->block_count == 0) return;", "    if (!pt) return;"),
 ("R99 destroy: the list of the virtual exit is not freed",
  "    for (uint32_t i = 0; i <= pt->block_count; i++)", "    for (uint32_t i = 0; i < pt->block_count; i++)"),
 ("RA0 destroy: no list is freed", "    for (uint32_t i = 0; i <= pt->block_count; i++)\n        cbae_vector_destroy(&pt->children[i]);\n", ""),
 ("RA1 ipdom: a null tree is not refused",
  "    if (!pt || block_id >= pt->block_count) return CBAE_PDOM_NONE;", "    if (block_id >= pt->block_count) return CBAE_PDOM_NONE;"),
 ("RA2 ipdom: the virtual exit is a block",
  "    if (!pt || block_id >= pt->block_count) return CBAE_PDOM_NONE;", "    if (!pt || block_id > pt->block_count) return CBAE_PDOM_NONE;"),
 ("RA3 ipdom: an unknown block has block 0 as its post-dominator",
  "return CBAE_PDOM_NONE;\n    const uint32_t p", "return 0;\n    const uint32_t p"),
 ("RA4 ipdom: the virtual exit is not named", "    return p == pt->block_count ? CBAE_PDOM_EXIT : p;", "    return p;"),
 ("RA5 ipdom: every block is named as post-dominated by the exit", "    return p == pt->block_count ? CBAE_PDOM_EXIT : p;", "    return p != pt->block_count ? CBAE_PDOM_EXIT : p;"),
 ("RA6 post_dominates: a null tree is not refused",
  "    if (!pt || " + _RANGE + ") return false;", "    if (" + _RANGE + ") return false;"),
 ("RA7 post_dominates: the virtual exit is a block (bound on a)", _RANGE, "a > pt->block_count || b >= pt->block_count"),
 ("RA8 post_dominates: the virtual exit is a block (bound on b) (equivalent: the virtual exit is the root, so no real block's interval starts at or before it)",
  _RANGE, "a >= pt->block_count || b > pt->block_count"),
 ("RA9 post_dominates: a block does not post-dominate itself (enter)", "pt->dt_enter[a] <= pt->dt_enter[b]", "pt->dt_enter[a] < pt->dt_enter[b]"),
 ("RB0 post_dominates: a block does not post-dominate itself (exit)", "pt->dt_exit[b] <= pt->dt_exit[a]", "pt->dt_exit[b] < pt->dt_exit[a]"),
 ("RB1 post_dominates: either end of the interval will do", _DOM, "pt->dt_enter[a] <= pt->dt_enter[b] || pt->dt_exit[b] <= pt->dt_exit[a]"),
 ("RB2 post_dominates: the intervals are compared the wrong way round", _DOM, "pt->dt_enter[b] <= pt->dt_enter[a] && pt->dt_exit[a] <= pt->dt_exit[b]"),
 ("RB3 post_dominates: only the entry times are compared", _DOM, "pt->dt_enter[a] <= pt->dt_enter[b]"),
 ("RB4 post_dominates: only the exit times are compared", _DOM, "pt->dt_exit[b] <= pt->dt_exit[a]"),
 ("RB5 children: a null tree is not refused",
  "    if (!pt || block_id >= pt->block_count) return &NO_BLOCKS;\n    return &pt->children[block_id];",
  "    if (block_id >= pt->block_count) return &NO_BLOCKS;\n    return &pt->children[block_id];"),
 ("RB6 children: the virtual exit is a block",
  "    if (!pt || block_id >= pt->block_count) return &NO_BLOCKS;\n    return &pt->children[block_id];",
  "    if (!pt || block_id > pt->block_count) return &NO_BLOCKS;\n    return &pt->children[block_id];"),
 ("RB7 children: an unknown block has no list", "return &NO_BLOCKS;\n    return &pt->children[block_id];", "return NULL;\n    return &pt->children[block_id];"),
 ("RB8 exit_children: a null tree is not refused",
  "    if (!pt || pt->block_count == 0) return &NO_BLOCKS;\n    return &pt->children[pt->block_count];",
  "    if (pt->block_count == 0) return &NO_BLOCKS;\n    return &pt->children[pt->block_count];"),
 ("RB9 exit_children: a tree without blocks is not refused",
  "    if (!pt || pt->block_count == 0) return &NO_BLOCKS;\n    return &pt->children[pt->block_count];",
  "    if (!pt) return &NO_BLOCKS;\n    return &pt->children[pt->block_count];"),
 ("RC0 exit_children: the list of block 0", "    return &pt->children[pt->block_count];", "    return &pt->children[0];"),
 ("RC1 exit_children: an empty tree has no list",
  "    if (!pt || pt->block_count == 0) return &NO_BLOCKS;\n    return &pt->children[pt->block_count];",
  "    if (!pt || pt->block_count == 0) return NULL;\n    return &pt->children[pt->block_count];"),
]
