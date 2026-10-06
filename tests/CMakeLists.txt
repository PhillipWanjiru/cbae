cmake_minimum_required(VERSION 3.20)

function(cbae_add_test name src)
    add_executable(${name} ${CMAKE_CURRENT_SOURCE_DIR}/${src})
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    # Tests are written with assert(), some wrapping calls that must run.
    # Release adds -DNDEBUG globally, which would delete those calls;
    # -UNDEBUG (applied last) keeps every test assertion live in all
    # build types. Library code is unaffected.
    target_compile_options(${name} PRIVATE -UNDEBUG)
    target_link_libraries(${name} PRIVATE cbae_engine ${ARGN})
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 30)
endfunction()

# ── Phase 1 — Foundation ──────────────────────────────────────────────────
cbae_add_test(test_hashmap         unit/test_hashmap.c)
cbae_add_test(test_arena_allocator unit/test_arena_allocator.c)
cbae_add_test(test_string_pool     unit/test_string_pool.c)
cbae_add_test(test_vector          unit/test_vector.c)
cbae_add_test(test_db_persistence  unit/test_db_persistence.c)

# ── Phase 2 — Binary Loaders ──────────────────────────────────────────────
cbae_add_test(test_pe_loader       unit/test_pe_loader.c  cbae_loader)
cbae_add_test(test_elf_loader      unit/test_elf_loader.c cbae_loader)

# ── Phase 3 — Disassembly & CFG ───────────────────────────────────────────
cbae_add_test(test_disassembler      unit/test_disassembler.c      cbae_disasm cbae_loader)
cbae_add_test(test_cfg_builder       unit/test_cfg_builder.c       cbae_disasm cbae_loader)
cbae_add_test(test_indirect_resolver unit/test_indirect_resolver.c cbae_disasm cbae_loader)
cbae_add_test(test_loader_to_disasm  unit/test_loader_to_disasm.c  cbae_disasm cbae_loader)

# ── Phase 4 — CIR Design & Lifting ────────────────────────────────────────
cbae_add_test(test_cir_builder       unit/test_cir_builder.c       cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_cir_lifter        unit/test_cir_lifter.c        cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_ssa_construction  unit/test_ssa_construction.c  cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_disasm_to_cir     unit/test_disasm_to_cir.c     cbae_cir cbae_disasm cbae_loader)

# ── Phase 5 — Dataflow Infrastructure ─────────────────────────────────────
cbae_add_test(test_dominator_tree    unit/test_dominator_tree.c    cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_post_dominator_tree unit/test_post_dominator_tree.c cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_dataflow_engine   unit/test_dataflow_engine.c   cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_use_def           unit/test_use_def.c           cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_alias_analysis    unit/test_alias_analysis.c    cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_alias_soundness   unit/test_alias_soundness.c   cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_graph_scc         unit/test_graph_scc.c         cbae_dataflow cbae_cir cbae_disasm cbae_loader)
# graph_scc / dom_core are internal headers; this test exercises them directly.
target_include_directories(test_graph_scc PRIVATE ${CMAKE_SOURCE_DIR}/src/dataflow)
