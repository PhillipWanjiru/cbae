cmake_minimum_required(VERSION 3.20)

# The limit kills a test that hangs; it is not a performance criterion, so a slow machine must not fail a test that is only slow.
# It is at least ten times the slowest test on the slowest machine measured so far. The slowest tests are the loader sweeps
# (test_elf_real, test_elf_hostile); in a Debug build they take 8.5 s and 7.2 s on the 2.3 GHz sandbox, and the author's machine
# runs them about 1.9 times slower (a 30 s limit failed test_elf_real there: A-055). Seconds on the sandbox, worst test per build:
# Debug 8.5, Release 6.8, ASan 34.5, TSan 55.8. -DCBAE_TEST_TIMEOUT=<seconds> sets the limit by hand.
set(CBAE_TEST_TIMEOUT "" CACHE STRING "Seconds one test may run before it is killed; empty: 300, with ASan 900, with TSan 1200")
if(NOT CBAE_TEST_TIMEOUT STREQUAL "")
    set(CBAE_TEST_LIMIT ${CBAE_TEST_TIMEOUT})
elseif(CBAE_SANITIZE STREQUAL "address")
    set(CBAE_TEST_LIMIT 900)
elseif(CBAE_SANITIZE STREQUAL "thread")
    set(CBAE_TEST_LIMIT 1200)
else()
    set(CBAE_TEST_LIMIT 300)
endif()

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
    set_tests_properties(${name} PROPERTIES TIMEOUT ${CBAE_TEST_LIMIT})
endfunction()

# ── Phase 1 — Foundation ──────────────────────────────────────────────────
cbae_add_test(test_hashmap         unit/test_hashmap.c)
target_link_options(test_hashmap PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
cbae_add_test(test_arena_allocator unit/test_arena_allocator.c)
cbae_add_test(test_string_pool     unit/test_string_pool.c)
# the out-of-memory tests count and fail allocations by wrapping the allocator (tests/unit/alloc_inject.h)
target_link_options(test_string_pool PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
cbae_add_test(test_vector          unit/test_vector.c)
target_link_options(test_vector PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
cbae_add_test(test_logging          unit/test_logging.c)
cbae_add_test(test_thread_pool      unit/test_thread_pool.c)
# the thread pool tests make the allocator, thread creation and lock creation fail on demand (tests/unit/alloc_inject.h, and the wrappers in the test)
target_link_options(test_thread_pool PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=pthread_create,--wrap=pthread_mutex_init,--wrap=pthread_cond_init)
cbae_add_test(test_db_persistence  unit/test_db_persistence.c)
# the db tests make SQLite's answers to the journal-mode query, the foreign-key query, the busy-timeout call and a busy lock different, and the wait between two tries instant (wrappers in the test)
target_link_options(test_db_persistence PRIVATE -Wl,--wrap=sqlite3_column_text,--wrap=sqlite3_busy_timeout,--wrap=sqlite3_step,--wrap=sqlite3_sleep)
cbae_add_test(test_sha256 unit/test_sha256.c)
cbae_add_test(test_file_io unit/test_file_io.c)
cbae_add_test(test_error           unit/test_error.c)
cbae_add_test(test_config          unit/test_config.c)
target_compile_definitions(test_config PRIVATE CBAE_SHIPPED_CONFIG="${CMAKE_SOURCE_DIR}/config/cbae.conf")

# ── Phase 2 — Binary Loaders ──────────────────────────────────────────────
cbae_add_test(test_pe_loader       unit/test_pe_loader.c  cbae_loader)
target_link_options(test_pe_loader PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
cbae_add_test(test_pe_hostile       unit/test_pe_hostile.c cbae_loader)
cbae_add_test(test_elf_hostile      unit/test_elf_hostile.c cbae_loader)
cbae_add_test(test_elf_loader      unit/test_elf_loader.c cbae_loader)
target_link_options(test_elf_loader PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
cbae_add_test(test_elf_real        unit/test_elf_real.c   cbae_loader)
target_compile_definitions(test_elf_real PRIVATE CBAE_ELF_FIXTURES="${CMAKE_SOURCE_DIR}/tests/fixtures/elf")
cbae_add_test(test_pe_boundaries   unit/test_pe_boundaries.c cbae_loader)
cbae_add_test(test_pe_real         unit/test_pe_real.c    cbae_loader)
target_link_options(test_pe_real PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
target_compile_definitions(test_pe_real PRIVATE CBAE_PE_FIXTURES="${CMAKE_SOURCE_DIR}/tests/fixtures/pe")

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
cbae_add_test(test_cir_verifier      unit/test_cir_verifier.c      cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_cir_serializer    unit/test_cir_serializer.c    cbae_cir cbae_disasm cbae_loader)
# the serializer and builder tests make the allocator fail on demand and measure the largest request (tests/unit/alloc_inject.h)
target_link_options(test_cir_serializer PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
cbae_add_test(test_cir_builder_hostile unit/test_cir_builder_hostile.c cbae_cir cbae_disasm cbae_loader)
target_link_options(test_cir_builder_hostile PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)

# ── Phase 5 — Dataflow Infrastructure ─────────────────────────────────────
cbae_add_test(test_dominator_tree    unit/test_dominator_tree.c    cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_post_dominator_tree unit/test_post_dominator_tree.c cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_dataflow_engine   unit/test_dataflow_engine.c   cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_use_def           unit/test_use_def.c           cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_alias_analysis    unit/test_alias_analysis.c    cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_alias_soundness   unit/test_alias_soundness.c   cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_reaching_stores   unit/test_reaching_stores.c   cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_reaching_soundness unit/test_reaching_soundness.c cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_const_prop         unit/test_const_prop.c         cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_const_prop_soundness unit/test_const_prop_soundness.c cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_ssa_verifier      unit/test_ssa_verifier.c      cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_compiled_code      unit/test_compiled_code.c     cbae_dataflow cbae_cir cbae_disasm cbae_loader)
cbae_add_test(test_dominance_oom      unit/test_dominance_oom.c     cbae_dataflow cbae_cir cbae_disasm cbae_loader)
# the dominance tests fail every allocation the dominator, post-dominator, frontier and SSA verifier code makes, in turn (tests/unit/alloc_inject.h)
target_link_options(test_dominance_oom PRIVATE -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free)
cbae_add_test(test_dominance_contracts unit/test_dominance_contracts.c cbae_dataflow cbae_cir cbae_disasm cbae_loader)
# dom_core.h is an internal header; this test exercises the numbering of the dominator tree directly (as test_graph_scc does for the SCCs).
target_include_directories(test_dominance_contracts PRIVATE ${CMAKE_SOURCE_DIR}/src/dataflow)
cbae_add_test(test_graph_scc         unit/test_graph_scc.c         cbae_dataflow cbae_cir cbae_disasm cbae_loader)
# graph_scc / dom_core are internal headers; this test exercises them directly.
target_include_directories(test_graph_scc PRIVATE ${CMAKE_SOURCE_DIR}/src/dataflow)
