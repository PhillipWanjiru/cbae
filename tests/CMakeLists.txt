cmake_minimum_required(VERSION 3.20)

function(cbae_add_test name src)
    add_executable(${name} ${CMAKE_CURRENT_SOURCE_DIR}/${src})
    target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
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
