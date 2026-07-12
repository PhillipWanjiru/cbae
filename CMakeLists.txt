cmake_minimum_required(VERSION 3.20)
project(cbae VERSION 0.2.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter -fno-strict-aliasing)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g3 -O0 -DCBAE_DEBUG=1)
else()
    add_compile_options(-O2 -DNDEBUG)
endif()

find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include ${SQLite3_INCLUDE_DIRS})

# ── LAYER 1: cbae_platform ────────────────────────────────────────────────────
# cbae_error.c lives here — it has no dependencies and is called by every layer.
add_library(cbae_platform STATIC
    src/engine/cbae_error.c
    src/platform/memory_arena.c
    src/platform/hashmap.c
    src/platform/vector.c
    src/platform/string_pool.c
    src/platform/logging.c
    src/platform/file_io.c
    src/platform/thread_pool.c
    src/platform/platform_linux.c
)
target_link_libraries(cbae_platform PUBLIC Threads::Threads)

# ── LAYER 2: cbae_db ──────────────────────────────────────────────────────────
add_library(cbae_db STATIC
    src/db/db_connection.c
    src/db/db_schema.c
    src/db/db_query_helpers.c
    src/db/db_transaction.c
    src/db/db_migration_001.c
    src/db/db_migration_002.c
)
target_link_libraries(cbae_db PUBLIC ${SQLite3_LIBRARIES} cbae_platform)

# ── LAYER 3: cbae_engine ──────────────────────────────────────────────────────
add_library(cbae_engine STATIC
    src/engine/cbae_engine.c
    src/engine/cbae_config.c
)
target_link_libraries(cbae_engine PUBLIC cbae_platform cbae_db)

# ── LAYER 4: cbae_loader (Phase 2) ───────────────────────────────────────────
add_library(cbae_loader STATIC
    src/loader/binary_image.c
    src/loader/pe_loader.c
    src/loader/elf_loader.c
)
target_link_libraries(cbae_loader PUBLIC cbae_platform)

# ── Rust integration (optional — requires cargo in PATH) ─────────────────────
# The Rust crates produce static libraries that extend the C engine.
# cbae_batchd replaces src/batch/*.c with memory-safe Rust.
# cbae_ipc    provides the typed IPC message layer with Rust's safety guarantees.
#
# To build Rust: cmake -DWITH_RUST=ON ..
option(WITH_RUST "Build Rust crates (requires cargo)" OFF)

if(WITH_RUST)
    find_program(CARGO_EXE cargo)
    if(CARGO_EXE)
        set(RUST_TARGET_DIR ${CMAKE_BINARY_DIR}/rust_target)

        add_custom_target(rust_crates ALL
            COMMAND ${CARGO_EXE} build
                --manifest-path ${CMAKE_SOURCE_DIR}/rust/Cargo.toml
                --target-dir    ${RUST_TARGET_DIR}
                $<$<NOT:$<CONFIG:Debug>>:--release>
            COMMENT "Building Rust crates (cbae_batchd, cbae_ipc)"
        )

        set(RUST_LIB_DIR ${RUST_TARGET_DIR}/debug)
        if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
            set(RUST_LIB_DIR ${RUST_TARGET_DIR}/release)
        endif()

        add_library(cbae_batchd_rs STATIC IMPORTED)
        set_target_properties(cbae_batchd_rs PROPERTIES
            IMPORTED_LOCATION ${RUST_LIB_DIR}/libcbae_batchd.a)
        add_dependencies(cbae_batchd_rs rust_crates)

        add_library(cbae_ipc_rs STATIC IMPORTED)
        set_target_properties(cbae_ipc_rs PROPERTIES
            IMPORTED_LOCATION ${RUST_LIB_DIR}/libcbae_ipc.a)
        add_dependencies(cbae_ipc_rs rust_crates)

        target_link_libraries(cbae_engine PUBLIC cbae_batchd_rs cbae_ipc_rs)
        message(STATUS "Rust crates enabled: cbae_batchd, cbae_ipc")
    else()
        message(WARNING "WITH_RUST=ON but cargo not found — skipping Rust build")
    endif()
endif()

enable_testing()
add_subdirectory(tests)

message(STATUS "CBAE ${PROJECT_VERSION} — build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  SQLite3: ${SQLite3_LIBRARIES}")
message(STATUS "  Layers:  platform -> db -> engine -> loader")
message(STATUS "  Rust:    ${WITH_RUST} (cmake -DWITH_RUST=ON .. to enable)")
