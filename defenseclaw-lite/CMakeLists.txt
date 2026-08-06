cmake_minimum_required(VERSION 3.22)
project(defenseclaw-lite C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Profile selection (maps to Kconfig)
set(DCLAW_PROFILE "STANDARD" CACHE STRING "Agent profile: MINIMAL, STANDARD, EDGE")
set_property(CACHE DCLAW_PROFILE PROPERTY STRINGS MINIMAL STANDARD EDGE)

# Profile-dependent defaults
if(DCLAW_PROFILE STREQUAL "MINIMAL")
    set(DCLAW_AUDIT_RING_SIZE 64)
    set(DCLAW_VERDICT_CACHE_SIZE 0)
    set(DCLAW_HEARTBEAT_INTERVAL_SEC 0)
    set(DCLAW_MQTT_ENABLED OFF)
    set(DCLAW_PII_REDACTION OFF)
    set(DCLAW_BLOOM_FILTER OFF)
    set(DCLAW_SPECULATIVE_EXECUTION OFF)
    set(DCLAW_AUDIT_RAM_BUFFER_SIZE 4)
    set(DCLAW_CANARY_WINDOW_SEC 0)
    set(DCLAW_BROKER_FALLBACK_LIST_SIZE 1)
    set(DCLAW_MAX_SESSIONS 4)
elseif(DCLAW_PROFILE STREQUAL "STANDARD")
    set(DCLAW_AUDIT_RING_SIZE 256)
    set(DCLAW_VERDICT_CACHE_SIZE 64)
    set(DCLAW_HEARTBEAT_INTERVAL_SEC 30)
    set(DCLAW_MQTT_ENABLED ON)
    set(DCLAW_PII_REDACTION ON)
    set(DCLAW_BLOOM_FILTER OFF)
    set(DCLAW_SPECULATIVE_EXECUTION ON)
    set(DCLAW_AUDIT_RAM_BUFFER_SIZE 16)
    set(DCLAW_CANARY_WINDOW_SEC 600)
    set(DCLAW_BROKER_FALLBACK_LIST_SIZE 3)
    set(DCLAW_MAX_SESSIONS 16)
elseif(DCLAW_PROFILE STREQUAL "EDGE")
    set(DCLAW_AUDIT_RING_SIZE 1024)
    set(DCLAW_VERDICT_CACHE_SIZE 256)
    set(DCLAW_HEARTBEAT_INTERVAL_SEC 10)
    set(DCLAW_MQTT_ENABLED ON)
    set(DCLAW_PII_REDACTION ON)
    set(DCLAW_BLOOM_FILTER ON)
    set(DCLAW_SPECULATIVE_EXECUTION ON)
    set(DCLAW_AUDIT_RAM_BUFFER_SIZE 32)
    set(DCLAW_CANARY_WINDOW_SEC 600)
    set(DCLAW_BROKER_FALLBACK_LIST_SIZE 3)
    set(DCLAW_MAX_SESSIONS 64)
endif()

# Generate config.h from profile settings
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/config.h
    @ONLY
)

# Compiler flags
add_compile_options(
    -Wall -Wextra -Werror
    -fstack-protector-strong
    -fno-strict-aliasing
    -Os
)

# Sources common to all profiles
set(CORE_SOURCES
    src/dclaw_core.c
    src/decision/policy_table.c
    src/decision/correlator.c
    src/decision/verdict_cache.c
    src/enforce/ipc_hook.c
    src/enforce/ipc_json.c
    src/enforce/rate_limiter.c
    src/persist/audit_ring.c
    src/persist/flash_safe.c
    src/persist/config_store.c
    src/platform/hal_linux.c
)

# Sources only for profiles with MQTT
if(DCLAW_MQTT_ENABLED)
    list(APPEND CORE_SOURCES
        src/comms/mqtt_client.c
        src/comms/tls_engine.c
        src/comms/cbor_codec.c
        src/comms/verdict_protocol.c
        src/comms/ota_receiver.c
    )
endif()

# Main library (static)
add_library(dclaw_core STATIC ${CORE_SOURCES})
target_include_directories(dclaw_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/generated
)

# Link mbedTLS for STANDARD/EDGE profiles
if(DCLAW_MQTT_ENABLED)
    find_package(MbedTLS QUIET)
    if(MbedTLS_FOUND)
        target_link_libraries(dclaw_core PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto)
        target_compile_definitions(dclaw_core PRIVATE DCLAW_HAS_MBEDTLS=1)
    else()
        find_library(MBEDTLS_LIB mbedtls)
        if(MBEDTLS_LIB)
            target_link_libraries(dclaw_core PRIVATE mbedtls mbedcrypto mbedx509)
            target_compile_definitions(dclaw_core PRIVATE DCLAW_HAS_MBEDTLS=1)
        else()
            message(WARNING "mbedTLS not found — TLS/MQTT stubs will be used (dev mode)")
            target_compile_definitions(dclaw_core PRIVATE DCLAW_HAS_MBEDTLS=0)
        endif()
    endif()
endif()

# Main executable
add_executable(defenseclaw-lite src/main.c)
target_link_libraries(defenseclaw-lite PRIVATE dclaw_core)

# Tests
option(DCLAW_BUILD_TESTS "Build unit tests" ON)
if(DCLAW_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Print build summary
message(STATUS "DefenseClaw Lite Configuration:")
message(STATUS "  Profile:          ${DCLAW_PROFILE}")
message(STATUS "  Audit ring:       ${DCLAW_AUDIT_RING_SIZE} entries")
message(STATUS "  Verdict cache:    ${DCLAW_VERDICT_CACHE_SIZE} entries")
message(STATUS "  Sessions:         ${DCLAW_MAX_SESSIONS}")
message(STATUS "  MQTT:             ${DCLAW_MQTT_ENABLED}")
message(STATUS "  Speculative exec: ${DCLAW_SPECULATIVE_EXECUTION}")
message(STATUS "  Canary window:    ${DCLAW_CANARY_WINDOW_SEC}s")
