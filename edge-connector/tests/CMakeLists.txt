# Unit tests for edge-connector
# Uses a simple test framework (no external deps)

# P2-22 fix: Collect all test targets so we can apply common definitions.
# In Release builds, CMake adds -DNDEBUG which compiles out assert().
# We undefine NDEBUG for test targets so that asserts remain active
# regardless of build type.
# P2-17: Removed DCLAW_TESTING=1 — no source file references it.
set(DCLAW_TEST_TARGETS "")

add_executable(test_input_validation test_input_validation.c)
target_link_libraries(test_input_validation PRIVATE dclaw_core)
add_test(NAME input_validation COMMAND test_input_validation)
list(APPEND DCLAW_TEST_TARGETS test_input_validation)

add_executable(test_policy_table test_policy_table.c)
target_link_libraries(test_policy_table PRIVATE dclaw_core)
add_test(NAME policy_table COMMAND test_policy_table)
list(APPEND DCLAW_TEST_TARGETS test_policy_table)

add_executable(test_correlator test_correlator.c)
target_link_libraries(test_correlator PRIVATE dclaw_core)
add_test(NAME correlator COMMAND test_correlator)
list(APPEND DCLAW_TEST_TARGETS test_correlator)

add_executable(test_audit_ring test_audit_ring.c)
target_link_libraries(test_audit_ring PRIVATE dclaw_core)
add_test(NAME audit_ring COMMAND test_audit_ring)
list(APPEND DCLAW_TEST_TARGETS test_audit_ring)

add_executable(test_rate_limiter test_rate_limiter.c)
target_link_libraries(test_rate_limiter PRIVATE dclaw_core)
add_test(NAME rate_limiter COMMAND test_rate_limiter)
list(APPEND DCLAW_TEST_TARGETS test_rate_limiter)

if(DCLAW_VERDICT_CACHE_SIZE GREATER 0)
    add_executable(test_verdict_cache test_verdict_cache.c)
    target_link_libraries(test_verdict_cache PRIVATE dclaw_core)
    add_test(NAME verdict_cache COMMAND test_verdict_cache)
    list(APPEND DCLAW_TEST_TARGETS test_verdict_cache)
endif()

add_executable(test_evaluate_pipeline test_evaluate_pipeline.c)
target_link_libraries(test_evaluate_pipeline PRIVATE dclaw_core)
add_test(NAME evaluate_pipeline COMMAND test_evaluate_pipeline)
list(APPEND DCLAW_TEST_TARGETS test_evaluate_pipeline)

if(DCLAW_MQTT_ENABLED)
    add_executable(test_verdict_protocol test_verdict_protocol.c)
    target_link_libraries(test_verdict_protocol PRIVATE dclaw_core)
    add_test(NAME verdict_protocol COMMAND test_verdict_protocol)
    list(APPEND DCLAW_TEST_TARGETS test_verdict_protocol)

    add_executable(test_ota_emergency test_ota_emergency.c)
    target_link_libraries(test_ota_emergency PRIVATE dclaw_core)
    add_test(NAME ota_emergency COMMAND test_ota_emergency)
    list(APPEND DCLAW_TEST_TARGETS test_ota_emergency)
    # P1-09: Give each test its own flash file so persisted emergency state
    # from one test does not leak into another.
    set_tests_properties(ota_emergency PROPERTIES
        ENVIRONMENT "DCLAW_FLASH_PATH=${CMAKE_CURRENT_BINARY_DIR}/flash-ota-emergency.bin")
endif()

if(DCLAW_CONTENT_SCAN AND DCLAW_MQTT_ENABLED)
    add_executable(test_acceptance test_acceptance.c)
    target_link_libraries(test_acceptance PRIVATE dclaw_core)
    add_test(NAME acceptance COMMAND test_acceptance)
    list(APPEND DCLAW_TEST_TARGETS test_acceptance)
    set_tests_properties(acceptance PROPERTIES
        ENVIRONMENT "DCLAW_FLASH_PATH=${CMAKE_CURRENT_BINARY_DIR}/flash-acceptance.bin")
endif()

add_executable(bench_latency bench_latency.c)
target_link_libraries(bench_latency PRIVATE dclaw_core)

if(DCLAW_CONTENT_SCAN)
    add_executable(test_content_scanner test_content_scanner.c)
    target_link_libraries(test_content_scanner PRIVATE dclaw_core)
    add_test(NAME content_scanner COMMAND test_content_scanner)
    list(APPEND DCLAW_TEST_TARGETS test_content_scanner)
endif()

# P2-22 fix: Ensure asserts are active in all test targets even in Release
# builds. -UNDEBUG removes the NDEBUG that CMake adds for Release/RelWithDebInfo.
# Also set DCLAW_FLASH_PATH for all tests so they work even when the default
# /var/lib/defenseclaw/ directory does not exist.
foreach(_tgt IN LISTS DCLAW_TEST_TARGETS)
    target_compile_options(${_tgt} PRIVATE -UNDEBUG)
endforeach()

# Set default flash path for tests that don't already have ENVIRONMENT set.
# Tests with explicit flash paths (ota_emergency, acceptance) keep their own.
get_property(_all_tests DIRECTORY PROPERTY TESTS)
foreach(_test IN LISTS _all_tests)
    get_test_property(${_test} ENVIRONMENT _env)
    if(NOT _env)
        set_tests_properties(${_test} PROPERTIES
            ENVIRONMENT "DCLAW_FLASH_PATH=${CMAKE_CURRENT_BINARY_DIR}/flash-${_test}.bin")
    endif()
endforeach()

# Fuzz harness (requires sanitizer support for libFuzzer)
if(DCLAW_SANITIZE)
    add_executable(fuzz_ipc_parser fuzz_ipc_parser.c)
    target_link_libraries(fuzz_ipc_parser dclaw_core)
    target_compile_options(fuzz_ipc_parser PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_ipc_parser PRIVATE -fsanitize=fuzzer)
endif()
