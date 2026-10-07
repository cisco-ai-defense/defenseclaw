# Unit tests for edge-connector
# Uses a simple test framework (no external deps)

add_executable(test_input_validation test_input_validation.c)
target_link_libraries(test_input_validation PRIVATE dclaw_core)
add_test(NAME input_validation COMMAND test_input_validation)

add_executable(test_policy_table test_policy_table.c)
target_link_libraries(test_policy_table PRIVATE dclaw_core)
add_test(NAME policy_table COMMAND test_policy_table)

add_executable(test_correlator test_correlator.c)
target_link_libraries(test_correlator PRIVATE dclaw_core)
add_test(NAME correlator COMMAND test_correlator)

add_executable(test_audit_ring test_audit_ring.c)
target_link_libraries(test_audit_ring PRIVATE dclaw_core)
add_test(NAME audit_ring COMMAND test_audit_ring)

add_executable(test_rate_limiter test_rate_limiter.c)
target_link_libraries(test_rate_limiter PRIVATE dclaw_core)
add_test(NAME rate_limiter COMMAND test_rate_limiter)

if(DCLAW_VERDICT_CACHE_SIZE GREATER 0)
    add_executable(test_verdict_cache test_verdict_cache.c)
    target_link_libraries(test_verdict_cache PRIVATE dclaw_core)
    add_test(NAME verdict_cache COMMAND test_verdict_cache)
endif()

add_executable(test_evaluate_pipeline test_evaluate_pipeline.c)
target_link_libraries(test_evaluate_pipeline PRIVATE dclaw_core)
add_test(NAME evaluate_pipeline COMMAND test_evaluate_pipeline)

if(DCLAW_MQTT_ENABLED)
    add_executable(test_verdict_protocol test_verdict_protocol.c)
    target_link_libraries(test_verdict_protocol PRIVATE dclaw_core)
    add_test(NAME verdict_protocol COMMAND test_verdict_protocol)

    add_executable(test_ota_emergency test_ota_emergency.c)
    target_link_libraries(test_ota_emergency PRIVATE dclaw_core)
    add_test(NAME ota_emergency COMMAND test_ota_emergency)
    # P1-09: Give each test its own flash file so persisted emergency state
    # from one test does not leak into another.
    set_tests_properties(ota_emergency PROPERTIES
        ENVIRONMENT "DCLAW_FLASH_PATH=${CMAKE_CURRENT_BINARY_DIR}/flash-ota-emergency.bin")
endif()

if(DCLAW_CONTENT_SCAN AND DCLAW_MQTT_ENABLED)
    add_executable(test_acceptance test_acceptance.c)
    target_link_libraries(test_acceptance PRIVATE dclaw_core)
    add_test(NAME acceptance COMMAND test_acceptance)
    set_tests_properties(acceptance PROPERTIES
        ENVIRONMENT "DCLAW_FLASH_PATH=${CMAKE_CURRENT_BINARY_DIR}/flash-acceptance.bin")
endif()

add_executable(bench_latency bench_latency.c)
target_link_libraries(bench_latency PRIVATE dclaw_core)

if(DCLAW_CONTENT_SCAN)
    add_executable(test_content_scanner test_content_scanner.c)
    target_link_libraries(test_content_scanner PRIVATE dclaw_core)
    add_test(NAME content_scanner COMMAND test_content_scanner)
endif()

# Fuzz harness (requires sanitizer support for libFuzzer)
if(DCLAW_SANITIZE)
    add_executable(fuzz_ipc_parser fuzz_ipc_parser.c)
    target_link_libraries(fuzz_ipc_parser dclaw_core)
    target_compile_options(fuzz_ipc_parser PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_ipc_parser PRIVATE -fsanitize=fuzzer)
endif()
