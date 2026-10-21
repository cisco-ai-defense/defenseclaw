# Unit tests for edge-connector
# Uses a simple test framework (no external deps)

# P2-22 fix: Collect all test targets so we can apply common definitions.
# In Release builds, CMake adds -DNDEBUG which compiles out assert().
# We undefine NDEBUG for test targets so that asserts remain active
# regardless of build type.
# P2-17: Removed DCLAW_TESTING=1 — no source file references it.
set(DCLAW_TEST_TARGETS "")

# Production permits flash only in its provisioned state directories. CI must
# create/chown this directory before running production tests; development
# tests can keep their fixtures inside the build tree.
set(DCLAW_TEST_FLASH_DIR "" CACHE PATH "Writable flash fixture directory for CTests")
if(NOT DCLAW_TEST_FLASH_DIR)
    if(DCLAW_DEV_MODE)
        set(DCLAW_TEST_FLASH_DIR "${CMAKE_CURRENT_BINARY_DIR}")
    else()
        set(DCLAW_TEST_FLASH_DIR "/var/lib/defenseclaw/ctest")
    endif()
endif()
if(NOT DCLAW_DEV_MODE AND
   NOT DCLAW_TEST_FLASH_DIR MATCHES "^(/var/lib/defenseclaw|/etc/defenseclaw)/")
    message(FATAL_ERROR "Production CTests require DCLAW_TEST_FLASH_DIR under /var/lib/defenseclaw/ or /etc/defenseclaw/")
endif()

add_executable(test_input_validation test_input_validation.c)
target_link_libraries(test_input_validation PRIVATE dclaw_core)
add_test(NAME input_validation COMMAND test_input_validation)
list(APPEND DCLAW_TEST_TARGETS test_input_validation)

add_executable(test_hal_linux test_hal_linux.c)
target_link_libraries(test_hal_linux PRIVATE dclaw_core)
add_test(NAME hal_linux COMMAND test_hal_linux)
list(APPEND DCLAW_TEST_TARGETS test_hal_linux)

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

add_executable(test_deferred_reply test_deferred_reply.c)
target_link_libraries(test_deferred_reply PRIVATE dclaw_core)
add_test(NAME deferred_reply COMMAND test_deferred_reply)
list(APPEND DCLAW_TEST_TARGETS test_deferred_reply)
set_tests_properties(deferred_reply PROPERTIES
    ENVIRONMENT "DCLAW_FLASH_PATH=${DCLAW_TEST_FLASH_DIR}/flash-deferred.bin")

add_executable(test_evaluate_pipeline test_evaluate_pipeline.c)
target_link_libraries(test_evaluate_pipeline PRIVATE dclaw_core)
add_test(NAME evaluate_pipeline COMMAND test_evaluate_pipeline)
list(APPEND DCLAW_TEST_TARGETS test_evaluate_pipeline)

if(DCLAW_MQTT_ENABLED)
    add_executable(test_mqtt_ack test_mqtt_ack.c)
    target_link_libraries(test_mqtt_ack PRIVATE dclaw_core)
    target_include_directories(test_mqtt_ack PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/paho-embedded
        ${CMAKE_SOURCE_DIR}/third_party/paho-embedded/MQTTClient-C
        ${CMAKE_SOURCE_DIR}/third_party/paho-embedded/MQTTPacket)
    target_compile_definitions(test_mqtt_ack PRIVATE
        MQTTCLIENT_PLATFORM_HEADER=MQTTDclaw.h)
    add_test(NAME mqtt_ack COMMAND test_mqtt_ack)

    add_executable(test_mqtt_publish_nowait test_mqtt_publish_nowait.c)
    target_link_libraries(test_mqtt_publish_nowait PRIVATE dclaw_core)
    target_include_directories(test_mqtt_publish_nowait PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/paho-embedded
        ${CMAKE_SOURCE_DIR}/third_party/paho-embedded/MQTTClient-C
        ${CMAKE_SOURCE_DIR}/third_party/paho-embedded/MQTTPacket)
    target_compile_definitions(test_mqtt_publish_nowait PRIVATE
        MQTTCLIENT_PLATFORM_HEADER=MQTTDclaw.h)
    add_test(NAME mqtt_publish_nowait COMMAND test_mqtt_publish_nowait)

    add_executable(test_mqtt_publish_bounds test_mqtt_publish_bounds.c)
    target_link_libraries(test_mqtt_publish_bounds PRIVATE dclaw_core)
    target_include_directories(test_mqtt_publish_bounds PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/paho-embedded
        ${CMAKE_SOURCE_DIR}/third_party/paho-embedded/MQTTClient-C
        ${CMAKE_SOURCE_DIR}/third_party/paho-embedded/MQTTPacket)
    target_compile_definitions(test_mqtt_publish_bounds PRIVATE
        MQTTCLIENT_PLATFORM_HEADER=MQTTDclaw.h)
    add_test(NAME mqtt_publish_bounds COMMAND test_mqtt_publish_bounds)
    list(APPEND DCLAW_TEST_TARGETS test_mqtt_publish_bounds)
    list(APPEND DCLAW_TEST_TARGETS test_mqtt_publish_nowait)
    list(APPEND DCLAW_TEST_TARGETS test_mqtt_ack)

    # Needs a real TLS stack (it runs an in-process mbedTLS server).
    if(DCLAW_HAS_USABLE_MBEDTLS)
        find_package(Threads REQUIRED)
        add_executable(test_tls_timeouts test_tls_timeouts.c)
        if(TARGET MbedTLS::mbedtls)
            target_link_libraries(test_tls_timeouts PRIVATE dclaw_core
                MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto Threads::Threads)
        else()
            target_include_directories(test_tls_timeouts PRIVATE ${_MBEDTLS_PREFIX}/include)
            target_link_directories(test_tls_timeouts PRIVATE ${_MBEDTLS_LIBDIR})
            target_link_libraries(test_tls_timeouts PRIVATE dclaw_core
                mbedtls mbedx509 mbedcrypto Threads::Threads)
        endif()
        add_test(NAME tls_timeouts COMMAND test_tls_timeouts)
        set_tests_properties(tls_timeouts PROPERTIES TIMEOUT 30)
        list(APPEND DCLAW_TEST_TARGETS test_tls_timeouts)
    endif()

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
        ENVIRONMENT "DCLAW_FLASH_PATH=${DCLAW_TEST_FLASH_DIR}/flash-ota-emergency.bin")

    add_executable(test_canary_attribution test_canary_attribution.c)
    target_link_libraries(test_canary_attribution PRIVATE dclaw_core)
    add_test(NAME canary_attribution COMMAND test_canary_attribution)
    list(APPEND DCLAW_TEST_TARGETS test_canary_attribution)

    if(DCLAW_SPECULATIVE_EXECUTION)
        add_executable(test_speculative_revocation test_speculative_revocation.c)
        target_link_libraries(test_speculative_revocation PRIVATE dclaw_core)
        add_test(NAME speculative_revocation COMMAND test_speculative_revocation)
        list(APPEND DCLAW_TEST_TARGETS test_speculative_revocation)
        set_tests_properties(speculative_revocation PROPERTIES
            ENVIRONMENT "DCLAW_STRICT_MODE=0;DCLAW_FLASH_PATH=${DCLAW_TEST_FLASH_DIR}/flash-speculative.bin")
    endif()
endif()

if(DCLAW_CONTENT_SCAN AND DCLAW_MQTT_ENABLED)
    add_executable(test_acceptance test_acceptance.c)
    target_link_libraries(test_acceptance PRIVATE dclaw_core)
    add_test(NAME acceptance COMMAND test_acceptance)
    list(APPEND DCLAW_TEST_TARGETS test_acceptance)
    set_tests_properties(acceptance PROPERTIES
        ENVIRONMENT "DCLAW_FLASH_PATH=${DCLAW_TEST_FLASH_DIR}/flash-acceptance.bin")
endif()

add_executable(bench_latency bench_latency.c)
target_link_libraries(bench_latency PRIVATE dclaw_core)
# Smoke run: fails if any benchmark path stops producing its expected verdict.
add_test(NAME bench_latency_paths COMMAND bench_latency 1000)
set_tests_properties(bench_latency_paths PROPERTIES
    ENVIRONMENT "DCLAW_FLASH_PATH=${DCLAW_TEST_FLASH_DIR}/flash-bench.bin")

if(DCLAW_CONTENT_SCAN)
    add_executable(test_content_scanner test_content_scanner.c)
    target_link_libraries(test_content_scanner PRIVATE dclaw_core)
    add_test(NAME content_scanner COMMAND test_content_scanner)
    list(APPEND DCLAW_TEST_TARGETS test_content_scanner)
endif()

# P2-22 fix: Ensure asserts are active in all test targets even in Release
# builds. -UNDEBUG removes the NDEBUG that CMake adds for Release/RelWithDebInfo.
# Also set a unique DCLAW_FLASH_PATH for every test.
foreach(_tgt IN LISTS DCLAW_TEST_TARGETS)
    target_compile_options(${_tgt} PRIVATE -UNDEBUG)
endforeach()

# Set default flash path and test audit key for all tests.
# Tests with explicit flash paths (ota_emergency, acceptance) keep their own
# flash path but get the audit key appended.
# BLOCKER fix: STANDARD/EDGE profiles have DEV_MODE=OFF, so tests need a valid
# DCLAW_AUDIT_KEY (64 hex chars = 32 bytes) to initialise the audit ring.
set(_test_audit_key "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
get_property(_all_tests DIRECTORY PROPERTY TESTS)
foreach(_test IN LISTS _all_tests)
    get_test_property(${_test} ENVIRONMENT _env)
    if(NOT _env)
        set_tests_properties(${_test} PROPERTIES
            ENVIRONMENT "DCLAW_FLASH_PATH=${DCLAW_TEST_FLASH_DIR}/flash-${_test}.bin;DCLAW_AUDIT_KEY=${_test_audit_key};DCLAW_OTA_HMAC_KEY=${_test_audit_key};DCLAW_EMERGENCY_KEY=${_test_audit_key}")
    else()
        # Append audit key to existing ENVIRONMENT list
        set_tests_properties(${_test} PROPERTIES
            ENVIRONMENT "${_env};DCLAW_AUDIT_KEY=${_test_audit_key};DCLAW_OTA_HMAC_KEY=${_test_audit_key};DCLAW_EMERGENCY_KEY=${_test_audit_key}")
    endif()
endforeach()

# Hardening properties of the daemon binary (PIE, RELRO/now on ELF, stack
# protector, _FORTIFY_SOURCE outside sanitizer builds).
add_test(NAME hardening_flags
         COMMAND ${CMAKE_COMMAND} -DBIN=$<TARGET_FILE:edge-connector>
                 -DSANITIZE=${DCLAW_SANITIZE} -DSYSTEM=${CMAKE_SYSTEM_NAME}
                 -P ${CMAKE_CURRENT_SOURCE_DIR}/check_hardening.cmake)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME policy_compiler
             COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_policy_compiler.py")
    add_test(NAME adapter_capability_parity
             COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_adapter_capability_parity.py")
    add_test(NAME adapter_destinations
             COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/test_adapter_destinations.py")
endif()

# IPC parser fuzz target (LLVMFuzzerTestOneInput in fuzz_ipc_parser.c).
# The libFuzzer binary is built in sanitizer builds when the compiler ships
# the libFuzzer runtime (Apple's Xcode clang does not). The replay driver
# runs the same entry point over the seed corpus in every build.
add_executable(fuzz_ipc_parser_replay fuzz_ipc_parser.c fuzz_replay_main.c)
target_link_libraries(fuzz_ipc_parser_replay PRIVATE dclaw_core)
file(GLOB _ipc_corpus ${CMAKE_CURRENT_SOURCE_DIR}/fuzz_corpus/*)
add_test(NAME fuzz_ipc_corpus COMMAND fuzz_ipc_parser_replay ${_ipc_corpus})
set_tests_properties(fuzz_ipc_corpus PROPERTIES
    ENVIRONMENT "DCLAW_FLASH_PATH=${DCLAW_TEST_FLASH_DIR}/flash-fuzz-ipc.bin")

if(DCLAW_SANITIZE)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
    check_c_source_compiles([=[
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }
]=] DCLAW_HAVE_LIBFUZZER)
    unset(CMAKE_REQUIRED_FLAGS)
    if(DCLAW_HAVE_LIBFUZZER)
        add_executable(fuzz_ipc_parser fuzz_ipc_parser.c)
        target_link_libraries(fuzz_ipc_parser PRIVATE dclaw_core)
        target_compile_options(fuzz_ipc_parser PRIVATE -fsanitize=fuzzer)
        target_link_options(fuzz_ipc_parser PRIVATE -fsanitize=fuzzer)
    else()
        message(STATUS "libFuzzer runtime not available: fuzz_ipc_parser not built "
                       "(fuzz_ipc_parser_replay still covers the corpus)")
    endif()
endif()
