# Unit tests for defenseclaw-lite
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

add_executable(test_verdict_cache test_verdict_cache.c)
target_link_libraries(test_verdict_cache PRIVATE dclaw_core)
add_test(NAME verdict_cache COMMAND test_verdict_cache)

add_executable(test_evaluate_pipeline test_evaluate_pipeline.c)
target_link_libraries(test_evaluate_pipeline PRIVATE dclaw_core)
add_test(NAME evaluate_pipeline COMMAND test_evaluate_pipeline)

add_executable(test_verdict_protocol test_verdict_protocol.c)
target_link_libraries(test_verdict_protocol PRIVATE dclaw_core)
add_test(NAME verdict_protocol COMMAND test_verdict_protocol)

add_executable(test_ota_emergency test_ota_emergency.c)
target_link_libraries(test_ota_emergency PRIVATE dclaw_core)
add_test(NAME ota_emergency COMMAND test_ota_emergency)

add_executable(test_acceptance test_acceptance.c)
target_link_libraries(test_acceptance PRIVATE dclaw_core)
add_test(NAME acceptance COMMAND test_acceptance)

add_executable(bench_latency bench_latency.c)
target_link_libraries(bench_latency PRIVATE dclaw_core)
