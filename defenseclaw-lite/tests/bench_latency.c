/*
 * Performance benchmark for DefenseClaw Lite.
 * Measures local decision latency on target hardware.
 *
 * Targets (REQ-47, REQ-48, REQ-50):
 *   - Local policy table decision: <5μs
 *   - Verdict cache hit: <10μs
 *   - Cloud verdict RTT: <500ms P95
 *   - Throughput: 100K decisions/s
 */

#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ITERATIONS 100000

static uint64_t clock_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void bench_local_decision(void) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, "test-tool", DCLAW_TOOL_NAME_MAX - 1);
    memset(req.tool_hash, 0x42, 32);
    req.cap_flags = DCLAW_CAP_READ_FS;
    req.session_id = 1;

    uint64_t start = clock_ns();
    for (int i = 0; i < ITERATIONS; i++) {
        dclaw_evaluate(&req);
    }
    uint64_t elapsed = clock_ns() - start;

    double avg_ns = (double)elapsed / ITERATIONS;
    double avg_us = avg_ns / 1000.0;
    double throughput = 1e9 / avg_ns;

    printf("  Local decision (cache miss, speculative):\n");
    printf("    Average: %.1f ns (%.2f μs)\n", avg_ns, avg_us);
    printf("    Throughput: %.0f decisions/sec\n", throughput);
    printf("    Target: <5μs → %s\n", avg_us < 5.0 ? "PASS" : "FAIL");
    printf("    Target: >100K/s → %s\n", throughput > 100000 ? "PASS" : "FAIL");
}

static void bench_cache_hit(void) {
    /* Pre-populate cache */
    extern void dclaw_cache_store(const uint8_t *tool_hash, dclaw_action_t action,
                                  dclaw_severity_t severity);
    extern dclaw_state_t *dclaw_get_state(void);

    dclaw_state_t *s = dclaw_get_state();
    s->clock.time_trusted = true;

    uint8_t hash[32];
    memset(hash, 0x42, 32);
    dclaw_cache_store(hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO);

    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, "cached-tool", DCLAW_TOOL_NAME_MAX - 1);
    memcpy(req.tool_hash, hash, 32);
    req.cap_flags = DCLAW_CAP_READ_FS;
    req.session_id = 2;

    uint64_t start = clock_ns();
    for (int i = 0; i < ITERATIONS; i++) {
        dclaw_evaluate(&req);
    }
    uint64_t elapsed = clock_ns() - start;

    double avg_ns = (double)elapsed / ITERATIONS;
    double avg_us = avg_ns / 1000.0;

    printf("  Cache hit decision:\n");
    printf("    Average: %.1f ns (%.2f μs)\n", avg_ns, avg_us);
    printf("    Target: <10μs → %s\n", avg_us < 10.0 ? "PASS" : "FAIL");
}

static void bench_sequence_check(void) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, "seq-test", DCLAW_TOOL_NAME_MAX - 1);
    memset(req.tool_hash, 0x99, 32);
    req.cap_flags = DCLAW_CAP_NET_FETCH;

    uint64_t start = clock_ns();
    for (int i = 0; i < ITERATIONS; i++) {
        req.session_id = (uint16_t)(i % DCLAW_MAX_SESSIONS);
        dclaw_evaluate(&req);
    }
    uint64_t elapsed = clock_ns() - start;

    double avg_ns = (double)elapsed / ITERATIONS;
    printf("  Sequence correlator (with session tracking):\n");
    printf("    Average: %.1f ns (%.2f μs)\n", avg_ns, avg_ns / 1000.0);
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    dclaw_init(&info);

    printf("DefenseClaw Lite Performance Benchmark\n");
    printf("  Iterations: %d\n\n", ITERATIONS);

    bench_local_decision();
    printf("\n");
    bench_cache_hit();
    printf("\n");
    bench_sequence_check();
    printf("\n");

    dclaw_shutdown();
    return 0;
}
