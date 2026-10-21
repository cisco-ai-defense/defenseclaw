/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Per-path latency benchmark for dclaw_evaluate().
 *
 * Each path drives a specific exit of the decision pipeline using tool
 * names from the trusted capability table, and every iteration checks the
 * verdict: a path that does not produce its expected action and reason
 * fails the run instead of silently timing a different exit.
 *
 * Rate-limiter buckets and the per-second IPC flood window are reset outside
 * the timed region so the loop measures the path itself (both checks still
 * run on every call). Throughput through dclaw_evaluate is capped at
 * DCLAW_IPC_RATE_LIMIT_PER_SEC by design and is not reported here.
 * Cloud verdicts are delivered in-process; network RTT is out of scope.
 *
 * Usage: bench_latency [iterations] [--json PATH]
 */

#include "defenseclaw.h"
#include "platform.h"
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern dclaw_state_t *dclaw_get_state(void);
extern void dclaw_ipc_rate_limit_reset(void);
extern void dclaw_cache_store_with_ttl(const uint8_t *tool_hash, dclaw_action_t action,
                                       dclaw_severity_t severity, uint16_t ttl_minutes);
#if DCLAW_MQTT_ENABLED
extern int dclaw_mqtt_init(void);
extern int dclaw_mqtt_connect(void);
extern int dclaw_verdict_handle_response(const uint8_t *resp_buf, size_t resp_len,
                                         const uint8_t *pending_tool_hash);
extern void dclaw_verdict_compute_expected_hmac(uint16_t request_id, uint8_t action,
                                                uint8_t severity, uint16_t ttl,
                                                uint8_t reason, uint8_t flags,
                                                uint32_t server_ts,
                                                const uint8_t *tool_hash,
                                                const uint8_t *request_nonce,
                                                uint8_t *out_hmac_32bytes);
extern void dclaw_verdict_set_device_key(const uint8_t *key, size_t key_len);
#endif

#define DEFAULT_ITERATIONS 20000

#if DCLAW_MQTT_ENABLED
/* The speculative path requires a request the transport accepted; the
 * benchmark measures local cost only, so the send itself is not timed. */
static int bench_send_ok(const dclaw_tool_request_t *req, uint16_t request_id) {
    (void)req; (void)request_id;
    return 0;
}
#endif
#define WARMUP_ITERATIONS  200
#define MAX_RESULTS        16
#define REASON_ANY         0xFF

typedef struct {
    const char *name;
    double p50_ns, p99_ns, p999_ns, max_ns, mean_ns;
    double flash_writes_per_call, flash_bytes_per_call, flash_syncs_per_call;
} result_t;

static result_t g_results[MAX_RESULTS];
static int g_result_count;
static int g_iterations = DEFAULT_ITERATIONS;
static uint32_t *g_samples;
static int g_failures;

static uint64_t clock_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

static void refill_rate_limiters(void) {
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < DCLAW_RATE_LIMITERS; i++) {
        s->rate_limiters[i].tokens = s->rate_limiters[i].bucket_size;
    }
    dclaw_ipc_rate_limit_reset();
}

static dclaw_tool_request_t make_request(const char *name, uint16_t session,
                                         const char *dest) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, name, DCLAW_TOOL_NAME_MAX - 1);
    dclaw_sha256((const uint8_t *)name, strlen(name), req.tool_hash);
    req.cap_flags = DCLAW_CAP_SENSOR_READ; /* ignored: the trusted table wins */
    req.session_id = session;
    if (dest) strncpy(req.destination, dest, DCLAW_DESTINATION_MAX - 1);
    return req;
}

#if DCLAW_CONTENT_SCAN
static void set_content(dclaw_tool_request_t *req, const char *text, size_t len,
                        uint8_t scope) {
    if (len > DCLAW_CONTENT_MAX) len = DCLAW_CONTENT_MAX;
    memcpy(req->content_buf, text, len);
    req->content = req->content_buf;
    req->content_len = (uint16_t)len;
    req->content_scope = scope;
}
#endif

#if DCLAW_VERDICT_CACHE_SIZE > 0
static void cache_allow(const char *name) {
    uint8_t hash[32];
    dclaw_sha256((const uint8_t *)name, strlen(name), hash);
    dclaw_cache_store_with_ttl(hash, DCLAW_ACTION_ALLOW, DCLAW_SEV_INFO, 60);
}
#endif

static bool verdict_ok(const dclaw_verdict_t *v, dclaw_action_t action, uint8_t reason,
                       uint8_t alt_reason) {
    if (v->action != action) return false;
    if (reason == REASON_ANY) return true;
    return v->reason == reason || v->reason == alt_reason;
}

/* Optional hooks run outside the timed region. */
typedef void (*hook_fn)(dclaw_tool_request_t *req, const dclaw_verdict_t *v);

static void run_path(const char *name, dclaw_tool_request_t *req,
                     dclaw_action_t expect_action, uint8_t expect_reason,
                     uint8_t alt_reason, hook_fn before, hook_fn after) {
    int total = WARMUP_ITERATIONS + g_iterations;
    int mismatches = 0;
    dclaw_verdict_t first_bad = {0};
    hal_flash_stats_t f0, f1;

    for (int i = 0; i < total; i++) {
        if (i == WARMUP_ITERATIONS) hal_flash_get_stats(&f0);
        refill_rate_limiters();
        if (before) before(req, NULL);
        uint64_t t0 = clock_ns();
        dclaw_verdict_t v = dclaw_evaluate(req);
        uint64_t t1 = clock_ns();
        if (after) after(req, &v);
        if (!verdict_ok(&v, expect_action, expect_reason, alt_reason)) {
            if (mismatches++ == 0) first_bad = v;
        }
        if (i >= WARMUP_ITERATIONS) {
            uint64_t d = t1 - t0;
            g_samples[i - WARMUP_ITERATIONS] = d > UINT32_MAX ? UINT32_MAX : (uint32_t)d;
        }
    }
    hal_flash_get_stats(&f1);

    if (mismatches) {
        fprintf(stderr, "FAIL %s: %d/%d verdicts unexpected (first: action=%d reason=%d mode=%d)\n",
                name, mismatches, total, first_bad.action, first_bad.reason, first_bad.mode);
        g_failures++;
        return;
    }

    double sum = 0;
    for (int i = 0; i < g_iterations; i++) sum += g_samples[i];
    qsort(g_samples, (size_t)g_iterations, sizeof(uint32_t), cmp_u32);

    result_t *r = &g_results[g_result_count++];
    r->name = name;
    r->mean_ns = sum / g_iterations;
    r->p50_ns = g_samples[g_iterations / 2];
    r->p99_ns = g_samples[(int)(g_iterations * 0.99)];
    r->p999_ns = g_samples[(int)(g_iterations * 0.999)];
    r->max_ns = g_samples[g_iterations - 1];
    r->flash_writes_per_call = (double)(f1.writes - f0.writes) / g_iterations;
    r->flash_bytes_per_call = (double)(f1.bytes_written - f0.bytes_written) / g_iterations;
    r->flash_syncs_per_call = (double)(f1.syncs - f0.syncs) / g_iterations;
}

/* --- Path-specific hooks --------------------------------------------- */

static dclaw_tool_request_t g_prime_req;

/* Sequence path: an untimed NET_FETCH precedes each timed EXEC_SHELL. */
static void prime_net_fetch(dclaw_tool_request_t *req, const dclaw_verdict_t *v) {
    (void)req; (void)v;
    refill_rate_limiters();
    (void)dclaw_evaluate(&g_prime_req);
    refill_rate_limiters();
}

#if DCLAW_MQTT_ENABLED
static void build_response(uint16_t request_id, uint8_t action,
                           const uint8_t *tool_hash, uint8_t *buf) {
    uint8_t severity = 0, reason = DCLAW_REASON_CLOUD_BLOCK, flags = 0;
    uint16_t ttl = 0; /* never cached: every iteration stays a cache miss */
    uint32_t server_ts = 0x000F4240;
    buf[0] = (uint8_t)(request_id >> 8); buf[1] = (uint8_t)request_id;
    buf[2] = action; buf[3] = severity;
    buf[4] = (uint8_t)(ttl >> 8); buf[5] = (uint8_t)ttl;
    buf[6] = reason; buf[7] = flags;
    buf[8] = (uint8_t)(server_ts >> 24); buf[9] = (uint8_t)(server_ts >> 16);
    buf[10] = (uint8_t)(server_ts >> 8); buf[11] = (uint8_t)server_ts;
    dclaw_state_t *s = dclaw_get_state();
    uint8_t nonce[4] = {0};
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (s->pending[i].request_id == request_id && !s->pending[i].resolved) {
            memcpy(nonce, s->pending[i].request_nonce, 4);
            break;
        }
    }
    dclaw_verdict_compute_expected_hmac(request_id, action, severity, ttl, reason,
                                        flags, server_ts, tool_hash, nonce, buf + 12);
}

/* Resolve the escalation with a gateway ALLOW so pending and speculative
 * slots are reclaimed for the next iteration. */
static void resolve_allow(dclaw_tool_request_t *req, const dclaw_verdict_t *v) {
    (void)v;
    uint8_t resp[44];
    build_response(dclaw_get_state()->next_request_id, DCLAW_ACTION_ALLOW,
                   req->tool_hash, resp);
    if (dclaw_verdict_handle_response(resp, sizeof(resp), req->tool_hash) != 0) {
        fprintf(stderr, "FAIL: gateway verdict rejected during escalation path\n");
        g_failures++;
    }
}

/* Verdict-verification path: times dclaw_verdict_handle_response alone. */
static void bench_verdict_verify(void) {
    dclaw_tool_request_t req = make_request("get_temperature", 40, NULL);
    hal_flash_stats_t f0, f1;
    int total = WARMUP_ITERATIONS + g_iterations;
    for (int i = 0; i < total; i++) {
        if (i == WARMUP_ITERATIONS) hal_flash_get_stats(&f0);
        refill_rate_limiters();
        (void)dclaw_evaluate(&req);
        uint8_t resp[44];
        build_response(dclaw_get_state()->next_request_id, DCLAW_ACTION_ALLOW,
                       req.tool_hash, resp);
        uint64_t t0 = clock_ns();
        int rc = dclaw_verdict_handle_response(resp, sizeof(resp), req.tool_hash);
        uint64_t t1 = clock_ns();
        if (rc != 0) {
            fprintf(stderr, "FAIL verdict_verify: response rejected (rc=%d)\n", rc);
            g_failures++;
            return;
        }
        if (i >= WARMUP_ITERATIONS) {
            uint64_t d = t1 - t0;
            g_samples[i - WARMUP_ITERATIONS] = d > UINT32_MAX ? UINT32_MAX : (uint32_t)d;
        }
    }
    hal_flash_get_stats(&f1);
    double sum = 0;
    for (int i = 0; i < g_iterations; i++) sum += g_samples[i];
    qsort(g_samples, (size_t)g_iterations, sizeof(uint32_t), cmp_u32);
    result_t *r = &g_results[g_result_count++];
    r->name = "verdict_verify (HMAC + cache store)";
    r->mean_ns = sum / g_iterations;
    r->p50_ns = g_samples[g_iterations / 2];
    r->p99_ns = g_samples[(int)(g_iterations * 0.99)];
    r->p999_ns = g_samples[(int)(g_iterations * 0.999)];
    r->max_ns = g_samples[g_iterations - 1];
    /* Includes the untimed evaluate's audit writes; reported for completeness. */
    r->flash_writes_per_call = (double)(f1.writes - f0.writes) / g_iterations;
    r->flash_bytes_per_call = (double)(f1.bytes_written - f0.bytes_written) / g_iterations;
    r->flash_syncs_per_call = (double)(f1.syncs - f0.syncs) / g_iterations;
}
#endif

static double clock_overhead_ns(void) {
    uint64_t best = UINT64_MAX;
    for (int i = 0; i < 1000; i++) {
        uint64_t t0 = clock_ns();
        uint64_t t1 = clock_ns();
        if (t1 - t0 < best) best = t1 - t0;
    }
    return (double)best;
}

static void print_results(double overhead) {
    printf("\n%-40s %9s %9s %9s %9s %9s %8s %8s\n", "path", "p50(ns)", "p99", "p99.9",
           "max", "mean", "fw/call", "B/call");
    for (int i = 0; i < g_result_count; i++) {
        const result_t *r = &g_results[i];
        printf("%-40s %9.0f %9.0f %9.0f %9.0f %9.0f %8.4f %8.1f\n", r->name, r->p50_ns,
               r->p99_ns, r->p999_ns, r->max_ns, r->mean_ns, r->flash_writes_per_call,
               r->flash_bytes_per_call);
    }
    printf("\nclock_gettime overhead (min): %.0f ns, included in every sample\n", overhead);
}

static int write_json(const char *path, double overhead) {
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return -1; }
    fprintf(f, "{\"profile\":\"%s\",\"iterations\":%d,\"clock_overhead_ns\":%.0f,"
               "\"speculative\":%d,\"mqtt\":%d,\"content_scan\":%d,\"paths\":[",
            DCLAW_PROFILE_NAME, g_iterations, overhead, DCLAW_SPECULATIVE_EXECUTION,
            DCLAW_MQTT_ENABLED, DCLAW_CONTENT_SCAN);
    for (int i = 0; i < g_result_count; i++) {
        const result_t *r = &g_results[i];
        fprintf(f, "%s{\"name\":\"%s\",\"p50_ns\":%.0f,\"p99_ns\":%.0f,\"p999_ns\":%.0f,"
                   "\"max_ns\":%.0f,\"mean_ns\":%.1f,\"flash_writes_per_call\":%.5f,"
                   "\"flash_bytes_per_call\":%.2f,\"flash_syncs_per_call\":%.5f}",
                i ? "," : "", r->name, r->p50_ns, r->p99_ns, r->p999_ns, r->max_ns,
                r->mean_ns, r->flash_writes_per_call, r->flash_bytes_per_call,
                r->flash_syncs_per_call);
    }
    fprintf(f, "]}\n");
    return fclose(f);
}

int main(int argc, char *argv[]) {
    const char *json_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
            json_path = argv[++i];
        } else {
            int n = atoi(argv[i]);
            if (n >= 1000) g_iterations = n;
        }
    }
    g_samples = calloc((size_t)g_iterations, sizeof(uint32_t));
    if (!g_samples) return 1;

    /* Speculative escalation is off by default in production builds. */
    setenv("DCLAW_STRICT_MODE", "0", 1);
    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    if (dclaw_init(&info) != 0) return 1;
#if DCLAW_MQTT_ENABLED
    dclaw_mqtt_init();
    dclaw_mqtt_connect();
    uint8_t key[32];
    memset(key, 0x42, sizeof(key));
    dclaw_verdict_set_device_key(key, sizeof(key));
    dclaw_register_verdict_sender(bench_send_ok);
#endif
    dclaw_get_state()->online = true;

    printf("Edge Connector per-path benchmark: profile=%s iterations=%d (+%d warmup)\n",
           DCLAW_PROFILE_NAME, g_iterations, WARMUP_ITERATIONS);

    /* Early exits */
    dclaw_tool_request_t untrusted = make_request("test-tool", 1, NULL);
    run_path("deny_untrusted_tool (step 1b)", &untrusted, DCLAW_ACTION_BLOCK,
             DCLAW_REASON_INVALID_INPUT, DCLAW_REASON_INVALID_INPUT, NULL, NULL);

    dclaw_tool_request_t mismatch = make_request("sensor_read", 2, NULL);
    dclaw_sha256((const uint8_t *)"bash", 4, mismatch.tool_hash);
    run_path("deny_hash_mismatch (step 1a)", &mismatch, DCLAW_ACTION_BLOCK,
             DCLAW_REASON_HASH_MISMATCH, DCLAW_REASON_HASH_MISMATCH, NULL, NULL);

#if DCLAW_VERDICT_CACHE_SIZE > 0
    /* Full local pipeline, then a cached ALLOW */
    cache_allow("sensor_read");
    dclaw_tool_request_t cached = make_request("sensor_read", 3, NULL);
    run_path("cache_allow (no content)", &cached, DCLAW_ACTION_ALLOW, REASON_ANY, 0,
             NULL, NULL);

    cache_allow("api-call");
    dclaw_tool_request_t dest_ok = make_request("api-call", 4, "8.8.8.8");
    run_path("cache_allow (allowlisted destination)", &dest_ok, DCLAW_ACTION_ALLOW,
             REASON_ANY, 0, NULL, NULL);
#elif !DCLAW_MQTT_ENABLED
    /* No cache and no gateway: a call that passes every local guard is
     * still denied, since only the gateway can allow. */
    dclaw_tool_request_t local = make_request("sensor_read", 3, NULL);
    run_path("local_pass_no_gateway (deny)", &local, DCLAW_ACTION_BLOCK,
             DCLAW_REASON_CLOUD_TIMEOUT, DCLAW_REASON_CLOUD_TIMEOUT, NULL, NULL);
#endif

    dclaw_tool_request_t ssrf = make_request("api-call", 5, "http://10.0.0.1/");
    run_path("deny_destination (step 4)", &ssrf, DCLAW_ACTION_BLOCK,
             DCLAW_REASON_SSRF_BLOCK, DCLAW_REASON_DEST_DENY, NULL, NULL);

#if DCLAW_CONTENT_SCAN && DCLAW_VERDICT_CACHE_SIZE > 0
    {
        static char benign[DCLAW_CONTENT_MAX];
        const char *line = "The living room is 21 degrees and the lights are on. ";
        size_t ll = strlen(line);
        for (size_t i = 0; i < sizeof(benign); i++) benign[i] = line[i % ll];
        static const size_t sizes[] = {64, 512, DCLAW_CONTENT_MAX};
        static const char *labels[] = {"cache_allow + scan 64 B", "cache_allow + scan 512 B",
                                       "cache_allow + scan 4 KiB"};
        cache_allow("read_data");
        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
            dclaw_tool_request_t c = make_request("read_data", 6, NULL);
            set_content(&c, benign, sizes[i], DCLAW_CONTENT_SCOPE_USER_INPUT);
            run_path(labels[i], &c, DCLAW_ACTION_ALLOW, REASON_ANY, 0, NULL, NULL);
        }
        const char *secret = "api_key = sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
        dclaw_tool_request_t s = make_request("read_data", 7, NULL);
        set_content(&s, secret, strlen(secret), DCLAW_CONTENT_SCOPE_USER_INPUT);
        run_path("deny_content_secret (step 3)", &s, DCLAW_ACTION_BLOCK,
                 DCLAW_REASON_CONTENT_BLOCK, DCLAW_REASON_PII_DETECTED, NULL, NULL);
    }
#endif

    g_prime_req = make_request("api-call", 8, "8.8.8.8");
    dclaw_tool_request_t seq = make_request("bash", 8, NULL);
    run_path("deny_sequence NET_FETCH->EXEC_SHELL (5)", &seq, DCLAW_ACTION_BLOCK,
             DCLAW_REASON_CAP_SEQUENCE, DCLAW_REASON_CAP_SEQUENCE, prime_net_fetch, NULL);

#if DCLAW_MQTT_ENABLED
    /* Cache miss: escalate to the gateway. Local cost only. */
#if DCLAW_SPECULATIVE_EXECUTION
    dclaw_tool_request_t spec = make_request("get_state", 9, NULL);
    run_path("escalate_speculative (ALLOW, pending)", &spec, DCLAW_ACTION_ALLOW,
             REASON_ANY, 0, NULL, resolve_allow);
#endif
    /* ACTUATE is never speculative. With the MQTT stub the send fails and the
     * call is denied with CLOUD_TIMEOUT; with a live broker it returns a
     * PENDING BLOCK while the caller waits for the gateway. */
    dclaw_tool_request_t sync = make_request("gpio_write", 10, NULL);
    run_path("escalate_sync ACTUATE (wait)", &sync, DCLAW_ACTION_BLOCK,
             DCLAW_REASON_CLOUD_TIMEOUT, DCLAW_REASON_CLOUD_BLOCK, NULL, resolve_allow);

    bench_verdict_verify();
#endif

    double overhead = clock_overhead_ns();
    print_results(overhead);
    if (json_path && write_json(json_path, overhead) != 0) g_failures++;

    dclaw_shutdown();
    free(g_samples);
    if (g_failures) {
        fprintf(stderr, "\n%d path(s) failed verification\n", g_failures);
        return 1;
    }
    return 0;
}
