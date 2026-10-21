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

#include "defenseclaw.h"
#include "deferred_reply.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern dclaw_state_t *dclaw_get_state(void);

static int g_writes;
static int g_last_fd;
static int32_t g_last_rpc;
static dclaw_verdict_t g_last;

static int fake_writer(int fd, const dclaw_verdict_t *v, int32_t rpc_id) {
    g_writes++;
    g_last_fd = fd;
    g_last_rpc = rpc_id;
    g_last = *v;
    return 0;
}

static dclaw_verdict_t gateway(dclaw_action_t action) {
    dclaw_verdict_t v = {.action = action, .reason = DCLAW_REASON_CLOUD_BLOCK,
                         .severity = DCLAW_SEV_INFO, .mode = DCLAW_VERDICT_PENDING,
                         .ttl_minutes = 5, .from_cache = true};
    return v;
}

static void reset(void) {
    dclaw_deferred_init(fake_writer);
    g_writes = 0;
    dclaw_get_state()->emergency.block_all_active = false;
}

static void test_allow_released(void) {
    reset();
    assert(dclaw_deferred_add(5, 77, 100, 1, 0xABCD, 1000));
    assert(dclaw_deferred_pending_for_fd(5));
    dclaw_verdict_t g = gateway(DCLAW_ACTION_ALLOW);
    dclaw_deferred_resolve(100, &g);
    assert(g_writes == 1 && g_last_fd == 5 && g_last_rpc == 77);
    assert(g_last.action == DCLAW_ACTION_ALLOW);
    assert(g_last.mode == DCLAW_VERDICT_SYNC && !g_last.from_cache);
    assert(!dclaw_deferred_pending_for_fd(5));
    printf("  PASS: gateway ALLOW releases the held reply\n");
}

static void test_block_released(void) {
    reset();
    assert(dclaw_deferred_add(5, 1, 101, 1, 0, 1000));
    dclaw_verdict_t g = gateway(DCLAW_ACTION_BLOCK);
    dclaw_deferred_resolve(101, &g);
    assert(g_writes == 1 && g_last.action == DCLAW_ACTION_BLOCK);
    printf("  PASS: gateway BLOCK releases the held reply\n");
}

static void test_unknown_request_ignored(void) {
    reset();
    assert(dclaw_deferred_add(5, 1, 102, 1, 0, 1000));
    dclaw_verdict_t g = gateway(DCLAW_ACTION_ALLOW);
    dclaw_deferred_resolve(999, &g);
    assert(g_writes == 0 && dclaw_deferred_pending_for_fd(5));
    printf("  PASS: verdict for another request leaves the reply held\n");
}

static void test_timeout_denies(void) {
    reset();
    assert(dclaw_deferred_add(6, 3, 103, 1, 0, 1000));
    dclaw_deferred_expire(1000 + DCLAW_VERDICT_TIMEOUT_MS - 1);
    assert(g_writes == 0);
    dclaw_deferred_expire(1000 + DCLAW_VERDICT_TIMEOUT_MS);
    assert(g_writes == 1 && g_last.action == DCLAW_ACTION_BLOCK);
    assert(g_last.reason == DCLAW_REASON_CLOUD_TIMEOUT && g_last_rpc == 3);
    /* A late verdict after the timeout has nothing to release. */
    dclaw_verdict_t g = gateway(DCLAW_ACTION_ALLOW);
    dclaw_deferred_resolve(103, &g);
    assert(g_writes == 1);
    printf("  PASS: timeout denies with CLOUD_TIMEOUT; late verdict ignored\n");
}

static void test_lockdown_while_waiting_blocks(void) {
    reset();
    assert(dclaw_deferred_add(5, 1, 104, 1, 0, 1000));
    dclaw_get_state()->emergency.block_all_active = true;
    dclaw_verdict_t g = gateway(DCLAW_ACTION_ALLOW);
    dclaw_deferred_resolve(104, &g);
    assert(g_writes == 1 && g_last.action == DCLAW_ACTION_BLOCK);
    assert(g_last.reason == DCLAW_REASON_CLOUD_BLOCK);
    dclaw_get_state()->emergency.block_all_active = false;
    printf("  PASS: BLOCK_ALL during the wait overrides a gateway ALLOW\n");
}

static void test_revoked_while_waiting_blocks(void) {
    reset();
    assert(dclaw_deferred_add(5, 1, 105, 42, 0, 1000));
    dclaw_session_revoke(42);
    dclaw_verdict_t g = gateway(DCLAW_ACTION_ALLOW);
    dclaw_deferred_resolve(105, &g);
    assert(g_writes == 1 && g_last.action == DCLAW_ACTION_BLOCK);
    assert(g_last.reason == DCLAW_REASON_RETROACTIVE);
    printf("  PASS: session revoked during the wait overrides a gateway ALLOW\n");
}

static void test_table_full_and_drop(void) {
    reset();
    for (int i = 0; i < DCLAW_DEFERRED_MAX; i++) {
        assert(dclaw_deferred_add(10 + i, i, (uint16_t)(200 + i), 1, 0, 1000));
    }
    assert(!dclaw_deferred_add(99, 0, 300, 1, 0, 1000));
    dclaw_deferred_drop_fd(10);
    assert(!dclaw_deferred_pending_for_fd(10));
    dclaw_verdict_t g = gateway(DCLAW_ACTION_ALLOW);
    dclaw_deferred_resolve(200, &g);
    assert(g_writes == 0);
    printf("  PASS: full table refuses; dropped client gets no reply\n");
}

#if DCLAW_MQTT_ENABLED
extern int dclaw_mqtt_init(void);
extern int dclaw_mqtt_connect(void);
extern int dclaw_verdict_register_pending(uint16_t request_id, const uint8_t *tool_hash);
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

/* The verdict protocol releases the held reply through the ready callback. */
static void test_verdict_protocol_releases(void) {
    reset();
    dclaw_register_verdict_ready_callback(dclaw_deferred_resolve);
    uint8_t hash[32];
    memset(hash, 0x5A, sizeof(hash));
    uint16_t rid = 400;
    assert(dclaw_verdict_register_pending(rid, hash) >= 0);
    assert(dclaw_deferred_add(7, 9, rid, 1, 0, hal_tick_ms()));

    uint8_t buf[44] = {0};
    uint32_t ts = 0x000F4240;
    buf[0] = (uint8_t)(rid >> 8); buf[1] = (uint8_t)rid;
    buf[2] = DCLAW_ACTION_ALLOW; buf[6] = DCLAW_REASON_CLOUD_BLOCK;
    buf[8] = (uint8_t)(ts >> 24); buf[9] = (uint8_t)(ts >> 16);
    buf[10] = (uint8_t)(ts >> 8); buf[11] = (uint8_t)ts;
    uint8_t nonce[4] = {0};
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (s->pending[i].request_id == rid) memcpy(nonce, s->pending[i].request_nonce, 4);
    }
    dclaw_verdict_compute_expected_hmac(rid, DCLAW_ACTION_ALLOW, 0, 0,
                                        DCLAW_REASON_CLOUD_BLOCK, 0, ts, hash, nonce,
                                        buf + 12);
    assert(dclaw_verdict_handle_response(buf, sizeof(buf), hash) == 0);
    assert(g_writes == 1 && g_last_fd == 7 && g_last_rpc == 9);
    assert(g_last.action == DCLAW_ACTION_ALLOW);
    dclaw_register_verdict_ready_callback(NULL);
    printf("  PASS: authenticated gateway verdict releases the reply end to end\n");
}
#endif

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    dclaw_init(&info);
#if DCLAW_MQTT_ENABLED
    dclaw_mqtt_init();
    dclaw_mqtt_connect();
    uint8_t key[32];
    memset(key, 0x42, sizeof(key));
    dclaw_verdict_set_device_key(key, sizeof(key));
#endif

    printf("test_deferred_reply:\n");
    test_allow_released();
    test_block_released();
    test_unknown_request_ignored();
    test_timeout_denies();
    test_lockdown_while_waiting_blocks();
    test_revoked_while_waiting_blocks();
    test_table_full_and_drop();
#if DCLAW_MQTT_ENABLED
    test_verdict_protocol_releases();
#endif
    printf("  ALL PASSED\n");

    dclaw_shutdown();
    return 0;
}
