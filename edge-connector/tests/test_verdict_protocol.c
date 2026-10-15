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
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern dclaw_state_t *dclaw_get_state(void);
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
extern bool dclaw_cache_lookup(const uint8_t *tool_hash, dclaw_verdict_t *out);

static void build_valid_response(uint16_t request_id, uint8_t action,
                                 uint16_t ttl, const uint8_t *tool_hash, uint8_t *buf) {
    /* Build 44-byte wire format response (12 header + 32 HMAC) */
    uint8_t severity = 0;
    uint8_t reason = DCLAW_REASON_CLOUD_BLOCK;
    uint8_t flags = 0;
    uint32_t server_ts = 0x000F4240; /* 1000000 */

    buf[0] = (uint8_t)(request_id >> 8);
    buf[1] = (uint8_t)(request_id);
    buf[2] = action;
    buf[3] = severity;
    buf[4] = (uint8_t)(ttl >> 8); buf[5] = (uint8_t)(ttl & 0xFF);
    buf[6] = reason;
    buf[7] = flags;
    buf[8] = (uint8_t)((server_ts >> 24) & 0xFF);
    buf[9] = (uint8_t)((server_ts >> 16) & 0xFF);
    buf[10] = (uint8_t)((server_ts >> 8) & 0xFF);
    buf[11] = (uint8_t)(server_ts & 0xFF);
    /* MF-3: Look up request_nonce from pending slot for this request_id */
    dclaw_state_t *s = dclaw_get_state();
    uint8_t request_nonce[4] = {0};
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        if (s->pending[i].request_id == request_id && !s->pending[i].resolved) {
            memcpy(request_nonce, s->pending[i].request_nonce, 4);
            break;
        }
    }
    /* NEW-6: HMAC now covers all verdict fields */
    dclaw_verdict_compute_expected_hmac(request_id, action, severity, ttl,
                                        reason, flags, server_ts,
                                        tool_hash, request_nonce, buf + 12);
}

static void test_valid_verdict_accepted(void) {
    uint8_t tool_hash[32];
    memset(tool_hash, 0xAA, 32);
    uint16_t rid = 1;

    dclaw_verdict_register_pending(rid, tool_hash);

    uint8_t resp[44];
    build_valid_response(rid, DCLAW_ACTION_ALLOW, 60, tool_hash, resp);

    int rc = dclaw_verdict_handle_response(resp, 44, tool_hash);
    assert(rc == 0);
    (void)rc;
    printf("  PASS: valid verdict response accepted\n");
}

static void test_clock_synced_from_response(void) {
    dclaw_state_t *s = dclaw_get_state();
    assert(s->clock.time_trusted == true);
    assert(s->clock.cloud_epoch == 0x000F4240); /* 1000000 */
    (void)s;
    printf("  PASS: clock synchronized from server_ts\n");
}

static void test_duplicate_discarded(void) {
    uint8_t tool_hash[32];
    memset(tool_hash, 0xAA, 32);

    uint8_t resp[44];
    build_valid_response(1, DCLAW_ACTION_ALLOW, 60, tool_hash, resp);

    /* Second response for same request_id should be rejected.
     * After Comment 24 fix, resolved slots have request_id cleared to 0
     * for reuse, so a duplicate is treated as "unknown request_id" (-1). */
    int rc = dclaw_verdict_handle_response(resp, 44, tool_hash);
    assert(rc == -1);
    (void)rc;
    printf("  PASS: duplicate verdict response rejected (slot reclaimed)\n");
}

static void test_invalid_hmac_rejected(void) {
    uint8_t tool_hash[32];
    memset(tool_hash, 0xBB, 32);
    uint16_t rid = 2;

    dclaw_verdict_register_pending(rid, tool_hash);

    uint8_t resp[44];
    build_valid_response(rid, DCLAW_ACTION_ALLOW, 60, tool_hash, resp);
    /* Corrupt HMAC */
    resp[12] ^= 0xFF;
    resp[13] ^= 0xFF;

    int rc = dclaw_verdict_handle_response(resp, 44, tool_hash);
    assert(rc == -1);
    (void)rc;
    printf("  PASS: invalid HMAC tag rejected\n");
}

static void test_unknown_request_id_rejected(void) {
    uint8_t tool_hash[32];
    memset(tool_hash, 0xCC, 32);

    uint8_t resp[44];
    build_valid_response(999, DCLAW_ACTION_ALLOW, 60, tool_hash, resp);

    int rc = dclaw_verdict_handle_response(resp, 44, tool_hash);
    assert(rc == -1);
    (void)rc;
    printf("  PASS: unknown request_id rejected\n");
}

static void test_wrong_size_rejected(void) {
    uint8_t resp[8] = {0};
    uint8_t hash[32] = {0};
    int rc = dclaw_verdict_handle_response(resp, 8, hash);
    assert(rc == -1);
    (void)rc;
    printf("  PASS: wrong response size (8 < 44) rejected\n");
}

static void test_signed_ttl_controls_cache(void) {
    uint8_t hash[32];
    uint8_t response[44];
    dclaw_verdict_t verdict;
    dclaw_state_t *state = dclaw_get_state();

    memset(hash, 0xD1, sizeof(hash));
    assert(dclaw_verdict_register_pending(3, hash) >= 0);
    build_valid_response(3, DCLAW_ACTION_ALLOW, 5, hash, response);
    assert(dclaw_verdict_handle_response(response, sizeof(response), hash) == 0);
    assert(dclaw_cache_lookup(hash, &verdict));
    assert(verdict.ttl_minutes == 5);
    for (size_t i = 0; i < DCLAW_VERDICT_CACHE_SIZE; i++) {
        if (state->cache[i].occupied && memcmp(state->cache[i].tool_hash, hash, 32) == 0) {
            state->cache[i].cached_at_tick = hal_tick_ms() - 6ULL * 60000ULL;
            break;
        }
    }
    assert(!dclaw_cache_lookup(hash, &verdict));

    memset(hash, 0xD2, sizeof(hash));
    assert(dclaw_verdict_register_pending(4, hash) >= 0);
    build_valid_response(4, DCLAW_ACTION_ALLOW, 0, hash, response);
    assert(dclaw_verdict_handle_response(response, sizeof(response), hash) == 0);
    assert(!dclaw_cache_lookup(hash, &verdict));

    memset(hash, 0xD3, sizeof(hash));
    assert(dclaw_verdict_register_pending(5, hash) >= 0);
    build_valid_response(5, DCLAW_ACTION_ALLOW, UINT16_MAX, hash, response);
    assert(dclaw_verdict_handle_response(response, sizeof(response), hash) == 0);
    assert(dclaw_cache_lookup(hash, &verdict));
    assert(verdict.ttl_minutes == 60); /* device ceiling for cloud ALLOW */

    memset(hash, 0xD4, sizeof(hash));
    assert(dclaw_verdict_register_pending(6, hash) >= 0);
    build_valid_response(6, DCLAW_ACTION_ALLOW, 5, hash, response);
    response[5] ^= 1; /* tamper with signed TTL, keep original HMAC */
    assert(dclaw_verdict_handle_response(response, sizeof(response), hash) == -1);
    assert(!dclaw_cache_lookup(hash, &verdict));
    build_valid_response(6, DCLAW_ACTION_ALLOW, 5, hash, response);
    assert(dclaw_verdict_handle_response(response, sizeof(response), hash) == 0);
    assert(dclaw_cache_lookup(hash, &verdict));
    assert(verdict.ttl_minutes == 5);

    memset(hash, 0xD5, sizeof(hash));
    assert(dclaw_verdict_register_pending(7, hash) >= 0);
    build_valid_response(7, DCLAW_ACTION_BLOCK, 2, hash, response);
    assert(dclaw_verdict_handle_response(response, sizeof(response), hash) == 0);
    assert(dclaw_cache_lookup(hash, &verdict));
    assert(verdict.action == DCLAW_ACTION_BLOCK && verdict.ttl_minutes == 2);

    memset(hash, 0xD6, sizeof(hash));
    assert(dclaw_verdict_register_pending(8, hash) >= 0);
    build_valid_response(8, DCLAW_ACTION_BLOCK, 0, hash, response);
    assert(dclaw_verdict_handle_response(response, sizeof(response), hash) == 0);
    assert(!dclaw_cache_lookup(hash, &verdict));

    /* A zero-TTL lockdown BLOCK must also remove an earlier ALLOW for the
     * same tool instead of leaving it available for the next lookup. */
    memset(hash, 0xD3, sizeof(hash));
    assert(dclaw_verdict_register_pending(9, hash) >= 0);
    build_valid_response(9, DCLAW_ACTION_BLOCK, 0, hash, response);
    assert(dclaw_verdict_handle_response(response, sizeof(response), hash) == 0);
    assert(!dclaw_cache_lookup(hash, &verdict));

    printf("  PASS: signed TTL controls ALLOW/BLOCK expiry, zero/no-cache, ceiling, and tamper rejection\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    dclaw_init(&info);
    dclaw_mqtt_init();
    dclaw_mqtt_connect();

    /* P0-1 fix: Provision a non-zero device key so that HMAC verification
     * is active. Without this, the zero-key fallback causes all verdict
     * responses to be rejected (device key not provisioned). */
    uint8_t test_key[32];
    memset(test_key, 0x42, 32);
    dclaw_verdict_set_device_key(test_key, 32);

    printf("test_verdict_protocol:\n");
    test_valid_verdict_accepted();
    test_clock_synced_from_response();
    test_duplicate_discarded();
    test_invalid_hmac_rejected();
    test_unknown_request_id_rejected();
    test_wrong_size_rejected();
    test_signed_ttl_controls_cache();
    printf("  ALL PASSED (7 tests)\n");

    dclaw_shutdown();
    return 0;
}
