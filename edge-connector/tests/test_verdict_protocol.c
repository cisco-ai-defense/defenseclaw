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
extern int dclaw_cbor_encode_verdict_request(const dclaw_tool_request_t *req, uint16_t request_id,
                                             uint8_t session_risk, uint8_t *buf, size_t *out_len,
                                             size_t buf_size);
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

/* Regression: the send path encoded into a 512-byte buffer although the
 * profile allows DCLAW_ESCALATION_PAYLOAD_MAX bytes of content, so requests
 * with more than ~450 bytes of content were never sent. */
static void test_max_content_request_encodes(void) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    memset(req.tool_name, 'a', DCLAW_TOOL_NAME_MAX - 1);
    memset(req.tool_hash, 0x11, 32);
    memset(req.destination, 'b', DCLAW_DESTINATION_MAX - 1);
    memset(req.content_buf, 'c', DCLAW_CONTENT_MAX);
    req.content = req.content_buf;
    req.content_len = DCLAW_CONTENT_MAX; /* more than the payload cap: encoder truncates */
    static uint8_t buf[DCLAW_VERDICT_REQUEST_MAX];
    size_t len = 0;
    assert(dclaw_cbor_encode_verdict_request(&req, 9, 0, buf, &len, sizeof(buf)) == 0);
    assert(len > DCLAW_ESCALATION_PAYLOAD_MAX && len <= sizeof(buf));
    printf("  PASS: maximum-size verdict request encodes (%zu bytes)\n", len);
}

extern uint64_t dclaw_mqtt_next_backoff(uint64_t *cap_ms, uint32_t rnd);

/* Reconnect backoff: jittered, bounded, short cap. */
static void test_reconnect_backoff_bounds(void) {
    uint64_t cap = 1000, expect_cap[] = {2000, 4000, 8000, 16000, 30000, 30000, 30000};
    for (size_t i = 0; i < sizeof(expect_cap) / sizeof(expect_cap[0]); i++) {
        uint64_t lo = dclaw_mqtt_next_backoff(&(uint64_t){cap}, 0);
        uint64_t hi = dclaw_mqtt_next_backoff(&(uint64_t){cap}, 0xFFFFFFFFu);
        uint64_t d = dclaw_mqtt_next_backoff(&cap, (uint32_t)(i * 2654435761u));
        assert(cap == expect_cap[i]);
        assert(lo == cap / 2 && hi < cap && d >= cap / 2 && d < cap);
    }
    /* Different random draws give different delays (no lock-step retries). */
    uint64_t c1 = 8000, c2 = 8000;
    assert(dclaw_mqtt_next_backoff(&c1, 1) != dclaw_mqtt_next_backoff(&c2, 3000));
    printf("  PASS: reconnect backoff is jittered in [cap/2, cap), cap <= 30 s\n");
}


extern int dclaw_verdict_require_device_key(bool production);
extern void dclaw_verdict_protocol_shutdown(void);

/* Regression: a production daemon started without a device key (or with an
 * all-zero one) and sent unsigned frames. */
static void test_production_requires_device_key(void) {
    unsetenv("DCLAW_DEVICE_KEY");
    dclaw_verdict_protocol_shutdown(); /* forget the loaded key */
    assert(dclaw_verdict_require_device_key(true) == -1);
    assert(dclaw_verdict_require_device_key(false) == 0);

    dclaw_verdict_protocol_shutdown();
    setenv("DCLAW_DEVICE_KEY",
           "0000000000000000000000000000000000000000000000000000000000000000", 1);
    assert(dclaw_verdict_require_device_key(true) == -1);

    dclaw_verdict_protocol_shutdown();
    setenv("DCLAW_DEVICE_KEY",
           "4242424242424242424242424242424242424242424242424242424242424242", 1);
    assert(dclaw_verdict_require_device_key(true) == 0);
    unsetenv("DCLAW_DEVICE_KEY");
    printf("  PASS: production startup requires a nonzero device key\n");
}


extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint32_t target_hash, uint16_t session_id);

static bool all_zero(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i]) return false;
    return true;
}

/* Regression: the heartbeat's audit-head HMAC (bytes 22..29) was all zero
 * whenever the RAM audit buffer was empty, i.e. after every BLOCK. */
static void test_heartbeat_audit_head(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint8_t hb[64];
    size_t len = 0;

    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CAP_SEQUENCE, 0x1234, 5);
    assert(s->audit_writer.count == 0);
    dclaw_get_health(hb, &len, sizeof(hb));
    assert(len == 40);
    assert(!all_zero(hb + 22, 8));
    assert(memcmp(hb + 22, s->audit_writer.prev_hmac, 8) == 0);

    dclaw_audit_write(DCLAW_ACTION_WARN, DCLAW_REASON_CAP_SEQUENCE, 0x5678, 5);
    assert(s->audit_writer.count > 0);
    dclaw_get_health(hb, &len, sizeof(hb));
    assert(memcmp(hb + 22, s->audit_writer.buffer[s->audit_writer.count - 1].hmac, 8) == 0);
    (void)all_zero;
    printf("  PASS: heartbeat carries the audit chain head after a BLOCK\n");
}


/* Regression: an emergency lockdown was not visible in heartbeats. */
static void test_heartbeat_lockdown_flag(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint8_t hb[64];
    size_t len = 0;
    bool was = s->emergency.block_all_active;

    s->emergency.block_all_active = true;
    dclaw_get_health(hb, &len, sizeof(hb));
    assert(len == 40 && (hb[30] & 0x40));
    s->emergency.block_all_active = false;
    dclaw_get_health(hb, &len, sizeof(hb));
    assert(len == 40 && !(hb[30] & 0x40));
    s->emergency.block_all_active = was;
    printf("  PASS: heartbeat flag 0x40 reports an emergency lockdown\n");
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
    test_max_content_request_encodes();
    test_reconnect_backoff_bounds();
    test_production_requires_device_key();
    test_heartbeat_audit_head();
    test_heartbeat_lockdown_flag();
    printf("  ALL PASSED (12 tests)\n");

    dclaw_shutdown();
    return 0;
}
