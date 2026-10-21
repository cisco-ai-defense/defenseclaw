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

/* End-to-end speculative execution: a speculatively allowed call that the
 * gateway later blocks must revoke its session and notify the callback. */

#include "defenseclaw.h"
#include "platform.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern dclaw_state_t *dclaw_get_state(void);
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
extern void dclaw_sessions_reset_keep_revoked(void);
extern const uint8_t *dclaw_mqtt_pending_lookup(uint16_t request_id);
extern void dclaw_ipc_rate_limit_reset(void);

static int fake_send_ok(const dclaw_tool_request_t *req, uint16_t request_id) {
    (void)req; (void)request_id;
    return 0; /* the transport accepted the request */
}

static int fake_send_fail(const dclaw_tool_request_t *req, uint16_t request_id) {
    (void)req; (void)request_id;
    return -1; /* offline, or the request could not be encoded */
}

static int g_cb_calls;
static uint16_t g_cb_session;

static void on_revoked(uint16_t session_id, const char *tool_name) {
    (void)tool_name;
    g_cb_calls++;
    g_cb_session = session_id;
}

static dclaw_tool_request_t make_request(const char *name, uint8_t caps, uint16_t session) {
    dclaw_tool_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.tool_name, name, DCLAW_TOOL_NAME_MAX - 1);
    dclaw_sha256((const uint8_t *)name, strlen(name), req.tool_hash);
    req.cap_flags = caps;
    req.session_id = session;
    return req;
}

static void build_response(uint16_t request_id, uint8_t action,
                           const uint8_t *tool_hash, uint8_t *buf) {
    uint8_t severity = 0, reason = DCLAW_REASON_CLOUD_BLOCK, flags = 0;
    uint16_t ttl = 0;
    uint32_t server_ts = 0x000F4240;
    buf[0] = (uint8_t)(request_id >> 8);
    buf[1] = (uint8_t)(request_id);
    buf[2] = action;
    buf[3] = severity;
    buf[4] = 0; buf[5] = 0;
    buf[6] = reason;
    buf[7] = flags;
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

/* Issue a speculative call and return its request_id (0 if not speculative). */
static uint16_t speculate(const char *name, uint16_t session, uint8_t *hash_out) {
    dclaw_tool_request_t req = make_request(name, DCLAW_CAP_SENSOR_READ, session);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    memcpy(hash_out, req.tool_hash, 32);
    if (v.action != DCLAW_ACTION_ALLOW || v.mode != DCLAW_VERDICT_PENDING) return 0;
    return dclaw_get_state()->next_request_id;
}

static void test_block_revokes_session(void) {
    uint8_t hash[32], resp[44];
    uint16_t rid = speculate("read-sensor", 7, hash);
    assert(rid != 0);

    g_cb_calls = 0;
    build_response(rid, DCLAW_ACTION_BLOCK, hash, resp);
    assert(dclaw_verdict_handle_response(resp, sizeof(resp), hash) == 0);
    assert(g_cb_calls == 1);
    assert(g_cb_session == 7);

    dclaw_tool_request_t next = make_request("sensor_read", DCLAW_CAP_SENSOR_READ, 7);
    dclaw_verdict_t v = dclaw_evaluate(&next);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_RETROACTIVE);
    (void)v;
    printf("  PASS: gateway BLOCK of speculative call revokes its session\n");
}

static void test_other_sessions_unaffected(void) {
    uint8_t hash[32];
    assert(speculate("sensor-read", 8, hash) != 0);
    printf("  PASS: revocation is scoped to one session\n");
}

static void test_allow_does_not_revoke(void) {
    uint8_t hash[32], resp[44];
    uint16_t rid = speculate("read_sensor", 9, hash);
    assert(rid != 0);
    g_cb_calls = 0;
    build_response(rid, DCLAW_ACTION_ALLOW, hash, resp);
    assert(dclaw_verdict_handle_response(resp, sizeof(resp), hash) == 0);
    assert(g_cb_calls == 0);
    assert(speculate("sensor", 9, hash) != 0);
    printf("  PASS: gateway ALLOW leaves the session usable\n");
}

static void test_sync_block_does_not_invoke_callback(void) {
    /* ACTUATE is never speculative: the BLOCK is not retroactive. */
    dclaw_tool_request_t req = make_request("gpio_write", DCLAW_CAP_ACTUATE, 10);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    /* Sync path: PENDING with a live broker, CLOUD_TIMEOUT with the stub. */
    assert(v.action == DCLAW_ACTION_BLOCK);
    (void)v;
    uint16_t rid = dclaw_get_state()->next_request_id;
    uint8_t resp[44];
    g_cb_calls = 0;
    build_response(rid, DCLAW_ACTION_BLOCK, req.tool_hash, resp);
    assert(dclaw_verdict_handle_response(resp, sizeof(resp), req.tool_hash) == 0);
    assert(g_cb_calls == 0);
    uint8_t hash[32];
    assert(speculate("get_state", 10, hash) != 0);
    printf("  PASS: sync-path BLOCK does not revoke the session\n");
}

static void test_full_slots_fall_back_to_sync(void) {
    dclaw_state_t *s = dclaw_get_state();
    memset(s->speculative, 0, sizeof(s->speculative));
    static const char *names[] = {
        "battery_status", "get_temperature", "check_status", "scan_surroundings",
        "check_room_state", "sensor_read", "sensor-read", "read_sensor",
    };
    _Static_assert(DCLAW_SPECULATIVE_SLOTS <= sizeof(names) / sizeof(names[0]),
                   "need one trusted tool name per speculative slot");
    uint8_t hash[32];
    for (int i = 0; i < DCLAW_SPECULATIVE_SLOTS; i++) {
        assert(speculate(names[i], (uint16_t)(20 + i), hash) != 0);
    }
    dclaw_tool_request_t req = make_request("list_devices", DCLAW_CAP_SENSOR_READ, 30);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    (void)v;
    printf("  PASS: no free speculative slot -> synchronous wait\n");
}

/* Regression: a speculative-class call whose verdict request was not sent
 * (offline, or too large to encode) used to be allowed and never verified. */
static void test_unsent_request_is_not_speculative(void) {
    dclaw_register_verdict_sender(fake_send_fail);
    dclaw_state_t *s = dclaw_get_state();
    /* Free every slot so the call reaches the speculation decision. */
    memset(s->speculative, 0, sizeof(s->speculative));
    memset(s->pending, 0, sizeof(s->pending));
    dclaw_tool_request_t req = make_request("get_sensors", DCLAW_CAP_SENSOR_READ, 40);
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CLOUD_TIMEOUT);
    for (int i = 0; i < DCLAW_SPECULATIVE_SLOTS; i++) assert(s->speculative[i].request_id == 0);
    (void)v;
    dclaw_register_verdict_sender(fake_send_ok);
    printf("  PASS: unsent request is not allowed speculatively\n");
}

/* A local WARN (here a MEDIUM content finding in tool output) is kept on the
 * speculative path, as on the cache path. */
static void test_speculative_keeps_local_warn(void) {
    dclaw_state_t *s = dclaw_get_state();
    memset(s->speculative, 0, sizeof(s->speculative));
    memset(s->pending, 0, sizeof(s->pending));
    dclaw_tool_request_t req = make_request("check_status", DCLAW_CAP_SENSOR_READ, 41);
    req.content = "contact: alice@example.com";
    req.content_len = (uint16_t)strlen(req.content);
    req.content_scope = DCLAW_CONTENT_SCOPE_TOOL_OUTPUT;
    dclaw_verdict_t v = dclaw_evaluate(&req);
    assert(v.mode == DCLAW_VERDICT_PENDING);
    assert(v.action == DCLAW_ACTION_WARN);
    (void)v;
    printf("  PASS: speculative path keeps a local WARN\n");
}

static void test_session_reset_keeps_revocations(void) {
    /* Session 7 was revoked above; sessions 20.. have unverified
     * speculative calls in flight. */
    dclaw_sessions_reset_keep_revoked();
    dclaw_tool_request_t a = make_request("get_history", DCLAW_CAP_SENSOR_READ, 7);
    dclaw_verdict_t v = dclaw_evaluate(&a);
    assert(v.reason == DCLAW_REASON_RETROACTIVE);
    dclaw_tool_request_t b = make_request("get_sensors", DCLAW_CAP_SENSOR_READ, 20);
    v = dclaw_evaluate(&b);
    assert(v.reason == DCLAW_REASON_RETROACTIVE);
    (void)v;
    printf("  PASS: session reset keeps revoked and in-flight speculative sessions denied\n");
}


static void refill_rate_limits(void) {
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < DCLAW_RATE_LIMITERS; i++)
        s->rate_limiters[i].tokens = s->rate_limiters[i].bucket_size;
    dclaw_ipc_rate_limit_reset();
}

static int pending_index(uint16_t rid) {
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++)
        if (s->pending[i].request_id == rid && !s->pending[i].resolved) return i;
    return -1;
}

static const char *const k_sensor_tools[] = {
    "get_state", "battery_status", "get_temperature", "check_status",
    "list_devices", "get_history", "get_sensors", "scan_surroundings",
    "check_room_state", "sensor_read", "sensor-read", "read_sensor",
};
#define N_SENSOR_TOOLS (int)(sizeof(k_sensor_tools) / sizeof(k_sensor_tools[0]))

/* Regression: a speculative call's pending slot was reclaimed by any new
 * escalation once it was 500 ms old, and its transport entry was evicted
 * after 16 more escalations. The gateway's late BLOCK then matched no
 * request and the session was never revoked. */
static void test_late_block_survives_slot_pressure(void) {
    dclaw_state_t *s = dclaw_get_state();
    memset(s->speculative, 0, sizeof(s->speculative));
    memset(s->pending, 0, sizeof(s->pending));
    refill_rate_limits();

    uint8_t hash[32], resp[44];
    uint16_t rid = speculate("read-sensor", 50, hash);
    assert(rid != 0);
    int p = pending_index(rid);
    assert(p >= 0);
    /* The synchronous deadline has long passed for this request. */
    uint64_t now = hal_tick_ms();
    s->pending[p].resolved_at = now > 10000 ? now - 10000 : 1;

    /* 8 new escalations from other sessions: they fill every other pending
     * slot, and the last one must fail closed instead of evicting ours. */
    dclaw_verdict_t v = {0};
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        refill_rate_limits();
        dclaw_tool_request_t o = make_request(k_sensor_tools[i % N_SENSOR_TOOLS],
                                              DCLAW_CAP_SENSOR_READ, (uint16_t)(100 + i));
        v = dclaw_evaluate(&o);
    }
    assert(v.action == DCLAW_ACTION_BLOCK);
    assert(v.reason == DCLAW_REASON_CLOUD_TIMEOUT);
    assert(pending_index(rid) == p);

    /* Free the other slots by answering them, then push more than a full
     * transport ring of escalations through. */
    for (int i = 0; i < DCLAW_PENDING_SLOTS; i++) {
        uint16_t other = s->pending[i].request_id;
        if (other == 0 || other == rid || s->pending[i].resolved) continue;
        const uint8_t *th = dclaw_mqtt_pending_lookup(other);
        assert(th != NULL);
        uint8_t th_copy[32];
        memcpy(th_copy, th, 32);
        build_response(other, DCLAW_ACTION_ALLOW, th_copy, resp);
        assert(dclaw_verdict_handle_response(resp, sizeof(resp), th_copy) == 0);
    }
    for (int i = 0; i < DCLAW_PENDING_RING_SIZE + 4; i++) {
        refill_rate_limits();
        dclaw_tool_request_t o = make_request(k_sensor_tools[i % N_SENSOR_TOOLS],
                                              DCLAW_CAP_SENSOR_READ, (uint16_t)(200 + i));
        (void)dclaw_evaluate(&o);
        uint16_t other = s->next_request_id;
        if (other == rid || pending_index(other) < 0) continue;
        build_response(other, DCLAW_ACTION_ALLOW, o.tool_hash, resp);
        assert(dclaw_verdict_handle_response(resp, sizeof(resp), o.tool_hash) == 0);
    }
    assert(pending_index(rid) == p);
    const uint8_t *kept = dclaw_mqtt_pending_lookup(rid);
    assert(kept != NULL && memcmp(kept, hash, 32) == 0);
    (void)kept;

    /* The late, authentic BLOCK still revokes the session. */
    g_cb_calls = 0;
    build_response(rid, DCLAW_ACTION_BLOCK, hash, resp);
    assert(dclaw_verdict_handle_response(resp, sizeof(resp), hash) == 0);
    assert(g_cb_calls == 1 && g_cb_session == 50);
    refill_rate_limits();
    dclaw_tool_request_t next = make_request("get_state", DCLAW_CAP_SENSOR_READ, 50);
    v = dclaw_evaluate(&next);
    assert(v.action == DCLAW_ACTION_BLOCK && v.reason == DCLAW_REASON_RETROACTIVE);
    (void)v;
    printf("  PASS: late gateway BLOCK revokes despite pending-slot and ring pressure\n");
}

/* A speculative call whose verdict never arrives does not hold its slot
 * forever: at the deadline the session is revoked and the slot is freed. */
static void test_speculative_deadline_revokes(void) {
    dclaw_state_t *s = dclaw_get_state();
    memset(s->speculative, 0, sizeof(s->speculative));
    memset(s->pending, 0, sizeof(s->pending));
    refill_rate_limits();

    uint8_t hash[32];
    uint16_t rid = speculate("battery_status", 60, hash);
    assert(rid != 0);
    int k = -1;
    for (int i = 0; i < DCLAW_SPECULATIVE_SLOTS; i++)
        if (s->speculative[i].request_id == rid) k = i;
    assert(k >= 0);
    uint64_t now = hal_tick_ms();
    assert(s->speculative[k].revoke_deadline_ms >= now);
    assert(s->speculative[k].revoke_deadline_ms <= now + DCLAW_SPECULATIVE_VERDICT_TIMEOUT_MS);
    s->speculative[k].revoke_deadline_ms = now; /* deadline reached */

    g_cb_calls = 0;
    refill_rate_limits();
    dclaw_tool_request_t next = make_request("get_temperature", DCLAW_CAP_SENSOR_READ, 60);
    dclaw_verdict_t v = dclaw_evaluate(&next);
    assert(v.action == DCLAW_ACTION_BLOCK && v.reason == DCLAW_REASON_RETROACTIVE);
    assert(g_cb_calls == 1 && g_cb_session == 60);
    assert(s->speculative[k].request_id == 0);
    assert(pending_index(rid) < 0);
    (void)v; (void)k;
    printf("  PASS: unanswered speculative call revokes its session at the deadline\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    dclaw_init(&info);
    dclaw_mqtt_init();
    dclaw_mqtt_connect();
    uint8_t key[32];
    memset(key, 0x42, 32);
    dclaw_verdict_set_device_key(key, 32);
    dclaw_register_retroactive_callback(on_revoked);
    dclaw_register_verdict_sender(fake_send_ok);

    printf("test_speculative_revocation:\n");
    test_block_revokes_session();
    test_other_sessions_unaffected();
    test_allow_does_not_revoke();
    test_sync_block_does_not_invoke_callback();
    test_full_slots_fall_back_to_sync();
    test_session_reset_keeps_revocations();
    test_unsent_request_is_not_speculative();
    test_speculative_keeps_local_warn();
    test_late_block_survives_slot_pressure();
    test_speculative_deadline_revokes();
    printf("  ALL PASSED (9 tests)\n");

    dclaw_shutdown();
    return 0;
}
