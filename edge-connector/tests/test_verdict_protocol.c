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
                                                uint8_t *out_hmac_4bytes);
extern void dclaw_verdict_set_device_key(const uint8_t *key, size_t key_len);

static void build_valid_response(uint16_t request_id, uint8_t action,
                                 const uint8_t *tool_hash, uint8_t *buf) {
    /* Build 28-byte wire format response (12 header + 16 HMAC) */
    uint8_t severity = 0;
    uint16_t ttl = 60;
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
    /* NEW-6: HMAC now covers all verdict fields */
    dclaw_verdict_compute_expected_hmac(request_id, action, severity, ttl,
                                        reason, flags, server_ts,
                                        tool_hash, buf + 12);
}

static void test_valid_verdict_accepted(void) {
    uint8_t tool_hash[32];
    memset(tool_hash, 0xAA, 32);
    uint16_t rid = 1;

    dclaw_verdict_register_pending(rid, tool_hash);

    uint8_t resp[28];
    build_valid_response(rid, DCLAW_ACTION_ALLOW, tool_hash, resp);

    int rc = dclaw_verdict_handle_response(resp, 28, tool_hash);
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

    uint8_t resp[28];
    build_valid_response(1, DCLAW_ACTION_ALLOW, tool_hash, resp);

    /* Second response for same request_id should be rejected.
     * After Comment 24 fix, resolved slots have request_id cleared to 0
     * for reuse, so a duplicate is treated as "unknown request_id" (-1). */
    int rc = dclaw_verdict_handle_response(resp, 28, tool_hash);
    assert(rc == -1);
    (void)rc;
    printf("  PASS: duplicate verdict response rejected (slot reclaimed)\n");
}

static void test_invalid_hmac_rejected(void) {
    uint8_t tool_hash[32];
    memset(tool_hash, 0xBB, 32);
    uint16_t rid = 2;

    dclaw_verdict_register_pending(rid, tool_hash);

    uint8_t resp[28];
    build_valid_response(rid, DCLAW_ACTION_ALLOW, tool_hash, resp);
    /* Corrupt HMAC */
    resp[12] ^= 0xFF;
    resp[13] ^= 0xFF;

    int rc = dclaw_verdict_handle_response(resp, 28, tool_hash);
    assert(rc == -1);
    (void)rc;
    printf("  PASS: invalid HMAC tag rejected\n");
}

static void test_unknown_request_id_rejected(void) {
    uint8_t tool_hash[32];
    memset(tool_hash, 0xCC, 32);

    uint8_t resp[28];
    build_valid_response(999, DCLAW_ACTION_ALLOW, tool_hash, resp);

    int rc = dclaw_verdict_handle_response(resp, 28, tool_hash);
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
    printf("  PASS: wrong response size (8 != 16) rejected\n");
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
    printf("  ALL PASSED (6 tests)\n");

    dclaw_shutdown();
    return 0;
}
