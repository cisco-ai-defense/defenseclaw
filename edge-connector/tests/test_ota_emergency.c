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
#include "hmac_sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

extern dclaw_state_t *dclaw_get_state(void);
extern void dclaw_canary_tick(void);
extern void dclaw_canary_tick_at(uint64_t now_ms);
extern void dclaw_canary_record_block(void);
extern void dclaw_policy_rollback(void);
extern bool dclaw_emergency_has_gap(uint32_t cloud_current_seq);
extern uint32_t dclaw_load_lockdown_release_seq(void);
extern int dclaw_store_lockdown_release_seq(uint32_t seq);
extern uint32_t dclaw_boot_counter_get(void);
extern int dclaw_boot_counter_advance(void);
extern int dclaw_cbor_encode_heartbeat(uint8_t *buf, size_t *out_len, size_t buf_size);

/* Helper: build a valid policy blob with correct header */
static void make_policy_blob(uint8_t *blob, size_t *len, uint16_t version,
                             uint16_t canary_baseline) {
    memset(blob, 0, 64);
    /* Header: version(2) + payload_len(2) + canary_baseline(2) + reserved(2) */
    blob[0] = (uint8_t)(version >> 8);
    blob[1] = (uint8_t)version;
    blob[2] = 0; blob[3] = 56; /* payload_len = 56 */
    blob[4] = (uint8_t)(canary_baseline >> 8);
    blob[5] = (uint8_t)canary_baseline;
    blob[6] = 0; blob[7] = 0;
    blob[8] = 0x87; /* explicit severity/sequence/destination sections */
    *len = 64;
}

/*
 * Test OTA key — a known non-zero key used for test signing.
 * Set as DCLAW_OTA_HMAC_KEY env var in hex before tests run.
 */
static const uint8_t TEST_OTA_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
};

static const char *TEST_OTA_KEY_HEX =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

/*
 * Helper: build a valid signature for the given blob using the test OTA key.
 * The explicitly selected HMAC mode uses HMAC-SHA256(ota_hmac_key, blob).
 */
static void make_valid_signature_for(const uint8_t *blob, size_t blob_len, uint8_t *sig) {
    memset(sig, 0, 64);
    dclaw_hmac_sha256(TEST_OTA_KEY, 32, blob, blob_len, sig);
}

static void make_invalid_signature(uint8_t *sig) {
    /* Fill with bytes that won't match any valid HMAC */
    memset(sig, 0xAA, 64);
    sig[0] = 0xBB; /* Ensure it doesn't accidentally match */
}

/* === Policy OTA Tests === */

static void test_policy_apply_valid(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->device.policy_version = 0;

    uint8_t blob[64];
    size_t len;
    make_policy_blob(blob, &len, 1, 5); /* version=1, baseline=5 */

    uint8_t sig[64];
    make_valid_signature_for(blob, len, sig);

    int rc = dclaw_apply_policy(blob, (uint32_t)len, sig);
    assert(rc == 0);
    assert(s->device.policy_version == 1);
    assert(s->canary.canary_active == true);
    assert(s->canary.baseline_blocks_per_min == 5);
    (void)rc;
    printf("  PASS: valid policy OTA applied, canary active\n");
}

static void test_policy_invalid_signature_rejected(void) {
    uint8_t blob[64];
    size_t len;
    make_policy_blob(blob, &len, 2, 5);

    uint8_t sig[64];
    make_invalid_signature(sig);

    int rc = dclaw_apply_policy(blob, (uint32_t)len, sig);
    assert(rc == -1);
    make_valid_signature_for(blob, len, sig);
    sig[63] = 1; /* HMAC wire format requires zero padding. */
    rc = dclaw_apply_policy(blob, (uint32_t)len, sig);
    assert(rc == -1);
    (void)rc;
    printf("  PASS: invalid signature and nonzero HMAC padding rejected\n");
}

static void test_policy_rollback_version_rejected(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->device.policy_version = 5;

    uint8_t blob[64];
    size_t len;
    make_policy_blob(blob, &len, 3, 5); /* version 3 < current 5 */

    uint8_t sig[64];
    make_valid_signature_for(blob, len, sig);

    int rc = dclaw_apply_policy(blob, (uint32_t)len, sig);
    assert(rc == -2);
    (void)rc;
    printf("  PASS: downgrade (version 3 < 5) rejected\n");
}

static void test_reserved_policy_version_rejected(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint16_t prior = s->device.policy_version;
    uint8_t blob[64], sig[64];
    size_t len;
    make_policy_blob(blob, &len, UINT16_MAX, 2);
    make_valid_signature_for(blob, len, sig);
    assert(dclaw_apply_policy(blob, (uint32_t)len, sig) == -2);
    assert(s->device.policy_version == prior);
    printf("  PASS: reserved version 65535 cannot reset anti-rollback on reboot\n");
}

static void test_policy_canary_rollback(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->device.policy_version = 5;

    uint8_t blob[64];
    size_t len;
    make_policy_blob(blob, &len, 6, 2); /* baseline = 2 blocks/min */

    uint8_t sig[64];
    make_valid_signature_for(blob, len, sig);

    dclaw_apply_policy(blob, (uint32_t)len, sig);
    assert(s->canary.canary_active == true);

    /* Simulate spike: 15 blocks in minute 0 (threshold = 2 * 5 = 10) */
    for (int i = 0; i < 15; i++) {
        dclaw_canary_record_block();
    }

    /* Advance to minute 1, then 2, then 3 — each with spike */
    s->canary.canary_minute = 0;
    s->canary.canary_blocks[0] = 15; /* spike */
    s->canary.canary_minute = 1;
    /* Simulate dclaw_canary_tick detecting spike */
    uint16_t threshold = s->canary.baseline_blocks_per_min * DCLAW_CANARY_SPIKE_MULT;
    assert(s->canary.canary_blocks[0] > threshold);
    (void)threshold;

    /* Manually trigger rollback path */
    s->canary.spike_streak = DCLAW_CANARY_SPIKE_CONSEC;
    dclaw_policy_rollback();

    assert(s->canary.canary_active == false);
    assert(s->device.policy_version == 6); /* signed anti-rollback watermark */
    uint8_t heartbeat[40];
    size_t heartbeat_len = 0;
    assert(dclaw_cbor_encode_heartbeat(heartbeat, &heartbeat_len, sizeof(heartbeat)) == 0);
    assert(heartbeat_len == sizeof(heartbeat));
    assert(heartbeat[8] == 0 && heartbeat[9] == 6); /* report watermark, not active v5 */
    assert((heartbeat[30] & 0x08) != 0); /* surface the canary rollback */
    assert(dclaw_apply_policy(blob, (uint32_t)len, sig) == -2); /* captured v6 cannot replay */
    printf("  PASS: canary rollback heartbeat reports high-water version and rollback flag\n");
}

static void test_canary_final_minute(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint8_t blob[64], sig[64];
    size_t len;
    make_policy_blob(blob, &len, 7, 2);
    make_valid_signature_for(blob, len, sig);
    assert(dclaw_apply_policy(blob, (uint32_t)len, sig) == 0);
    assert(!s->rollback_pending); /* durable higher version clears prior rollback */
    s->canary.canary_started_at = 1000000;
    s->canary.canary_minute = 7;
    s->canary.canary_blocks[7] = 15;
    s->canary.canary_blocks[8] = 15;
    s->canary.canary_blocks[9] = 15;
    dclaw_canary_tick_at(1000000 + 8 * 60000);
    assert(s->canary.spike_streak == 1);
    dclaw_canary_tick_at(1000000 + 9 * 60000);
    assert(s->canary.spike_streak == 2);
    dclaw_canary_tick_at(1000000 + 10 * 60000);
    assert(!s->canary.canary_active && s->rollback_pending);
    assert(s->device.policy_version == 7);
    printf("  PASS: final canary minute is scored before window expiry\n");
}

/* === Emergency Broadcast Tests === */

static void make_emergency_msg(uint8_t *buf, uint32_t seq, uint32_t prev,
                               uint8_t cmd, bool valid_sig) {
    memset(buf, 0, 112);
    /* sequence (4 bytes BE) */
    buf[0] = (uint8_t)(seq >> 24);
    buf[1] = (uint8_t)(seq >> 16);
    buf[2] = (uint8_t)(seq >> 8);
    buf[3] = (uint8_t)seq;
    /* timestamp (4 bytes) */
    buf[4] = 0; buf[5] = 0; buf[6] = 0x01; buf[7] = 0x00;
    /* command */
    buf[8] = cmd;
    /* scope */
    buf[9] = 0x00; /* ALL_DEVICES */
    /* payload[32] + reserved[2] = 34 bytes of zeros (already memset) */
    buf[44] = (uint8_t)(prev >> 24);
    buf[45] = (uint8_t)(prev >> 16);
    buf[46] = (uint8_t)(prev >> 8);
    buf[47] = (uint8_t)prev;
    /* signature at offset 48 — sign the first 48 bytes */
    if (valid_sig) {
        make_valid_signature_for(buf, 48, buf + 48);
    } else {
        make_invalid_signature(buf + 48);
    }
}

static void test_emergency_valid_applies(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->emergency.last_seen_seq = 0;

    uint8_t msg[112];
    make_emergency_msg(msg, 1, 0, 0x01, true); /* BLOCK_ALL, seq=1 */

    int rc = dclaw_apply_emergency(msg, sizeof(msg));
    assert(rc == 0);
    assert(s->emergency.last_seen_seq == 1);
    (void)rc;
    printf("  PASS: valid emergency broadcast applied\n");
}

static void test_emergency_invalid_sig_rejected(void) {
    uint8_t msg[112];
    make_emergency_msg(msg, 2, 1, 0x01, false);

    int rc = dclaw_apply_emergency(msg, sizeof(msg));
    assert(rc == -1);
    (void)rc;
    printf("  PASS: emergency with invalid signature rejected\n");

    make_emergency_msg(msg, 2, 1, 0x01, true);
    msg[111] = 1; /* reject nonzero HMAC padding, including final byte */
    assert(dclaw_apply_emergency(msg, sizeof(msg)) == -1);
    printf("  PASS: emergency HMAC padding tamper rejected\n");
}

static void test_emergency_replay_rejected(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->emergency.last_seen_seq = 5;

    uint8_t msg[112];
    make_emergency_msg(msg, 3, 1, 0x01, true); /* seq 3 < last_seen 5 */

    int rc = dclaw_apply_emergency(msg, sizeof(msg));
    assert(rc == -2);
    (void)rc;
    printf("  PASS: replayed emergency (old sequence) rejected\n");
}

static void test_emergency_predecessor_gap(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->emergency.last_seen_seq = 5;

    uint8_t msg[112];
    make_emergency_msg(msg, 5 + 1001, 5 + 1000, 0x03, true);

    int rc = dclaw_apply_emergency(msg, sizeof(msg));
    assert(rc == -3);
    assert(s->emergency.last_seen_seq == 5);
    make_emergency_msg(msg, 5 + 1001, 5, 0x03, true);
    assert(dclaw_apply_emergency(msg, sizeof(msg)) == 0);
    assert(s->emergency.last_seen_seq == 5 + 1001);
    (void)rc;
    printf("  PASS: missing predecessor rejects out-of-order command; global gap with correct predecessor accepted\n");
}

static void test_emergency_gap_detection(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->emergency.last_seen_seq = 5;
    s->emergency.replay_requested = false;

    bool has_gap = dclaw_emergency_has_gap(10); /* cloud is at 10, device at 5 */
    assert(has_gap == true);
    assert(s->emergency.gap_start == 6);
    assert(s->emergency.replay_requested == true);
    (void)has_gap;
    printf("  PASS: emergency sequence gap detected, replay requested\n");
}

static void test_emergency_no_gap(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->emergency.last_seen_seq = 10;

    bool has_gap = dclaw_emergency_has_gap(11); /* exactly one ahead = no gap */
    assert(has_gap == false);
    (void)has_gap;
    printf("  PASS: no gap when cloud is exactly 1 ahead\n");
}

/* Force the OTA key loader to re-read from env on next call */
extern void dclaw_ota_reset_key_state(void);

static void test_unprovisioned_key_rejects_valid_signature(void) {
    /* Unset the OTA key — should reject even a correctly signed blob */
    unsetenv("DCLAW_OTA_HMAC_KEY");
    setenv("DCLAW_OTA_KEY", TEST_OTA_KEY_HEX, 1); /* public key is not an HMAC secret */
    dclaw_ota_reset_key_state();

    dclaw_state_t *s = dclaw_get_state();
    uint16_t saved_version = s->device.policy_version;

    uint8_t blob[64];
    size_t len;
    make_policy_blob(blob, &len, saved_version + 1, 5);

    /* Sign with zero key (what the old code would have accepted) */
    uint8_t sig[64];
    memset(sig, 0, 64);
    uint8_t zero_key[32];
    memset(zero_key, 0, sizeof(zero_key));
    dclaw_hmac_sha256(zero_key, 32, blob, len, sig);

    int rc = dclaw_apply_policy(blob, (uint32_t)len, sig);
    assert(rc == -1); /* Must reject — no key provisioned */
    assert(s->device.policy_version == saved_version); /* Version unchanged */
    make_valid_signature_for(blob, len, sig);
    rc = dclaw_apply_policy(blob, (uint32_t)len, sig);
    assert(rc == -1); /* Public DCLAW_OTA_KEY must never sign an HMAC update */
    (void)rc; (void)saved_version;
    printf("  PASS: unprovisioned key and public-key HMAC forgery rejected\n");

    /* Restore both test keys for subsequent tests */
    unsetenv("DCLAW_OTA_KEY");
    setenv("DCLAW_OTA_HMAC_KEY", TEST_OTA_KEY_HEX, 1);
    setenv("DCLAW_EMERGENCY_KEY", TEST_OTA_KEY_HEX, 1);
    dclaw_ota_reset_key_state();
}

static void test_release_counter_redundancy(void) {
    uint8_t blank[12] = {0};
    uint8_t damaged = 0;
    assert(hal_flash_write(HAL_FLASH_CONFIG_OFFSET + 32, blank, sizeof(blank)) == 0);
    assert(hal_flash_write(HAL_FLASH_CONFIG_OFFSET + 48, blank, sizeof(blank)) == 0);
    assert(hal_flash_sync() == 0);
    assert(dclaw_load_lockdown_release_seq() == 0);
    assert(dclaw_store_lockdown_release_seq(1) == 0);
    assert(dclaw_load_lockdown_release_seq() == 1);
    assert(dclaw_store_lockdown_release_seq(1) == -1);
    assert(hal_flash_write(HAL_FLASH_CONFIG_OFFSET + 32, &damaged, 1) == 0);
    assert(dclaw_load_lockdown_release_seq() == 1); /* backup B survives */
    assert(dclaw_store_lockdown_release_seq(2) == 0); /* next signed release repairs A */
    assert(dclaw_load_lockdown_release_seq() == 2);
    assert(hal_flash_write(HAL_FLASH_CONFIG_OFFSET + 48, &damaged, 1) == 0);
    assert(dclaw_load_lockdown_release_seq() == 2); /* repaired A survives B corruption */
    assert(hal_flash_write(HAL_FLASH_CONFIG_OFFSET + 32, &damaged, 1) == 0);
    assert(dclaw_load_lockdown_release_seq() == UINT32_MAX); /* both corrupt: fail closed */
    printf("  PASS: release counter persists, rejects replay, repairs one torn copy, and fails closed on two\n");
}

static void test_boot_counter_durability(void) {
    uint32_t initial = dclaw_boot_counter_get();
    assert(initial > 0);
    uint8_t heartbeat[40];
    size_t length = 0;
    assert(dclaw_cbor_encode_heartbeat(heartbeat, &length, sizeof(heartbeat)) == 0);
    assert(length == 40);
    assert(heartbeat[32] == (uint8_t)(initial >> 24));
    assert(heartbeat[33] == (uint8_t)(initial >> 16));
    assert(heartbeat[34] == (uint8_t)(initial >> 8));
    assert(heartbeat[35] == (uint8_t)initial);
    assert(heartbeat[36] == (uint8_t)(dclaw_get_state()->emergency.last_seen_seq >> 24));
    assert(heartbeat[39] == (uint8_t)dclaw_get_state()->emergency.last_seen_seq);
    assert(dclaw_boot_counter_advance() == 0);
    assert(dclaw_boot_counter_get() == initial + 1);
    uint8_t damaged = 0;
    assert(hal_flash_write(HAL_FLASH_CONFIG_OFFSET + 64, &damaged, 1) == 0);
    assert(dclaw_boot_counter_advance() == 0); /* B survives and A repairs */
    assert(dclaw_boot_counter_get() == initial + 2);
    assert(hal_flash_write(HAL_FLASH_CONFIG_OFFSET + 80, &damaged, 1) == 0);
    assert(dclaw_boot_counter_advance() == 0); /* A survives and B repairs */
    assert(dclaw_boot_counter_get() == initial + 3);
    assert(hal_flash_write(HAL_FLASH_CONFIG_OFFSET + 64, &damaged, 1) == 0);
    assert(hal_flash_write(HAL_FLASH_CONFIG_OFFSET + 80, &damaged, 1) == 0);
    assert(dclaw_boot_counter_advance() == -1); /* both corrupt: fail closed */
    assert(dclaw_boot_counter_get() == 0);
    printf("  PASS: signed heartbeat includes durable boot generation; one copy repairs and two corrupt copies fail closed\n");
}

int main(void) {
    /* The test intentionally corrupts both boot-counter copies. Start from
     * its dedicated fixture on every run so CTest is repeatable. */
    const char *flash_path = getenv("DCLAW_FLASH_PATH");
    if (flash_path && strstr(flash_path, "flash-ota-emergency.bin"))
        unlink(flash_path);
    /* Set test keys for both OTA and emergency signature verification */
    setenv("DCLAW_OTA_HMAC_KEY", TEST_OTA_KEY_HEX, 1);
    setenv("DCLAW_EMERGENCY_KEY", TEST_OTA_KEY_HEX, 1);

    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    dclaw_init(&info);

    printf("test_ota_emergency:\n");
    printf(" -- Policy OTA --\n");
    test_policy_apply_valid();
    test_policy_invalid_signature_rejected();
    test_policy_rollback_version_rejected();
    test_reserved_policy_version_rejected();
    test_policy_canary_rollback();
    test_canary_final_minute();
    test_unprovisioned_key_rejects_valid_signature();
    test_release_counter_redundancy();
    printf(" -- Emergency Broadcast --\n");
    test_emergency_valid_applies();
    test_emergency_invalid_sig_rejected();
    test_emergency_replay_rejected();
    test_emergency_predecessor_gap();
    test_emergency_gap_detection();
    test_emergency_no_gap();
    test_boot_counter_durability();
    printf("  ALL PASSED (12 tests)\n");

    dclaw_shutdown();
    return 0;
}
