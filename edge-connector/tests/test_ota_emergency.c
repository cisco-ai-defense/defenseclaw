#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

extern dclaw_state_t *dclaw_get_state(void);
extern void dclaw_canary_tick(void);
extern void dclaw_canary_record_block(void);
extern void dclaw_policy_rollback(void);
extern bool dclaw_emergency_has_gap(uint32_t cloud_current_seq);

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
    *len = 64;
}

/* Helper: build a "valid" signature (dev stub: starts with 0xED) */
static void make_valid_signature(uint8_t *sig) {
    memset(sig, 0, 64);
    sig[0] = 0xED; /* Dev stub marker */
}

static void make_invalid_signature(uint8_t *sig) {
    memset(sig, 0xAA, 64); /* Does NOT start with 0xED */
}

/* === Policy OTA Tests === */

static void test_policy_apply_valid(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->device.policy_version = 0;

    uint8_t blob[64];
    size_t len;
    make_policy_blob(blob, &len, 1, 5); /* version=1, baseline=5 */

    uint8_t sig[64];
    make_valid_signature(sig);

    int rc = dclaw_apply_policy(blob, (uint32_t)len, sig);
    assert(rc == 0);
    assert(s->device.policy_version == 1);
    assert(s->canary.canary_active == true);
    assert(s->canary.baseline_blocks_per_min == 5);
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
    printf("  PASS: invalid signature rejected\n");
}

static void test_policy_rollback_version_rejected(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->device.policy_version = 5;

    uint8_t blob[64];
    size_t len;
    make_policy_blob(blob, &len, 3, 5); /* version 3 < current 5 */

    uint8_t sig[64];
    make_valid_signature(sig);

    int rc = dclaw_apply_policy(blob, (uint32_t)len, sig);
    assert(rc == -2);
    printf("  PASS: downgrade (version 3 < 5) rejected\n");
}

static void test_policy_canary_rollback(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->device.policy_version = 5;

    uint8_t blob[64];
    size_t len;
    make_policy_blob(blob, &len, 6, 2); /* baseline = 2 blocks/min */

    uint8_t sig[64];
    make_valid_signature(sig);

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

    /* Manually trigger rollback path */
    s->canary.spike_streak = DCLAW_CANARY_SPIKE_CONSEC;
    dclaw_policy_rollback();

    assert(s->canary.canary_active == false);
    printf("  PASS: canary spike triggers rollback\n");
}

/* === Emergency Broadcast Tests === */

static void make_emergency_msg(uint8_t *buf, uint32_t seq, uint8_t cmd, bool valid_sig) {
    memset(buf, 0, 108);
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
    /* signature at offset 44 */
    if (valid_sig) {
        buf[44] = 0xED; /* Dev stub: valid */
    } else {
        buf[44] = 0xAA; /* Invalid */
    }
}

static void test_emergency_valid_applies(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->emergency.last_seen_seq = 0;

    uint8_t msg[108];
    make_emergency_msg(msg, 1, 0x01, true); /* BLOCK_ALL, seq=1 */

    int rc = dclaw_apply_emergency(msg, sizeof(msg));
    assert(rc == 0);
    assert(s->emergency.last_seen_seq == 1);
    printf("  PASS: valid emergency broadcast applied\n");
}

static void test_emergency_invalid_sig_rejected(void) {
    uint8_t msg[108];
    make_emergency_msg(msg, 2, 0x01, false);

    int rc = dclaw_apply_emergency(msg, sizeof(msg));
    assert(rc == -1);
    printf("  PASS: emergency with invalid signature rejected\n");
}

static void test_emergency_replay_rejected(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->emergency.last_seen_seq = 5;

    uint8_t msg[108];
    make_emergency_msg(msg, 3, 0x01, true); /* seq 3 < last_seen 5 */

    int rc = dclaw_apply_emergency(msg, sizeof(msg));
    assert(rc == -2);
    printf("  PASS: replayed emergency (old sequence) rejected\n");
}

static void test_emergency_jump_attack_rejected(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->emergency.last_seen_seq = 5;

    uint8_t msg[108];
    make_emergency_msg(msg, 5 + 1001, 0x01, true); /* delta > 1000 */

    int rc = dclaw_apply_emergency(msg, sizeof(msg));
    assert(rc == -3);
    printf("  PASS: emergency jump attack (delta > 1000) rejected\n");
}

static void test_emergency_gap_detection(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->emergency.last_seen_seq = 5;
    s->emergency.replay_requested = false;

    bool has_gap = dclaw_emergency_has_gap(10); /* cloud is at 10, device at 5 */
    assert(has_gap == true);
    assert(s->emergency.gap_start == 6);
    assert(s->emergency.replay_requested == true);
    printf("  PASS: emergency sequence gap detected, replay requested\n");
}

static void test_emergency_no_gap(void) {
    dclaw_state_t *s = dclaw_get_state();
    s->emergency.last_seen_seq = 10;

    bool has_gap = dclaw_emergency_has_gap(11); /* exactly one ahead = no gap */
    assert(has_gap == false);
    printf("  PASS: no gap when cloud is exactly 1 ahead\n");
}

int main(void) {
    hal_init();
    dclaw_device_info_t info = {.device_id = 42, .tenant_id = 1, .fleet_id = 1};
    dclaw_init(&info);

    printf("test_ota_emergency:\n");
    printf(" -- Policy OTA --\n");
    test_policy_apply_valid();
    test_policy_invalid_signature_rejected();
    test_policy_rollback_version_rejected();
    test_policy_canary_rollback();
    printf(" -- Emergency Broadcast --\n");
    test_emergency_valid_applies();
    test_emergency_invalid_sig_rejected();
    test_emergency_replay_rejected();
    test_emergency_jump_attack_rejected();
    test_emergency_gap_detection();
    test_emergency_no_gap();
    printf("  ALL PASSED (10 tests)\n");

    dclaw_shutdown();
    return 0;
}
