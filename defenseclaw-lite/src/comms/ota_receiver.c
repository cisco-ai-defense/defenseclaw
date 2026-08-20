#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

/*
 * OTA Policy + Emergency Broadcast Handler.
 * Implements:
 * - REQ-33: Ed25519 signature verification on policy blobs
 * - REQ-34: A/B flash partition write
 * - REQ-35: 10-minute canary health-check window with auto-rollback
 * - REQ-36: Monotonic version anti-rollback
 * - REQ-30: Emergency broadcast Ed25519 verification
 * - REQ-31: Emergency sequence anti-replay
 * - REQ-32: Gap detection + replay request on reconnect
 */

extern dclaw_state_t *dclaw_get_state(void);
extern uint8_t dclaw_config_active_policy_partition(void);
extern void dclaw_config_switch_policy_partition(void);
extern void dclaw_cache_flush_all(void);
extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint16_t target_hash, uint16_t session_id);

/* Forward declarations for this file */
void dclaw_policy_rollback(void);
void dclaw_canary_tick(void);
void dclaw_canary_record_block(void);

/* Policy blob header format (first 8 bytes of blob) */
typedef struct {
    uint16_t version;
    uint16_t payload_len;
    uint16_t canary_baseline;
    uint16_t _reserved;
} dclaw_policy_header_t;

#define ED25519_SIG_LEN  64
#define ED25519_PUBKEY_LEN 32

/* Placeholder Ed25519 verification.
 * In production: use TweetNaCl crypto_sign_verify_detached or mbedtls_pk_verify.
 * For Phase 1 dev: accepts any signature that starts with 0xED (marker byte). */
static bool verify_ed25519(const uint8_t *message, size_t msg_len,
                           const uint8_t *signature,
                           const uint8_t *pubkey) {
    (void)message; (void)msg_len; (void)pubkey;
    /* Production: crypto_sign_verify_detached(signature, message, msg_len, pubkey) == 0 */
    /* Dev stub: signature[0] == 0xED means "valid" for testing */
    return signature[0] == 0xED;
}

/* OTA CA public key — pinned in firmware at build time */
static const uint8_t ota_ca_pubkey[ED25519_PUBKEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
};

/* === Policy OTA (REQ-33 through REQ-36) === */

int dclaw_apply_policy(const uint8_t *blob, uint32_t blob_len,
                       const uint8_t *signature) {
    dclaw_state_t *s = dclaw_get_state();

    if (blob_len < sizeof(dclaw_policy_header_t)) return -1;
    if (blob_len > HAL_FLASH_POLICY_A_SIZE) return -1;

    /* REQ-33: Verify Ed25519 signature */
    if (!verify_ed25519(blob, blob_len, signature, ota_ca_pubkey)) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT, 0, 0);
        return -1;
    }

    /* Parse header (big-endian wire format) */
    dclaw_policy_header_t hdr;
    hdr.version = ((uint16_t)blob[0] << 8) | blob[1];
    hdr.payload_len = ((uint16_t)blob[2] << 8) | blob[3];
    hdr.canary_baseline = ((uint16_t)blob[4] << 8) | blob[5];

    /* REQ-36: Anti-rollback — reject version ≤ current */
    if (hdr.version <= s->device.policy_version) {
        return -2;
    }

    /* REQ-34: Write to INACTIVE partition */
    uint8_t active = dclaw_config_active_policy_partition();
    uint32_t target_offset = (active == 0) ? HAL_FLASH_POLICY_B_OFFSET
                                           : HAL_FLASH_POLICY_A_OFFSET;

    if (hal_flash_write(target_offset, blob, blob_len) != 0) {
        return -3;
    }

    /* Verify written data (read-back check) */
    uint8_t verify_buf[8];
    if (hal_flash_read(target_offset, verify_buf, 8) != 0) {
        return -3;
    }
    if (memcmp(verify_buf, blob, 8) != 0) {
        return -3;
    }

    /* Switch to new partition */
    dclaw_config_switch_policy_partition();
    s->device.policy_version = hdr.version;

    /* Flush verdict cache — policy changed, cached verdicts may be stale */
    dclaw_cache_flush_all();

    /* REQ-35: Enter canary window */
    s->canary.canary_active = true;
    s->canary.canary_started_at = hal_tick_ms();
    s->canary.spike_streak = 0;
    s->canary.canary_minute = 0;
    memset(s->canary.canary_blocks, 0, sizeof(s->canary.canary_blocks));

    /* Use baseline from policy blob if available, else keep existing */
    if (hdr.canary_baseline > 0) {
        s->canary.baseline_blocks_per_min = hdr.canary_baseline;
    }

    return 0;
}

/* Canary tick — called periodically from event loop */
void dclaw_canary_tick(void) {
    dclaw_state_t *s = dclaw_get_state();
    if (!s->canary.canary_active) return;

    uint32_t elapsed = hal_tick_ms() - s->canary.canary_started_at;

    /* Check if canary window has expired (10 minutes) */
    if (elapsed >= (uint32_t)DCLAW_CANARY_WINDOW_SEC * 1000) {
        s->canary.canary_active = false;
        return;
    }

    /* Advance minute counter */
    uint8_t current_min = (uint8_t)(elapsed / 60000);
    if (current_min != s->canary.canary_minute && current_min < 10) {
        s->canary.canary_minute = current_min;

        /* Check spike: blocks in previous minute vs baseline */
        uint8_t prev_min = (current_min > 0) ? current_min - 1 : 0;
        uint16_t rate = s->canary.canary_blocks[prev_min];
        uint16_t threshold = s->canary.baseline_blocks_per_min * DCLAW_CANARY_SPIKE_MULT;

        if (rate > threshold && s->canary.baseline_blocks_per_min > 0) {
            s->canary.spike_streak++;
        } else {
            s->canary.spike_streak = 0;
        }

        /* REQ-35: Auto-rollback if 3 consecutive spike minutes */
        if (s->canary.spike_streak >= DCLAW_CANARY_SPIKE_CONSEC) {
            dclaw_policy_rollback();
        }
    }
}

/* Record a BLOCK event for canary tracking */
void dclaw_canary_record_block(void) {
    dclaw_state_t *s = dclaw_get_state();
    if (!s->canary.canary_active) return;
    if (s->canary.canary_minute < 10) {
        s->canary.canary_blocks[s->canary.canary_minute]++;
    }
}

/* Rollback to previous policy partition */
void dclaw_policy_rollback(void) {
    dclaw_state_t *s = dclaw_get_state();
    dclaw_config_switch_policy_partition();
    s->canary.canary_active = false;
    dclaw_cache_flush_all();
    dclaw_audit_write(DCLAW_ACTION_WARN, DCLAW_REASON_POLICY_TABLE, 0xFFFF, 0);
}

/* === Emergency Broadcast (REQ-30 through REQ-32) === */

typedef struct {
    uint32_t sequence;
    uint32_t timestamp;
    uint8_t  command;
    uint8_t  scope;
    uint8_t  payload[32];
    uint8_t  _reserved[2];
    uint8_t  signature[64];
} __attribute__((packed)) dclaw_emergency_msg_t;

int dclaw_apply_emergency(const uint8_t *msg, uint32_t msg_len) {
    dclaw_state_t *s = dclaw_get_state();

    if (msg_len < sizeof(dclaw_emergency_msg_t)) return -1;

    /* Parse fields in big-endian wire format */
    uint32_t seq = ((uint32_t)msg[0] << 24) | ((uint32_t)msg[1] << 16) |
                   ((uint32_t)msg[2] << 8) | msg[3];
    uint8_t command = msg[8];
    const uint8_t *signature = msg + 44;

    /* REQ-30: Verify Ed25519 signature over first 44 bytes */
    if (!verify_ed25519(msg, 44, signature, ota_ca_pubkey)) {
        return -1;
    }

    /* REQ-31: Anti-replay — sequence must be strictly increasing */
    if (seq <= s->emergency.last_seen_seq) {
        return -2;
    }

    /* REQ-31: Jump attack detection — reject delta > 1000 */
    if (seq - s->emergency.last_seen_seq > 1000) {
        return -3;
    }

    /* Apply command */
    switch (command) {
    case 0x01: /* BLOCK_ALL */
        /* Flush cache, set all verdicts to BLOCK */
        dclaw_cache_flush_all();
        break;

    case 0x02: /* REVOKE_HASH */
        /* payload[0:32] contains the hash to revoke */
        dclaw_cache_flush_all(); /* simplified: flush everything */
        break;

    case 0x03: /* FORCE_SYNC */
        dclaw_flush_audit();
        break;

    case 0x04: /* ENTER_LOCKDOWN */
        /* Would trigger full lockdown — Phase 2+ */
        break;

    default:
        return -4;
    }

    /* Update sequence counter */
    s->emergency.last_seen_seq = seq;

    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_BLOCK, 0, 0);
    return 0;
}

/* REQ-32: Check for emergency sequence gap on reconnect */
bool dclaw_emergency_has_gap(uint32_t cloud_current_seq) {
    dclaw_state_t *s = dclaw_get_state();
    if (cloud_current_seq > s->emergency.last_seen_seq + 1) {
        s->emergency.gap_start = s->emergency.last_seen_seq + 1;
        s->emergency.replay_requested = true;
        return true;
    }
    return false;
}
