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
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * OTA Policy + Emergency Broadcast Handler.
 * Implements:
 * - REQ-33: explicit HMAC-SHA256 verification on policy blobs
 * - REQ-34: A/B flash partition write
 * - REQ-35: 10-minute canary health-check window with auto-rollback
 * - REQ-36: Monotonic version anti-rollback
 * - REQ-30: emergency broadcast HMAC-SHA256 verification
 * - REQ-31: Emergency sequence anti-replay
 * - REQ-32: Gap detection + replay request on reconnect
 */

extern dclaw_state_t *dclaw_get_state(void);
extern uint8_t dclaw_config_active_policy_partition(void);
extern int dclaw_config_switch_policy_partition(uint16_t policy_version);
extern void dclaw_cache_flush_all(void);
extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint32_t target_hash, uint16_t session_id);

/* Forward declarations for this file */
void dclaw_policy_rollback(void);
void dclaw_canary_tick(void);
void dclaw_canary_record_block(void);
int dclaw_policy_reload_from_flash(void);
int dclaw_emergency_persist(void);
int dclaw_emergency_load_from_flash(void);

/* Policy blob header format (first 8 bytes of blob) */
typedef struct {
    uint16_t version;
    uint16_t payload_len;
    uint16_t canary_baseline;
    uint16_t _reserved;
} dclaw_policy_header_t;

#define OTA_KEY_LEN 32
#define OTA_SIGNATURE_LEN 64

/* Ed25519 verification is not linked in this connector. HMAC is a distinct,
 * explicit mode: a public DCLAW_OTA_KEY is never interpreted as a secret. */
#ifndef DCLAW_ALLOW_HMAC_OTA
#define DCLAW_ALLOW_HMAC_OTA 0
#endif

static uint8_t ota_hmac_key[OTA_KEY_LEN];
static bool ota_hmac_key_loaded = false;
static bool ota_hmac_key_provisioned = false;

void dclaw_ota_reset_key_state(void) {
    ota_hmac_key_loaded = false;
    ota_hmac_key_provisioned = false;
    dclaw_secure_zero(ota_hmac_key, sizeof(ota_hmac_key));
}

static bool key_is_nonzero(const uint8_t key[OTA_KEY_LEN]) {
    uint8_t bits = 0;
    for (size_t i = 0; i < OTA_KEY_LEN; i++) bits |= key[i];
    return bits != 0;
}

static bool load_ota_hmac_key(void) {
    if (ota_hmac_key_loaded) return ota_hmac_key_provisioned;
    ota_hmac_key_loaded = true;
    const char *env = getenv("DCLAW_OTA_HMAC_KEY");
    if (!env || strlen(env) != OTA_KEY_LEN * 2 ||
        dclaw_hex_decode(env, ota_hmac_key, OTA_KEY_LEN) != 0 ||
        !key_is_nonzero(ota_hmac_key)) {
        dclaw_secure_zero(ota_hmac_key, sizeof(ota_hmac_key));
        fprintf(stderr, "[DCLAW] REJECT: DCLAW_OTA_HMAC_KEY must be a nonzero 32-byte hex secret. "
                        "DCLAW_OTA_KEY is not an HMAC key.\n");
        return false;
    }
    ota_hmac_key_provisioned = true;
    dclaw_scrub_env("DCLAW_OTA_HMAC_KEY");
    return true;
}

/* Both policy and emergency messages reserve 64 signature bytes. HMAC mode
 * uses the first 32 bytes and requires the other 32 to be zero so a wire
 * message cannot be ambiguously interpreted as an Ed25519 signature. */
static bool verify_hmac_signature(const uint8_t *message, size_t msg_len,
                                  const uint8_t *signature,
                                  const uint8_t key[OTA_KEY_LEN]) {
    uint8_t tail_bits = 0;
    for (size_t i = OTA_KEY_LEN; i < OTA_SIGNATURE_LEN; i++)
        tail_bits |= signature[i];
    uint8_t expected[OTA_KEY_LEN];
    dclaw_hmac_sha256(key, OTA_KEY_LEN, message, msg_len, expected);
    bool valid = (tail_bits == 0) && ct_compare(signature, expected, OTA_KEY_LEN);
    dclaw_secure_zero(expected, sizeof(expected));
    return valid;
}

static bool verify_signature(const uint8_t *message, size_t msg_len,
                             const uint8_t *signature) {
    if (!DCLAW_DEV_MODE && !DCLAW_ALLOW_HMAC_OTA) {
        fprintf(stderr, "[DCLAW] REJECT: OTA HMAC disabled in production; "
                        "rebuild with explicit DCLAW_ALLOW_HMAC_OTA=ON.\n");
        return false;
    }
    if (!load_ota_hmac_key()) return false;
    return verify_hmac_signature(message, msg_len, signature, ota_hmac_key);
}

/* === Policy OTA (REQ-33 through REQ-36) === */

int dclaw_apply_policy(const uint8_t *blob, uint32_t blob_len,
                       const uint8_t *signature) {
    dclaw_state_t *s = dclaw_get_state();

    if (blob_len < sizeof(dclaw_policy_header_t)) return -1;
    if (blob_len > HAL_FLASH_POLICY_A_SIZE - OTA_SIGNATURE_LEN) return -1;

    /* REQ-33: Explicit HMAC mode with a separately provisioned secret.
     * Unsupported Ed25519 configurations fail closed. */
    if (!verify_signature(blob, blob_len, signature)) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT, 0, 0);
        return -1;
    }

    /* Parse header (big-endian wire format) */
    dclaw_policy_header_t hdr;
    hdr.version = ((uint16_t)blob[0] << 8) | blob[1];
    hdr.payload_len = ((uint16_t)blob[2] << 8) | blob[3];
    hdr.canary_baseline = ((uint16_t)blob[4] << 8) | blob[5];

    /* 0xFFFF is the erased-flash sentinel in the persisted version record.
     * Accepting it would reset the anti-rollback watermark on reboot. */
    if (hdr.version == 0 || hdr.version == UINT16_MAX) return -2;

    {
        uint32_t expected_total = (uint32_t)sizeof(dclaw_policy_header_t)
                                + (uint32_t)hdr.payload_len;
        if (expected_total != blob_len) {
            dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT, 0, 0);
            return -1; /* payload length mismatch */
        }
    }

    /* REQ-36: Anti-rollback — reject version ≤ current */
    if (hdr.version <= s->device.policy_version) {
        return -2;
    }

    /* REQ-34: Write to INACTIVE partition */
    uint8_t active = dclaw_config_active_policy_partition();
    uint32_t target_offset = (active == 0) ? HAL_FLASH_POLICY_B_OFFSET
                                           : HAL_FLASH_POLICY_A_OFFSET;

    if (hal_flash_write(target_offset, blob, blob_len) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Flash write failed for policy blob (%u bytes at offset 0x%x) — "
                "aborting OTA apply, partition NOT switched\n",
                blob_len, target_offset);
        return -3;
    }
    if (hal_flash_write(target_offset + HAL_FLASH_POLICY_A_SIZE - OTA_SIGNATURE_LEN,
                        signature, OTA_SIGNATURE_LEN) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Flash write failed for policy signature.\n");
        return -3;
    }

    if (hal_flash_sync() != 0) {
        fprintf(stderr, "[DCLAW] ERROR: hal_flash_sync() failed after policy write — "
                "aborting OTA apply, partition NOT switched\n");
        return -3;
    }

    /* Read back every policy byte and the signed trailer before committing
     * the partition switch. A matching header alone cannot detect payload
     * corruption that changes an allow/deny rule. */
    static uint8_t verify_buf[HAL_FLASH_POLICY_A_SIZE];
    if (hal_flash_read(target_offset, verify_buf, blob_len) != 0 ||
        hal_flash_read(target_offset + HAL_FLASH_POLICY_A_SIZE - OTA_SIGNATURE_LEN,
                       verify_buf + HAL_FLASH_POLICY_A_SIZE - OTA_SIGNATURE_LEN,
                       OTA_SIGNATURE_LEN) != 0) {
        return -3;
    }
    if (memcmp(verify_buf, blob, blob_len) != 0 ||
        memcmp(verify_buf + HAL_FLASH_POLICY_A_SIZE - OTA_SIGNATURE_LEN,
               signature, OTA_SIGNATURE_LEN) != 0) {
        return -3;
    }

    if (dclaw_config_switch_policy_partition(hdr.version) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: OTA policy partition switch could not be persisted.\n");
        return -3;
    }
    s->device.policy_version = hdr.version;

    /* Flush verdict cache — policy changed, cached verdicts may be stale */
    dclaw_cache_flush_all();

    /* Reload the mutable policy tables from the new flash contents. */
    if (dclaw_policy_reload_from_flash() != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Persisted policy failed validation after switch; rolling back.\n");
        dclaw_policy_rollback();
        return -3;
    }

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
void dclaw_canary_tick_at(uint64_t now_ms) {
    dclaw_state_t *s = dclaw_get_state();
    if (!s->canary.canary_active) return;

    if (now_ms < s->canary.canary_started_at) return;
    uint64_t elapsed = now_ms - s->canary.canary_started_at;

    /* Advance minute counter */
    uint8_t current_min = (uint8_t)(elapsed / 60000 > 10 ? 10 : elapsed / 60000);
    if (current_min != s->canary.canary_minute && current_min <= 10) {
        s->canary.canary_minute = current_min;

        /* Check spike: blocks in previous minute vs baseline */
        uint8_t prev_min = (current_min > 0) ? current_min - 1 : 0;
        uint64_t rate = s->canary.canary_blocks[prev_min];
        uint64_t threshold = (uint64_t)s->canary.baseline_blocks_per_min * DCLAW_CANARY_SPIKE_MULT;

        if (rate > threshold && s->canary.baseline_blocks_per_min > 0) {
            s->canary.spike_streak++;
        } else {
            s->canary.spike_streak = 0;
        }

        /* REQ-35: Auto-rollback if 3 consecutive spike minutes */
        if (s->canary.spike_streak >= DCLAW_CANARY_SPIKE_CONSEC) {
            dclaw_policy_rollback();
            return;
        }
    }
    if (elapsed >= (uint64_t)DCLAW_CANARY_WINDOW_SEC * 1000)
        s->canary.canary_active = false;
}

void dclaw_canary_tick(void) {
    dclaw_canary_tick_at(hal_tick_ms());
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
    uint8_t active = dclaw_config_active_policy_partition();
    /* active=current partition (bad policy). The previous (good) policy is
     * on the inactive partition. switch_policy_partition flips active↔inactive,
     * so we read the version from the currently inactive partition first. */
    uint32_t prev_offset = (active == 0) ? HAL_FLASH_POLICY_B_OFFSET
                                         : HAL_FLASH_POLICY_A_OFFSET;
    uint16_t prev_version = 0;
    {
        uint8_t hdr_buf[8];
        if (hal_flash_read(prev_offset, hdr_buf, 8) == 0) {
            uint16_t plen = ((uint16_t)hdr_buf[2] << 8) | hdr_buf[3];
            if (plen > 0) {
                prev_version = ((uint16_t)hdr_buf[0] << 8) | hdr_buf[1];
            }
        }
    }
    /* Keep the highest signed version as the anti-rollback watermark. The
     * active partition can return to an older policy, but that rejected
     * release must not become replayable after reboot. */
    if (dclaw_config_switch_policy_partition(0) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Canary rollback partition switch could not be persisted.\n");
        return;
    }
    fprintf(stderr, "[DCLAW] Canary rollback restored partition policy version %u; "
                    "anti-rollback watermark remains %u.\n",
            prev_version, s->device.policy_version);
    s->canary.canary_active = false;
    s->rollback_pending = true;
    dclaw_cache_flush_all();

    if (dclaw_policy_reload_from_flash() != 0) {
        fprintf(stderr, "[DCLAW] WARNING: Rollback partition is blank or corrupt. "
                "Falling back to compiled-in policy defaults.\n");
        dclaw_policy_tables_init();
    }

    dclaw_audit_write(DCLAW_ACTION_WARN, DCLAW_REASON_POLICY_TABLE, 0xFFFF, 0);
}

/* === Emergency Broadcast (REQ-30 through REQ-32) === */

/*
 * Separate HMAC key for emergency command verification. There is no fallback
 * to the OTA key: that may be a public Ed25519 key or a different secret.
 */
static uint8_t emergency_ca_key[OTA_KEY_LEN];
static bool    emergency_ca_key_loaded = false;
static bool    emergency_ca_key_provisioned = false;

void dclaw_emergency_reset_key_state(void) {
    emergency_ca_key_loaded = false;
    emergency_ca_key_provisioned = false;
    dclaw_secure_zero(emergency_ca_key, sizeof(emergency_ca_key));
}

static const uint8_t *get_emergency_ca_key(void) {
    if (emergency_ca_key_loaded) return emergency_ca_key;
    emergency_ca_key_loaded = true;
    emergency_ca_key_provisioned = false;

    const char *env = getenv("DCLAW_EMERGENCY_KEY");
    if (env != NULL && strlen(env) == 64) {
        bool valid = (dclaw_hex_decode(env, emergency_ca_key, 32) == 0);
        if (valid) {
            bool all_zero = true;
            for (int i = 0; i < OTA_KEY_LEN; i++) {
                if (emergency_ca_key[i] != 0) { all_zero = false; break; }
            }
            if (!all_zero) {
                emergency_ca_key_provisioned = true;
                /* Best-effort scrub DCLAW_EMERGENCY_KEY from env */
                dclaw_scrub_env("DCLAW_EMERGENCY_KEY");
                fprintf(stderr, "[DCLAW] Emergency key loaded from DCLAW_EMERGENCY_KEY.\n");
                return emergency_ca_key;
            }
        }
    }

    fprintf(stderr, "[DCLAW] REJECT: DCLAW_EMERGENCY_KEY must be a nonzero 32-byte hex secret.\n");
    dclaw_secure_zero(emergency_ca_key, sizeof(emergency_ca_key));
    emergency_ca_key_provisioned = false;
    return emergency_ca_key;
}

const uint8_t *dclaw_emergency_get_key(size_t *out_len) {
    const uint8_t *key = get_emergency_ca_key();
    *out_len = emergency_ca_key_provisioned ? OTA_KEY_LEN : 0;
    return key;
}

static bool verify_emergency_signature(const uint8_t *message, size_t msg_len,
                                       const uint8_t *signature) {
    const uint8_t *key = get_emergency_ca_key();
    if (!emergency_ca_key_provisioned) {
        fprintf(stderr, "[DCLAW] REJECT: Emergency signature verification failed — "
                "no key provisioned. Set DCLAW_EMERGENCY_KEY.\n");
        return false;
    }
    return verify_hmac_signature(message, msg_len, signature, key);
}

typedef struct {
    uint32_t sequence;
    uint32_t timestamp;
    uint8_t  command;
    uint8_t  scope;
    uint8_t  payload[32];
    uint8_t  _reserved[2];
    uint32_t prev_fleet_seq;
    uint8_t  signature[64];
} __attribute__((packed)) dclaw_emergency_msg_t;

int dclaw_apply_emergency(const uint8_t *msg, uint32_t msg_len) {
    dclaw_state_t *s = dclaw_get_state();

    if (msg_len != sizeof(dclaw_emergency_msg_t)) return -1;

    /* Parse fields in big-endian wire format */
    uint32_t seq = ((uint32_t)msg[0] << 24) | ((uint32_t)msg[1] << 16) |
                   ((uint32_t)msg[2] << 8) | msg[3];
    uint8_t command = msg[8];
    uint32_t prev_fleet_seq = ((uint32_t)msg[44] << 24) | ((uint32_t)msg[45] << 16) |
                              ((uint32_t)msg[46] << 8) | msg[47];
    const uint8_t *signature = msg + 48;

    /* REQ-30: Verify signature over first 44 bytes using the separate
     * DCLAW_EMERGENCY_KEY. Reject when no key is provisioned. */
    if (!verify_emergency_signature(msg, 48, signature)) {
        return -1;
    }

    /* The authenticated predecessor is the last command in this fleet's
     * signed chain. A global sequence may jump when other fleets receive
     * commands, but a missed BLOCK must not be hidden by a later FORCE_SYNC. */
    if (seq == 0 || (s->emergency.initialized && seq <= s->emergency.last_seen_seq))
        return -2;
    if (prev_fleet_seq != s->emergency.last_seen_seq)
        return -3;
    if (command < 0x01 || command > 0x05) return -4;

    dclaw_emergency_state_t prior = s->emergency;
    s->emergency.initialized = true;

    /* Apply command */
    switch (command) {
    case 0x01: /* BLOCK_ALL */
        dclaw_cache_flush_all();
        s->emergency.block_all_active = true;
        s->emergency.last_was_lockdown = true;
        memset(s->speculative, 0, sizeof(s->speculative));
        s->emergency.lockdown_timestamp = hal_tick_ms();
        break;

    case 0x02: /* REVOKE_HASH / REVOKE_SESSIONS */
        /* payload[0:32] contains the hash to revoke */
        dclaw_cache_flush_all(); /* simplified: flush everything */
        /* Clear session table to revoke all active sessions */
        memset(s->sessions, 0, sizeof(s->sessions));
        /* Reset correlator FSM states: zero out pending/speculative slots
         * so no stale session state lingers after a revocation. */
        memset(s->pending, 0, sizeof(s->pending));
        memset(s->speculative, 0, sizeof(s->speculative));
        break;

    case 0x03: /* FORCE_SYNC */
        /* Flush the in-RAM audit buffer to flash immediately,
         * then sync to durable storage. */
        dclaw_flush_audit();
        hal_flash_sync();
        break;

    case 0x04: /* ENTER_LOCKDOWN */
        dclaw_cache_flush_all();
        s->emergency.block_all_active = true;
        s->emergency.last_was_lockdown = true;
        memset(s->speculative, 0, sizeof(s->speculative));
        s->emergency.lockdown_timestamp = hal_tick_ms();
        break;

    case 0x05: /* RELEASE_LOCKDOWN */
        s->emergency.block_all_active = false;
        s->emergency.last_was_lockdown = false;
        s->emergency.lockdown_timestamp = 0;
        dclaw_cache_flush_all();
        break;

    default:
        return -4;
    }

    /* A command is acknowledged only after the checked emergency state has
     * at least one durable copy. In RAM, persistence errors leave lockdown
     * active until an operator repairs storage and the command is replayed. */
    s->emergency.last_seen_seq = seq;
    if (dclaw_emergency_persist() != 0) {
        s->emergency = prior;
        s->emergency.block_all_active = true;
        s->emergency.last_was_lockdown = true;
        dclaw_cache_flush_all();
        return -3;
    }

    dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_CLOUD_BLOCK, 0, 0);
    return 0;
}

/*
 * Reload policy tables from flash after an OTA update.
 *
 * Reads the active flash partition, parses the policy blob header and payload
 * sections, and overwrites the runtime policy tables (rt_policy) so the new
 * deny hashes, destination allowlist, severity rules, and sequence rules take
 * effect immediately — no daemon restart required.
 *
 * Binary payload layout (produced by policy_compiler.py):
 *   [0]       severity_rule_count  (uint8)
 *   [1..N]    severity rules: pairs of (severity:u8, action:u8)
 *   [N]       sequence_rule_count  (uint8)
 *   [N+1..]   sequence rules: (seq[4], seq_len:u8, action:u8) = 6 bytes each
 *   [..]      dest_count (uint8)
 *   [..]      for each dest: length (uint8) + string bytes (no NUL terminator)
 *   [..]      remaining bytes are reserved / content rules (ignored here)
 *
 * Returns 0 on success, 1 if flash read or parse fails (compiled-in defaults
 * remain in effect).
 */
int dclaw_policy_reload_from_flash(void) {
    dclaw_state_t *s = dclaw_get_state();

    /* Read the active partition */
    uint8_t active = dclaw_config_active_policy_partition();
    uint32_t offset = (active == 0) ? HAL_FLASH_POLICY_A_OFFSET
                                    : HAL_FLASH_POLICY_B_OFFSET;
    uint32_t max_size = HAL_FLASH_POLICY_A_SIZE;

    /* Static buffer to avoid ~4KB stack allocation. Single-threaded daemon. */
    static uint8_t flash_buf[HAL_FLASH_POLICY_A_SIZE];
    if (hal_flash_read(offset, flash_buf, max_size) != 0) {
        fprintf(stderr, "[DCLAW] WARNING: Failed to read policy from flash partition %d. "
                "Compiled-in defaults remain active.\n", active);
        return 1;
    }

    /* Parse header */
    if (max_size < 8) return 1;
    uint16_t payload_len = ((uint16_t)flash_buf[2] << 8) | flash_buf[3];
    if (payload_len == 0 || (uint32_t)(8 + payload_len) >
                            max_size - OTA_SIGNATURE_LEN) {
        fprintf(stderr, "[DCLAW] INFO: No OTA policy in flash (payload_len=%u). "
                "Compiled-in defaults remain active.\n", payload_len);
        return 1;
    }
    /* The trailer is the original wire signature. Recheck it on every boot
     * and rollback so a modified flash payload cannot become live policy. */
    if (!verify_signature(flash_buf, (size_t)8 + payload_len,
                          flash_buf + max_size - OTA_SIGNATURE_LEN)) {
        fprintf(stderr, "[DCLAW] ERROR: Stored policy signature invalid; refusing flash policy.\n");
        return 1;
    }

    dclaw_policy_table_t staged;
    memcpy(&staged, &s->rt_policy, sizeof(staged));

    const uint8_t *payload = flash_buf + 8;
    size_t remaining = payload_len;
    size_t pos = 0;
    bool any_parsed = false;

    /*
     * Binary format extension — "sections present" bitmask.
     *
     * If the first byte of the payload has the high bit set (0x80 | mask),
     * it is a sections-present bitmask:
     *   bit 0 = severity rules section present
     *   bit 1 = sequence rules section present
     *   bit 2 = destination allowlist section present
     *   bits 3-6 = reserved
     *   bit 7 = bitmask marker (always 1)
     *
     * When a section is "present" but has count=0, the fix is to CLEAR
     * that section (revoke/empty the list). When a section is NOT present
     * (bit clear), preserve the existing values.
     *
     * For backward compatibility, if the first byte does NOT have bit 7 set,
     * the old parsing logic applies (sections with count>0 replace, count==0
     * is treated as omitted/preserve).
     */
    uint8_t sections_bitmask = 0xFF; /* default: all sections "present" for compat */
    bool has_bitmask = false;
    if (remaining > 0 && (payload[0] & 0x80)) {
        sections_bitmask = payload[0] & 0x7F;
        has_bitmask = true;
        pos++;
        any_parsed = true; /* bitmask itself counts as valid content */
    }

    /* Parse severity rules — section bit 0 */
    if (pos >= remaining) goto parse_done;
    {
        uint8_t sev_count = payload[pos++];
        bool section_present = has_bitmask ? (sections_bitmask & 0x01) : (sev_count > 0);
        if (section_present) {
            staged.severity_rules_count = 0;  /* replace section (even if count==0 = clear) */
        }
        for (uint8_t i = 0; i < sev_count && pos + 1 < remaining; i++) {
            if (staged.severity_rules_count < DCLAW_RT_MAX_SEVERITY_RULES) {
                staged.severity_rules[staged.severity_rules_count].severity = payload[pos];
                staged.severity_rules[staged.severity_rules_count].action = payload[pos + 1];
                staged.severity_rules_count++;
                any_parsed = true;
            }
            pos += 2;
        }
    }

    /* Parse sequence rules — section bit 1 */
    if (pos >= remaining) goto parse_done;
    {
        uint8_t seq_count = payload[pos++];
        bool section_present = has_bitmask ? (sections_bitmask & 0x02) : (seq_count > 0);
        if (section_present) {
            staged.sequence_rules_count = 0;  /* replace section */
        }
        for (uint8_t i = 0; i < seq_count && pos + 5 < remaining; i++) {
            if (staged.sequence_rules_count < DCLAW_RT_MAX_SEQUENCE_RULES) {
                memcpy(staged.sequence_rules[staged.sequence_rules_count].seq, payload + pos, 4);
                staged.sequence_rules[staged.sequence_rules_count].seq_len = payload[pos + 4];
                if (staged.sequence_rules[staged.sequence_rules_count].seq_len > 4) {
                    staged.sequence_rules[staged.sequence_rules_count].seq_len = 4;
                }
                staged.sequence_rules[staged.sequence_rules_count].action = payload[pos + 5];
                staged.sequence_rules_count++;
                any_parsed = true;
            }
            pos += 6;
        }
    }

    /* Parse destination allowlist — section bit 2.
     * When bit 2 is set AND dest_count==0, the sender explicitly
     * wants an empty allowlist (revoke all destinations). This is different
     * from "section not present" (bit 2 clear) which preserves existing. */
    if (pos >= remaining) goto parse_done;
    {
        uint8_t dest_count = payload[pos++];
        bool section_present = has_bitmask ? (sections_bitmask & 0x04) : (dest_count > 0);
        if (section_present) {
            staged.dest_allowlist_count = 0;  /* replace section (even if count==0 = clear) */
            if (dest_count == 0) {
                any_parsed = true; /* explicit empty list is a valid policy change */
            }
        }
        for (uint8_t i = 0; i < dest_count && pos < remaining; i++) {
            uint8_t dlen = payload[pos++];
            if (pos + dlen > remaining) break;
            if (staged.dest_allowlist_count < DCLAW_RT_MAX_DEST_ALLOWLIST && dlen < DCLAW_RT_MAX_DEST_LEN) {
                memcpy(staged.dest_allowlist[staged.dest_allowlist_count], payload + pos, dlen);
                staged.dest_allowlist[staged.dest_allowlist_count][dlen] = '\0';
                staged.dest_allowlist_count++;
                any_parsed = true;
            }
            pos += dlen;
        }
    }

parse_done:
    if (!any_parsed) {
        /* The payload contained no real policy sections (e.g. a test blob
         * with all-zero payload). Keep the current tables unchanged. */
        fprintf(stderr, "[DCLAW] Policy blob has no parseable sections; "
                "existing policy tables remain active.\n");
        return 1;
    }

    /* Commit the staged tables to the live runtime policy */
    staged.loaded = true;
    memcpy(&s->rt_policy, &staged, sizeof(dclaw_policy_table_t));

    fprintf(stderr, "[DCLAW] Policy tables reloaded from flash: "
            "%zu severity rules, %zu sequence rules, %zu destinations.\n",
            s->rt_policy.severity_rules_count, s->rt_policy.sequence_rules_count,
            s->rt_policy.dest_allowlist_count);
    return 0;
}

/* REQ-32: Check for emergency sequence gap on reconnect */
bool dclaw_emergency_has_gap(uint32_t cloud_current_seq) {
    dclaw_state_t *s = dclaw_get_state();
    if (cloud_current_seq > s->emergency.last_seen_seq &&
        cloud_current_seq - s->emergency.last_seen_seq > 1) {
        s->emergency.gap_start = s->emergency.last_seen_seq + 1;
        s->emergency.replay_requested = true;
        return true;
    }
    return false;
}

#define DCLAW_LOCKDOWN_TIMEOUT_SEC (24 * 60 * 60) /* 24 hours */

void dclaw_lockdown_timeout_check(void) {
    dclaw_state_t *s = dclaw_get_state();
    if (!s->emergency.block_all_active) return;
    if (s->emergency.lockdown_timestamp == 0) return;

    /* Use monotonic clock (hal_tick_ms) instead of wall clock (time(NULL))
     * to prevent NTP jumps from prematurely expiring or indefinitely
     * extending the lockdown timeout. */
    uint64_t now_ms = hal_tick_ms();
    if (now_ms < s->emergency.lockdown_timestamp) return;

    uint64_t elapsed_sec = (now_ms - s->emergency.lockdown_timestamp) / 1000;
    if (elapsed_sec >= DCLAW_LOCKDOWN_TIMEOUT_SEC) {
        dclaw_emergency_state_t prior = s->emergency;
        fprintf(stderr, "[DCLAW] WARNING: Lockdown auto-cleared after 24 hours (elapsed=%llu sec). "
                "Normal policy evaluation resumed. Investigate the original lockdown cause.\n",
                (unsigned long long)elapsed_sec);
        s->emergency.block_all_active = false;
        s->emergency.last_was_lockdown = false;
        s->emergency.lockdown_timestamp = 0;
        if (dclaw_emergency_persist() != 0) {
            s->emergency = prior;
            fprintf(stderr, "[DCLAW] ERROR: Lockdown auto-clear could not be persisted; remaining locked.\n");
            return;
        }
        dclaw_cache_flush_all();
        dclaw_audit_write(DCLAW_ACTION_WARN, DCLAW_REASON_CLOUD_BLOCK, 0xFFFE, 0);
    }
}

int dclaw_ipc_release_lockdown(void) {
    dclaw_state_t *s = dclaw_get_state();
    if (!s->emergency.block_all_active) {
        return -1;
    }
    fprintf(stderr, "[DCLAW] Lockdown released via local IPC command.\n");
    dclaw_emergency_state_t prior = s->emergency;
    s->emergency.block_all_active = false;
    s->emergency.last_was_lockdown = false;
    s->emergency.lockdown_timestamp = 0;
    if (dclaw_emergency_persist() != 0) {
        s->emergency = prior;
        fprintf(stderr, "[DCLAW] ERROR: Local release could not be persisted; remaining locked.\n");
        return -1;
    }
    dclaw_cache_flush_all();
    dclaw_audit_write(DCLAW_ACTION_WARN, DCLAW_REASON_CLOUD_BLOCK, 0xFFFD, 0);
    return 0;
}


/* The first 16 config bytes hold the legacy state or a migration marker.
 * Two checked records at +96/+128 preserve sequence, lockdown, identity and
 * generation across partial writes. They do not overlap policy, release or
 * boot counters. A valid record from a different fleet refuses startup;
 * re-enrolment requires trusted flash provisioning, never silent reset. */
#define EMERGENCY_FLASH_OFFSET  HAL_FLASH_CONFIG_OFFSET
#define EMERGENCY_FLASH_SIZE    16
#define EMERGENCY_MAGIC_0       0xDC
#define EMERGENCY_MAGIC_1       0xE9
#define EMERGENCY_MIGRATED      0xEA
#define EMERGENCY_RECORD_A      (HAL_FLASH_CONFIG_OFFSET + 96)
#define EMERGENCY_RECORD_B      (HAL_FLASH_CONFIG_OFFSET + 128)
#define EMERGENCY_RECORD_SIZE   28
static uint32_t emergency_generation;

#define LOCKDOWN_RELEASE_SEQ_A (HAL_FLASH_CONFIG_OFFSET + 32)
#define LOCKDOWN_RELEASE_SEQ_B (HAL_FLASH_CONFIG_OFFSET + 48)
#define LOCKDOWN_RELEASE_SEQ_RECORD_SIZE 12
#define LOCKDOWN_RELEASE_SEQ_MAX 99999999U /* IPC decimal parser accepts 8 digits */

/* Each copy contains magic, big-endian sequence, its inverse, and CRC16.
 * The two copies are written B then A with sync and readback per copy. */
static uint16_t release_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xffff;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int bit = 0; bit < 8; bit++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                                 : (uint16_t)(crc << 1);
    }
    return crc;
}

static uint32_t release_be32(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) | data[3];
}

static void release_put_be32(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
}

static bool release_record_valid(const uint8_t *record, uint32_t *sequence) {
    if (record[0] != 0xdc || record[1] != 0x52) return false;
    uint32_t value = release_be32(record + 2);
    if (value > LOCKDOWN_RELEASE_SEQ_MAX ||
        release_be32(record + 6) != ~value ||
        (((uint16_t)record[10] << 8) | record[11]) != release_crc16(record, 10))
        return false;
    *sequence = value;
    return true;
}

static bool release_blank(const uint8_t *record, uint8_t fill) {
    for (size_t i = 0; i < LOCKDOWN_RELEASE_SEQ_RECORD_SIZE; i++)
        if (record[i] != fill) return false;
    return true;
}

uint32_t dclaw_load_lockdown_release_seq(void) {
    uint8_t a[LOCKDOWN_RELEASE_SEQ_RECORD_SIZE];
    uint8_t b[LOCKDOWN_RELEASE_SEQ_RECORD_SIZE];
    if (hal_flash_read(LOCKDOWN_RELEASE_SEQ_A, a, sizeof(a)) != 0 ||
        hal_flash_read(LOCKDOWN_RELEASE_SEQ_B, b, sizeof(b)) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Cannot read lockdown release counter; signed release disabled.\n");
        return UINT32_MAX;
    }
    uint32_t seq_a = 0, seq_b = 0;
    bool valid_a = release_record_valid(a, &seq_a);
    bool valid_b = release_record_valid(b, &seq_b);
    if (valid_a || valid_b) return seq_a > seq_b ? seq_a : seq_b;

    if ((release_blank(a, 0) && release_blank(b, 0)) ||
        (release_blank(a, 0xff) && release_blank(b, 0xff))) return 0;

    /* Upgrade from the earlier unprotected single uint32 record. It was
     * stored at +32 with zero-filled trailing bytes. Preserve its sequence
     * until the next successful write creates both checked records. */
    uint32_t legacy = release_be32(a);
    bool legacy_shape = release_blank(b, 0);
    for (size_t i = 4; i < sizeof(a); i++) legacy_shape &= (a[i] == 0);
    if (legacy_shape && legacy <= LOCKDOWN_RELEASE_SEQ_MAX) return legacy;

    fprintf(stderr, "[DCLAW] ERROR: Both lockdown release counter records invalid; "
                    "signed release disabled until flash is repaired.\n");
    return UINT32_MAX;
}

static int release_write_record(uint32_t offset, const uint8_t *record) {
    uint8_t previous[LOCKDOWN_RELEASE_SEQ_RECORD_SIZE];
    uint8_t verify[LOCKDOWN_RELEASE_SEQ_RECORD_SIZE];
    if (hal_flash_read(offset, previous, sizeof(previous)) != 0) return -1;
    if (hal_flash_write(offset, record, LOCKDOWN_RELEASE_SEQ_RECORD_SIZE) != 0 ||
        hal_flash_sync() != 0 ||
        hal_flash_read(offset, verify, sizeof(verify)) != 0 ||
        memcmp(record, verify, sizeof(verify)) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Lockdown release counter persistence failed at 0x%x.\n",
                (unsigned)offset);
        /* The release has not been acknowledged. Best-effort rollback keeps a
         * transient short write from stranding the device in lockdown. If
         * rollback also fails, the next boot rejects the corrupt record. */
        if (hal_flash_write(offset, previous, sizeof(previous)) != 0 ||
            hal_flash_sync() != 0 ||
            hal_flash_read(offset, verify, sizeof(verify)) != 0 ||
            memcmp(previous, verify, sizeof(verify)) != 0)
            fprintf(stderr, "[DCLAW] ERROR: Lockdown release counter rollback failed; flash repair may be required.\n");
        return -1;
    }
    return 0;
}

int dclaw_store_lockdown_release_seq(uint32_t seq) {
    uint32_t last = dclaw_load_lockdown_release_seq();
    if (last == UINT32_MAX || seq <= last || seq > LOCKDOWN_RELEASE_SEQ_MAX) return -1;
    uint8_t record[LOCKDOWN_RELEASE_SEQ_RECORD_SIZE] = {0xdc, 0x52};
    release_put_be32(record + 2, seq);
    release_put_be32(record + 6, ~seq);
    uint16_t crc = release_crc16(record, 10);
    record[10] = (uint8_t)(crc >> 8);
    record[11] = (uint8_t)crc;
    if (release_write_record(LOCKDOWN_RELEASE_SEQ_B, record) != 0) return -1;
    if (release_write_record(LOCKDOWN_RELEASE_SEQ_A, record) != 0) return -1;
    return 0;
}

static bool emergency_blank(const uint8_t *bytes, size_t len) {
    bool zero = true, erased = true;
    for (size_t i = 0; i < len; i++) {
        zero &= bytes[i] == 0;
        erased &= bytes[i] == 0xff;
    }
    return zero || erased;
}

static uint64_t emergency_be64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) value = (value << 8) | bytes[i];
    return value;
}

static void emergency_put_be64(uint8_t *bytes, uint64_t value) {
    for (int i = 7; i >= 0; i--) {
        bytes[i] = (uint8_t)value;
        value >>= 8;
    }
}

static bool emergency_record_valid(const uint8_t *bytes) {
    uint16_t expected = ((uint16_t)bytes[26] << 8) | bytes[27];
    return bytes[0] == EMERGENCY_MAGIC_0 && bytes[1] == EMERGENCY_MIGRATED &&
           bytes[2] <= 1 && bytes[3] <= 1 &&
           release_be32(bytes + 8) != 0 &&
           bytes[24] == 0 && bytes[25] == 0 &&
           expected == release_crc16(bytes, 26);
}

static bool emergency_record_identity_matches(const uint8_t *bytes,
                                              const dclaw_state_t *s) {
    uint16_t tenant = ((uint16_t)bytes[20] << 8) | bytes[21];
    uint16_t fleet = ((uint16_t)bytes[22] << 8) | bytes[23];
    return tenant == s->device.tenant_id && fleet == s->device.fleet_id;
}

static int emergency_write_record(uint32_t offset, const uint8_t *record) {
    uint8_t verify[EMERGENCY_RECORD_SIZE];
    if (hal_flash_write(offset, record, sizeof(verify)) != 0 ||
        hal_flash_sync() != 0 ||
        hal_flash_read(offset, verify, sizeof(verify)) != 0 ||
        memcmp(record, verify, sizeof(verify)) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Emergency state write/sync/readback failed at 0x%x.\n",
                (unsigned)offset);
        return -1;
    }
    return 0;
}

int dclaw_emergency_persist(void) {
    dclaw_state_t *s = dclaw_get_state();
    if (emergency_generation == UINT32_MAX) return -1;
    uint8_t record[EMERGENCY_RECORD_SIZE] = {EMERGENCY_MAGIC_0, EMERGENCY_MIGRATED};
    record[2] = s->emergency.block_all_active ? 1 : 0;
    record[3] = s->emergency.last_was_lockdown ? 1 : 0;
    release_put_be32(record + 4, s->emergency.last_seen_seq);
    release_put_be32(record + 8, emergency_generation + 1);
    emergency_put_be64(record + 12, s->emergency.lockdown_timestamp);
    record[20] = (uint8_t)(s->device.tenant_id >> 8);
    record[21] = (uint8_t)s->device.tenant_id;
    record[22] = (uint8_t)(s->device.fleet_id >> 8);
    record[23] = (uint8_t)s->device.fleet_id;
    uint16_t crc = release_crc16(record, 26);
    record[26] = (uint8_t)(crc >> 8);
    record[27] = (uint8_t)crc;
    bool stored_b = emergency_write_record(EMERGENCY_RECORD_B, record) == 0;
    bool stored_a = emergency_write_record(EMERGENCY_RECORD_A, record) == 0;
    if (!stored_a && !stored_b) return -1;

    /* Mark the legacy slot as migrated so a loss of both new copies cannot
     * silently resurrect an old, unauthenticated single record. */
    uint8_t marker[2] = {EMERGENCY_MAGIC_0, EMERGENCY_MIGRATED}, verify[2];
    if (hal_flash_write(EMERGENCY_FLASH_OFFSET, marker, sizeof(marker)) != 0 ||
        hal_flash_sync() != 0 ||
        hal_flash_read(EMERGENCY_FLASH_OFFSET, verify, sizeof(verify)) != 0 ||
        memcmp(marker, verify, sizeof(marker)) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Emergency migration marker not durable.\n");
        return -1;
    }
    if (!stored_a || !stored_b)
        fprintf(stderr, "[DCLAW] WARNING: Emergency state redundancy degraded.\n");
    emergency_generation++;
    return 0;
}

int dclaw_emergency_load_from_flash(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint8_t a[EMERGENCY_RECORD_SIZE], b[EMERGENCY_RECORD_SIZE];
    uint8_t legacy[EMERGENCY_FLASH_SIZE];
    if (hal_flash_read(EMERGENCY_RECORD_A, a, sizeof(a)) != 0 ||
        hal_flash_read(EMERGENCY_RECORD_B, b, sizeof(b)) != 0 ||
        hal_flash_read(EMERGENCY_FLASH_OFFSET, legacy, sizeof(legacy)) != 0)
        return -1;
    bool valid_a = emergency_record_valid(a), valid_b = emergency_record_valid(b);
    if ((valid_a && !emergency_record_identity_matches(a, s)) ||
        (valid_b && !emergency_record_identity_matches(b, s))) {
        fprintf(stderr, "[DCLAW] ERROR: Emergency history belongs to another tenant/fleet; trusted reprovisioning required.\n");
        return -1;
    }
    if (valid_a || valid_b) {
        const uint8_t *chosen = valid_a ? a : b;
        if (valid_a && valid_b) {
            uint32_t ga = release_be32(a + 8), gb = release_be32(b + 8);
            if (ga == gb && memcmp(a, b, sizeof(a)) != 0) return -1;
            if (gb > ga) chosen = b;
        }
        emergency_generation = release_be32(chosen + 8);
        s->emergency.block_all_active = chosen[2] == 1;
        s->emergency.last_was_lockdown = chosen[3] == 1;
        s->emergency.last_seen_seq = release_be32(chosen + 4);
        s->emergency.lockdown_timestamp = emergency_be64(chosen + 12);
        s->emergency.initialized = s->emergency.last_seen_seq != 0;
    } else {
        emergency_generation = 0;
        if (!emergency_blank(a, sizeof(a)) || !emergency_blank(b, sizeof(b))) {
            fprintf(stderr, "[DCLAW] ERROR: Both checked emergency records are corrupt.\n");
            return -1;
        }
        if (emergency_blank(legacy, sizeof(legacy))) return 0;
        if (legacy[0] != EMERGENCY_MAGIC_0 || legacy[1] != EMERGENCY_MAGIC_1 ||
            legacy[2] > 1 || legacy[3] > 1) {
            fprintf(stderr, "[DCLAW] ERROR: Legacy emergency state is corrupt.\n");
            return -1;
        }
        s->emergency.block_all_active = legacy[2] == 1;
        s->emergency.last_was_lockdown = legacy[3] == 1;
        s->emergency.last_seen_seq = release_be32(legacy + 4);
        s->emergency.lockdown_timestamp = emergency_be64(legacy + 8);
        s->emergency.initialized = true;
        if (dclaw_emergency_persist() != 0) return -1;
    }
    if (s->emergency.block_all_active) {
        /* Monotonic timestamps from prior processes cannot be compared after
         * reboot. Restart the 24-hour lockdown window from this process. */
        s->emergency.lockdown_timestamp = hal_tick_ms();
        fprintf(stderr, "[DCLAW] Emergency lockdown restored (24h timer restarted).\n");
    }
    return 0;
}
