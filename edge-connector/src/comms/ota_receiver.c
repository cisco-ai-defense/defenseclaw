#include "defenseclaw.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
extern void dclaw_config_persist_policy_version(uint16_t version);
extern void dclaw_cache_flush_all(void);
extern int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                             uint16_t target_hash, uint16_t session_id);

/* Forward declarations for this file */
void dclaw_policy_rollback(void);
void dclaw_canary_tick(void);
void dclaw_canary_record_block(void);
int dclaw_policy_reload_from_flash(void);
void dclaw_emergency_persist(void);
void dclaw_emergency_load_from_flash(void);

/* Policy blob header format (first 8 bytes of blob) */
typedef struct {
    uint16_t version;
    uint16_t payload_len;
    uint16_t canary_baseline;
    uint16_t _reserved;
} dclaw_policy_header_t;

#define ED25519_SIG_LEN  64
#define ED25519_PUBKEY_LEN 32

/*
 * Ed25519 signature verification.
 * When DCLAW_HAS_MBEDTLS=1: uses TweetNaCl crypto_sign_ed25519_verify_detached.
 * When DCLAW_HAS_MBEDTLS=0: stub for dev builds only.
 */
#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS == 1

/* mbedTLS path — real Ed25519 signature verification */

#if defined(HAVE_TWEETNACL)
/*
 * TweetNaCl Ed25519 verification (Comment 36 fix).
 * Only available when TweetNaCl is linked (HAVE_TWEETNACL defined).
 */
extern int crypto_sign_ed25519_verify_detached(const uint8_t *sig,
                                               const uint8_t *msg,
                                               uint64_t msg_len,
                                               const uint8_t *pk);

static bool verify_ed25519(const uint8_t *message, size_t msg_len,
                           const uint8_t *signature,
                           const uint8_t *pubkey) {
    return crypto_sign_ed25519_verify_detached(signature, message,
                                               (uint64_t)msg_len,
                                               pubkey) == 0;
}

#else /* HAVE_TWEETNACL not defined — fall through to HMAC-SHA256 path */

/*
 * Comment 36 fix: When mbedTLS is enabled but TweetNaCl is not linked,
 * we cannot perform Ed25519 verification. Fall through to the HMAC-SHA256
 * path which provides integrity verification with a pre-shared key.
 */
#pragma message "mbedTLS enabled but TweetNaCl not linked — using HMAC-SHA256 for OTA verification."

#include "hmac_sha256.h"

static bool verify_ed25519(const uint8_t *message, size_t msg_len,
                           const uint8_t *signature,
                           const uint8_t *pubkey) {
    uint8_t expected[32];
    dclaw_hmac_sha256(pubkey, ED25519_PUBKEY_LEN, message, msg_len, expected);

    volatile uint8_t diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= signature[i] ^ expected[i];
    }
    return diff == 0;
}

#endif /* HAVE_TWEETNACL */

#else /* Built-in HMAC-SHA256 verification — no external library required */

/*
 * NOTE: This path uses HMAC-SHA256 for integrity verification instead of Ed25519.
 * It is cryptographically sound for integrity checking with a pre-shared key, but
 * does NOT provide non-repudiation (asymmetric signatures).
 * Production deployments should enable mbedTLS for proper Ed25519 verification.
 */
#pragma message "Ed25519 unavailable — using HMAC-SHA256 verification. Enable mbedTLS for Ed25519."

#include "hmac_sha256.h"

static bool verify_ed25519(const uint8_t *message, size_t msg_len,
                           const uint8_t *signature,
                           const uint8_t *pubkey) {
    /*
     * HMAC-SHA256 integrity verification using the pubkey as a pre-shared key.
     * The first 32 bytes of the 64-byte signature field hold the expected
     * HMAC-SHA256(pubkey, message) truncated to 32 bytes.
     *
     * Constant-time comparison to prevent timing side-channels.
     */
    uint8_t expected[32];
    dclaw_hmac_sha256(pubkey, ED25519_PUBKEY_LEN, message, msg_len, expected);

    volatile uint8_t diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= signature[i] ^ expected[i];
    }
    return diff == 0;
}

#endif /* DCLAW_HAS_MBEDTLS */

/*
 * OTA CA key — loaded from DCLAW_OTA_KEY env var (hex-encoded 32 bytes)
 * at first use, falling back to a zero key with a warning.
 *
 * When DCLAW_HAS_MBEDTLS=1 this is the Ed25519 public key.
 * When DCLAW_HAS_MBEDTLS=0 this is the HMAC-SHA256 pre-shared key.
 */
static uint8_t ota_ca_key[ED25519_PUBKEY_LEN];
static bool    ota_ca_key_loaded = false;
static bool    ota_ca_key_provisioned = false;  /* true only when a real (non-zero) key is loaded */

/* Reset key state — allows tests to force re-reading from env */
void dclaw_ota_reset_key_state(void) {
    ota_ca_key_loaded = false;
    ota_ca_key_provisioned = false;
    memset(ota_ca_key, 0, sizeof(ota_ca_key));
}

static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static const uint8_t *get_ota_ca_key(void) {
    if (ota_ca_key_loaded) return ota_ca_key;
    ota_ca_key_loaded = true;
    ota_ca_key_provisioned = false;

    const char *env = getenv("DCLAW_OTA_KEY");
    if (env != NULL && strlen(env) == 64) {
        /* Parse 64 hex characters into 32 bytes */
        bool valid = true;
        for (int i = 0; i < 32; i++) {
            int hi = hex_char_to_nibble(env[i * 2]);
            int lo = hex_char_to_nibble(env[i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                valid = false;
                break;
            }
            ota_ca_key[i] = (uint8_t)((hi << 4) | lo);
        }
        if (valid) {
            /* Check that the key is not all zeros */
            bool all_zero = true;
            for (int i = 0; i < ED25519_PUBKEY_LEN; i++) {
                if (ota_ca_key[i] != 0) { all_zero = false; break; }
            }
            if (!all_zero) {
                ota_ca_key_provisioned = true;
                return ota_ca_key;
            }
            fprintf(stderr, "[DCLAW] WARNING: DCLAW_OTA_KEY is all zeros — "
                    "OTA updates will be REJECTED until a real key is provisioned.\n");
            return ota_ca_key;
        }
        fprintf(stderr, "[DCLAW] WARNING: DCLAW_OTA_KEY has invalid hex — "
                "OTA updates will be REJECTED until a valid key is provisioned.\n");
    } else if (env != NULL) {
        fprintf(stderr, "[DCLAW] WARNING: DCLAW_OTA_KEY must be 64 hex chars (32 bytes) — "
                "OTA updates will be REJECTED until a valid key is provisioned.\n");
    } else {
        fprintf(stderr, "[DCLAW] WARNING: DCLAW_OTA_KEY not set — "
                "OTA updates will be REJECTED until a key is provisioned.\n");
    }

    memset(ota_ca_key, 0, sizeof(ota_ca_key));
    return ota_ca_key;
}

/*
 * Verify signature only when a real (non-zero) OTA key has been provisioned.
 * When no key is provisioned, ALL signatures are rejected to prevent attackers
 * from forging updates against a known-zero key.
 */
static bool verify_signature(const uint8_t *message, size_t msg_len,
                             const uint8_t *signature) {
    const uint8_t *key = get_ota_ca_key();
    if (!ota_ca_key_provisioned) {
        fprintf(stderr, "[DCLAW] REJECT: OTA signature verification failed — "
                "no key provisioned. Set DCLAW_OTA_KEY to accept updates.\n");
        return false;
    }
    return verify_ed25519(message, msg_len, signature, key);
}

/* === Policy OTA (REQ-33 through REQ-36) === */

int dclaw_apply_policy(const uint8_t *blob, uint32_t blob_len,
                       const uint8_t *signature) {
    dclaw_state_t *s = dclaw_get_state();

    if (blob_len < sizeof(dclaw_policy_header_t)) return -1;
    if (blob_len > HAL_FLASH_POLICY_A_SIZE) return -1;

    /* REQ-33: Verify Ed25519 signature (or HMAC-SHA256 when mbedTLS unavailable).
     * Rejects ALL updates when no OTA key is provisioned. */
    if (!verify_signature(blob, blob_len, signature)) {
        dclaw_audit_write(DCLAW_ACTION_BLOCK, DCLAW_REASON_INVALID_INPUT, 0, 0);
        return -1;
    }

    /* Parse header (big-endian wire format) */
    dclaw_policy_header_t hdr;
    hdr.version = ((uint16_t)blob[0] << 8) | blob[1];
    hdr.payload_len = ((uint16_t)blob[2] << 8) | blob[3];
    hdr.canary_baseline = ((uint16_t)blob[4] << 8) | blob[5];

    /* P1-4 fix: Validate that the declared payload length matches the actual
     * blob size. The signed blob format is: header(8) + payload(N) + signature(64).
     * Without this check, a short blob with a header claiming a large payload
     * would pass signature verification (which only covers blob_len bytes)
     * and then cause out-of-bounds reads in downstream consumers. */
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
    /* P1-10 fix: Persist the new policy version to flash so anti-rollback
     * (REQ-36) works correctly after restart. */
    dclaw_config_persist_policy_version(hdr.version);

    /* Flush verdict cache — policy changed, cached verdicts may be stale */
    dclaw_cache_flush_all();

    /* Reload policy tables from the new flash contents (Comment 22 fix).
     * The compiled-in policy tables (deny_hashes, dest_allowlist, etc.) are
     * static const arrays generated at build time and cannot be replaced at
     * runtime without a restart. Log a warning so operators know a restart
     * is needed for the new policy tables to take full effect.
     * The version, cache flush, and canary protection ARE applied immediately. */
    dclaw_policy_reload_from_flash();

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

    uint64_t elapsed = hal_tick_ms() - s->canary.canary_started_at;

    /* Check if canary window has expired (10 minutes) */
    if (elapsed >= (uint64_t)DCLAW_CANARY_WINDOW_SEC * 1000) {
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
    /* P2-19 fix: Signal the next heartbeat to include flag 0x08 so the fleet
     * manager knows a canary rollback occurred. Cleared after the heartbeat
     * is encoded (one-shot notification). */
    s->rollback_pending = true;
    dclaw_cache_flush_all();

    /* P1-07 fix: Reload policy tables from the rolled-back partition so the
     * runtime tables actually reflect the old policy. Without this, the
     * partition was switched but the in-memory tables still held the new
     * (bad) policy rules.
     *
     * P1-07 fix (part 2): If the rolled-back partition is blank (first OTA
     * went to B, rollback switches to A which was never written), the reload
     * will fail. In that case, fall back to compiled-in defaults instead of
     * leaving the new (bad) policy active. */
    if (dclaw_policy_reload_from_flash() != 0) {
        fprintf(stderr, "[DCLAW] WARNING: Rollback partition is blank or corrupt. "
                "Falling back to compiled-in policy defaults.\n");
        dclaw_policy_tables_init();
    }

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

    /* REQ-30: Verify Ed25519 signature over first 44 bytes
     * (or HMAC-SHA256 when mbedTLS unavailable).
     * Rejects ALL emergency messages when no OTA key is provisioned. */
    if (!verify_signature(msg, 44, signature)) {
        return -1;
    }

    /* REQ-31: Anti-replay — sequence must be strictly increasing.
     * On first message (initialized==false), accept any sequence to bootstrap. */
    if (!s->emergency.initialized) {
        s->emergency.last_seen_seq = seq;
        s->emergency.initialized = true;
    } else {
        if (seq <= s->emergency.last_seen_seq) {
            return -2;
        }

        /* REQ-31: Jump attack detection — reject delta > 1000 */
        if (seq - s->emergency.last_seen_seq > 1000) {
            return -3;
        }
    }

    /* Apply command */
    switch (command) {
    case 0x01: /* BLOCK_ALL */
        /* P1-6 fix: Set global emergency block flag so dclaw_evaluate()
         * returns BLOCK for ALL requests until cleared or daemon restart. */
        dclaw_cache_flush_all();
        s->emergency.block_all_active = true;
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
        /* P1-6 fix: Full lockdown — set global emergency block flag.
         * Same effect as BLOCK_ALL: dclaw_evaluate() returns BLOCK for
         * all requests. The flag persists until cleared or daemon restart. */
        dclaw_cache_flush_all();
        s->emergency.block_all_active = true;
        break;

    case 0x05: /* RELEASE_LOCKDOWN */
        /* P1-09 fix: Clear the global emergency block flag so normal policy
         * evaluation resumes. Without this command, lockdown could only be
         * lifted by restarting the daemon — which is unacceptable for
         * remote/headless devices.
         *
         * Recovery procedure:
         *   1. Operator sends RELEASE_LOCKDOWN via fleet API
         *   2. Device clears block_all_active and persists cleared state
         *   3. Normal policy evaluation resumes on next tool call
         *   4. Verdict cache is flushed to force re-evaluation */
        s->emergency.block_all_active = false;
        dclaw_cache_flush_all();
        break;

    default:
        return -4;
    }

    /* Update sequence counter */
    s->emergency.last_seen_seq = seq;

    /* P1-09 fix: Persist emergency state to flash so lockdown survives restart */
    dclaw_emergency_persist();

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

    uint8_t flash_buf[HAL_FLASH_POLICY_A_SIZE];
    if (hal_flash_read(offset, flash_buf, max_size) != 0) {
        fprintf(stderr, "[DCLAW] WARNING: Failed to read policy from flash partition %d. "
                "Compiled-in defaults remain active.\n", active);
        return 1;
    }

    /* Parse header */
    if (max_size < 8) return 1;
    uint16_t payload_len = ((uint16_t)flash_buf[2] << 8) | flash_buf[3];
    if (payload_len == 0 || (uint32_t)(8 + payload_len) > max_size) {
        fprintf(stderr, "[DCLAW] WARNING: Invalid policy payload length %u in flash. "
                "Compiled-in defaults remain active.\n", payload_len);
        return 1;
    }

    /* P1-08 fix: Stage from a COPY of the current runtime tables (not zeros).
     * This way, sections omitted from the OTA blob preserve their existing
     * values instead of being zeroed. Only sections present in the blob are
     * overwritten. Previously, staging from zeros meant a partial OTA that
     * only contained severity rules would wipe out destination allowlists
     * and sequence rules. */
    dclaw_policy_table_t staged;
    memcpy(&staged, &s->rt_policy, sizeof(staged));

    /* Deny hashes are preserved from the copy above.
     * NOTE: The OTA binary blob format (policy_compiler.py generate_binary_blob)
     * does not currently include deny hashes — they are only populated via the
     * threat-intel push API at runtime. */
    if (staged.deny_hashes_count > 0) {
        fprintf(stderr, "[DCLAW] WARNING: %zu deny hashes preserved from previous policy. "
                "OTA blob does not carry deny hashes — updates require restart or "
                "threat-intel push.\n", staged.deny_hashes_count);
    }

    const uint8_t *payload = flash_buf + 8;
    size_t remaining = payload_len;
    size_t pos = 0;
    bool any_parsed = false;

    /*
     * P1-08 fix: Binary format extension — "sections present" bitmask.
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
                staged.sequence_rules[staged.sequence_rules_count].action = payload[pos + 5];
                staged.sequence_rules_count++;
                any_parsed = true;
            }
            pos += 6;
        }
    }

    /* Parse destination allowlist — section bit 2.
     * P1-08 fix: When bit 2 is set AND dest_count==0, the sender explicitly
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
    if (cloud_current_seq > s->emergency.last_seen_seq + 1) {
        s->emergency.gap_start = s->emergency.last_seen_seq + 1;
        s->emergency.replay_requested = true;
        return true;
    }
    return false;
}

/* === P1-09 fix: Persist emergency state to flash === */

/*
 * Emergency state is stored in the first 8 bytes of the config partition
 * (HAL_FLASH_CONFIG_OFFSET). Layout:
 *   [0..1] magic marker (0xDC, 0xE9) — "DC Emergency 9"
 *   [2]    block_all_active (0x00 or 0x01)
 *   [3]    reserved (0x00)
 *   [4..7] last_seen_seq  (big-endian uint32)
 *
 * The 2-byte magic ensures we don't misinterpret stale/uninitialized flash
 * (which reads as all-zeros or all-0xFF) as a valid emergency state.
 */
#define EMERGENCY_FLASH_OFFSET  HAL_FLASH_CONFIG_OFFSET
#define EMERGENCY_FLASH_SIZE    8
#define EMERGENCY_MAGIC_0       0xDC
#define EMERGENCY_MAGIC_1       0xE9

void dclaw_emergency_persist(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint8_t buf[EMERGENCY_FLASH_SIZE];

    buf[0] = EMERGENCY_MAGIC_0;
    buf[1] = EMERGENCY_MAGIC_1;
    buf[2] = s->emergency.block_all_active ? 0x01 : 0x00;
    buf[3] = 0x00;
    buf[4] = (uint8_t)(s->emergency.last_seen_seq >> 24);
    buf[5] = (uint8_t)(s->emergency.last_seen_seq >> 16);
    buf[6] = (uint8_t)(s->emergency.last_seen_seq >> 8);
    buf[7] = (uint8_t)(s->emergency.last_seen_seq);

    if (hal_flash_write(EMERGENCY_FLASH_OFFSET, buf, EMERGENCY_FLASH_SIZE) != 0) {
        fprintf(stderr, "[DCLAW] WARNING: Failed to persist emergency state to flash.\n");
    }
}

void dclaw_emergency_load_from_flash(void) {
    dclaw_state_t *s = dclaw_get_state();
    uint8_t buf[EMERGENCY_FLASH_SIZE];

    if (hal_flash_read(EMERGENCY_FLASH_OFFSET, buf, EMERGENCY_FLASH_SIZE) != 0) {
        return; /* Flash read failed — start fresh */
    }

    /* Verify magic marker — rejects uninitialized flash (all 0x00 or 0xFF) */
    if (buf[0] != EMERGENCY_MAGIC_0 || buf[1] != EMERGENCY_MAGIC_1) {
        return; /* No valid persisted emergency state */
    }

    s->emergency.block_all_active = (buf[2] == 0x01);
    s->emergency.last_seen_seq = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                                 ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
    s->emergency.initialized = true;

    if (s->emergency.block_all_active) {
        fprintf(stderr, "[DCLAW] Emergency lockdown state restored from flash.\n");
    }
}
