#include "defenseclaw.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern dclaw_state_t *dclaw_get_state(void);

static uint16_t ring_head = 0; /* next write position in flash ring */

/*
 * Audit HMAC key (Comment 33 fix).
 * Instead of using the previous 4-byte tag as the HMAC key (which is weak
 * and predictable), use a proper device key. The key is loaded from the
 * DCLAW_AUDIT_KEY environment variable (hex-encoded 32 bytes), or falls
 * back to a hardcoded dev key with a warning.
 *
 * The chain integrity is maintained by including the previous HMAC tag in
 * the HMAC message (not as the key).
 */
#define AUDIT_KEY_LEN 32
static uint8_t s_audit_key[AUDIT_KEY_LEN];
static bool    s_audit_key_loaded = false;

static const uint8_t *get_audit_key(void) {
    if (s_audit_key_loaded) return s_audit_key;
    s_audit_key_loaded = true;

    const char *env = getenv("DCLAW_AUDIT_KEY");
    if (env != NULL && strlen(env) == 64) {
        bool valid = true;
        for (int i = 0; i < 32; i++) {
            int hi, lo;
            char c;
            c = env[i * 2];
            if (c >= '0' && c <= '9') hi = c - '0';
            else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
            else { valid = false; break; }
            c = env[i * 2 + 1];
            if (c >= '0' && c <= '9') lo = c - '0';
            else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
            else { valid = false; break; }
            s_audit_key[i] = (uint8_t)((hi << 4) | lo);
        }
        if (valid) return s_audit_key;
        fprintf(stderr, "[DCLAW] WARNING: DCLAW_AUDIT_KEY has invalid hex, "
                "using dev fallback key.\n");
    } else if (env != NULL) {
        fprintf(stderr, "[DCLAW] WARNING: DCLAW_AUDIT_KEY must be 64 hex chars, "
                "using dev fallback key.\n");
    } else {
        fprintf(stderr, "[DCLAW] WARNING: DCLAW_AUDIT_KEY not set — using dev "
                "fallback key. Audit chain integrity is reduced.\n");
    }

    /* Dev fallback: deterministic but non-zero key */
    for (int i = 0; i < AUDIT_KEY_LEN; i++) {
        s_audit_key[i] = (uint8_t)(0xDC ^ i);
    }
    return s_audit_key;
}

/*
 * Audit HMAC computation (chained integrity).
 * When DCLAW_HAS_MBEDTLS=1: HMAC-SHA256 via mbedtls_md, truncated to 4 bytes.
 * Otherwise: built-in HMAC-SHA256 (no external library), truncated to 4 bytes.
 */
/*
 * Build the HMAC input covering ALL decision fields of the audit entry,
 * excluding the hmac tag itself and padding.
 *
 * Layout of dclaw_audit_entry_t (24 bytes):
 *   [0..7]   timestamp       (8 bytes)
 *   [8..9]   target_hash     (2 bytes)
 *   [10..11] session_id      (2 bytes)
 *   [12..15] hmac            (4 bytes) -- EXCLUDED from HMAC input
 *   [16]     action          (1 byte)
 *   [17]     reason          (1 byte)
 *   [18..23] _pad            (6 bytes) -- EXCLUDED (padding only)
 *
 * HMAC message = prev_hmac(4) || timestamp(8) || target_hash(2) || session_id(2) || action(1) || reason(1)
 *              = 18 bytes
 *
 * Comment 33 fix: The previous HMAC tag is included in the message (for chain
 * integrity) but a proper device key is used as the HMAC key, not the prev tag.
 */
#define AUDIT_HMAC_MSG_LEN 18

static void build_hmac_message(const dclaw_audit_entry_t *entry,
                               const uint8_t *prev_hmac, uint8_t *msg) {
    /* Include previous HMAC tag in message for chain integrity */
    memcpy(msg, prev_hmac, 4);
    /* Copy fields before the hmac tag: timestamp + target_hash + session_id = 12 bytes */
    memcpy(msg + 4, entry, 12);
    /* Copy fields after the hmac tag: action + reason = 2 bytes */
    msg[16] = entry->action;
    msg[17] = entry->reason;
}

#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS == 1

/* mbedTLS path — real HMAC-SHA256 via mbedtls_md */

#include <mbedtls/md.h>

static void compute_hmac(const dclaw_audit_entry_t *entry, const uint8_t *prev_hmac,
                         uint8_t *out_hmac) {
    /*
     * Real HMAC-SHA256 truncated to 4 bytes (Comment 33 fix).
     * Key: device audit key (32 bytes), Message: prev_hmac(4) + decision fields(14) = 18 bytes.
     */
    uint8_t hmac_full[32];
    uint8_t entry_data[AUDIT_HMAC_MSG_LEN];
    const uint8_t *key = get_audit_key();
    build_hmac_message(entry, prev_hmac, entry_data);

    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1 /* HMAC */);
    mbedtls_md_hmac_starts(&ctx, key, AUDIT_KEY_LEN);
    mbedtls_md_hmac_update(&ctx, entry_data, AUDIT_HMAC_MSG_LEN);
    mbedtls_md_hmac_finish(&ctx, hmac_full);
    mbedtls_md_free(&ctx);

    /* Truncate to 4 bytes */
    memcpy(out_hmac, hmac_full, 4);
}

#else /* Built-in HMAC-SHA256 — no external library required */

#include "hmac_sha256.h"

static void compute_hmac(const dclaw_audit_entry_t *entry, const uint8_t *prev_hmac,
                         uint8_t *out_hmac) {
    /*
     * Real HMAC-SHA256 truncated to 4 bytes (Comment 33 fix).
     * Key: device audit key (32 bytes), Message: prev_hmac(4) + decision fields(14) = 18 bytes.
     * Matches the mbedTLS path semantics exactly.
     */
    uint8_t hmac_full[32];
    uint8_t entry_data[AUDIT_HMAC_MSG_LEN];
    const uint8_t *key = get_audit_key();
    build_hmac_message(entry, prev_hmac, entry_data);

    dclaw_hmac_sha256(key, AUDIT_KEY_LEN, entry_data, AUDIT_HMAC_MSG_LEN, hmac_full);

    /* Truncate to 4 bytes */
    memcpy(out_hmac, hmac_full, 4);
}

#endif /* DCLAW_HAS_MBEDTLS */

/*
 * Maximum number of audit entries that fit in the flash audit partition.
 * This bounds the ring to prevent writes beyond the partition boundary.
 * (Comment 20 fix)
 */
#define DCLAW_AUDIT_PARTITION_ENTRIES (HAL_FLASH_AUDIT_SIZE / sizeof(dclaw_audit_entry_t))

static int flush_buffer_to_flash(dclaw_audit_writer_t *w) {
    if (w->count == 0) return 0;

    for (uint8_t i = 0; i < w->count; i++) {
        /* Wrap ring_head within BOTH the logical ring size AND the flash
         * partition boundary to prevent overflow (Comment 20 fix). */
        uint16_t bounded_index = ring_head % DCLAW_AUDIT_RING_SIZE;
        if (bounded_index >= DCLAW_AUDIT_PARTITION_ENTRIES) {
            bounded_index = bounded_index % DCLAW_AUDIT_PARTITION_ENTRIES;
        }
        uint32_t write_offset = HAL_FLASH_AUDIT_OFFSET +
            (bounded_index * sizeof(dclaw_audit_entry_t));

        /* Verify write stays within partition bounds */
        if (write_offset + sizeof(dclaw_audit_entry_t) >
            HAL_FLASH_AUDIT_OFFSET + HAL_FLASH_AUDIT_SIZE) {
            /* Wrap to start of partition */
            write_offset = HAL_FLASH_AUDIT_OFFSET;
            ring_head = 0;
        }

        if (hal_flash_write(write_offset, &w->buffer[i], sizeof(dclaw_audit_entry_t)) != 0) {
            return -1;
        }
        ring_head = (ring_head + 1) % DCLAW_AUDIT_RING_SIZE;
    }

    /* Update prev_hmac to the last flushed entry for cross-flush HMAC chaining */
    memcpy(w->prev_hmac, w->buffer[w->count - 1].hmac, 4);

    w->total_flash_writes++;
    w->count = 0;
    w->last_flush_tick = hal_tick_ms();

    /* Sync to durable storage on periodic flush */
    hal_flash_sync();
    return 0;
}

int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                      uint16_t target_hash, uint16_t session_id) {
    dclaw_state_t *s = dclaw_get_state();
    dclaw_audit_writer_t *w = &s->audit_writer;

    dclaw_audit_entry_t entry = {
        .timestamp = hal_tick_ms(),
        .target_hash = target_hash,
        .session_id = session_id,
        .action = (uint8_t)action,
        .reason = (uint8_t)reason,
        ._pad = {0, 0},
    };

    /* Compute HMAC chain — use writer's prev_hmac for cross-flush continuity */
    uint8_t prev_hmac[4];
    if (w->count > 0) {
        memcpy(prev_hmac, w->buffer[w->count - 1].hmac, 4);
    } else {
        memcpy(prev_hmac, w->prev_hmac, 4);
    }
    compute_hmac(&entry, prev_hmac, entry.hmac);

    /* INVARIANT: BLOCK events bypass the coalescing buffer */
    if (action == DCLAW_ACTION_BLOCK) {
        /* Flush existing buffer first, then write BLOCK entry directly */
        flush_buffer_to_flash(w);

        /* Bound the write offset within the flash audit partition (Comment 20 fix) */
        uint16_t bounded_index = ring_head % DCLAW_AUDIT_RING_SIZE;
        if (bounded_index >= DCLAW_AUDIT_PARTITION_ENTRIES) {
            bounded_index = bounded_index % DCLAW_AUDIT_PARTITION_ENTRIES;
        }
        uint32_t write_offset = HAL_FLASH_AUDIT_OFFSET +
            (bounded_index * sizeof(dclaw_audit_entry_t));
        if (write_offset + sizeof(dclaw_audit_entry_t) >
            HAL_FLASH_AUDIT_OFFSET + HAL_FLASH_AUDIT_SIZE) {
            write_offset = HAL_FLASH_AUDIT_OFFSET;
            ring_head = 0;
        }
        if (hal_flash_write(write_offset, &entry, sizeof(dclaw_audit_entry_t)) != 0) {
            return -1;
        }
        ring_head = (ring_head + 1) % DCLAW_AUDIT_RING_SIZE;
        w->total_flash_writes++;
        /* Update prev_hmac so the next buffered entry chains from this BLOCK entry */
        memcpy(w->prev_hmac, entry.hmac, 4);
        /* Sync to durable storage for BLOCK durability (Comment 33 fix) */
        hal_flash_sync();
        return 0;
    }

    /* Buffered write for non-BLOCK events */
    if (w->count >= DCLAW_AUDIT_RAM_BUFFER_SIZE) {
        /* Buffer full — flush before writing to prevent out-of-bounds access */
        if (flush_buffer_to_flash(w) != 0) {
            /* Flush failed; retry once more on next call. Return error. */
            return -1;
        }
    }
    w->buffer[w->count++] = entry;

    /* Check flush triggers */
    bool should_flush = (w->count >= DCLAW_AUDIT_RAM_BUFFER_SIZE) ||
                        (hal_tick_ms() - w->last_flush_tick >= DCLAW_AUDIT_FLUSH_SEC * 1000);

    if (should_flush) {
        return flush_buffer_to_flash(w);
    }
    return 0;
}

int dclaw_flush_audit(void) {
    dclaw_state_t *s = dclaw_get_state();
    return flush_buffer_to_flash(&s->audit_writer);
}
