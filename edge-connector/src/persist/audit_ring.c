#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

extern dclaw_state_t *dclaw_get_state(void);

static uint16_t ring_head = 0; /* next write position in flash ring */

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
 * HMAC message = timestamp(8) || target_hash(2) || session_id(2) || action(1) || reason(1)
 *              = 14 bytes
 */
#define AUDIT_HMAC_MSG_LEN 14

static void build_hmac_message(const dclaw_audit_entry_t *entry, uint8_t *msg) {
    /* Copy fields before the hmac tag: timestamp + target_hash + session_id = 12 bytes */
    memcpy(msg, entry, 12);
    /* Copy fields after the hmac tag: action + reason = 2 bytes */
    msg[12] = entry->action;
    msg[13] = entry->reason;
}

#if defined(DCLAW_HAS_MBEDTLS) && DCLAW_HAS_MBEDTLS == 1

/* mbedTLS path — real HMAC-SHA256 via mbedtls_md */

#include <mbedtls/md.h>

static void compute_hmac(const dclaw_audit_entry_t *entry, const uint8_t *prev_hmac,
                         uint8_t *out_hmac) {
    /*
     * Real HMAC-SHA256 truncated to 4 bytes.
     * Key: prev_hmac (chained), Message: all decision fields (14 bytes).
     */
    uint8_t hmac_full[32];
    uint8_t entry_data[AUDIT_HMAC_MSG_LEN];
    build_hmac_message(entry, entry_data);

    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1 /* HMAC */);
    mbedtls_md_hmac_starts(&ctx, prev_hmac, 4);
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
     * Real HMAC-SHA256 truncated to 4 bytes.
     * Key: prev_hmac (chained, 4 bytes), Message: all decision fields (14 bytes).
     * Matches the mbedTLS path semantics exactly.
     */
    uint8_t hmac_full[32];
    uint8_t entry_data[AUDIT_HMAC_MSG_LEN];
    build_hmac_message(entry, entry_data);

    dclaw_hmac_sha256(prev_hmac, 4, entry_data, AUDIT_HMAC_MSG_LEN, hmac_full);

    /* Truncate to 4 bytes */
    memcpy(out_hmac, hmac_full, 4);
}

#endif /* DCLAW_HAS_MBEDTLS */

static int flush_buffer_to_flash(dclaw_audit_writer_t *w) {
    if (w->count == 0) return 0;

    for (uint8_t i = 0; i < w->count; i++) {
        uint32_t write_offset = HAL_FLASH_AUDIT_OFFSET +
            ((ring_head % DCLAW_AUDIT_RING_SIZE) * sizeof(dclaw_audit_entry_t));

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

        uint32_t write_offset = HAL_FLASH_AUDIT_OFFSET +
            ((ring_head % DCLAW_AUDIT_RING_SIZE) * sizeof(dclaw_audit_entry_t));
        if (hal_flash_write(write_offset, &entry, sizeof(dclaw_audit_entry_t)) != 0) {
            return -1;
        }
        ring_head = (ring_head + 1) % DCLAW_AUDIT_RING_SIZE;
        w->total_flash_writes++;
        /* Update prev_hmac so the next buffered entry chains from this BLOCK entry */
        memcpy(w->prev_hmac, entry.hmac, 4);
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
