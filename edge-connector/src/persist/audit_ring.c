#include "defenseclaw.h"
#include "platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

extern dclaw_state_t *dclaw_get_state(void);

static uint16_t ring_head = 0; /* next write position in flash ring */

/*
 * NEW-1 fix: Persistent audit ring header.
 *
 * A small header is stored at the very start of the audit flash region so
 * the write-head position and previous HMAC survive across restarts.
 * Without this, every reboot would overwrite slot 0 and break the HMAC
 * chain, making the entire audit ring non-tamper-evident.
 *
 * Flash layout (within HAL_FLASH_AUDIT_OFFSET .. +HAL_FLASH_AUDIT_SIZE):
 *   [0..1]   magic      0xDC, 0xA1  (identifies a valid header)
 *   [2..3]   head_pos   uint16_t LE (next write slot index)
 *   [4..7]   last_hmac  4 bytes     (HMAC tag of the last written entry)
 *
 * Total header = 8 bytes (fits in one aligned flash word).
 * Audit entries start at HAL_FLASH_AUDIT_OFFSET + AUDIT_RING_HDR_SIZE.
 */
#define AUDIT_RING_HDR_MAGIC_0  0xDC
#define AUDIT_RING_HDR_MAGIC_1  0xA1
#define AUDIT_RING_HDR_SIZE     8

typedef struct __attribute__((packed)) {
    uint8_t  magic[2];
    uint16_t head_pos;
    uint8_t  last_hmac[4];
} audit_ring_hdr_t;

_Static_assert(sizeof(audit_ring_hdr_t) == AUDIT_RING_HDR_SIZE,
               "audit ring header must be 8 bytes");

/*
 * Write the persistent header to flash.  Called after every flush and
 * after every direct BLOCK write so the durable state is always current.
 */
static int audit_ring_persist_header(const uint8_t *last_hmac) {
    audit_ring_hdr_t hdr;
    hdr.magic[0]  = AUDIT_RING_HDR_MAGIC_0;
    hdr.magic[1]  = AUDIT_RING_HDR_MAGIC_1;
    hdr.head_pos  = ring_head;
    memcpy(hdr.last_hmac, last_hmac, 4);
    return hal_flash_write(HAL_FLASH_AUDIT_OFFSET, &hdr, sizeof(hdr));
}

/*
 * Restore ring_head and prev_hmac from the persistent header on init.
 * Returns 0 if a valid header was found, -1 if the region is blank /
 * corrupt (caller should start fresh from slot 0).
 */
static int audit_ring_restore_header(uint16_t *out_head, uint8_t *out_last_hmac) {
    audit_ring_hdr_t hdr;
    if (hal_flash_read(HAL_FLASH_AUDIT_OFFSET, &hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    if (hdr.magic[0] != AUDIT_RING_HDR_MAGIC_0 ||
        hdr.magic[1] != AUDIT_RING_HDR_MAGIC_1) {
        return -1; /* no valid header — first boot or erased */
    }
    *out_head = hdr.head_pos;
    memcpy(out_last_hmac, hdr.last_hmac, 4);
    return 0;
}

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
static bool    s_audit_key_provisioned = false; /* true only when DCLAW_AUDIT_KEY is valid */

/*
 * P2-18 fix: s_audit_key_refused is set to true when DCLAW_DEV_MODE is OFF
 * (production) and no valid DCLAW_AUDIT_KEY is provisioned. When true,
 * audit writes are silently dropped to prevent tamper-evident logging
 * with a known/predictable key.
 */
static bool s_audit_key_refused = false;

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
        if (valid) {
            /* P1-18 fix: Reject an all-zero key as weak/invalid.
             * 64 hex zero digits decode to 32 zero bytes, which is a
             * trivially guessable key that defeats HMAC integrity. */
            bool all_zero = true;
            for (int j = 0; j < AUDIT_KEY_LEN; j++) {
                if (s_audit_key[j] != 0) { all_zero = false; break; }
            }
            if (all_zero) {
                fprintf(stderr, "[DCLAW] WARNING: DCLAW_AUDIT_KEY is all zeros — "
                        "rejected as weak/invalid.\n");
                valid = false;
            }
        }
        if (valid) {
            s_audit_key_provisioned = true;
            return s_audit_key;
        }
        fprintf(stderr, "[DCLAW] WARNING: DCLAW_AUDIT_KEY has invalid hex.\n");
    } else if (env != NULL) {
        fprintf(stderr, "[DCLAW] WARNING: DCLAW_AUDIT_KEY must be 64 hex chars.\n");
    } else {
        fprintf(stderr, "[DCLAW] WARNING: DCLAW_AUDIT_KEY not set.\n");
    }

    /*
     * P2-18 fix: In production builds (DCLAW_DEV_MODE=OFF), refuse to
     * start the audit ring with a fallback key. This prevents shipping
     * tamper-evident logs with a known/predictable key that attackers
     * could forge.
     *
     * In dev builds (DCLAW_DEV_MODE=ON, the default), use the fallback
     * key with a warning for development convenience.
     */
#if !DCLAW_DEV_MODE
    fprintf(stderr, "[DCLAW] ERROR: Audit ring DISABLED — DCLAW_AUDIT_KEY required "
            "in production builds. Set a valid 64-hex-char key.\n");
    s_audit_key_refused = true;
    memset(s_audit_key, 0, AUDIT_KEY_LEN);
    return s_audit_key;
#else
    fprintf(stderr, "[DCLAW] WARNING: Using dev fallback audit key. "
            "Set DCLAW_AUDIT_KEY for tamper-evident logging.\n");
    /* Dev fallback: deterministic but non-zero key */
    for (int i = 0; i < AUDIT_KEY_LEN; i++) {
        s_audit_key[i] = (uint8_t)(0xDC ^ i);
    }
    return s_audit_key;
#endif
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
 * The first AUDIT_RING_HDR_SIZE bytes are reserved for the persistent
 * header (NEW-1 fix), so entries start after that.
 * (Comment 20 fix)
 */
#define DCLAW_AUDIT_ENTRY_AREA_SIZE  (HAL_FLASH_AUDIT_SIZE - AUDIT_RING_HDR_SIZE)
#define DCLAW_AUDIT_PARTITION_ENTRIES (DCLAW_AUDIT_ENTRY_AREA_SIZE / sizeof(dclaw_audit_entry_t))

static int flush_buffer_to_flash(dclaw_audit_writer_t *w) {
    if (w->count == 0) return 0;

    /* NEW-1 fix: Entries start after the persistent header. */
    const uint32_t entry_base = HAL_FLASH_AUDIT_OFFSET + AUDIT_RING_HDR_SIZE;

    for (uint8_t i = 0; i < w->count; i++) {
        /* Wrap ring_head within BOTH the logical ring size AND the flash
         * partition boundary to prevent overflow (Comment 20 fix). */
        uint16_t bounded_index = ring_head % DCLAW_AUDIT_RING_SIZE;
        if (bounded_index >= DCLAW_AUDIT_PARTITION_ENTRIES) {
            bounded_index = bounded_index % DCLAW_AUDIT_PARTITION_ENTRIES;
        }
        uint32_t write_offset = entry_base +
            (bounded_index * sizeof(dclaw_audit_entry_t));

        /* Verify write stays within partition bounds */
        if (write_offset + sizeof(dclaw_audit_entry_t) >
            HAL_FLASH_AUDIT_OFFSET + HAL_FLASH_AUDIT_SIZE) {
            /* Wrap to start of entry area */
            write_offset = entry_base;
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

    /* NEW-1 fix: Persist head position and last HMAC to flash header */
    audit_ring_persist_header(w->prev_hmac);

    /* Sync to durable storage on periodic flush */
    hal_flash_sync();
    return 0;
}

/*
 * Verify a single audit entry's HMAC given a known previous HMAC tag.
 * Returns true if the entry's HMAC matches.
 */
static bool verify_entry_hmac(const dclaw_audit_entry_t *entry,
                              const uint8_t *prev_hmac) {
    uint8_t expected[4];
    compute_hmac(entry, prev_hmac, expected);
    return memcmp(expected, entry->hmac, 4) == 0;
}

/*
 * NEW-1 fix: Migrate an old-format audit region that has no header.
 *
 * Old layout: entries started at HAL_FLASH_AUDIT_OFFSET (no 8-byte header).
 * The first entry occupied what is now the header area.  We must NOT corrupt
 * any existing entries.
 *
 * Strategy:
 *   1.  Scan entries from slot 0 forward, validating HMACs with the chain
 *       starting from prev_hmac = {0,0,0,0} (the original boot default).
 *   2.  The first slot whose HMAC does NOT validate is the next write
 *       position (entries after it are either empty/erased or corrupt).
 *   3.  Set ring_head to that slot, and prev_hmac to the last valid
 *       entry's HMAC (or zeros if none were valid).
 *   4.  Write the persistent header.  The header occupies the first 8
 *       bytes of the audit region — overlapping the very first old-format
 *       entry (24 bytes).  That first entry is sacrificed, but all
 *       remaining entries are preserved.
 *
 * The old-format region is detected by audit_ring_restore_header returning
 * -1 (magic mismatch), which is also the case on a truly blank flash.
 * A blank flash will simply have no valid HMACs and we start at slot 0.
 */
static void audit_ring_migrate_old_format(dclaw_audit_writer_t *w) {
    /* Old entries started at the very beginning of the audit region
     * (no header reserved), so old slot N is at:
     *   HAL_FLASH_AUDIT_OFFSET + N * sizeof(dclaw_audit_entry_t)
     */
    const uint32_t old_entry_base = HAL_FLASH_AUDIT_OFFSET;
    const uint16_t max_old_entries = (uint16_t)(HAL_FLASH_AUDIT_SIZE /
                                                sizeof(dclaw_audit_entry_t));

    uint8_t chain_hmac[4] = {0, 0, 0, 0}; /* old format chain started from zeros */
    uint16_t last_valid_slot = 0;
    bool found_any = false;
    uint8_t last_valid_hmac[4] = {0, 0, 0, 0};

    for (uint16_t i = 0; i < max_old_entries && i < DCLAW_AUDIT_RING_SIZE; i++) {
        dclaw_audit_entry_t entry;
        uint32_t offset = old_entry_base + (uint32_t)i * sizeof(dclaw_audit_entry_t);
        if (hal_flash_read(offset, &entry, sizeof(entry)) != 0) {
            break;
        }

        /* An erased/blank entry has all-0xFF or all-0x00 timestamp.
         * Treat either as the end of valid data. */
        if (entry.timestamp == 0 || entry.timestamp == UINT64_MAX) {
            break;
        }

        if (verify_entry_hmac(&entry, chain_hmac)) {
            memcpy(chain_hmac, entry.hmac, 4);
            last_valid_slot = i;
            memcpy(last_valid_hmac, entry.hmac, 4);
            found_any = true;
        } else {
            /* HMAC chain broke — stop here; this is the first invalid slot. */
            break;
        }
    }

    if (found_any) {
        /* The new header occupies the first 8 bytes, which overlaps old slot 0.
         * Entries are now indexed relative to entry_base (after the header).
         * The old slot 0 is sacrificed.  Remaining old entries at offsets
         * [1..last_valid_slot] are still physically in flash at their original
         * positions, but future writes use the new layout.
         *
         * Set head to slot after the last valid one (in new indexing).  Since
         * old slot 0 is now under the header, the effective valid range is
         * reduced by one — but it is simpler and safer to just start writing
         * after the last known-good position.  If last_valid_slot+1 overflows
         * past the new partition entries, wrap around. */
        ring_head = (last_valid_slot + 1) % DCLAW_AUDIT_PARTITION_ENTRIES;
        memcpy(w->prev_hmac, last_valid_hmac, 4);
        fprintf(stderr,
                "[DCLAW-AUDIT] Migrated old-format ring: %u valid entries found, "
                "head set to %u\n", (unsigned)(last_valid_slot + 1),
                (unsigned)ring_head);
    } else {
        /* No valid old entries — truly fresh flash. */
        ring_head = 0;
        memset(w->prev_hmac, 0, 4);
        fprintf(stderr, "[DCLAW-AUDIT] No old-format entries found — starting fresh\n");
    }

    /* Write the new-format header so subsequent boots use the fast path. */
    audit_ring_persist_header(w->prev_hmac);
    hal_flash_sync();
}

/*
 * NEW-1 fix: Initialise the audit ring from persistent flash state.
 *
 * Must be called once at boot (before any dclaw_audit_write).  Reads
 * the persistent header to restore ring_head and prev_hmac so that
 * new entries append after the last valid one and the HMAC chain
 * continues unbroken across restarts.
 *
 * If no valid header is found, check whether the flash contains
 * old-format audit entries (no header) and migrate gracefully.
 * If the flash is truly blank, start fresh from slot 0.
 */
int dclaw_audit_ring_init(void) {
    dclaw_state_t *s = dclaw_get_state();
    dclaw_audit_writer_t *w = &s->audit_writer;

    uint16_t saved_head = 0;
    uint8_t  saved_hmac[4] = {0};

    if (audit_ring_restore_header(&saved_head, saved_hmac) == 0) {
        ring_head = saved_head;
        memcpy(w->prev_hmac, saved_hmac, 4);
        fprintf(stderr, "[DCLAW-AUDIT] Restored ring head=%u from flash\n",
                (unsigned)ring_head);
    } else {
        /* No valid header — could be old-format layout or blank flash.
         * Scan for old-format entries by checking HMACs, set head to the
         * next slot, and write the new header without corrupting existing
         * valid entries. */
        audit_ring_migrate_old_format(w);
    }
    return 0;
}

int dclaw_audit_write(dclaw_action_t action, dclaw_reason_t reason,
                      uint16_t target_hash, uint16_t session_id) {
    /* P2-18 fix: If the audit key was refused (production build without
     * DCLAW_AUDIT_KEY), silently drop the write. The audit ring is
     * non-functional without a proper key. */
    get_audit_key(); /* ensure lazy init */
    if (s_audit_key_refused) {
        return -1;
    }

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

        /* NEW-1 fix: Entries start after the persistent header. */
        const uint32_t entry_base = HAL_FLASH_AUDIT_OFFSET + AUDIT_RING_HDR_SIZE;

        /* Bound the write offset within the flash audit partition (Comment 20 fix) */
        uint16_t bounded_index = ring_head % DCLAW_AUDIT_RING_SIZE;
        if (bounded_index >= DCLAW_AUDIT_PARTITION_ENTRIES) {
            bounded_index = bounded_index % DCLAW_AUDIT_PARTITION_ENTRIES;
        }
        uint32_t write_offset = entry_base +
            (bounded_index * sizeof(dclaw_audit_entry_t));
        if (write_offset + sizeof(dclaw_audit_entry_t) >
            HAL_FLASH_AUDIT_OFFSET + HAL_FLASH_AUDIT_SIZE) {
            write_offset = entry_base;
            ring_head = 0;
        }
        if (hal_flash_write(write_offset, &entry, sizeof(dclaw_audit_entry_t)) != 0) {
            return -1;
        }
        ring_head = (ring_head + 1) % DCLAW_AUDIT_RING_SIZE;
        w->total_flash_writes++;
        /* Update prev_hmac so the next buffered entry chains from this BLOCK entry */
        memcpy(w->prev_hmac, entry.hmac, 4);
        /* NEW-1 fix: Persist head position and last HMAC to flash header */
        audit_ring_persist_header(w->prev_hmac);
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

bool dclaw_audit_key_provisioned(void) {
    /* Trigger lazy key load if not yet done */
    get_audit_key();
    return s_audit_key_provisioned;
}
