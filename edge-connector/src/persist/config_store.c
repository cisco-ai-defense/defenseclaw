#include "defenseclaw.h"
#include "platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static char broker_urls[DCLAW_BROKER_FALLBACK_LIST_SIZE][DCLAW_BROKER_URL_MAX];
static uint8_t active_policy_partition = 0; /* 0 = A, 1 = B */
static uint16_t persisted_policy_version = 0;

extern dclaw_state_t *dclaw_get_state(void);

/*
 * P1-07 fix: Persist the active policy partition indicator to the config
 * partition in flash so it survives restarts. Without this, the daemon
 * always boots reading partition A (default), losing any OTA that wrote
 * to partition B.
 *
 * P1-10 fix: Extended to also persist the policy version (uint16, big-endian)
 * so that anti-rollback checks (REQ-36) work correctly across restarts.
 * Without persisting the version, the daemon boots with policy_version=0
 * and accepts any OTA version > 0, even if the device previously ran a
 * higher version — defeating the monotonic version requirement.
 *
 * Layout in config flash (at CONFIG_OFFSET + 8, after the emergency state):
 *   [8]  magic marker 0xDC
 *   [9]  magic marker 0xAB  ("DC Active B")
 *   [10] active_partition (0x00 or 0x01)
 *   [11] reserved (0x00)
 *   [12] policy_version high byte
 *   [13] policy_version low byte
 *
 * Issue #07 fix: Double-write + CRC16 scheme for partial-write resilience.
 * Each record is 8 bytes: 6 data + 2 CRC16 appended.  Two copies (A & B)
 * are written so that a partial write to copy A still leaves copy B intact.
 * On load: check CRC of A, if valid use it.  Else check CRC of B.  If both
 * invalid, fall back to defaults.
 *
 * Flash layout (each copy):
 *   [0]  PARTITION_MAGIC_0  (0xDC)
 *   [1]  PARTITION_MAGIC_1  (0xAB)
 *   [2]  active_partition   (0x00 or 0x01)
 *   [3]  reserved           (0x00)
 *   [4]  policy_version high byte
 *   [5]  policy_version low byte
 *   [6]  CRC16 high byte
 *   [7]  CRC16 low byte
 */
#define PARTITION_FLASH_OFFSET_A (HAL_FLASH_CONFIG_OFFSET + 8)
#define PARTITION_FLASH_OFFSET_B (HAL_FLASH_CONFIG_OFFSET + 8 + PARTITION_RECORD_SIZE)
#define PARTITION_DATA_SIZE      6
#define PARTITION_RECORD_SIZE    8   /* 6 data + 2 CRC16 */
#define PARTITION_MAGIC_0        0xDC
#define PARTITION_MAGIC_1        0xAB

/* CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no final XOR */
static uint16_t crc16_ccitt(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc = crc << 1;
        }
    }
    return crc;
}

/*
 * Write a single record (data + CRC16) to the given flash offset.
 * Returns 0 on success, -1 on failure (retries once on short write).
 */
static int write_record_with_crc(uint32_t offset, const uint8_t *data) {
    uint8_t record[PARTITION_RECORD_SIZE];
    memcpy(record, data, PARTITION_DATA_SIZE);
    uint16_t crc = crc16_ccitt(data, PARTITION_DATA_SIZE);
    record[6] = (uint8_t)(crc >> 8);
    record[7] = (uint8_t)(crc);

    int rc = hal_flash_write(offset, record, PARTITION_RECORD_SIZE);
    if (rc != 0) {
        fprintf(stderr, "[DCLAW] WARNING: flash write returned %d at offset 0x%X, retrying.\n",
                rc, (unsigned)offset);
        rc = hal_flash_write(offset, record, PARTITION_RECORD_SIZE);
        if (rc != 0) {
            fprintf(stderr, "[DCLAW] ERROR: flash write retry failed at offset 0x%X.\n",
                    (unsigned)offset);
            return -1;
        }
    }
    return 0;
}

/*
 * Validate a record: check that magic bytes and CRC16 match.
 * Returns true if valid, and fills out_buf with the 6 data bytes.
 */
static bool read_and_validate_record(uint32_t offset, uint8_t *out_buf) {
    uint8_t record[PARTITION_RECORD_SIZE];
    if (hal_flash_read(offset, record, PARTITION_RECORD_SIZE) != 0) {
        return false;
    }
    if (record[0] != PARTITION_MAGIC_0 || record[1] != PARTITION_MAGIC_1) {
        return false;
    }
    uint16_t stored_crc = ((uint16_t)record[6] << 8) | record[7];
    uint16_t computed_crc = crc16_ccitt(record, PARTITION_DATA_SIZE);
    if (stored_crc != computed_crc) {
        return false;
    }
    memcpy(out_buf, record, PARTITION_DATA_SIZE);
    return true;
}

static void persist_active_partition(void) {
    uint8_t data[PARTITION_DATA_SIZE];
    data[0] = PARTITION_MAGIC_0;
    data[1] = PARTITION_MAGIC_1;
    data[2] = active_policy_partition;
    data[3] = 0x00;
    data[4] = (uint8_t)(persisted_policy_version >> 8);
    data[5] = (uint8_t)(persisted_policy_version);

    /* Issue #07 fix: Double-write with CRC16 for partial-write resilience.
     * Write copy A first, then copy B.  On load, A is preferred; B is the
     * backup in case A was only partially written. */
    if (write_record_with_crc(PARTITION_FLASH_OFFSET_A, data) != 0) {
        fprintf(stderr, "[DCLAW] WARNING: Failed to persist partition record A.\n");
    }
    if (write_record_with_crc(PARTITION_FLASH_OFFSET_B, data) != 0) {
        fprintf(stderr, "[DCLAW] WARNING: Failed to persist partition record B.\n");
    }

    /* P1-07 fix: Flush to durable storage so a power cut after this call
     * cannot lose the write that is sitting in the OS page cache. */
    if (hal_flash_sync() != 0) {
        fprintf(stderr, "[DCLAW] ERROR: hal_flash_sync failed after partition persist.\n");
    }
}

static void load_active_partition_from_flash(void) {
    /* Issue #07 fix: Try both records A and B (CRC-validated).
     * P1-07 fix (dual-record selection): When both are valid, pick the one
     * with the HIGHER policy version — not just the first valid one. This
     * handles the case where copy A has an older version because its write
     * failed during a v11 apply that successfully wrote copy B.
     * If versions are equal, prefer A (canonical copy). */
    uint8_t buf_a[PARTITION_DATA_SIZE];
    uint8_t buf_b[PARTITION_DATA_SIZE];
    bool valid_a = read_and_validate_record(PARTITION_FLASH_OFFSET_A, buf_a);
    bool valid_b = read_and_validate_record(PARTITION_FLASH_OFFSET_B, buf_b);

    uint8_t *buf = NULL;

    if (valid_a && valid_b) {
        /* Both valid: pick the record with the higher policy version.
         * If equal, prefer A (canonical primary copy). */
        uint16_t ver_a = ((uint16_t)buf_a[4] << 8) | buf_a[5];
        uint16_t ver_b = ((uint16_t)buf_b[4] << 8) | buf_b[5];
        if (ver_b > ver_a) {
            buf = buf_b;
            fprintf(stderr, "[DCLAW] Both partition records valid; B has newer version "
                    "(%u > %u) — using B.\n", ver_b, ver_a);
        } else {
            buf = buf_a;
            if (ver_a != ver_b) {
                fprintf(stderr, "[DCLAW] Both partition records valid; A has newer version "
                        "(%u >= %u) — using A.\n", ver_a, ver_b);
            }
        }
    } else if (valid_a) {
        buf = buf_a;
    } else if (valid_b) {
        fprintf(stderr, "[DCLAW] WARNING: Partition record A CRC invalid, using backup B.\n");
        buf = buf_b;
    } else {
        /* P1-07 fix (old format migration): Both CRC-validated records failed.
         * Check if offset A has the raw magic bytes 0xDC 0xAB from the old
         * 4-byte format (magic + partition + reserved, no version, no CRC).
         * The old format's CRC fails because bytes [4..7] are not a valid
         * CRC16 for the 6-byte data region.
         *
         * Recovery: read the old 4-byte record to get the active partition,
         * then recover the version from the active partition's OTA header.
         * Re-write both records in the new 8-byte CRC format. */
        uint8_t raw[PARTITION_RECORD_SIZE];
        if (hal_flash_read(PARTITION_FLASH_OFFSET_A, raw, PARTITION_RECORD_SIZE) == 0 &&
            raw[0] == PARTITION_MAGIC_0 && raw[1] == PARTITION_MAGIC_1) {
            fprintf(stderr, "[DCLAW] Detected old 4-byte flash format at record A — migrating.\n");
            uint8_t old_partition = raw[2];
            if (old_partition <= 1) {
                active_policy_partition = old_partition;
            }
            /* Recover version from the active partition's OTA header */
            uint32_t part_offset = (active_policy_partition == 0)
                                    ? HAL_FLASH_POLICY_A_OFFSET
                                    : HAL_FLASH_POLICY_B_OFFSET;
            uint8_t hdr_buf[8];
            if (hal_flash_read(part_offset, hdr_buf, 8) == 0) {
                uint16_t recovered_ver = ((uint16_t)hdr_buf[0] << 8) | hdr_buf[1];
                uint16_t payload_len   = ((uint16_t)hdr_buf[2] << 8) | hdr_buf[3];
                if (recovered_ver > 0 && recovered_ver != 0xFFFF &&
                    payload_len > 0 && payload_len <= HAL_FLASH_POLICY_A_SIZE - 8) {
                    persisted_policy_version = recovered_ver;
                    fprintf(stderr, "[DCLAW] Migration: recovered policy version %u "
                            "from partition %c OTA header.\n",
                            recovered_ver,
                            active_policy_partition == 0 ? 'A' : 'B');
                } else {
                    persisted_policy_version = 0;
                    fprintf(stderr, "[DCLAW] Migration: partition %c OTA header blank/invalid "
                            "— version defaults to 0.\n",
                            active_policy_partition == 0 ? 'A' : 'B');
                }
            }
            /* Re-write both records in new 8-byte CRC format */
            persist_active_partition();
            fprintf(stderr, "[DCLAW] Migration: re-persisted in new CRC format "
                    "(partition=%c, version=%u).\n",
                    active_policy_partition == 0 ? 'A' : 'B',
                    persisted_policy_version);
            goto apply_version;
        }

        fprintf(stderr, "[DCLAW] WARNING: Both partition records corrupt — using defaults.\n");
        return; /* fall back to defaults (partition A, version 0) */
    }

    if (buf[2] <= 1) {
        active_policy_partition = buf[2];
        fprintf(stderr, "[DCLAW] Restored active policy partition %c from flash.\n",
                active_policy_partition == 0 ? 'A' : 'B');
    }
    /* P1-10 fix: Restore persisted policy version for anti-rollback (REQ-36).
     * Also write it into g_state.device.policy_version so the OTA receiver's
     * version check (hdr.version <= s->device.policy_version) uses the real
     * last-applied version instead of 0. */
    persisted_policy_version = ((uint16_t)buf[4] << 8) | buf[5];

    /* P1-07 migration fix: Handle upgrade from old 4-byte flash format to the
     * new 6-byte format. The old format was [magic0, magic1, partition, reserved]
     * and did not include version bytes. When upgrading, bytes [4..5] read as
     * 0x0000 (or 0xFFFF on erased flash), which resets the version to 0 and
     * allows policy downgrade — defeating REQ-36 anti-rollback.
     *
     * Recovery: if the version field is zero (or 0xFFFF) but we have a valid
     * active partition, read the OTA policy header directly from that flash
     * partition. The header format is: version(u16 BE), payload_len(u16 BE),
     * canary_baseline(u16 BE), reserved(u16 BE) = 8 bytes total. If we find
     * a valid version > 0 there, adopt it and re-persist in the new 6-byte
     * format so subsequent boots use the fast path. */
    if (persisted_policy_version == 0 || persisted_policy_version == 0xFFFF) {
        uint32_t part_offset = (active_policy_partition == 0)
                                ? HAL_FLASH_POLICY_A_OFFSET
                                : HAL_FLASH_POLICY_B_OFFSET;
        uint8_t hdr_buf[8];
        if (hal_flash_read(part_offset, hdr_buf, 8) == 0) {
            uint16_t recovered_ver = ((uint16_t)hdr_buf[0] << 8) | hdr_buf[1];
            uint16_t payload_len   = ((uint16_t)hdr_buf[2] << 8) | hdr_buf[3];
            /* Sanity: version must be non-zero and payload_len must be plausible
             * (non-zero, fits in partition). This rejects blank/erased partitions
             * where all bytes are 0x00 or 0xFF. */
            if (recovered_ver > 0 && recovered_ver != 0xFFFF &&
                payload_len > 0 && payload_len <= HAL_FLASH_POLICY_A_SIZE - 8) {
                persisted_policy_version = recovered_ver;
                fprintf(stderr, "[DCLAW] Migration: recovered policy version %u "
                        "from active partition %c OTA header.\n",
                        recovered_ver,
                        active_policy_partition == 0 ? 'A' : 'B');
                /* Re-persist in new 6-byte format so future boots are clean */
                persist_active_partition();
            } else {
                /* Partition is blank or erased — no version to recover.
                 * Leave persisted_policy_version at 0; this is a fresh device
                 * or the partition was never written via OTA. */
                persisted_policy_version = 0;
            }
        }
    }

apply_version:
    if (persisted_policy_version > 0) {
        dclaw_state_t *s = dclaw_get_state();
        s->device.policy_version = persisted_policy_version;
        fprintf(stderr, "[DCLAW] Restored policy version %u from flash.\n",
                persisted_policy_version);
    }
}

int dclaw_config_load_brokers(void) {
    /* In Phase 1, broker URLs are loaded from /etc/edge-connector/brokers.conf
     * Each line is one URL, up to DCLAW_BROKER_FALLBACK_LIST_SIZE */
    memset(broker_urls, 0, sizeof(broker_urls));
    const char *env_broker = getenv("DCLAW_BROKER_URL");
    const char *url = (env_broker && env_broker[0] != '\0') ? env_broker : "mqtt://localhost:1883";
    strncpy(broker_urls[0], url, DCLAW_BROKER_URL_MAX - 1);
    broker_urls[0][DCLAW_BROKER_URL_MAX - 1] = '\0'; /* explicit NUL after strncpy */

    /* P1-07 fix: Restore the active policy partition from flash on startup */
    load_active_partition_from_flash();

    return 0;
}

const char *dclaw_config_get_broker(uint8_t index) {
    if (index >= DCLAW_BROKER_FALLBACK_LIST_SIZE) return NULL;
    if (broker_urls[index][0] == '\0') return NULL;
    return broker_urls[index];
}

uint8_t dclaw_config_active_policy_partition(void) {
    return active_policy_partition;
}

/*
 * P1-07 fix (atomic persistence): Switch the active policy partition AND
 * persist both the new partition indicator and the policy version in a
 * SINGLE hal_flash_write call. Previously the partition and version were
 * written in two separate calls; a power cut between them could leave the
 * version at the old value while the partition had already been switched,
 * defeating the anti-rollback check (REQ-36) on the next boot.
 *
 * @param policy_version  The policy version to persist alongside the
 *                        partition switch. Pass 0 to keep the currently
 *                        persisted version (used by rollback paths that
 *                        do not change the version).
 */
void dclaw_config_switch_policy_partition(uint16_t policy_version) {
    active_policy_partition = (active_policy_partition == 0) ? 1 : 0;
    if (policy_version != 0) {
        persisted_policy_version = policy_version;
    }
    /* Single flash write covers both partition indicator and policy version */
    persist_active_partition();
}

/* P2-17: dclaw_config_persist_policy_version() removed — had no callers.
 * The normal OTA path uses dclaw_config_switch_policy_partition(version)
 * which writes both the partition indicator and version atomically. */
