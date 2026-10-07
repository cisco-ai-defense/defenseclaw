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
 */
#define PARTITION_FLASH_OFFSET   (HAL_FLASH_CONFIG_OFFSET + 8)
#define PARTITION_FLASH_SIZE     6
#define PARTITION_MAGIC_0        0xDC
#define PARTITION_MAGIC_1        0xAB

static void persist_active_partition(void) {
    uint8_t buf[PARTITION_FLASH_SIZE];
    buf[0] = PARTITION_MAGIC_0;
    buf[1] = PARTITION_MAGIC_1;
    buf[2] = active_policy_partition;
    buf[3] = 0x00;
    buf[4] = (uint8_t)(persisted_policy_version >> 8);
    buf[5] = (uint8_t)(persisted_policy_version);
    if (hal_flash_write(PARTITION_FLASH_OFFSET, buf, PARTITION_FLASH_SIZE) != 0) {
        fprintf(stderr, "[DCLAW] WARNING: Failed to persist active partition to flash.\n");
    }
    /* P1-07 fix: Flush to durable storage so a power cut after this call
     * cannot lose the write that is sitting in the OS page cache. */
    hal_flash_sync();
}

static void load_active_partition_from_flash(void) {
    uint8_t buf[PARTITION_FLASH_SIZE];
    if (hal_flash_read(PARTITION_FLASH_OFFSET, buf, PARTITION_FLASH_SIZE) != 0) {
        return; /* flash read failed — use default (partition A) */
    }
    if (buf[0] != PARTITION_MAGIC_0 || buf[1] != PARTITION_MAGIC_1) {
        return; /* no valid persisted state — use default */
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
    const char *url = (env_broker && env_broker[0] != '\0') ? env_broker : "mqtts://localhost:8883";
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

/*
 * Persist a new policy version WITHOUT switching the active partition.
 * Primarily a convenience for callers that need to update the version
 * in-place (e.g. migration paths). The normal OTA path should use
 * dclaw_config_switch_policy_partition(version) which writes both the
 * partition indicator and version atomically in a single flash write.
 */
void dclaw_config_persist_policy_version(uint16_t version) {
    persisted_policy_version = version;
    persist_active_partition();
}
