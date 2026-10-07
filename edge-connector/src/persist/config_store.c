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

void dclaw_config_switch_policy_partition(void) {
    active_policy_partition = (active_policy_partition == 0) ? 1 : 0;
    /* P1-07 fix: Persist the new active partition to flash */
    persist_active_partition();
}

/*
 * P1-10 fix: Persist the policy version alongside the active partition.
 * Called from ota_receiver.c after a successful OTA apply so the version
 * survives restarts and the anti-rollback check (REQ-36) works correctly.
 */
void dclaw_config_persist_policy_version(uint16_t version) {
    persisted_policy_version = version;
    persist_active_partition();
}
