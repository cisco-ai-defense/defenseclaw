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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static char broker_urls[DCLAW_BROKER_FALLBACK_LIST_SIZE][DCLAW_BROKER_URL_MAX];
static uint8_t active_policy_partition = 0; /* 0 = A, 1 = B */
static uint16_t persisted_policy_version = 0;
static bool partition_rolled_back = false;

extern dclaw_state_t *dclaw_get_state(void);

/*
 * Persist the active policy partition indicator and policy version to the
 * config partition in flash so they survive restarts. Without this, the
 * daemon always boots reading partition A (default), losing any OTA that
 * wrote to partition B, and the anti-rollback check (REQ-36) would accept
 * any OTA version > 0 even if the device previously ran a higher version.
 *
 * Layout in config flash (at CONFIG_OFFSET + 8, after the emergency state):
 *   [8]  magic marker 0xDC
 *   [9]  magic marker 0xAB  ("DC Active B")
 *   [10] active_partition (0x00 or 0x01)
 *   [11] reserved (0x00)
 *   [12] policy_version high byte
 *   [13] policy_version low byte
 *
 * Double-write + CRC16 scheme for partial-write resilience.
 * Each record is 8 bytes: 6 data + 2 CRC16 appended.  Two copies (A & B)
 * are written so that a partial write to copy A still leaves copy B intact.
 * On load: check CRC of A, if valid use it.  Else check CRC of B.  If both
 * invalid, fall back to defaults.
 *
 * Flash layout (each copy):
 *   [0]  PARTITION_MAGIC_0  (0xDC)
 *   [1]  PARTITION_MAGIC_1  (0xAB)
 *   [2]  active_partition   (0x00 or 0x01)
 *   [3]  canary_rolled_back (0x00 or 0x01)
 *   [4]  policy_version high byte
 *   [5]  policy_version low byte
 *   [6]  CRC16 high byte
 *   [7]  CRC16 low byte
 */
#define PARTITION_FLASH_OFFSET_A (HAL_FLASH_CONFIG_OFFSET + 24)
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
 * Write, sync, and read back a single record (data + CRC16). A caller may
 * acknowledge a policy switch only after at least one copy is durable.
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
    if (hal_flash_sync() != 0) {
        fprintf(stderr, "[DCLAW] ERROR: flash sync failed at partition record 0x%X.\n",
                (unsigned)offset);
        return -1;
    }
    uint8_t verify[PARTITION_RECORD_SIZE];
    if (hal_flash_read(offset, verify, sizeof(verify)) != 0 ||
        memcmp(verify, record, sizeof(record)) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: partition record readback failed at 0x%X.\n",
                (unsigned)offset);
        return -1;
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
    if (record[2] > 1 || record[3] > 1) return false;
    uint16_t stored_crc = ((uint16_t)record[6] << 8) | record[7];
    uint16_t computed_crc = crc16_ccitt(record, PARTITION_DATA_SIZE);
    if (stored_crc != computed_crc) {
        return false;
    }
    memcpy(out_buf, record, PARTITION_DATA_SIZE);
    return true;
}

static int persist_active_partition(void) {
    uint8_t data[PARTITION_DATA_SIZE];
    data[0] = PARTITION_MAGIC_0;
    data[1] = PARTITION_MAGIC_1;
    data[2] = active_policy_partition;
    data[3] = partition_rolled_back ? 0x01 : 0x00;
    data[4] = (uint8_t)(persisted_policy_version >> 8);
    data[5] = (uint8_t)(persisted_policy_version);

    /* Double-write with CRC16 for partial-write resilience.
     * Write copy A first, then copy B.  On load, A is preferred; B is the
     * backup in case A was only partially written. */
    bool persisted_a = write_record_with_crc(PARTITION_FLASH_OFFSET_A, data) == 0;
    if (!persisted_a) {
        fprintf(stderr, "[DCLAW] WARNING: Failed to persist partition record A.\n");
    }
    bool persisted_b = write_record_with_crc(PARTITION_FLASH_OFFSET_B, data) == 0;
    if (!persisted_b) {
        fprintf(stderr, "[DCLAW] WARNING: Failed to persist partition record B.\n");
    }
    return (int)persisted_a + (int)persisted_b;
}

static bool blank_record(const uint8_t *bytes, size_t len) {
    bool zero = true, erased = true;
    for (size_t i = 0; i < len; i++) {
        zero &= bytes[i] == 0;
        erased &= bytes[i] == 0xff;
    }
    return zero || erased;
}

/* A process boot consumes one monotonically increasing generation before it
 * can register or send heartbeats. These records do not overlap emergency
 * state (+0), policy metadata (+16/+24), or release sequence (+32/+48). */
#define BOOT_COUNTER_A (HAL_FLASH_CONFIG_OFFSET + 64)
#define BOOT_COUNTER_B (HAL_FLASH_CONFIG_OFFSET + 80)
#define BOOT_COUNTER_SIZE 12
static uint32_t boot_counter;

static uint32_t boot_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static void boot_put_be32(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static bool boot_record_valid(const uint8_t *record, uint32_t *value) {
    if (record[0] != 0xdc || record[1] != 0x42) return false;
    uint32_t seq = boot_be32(record + 2);
    uint16_t crc = ((uint16_t)record[10] << 8) | record[11];
    if (seq == 0 || boot_be32(record + 6) != ~seq ||
        crc != crc16_ccitt(record, 10)) return false;
    *value = seq;
    return true;
}

static int boot_write_record(uint32_t offset, const uint8_t *record) {
    uint8_t verify[BOOT_COUNTER_SIZE];
    if (hal_flash_write(offset, record, BOOT_COUNTER_SIZE) != 0 ||
        hal_flash_sync() != 0 ||
        hal_flash_read(offset, verify, sizeof(verify)) != 0 ||
        memcmp(record, verify, sizeof(verify)) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Boot counter write/sync/readback failed at 0x%X.\n",
                (unsigned)offset);
        return -1;
    }
    return 0;
}

uint32_t dclaw_boot_counter_get(void) { return boot_counter; }

int dclaw_boot_counter_advance(void) {
    boot_counter = 0;
    uint8_t a[BOOT_COUNTER_SIZE], b[BOOT_COUNTER_SIZE];
    if (hal_flash_read(BOOT_COUNTER_A, a, sizeof(a)) != 0 ||
        hal_flash_read(BOOT_COUNTER_B, b, sizeof(b)) != 0) {
        fprintf(stderr, "[DCLAW] ERROR: Cannot read boot counter; refusing MQTT startup.\n");
        return -1;
    }
    uint32_t seq_a = 0, seq_b = 0;
    bool valid_a = boot_record_valid(a, &seq_a);
    bool valid_b = boot_record_valid(b, &seq_b);
    uint32_t last = seq_a > seq_b ? seq_a : seq_b;
    if (!valid_a && !valid_b &&
        !(blank_record(a, sizeof(a)) && blank_record(b, sizeof(b)))) {
        fprintf(stderr, "[DCLAW] ERROR: Both boot counter copies corrupt; refusing MQTT startup.\n");
        return -1;
    }
    if (last == UINT32_MAX) {
        fprintf(stderr, "[DCLAW] ERROR: Boot counter exhausted; refusing MQTT startup.\n");
        return -1;
    }
    uint32_t next = last + 1;
    uint8_t record[BOOT_COUNTER_SIZE] = {0xdc, 0x42};
    boot_put_be32(record + 2, next);
    boot_put_be32(record + 6, ~next);
    uint16_t crc = crc16_ccitt(record, 10);
    record[10] = (uint8_t)(crc >> 8);
    record[11] = (uint8_t)crc;
    bool stored_a = boot_write_record(BOOT_COUNTER_A, record) == 0;
    bool stored_b = boot_write_record(BOOT_COUNTER_B, record) == 0;
    if (!stored_a && !stored_b) {
        fprintf(stderr, "[DCLAW] ERROR: Boot counter not durable; refusing MQTT startup.\n");
        return -1;
    }
    if (!stored_a || !stored_b)
        fprintf(stderr, "[DCLAW] WARNING: Boot counter redundancy degraded; one copy will be repaired on next boot.\n");
    boot_counter = next;
    return 0;
}

static int load_active_partition_from_flash(void) {
    /* Try both records A and B (CRC-validated).
     * When both are valid, pick the one
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
        uint8_t raw[PARTITION_RECORD_SIZE];
        if (hal_flash_read(PARTITION_FLASH_OFFSET_A, raw, PARTITION_RECORD_SIZE) == 0 &&
            raw[0] == PARTITION_MAGIC_0 && raw[1] == PARTITION_MAGIC_1) {
#if !DCLAW_DEV_MODE
            fprintf(stderr, "[DCLAW] ERROR: Detected unprotected legacy 4-byte flash format. "
                    "State preserved; run the explicit migration before production startup.\n");
            return -1;
#endif
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
            if (persist_active_partition() == 0) return -1;
            fprintf(stderr, "[DCLAW] Migration: re-persisted in new CRC format "
                    "(partition=%c, version=%u).\n",
                    active_policy_partition == 0 ? 'A' : 'B',
                    persisted_policy_version);
            goto apply_version;
        }

        /* Only a blank flash is a first boot. Treat damaged records or an
         * existing OTA partition without records as corruption; resetting
         * version zero there would permit policy rollback after a reboot. */
        uint8_t raw_b[PARTITION_RECORD_SIZE];
        uint8_t policy_a[8], policy_b[8];
        if (hal_flash_read(PARTITION_FLASH_OFFSET_A, raw, sizeof(raw)) != 0 ||
            hal_flash_read(PARTITION_FLASH_OFFSET_B, raw_b, sizeof(raw_b)) != 0 ||
            hal_flash_read(HAL_FLASH_POLICY_A_OFFSET, policy_a, sizeof(policy_a)) != 0 ||
            hal_flash_read(HAL_FLASH_POLICY_B_OFFSET, policy_b, sizeof(policy_b)) != 0 ||
            !blank_record(raw, sizeof(raw)) || !blank_record(raw_b, sizeof(raw_b)) ||
            !blank_record(policy_a, sizeof(policy_a)) ||
            !blank_record(policy_b, sizeof(policy_b))) {
            fprintf(stderr, "[DCLAW] ERROR: Partition records invalid on nonblank flash; refusing policy version reset.\n");
            return -1;
        }
        fprintf(stderr, "[DCLAW] INFO: No partition records found (first boot) — initializing defaults.\n");
        return persist_active_partition() > 0 ? 0 : -1;
    }

    if (buf[2] <= 1) {
        active_policy_partition = buf[2];
        fprintf(stderr, "[DCLAW] Restored active policy partition %c from flash.\n",
                active_policy_partition == 0 ? 'A' : 'B');
    }
    persisted_policy_version = ((uint16_t)buf[4] << 8) | buf[5];
    partition_rolled_back = buf[3] == 1;

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
                if (persist_active_partition() == 0) return -1;
            } else {
                /* Partition is blank or erased — no version to recover.
                 * Leave persisted_policy_version at 0; this is a fresh device
                 * or the partition was never written via OTA. */
                persisted_policy_version = 0;
            }
        }
    }

apply_version:
    dclaw_get_state()->rollback_pending = partition_rolled_back;
    if (persisted_policy_version > 0) {
        dclaw_state_t *s = dclaw_get_state();
        s->device.policy_version = persisted_policy_version;
        fprintf(stderr, "[DCLAW] Restored policy version %u from flash.\n",
                persisted_policy_version);
    }
    return 0;
}

int dclaw_config_load_brokers(void) {
    /* In Phase 1, broker URLs are loaded from /etc/edge-connector/brokers.conf
     * Each line is one URL, up to DCLAW_BROKER_FALLBACK_LIST_SIZE */
    memset(broker_urls, 0, sizeof(broker_urls));
    const char *env_broker = getenv("DCLAW_BROKER_URL");
    const char *url = (env_broker && env_broker[0] != '\0') ? env_broker : "mqtt://localhost:1883";
    strncpy(broker_urls[0], url, DCLAW_BROKER_URL_MAX - 1);
    broker_urls[0][DCLAW_BROKER_URL_MAX - 1] = '\0'; /* explicit NUL after strncpy */

    return load_active_partition_from_flash();
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
 * Switch the active policy partition and persist its version together in
 * each checked flash record. At least one synced/read-back copy is required.
 *
 * @param policy_version  The policy version to persist alongside the
 *                        partition switch. Pass 0 to keep the currently
 *                        highest accepted version (used by canary rollback
 *                        so the rejected signed policy cannot be replayed).
 */
int dclaw_config_switch_policy_partition(uint16_t policy_version) {
    uint8_t previous_partition = active_policy_partition;
    uint16_t previous_version = persisted_policy_version;
    bool previous_rollback = partition_rolled_back;
    bool rollback = policy_version == 0;
    uint8_t old_a[PARTITION_RECORD_SIZE], old_b[PARTITION_RECORD_SIZE];
    if (hal_flash_read(PARTITION_FLASH_OFFSET_A, old_a, sizeof(old_a)) != 0 ||
        hal_flash_read(PARTITION_FLASH_OFFSET_B, old_b, sizeof(old_b)) != 0)
        return -1;
    active_policy_partition = (active_policy_partition == 0) ? 1 : 0;
    partition_rolled_back = rollback;
    if (policy_version != 0) {
        persisted_policy_version = policy_version;
    }
    int durable_copies = persist_active_partition();
    /* Forward OTA is recoverable from either copy: load picks the higher
     * version. Rollback retains that version while switching partitions; a
     * stale copy could otherwise win the equal-version tie after reboot. */
    if (durable_copies < (rollback ? 2 : 1)) {
        active_policy_partition = previous_partition;
        persisted_policy_version = previous_version;
        partition_rolled_back = previous_rollback;
        uint8_t check[PARTITION_RECORD_SIZE];
        bool restored_a = hal_flash_write(PARTITION_FLASH_OFFSET_A, old_a, sizeof(old_a)) == 0 &&
                          hal_flash_sync() == 0 &&
                          hal_flash_read(PARTITION_FLASH_OFFSET_A, check, sizeof(check)) == 0 &&
                          memcmp(check, old_a, sizeof(check)) == 0;
        bool restored_b = hal_flash_write(PARTITION_FLASH_OFFSET_B, old_b, sizeof(old_b)) == 0 &&
                          hal_flash_sync() == 0 &&
                          hal_flash_read(PARTITION_FLASH_OFFSET_B, check, sizeof(check)) == 0 &&
                          memcmp(check, old_b, sizeof(check)) == 0;
        if (!restored_a || !restored_b)
            fprintf(stderr, "[DCLAW] ERROR: Partition switch rollback incomplete; flash repair may be required.\n");
        return -1;
    }
    dclaw_get_state()->rollback_pending = partition_rolled_back;
    return 0;
}
