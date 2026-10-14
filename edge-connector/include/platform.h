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

#ifndef DCLAW_PLATFORM_H
#define DCLAW_PLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/* Hardware Abstraction Layer — platform-specific operations. */

/* Monotonic tick counter (millisecond resolution). Wraps after ~584 million years with uint64_t. */
uint64_t hal_tick_ms(void);

/* Flash operations */
int hal_flash_read(uint32_t offset, void *buf, size_t len);
int hal_flash_write(uint32_t offset, const void *buf, size_t len);
int hal_flash_sync(void);   /* Flush OS page cache to durable storage */
int hal_flash_erase_sector(uint32_t sector);

/* Flash partition offsets (configured per platform) */
#define HAL_FLASH_POLICY_A_OFFSET   0x00000
#define HAL_FLASH_POLICY_A_SIZE     4096
#define HAL_FLASH_POLICY_B_OFFSET   0x01000
#define HAL_FLASH_POLICY_B_SIZE     4096
#define HAL_FLASH_AUDIT_OFFSET      0x02000
#define HAL_FLASH_AUDIT_SIZE        4096
#define HAL_FLASH_CONFIG_OFFSET     0x03000
#define HAL_FLASH_CONFIG_SIZE       1024

/* Unix socket for IPC */
int hal_ipc_socket_create(const char *path);
int hal_ipc_socket_accept(int server_fd);
void hal_ipc_socket_close(int fd);

/* Peer credential retrieval */
int hal_get_peer_cred(int fd, uint32_t *uid, uint32_t *gid, int32_t *pid);
uint64_t hal_get_pid_start_time(int32_t pid);

/* Secure random */
int hal_random_bytes(void *buf, size_t len);

/* Device certificate loading */
int hal_load_device_cert(uint8_t *cert_buf, size_t *cert_len, size_t max_len);
int hal_load_device_key(uint8_t *key_buf, size_t *key_len, size_t max_len);
int hal_load_ca_cert(uint8_t *cert_buf, size_t *cert_len, size_t max_len);

/* Watchdog */
void hal_watchdog_feed(void);

/* Platform init/shutdown */
int hal_init(void);
void hal_shutdown(void);

static void *(*const volatile dclaw_secure_zero_ptr)(void *, int, size_t) = memset;
static inline void dclaw_secure_zero(void *buf, size_t len) {
    dclaw_secure_zero_ptr(buf, 0, len);
}

/*
 * Best-effort scrub of an environment variable from the C runtime.
 * Overwrites the getenv() pointer with '0' bytes (via volatile to
 * defeat dead-store elimination), then calls unsetenv().
 *
 * NOTE: /proc/PID/environ (a snapshot at exec) is NOT cleared by this.
 * Use file-based secret provisioning in production.
 */
#include <stdlib.h>
static inline void dclaw_scrub_env(const char *name) {
    char *ev = getenv(name);
    if (ev) {
        volatile char *p = (volatile char *)ev;
        while (*p) { *p++ = '0'; }
    }
    unsetenv(name);
}

/*
 * dclaw_scrub_env() does NOT clear /proc/PID/environ (exec-time snapshot).
 * In production, use file-based key provisioning (/etc/defenseclaw/device.key).
 * The daemon calls prctl(PR_SET_DUMPABLE, 0) to block /proc/PID/environ reads.
 */

#endif /* DCLAW_PLATFORM_H */
