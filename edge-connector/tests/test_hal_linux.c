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


/* Linux HAL checks. */

#include "defenseclaw.h"
#include "platform.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

/* Regression: the production prefix check compared 20 of the 21 characters
 * of "/var/lib/defenseclaw/", so "/var/lib/defenseclawX/flash.bin" passed. */
static void test_flash_path_prefix(void) {
    assert(hal_flash_path_is_provisioned("/var/lib/defenseclaw/flash.bin"));
    assert(hal_flash_path_is_provisioned("/etc/defenseclaw/flash.bin"));
    assert(!hal_flash_path_is_provisioned("/var/lib/defenseclawX/flash.bin"));
    assert(!hal_flash_path_is_provisioned("/var/lib/defenseclaw"));
    assert(!hal_flash_path_is_provisioned("/etc/defenseclawX/flash.bin"));
    assert(!hal_flash_path_is_provisioned("/tmp/flash.bin"));
    assert(!hal_flash_path_is_provisioned(NULL));
    printf("  PASS: production flash path prefix is matched exactly\n");
}


/* Exit status of a child process that tries to start a second engine on
 * the current flash file: 0 when it started, 1 when it refused. */
static int second_engine_status(void) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        dclaw_device_info_t info = {.device_id = 2, .tenant_id = 1, .fleet_id = 1};
        _exit(dclaw_init(&info) == 0 ? 0 : 1);
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status));
    return WEXITSTATUS(status);
}

/* Regression: the daemon and an in-process engine (or two daemons) could
 * open one flash file and overwrite each other's audit ring, boot counter
 * and emergency records. */
static void test_flash_file_is_exclusive(void) {
    char path[256];
    const char *base = getenv("DCLAW_FLASH_PATH");
    snprintf(path, sizeof(path), "%s.lock-test", base ? base : "/tmp/dclaw-hal-test.bin");
    setenv("DCLAW_FLASH_PATH", path, 1);
    unlink(path);

    dclaw_device_info_t info = {.device_id = 1, .tenant_id = 1, .fleet_id = 1};
    assert(hal_init() == 0);
    assert(dclaw_init(&info) == 0); /* re-initialising in one process is fine */
    assert(second_engine_status() == 1);

    dclaw_shutdown(); /* releases the file */
    assert(second_engine_status() == 0);
    unlink(path);
    printf("  PASS: a second engine cannot open a flash file in use\n");
}

int main(void) {
    printf("test_hal_linux:\n");
    test_flash_path_prefix();
    test_flash_file_is_exclusive();
    return 0;
}
