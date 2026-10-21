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


/*
 * libFuzzer target for the IPC JSON-RPC path:
 *   dclaw_ipc_parse_request -> dclaw_ipc_validate_request -> dclaw_evaluate
 *   (-> dclaw_cbor_encode_verdict_request in MQTT profiles).
 *
 * Build: configure with -DDCLAW_SANITIZE=ON using a clang that ships the
 * libFuzzer runtime; CMake then builds fuzz_ipc_parser.
 * Run:   ./fuzz_ipc_parser -max_len=8192 tests/fuzz_corpus/
 *
 * The engine state persists across inputs (as in the daemon); rate-limit
 * buckets are refilled per input so later inputs still reach the deeper
 * stages. Each process uses its own flash file (the engine locks it), so
 * parallel workers do not collide; set DCLAW_FLASH_PATH to override.
 * fuzz_replay_main.c runs this entry point over files without libFuzzer.
 */

#include "defenseclaw.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int dclaw_ipc_parse_request(const char *json, size_t json_len,
                                   dclaw_tool_request_t *out);
extern int dclaw_ipc_validate_request(const dclaw_tool_request_t *req);
extern void dclaw_ipc_rate_limit_reset(void);
extern dclaw_state_t *dclaw_get_state(void);
#if DCLAW_MQTT_ENABLED
extern int dclaw_cbor_encode_verdict_request(const dclaw_tool_request_t *req,
                                             uint16_t request_id, uint8_t session_risk,
                                             uint8_t *buf, size_t *out_len, size_t buf_size);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void boot_once(void) {
    static bool booted = false;
    if (booted) return;
    if (!getenv("DCLAW_FLASH_PATH")) {
        char path[64];
        snprintf(path, sizeof(path), "/tmp/dclaw-fuzz-ipc-%ld.bin", (long)getpid());
        setenv("DCLAW_FLASH_PATH", path, 1);
    }
    dclaw_device_info_t info = {.device_id = 1, .tenant_id = 1, .fleet_id = 1};
    if (dclaw_init(&info) != 0) {
        fprintf(stderr, "fuzz_ipc_parser: dclaw_init failed\n");
        abort();
    }
    booted = true;
}

static void refill_rate_limits(void) {
    dclaw_state_t *s = dclaw_get_state();
    for (int i = 0; i < DCLAW_RATE_LIMITERS; i++)
        s->rate_limiters[i].tokens = s->rate_limiters[i].bucket_size;
    dclaw_ipc_rate_limit_reset();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    boot_once();
    if (size > DCLAW_IPC_MAX_PAYLOAD) return 0;

    /* Exact-size, NUL-terminated heap copy (as the daemon frames a
     * message), so ASan reports any read past the input. */
    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';
    refill_rate_limits();

    dclaw_tool_request_t req;
    if (dclaw_ipc_parse_request(buf, size, &req) == 0) {
        /* Parser invariants */
        if (memchr(req.tool_name, 0, DCLAW_TOOL_NAME_MAX) == NULL) abort();
        if (memchr(req.destination, 0, DCLAW_DESTINATION_MAX) == NULL) abort();
        if (req.content &&
            (req.content_len >= DCLAW_CONTENT_MAX || req.content[req.content_len] != '\0'))
            abort();

        (void)dclaw_ipc_validate_request(&req);
        dclaw_verdict_t v = dclaw_evaluate(&req);
        if (v.action > DCLAW_ACTION_ESCALATE) abort();
#if DCLAW_MQTT_ENABLED
        size_t cap = DCLAW_VERDICT_REQUEST_MAX;
        uint8_t *out = malloc(cap);
        if (out) {
            size_t olen = 0;
            if (dclaw_cbor_encode_verdict_request(&req, 7, 0, out, &olen, cap) == 0 &&
                olen > cap)
                abort();
            free(out);
        }
#endif
    }
    free(buf);
    return 0;
}
