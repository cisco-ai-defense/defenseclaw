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
 * Minimal SHA-256 implementation (FIPS 180-4).
 * Public domain — no external library required.
 *
 * Usage:
 *   dclaw_sha256_ctx ctx;
 *   dclaw_sha256_init(&ctx);
 *   dclaw_sha256_update(&ctx, data, len);
 *   dclaw_sha256_final(&ctx, hash);  // hash must be 32 bytes
 */

#ifndef DCLAW_SHA256_H
#define DCLAW_SHA256_H

#include <stdint.h>
#include <stddef.h>

#define DCLAW_SHA256_BLOCK_SIZE  64
#define DCLAW_SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buffer[DCLAW_SHA256_BLOCK_SIZE];
    uint32_t buflen;
} dclaw_sha256_ctx;

void dclaw_sha256_init(dclaw_sha256_ctx *ctx);
void dclaw_sha256_update(dclaw_sha256_ctx *ctx, const uint8_t *data, size_t len);
void dclaw_sha256_final(dclaw_sha256_ctx *ctx, uint8_t *hash);

/* Convenience: compute SHA-256 in one call */
void dclaw_sha256(const uint8_t *data, size_t len, uint8_t *hash);

#endif /* DCLAW_SHA256_H */
