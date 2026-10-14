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
 * HMAC-SHA256 implementation per RFC 2104.
 * Uses the built-in dclaw_sha256 implementation — no external library required.
 *
 * HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
 *   where K' = K if |K| <= block_size, else H(K)
 *   ipad = 0x36 repeated, opad = 0x5c repeated
 */

#include "hmac_sha256.h"
#include "sha256.h"
#include "platform.h"
#include <string.h>

void dclaw_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len,
                       uint8_t *out) {
    uint8_t k_prime[DCLAW_SHA256_BLOCK_SIZE];
    uint8_t ipad[DCLAW_SHA256_BLOCK_SIZE];
    uint8_t opad[DCLAW_SHA256_BLOCK_SIZE];
    uint8_t inner_hash[DCLAW_SHA256_DIGEST_SIZE];
    dclaw_sha256_ctx ctx;

    /* Step 1: Derive K' (key block) */
    memset(k_prime, 0, sizeof(k_prime));
    if (key_len > DCLAW_SHA256_BLOCK_SIZE) {
        /* Key longer than block size: K' = H(K), zero-padded */
        dclaw_sha256(key, key_len, k_prime);
    } else {
        /* Key <= block size: K' = K, zero-padded */
        memcpy(k_prime, key, key_len);
    }

    /* Step 2: Compute ipad and opad */
    for (int i = 0; i < DCLAW_SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }

    /* Step 3: Inner hash = H(ipad || msg) */
    dclaw_sha256_init(&ctx);
    dclaw_sha256_update(&ctx, ipad, DCLAW_SHA256_BLOCK_SIZE);
    dclaw_sha256_update(&ctx, msg, msg_len);
    dclaw_sha256_final(&ctx, inner_hash);

    /* Step 4: Outer hash = H(opad || inner_hash) */
    dclaw_sha256_init(&ctx);
    dclaw_sha256_update(&ctx, opad, DCLAW_SHA256_BLOCK_SIZE);
    dclaw_sha256_update(&ctx, inner_hash, DCLAW_SHA256_DIGEST_SIZE);
    dclaw_sha256_final(&ctx, out);

    /* Zero sensitive material */
    dclaw_secure_zero(k_prime, sizeof(k_prime));
    dclaw_secure_zero(ipad, sizeof(ipad));
    dclaw_secure_zero(opad, sizeof(opad));
    dclaw_secure_zero(inner_hash, sizeof(inner_hash));
}

/* Constant-time comparison to prevent timing side-channel attacks.
 * Returns true if the first `len` bytes of `a` and `b` are identical.
 * Declared in hmac_sha256.h; shared across all compilation units. */
bool ct_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

/*
 * Strict hex character to nibble conversion.
 * Returns 0-15 on success, -1 for any non-hex character (including
 * whitespace, signs, and control characters).
 */
static int dclaw_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Parse a hex-encoded string into a byte buffer with strict validation.
 * Rejects input containing whitespace, signs, or any non-[0-9a-fA-F] chars.
 * The hex string must be exactly out_len*2 characters long.
 * Returns 0 on success, -1 on invalid input.
 * Declared in hmac_sha256.h; shared across all compilation units. */
int dclaw_hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = dclaw_hex_nibble(hex[i * 2]);
        int lo = dclaw_hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
