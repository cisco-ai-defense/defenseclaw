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
