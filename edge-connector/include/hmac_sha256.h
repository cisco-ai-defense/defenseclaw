/*
 * HMAC-SHA256 implementation per RFC 2104.
 * Uses the built-in dclaw_sha256 implementation — no external library required.
 *
 * Usage:
 *   uint8_t mac[32];
 *   dclaw_hmac_sha256(key, key_len, message, msg_len, mac);
 */

#ifndef DCLAW_HMAC_SHA256_H
#define DCLAW_HMAC_SHA256_H

#include <stdint.h>
#include <stddef.h>

#define DCLAW_HMAC_SHA256_SIZE 32

/*
 * Compute HMAC-SHA256.
 *   key     — secret key (any length; keys > 64 bytes are pre-hashed)
 *   key_len — length of key in bytes
 *   msg     — message to authenticate
 *   msg_len — length of message in bytes
 *   out     — output buffer, must be at least 32 bytes
 */
void dclaw_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len,
                       uint8_t *out);

/*
 * Constant-time comparison to prevent timing side-channel attacks.
 * Returns true if the first `len` bytes of `a` and `b` are identical.
 * Defined in hmac_sha256.c; shared across compilation units.
 */
#include <stdbool.h>
bool ct_compare(const uint8_t *a, const uint8_t *b, size_t len);

/*
 * Parse a hex-encoded string into a byte buffer with strict validation.
 * Rejects input containing whitespace, signs, or any non-[0-9a-fA-F] chars.
 * The hex string must be exactly out_len*2 characters long.
 * Returns 0 on success, -1 on invalid input.
 * Defined in hmac_sha256.c; shared across compilation units.
 */
int dclaw_hex_decode(const char *hex, uint8_t *out, size_t out_len);

#endif /* DCLAW_HMAC_SHA256_H */
