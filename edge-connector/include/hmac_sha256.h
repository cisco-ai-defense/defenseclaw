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

#endif /* DCLAW_HMAC_SHA256_H */
