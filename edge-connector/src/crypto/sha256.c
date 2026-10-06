/*
 * SHA-256 implementation per FIPS 180-4.
 * Public domain — no external library required.
 *
 * This is a straightforward implementation of the SHA-256 algorithm.
 * It is not optimized for speed but is correct and portable C11.
 */

#include "sha256.h"
#include <string.h>

/* SHA-256 constants: first 32 bits of the fractional parts of the
 * cube roots of the first 64 primes (2..311). */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SIGMA1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define sigma0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void store_be64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;

    /* Prepare message schedule */
    for (int t = 0; t < 16; t++) {
        W[t] = load_be32(block + t * 4);
    }
    for (int t = 16; t < 64; t++) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    /* Initialize working variables */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* 64 rounds */
    for (int t = 0; t < 64; t++) {
        uint32_t T1 = h + SIGMA1(e) + CH(e, f, g) + K[t] + W[t];
        uint32_t T2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    /* Add compressed chunk to hash value */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void dclaw_sha256_init(dclaw_sha256_ctx *ctx) {
    /* Initial hash values: first 32 bits of the fractional parts of
     * the square roots of the first 8 primes (2..19). */
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->bitcount = 0;
    ctx->buflen = 0;
}

void dclaw_sha256_update(dclaw_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->bitcount += (uint64_t)len * 8;

    /* If there is data in the buffer, try to fill it */
    if (ctx->buflen > 0) {
        uint32_t fill = DCLAW_SHA256_BLOCK_SIZE - ctx->buflen;
        if (len < fill) {
            memcpy(ctx->buffer + ctx->buflen, data, len);
            ctx->buflen += (uint32_t)len;
            return;
        }
        memcpy(ctx->buffer + ctx->buflen, data, fill);
        sha256_transform(ctx->state, ctx->buffer);
        data += fill;
        len -= fill;
        ctx->buflen = 0;
    }

    /* Process full blocks */
    while (len >= DCLAW_SHA256_BLOCK_SIZE) {
        sha256_transform(ctx->state, data);
        data += DCLAW_SHA256_BLOCK_SIZE;
        len -= DCLAW_SHA256_BLOCK_SIZE;
    }

    /* Buffer remaining bytes */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buflen = (uint32_t)len;
    }
}

void dclaw_sha256_final(dclaw_sha256_ctx *ctx, uint8_t *hash) {
    /* Pad the message: append bit '1', then zeros, then 64-bit length (big-endian) */

    /* Append 0x80 byte */
    ctx->buffer[ctx->buflen++] = 0x80;

    if (ctx->buflen > 56) {
        /* Not enough room for the 8-byte length — need two blocks */
        memset(ctx->buffer + ctx->buflen, 0, DCLAW_SHA256_BLOCK_SIZE - ctx->buflen);
        sha256_transform(ctx->state, ctx->buffer);
        ctx->buflen = 0;
    }

    /* Pad with zeros up to byte 56 */
    memset(ctx->buffer + ctx->buflen, 0, 56 - ctx->buflen);

    /* Append bit length as big-endian 64-bit integer */
    store_be64(ctx->buffer + 56, ctx->bitcount);
    sha256_transform(ctx->state, ctx->buffer);

    /* Produce the final hash in big-endian */
    for (int i = 0; i < 8; i++) {
        store_be32(hash + i * 4, ctx->state[i]);
    }

    /* Zero sensitive state */
    memset(ctx, 0, sizeof(*ctx));
}

void dclaw_sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    dclaw_sha256_ctx ctx;
    dclaw_sha256_init(&ctx);
    dclaw_sha256_update(&ctx, data, len);
    dclaw_sha256_final(&ctx, hash);
}
