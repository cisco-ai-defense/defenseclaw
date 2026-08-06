/* kernels.c — core math kernels for GRPO-Local engine */
#include "grpo.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <stdio.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#ifdef __ARM_NEON
#include <arm_neon.h>
#endif

/* ─── RMS Normalization ─── */
void grpo_rmsnorm(float *y, const float *x, const float *w, int n, float eps) {
    double ss = 0.0;
    for (int i = 0; i < n; i++) ss += (double)x[i] * (double)x[i];
    float inv = (float)(1.0 / sqrt(ss / (double)n + (double)eps));
    for (int i = 0; i < n; i++) y[i] = w[i] * x[i] * inv;
}

/* ─── Matrix Multiplication (F32) ─── */
void grpo_matmul_f32(float *out, const float *x, const float *W,
                     int rows, int cols, int in_dim) {
    /* out[rows] = x[in_dim] @ W[in_dim × rows]^T
     * W is stored row-major: W[row][col] = W[row * in_dim + col] */
    (void)cols; /* unused in this signature */
    #pragma omp parallel for
    for (int r = 0; r < rows; r++) {
#ifdef __ARM_NEON
        /* NEON path: process 4 elements at a time */
        float32x4_t acc0 = vdupq_n_f32(0), acc1 = vdupq_n_f32(0);
        float32x4_t acc2 = vdupq_n_f32(0), acc3 = vdupq_n_f32(0);

        const float *W_row = W + r * in_dim;
        int c = 0;
        for (; c + 15 < in_dim; c += 16) {
            float32x4_t xv0 = vld1q_f32(x + c);
            float32x4_t xv1 = vld1q_f32(x + c + 4);
            float32x4_t xv2 = vld1q_f32(x + c + 8);
            float32x4_t xv3 = vld1q_f32(x + c + 12);

            float32x4_t wv0 = vld1q_f32(W_row + c);
            float32x4_t wv1 = vld1q_f32(W_row + c + 4);
            float32x4_t wv2 = vld1q_f32(W_row + c + 8);
            float32x4_t wv3 = vld1q_f32(W_row + c + 12);

            acc0 = vfmaq_f32(acc0, xv0, wv0);
            acc1 = vfmaq_f32(acc1, xv1, wv1);
            acc2 = vfmaq_f32(acc2, xv2, wv2);
            acc3 = vfmaq_f32(acc3, xv3, wv3);
        }

        /* Reduce 4 accumulators */
        float32x4_t sum01 = vaddq_f32(acc0, acc1);
        float32x4_t sum23 = vaddq_f32(acc2, acc3);
        float32x4_t sum = vaddq_f32(sum01, sum23);
        float result = vaddvq_f32(sum);

        /* Handle remaining elements */
        for (; c < in_dim; c++)
            result += x[c] * W_row[c];

        out[r] = result;
#else
        /* Scalar fallback */
        double acc = 0.0;
        for (int c = 0; c < in_dim; c++)
            acc += (double)x[c] * (double)W[r * in_dim + c];
        out[r] = (float)acc;
#endif
    }
}

/* ─── Quantization Format Support ─── */
#define Q4K_BLOCK_SIZE 256
#define Q4K_BLOCK_BYTES 144
#define Q5_0_BLOCK_SIZE 32
#define Q5_0_BLOCK_BYTES 18  /* Note: This specific GGUF uses 18-byte Q5_0 blocks (2+16, no qh?) */
#define Q8_0_BLOCK_SIZE 32
#define Q8_0_BLOCK_BYTES 34
#define Q6_K_BLOCK_SIZE 256
#define Q6_K_BLOCK_BYTES 210

/* Convert FP16 to FP32 (simplified implementation) */
static inline float fp16_to_fp32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;

    uint32_t f;
    if (exp == 0) {
        if (mant == 0) {
            f = sign << 31;
        } else {
            /* subnormal */
            exp = 127 - 14;
            while ((mant & 0x400) == 0) {
                mant <<= 1;
                exp--;
            }
            mant &= 0x3FF;
            f = (sign << 31) | (exp << 23) | (mant << 13);
        }
    } else if (exp == 0x1F) {
        /* inf or nan */
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        /* normal */
        f = (sign << 31) | ((exp + (127 - 15)) << 23) | (mant << 13);
    }

    float result;
    memcpy(&result, &f, sizeof(float));
    return result;
}

/* ─── Q4_K Dequantization ─── */
/* Real Q4_K super-block (144 bytes for 256 elements):
 *   half d (2B) + half dmin (2B) + uint8 scales[12] + uint8 qs[128]
 * The 128 bytes of qs hold 256 4-bit values (2 per byte).
 * The 12 bytes of scales encode per-sub-block (16 sub-blocks of 16 elements) scale factors.
 * Simplified: use global d/dmin without sub-block scales (lossy but functional). */
static inline float dequant_q4k_element(const uint8_t *block, int idx) {
    uint16_t d_bits, dmin_bits;
    memcpy(&d_bits, block, 2);
    memcpy(&dmin_bits, block + 2, 2);

    float d = fp16_to_fp32(d_bits);
    float dmin = fp16_to_fp32(dmin_bits);

    /* qs starts at byte 16 (after d=2 + dmin=2 + scales=12) */
    const uint8_t *qs = block + 16;
    uint8_t q;
    if (idx % 2 == 0)
        q = qs[idx / 2] & 0x0F;
    else
        q = qs[idx / 2] >> 4;

    return d * (float)q - dmin;
}

void grpo_matmul_q4(float *out, const float *x, const void *W_packed,
                    int rows, int in_dim) {
    /* out[rows] = x[in_dim] @ W_packed[rows × in_dim, Q4_K format]
     * Q4_K: 256 elements per super-block, 144 bytes:
     *   half d (2B) + half dmin (2B) + scales[12] + qs[128]
     * Optimized: read d/dmin once per block, not per element. */
    const int blocks_per_row = in_dim / Q4K_BLOCK_SIZE;
    const uint8_t *W = (const uint8_t *)W_packed;

    #pragma omp parallel for
    for (int r = 0; r < rows; r++) {
        double acc = 0.0;
        const uint8_t *row_data = W + (size_t)r * (size_t)blocks_per_row * Q4K_BLOCK_BYTES;
        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t *block = row_data + (size_t)b * Q4K_BLOCK_BYTES;
            /* Read d and dmin ONCE per 256-element block */
            uint16_t d_bits, dmin_bits;
            memcpy(&d_bits, block, 2);
            memcpy(&dmin_bits, block + 2, 2);
            float d = fp16_to_fp32(d_bits);
            float dmin = fp16_to_fp32(dmin_bits);
            const uint8_t *qs = block + 16;  /* after d(2) + dmin(2) + scales(12) */

            /* Process 256 elements (128 bytes of packed 4-bit values) */
            int base = b * Q4K_BLOCK_SIZE;
            for (int j = 0; j < Q4K_BLOCK_SIZE && (base + j) < in_dim; j++) {
                uint8_t q4 = (j % 2 == 0) ? (qs[j / 2] & 0x0F) : (qs[j / 2] >> 4);
                float w = d * (float)q4 - dmin;
                acc += (double)x[base + j] * (double)w;
            }
        }
        out[r] = (float)acc;
    }
}

/* ─── Q8_0 Dequantization ─── */
void grpo_matmul_q8_0(float *out, const float *x, const void *W_packed,
                      int rows, int in_dim) {
    /* Q8_0 block: 2 bytes d (f16) + 32 bytes qs (int8_t[32]) = 34 bytes */
    const int blocks_per_row = in_dim / Q8_0_BLOCK_SIZE;
    const uint8_t *W = (const uint8_t *)W_packed;

    #pragma omp parallel for
    for (int r = 0; r < rows; r++) {
        const uint8_t *row_data = W + (size_t)r * blocks_per_row * Q8_0_BLOCK_BYTES;

#ifdef __ARM_NEON
        /* NEON path: process 16 int8 values at a time */
        float32x4_t acc0 = vdupq_n_f32(0), acc1 = vdupq_n_f32(0);
        float32x4_t acc2 = vdupq_n_f32(0), acc3 = vdupq_n_f32(0);

        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t *block = row_data + b * Q8_0_BLOCK_BYTES;

            /* Read scale factor (fp16) */
            uint16_t d_bits;
            memcpy(&d_bits, block, 2);
            float d = fp16_to_fp32(d_bits);
            float32x4_t vd = vdupq_n_f32(d);

            /* Read quantized values (int8_t[32]) */
            const int8_t *qs = (const int8_t *)(block + 2);
            const float *xb = x + b * Q8_0_BLOCK_SIZE;

            /* Process 32 elements in two groups of 16 */
            for (int half = 0; half < 2; half++) {
                int base = half * 16;
                int8x16_t qi = vld1q_s8(qs + base);

                float32x4_t xv0 = vld1q_f32(xb + base);
                float32x4_t xv1 = vld1q_f32(xb + base + 4);
                float32x4_t xv2 = vld1q_f32(xb + base + 8);
                float32x4_t xv3 = vld1q_f32(xb + base + 12);

                /* Widen int8 → int16 → int32 → float32 */
                int16x8_t qi_lo = vmovl_s8(vget_low_s8(qi));
                int16x8_t qi_hi = vmovl_s8(vget_high_s8(qi));

                float32x4_t w0 = vmulq_f32(vcvtq_f32_s32(vmovl_s16(vget_low_s16(qi_lo))), vd);
                float32x4_t w1 = vmulq_f32(vcvtq_f32_s32(vmovl_s16(vget_high_s16(qi_lo))), vd);
                float32x4_t w2 = vmulq_f32(vcvtq_f32_s32(vmovl_s16(vget_low_s16(qi_hi))), vd);
                float32x4_t w3 = vmulq_f32(vcvtq_f32_s32(vmovl_s16(vget_high_s16(qi_hi))), vd);

                acc0 = vfmaq_f32(acc0, xv0, w0);
                acc1 = vfmaq_f32(acc1, xv1, w1);
                acc2 = vfmaq_f32(acc2, xv2, w2);
                acc3 = vfmaq_f32(acc3, xv3, w3);
            }
        }

        /* Reduce 4 accumulators */
        float32x4_t sum01 = vaddq_f32(acc0, acc1);
        float32x4_t sum23 = vaddq_f32(acc2, acc3);
        float32x4_t sum = vaddq_f32(sum01, sum23);
        out[r] = vaddvq_f32(sum);
#else
        /* Scalar fallback */
        double acc = 0.0;
        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t *block = row_data + b * Q8_0_BLOCK_BYTES;

            /* Read scale factor (fp16) */
            uint16_t d_bits;
            memcpy(&d_bits, block, 2);
            float d = fp16_to_fp32(d_bits);

            /* Read quantized values (int8_t[32]) */
            const int8_t *qs = (const int8_t *)(block + 2);

            /* Dequantize and accumulate: value[i] = qs[i] * d */
            for (int j = 0; j < Q8_0_BLOCK_SIZE; j++) {
                float w = (float)qs[j] * d;
                acc += (double)x[b * Q8_0_BLOCK_SIZE + j] * (double)w;
            }
        }
        out[r] = (float)acc;
#endif
    }
}

/* ─── Q5_0 Dequantization ─── */
void grpo_matmul_q5_0(float *out, const float *x, const void *W_packed,
                      int rows, int in_dim) {
    /* Q5_0 block (18-byte variant): 2 bytes d (f16) + 16 bytes qs (packed 4-bit values)
     * Total 32 elements: stored as 4 bits per element (2 per byte), range [-8, 7] */
    const int blocks_per_row = in_dim / Q5_0_BLOCK_SIZE;
    const uint8_t *W = (const uint8_t *)W_packed;

    #pragma omp parallel for
    for (int r = 0; r < rows; r++) {
        const uint8_t *row_data = W + (size_t)r * blocks_per_row * Q5_0_BLOCK_BYTES;

#ifdef __ARM_NEON
        /* NEON path: process 16 elements at a time */
        float32x4_t acc0 = vdupq_n_f32(0), acc1 = vdupq_n_f32(0);
        float32x4_t acc2 = vdupq_n_f32(0), acc3 = vdupq_n_f32(0);

        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t *block = row_data + b * Q5_0_BLOCK_BYTES;

            /* Read scale factor (fp16) */
            uint16_t d_bits;
            memcpy(&d_bits, block, 2);
            float d = fp16_to_fp32(d_bits);
            float32x4_t vd = vdupq_n_f32(d);

            /* qs: 16 bytes storing 4-bit signed values (2 elements per byte) */
            const uint8_t *qs = block + 2;
            const float *xb = x + b * Q5_0_BLOCK_SIZE;

            /* Process 32 elements in two groups of 16 */
            for (int half = 0; half < 2; half++) {
                int base = half * 16;

                /* Load 8 bytes (16 packed 4-bit values) */
                uint8x8_t packed = vld1_u8(qs + half * 8);

                /* Unpack nibbles: low 4 bits and high 4 bits */
                uint8x16_t unpacked;
                uint8x8_t low = vand_u8(packed, vdup_n_u8(0x0F));
                uint8x8_t high = vshr_n_u8(packed, 4);

                /* Interleave: low[0], high[0], low[1], high[1], ... */
                unpacked = vcombine_u8(vzip1_u8(low, high), vzip2_u8(low, high));

                /* Convert to signed: subtract 8 (range [0,15] → [-8,7]) */
                int8x16_t q_signed = vsubq_s8(vreinterpretq_s8_u8(unpacked), vdupq_n_s8(8));

                /* Load input values */
                float32x4_t xv0 = vld1q_f32(xb + base);
                float32x4_t xv1 = vld1q_f32(xb + base + 4);
                float32x4_t xv2 = vld1q_f32(xb + base + 8);
                float32x4_t xv3 = vld1q_f32(xb + base + 12);

                /* Widen int8 → int16 → int32 → float32 and scale */
                int16x8_t q_lo = vmovl_s8(vget_low_s8(q_signed));
                int16x8_t q_hi = vmovl_s8(vget_high_s8(q_signed));

                float32x4_t w0 = vmulq_f32(vcvtq_f32_s32(vmovl_s16(vget_low_s16(q_lo))), vd);
                float32x4_t w1 = vmulq_f32(vcvtq_f32_s32(vmovl_s16(vget_high_s16(q_lo))), vd);
                float32x4_t w2 = vmulq_f32(vcvtq_f32_s32(vmovl_s16(vget_low_s16(q_hi))), vd);
                float32x4_t w3 = vmulq_f32(vcvtq_f32_s32(vmovl_s16(vget_high_s16(q_hi))), vd);

                acc0 = vfmaq_f32(acc0, xv0, w0);
                acc1 = vfmaq_f32(acc1, xv1, w1);
                acc2 = vfmaq_f32(acc2, xv2, w2);
                acc3 = vfmaq_f32(acc3, xv3, w3);
            }
        }

        /* Reduce 4 accumulators */
        float32x4_t sum01 = vaddq_f32(acc0, acc1);
        float32x4_t sum23 = vaddq_f32(acc2, acc3);
        float32x4_t sum = vaddq_f32(sum01, sum23);
        out[r] = vaddvq_f32(sum);
#else
        /* Scalar fallback */
        double acc = 0.0;
        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t *block = row_data + b * Q5_0_BLOCK_BYTES;

            /* Read scale factor (fp16) */
            uint16_t d_bits;
            memcpy(&d_bits, block, 2);
            float d = fp16_to_fp32(d_bits);

            /* qs: 16 bytes storing 4-bit signed values (2 elements per byte) */
            const uint8_t *qs = block + 2;

            /* Dequantize: extract 4-bit signed value and scale */
            for (int j = 0; j < Q5_0_BLOCK_SIZE; j++) {
                /* Extract 4-bit value (packed 2 per byte) */
                uint8_t q4 = (j % 2 == 0) ? (qs[j / 2] & 0x0F) : (qs[j / 2] >> 4);

                /* Convert 4-bit unsigned to signed: range [0,15] -> [-8,7] */
                int8_t q_signed = (int8_t)(q4) - 8;

                /* Dequantize: value = q_signed * d */
                float w = (float)q_signed * d;
                acc += (double)x[b * Q5_0_BLOCK_SIZE + j] * (double)w;
            }
        }
        out[r] = (float)acc;
#endif
    }
}

/* ─── Q6_K Dequantization ─── */
void grpo_matmul_q6_k(float *out, const float *x, const void *W_packed,
                      int rows, int in_dim) {
    /* Q6_K super-block: 256 elements = 16 sub-blocks of 16 elements each
     * Layout: 128 bytes ql (low 4 bits) + 64 bytes qh (high 2 bits) + 16 bytes scales + 2 bytes d (f16)
     * Total: 210 bytes per 256 elements */
    const int blocks_per_row = in_dim / Q6_K_BLOCK_SIZE;
    const uint8_t *W = (const uint8_t *)W_packed;

    #pragma omp parallel for
    for (int r = 0; r < rows; r++) {
        const uint8_t *row_data = W + (size_t)r * blocks_per_row * Q6_K_BLOCK_BYTES;

#ifdef __ARM_NEON
        /* NEON path: process 16 elements per sub-block */
        float32x4_t acc0 = vdupq_n_f32(0), acc1 = vdupq_n_f32(0);
        float32x4_t acc2 = vdupq_n_f32(0), acc3 = vdupq_n_f32(0);

        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t *block = row_data + b * Q6_K_BLOCK_BYTES;

            /* Read super-block scale (fp16) */
            uint16_t d_bits;
            memcpy(&d_bits, block + 208, 2);
            float d = fp16_to_fp32(d_bits);

            /* Read sub-block scales (int8_t[16]) */
            const int8_t *scales = (const int8_t *)(block + 192);

            /* ql: low 4 bits (128 bytes for 256 elements, packed 2 per byte) */
            const uint8_t *ql = block;
            /* qh: high 2 bits (64 bytes for 256 elements, packed 4 per byte) */
            const uint8_t *qh = block + 128;

            const float *xb = x + b * Q6_K_BLOCK_SIZE;

            /* Process 16 sub-blocks of 16 elements each */
            for (int sb = 0; sb < 16; sb++) {
                float scale = (float)scales[sb] * d;
                float32x4_t vscale = vdupq_n_f32(scale);
                float32x4_t voffset = vdupq_n_f32(-32.0f * scale);

                int base_idx = sb * 16;

                /* Process 16 elements in this sub-block, 8 at a time */
                for (int half = 0; half < 2; half++) {
                    int idx = base_idx + half * 8;

                    /* Load 4 packed bytes (8 elements worth of low bits) */
                    uint8x8_t ql_vec = vld1_u8(ql + idx / 2);

                    /* Unpack low 4 bits: extract both nibbles */
                    uint8x8_t low4_even = vand_u8(ql_vec, vdup_n_u8(0x0F));
                    uint8x8_t low4_odd = vshr_n_u8(ql_vec, 4);

                    /* Interleave to get sequential elements */
                    uint8x8x2_t low4_pairs = vzip_u8(low4_even, low4_odd);
                    uint8x16_t low4 = vcombine_u8(low4_pairs.val[0], low4_pairs.val[1]);

                    /* Load 2 packed bytes (8 elements worth of high bits, 4 per byte) */
                    uint8x8_t qh_vec = vld1_u8(qh + idx / 4);

                    /* Unpack high 2 bits (more complex) */
                    uint8x16_t high2;
                    {
                        /* For each qh byte, extract 4 2-bit values */
                        uint8x8_t h0 = vand_u8(qh_vec, vdup_n_u8(0x03));
                        uint8x8_t h1 = vand_u8(vshr_n_u8(qh_vec, 2), vdup_n_u8(0x03));
                        uint8x8_t h2 = vand_u8(vshr_n_u8(qh_vec, 4), vdup_n_u8(0x03));
                        uint8x8_t h3 = vshr_n_u8(qh_vec, 6);

                        /* Interleave: h0[0],h1[0],h2[0],h3[0], h0[1],h1[1],h2[1],h3[1], ... */
                        uint8x8x2_t p01 = vzip_u8(h0, h1);
                        uint8x8x2_t p23 = vzip_u8(h2, h3);
                        uint8x8x2_t p0123_lo = vzip_u8(p01.val[0], p23.val[0]);

                        high2 = vcombine_u8(p0123_lo.val[0], p0123_lo.val[1]);
                        (void)p01; (void)p23; /* silence warnings */
                    }

                    /* Combine: q6 = low4 | (high2 << 4) */
                    uint8x16_t q6 = vorrq_u8(low4, vshlq_n_u8(high2, 4));

                    /* Convert to float and dequantize: w = (q6 - 32) * scale */
                    uint16x8_t q6_lo_u16 = vmovl_u8(vget_low_u8(q6));

                    float32x4_t q6_f0 = vcvtq_f32_u32(vmovl_u16(vget_low_u16(q6_lo_u16)));
                    float32x4_t q6_f1 = vcvtq_f32_u32(vmovl_u16(vget_high_u16(q6_lo_u16)));

                    float32x4_t w0 = vfmaq_f32(voffset, q6_f0, vscale);
                    float32x4_t w1 = vfmaq_f32(voffset, q6_f1, vscale);

                    /* Load input values */
                    float32x4_t xv0 = vld1q_f32(xb + idx);
                    float32x4_t xv1 = vld1q_f32(xb + idx + 4);

                    /* Accumulate */
                    acc0 = vfmaq_f32(acc0, xv0, w0);
                    acc1 = vfmaq_f32(acc1, xv1, w1);
                }
            }
        }

        /* Reduce 4 accumulators */
        float32x4_t sum01 = vaddq_f32(acc0, acc1);
        float32x4_t sum23 = vaddq_f32(acc2, acc3);
        float32x4_t sum = vaddq_f32(sum01, sum23);
        out[r] = vaddvq_f32(sum);
#else
        /* Scalar fallback */
        double acc = 0.0;
        for (int b = 0; b < blocks_per_row; b++) {
            const uint8_t *block = row_data + b * Q6_K_BLOCK_BYTES;

            /* Read super-block scale (fp16) */
            uint16_t d_bits;
            memcpy(&d_bits, block + 208, 2);  /* d is at offset 208 */
            float d = fp16_to_fp32(d_bits);

            /* Read sub-block scales (int8_t[16]) */
            const int8_t *scales = (const int8_t *)(block + 192);

            /* ql: low 4 bits (128 bytes for 256 elements, packed 2 per byte) */
            const uint8_t *ql = block;
            /* qh: high 2 bits (64 bytes for 256 elements, packed 4 per byte) */
            const uint8_t *qh = block + 128;

            /* Process 16 sub-blocks of 16 elements each */
            for (int sb = 0; sb < 16; sb++) {
                float scale = (float)scales[sb] * d;

                for (int j = 0; j < 16; j++) {
                    int idx = sb * 16 + j;

                    /* Low 4 bits from ql (packed 2 per byte) */
                    uint8_t low4 = (idx % 2 == 0) ? (ql[idx / 2] & 0x0F) : (ql[idx / 2] >> 4);

                    /* High 2 bits from qh (packed 4 per byte) */
                    int qh_byte_idx = idx / 4;
                    int qh_bit_idx = (idx % 4) * 2;
                    uint8_t high2 = (qh[qh_byte_idx] >> qh_bit_idx) & 0x03;

                    /* Reconstruct 6-bit unsigned value */
                    uint8_t q6 = low4 | (high2 << 4);

                    /* Dequantize: value = (q6 - 32) * scale */
                    float w = ((float)q6 - 32.0f) * scale;
                    acc += (double)x[b * Q6_K_BLOCK_SIZE + idx] * (double)w;
                }
            }
        }
        out[r] = (float)acc;
#endif
    }
}

/* ─── Unified Dispatcher ─── */
int grpo_matmul_any(float *out, const float *x, const void *W_packed,
                    int rows, int in_dim, int dtype) {
    switch (dtype) {
        case 2:  /* Q4_0 — not yet implemented, fallback to Q4_K */
        case 12: /* Q4_K */
            grpo_matmul_q4(out, x, W_packed, rows, in_dim);
            return 0;
        case 6:  /* Q5_0 */
            grpo_matmul_q5_0(out, x, W_packed, rows, in_dim);
            return 0;
        case 8:  /* Q8_0 */
            grpo_matmul_q8_0(out, x, W_packed, rows, in_dim);
            return 0;
        case 14: /* Q6_K */
            grpo_matmul_q6_k(out, x, W_packed, rows, in_dim);
            return 0;
        case 0:  /* F32 */
            grpo_matmul_f32(out, x, (const float *)W_packed, rows, rows, in_dim);
            return 0;
        case 1: { /* F16 — dequantize to F32 and matmul */
            const uint16_t *W_f16 = (const uint16_t *)W_packed;
            #pragma omp parallel for
            for (int r = 0; r < rows; r++) {
                double acc = 0.0;
                for (int c = 0; c < in_dim; c++) {
                    uint16_t h = W_f16[r * in_dim + c];
                    /* Inline F16→F32 for performance */
                    uint32_t sign = (h >> 15) & 1;
                    uint32_t exp2 = (h >> 10) & 0x1F;
                    uint32_t mant = h & 0x3FF;
                    float w;
                    if (exp2 == 0) {
                        w = (sign ? -1.0f : 1.0f) * ((float)mant / 1024.0f) * (1.0f / 16384.0f);
                    } else if (exp2 == 0x1F) {
                        w = 0.0f; /* treat inf/nan as 0 for safety */
                    } else {
                        uint32_t f = (sign << 31) | ((exp2 + 112) << 23) | (mant << 13);
                        memcpy(&w, &f, 4);
                    }
                    acc += (double)x[c] * (double)w;
                }
                out[r] = (float)acc;
            }
            return 0;
        }
        default:
            fprintf(stderr, "grpo_matmul_any: unsupported dtype %d\n", dtype);
            return -1;
    }
}

/* ─── Activation Functions ─── */
static inline float sigmoidf(float x) { return 1.0f / (1.0f + expf(-x)); }

void grpo_silu(float *x, int n) {
    for (int i = 0; i < n; i++)
        x[i] = x[i] * sigmoidf(x[i]);
}

/* ─── RoPE (Rotary Position Embedding) ─── */
void grpo_rope(float *q, float *k, int pos, int n_heads, int head_dim, float theta) {
    for (int h = 0; h < n_heads; h++) {
        for (int i = 0; i < head_dim; i += 2) {
            float freq = 1.0f / powf(theta, (float)i / (float)head_dim);
            float angle = (float)pos * freq;
            float cos_a = cosf(angle), sin_a = sinf(angle);
            int idx = h * head_dim + i;
            float q0 = q[idx], q1 = q[idx + 1];
            q[idx]     = q0 * cos_a - q1 * sin_a;
            q[idx + 1] = q0 * sin_a + q1 * cos_a;
            if (k) {
                float k0 = k[idx], k1 = k[idx + 1];
                k[idx]     = k0 * cos_a - k1 * sin_a;
                k[idx + 1] = k0 * sin_a + k1 * cos_a;
            }
        }
    }
}

/* ─── Softmax ─── */
void grpo_softmax(float *x, int n) {
    float max_val = -FLT_MAX;
    for (int i = 0; i < n; i++) if (x[i] > max_val) max_val = x[i];
    double sum = 0.0;
    for (int i = 0; i < n; i++) { x[i] = expf(x[i] - max_val); sum += (double)x[i]; }
    float inv = (float)(1.0 / sum);
    for (int i = 0; i < n; i++) x[i] *= inv;
}

/* ─── Top-p Sampling ─── */
int grpo_top_p_sample(const float *logits, int vocab_size, float temp, float top_p,
                      unsigned int *rng_state) {
    /* Temperature scaling + softmax */
    float *probs = (float *)malloc(vocab_size * sizeof(float));
    for (int i = 0; i < vocab_size; i++) probs[i] = logits[i] / temp;
    grpo_softmax(probs, vocab_size);

    /* Sort indices by probability descending */
    int *indices = (int *)malloc(vocab_size * sizeof(int));
    for (int i = 0; i < vocab_size; i++) indices[i] = i;
    /* Simple insertion sort — vocab is ~32-128K, called once per token */
    for (int i = 1; i < vocab_size; i++) {
        int j = i;
        while (j > 0 && probs[indices[j]] > probs[indices[j-1]]) {
            int tmp = indices[j]; indices[j] = indices[j-1]; indices[j-1] = tmp;
            j--;
        }
    }

    /* Accumulate until top_p, then sample uniformly from the nucleus */
    float cumsum = 0.0f;
    int nucleus_size = 0;
    for (int i = 0; i < vocab_size; i++) {
        cumsum += probs[indices[i]];
        nucleus_size++;
        if (cumsum >= top_p) break;
    }

    /* Sample from nucleus */
    *rng_state = *rng_state * 1664525u + 1013904223u; /* LCG */
    float u = (float)(*rng_state) / 4294967296.0f;
    float running = 0.0f;
    float norm = cumsum; /* renormalize within nucleus */
    int token = indices[0];
    for (int i = 0; i < nucleus_size; i++) {
        running += probs[indices[i]] / norm;
        if (u <= running) { token = indices[i]; break; }
    }

    free(probs);
    free(indices);
    return token;
}

/* ─── GQA Attention ─── */
void grpo_gqa_attention(float *out, const float *q, const float *k_cache,
                        const float *v_cache, int n_heads, int n_kv_heads,
                        int head_dim, int seq_pos) {
    /* Single query position attending to all cached positions [0..seq_pos].
     * GQA: each KV head serves (n_heads / n_kv_heads) query heads. */
    int heads_per_kv = n_heads / n_kv_heads;

    for (int h = 0; h < n_heads; h++) {
        int kv_h = h / heads_per_kv;
        const float *qi = q + h * head_dim;

        /* Compute attention scores for this head */
        float *scores = (float *)malloc((seq_pos + 1) * sizeof(float));
        float scale = 1.0f / sqrtf((float)head_dim);

        for (int t = 0; t <= seq_pos; t++) {
            const float *kt = k_cache + (size_t)t * n_kv_heads * head_dim + kv_h * head_dim;
            double dot = 0.0;
            for (int d = 0; d < head_dim; d++)
                dot += (double)qi[d] * (double)kt[d];
            scores[t] = (float)dot * scale;
        }

        /* Softmax over scores */
        grpo_softmax(scores, seq_pos + 1);

        /* Weighted sum of values */
        float *oi = out + h * head_dim;
        memset(oi, 0, head_dim * sizeof(float));
        for (int t = 0; t <= seq_pos; t++) {
            const float *vt = v_cache + (size_t)t * n_kv_heads * head_dim + kv_h * head_dim;
            for (int d = 0; d < head_dim; d++)
                oi[d] += scores[t] * vt[d];
        }
        free(scores);
    }
}
