#!/usr/bin/env python3
"""Generate a tiny 2-layer GGUF model for testing the GRPO engine.

Creates a minimal valid GGUF v3 file with:
- 2 transformer layers
- hidden_dim=64, intermediate_dim=128, vocab=256
- n_heads=4, n_kv_heads=2, head_dim=16
- Q4_K quantized weights for projections
- F32 weights for norms and embeddings

Usage:
    python3 scripts/gen_tiny_gguf.py internal/training/grpo_engine/testdata/tiny_model.gguf
"""

import struct
import sys
import os
import numpy as np

# Model architecture
N_LAYERS = 2
HIDDEN_DIM = 64
INTERMEDIATE_DIM = 128
VOCAB_SIZE = 256
N_HEADS = 4
N_KV_HEADS = 2
HEAD_DIM = HIDDEN_DIM // N_HEADS  # 16

# GGUF constants
GGUF_MAGIC = 0x46475547  # "GGUF" little-endian
GGUF_VERSION = 3

# GGUF metadata value types
GV_U32 = 4
GV_F32 = 6
GV_STR = 8
GV_U64 = 10

# GGUF tensor types
GGUF_TYPE_F32 = 0
GGUF_TYPE_Q4_K = 12

# Q4_K block size: 256 elements per super-block
# Each super-block: 2 bytes (d) + 2 bytes (dmin) + 12 bytes (scales) + 128 bytes (qs) = 144 bytes per 256 elements
Q4K_BLOCK_SIZE = 256
Q4K_BYTES_PER_BLOCK = 144


def write_string(buf, s):
    """Write GGUF string: u64 length + bytes."""
    encoded = s.encode('utf-8')
    buf.extend(struct.pack('<Q', len(encoded)))
    buf.extend(encoded)


def write_kv_u32(buf, key, value):
    """Write a u32 metadata KV pair."""
    write_string(buf, key)
    buf.extend(struct.pack('<I', GV_U32))
    buf.extend(struct.pack('<I', value))


def write_kv_u64(buf, key, value):
    """Write a u64 metadata KV pair."""
    write_string(buf, key)
    buf.extend(struct.pack('<I', GV_U64))
    buf.extend(struct.pack('<Q', value))


def write_kv_f32(buf, key, value):
    """Write a f32 metadata KV pair."""
    write_string(buf, key)
    buf.extend(struct.pack('<I', GV_F32))
    buf.extend(struct.pack('<f', value))


def write_kv_str(buf, key, value):
    """Write a string metadata KV pair."""
    write_string(buf, key)
    buf.extend(struct.pack('<I', GV_STR))
    write_string(buf, value)


def quantize_q4k(tensor_f32):
    """Quantize a float32 tensor to Q4_K format (simplified).

    Real Q4_K uses super-blocks of 256 elements with sub-blocks of 32.
    This simplified version creates valid Q4_K binary that the parser accepts.
    """
    flat = tensor_f32.flatten().astype(np.float32)
    numel = len(flat)

    # Pad to multiple of Q4K_BLOCK_SIZE
    pad_to = ((numel + Q4K_BLOCK_SIZE - 1) // Q4K_BLOCK_SIZE) * Q4K_BLOCK_SIZE
    if pad_to > numel:
        flat = np.concatenate([flat, np.zeros(pad_to - numel, dtype=np.float32)])

    n_blocks = len(flat) // Q4K_BLOCK_SIZE
    result = bytearray()

    for b in range(n_blocks):
        block = flat[b * Q4K_BLOCK_SIZE:(b + 1) * Q4K_BLOCK_SIZE]

        # Compute scale (d) and min (dmin) for the block
        bmin = float(block.min())
        bmax = float(block.max())
        d = (bmax - bmin) / 15.0 if bmax != bmin else 1.0
        dmin = bmin

        # Convert d and dmin to float16 bytes
        d_f16 = np.float16(d)
        dmin_f16 = np.float16(abs(dmin))

        result.extend(d_f16.tobytes())    # 2 bytes: d
        result.extend(dmin_f16.tobytes())  # 2 bytes: dmin

        # Scales for sub-blocks (12 bytes for 8 sub-blocks of 32 elements)
        # Simplified: uniform scales
        result.extend(bytes(12))

        # Quantized values: 4 bits per element, 256 elements = 128 bytes
        quantized = np.clip(np.round((block - bmin) / d), 0, 15).astype(np.uint8)
        packed = bytearray(128)
        for i in range(0, 256, 2):
            packed[i // 2] = (quantized[i] & 0x0F) | ((quantized[i + 1] & 0x0F) << 4)
        result.extend(packed)

    return bytes(result), numel


def make_f32_tensor(shape):
    """Create random f32 tensor data."""
    rng = np.random.default_rng(42)
    data = rng.standard_normal(shape).astype(np.float32) * 0.02
    return data.tobytes(), int(np.prod(shape))


def make_q4k_tensor(shape):
    """Create random Q4_K quantized tensor data."""
    rng = np.random.default_rng(42)
    data = rng.standard_normal(shape).astype(np.float32) * 0.02
    packed, numel = quantize_q4k(data)
    return packed, int(np.prod(shape))


def build_gguf(output_path):
    """Build the complete GGUF file."""

    # Collect all tensors: (name, dtype, dims, data_bytes)
    tensors = []

    # Token embedding: [vocab_size, hidden_dim] — F32
    data, _ = make_f32_tensor((VOCAB_SIZE, HIDDEN_DIM))
    tensors.append(("token_embd.weight", GGUF_TYPE_F32, [HIDDEN_DIM, VOCAB_SIZE], data))

    # Per-layer tensors
    for layer in range(N_LAYERS):
        prefix = f"blk.{layer}"

        # Attention norm — F32 [hidden_dim]
        data, _ = make_f32_tensor((HIDDEN_DIM,))
        tensors.append((f"{prefix}.attn_norm.weight", GGUF_TYPE_F32, [HIDDEN_DIM], data))

        # Q projection — Q4_K [hidden_dim, hidden_dim]
        data, _ = make_q4k_tensor((HIDDEN_DIM, HIDDEN_DIM))
        tensors.append((f"{prefix}.attn_q.weight", GGUF_TYPE_Q4_K, [HIDDEN_DIM, HIDDEN_DIM], data))

        # K projection — Q4_K [hidden_dim, n_kv_heads * head_dim]
        kv_dim = N_KV_HEADS * HEAD_DIM
        data, _ = make_q4k_tensor((kv_dim, HIDDEN_DIM))
        tensors.append((f"{prefix}.attn_k.weight", GGUF_TYPE_Q4_K, [HIDDEN_DIM, kv_dim], data))

        # V projection — Q4_K [hidden_dim, n_kv_heads * head_dim]
        data, _ = make_q4k_tensor((kv_dim, HIDDEN_DIM))
        tensors.append((f"{prefix}.attn_v.weight", GGUF_TYPE_Q4_K, [HIDDEN_DIM, kv_dim], data))

        # O projection — Q4_K [n_heads * head_dim, hidden_dim]
        data, _ = make_q4k_tensor((HIDDEN_DIM, HIDDEN_DIM))
        tensors.append((f"{prefix}.attn_output.weight", GGUF_TYPE_Q4_K, [HIDDEN_DIM, HIDDEN_DIM], data))

        # FFN norm — F32 [hidden_dim]
        data, _ = make_f32_tensor((HIDDEN_DIM,))
        tensors.append((f"{prefix}.ffn_norm.weight", GGUF_TYPE_F32, [HIDDEN_DIM], data))

        # Gate projection — Q4_K [hidden_dim, intermediate_dim]
        data, _ = make_q4k_tensor((INTERMEDIATE_DIM, HIDDEN_DIM))
        tensors.append((f"{prefix}.ffn_gate.weight", GGUF_TYPE_Q4_K, [HIDDEN_DIM, INTERMEDIATE_DIM], data))

        # Up projection — Q4_K [hidden_dim, intermediate_dim]
        data, _ = make_q4k_tensor((INTERMEDIATE_DIM, HIDDEN_DIM))
        tensors.append((f"{prefix}.ffn_up.weight", GGUF_TYPE_Q4_K, [HIDDEN_DIM, INTERMEDIATE_DIM], data))

        # Down projection — Q4_K [intermediate_dim, hidden_dim]
        data, _ = make_q4k_tensor((HIDDEN_DIM, INTERMEDIATE_DIM))
        tensors.append((f"{prefix}.ffn_down.weight", GGUF_TYPE_Q4_K, [INTERMEDIATE_DIM, HIDDEN_DIM], data))

    # Output norm — F32 [hidden_dim]
    data, _ = make_f32_tensor((HIDDEN_DIM,))
    tensors.append(("output_norm.weight", GGUF_TYPE_F32, [HIDDEN_DIM], data))

    # Output (lm_head) — Q4_K [hidden_dim, vocab_size]
    data, _ = make_q4k_tensor((VOCAB_SIZE, HIDDEN_DIM))
    tensors.append(("output.weight", GGUF_TYPE_Q4_K, [HIDDEN_DIM, VOCAB_SIZE], data))

    # --- Build the GGUF binary ---

    # Metadata KV pairs
    metadata_kvs = []
    metadata_kvs.append(("general.architecture", "llama", "str"))
    metadata_kvs.append(("general.name", "tiny-grpo-test", "str"))
    metadata_kvs.append(("llama.block_count", N_LAYERS, "u32"))
    metadata_kvs.append(("llama.embedding_length", HIDDEN_DIM, "u32"))
    metadata_kvs.append(("llama.feed_forward_length", INTERMEDIATE_DIM, "u32"))
    metadata_kvs.append(("llama.attention.head_count", N_HEADS, "u32"))
    metadata_kvs.append(("llama.attention.head_count_kv", N_KV_HEADS, "u32"))
    metadata_kvs.append(("llama.vocab_size", VOCAB_SIZE, "u32"))
    metadata_kvs.append(("llama.attention.layer_norm_rms_epsilon", 1e-5, "f32"))
    metadata_kvs.append(("llama.rope.freq_base", 10000.0, "f32"))

    n_kv = len(metadata_kvs)
    n_tensors = len(tensors)

    # Write header
    header = bytearray()
    header.extend(struct.pack('<I', GGUF_MAGIC))
    header.extend(struct.pack('<I', GGUF_VERSION))
    header.extend(struct.pack('<Q', n_tensors))
    header.extend(struct.pack('<Q', n_kv))

    # Write metadata
    for key, value, vtype in metadata_kvs:
        if vtype == "str":
            write_kv_str(header, key, value)
        elif vtype == "u32":
            write_kv_u32(header, key, value)
        elif vtype == "u64":
            write_kv_u64(header, key, value)
        elif vtype == "f32":
            write_kv_f32(header, key, value)

    # Write tensor info (before alignment)
    # Calculate data offsets (relative to data section start)
    data_offset = 0
    tensor_infos = []
    for name, dtype, dims, data in tensors:
        # Align each tensor to 32 bytes
        aligned_offset = ((data_offset + 31) // 32) * 32
        tensor_infos.append((name, dtype, dims, aligned_offset, len(data)))
        data_offset = aligned_offset + len(data)

    # Write tensor info entries
    for name, dtype, dims, offset, _ in tensor_infos:
        write_string(header, name)
        header.extend(struct.pack('<I', len(dims)))  # n_dims
        for d in dims:
            header.extend(struct.pack('<Q', d))
        header.extend(struct.pack('<I', dtype))
        header.extend(struct.pack('<Q', offset))

    # Align header to 32 bytes
    alignment = 32
    header_size = len(header)
    aligned_header = ((header_size + alignment - 1) // alignment) * alignment
    padding = aligned_header - header_size
    header.extend(bytes(padding))

    # Write data section
    data_section = bytearray()
    for i, (name, dtype, dims, data) in enumerate(tensors):
        aligned_offset = tensor_infos[i][3]
        # Pad to reach this tensor's offset
        current = len(data_section)
        if aligned_offset > current:
            data_section.extend(bytes(aligned_offset - current))
        data_section.extend(data)

    # Combine and write
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(header)
        f.write(data_section)

    file_size = len(header) + len(data_section)
    print(f"Generated {output_path}")
    print(f"  Architecture: llama (tiny)")
    print(f"  Layers: {N_LAYERS}")
    print(f"  Hidden dim: {HIDDEN_DIM}")
    print(f"  Intermediate dim: {INTERMEDIATE_DIM}")
    print(f"  Vocab: {VOCAB_SIZE}")
    print(f"  Heads: {N_HEADS} (KV: {N_KV_HEADS})")
    print(f"  Tensors: {n_tensors}")
    print(f"  File size: {file_size:,} bytes ({file_size / 1024:.1f} KB)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        output = "internal/training/grpo_engine/testdata/tiny_model.gguf"
    else:
        output = sys.argv[1]

    build_gguf(output)
