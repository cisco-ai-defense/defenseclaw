// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//
// Encode/decode a Policy into the URL hash so operators can share a
// draft via "Copy share link". Hash payload is gzip-compressed JSON,
// then base64url-encoded so it round-trips through clipboard +
// browser address bar without %-escaping noise.
//
// The fragment never gets sent to the server (browsers strip it from
// every request), so this is a privacy-preserving teammate handoff —
// no upload, no DB, no tracking. The downside: anyone with the link
// can see the policy. That's fine; policies are not secrets (they
// reference env-var names, never inline values).
//
// Format:  #policy=v1.<base64url(gzip(json))>
//
// We pin a version prefix so future format changes (e.g. switch to
// CBOR) can fall back gracefully.
//
// SECURITY NOTES:
//   - Caps on both compressed input size and decompressed output size
//     prevent gzip-bomb attacks where a tiny URL expands to gigabytes
//     of memory before we fail the JSON parse. A real-world DefenseClaw
//     policy compresses to <5 KB; a 1 MB cap is generous and still safe.
//   - decodePolicyFromHash returns a tagged result so the caller can
//     distinguish "no payload" (null) from "bad payload" (a typed
//     reason) and show an actionable error to the operator.

import type { Policy } from '../types';

const HASH_KEY = 'policy';
const VERSION = 'v1';

/** Refuse hash bodies larger than this many base64url characters
 *  (~96 KB compressed). Real policies are <10 KB compressed, so
 *  anything past this is almost certainly an attack or a copy-paste
 *  mishap. Bound enforced before we touch the decompressor so we
 *  never allocate runaway buffers. */
const MAX_PAYLOAD_CHARS = 128_000;

/** Refuse decompressed JSON larger than this many bytes (1 MB).
 *  Sanity bound to neutralize gzip-bomb amplification (default
 *  gzip can reach ~1000:1 on highly compressible input, so a 100 KB
 *  body could expand to ~100 MB without this guard). */
const MAX_DECOMPRESSED_BYTES = 1_000_000;

export type DecodeFailure =
  | 'version'
  | 'too-large'
  | 'malformed'
  | 'invalid-shape';

export type DecodeResult =
  | { ok: true; policy: Policy }
  | { ok: false; reason: DecodeFailure };

/** True if the runtime exposes the streaming compression APIs we use.
 *  Probed via globalThis so the same module works in browsers (where
 *  these live on `window`) and in Node ≥18 unit tests (where they're
 *  globals on globalThis). */
function hasCompression(): boolean {
  return typeof (globalThis as { CompressionStream?: unknown }).CompressionStream === 'function';
}

/** True if the runtime exposes DecompressionStream. Decoupled from
 *  hasCompression so a runtime that only ships one of the two (rare
 *  but possible across polyfills) doesn't get falsely promoted. */
function hasDecompression(): boolean {
  return typeof (globalThis as { DecompressionStream?: unknown }).DecompressionStream === 'function';
}

async function gzip(input: string): Promise<Uint8Array> {
  const stream = new Blob([input])
    .stream()
    .pipeThrough(new CompressionStream('gzip'));
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

/** Decompress with a hard upper bound on total bytes produced. We
 *  pull chunks manually instead of using Response().text() so we can
 *  abort the stream the moment we exceed the cap, before allocating
 *  the full string. */
async function gunzipBounded(
  input: Uint8Array,
  maxBytes: number,
): Promise<{ ok: true; text: string } | { ok: false; reason: 'too-large' | 'malformed' }> {
  // Slice into a fresh ArrayBuffer to satisfy BlobPart's stricter
  // typing in newer TS lib defs.
  const buf = input.buffer.slice(
    input.byteOffset,
    input.byteOffset + input.byteLength,
  ) as ArrayBuffer;

  let stream: ReadableStream<Uint8Array>;
  try {
    stream = new Blob([buf])
      .stream()
      .pipeThrough(new DecompressionStream('gzip'));
  } catch {
    return { ok: false, reason: 'malformed' };
  }

  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          /* ignore */
        }
        return { ok: false, reason: 'too-large' };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, reason: 'malformed' };
  }

  // Reassemble. Total is bounded by maxBytes so this allocation is safe.
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    merged.set(c, off);
    off += c.byteLength;
  }
  try {
    return { ok: true, text: new TextDecoder().decode(merged) };
  } catch {
    return { ok: false, reason: 'malformed' };
  }
}

function bytesToBase64Url(bytes: Uint8Array): string {
  // btoa wants a binary string, so chunk to avoid call-stack blow-ups
  // on policies that compress to tens of KB.
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(s: string): Uint8Array | null {
  // Restore standard base64 padding.
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const std = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  let bin: string;
  try {
    bin = atob(std);
  } catch {
    // atob throws on illegal characters; treat as malformed.
    return null;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/** Minimal structural sanity check on the decoded JSON. We don't enforce
 *  the full Policy schema (drafts saved by older versions of the wizard
 *  may legitimately omit newer fields), only the bare minimum that
 *  proves the payload is a v1-shaped policy and not arbitrary data. */
function looksLikePolicy(value: unknown): value is Policy {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  // Every Policy carries a top-level metadata block with name+description.
  if (typeof v.metadata !== 'object' || v.metadata === null) return false;
  const meta = v.metadata as Record<string, unknown>;
  if (typeof meta.name !== 'string') return false;
  // Severity matrix is also always present and is the field most likely
  // to flag a "this is a totally different blob" mistake.
  if (typeof v.severity_matrix !== 'object' || v.severity_matrix === null) return false;
  return true;
}

/** Encode a Policy as a base64url(gzip(json)) string. */
export async function encodePolicyForHash(policy: Policy): Promise<string> {
  const json = JSON.stringify(policy);
  if (!hasCompression()) {
    // Fallback: plain base64url(json). Larger URL, but works on
    // browsers without CompressionStream (Firefox <113, Safari <16.4).
    const bytes = new TextEncoder().encode(json);
    return `${VERSION}.${bytesToBase64Url(bytes)}`;
  }
  const compressed = await gzip(json);
  return `${VERSION}.${bytesToBase64Url(compressed)}`;
}

/** Decode a hash payload back into a Policy. Returns a tagged result so
 *  the caller can react differently to "wrong version" vs "obviously
 *  bad data" vs "passes shape sanity-check". */
export async function decodePolicyFromHash(payload: string): Promise<DecodeResult> {
  const dot = payload.indexOf('.');
  if (dot < 0) return { ok: false, reason: 'malformed' };
  const version = payload.slice(0, dot);
  const body = payload.slice(dot + 1);
  if (version !== VERSION) return { ok: false, reason: 'version' };
  if (body.length > MAX_PAYLOAD_CHARS) return { ok: false, reason: 'too-large' };

  const bytes = base64UrlToBytes(body);
  if (!bytes) return { ok: false, reason: 'malformed' };

  let json: string;
  if (hasDecompression()) {
    const decompressed = await gunzipBounded(bytes, MAX_DECOMPRESSED_BYTES);
    if (decompressed.ok) {
      json = decompressed.text;
    } else if (decompressed.reason === 'too-large') {
      return { ok: false, reason: 'too-large' };
    } else {
      // Could be a non-gzip payload from the fallback encoder; try
      // raw UTF-8 within the same byte cap.
      if (bytes.byteLength > MAX_DECOMPRESSED_BYTES) {
        return { ok: false, reason: 'too-large' };
      }
      try {
        json = new TextDecoder().decode(bytes);
      } catch {
        return { ok: false, reason: 'malformed' };
      }
    }
  } else {
    if (bytes.byteLength > MAX_DECOMPRESSED_BYTES) {
      return { ok: false, reason: 'too-large' };
    }
    try {
      json = new TextDecoder().decode(bytes);
    } catch {
      return { ok: false, reason: 'malformed' };
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (!looksLikePolicy(parsed)) return { ok: false, reason: 'invalid-shape' };
  return { ok: true, policy: parsed };
}

/** Build the full shareable URL for the current page. The current
 *  base path + pathname are preserved; only the hash is replaced. */
export function buildShareUrl(payload: string): string {
  if (typeof window === 'undefined') return '';
  const base = `${window.location.origin}${window.location.pathname}${window.location.search}`;
  return `${base}#${HASH_KEY}=${payload}`;
}

/** Read the share payload from the current URL hash (on first mount).
 *  Returns null if no #policy= present. */
export function readHashPayload(): string | null {
  if (typeof window === 'undefined') return null;
  const hash = window.location.hash.replace(/^#/, '');
  if (!hash) return null;
  // Hash may be e.g. #policy=v1.abc&foo=bar — handle both = and & delim.
  const params = new URLSearchParams(hash);
  return params.get(HASH_KEY);
}

/** Strip #policy= from the URL after we've consumed it, so the operator
 *  doesn't accidentally re-prompt themselves on every reload. */
export function clearHashPayload(): void {
  if (typeof window === 'undefined') return;
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
  params.delete(HASH_KEY);
  const remaining = params.toString();
  const url = `${window.location.pathname}${window.location.search}${remaining ? `#${remaining}` : ''}`;
  window.history.replaceState(null, '', url);
}

// Exposed for tests; not part of the public API.
export const __TEST_INTERNALS = {
  MAX_PAYLOAD_CHARS,
  MAX_DECOMPRESSED_BYTES,
  looksLikePolicy,
};
